"""Opt-in, exact-path Linux observation; never imports/executes inspected source."""
import argparse
import hashlib
import json
import os
import selectors
import stat
import subprocess
import sys
import time
import traceback

LINK = '/usr/lib/python3.12/sitecustomize.py'
TARGET = '/etc/python3.12/sitecustomize.py'
APPROVED_LINK_SPELLINGS = (TARGET, '../../../etc/python3.12/sitecustomize.py')
LIMIT = 65536


def require(ok, message):
    if not ok: raise ValueError(message)


def metadata(s):
    return {k: getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                                      'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


class LinuxIO:
    def parent(self, path):
        require(path in (LINK, TARGET), 'path outside exact diagnostic scope')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.strip('/').split('/')[:-1]:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = nxt
            return fd
        except BaseException:
            os.close(fd); raise

    def inspect(self, path):
        fd = self.parent(path)
        try:
            name = path.rsplit('/', 1)[1]
            before = metadata(os.stat(name, dir_fd=fd, follow_symlinks=False))
            row = {'path': path, 'metadata': before}
            if stat.S_ISLNK(before['st_mode']): row['link_text'] = os.readlink(name, dir_fd=fd)
            require(metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)) == before, 'path changed during inspection')
            return row
        finally: os.close(fd)

    def read_target(self, expected):
        parent = self.parent(TARGET)
        try:
            fd = os.open('sitecustomize.py', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = metadata(os.fstat(fd))
                require(before == expected and stat.S_ISREG(before['st_mode']), 'target identity/type changed')
                require(before['st_size'] <= LIMIT, 'source exceeds 64 KiB bound; not read or hashed')
                data = bytearray()
                while len(data) <= LIMIT:
                    block = os.read(fd, min(4096, LIMIT + 1 - len(data)))
                    if not block: break
                    data.extend(block)
                require(len(data) <= LIMIT, 'source grew beyond bound')
                require(metadata(os.fstat(fd)) == before, 'opened target changed')
                require(metadata(os.stat('sitecustomize.py', dir_fd=parent, follow_symlinks=False)) == before,
                        'target path replaced')
                return bytes(data)
            finally: os.close(fd)
        finally: os.close(parent)

    def ownership(self, path):
        require(path in (LINK, TARGET), 'ownership outside exact scope')
        argv = ['/usr/bin/dpkg-query', '--search', path]
        end = time.monotonic() + 5
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env={'PATH': '/usr/bin', 'LANG': 'C'}, close_fds=True)
        data = bytearray()
        try:
            os.set_blocking(proc.stdout.fileno(), False)
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    left = end - time.monotonic(); require(left > 0, 'ownership timeout')
                    if not sel.select(min(left, .1)): continue
                    block = os.read(proc.stdout.fileno(), 4096)
                    if not block: break
                    data.extend(block); require(len(data) <= LIMIT, 'ownership output bound')
            left = end - time.monotonic(); require(left > 0, 'ownership timeout')
            rc = proc.wait(timeout=left)
            require(time.monotonic() <= end, 'ownership deadline overrun')
            return {'argv': argv, 'exit_code': rc, 'text': data.decode('utf-8', errors='replace'),
                    'meaning': 'package database claim only; not publisher-byte verification'}
        finally:
            active_error = sys.exc_info()[1]
            cleanup = []
            if proc.poll() is None:
                try: proc.kill()
                except Exception as exc: cleanup.append(repr(exc))
                try: proc.wait(timeout=1)
                except Exception as exc: cleanup.append(repr(exc))
            proc.stdout.close()
            if cleanup:
                if active_error is not None: active_error.args += ('cleanup unconfirmed: ' + repr(cleanup),)
                else: raise RuntimeError('ownership cleanup unconfirmed: ' + repr(cleanup))


def source_summary(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'policy': 'raw bytes hashed only; no source text, decoding, parsing, import or execution'}


def collect(io):
    report = {'schema': 'pv2_exact_sitecustomize_diagnostic_v1', 'status': 'partial', 'chain': [],
              'ownership': {}, 'errors': [], 'execution_approved': False, 'security_approved': False,
              'dependencies_approved': False, 'pilot_execution_authorized': False, 'stage_b': 'paused'}
    try:
        link = io.inspect(LINK); report['chain'].append(link)
        require(stat.S_ISLNK(link['metadata']['st_mode']), 'expected source symlink')
        # Literal spellings only. parent() rejects symlinks in every source/target
        # ancestor, so the approved relative spelling traverses those checked dirs.
        # Never normalize arbitrary '..' components or follow an unexpected hop.
        require(link['link_text'] in APPROVED_LINK_SPELLINGS,
                'unapproved link spelling (not followed): ' + link['link_text'])
        target = io.inspect(TARGET); report['chain'].append(target)
        require(stat.S_ISREG(target['metadata']['st_mode']), 'expected exact target regular file; no further hop followed')
        data = io.read_target(target['metadata'])
        require(len(data) <= LIMIT, 'source bound')
        require(io.inspect(LINK) == link and io.inspect(TARGET) == target, 'chain changed; hash not accepted')
        report['source'] = source_summary(data)
        for path in (LINK, TARGET):
            try:
                report['ownership'][path] = io.ownership(path)
                if report['ownership'][path]['exit_code'] != 0:
                    report['errors'].append({'path': path, 'error': 'ownership unresolved/nonzero; retained verbatim'})
            except Exception:
                report['errors'].append({'path': path, 'error': traceback.format_exc()})
        require(io.inspect(LINK) == link and io.inspect(TARGET) == target, 'chain changed during ownership queries')
        report['status'] = 'observed_with_gaps' if report['errors'] else 'observed_not_approved'
    except Exception:
        report['errors'].append({'error': traceback.format_exc()})
        report['status'] = 'failed'
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--read-only-exact-path', action='store_true', required=True)
    parser.parse_args()
    require(sys.platform == 'linux' and sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode,
            'requires Linux /usr/bin/python3 -I -S -B')
    report = collect(LinuxIO())
    report['runtime'] = {'python': sys.version, 'executable': sys.executable,
                         'run_id': os.environ.get('GITHUB_RUN_ID'), 'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
                         'commit': os.environ.get('GITHUB_SHA'), 'job': os.environ.get('GITHUB_JOB'),
                         'runner': os.environ.get('RUNNER_NAME')}
    try:
        with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:
            report['runtime']['boot_id'] = stream.read(128).strip()
    except Exception:
        report['status'] = 'failed'
        report['errors'].append({'error': traceback.format_exc()})
    print(json.dumps(report, sort_keys=True, indent=2), flush=True)
    return {'observed_not_approved': 0, 'observed_with_gaps': 2, 'failed': 3}[report['status']]


if __name__ == '__main__': raise SystemExit(main())
