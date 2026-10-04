"""Opt-in read-only Linux observations. No installs, service operations or network.

Writes JSON to stdout only. This is NOT an authorizer or a complete runtime-closure
resolver. No Docker/weight/model code is invoked, even for version reporting.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import sysconfig
import time

EXECUTABLES = ('/usr/bin/python3', '/usr/bin/systemctl', '/usr/bin/systemd-run',
               '/usr/bin/busctl', '/usr/bin/dockerd', '/usr/bin/containerd',
               '/usr/bin/runc', '/usr/bin/fallocate', '/usr/sbin/mkfs.ext4',
               '/usr/sbin/losetup', '/usr/bin/mount', '/usr/bin/umount', '/usr/sbin/blkid')
FILES = ('/etc/os-release', '/proc/sys/kernel/random/boot_id', '/proc/self/cgroup',
         '/proc/self/mountinfo', '/proc/1/comm', '/proc/self/status',
         '/sys/kernel/security/lsm', '/sys/module/apparmor/parameters/enabled',
         '/sys/module/loop/parameters/max_loop')
PATHS = ('/var/tmp', '/var/lib', '/var/lib/pv2-acceptance', '/opt',
         '/opt/pv2-native-acceptance', '/run', '/run/pv2-authorization', '/dev/loop-control')


def require(value, why):
    if not value: raise ValueError(why)


def mounts(text):
    rows = []
    def unescape(s):
        for a, b in ((r'\040', ' '), (r'\011', '\t'), (r'\012', '\n'), (r'\134', '\\')): s = s.replace(a, b)
        return s
    for line in text.splitlines():
        left, right = line.split(' - ', 1); a, b = left.split(), right.split()
        rows.append({'id': int(a[0]), 'device': a[2], 'root': unescape(a[3]), 'mount': unescape(a[4]),
                     'options': a[5], 'filesystem': b[0], 'source': unescape(b[1]), 'super_options': b[2]})
    return rows


class Reader:
    def __init__(self):
        self.end = time.monotonic()+180
        self.hashed = 0
        self.runtime_rejections = []
    def remaining(self):
        left = self.end-time.monotonic(); require(left > 0, 'collection deadline'); return left
    def text(self, path):
        self.remaining()
        with open(path, 'rb') as f: raw = f.read(2*1024*1024+1)
        require(len(raw) <= 2*1024*1024, 'metadata bound'); self.remaining()
        return raw.decode('utf-8')
    def artifact(self, path):
        resolved = os.path.realpath(path); s = os.stat(resolved)
        require(stat.S_ISREG(s.st_mode), 'artifact is not regular')
        h = hashlib.sha256()
        with open(resolved, 'rb') as f:
            before = os.fstat(f.fileno())
            while True:
                self.remaining(); block = f.read(65536)
                if not block: break
                self.hashed += len(block); require(self.hashed <= 2*1024**3, 'aggregate hashing bound')
                h.update(block)
            after = os.fstat(f.fileno())
        require((s.st_dev, s.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'artifact changed')
        return {'resolved_path': resolved, 'sha256': h.hexdigest(), 'size_bytes': after.st_size,
                'uid': after.st_uid, 'mode': oct(stat.S_IMODE(after.st_mode)), 'inode': after.st_ino, 'device': after.st_dev}
    def path(self, path):
        s = os.lstat(path); fs = os.statvfs(path)
        return {'resolved_path': os.path.realpath(path), 'uid': s.st_uid, 'mode': oct(stat.S_IMODE(s.st_mode)),
                'symlink': stat.S_ISLNK(s.st_mode), 'device': os.stat(path).st_dev, 'inode': s.st_ino,
                'capacity_bytes': fs.f_blocks*fs.f_frsize, 'free_bytes': fs.f_bavail*fs.f_frsize,
                'free_inodes': fs.f_favail}
    def command(self, argv):
        # No arbitrary executable, shell, Docker API, ldd or loader invocation.
        ok = (argv[:2] == ['/usr/bin/dpkg-query', '--show'] or
              argv[:2] == ['/usr/bin/dpkg-query', '--search'] or
              argv == ['/usr/bin/systemctl', '--version'] or
              (len(argv) == 4 and argv[:3] == ['/usr/bin/readelf', '-l', '-d']))
        require(ok, 'command outside metadata allowlist')
        deadline = time.monotonic()+min(5, self.remaining())
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env={'PATH': '/usr/bin:/usr/sbin', 'LANG': 'C'}, close_fds=True)
        output = bytearray()
        primary = None
        try:
            os.set_blocking(proc.stdout.fileno(), False)
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    left = deadline-time.monotonic(); require(left > 0, 'metadata command deadline')
                    if not sel.select(min(left, .1)): continue
                    block = os.read(proc.stdout.fileno(), 65536)
                    if not block: break
                    output.extend(block); require(len(output) <= 1024*1024, 'command output bound')
            code = proc.wait(timeout=max(.001, deadline-time.monotonic()))
            require(time.monotonic() <= deadline, 'command overrun')
            return {'argv': argv, 'exit_code': code, 'text': output.decode('utf-8')}
        except BaseException as exc:
            primary = exc
            raise
        finally:
            if proc.poll() is None:
                cleanup = []
                try: proc.kill()
                except BaseException as exc: cleanup.append('kill: '+repr(exc))
                try: proc.wait(timeout=1)
                except BaseException as exc: cleanup.append('wait: '+repr(exc))
                if cleanup:
                    if primary is None: raise RuntimeError('metadata cleanup unconfirmed: '+repr(cleanup))
                    primary.args = (*primary.args, 'metadata cleanup unconfirmed: '+repr(cleanup))
    def runtime_paths(self):
        # Conservative Python candidate set; not native dependency closure proof.
        # Reject outside-root candidates individually, but continue collecting
        # in-root candidates so one out-of-policy path does not erase the safe
        # runtime inventory. Rejected candidates are never passed to artifact().
        paths = set()
        sources = {}
        def add_candidate(path, origin):
            resolved = os.path.realpath(path)
            paths.add(resolved)
            source = {'origin': origin, 'path': path}
            if source not in sources.setdefault(resolved, []): sources[resolved].append(source)
        base = sysconfig.get_path('stdlib')
        for root, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in ('site-packages', 'dist-packages') and not os.path.islink(os.path.join(root, d)))
            for name in sorted(files):
                self.remaining()
                if name.endswith(('.py', '.pyc', '.so')): add_candidate(os.path.join(root, name), 'stdlib_walk')
                require(len(paths) <= 12000, 'runtime candidate count')
        for line in self.text('/proc/self/maps').splitlines():
            parts = line.split(None, 5)
            if len(parts) == 6 and parts[5].startswith('/'):
                require(not parts[5].endswith(' (deleted)'), 'deleted mapped runtime file')
                add_candidate(parts[5], 'proc_self_maps')
        for entry in sys.path:
            if entry.endswith('.zip') and os.path.isfile(entry): add_candidate(entry, 'sys_path_zip')
        add_candidate(sys.executable, 'sys_executable')
        roots = ('/usr/lib/', '/usr/lib64/', '/usr/local/lib/', '/usr/bin/', '/usr/local/bin/', '/lib/', '/lib64/')
        approved = []
        self.runtime_rejections = []
        for path in sorted(paths):
            if path.startswith(roots):
                approved.append(path)
                continue
            self.runtime_rejections.append({
                'resolved_candidate_path': path,
                'candidate_sources': sorted(sources[path], key=lambda x: (x['origin'], x['path'])),
                'approved_roots': list(roots),
                'candidate_hashed': False,
                'validation_stage': 'runtime_paths_before_artifact_hashing'})
        return approved


def capture_runtime_candidates(reader, report):
    """Hash only allowlisted runtime paths and preserve each rejected path."""
    try:
        for path in reader.runtime_paths():
            try:
                report['runtime_candidates'][path] = reader.artifact(path)
            except Exception as exc:
                report['errors'].append({'item': path, 'error': repr(exc)})
        for context in reader.runtime_rejections:
            report['errors'].append({
                'item': 'runtime enumeration',
                'error': 'runtime candidate outside approved OS roots; candidate not hashed',
                'context': context})
    except Exception as exc:
        report['errors'].append({'item': 'runtime enumeration', 'error': repr(exc)})


def collect(reader, identity, stage):
    report = {'schema': 'pv2_host_observation_v1', 'stage': stage, 'identity': identity, 'files': {},
              'paths': {}, 'executables': {}, 'runtime_candidates': {}, 'metadata': {}, 'errors': [],
              'runtime_closure_reviewed': False, 'execution_approved': False, 'security_approved': False,
              'dependencies_approved': False, 'pilot_execution_authorized': False, 'stage_b': 'paused',
              'launcher_inventory_ready': False}
    def capture(section, key, fn):
        try:
            value = fn(); report[section][key] = value
            if isinstance(value, dict) and value.get('exit_code', 0) != 0:
                report['errors'].append({'item': key, 'error': 'metadata command nonzero', 'exit_code': value['exit_code']})
        except Exception as exc: report['errors'].append({'item': key, 'error': repr(exc)})
    for path in FILES: capture('files', path, lambda p=path: reader.text(p))
    # Limit process status to readiness/security fields, not process environment.
    if '/proc/self/status' in report['files']:
        report['files']['/proc/self/status'] = '\n'.join(x for x in report['files']['/proc/self/status'].splitlines()
            if x.startswith(('Uid:', 'Gid:', 'CapEff:', 'NoNewPrivs:', 'Seccomp:', 'Seccomp_filters:')))
    for path in PATHS: capture('paths', path, lambda p=path: reader.path(p))
    for path in EXECUTABLES:
        capture('executables', path, lambda p=path: reader.artifact(p))
        capture('metadata', 'owner:'+path, lambda p=path: reader.command(['/usr/bin/dpkg-query', '--search', p]))
        if path in report['executables']:
            target = report['executables'][path]['resolved_path']
            capture('metadata', 'owner-resolved:'+path, lambda p=target: reader.command(['/usr/bin/dpkg-query', '--search', p]))
            capture('metadata', 'elf:'+path, lambda p=target: reader.command(['/usr/bin/readelf', '-l', '-d', p]))
    capture('metadata', 'packages', lambda: reader.command(['/usr/bin/dpkg-query', '--show',
        '--showformat=${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Status}\n']))
    capture('metadata', 'systemd', lambda: reader.command(['/usr/bin/systemctl', '--version']))
    for path in ('/usr/bin/dpkg-query', '/usr/bin/readelf', '/etc/os-release'):
        capture('metadata', 'collector-artifact:'+path, lambda p=path: reader.artifact(p))
    try:
        rows = mounts(report['files']['/proc/self/mountinfo'])
        report['mounts'] = rows
        cg = [m for m in rows if m['filesystem'] == 'cgroup2']
        require(len(cg) == 1 and cg[0]['root'] == '/', 'requires unambiguous root cgroup-v2 view')
        membership = [x[3:] for x in report['files']['/proc/self/cgroup'].splitlines() if x.startswith('0::')]
        require(len(membership) == 1 and membership[0].startswith('/') and '..' not in membership[0].split('/'), 'cgroup membership')
        for suffix in ('cgroup.controllers', 'cgroup.subtree_control'):
            p = cg[0]['mount']+'/'+suffix; capture('files', p, lambda p=p: reader.text(p))
        for suffix in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max', 'cgroup.events'):
            p = cg[0]['mount'].rstrip('/')+membership[0].rstrip('/')+'/'+suffix
            capture('files', p, lambda p=p: reader.text(p))
    except Exception as exc: report['errors'].append({'item': 'cgroup resolution', 'error': repr(exc)})
    capture_runtime_candidates(reader, report)
    report['status'] = 'observed_with_gaps' if report['errors'] else 'observed_not_approved'
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--collect-read-only', action='store_true', required=True)
    p.add_argument('--stage', choices=('pre-provision', 'post-provision'), required=True)
    args = p.parse_args()
    require(sys.platform == 'linux' and sys.flags.isolated and sys.flags.no_site, 'Linux python -I -S required')
    reader = Reader()
    collector_hash = reader.artifact(__file__)['sha256']
    report = collect(reader, {'architecture': os.uname().machine, 'kernel': os.uname().release,
                    'kernel_version': os.uname().version, 'python_version': '.'.join(map(str, sys.version_info[:3])),
                    'executable': sys.executable}, args.stage)
    report['collector_sha256'] = collector_hash
    raw = json.dumps(report, sort_keys=True, indent=2)
    if len(raw.encode()) > 16*1024*1024:
        print(json.dumps({'status': 'failed_report_bound', 'collector_sha256': collector_hash,
                          'execution_approved': False, 'security_approved': False}), flush=True)
        return 3
    print(raw, flush=True)
    return 0 if report['status'] == 'observed_not_approved' else 2


if __name__ == '__main__': raise SystemExit(main())
