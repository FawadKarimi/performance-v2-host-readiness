"""Read-only package-record and cgroup-ancestry evidence for the same Actions job.

Never imports or executes the observed sitecustomize target, writes only one new
JSON evidence file, and never creates cgroups or invokes Docker.
"""
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import sys

LINK = '/usr/lib/python3.12/sitecustomize.py'
TARGET = '/etc/python3.12/sitecustomize.py'
PACKAGE = 'libpython3.12-minimal:amd64'
PACKAGE_MANIFEST = '/var/lib/dpkg/info/libpython3.12-minimal:amd64.md5sums'
MAX_TARGET_BYTES = 4 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
LIMITS = ('cpu.max', 'memory.max', 'memory.swap.max', 'pids.max',
          'cpuset.cpus.effective', 'memory.current', 'pids.current')
FLAGS = {'execution_approved': False, 'security_approved': False,
         'dependencies_approved': False, 'pilot_execution_authorized': False,
         'stage_b': 'paused'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def parse_membership(text):
    rows = [line[3:] for line in text.splitlines() if line.startswith('0::')]
    require(len(rows) == 1, 'expected one cgroup-v2 membership')
    value = rows[0]
    require(canonical_absolute_path(value), 'invalid cgroup membership')
    return value


def canonical_absolute_path(value):
    return (isinstance(value, str) and value.startswith('/') and '\x00' not in value and
            (value == '/' or all(part not in ('', '.', '..') for part in value[1:].split('/'))))


def ancestry(mountpoint, mount_root, membership):
    """Map a cgroup membership to mount-relative ancestors, root first."""
    require(canonical_absolute_path(mountpoint) and
            (mountpoint == '/sys/fs/cgroup' or mountpoint.startswith('/sys/fs/cgroup/')),
            'unexpected cgroup mountpoint')
    require(canonical_absolute_path(mount_root), 'invalid cgroup mount root')
    require(canonical_absolute_path(membership), 'invalid cgroup membership')
    require(membership == mount_root or membership.startswith(mount_root.rstrip('/') + '/'),
            'membership is outside the mounted cgroup subtree')
    relative = posixpath.relpath(membership, mount_root)
    parts = [] if relative == '.' else relative.split('/')
    require(all(p not in ('', '.', '..') for p in parts), 'invalid cgroup path components')
    paths = [mountpoint]
    current = mountpoint
    for part in parts:
        current = posixpath.join(current, part)
        paths.append(current)
    require(all(os.path.commonpath((mountpoint, p)) == mountpoint for p in paths), 'cgroup path escaped mount')
    return paths


def parse_cpu_max(value):
    bits = value.split()
    require(len(bits) == 2 and bits[1].isdigit() and int(bits[1]) > 0, 'invalid cpu.max')
    if bits[0] == 'max':
        return None
    require(bits[0].isdigit() and int(bits[0]) > 0, 'invalid cpu quota')
    return int(bits[0]) / int(bits[1])


def parse_limit(value):
    value = value.strip()
    if value == 'max':
        return None
    require(value.isdigit(), 'invalid numeric cgroup limit')
    return int(value)


def parse_cpuset(value):
    cpus = set()
    for part in value.strip().split(','):
        bits = part.split('-')
        require(len(bits) in (1, 2) and all(x.isdigit() for x in bits), 'invalid cpuset')
        lo = int(bits[0]); hi = int(bits[-1])
        require(0 <= lo <= hi and hi <= 1_000_000, 'cpuset range out of bound')
        cpus.update(range(lo, hi + 1))
        require(len(cpus) <= 1_000_000, 'cpuset expansion bound')
    require(bool(cpus), 'empty cpuset')
    return cpus


def effective_caps(levels):
    cpu = [parse_cpu_max(x['cpu.max']) for x in levels if 'cpu.max' in x]
    memory = [parse_limit(x['memory.max']) for x in levels if 'memory.max' in x]
    pids = [parse_limit(x['pids.max']) for x in levels if 'pids.max' in x]
    cpus = [parse_cpuset(x['cpuset.cpus.effective']) for x in levels if x.get('cpuset.cpus.effective')]
    cpu = [x for x in cpu if x is not None]
    memory = [x for x in memory if x is not None]
    pids = [x for x in pids if x is not None]
    quota_cores = min(cpu) if cpu else None
    # A missing leaf value must not be mislabeled as the current process cpuset.
    current_cpuset = (len(cpus[-1]) if cpus and
                      'cpuset.cpus.effective' in levels[-1] else None)
    # Any observed ancestor cpuset is an upper bound on its descendants.
    observed_cpuset_bound = min((len(x) for x in cpus), default=None)
    capacities = [x for x in (quota_cores,
                              float(observed_cpuset_bound) if observed_cpuset_bound is not None else None)
                  if x is not None]
    return {'minimum_finite_cpu_quota_cores': quota_cores,
            'current_effective_cpuset_cpu_count': current_cpuset,
            'minimum_observed_ancestor_or_leaf_cpuset_count': observed_cpuset_bound,
            'upper_bound_cpu_capacity_cores': min(capacities) if capacities else None,
            'minimum_finite_memory_bytes': min(memory) if memory else None,
            'minimum_finite_pids': min(pids) if pids else None,
            'interpretation': ('read-only, non-atomic observations of quota/cpuset ceilings; sibling consumption at shared ancestors is not measured; '
                               'does not prove child-cgroup delegation or enforcement')}


def package_md5_record(manifest_text, relative_path):
    matches = []
    for line in manifest_text.splitlines():
        fields = line.split(None, 1)
        if len(fields) == 2 and fields[1].lstrip('*') == relative_path:
            matches.append(fields[0].lower())
    require(len(matches) == 1 and re.fullmatch(r'[0-9a-f]{32}', matches[0]),
            'expected exactly one package checksum record')
    return matches[0]


def read_bounded(path, bound):
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'metadata input is not a regular file')
        raw = bytearray()
        while len(raw) <= bound:
            block = os.read(fd, min(65536, bound + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
        require(len(raw) <= bound, 'bounded read exceeded')
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'file changed during read')
        return bytes(raw), after
    finally:
        os.close(fd)


def hash_target():
    require(os.readlink(LINK) == TARGET, 'sitecustomize link text differs from reviewed exact pair')
    resolved = os.path.realpath(LINK)
    require(resolved == TARGET and os.path.realpath(TARGET) == TARGET,
            'sitecustomize target does not match exact reviewed path')
    raw, st = read_bounded(TARGET, MAX_TARGET_BYTES)
    return {'link': LINK, 'link_text': TARGET, 'resolved_target': resolved,
            'target_metadata': {'uid': st.st_uid, 'gid': st.st_gid, 'mode': oct(stat.S_IMODE(st.st_mode)),
                                'size_bytes': st.st_size, 'device': st.st_dev, 'inode': st.st_ino},
            'target_sha256': hashlib.sha256(raw).hexdigest(),
            'target_md5': hashlib.md5(raw, usedforsecurity=False).hexdigest(),
            'target_contents_disclosed': False, 'target_imported_or_executed': False}


def package_integrity(raw_report):
    package_metadata = raw_report.get('metadata', {}).get('packages', {})
    package_text = package_metadata.get('text') if isinstance(package_metadata, dict) else None
    require(isinstance(package_text, str), 'collector package metadata missing')
    package_rows = [line.split('\t') for line in package_text.splitlines()
                    if line.split('\t', 1)[0] == PACKAGE]
    require(len(package_rows) == 1 and len(package_rows[0]) == 6 and package_rows[0][5] == 'installed',
            'expected one installed package record')
    raw, st = read_bounded(PACKAGE_MANIFEST, MAX_METADATA_BYTES)
    require(st.st_uid == 0 and stat.S_IMODE(st.st_mode) & 0o022 == 0,
            'installed package checksum record has unexpected owner/mode')
    text = raw.decode('utf-8', errors='strict')
    expected = package_md5_record(text, 'etc/python3.12/sitecustomize.py')
    observed = hash_target()
    observed['package'] = PACKAGE
    observed['package_version'] = package_rows[0][1]
    observed['package_architecture'] = package_rows[0][2]
    observed['installed_manifest'] = PACKAGE_MANIFEST
    observed['installed_manifest_sha256'] = hashlib.sha256(raw).hexdigest()
    observed['installed_manifest_metadata'] = {'uid': st.st_uid, 'mode': oct(stat.S_IMODE(st.st_mode))}
    observed['manifest_expected_md5'] = expected
    observed['local_package_record_match'] = observed['target_md5'] == expected
    observed['publisher_signature_verified'] = False
    observed['interpretation'] = ('matches the installed local dpkg checksum record; this is not independent '
                                  'publisher/signature verification')
    return observed


def cgroup_observation(raw_report):
    mounts = [m for m in raw_report.get('mounts', []) if m.get('filesystem') == 'cgroup2']
    require(len(mounts) == 1, 'expected one cgroup-v2 mount in collector record')
    membership_text = raw_report.get('files', {}).get('/proc/self/cgroup')
    require(isinstance(membership_text, str), 'collector cgroup membership unavailable')
    collector_member = parse_membership(membership_text)
    process_membership_raw, _ = read_bounded('/proc/self/cgroup', MAX_METADATA_BYTES)
    process_member = parse_membership(process_membership_raw.decode('utf-8', errors='strict'))
    paths = ancestry(mounts[0]['mount'], mounts[0]['root'], process_member)
    levels = []
    for path in paths:
        entry = {'path': path, 'limits': {}, 'read_errors': {}}
        for name in LIMITS:
            full = posixpath.join(path, name)
            try:
                data, _ = read_bounded(full, 4096)
                entry['limits'][name] = data.decode('ascii', errors='strict').strip()
            except (OSError, ValueError, UnicodeError) as exc:
                entry['read_errors'][name] = type(exc).__name__
        levels.append(entry)
    required_fields = ('cpu.max', 'memory.max', 'memory.swap.max', 'pids.max')
    missing_critical = [{'path': x['path'], 'file': name}
                        for x in levels for name in required_fields
                        if name not in x['limits']]
    if 'cpuset.cpus.effective' not in levels[-1]['limits']:
        missing_critical.append({'path': levels[-1]['path'], 'file': 'cpuset.cpus.effective'})
    process_membership_after, _ = read_bounded('/proc/self/cgroup', MAX_METADATA_BYTES)
    stable = process_membership_after == process_membership_raw
    return {'collector_membership': collector_member,
            'supplemental_process_membership': process_member,
            'membership_matches_collector': process_member == collector_member,
            'supplemental_membership_stable_during_observation': stable,
            'mount': {'path': mounts[0]['mount'], 'root': mounts[0]['root']},
            'ancestors_root_to_current': levels,
            'effective_caps': effective_caps([x['limits'] for x in levels]),
            'critical_limit_chain_complete': not missing_critical,
            'missing_critical_limits': missing_critical,
            'child_cgroup_creation_tested': False, 'resource_controls_mutated': False}


def identity():
    keys = ('GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'GITHUB_JOB',
            'RUNNER_NAME', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH', 'ImageOS', 'ImageVersion')
    value = {k: os.environ.get(k) for k in keys}
    require(all(isinstance(v, str) and v for v in value.values()), 'missing workflow identity')
    value['boot_id'] = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    return value


def main():
    require(sys.platform == 'linux' and sys.flags.isolated and sys.flags.no_site,
            'run with Linux Python -I -S')
    root = Path(os.environ['EVIDENCE'])
    raw_path = root / 'raw.json'
    raw_bytes, _ = read_bounded(str(raw_path), 16 * 1024 * 1024)
    raw = json.loads(raw_bytes)
    current_identity = identity()
    script_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    require(script_hash == os.environ['SUPPLEMENTAL_SHA256'], 'supplemental script hash mismatch')
    before_bytes, _ = read_bounded(str(root / 'same-job-before.json'), 1024 * 1024)
    before = json.loads(before_bytes)
    require(before.get('identity') == current_identity, 'same-job identity changed')
    raw_boot = raw.get('files', {}).get('/proc/sys/kernel/random/boot_id', '').strip()
    require(raw_boot == current_identity['boot_id'], 'collector boot identity mismatch')
    inv_binding_bytes, _ = read_bounded(str(root / 'inventory-binding.json'), 1024 * 1024)
    inv_binding = json.loads(inv_binding_bytes)
    raw_hash = hashlib.sha256(raw_bytes).hexdigest()
    inventory_exit_bytes, _ = read_bounded(str(root / 'exit-status.txt'), 32)
    require(inv_binding.get('identity') == current_identity and
            inv_binding.get('inventory_report_sha256') == raw_hash and
            inv_binding.get('inventory_exit_sha256') == hashlib.sha256(inventory_exit_bytes).hexdigest(),
            'inventory binding mismatch')
    links = {'same_job_before_sha256': hashlib.sha256(before_bytes).hexdigest(),
             'inventory_binding_sha256': hashlib.sha256(inv_binding_bytes).hexdigest(),
             'inventory_report_sha256': raw_hash,
             'inventory_exit_sha256': hashlib.sha256(inventory_exit_bytes).hexdigest()}
    diag_path = root / 'diagnostic-binding.json'
    if diag_path.exists():
        diag_bytes, _ = read_bounded(str(diag_path), 1024 * 1024)
        diag = json.loads(diag_bytes)
        diagnostic_path = root / 'diagnostic.json'
        diagnostic_bytes, _ = read_bounded(str(diagnostic_path), 16 * 1024 * 1024)
        diagnostic_exit_bytes, _ = read_bounded(str(root / 'diagnostic-exit-status.txt'), 32)
        require(diag.get('identity') == current_identity and diag.get('inventory_report_sha256') == raw_hash,
                'diagnostic binding mismatch')
        require(diag.get('diagnostic_report_sha256') == hashlib.sha256(diagnostic_bytes).hexdigest() and
                diag.get('diagnostic_exit_sha256') == hashlib.sha256(diagnostic_exit_bytes).hexdigest(),
                'diagnostic evidence hash mismatch')
        links['diagnostic_binding_sha256'] = hashlib.sha256(diag_bytes).hexdigest()
        links['diagnostic_report_sha256'] = hashlib.sha256(diagnostic_bytes).hexdigest()
        links['diagnostic_exit_sha256'] = hashlib.sha256(diagnostic_exit_bytes).hexdigest()
    require(inv_binding.get('diagnostic_required') is (diag_path.exists()),
            'diagnostic evidence presence does not match gate')
    record = {'schema': 'pv2_supplemental_host_evidence_v1', 'identity': current_identity,
              'script_sha256': script_hash, 'bindings': links,
              'local_package_record_comparison': None, 'cgroup': None, 'errors': [], **FLAGS,
              'read_only': True, 'docker_invoked': False, 'training_performed': False}
    try:
        record['local_package_record_comparison'] = package_integrity(raw)
    except Exception as exc:
        record['errors'].append({'item': 'sitecustomize local package record comparison', 'error': type(exc).__name__})
    try:
        record['cgroup'] = cgroup_observation(raw)
        if not record['cgroup']['critical_limit_chain_complete']:
            record['errors'].append({'item': 'cgroup ancestry', 'error': 'critical limit missing at one or more hierarchy levels'})
        if not record['cgroup']['membership_matches_collector']:
            record['errors'].append({'item': 'cgroup ancestry', 'error': 'collector and supplemental process memberships differ'})
        if not record['cgroup']['supplemental_membership_stable_during_observation']:
            record['errors'].append({'item': 'cgroup ancestry', 'error': 'supplemental process membership changed during observation'})
    except Exception as exc:
        record['errors'].append({'item': 'cgroup ancestry', 'error': type(exc).__name__})
    record['status'] = 'observed_not_approved' if not record['errors'] else 'observed_with_gaps'
    output = root / 'supplemental-host-evidence.json'
    with output.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(record, f, sort_keys=True, indent=2); f.write('\n')
    print(json.dumps({'status': record['status'], 'errors': record['errors'],
                      'publisher_signature_verified': False, 'child_cgroup_creation_tested': False}, sort_keys=True))
    return 0 if record['status'] == 'observed_not_approved' else 2


if __name__ == '__main__':
    raise SystemExit(main())
