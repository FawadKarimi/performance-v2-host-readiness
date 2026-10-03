"""Read-only observation binding; writes only new evidence sidecars, never forwards."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import traceback

LINK = '/usr/lib/python3.12/sitecustomize.py'
TARGET = '/etc/python3.12/sitecustomize.py'
FLAGS = ('execution_approved', 'security_approved', 'dependencies_approved', 'pilot_execution_authorized')
SCRIPTS = {'collector': ('scripts/collect_native_inventory.py', 'COLLECTOR_SHA256'),
           'diagnostic': ('scripts/diagnose_sitecustomize.py', 'DIAGNOSTIC_SHA256'),
           'binding': ('scripts/sitecustomize_binding.py', 'BINDING_SHA256')}
IDENTITY_ENV = ('GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'GITHUB_JOB',
                'RUNNER_NAME', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH', 'ImageOS', 'ImageVersion')


def require(value, message):
    if not value: raise ValueError(message)


def read_bytes(path, bound=16 * 1024 * 1024):
    require(not path.is_symlink(), 'evidence/source symlink refused')
    with path.open('rb') as stream: data = stream.read(bound + 1)
    require(len(data) <= bound, 'bounded file read exceeded')
    return data


def digest(path): return hashlib.sha256(read_bytes(path)).hexdigest()
def read_json(path): return json.loads(read_bytes(path))


def write_json(path, record):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(record, stream, sort_keys=True, indent=2); stream.write('\n')


def identity():
    result = {key: os.environ.get(key) for key in IDENTITY_ENV}
    require(all(isinstance(v, str) and v for v in result.values()), 'missing run/job/runner/image identity')
    require(result['GITHUB_REPOSITORY'] == 'FawadKarimi/performance-v2-host-readiness', 'repository mismatch')
    require(result['RUNNER_ENVIRONMENT'] == 'github-hosted' and result['RUNNER_OS'] == 'Linux'
            and result['RUNNER_ARCH'] == 'X64' and result['ImageOS'] == 'ubuntu24', 'host class mismatch')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    require(re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}', boot), 'invalid boot identity')
    result['boot_id'] = boot
    return result


def script_hashes():
    result = {}
    for name, (path, variable) in SCRIPTS.items():
        actual = digest(Path(path)); expected = os.environ[variable]
        require(actual == expected, name + ' reviewed script hash mismatch')
        result[name] = actual
    return result


def snapshot(root):
    record = {'identity': identity(), 'script_sha256': script_hashes(), 'stage_b': 'paused',
              **{k: False for k in FLAGS}}
    write_json(root / 'same-job-before.json', record)
    return record


def current(root):
    before = read_json(root / 'same-job-before.json')
    require(before['identity'] == identity(), 'run/attempt/commit/job/runner/image/boot changed')
    require(before['script_sha256'] == script_hashes(), 'script binding changed')
    return before


def validate_report(report):
    require(all(report[k] is False for k in FLAGS) and report['stage_b'] == 'paused', 'approval state mismatch')


def exact_pair(report):
    # No text substring matching, guessing, or arbitrary path parameter.
    hits = []
    for entry in report['errors']:
        context = entry.get('context', {})
        if (entry.get('item') == 'runtime enumeration'
                and context.get('resolved_candidate_path') == TARGET
                and context.get('candidate_sources') == [{'origin': 'stdlib_walk', 'path': LINK}]
                and context.get('candidate_hashed') is False
                and context.get('validation_stage') == 'runtime_paths_before_artifact_hashing'):
            hits.append(entry)
    require(len(hits) <= 1, 'duplicate exact rejection is ambiguous')
    return len(hits) == 1


def inventory_observation(root, before):
    report = read_json(root / 'raw.json')
    rc = int(read_bytes(root / 'exit-status.txt', 32).strip())
    require(rc in (0, 2), 'inventory failed/timed out; diagnostic forbidden')
    require(report['schema'] == 'pv2_host_observation_v1' and report['stage'] == 'pre-provision', 'inventory scope')
    require(report['status'] == {0: 'observed_not_approved', 2: 'observed_with_gaps'}[rc], 'inventory status mismatch')
    validate_report(report)
    require(report['runtime_closure_reviewed'] is False and report['launcher_inventory_ready'] is False,
            'inventory approval state mismatch')
    require(report['collector_sha256'] == before['script_sha256']['collector'], 'collector binding mismatch')
    require(report['files']['/proc/sys/kernel/random/boot_id'].strip() == before['identity']['boot_id'],
            'inventory boot does not match same job')
    require(report['identity']['executable'] == '/usr/bin/python3' and report['identity']['architecture'] == 'x86_64',
            'inventory runtime mismatch')
    required = exact_pair(report)
    require(not required or rc == 2, 'rejection must be observed with gaps')
    return required


def gate(root):
    before = current(root)
    required = inventory_observation(root, before)
    record = {**before, 'inventory_report_sha256': digest(root / 'raw.json'),
              'inventory_exit_sha256': digest(root / 'exit-status.txt'),
              'diagnostic_required': required,
              'decision': 'exact_pair_observed' if required else 'not_invoked_exact_pair_not_observed'}
    write_json(root / 'inventory-binding.json', record)
    return record


def prediagnostic(root):
    before = current(root); record = read_json(root / 'inventory-binding.json')
    require(record['identity'] == before['identity'] and record['script_sha256'] == before['script_sha256'], 'gate identity mismatch')
    require(record['inventory_report_sha256'] == digest(root / 'raw.json') and
            record['inventory_exit_sha256'] == digest(root / 'exit-status.txt'), 'inventory changed after gate')
    require(record['diagnostic_required'] is True and inventory_observation(root, before), 'exact pair gate not satisfied')
    write_json(root / 'diagnostic-before.json', {**before, 'inventory_binding_sha256': digest(root / 'inventory-binding.json')})


def after(root):
    before = current(root)
    diagnostic_before = read_json(root / 'diagnostic-before.json')
    require(diagnostic_before['identity'] == before['identity'], 'diagnostic before identity mismatch')
    require(diagnostic_before['inventory_binding_sha256'] == digest(root / 'inventory-binding.json'), 'gate changed')
    gate_record = read_json(root / 'inventory-binding.json')
    require(gate_record['inventory_report_sha256'] == digest(root / 'raw.json'), 'inventory report changed')
    report = read_json(root / 'diagnostic.json')
    rc = int(read_bytes(root / 'diagnostic-exit-status.txt', 32).strip())
    require(rc in (0, 2), 'diagnostic failed/timed out; partial evidence retained')
    require(report['schema'] == 'pv2_exact_sitecustomize_diagnostic_v1', 'diagnostic scope mismatch')
    require(report['status'] == {0: 'observed_not_approved', 2: 'observed_with_gaps'}[rc], 'diagnostic status mismatch')
    validate_report(report)
    expected_runtime = {k: before['identity'][v] for k, v in {
        'run_id': 'GITHUB_RUN_ID', 'run_attempt': 'GITHUB_RUN_ATTEMPT', 'commit': 'GITHUB_SHA',
        'job': 'GITHUB_JOB', 'runner': 'RUNNER_NAME', 'boot_id': 'boot_id'}.items()}
    require(all(report['runtime'].get(k) == v for k, v in expected_runtime.items()), 'diagnostic host binding mismatch')
    require([row['path'] for row in report['chain']] == [LINK, TARGET], 'diagnostic chain scope')
    require(set(report['source']) == {'bytes', 'sha256', 'policy'}, 'source privacy schema')
    record = {**before, 'inventory_report_sha256': digest(root / 'raw.json'),
              'diagnostic_report_sha256': digest(root / 'diagnostic.json'),
              'diagnostic_exit_sha256': digest(root / 'diagnostic-exit-status.txt'),
              'inventory_binding_sha256': digest(root / 'inventory-binding.json'),
              'status': 'same_job_observations_bound_not_approved'}
    write_json(root / 'diagnostic-binding.json', record)
    return record


def verify(root):
    before = current(root); gate_record = read_json(root / 'inventory-binding.json')
    require(gate_record['identity'] == before['identity'] and gate_record['script_sha256'] == before['script_sha256'], 'final identity')
    require(gate_record['inventory_report_sha256'] == digest(root / 'raw.json') and
            gate_record['inventory_exit_sha256'] == digest(root / 'exit-status.txt'), 'final inventory integrity')
    required = inventory_observation(root, before)
    require(gate_record['diagnostic_required'] is required, 'final gate mismatch')
    if required:
        record = read_json(root / 'diagnostic-binding.json')
        require(record['identity'] == before['identity'] and record['script_sha256'] == before['script_sha256'], 'final diagnostic identity')
        require(record['diagnostic_report_sha256'] == digest(root / 'diagnostic.json') and
                record['diagnostic_exit_sha256'] == digest(root / 'diagnostic-exit-status.txt') and
                record['inventory_report_sha256'] == digest(root / 'raw.json') and
                record['inventory_binding_sha256'] == digest(root / 'inventory-binding.json'), 'final pairing integrity')
    else:
        require(not any((root / name).exists() for name in ('diagnostic-before.json', 'diagnostic.json',
                     'diagnostic-exit-status.txt', 'diagnostic-binding.json')), 'unexpected diagnostic execution evidence')
    return required


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=('snapshot', 'gate', 'prediagnostic', 'after', 'verify'))
    phase = parser.parse_args().phase
    root = Path(os.environ['EVIDENCE'])
    try:
        result = globals()[phase](root)
        if phase == 'gate':
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
                stream.write('required=' + str(result['diagnostic_required']).lower() + '\n')
        return 0
    except Exception:
        record = {'phase': phase, 'error': traceback.format_exc(), 'stage_b': 'paused', **{k: False for k in FLAGS}}
        try: write_json(root / ('binding-' + phase + '-failure.json'), record)
        finally: print(json.dumps(record, sort_keys=True), flush=True)
        return 1


if __name__ == '__main__': raise SystemExit(main())
