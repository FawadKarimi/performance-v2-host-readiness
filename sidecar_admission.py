"""Sidecar-only local admission; this module never makes network requests.

Historical discovery approvals are insufficient. Future admission requires new
reviewed records and a supplied, hash-bound API identity snapshot. Snapshot
provenance is an explicit reviewer prerequisite, not implied by its digest.
"""
import datetime as dt
import hashlib
import os
from pathlib import Path
import re

import admission
import collector
import output_security
import runtime_acceptance

PROPOSAL_SHA256 = 'ad7c7e726ba0c5df2ecd74c601f9036570c5bbc92206f7e98dda230d6054fe9b'
SCOPE = '7_hash_bound_metadata_gets_only'
SCHEMA = 'pv2_sidecar_admission_v1'
TRANSPORT_SCHEMA = 'pv2_sidecar_transport_acceptance_v1'
SOURCE_FILES = ('sidecar_contract.py', 'sidecar_metadata.py', 'sidecar_transport.py',
                'sidecar_collector.py', 'sidecar_supervisor.py', 'sidecar_admission.py',
                'admission.py', 'collector.py', 'runtime_acceptance.py',
                'output_security.py', 'worker_diagnostics.py')
APPROVALS = ('owner_authorized', 'independent_workflow_reviewed',
             'sidecar_transport_reviewed', 'run_identity_evidence_reviewed',
             'zero_paid_usage_confirmed', 'same_uid_residual_risk_accepted')
FALSE_FLAGS = ('security_approved', 'pilot_execution_authorized',
               'research_execution_authorized', 'artifact_acquisition_authorized',
               'training_authorized', 'installation_authorized', 'automatic_recursion_authorized',
               'execution_approved', 'dependency_closure_complete', 'full_docker_acceptance')
TRANSPORT_APPROVALS = ('sidecar_transport_accepted', 'owner_accepted',
                      'independent_review_accepted', 'metadata_scope_security_disposition_accepted')
REPOSITORY = 'FawadKarimi/performance-v2-host-readiness'
REPOSITORY_ID = 1392457611
OWNER_ID = 108207574


def need(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def is_hash(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def read_record(path, expected_hash, cap, code):
    need(is_hash(expected_hash), code + '_hash_missing')
    with Path(path).open('rb') as stream:
        raw = stream.read(cap + 1)
    need(len(raw) <= cap, code + '_size')
    need(sha(raw) == expected_hash, code + '_hash_mismatch')
    obj = collector.strict_json(raw)
    need(type(obj) is dict, code + '_object')
    return obj


def utc(value):
    need(isinstance(value, str), 'admission_time_format')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('admission_time_format') from None
    need(parsed.utcoffset() == dt.timedelta(0), 'admission_utc_required')
    return parsed


def source_hashes(source_dir):
    root = Path(source_dir)
    result = {}
    for name in SOURCE_FILES:
        path = root / name
        need(path.is_file() and not path.is_symlink(), 'source_layout_rejected')
        result[name] = sha(path.read_bytes())
    return result


def authorization_template():
    record = dict(schema=SCHEMA, scope=SCOPE, proposal_sha256=PROPOSAL_SHA256)
    record.update({name: False for name in APPROVALS + FALSE_FLAGS})
    record.update({name: None for name in ('source_hashes', 'runtime_acceptance_sha256',
        'transport_acceptance_sha256', 'context', 'workflow_path', 'workflow_sha256',
        'workflow_id', 'run_number', 'run_api_file', 'run_api_sha256',
        'run_api_observed_utc', 'issued_utc', 'expires_utc')})
    record['home_default_acl_disposition_accepted'] = False
    return record


def transport_template():
    record = dict(schema=TRANSPORT_SCHEMA, scope=SCOPE, proposal_sha256=PROPOSAL_SHA256)
    record.update({name: False for name in TRANSPORT_APPROVALS + FALSE_FLAGS})
    record.update({name: None for name in ('runtime_acceptance_sha256', 'source_hashes',
        'review_reference', 'security_review_reference', 'native_compatibility_review_reference')})
    return record


def validate_grant(proposal, grant=None):
    # Pure contract validation imports no packaging/email parser and cannot fetch.
    from sidecar_contract import validate_proposal
    validate_proposal(proposal)
    need(type(grant) is dict and grant.get('scope') == SCOPE,
         'sidecar_network_disabled')
    need(grant.get('proposal_sha256') == PROPOSAL_SHA256, 'sidecar_proposal_binding')
    need(all(is_hash(grant.get(name)) for name in ('receipt_sha256',
        'runtime_acceptance_sha256', 'transport_acceptance_sha256', 'run_api_sha256')),
        'sidecar_grant_binding')
    need(all(grant.get(name) is True for name in ('admission_verified',
        'runtime_verified', 'sidecar_transport_verified', 'run_binding_verified',
        'role_claim_verified', 'output_checks_verified')), 'sidecar_grant_unverified')
    need(grant.get('role') in ('parent', 'worker'), 'sidecar_grant_role')
    issued, expires = utc(grant.get('issued_utc')), utc(grant.get('expires_utc'))
    need(issued <= dt.datetime.now(dt.timezone.utc) < expires
         and dt.timedelta(0) < expires - issued <= dt.timedelta(hours=1),
         'sidecar_grant_expired')
    need(type(grant.get('source_hashes')) is dict
         and set(grant['source_hashes']) == set(SOURCE_FILES)
         and all(is_hash(value) for value in grant['source_hashes'].values()),
         'sidecar_source_binding')
    need(all(grant.get(name) is False for name in FALSE_FLAGS), 'sidecar_broader_scope')
    return True


def authorize_network(proposal, grant=None):
    validate_grant(proposal, grant)
    need(grant.get('role') == 'worker', 'sidecar_worker_role_required')
    return True


def verify_run(receipt, context, env, source_dir, folder, now):
    need(receipt.get('context') == context, 'sidecar_context_mismatch')
    need(context.get('repository') == REPOSITORY, 'sidecar_repository')
    need(context.get('event') == 'workflow_dispatch' and context.get('os') == 'Linux'
         and context.get('arch') == 'X64', 'sidecar_runner_event')
    need(all(isinstance(context.get(k), str) and context[k] for k in
         ('repository', 'commit', 'run_id', 'attempt', 'runner', 'boot_id', 'workflow_ref')),
         'sidecar_context_incomplete')
    need(re.fullmatch('[0-9a-f]{40}', context['commit']) is not None
         and re.fullmatch('[1-9][0-9]*', context['run_id']) is not None,
         'sidecar_context_format')
    need(context['attempt'] == env.get('GITHUB_RUN_ATTEMPT') == '1', 'sidecar_attempt_replay')
    need(env.get('GITHUB_ACTOR_ID') == str(OWNER_ID)
         and env.get('GITHUB_TRIGGERING_ACTOR_ID') == str(OWNER_ID), 'sidecar_actor')
    workflow = receipt.get('workflow_path')
    need(isinstance(workflow, str)
         and re.fullmatch(r'\.github/workflows/[A-Za-z0-9_-]+\.ya?ml', workflow) is not None,
         'sidecar_workflow_path')
    need(context['workflow_ref'] == REPOSITORY + '/' + workflow + '@refs/heads/main',
         'sidecar_workflow_ref')
    path = Path(source_dir) / workflow
    need(not path.is_symlink() and path.is_file()
         and sha(path.read_bytes()) == receipt.get('workflow_sha256'), 'sidecar_workflow_hash')
    name = receipt.get('run_api_file')
    need(isinstance(name, str) and re.fullmatch('[A-Za-z0-9_-]+\\.json', name) is not None,
         'sidecar_run_api_path')
    path = folder / name
    need(path.is_file() and not path.is_symlink(), 'sidecar_run_api_layout')
    run = read_record(path, receipt.get('run_api_sha256'), 1048576, 'sidecar_run_api')
    observed = utc(receipt.get('run_api_observed_utc'))
    need(dt.timedelta(0) <= now - observed <= dt.timedelta(minutes=5), 'sidecar_run_snapshot_stale')
    need(type(receipt.get('workflow_id')) is int and receipt['workflow_id'] > 0
         and type(receipt.get('run_number')) is int and receipt['run_number'] > 0,
         'sidecar_run_identity_missing')
    need(str(receipt['run_number']) == env.get('GITHUB_RUN_NUMBER'), 'sidecar_run_number')
    need(type(run.get('id')) is int and run['id'] == int(context['run_id'])
         and type(run.get('run_attempt')) is int and run['run_attempt'] == 1
         and run.get('workflow_id') == receipt['workflow_id']
         and run.get('run_number') == receipt['run_number'], 'sidecar_run_identity')
    need(run.get('repository', {}).get('id') == REPOSITORY_ID
         and run['repository'].get('full_name') == REPOSITORY
         and run['repository'].get('private') is True, 'sidecar_run_repository')
    need(run.get('head_sha') == context['commit'] and run.get('head_branch') == 'main'
         and run.get('event') == 'workflow_dispatch' and run.get('path') == workflow
         and run.get('status') == 'in_progress', 'sidecar_run_state')
    need(run.get('actor', {}).get('id') == OWNER_ID
         and run.get('triggering_actor', {}).get('id') == OWNER_ID, 'sidecar_run_actor')
    return run


def write_claim(path, value):
    raw = (__import__('json').dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        output_security.verify_created(path, fd=stream.fileno())
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def load_grant(proposal_path, receipt_path, expected_raw_hash, source_dir, output,
               env=None, worker=False, runtime_path=None, runtime_hash=None,
               transport_path=None, transport_hash=None, runtime_observe=None):
    env = os.environ if env is None else env
    now = dt.datetime.now(dt.timezone.utc)
    proposal = read_record(proposal_path, PROPOSAL_SHA256, 65536, 'sidecar_proposal')
    from sidecar_contract import validate_proposal
    validate_proposal(proposal)
    receipt = read_record(receipt_path, expected_raw_hash, 65536, 'sidecar_authorization')
    need(receipt.get('schema') == SCHEMA and receipt.get('scope') == SCOPE,
         'sidecar_authorization_scope')
    need(all(receipt.get(name) is True for name in APPROVALS), 'sidecar_approval_missing')
    need(all(receipt.get(name) is False for name in FALSE_FLAGS), 'sidecar_broader_scope')
    need(type(receipt.get('home_default_acl_disposition_accepted', False)) is bool,
         'sidecar_home_acl_disposition')
    need(receipt.get('proposal_sha256') == PROPOSAL_SHA256, 'sidecar_proposal_binding')
    issued, expires = utc(receipt.get('issued_utc')), utc(receipt.get('expires_utc'))
    need(issued <= now < expires and dt.timedelta(0) < expires - issued <= dt.timedelta(hours=1),
         'sidecar_authorization_expired')
    hashes = source_hashes(source_dir)
    need(receipt.get('source_hashes') == hashes, 'sidecar_source_drift')
    need(runtime_path is not None and is_hash(runtime_hash)
         and receipt.get('runtime_acceptance_sha256') == runtime_hash, 'sidecar_runtime_binding')
    runtime = runtime_acceptance.verify_record(runtime_path, runtime_hash, observe=runtime_observe)
    need(transport_path is not None and is_hash(transport_hash)
         and receipt.get('transport_acceptance_sha256') == transport_hash,
         'sidecar_transport_binding')
    transport = read_record(transport_path, transport_hash, 65536, 'sidecar_transport')
    need(transport.get('schema') == TRANSPORT_SCHEMA and transport.get('scope') == SCOPE,
         'sidecar_transport_scope')
    need(all(transport.get(name) is True for name in TRANSPORT_APPROVALS),
         'sidecar_transport_not_accepted')
    need(all(transport.get(name) is False for name in FALSE_FLAGS), 'sidecar_transport_broader_scope')
    need(transport.get('proposal_sha256') == PROPOSAL_SHA256
         and transport.get('runtime_acceptance_sha256') == runtime_hash
         and transport.get('source_hashes') == hashes, 'sidecar_transport_source_binding')
    need(all(isinstance(transport.get(name), str) and transport[name].strip()
         for name in ('review_reference', 'security_review_reference', 'native_compatibility_review_reference')),
         'sidecar_transport_review_missing')
    context = admission.context_from_env(env)
    folder = Path(receipt_path).parent
    verify_run(receipt, context, env, source_dir, folder, now)
    need(folder.parent == Path(env['RUNNER_TEMP'])
         and folder.name == 'sidecar-admission-' + context['run_id'] + '-' + context['attempt'],
         'sidecar_admission_folder_binding')
    need(Path(output).name == 'pypi-evidence-' + context['run_id'] + '-' + context['attempt'],
         'sidecar_output_run_binding')
    policy = admission.output_policy(env['RUNNER_TEMP'], env['GITHUB_WORKSPACE'], output, worker=worker)
    checks = output_security.observe(env['RUNNER_TEMP'], env['GITHUB_WORKSPACE'],
        allow_home_default_acl=receipt.get('home_default_acl_disposition_accepted', False))
    output_security.verify_evidence_folder(folder)
    claim = dict(schema='sidecar_role_claim_v1', receipt_sha256=expected_raw_hash,
                 context=context, output=str(output), proposal_sha256=PROPOSAL_SHA256)
    if worker:
        parent_path = folder / 'sidecar-parent-claimed.json'
        with parent_path.open('rb') as stream:
            raw = stream.read(65537)
        need(len(raw) <= 65536 and collector.strict_json(raw) == claim, 'sidecar_parent_claim')
    claim_path = folder / ('sidecar-worker-claimed.json' if worker else 'sidecar-parent-claimed.json')
    write_claim(claim_path, claim)
    output_security.verify_evidence_folder(folder)
    grant = dict(scope=SCOPE, proposal_sha256=PROPOSAL_SHA256, receipt_sha256=expected_raw_hash,
        runtime_acceptance_sha256=runtime_hash, transport_acceptance_sha256=transport_hash,
        run_api_sha256=receipt['run_api_sha256'], source_hashes=hashes,
        issued_utc=receipt['issued_utc'], expires_utc=receipt['expires_utc'],
        context=context, role='worker' if worker else 'parent', output=str(output),
        output_policy=policy, fresh_output_checks=checks, runtime_acceptance=runtime,
        verify_created_acl=True)
    grant.update({name: True for name in ('admission_verified', 'runtime_verified',
        'sidecar_transport_verified', 'run_binding_verified', 'role_claim_verified', 'output_checks_verified')})
    grant.update({name: False for name in FALSE_FLAGS})
    validate_grant(proposal, grant)
    return grant
