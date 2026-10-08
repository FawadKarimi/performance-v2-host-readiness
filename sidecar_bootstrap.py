"""Inactive-by-default, one-GET GitHub control-plane bootstrap; never collects."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import admission
import collector
import output_security as fs
import runtime_acceptance
import sidecar_admission as a
from sidecar_transport import WireResponse

ROOT = Path(__file__).resolve().parent
WORKFLOW = '.github/workflows/sidecar-collection.yml'
API_HOST = 'api.github.com'
API_CAP = 1048576
LOCK_NAME = 'collection-source-lock.json'
COMPAT = {
    'run_id': 37305200076, 'attempt': 1,
    'commit': 'd0a08a9e70879c3af2cec06f7699631e927024e9',
    'artifact_id': 11343410741,
    'artifact_sha256': '6d94ff0353f0495dc440351bdc0360be05b0e788fbb83ff3b4385b477644f53d',
    'source_lock_sha256': 'cd2324ed632c9eaffa60b1e7ba65651874255ff84c870aca3612a3ec9f329766',
    'workflow_sha256': 'e39c2e7bfabad7dc764a72fda26ac01e7d156fa39ceebd32ac60d39183fb4f1a',
    'runtime_record_sha256': 'b650feec2b4f59006618385c0dd5eb00f56fbda9a9e19c84d0fdee68ffb2ae40',
    'python_executable_sha256': 'e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f',
    'parser_tree_sha256': '6b7b5579f746ae9abb3a485b85396412fdfd94815a4fa5abbabc6692f9093cc3',
    'tests': 167,
}
APPROVALS = a.APPROVALS + ('control_plane_capture_authorized', 'bootstrap_reviewed')
need = a.need


def encoded(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':')) + '\n').encode()


def decode(raw, cap, code):
    need(type(raw) is bytes and len(raw) <= cap, code + '_size')
    result = collector.strict_json(raw)
    need(type(result) is dict, code + '_object')
    return result


def write_bytes(path, raw):
    need(type(raw) is bytes and len(raw) <= API_CAP, 'evidence_size')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        fs.verify_created(path, fd=stream.fileno())
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def verify_lock(root, expected):
    lock = a.read_record(root / LOCK_NAME, expected, 65536, 'collection_lock')
    need(lock.get('schema') == 'sidecar_collection_source_lock_v1'
         and lock.get('collection_authorized') is False, 'collection_lock_schema')
    files = lock.get('files')
    need(type(files) is dict and 1 <= len(files) <= 100, 'collection_lock_files')
    required = set(a.SOURCE_FILES) | {WORKFLOW, 'sidecar_bootstrap.py',
                'source-lock.json', 'sidecar-request-PROPOSED.json'}
    need(required <= set(files), 'collection_lock_missing')
    for name, digest in files.items():
        need(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.\-/]+', name)
             and not name.startswith('/') and '..' not in name.split('/'),
             'collection_lock_path')
        path = root / name
        need(not any(p.is_symlink() for p in (path, *path.parents)),
             'collection_lock_symlink')
        need(path.is_file() and a.sha(path.read_bytes()) == digest, 'collection_source_drift')
    need(a.sha((root / 'source-lock.json').read_bytes()) == COMPAT['source_lock_sha256'],
         'historical_lock_drift')
    need(a.sha((root / 'sidecar-request-PROPOSED.json').read_bytes()) == a.PROPOSAL_SHA256,
         'proposal_drift')
    return lock


def validate_activation(raw, digest, lock_digest, env, root, now):
    need(a.is_hash(digest) and a.sha(raw) == digest, 'activation_hash')
    record = decode(raw, 60000, 'activation')
    need(record.get('schema') == 'sidecar_collection_activation_v1'
         and record.get('scope') == a.SCOPE, 'activation_scope')
    need(all(record.get(k) is True for k in APPROVALS), 'activation_inactive')
    need(all(record.get(k) is False for k in a.FALSE_FLAGS), 'activation_broader_scope')
    need(env.get('OWNER_AUTHORIZATION') == env.get('BILLING_CONFIRMATION') == 'true',
         'dispatch_confirmation')
    issued, expires = a.utc(record.get('issued_utc')), a.utc(record.get('expires_utc'))
    need(issued <= now < expires and dt.timedelta(0) < expires-issued <= dt.timedelta(minutes=15),
         'activation_expired')
    need(record.get('collection_source_lock_sha256') == lock_digest, 'activation_lock')
    need(re.fullmatch('[0-9a-f]{40}', str(record.get('commit'))) is not None
         and record['commit'] == env.get('GITHUB_SHA'), 'activation_commit')
    need(type(record.get('workflow_id')) is int and record['workflow_id'] > 0
         and type(record.get('run_number')) is int and record['run_number'] > 0
         and str(record['run_number']) == env.get('GITHUB_RUN_NUMBER'), 'activation_run_identity')
    need(env.get('GITHUB_REPOSITORY') == a.REPOSITORY
         and env.get('GITHUB_REF') == 'refs/heads/main'
         and env.get('GITHUB_RUN_ATTEMPT') == '1'
         and env.get('GITHUB_ACTOR_ID') == str(a.OWNER_ID)
         and env.get('GITHUB_TRIGGERING_ACTOR_ID') == str(a.OWNER_ID)
         and env.get('GITHUB_TRIGGERING_ACTOR') == 'FawadKarimi',
         'activation_owner_context')
    need(record.get('workflow_sha256') == a.sha((root / WORKFLOW).read_bytes()),
         'activation_workflow')
    need(record.get('source_hashes') == a.source_hashes(root), 'activation_sources')
    need(type(record.get('home_default_acl_disposition_accepted')) is bool, 'activation_acl')
    need(all(isinstance(record.get(k), str) and record[k].strip()
             for k in ('review_reference', 'security_review_reference')), 'activation_review')
    native = record.get('native_acceptance')
    need(type(native) is dict and native.get('schema') == 'sidecar_native_acceptance_v1'
         and native.get('accepted') is True and native.get('evidence') == COMPAT,
         'native_acceptance_missing')
    need(native.get('collection_authorized') is False
         and isinstance(native.get('review_reference'), str) and native['review_reference'].strip(),
         'native_acceptance_scope')
    for k in ('runtime_record', 'transport_record'):
        need(type(record.get(k)) is dict, k + '_missing')
    runtime = record['runtime_record']
    need(runtime.get('metadata_runtime_accepted') is True
         and runtime.get('python', {}).get('executable_sha256') == COMPAT['python_executable_sha256']
         and runtime.get('parser', {}).get('tree_sha256') == COMPAT['parser_tree_sha256'],
         'runtime_activation')
    transport = record['transport_record']
    need(transport.get('schema') == a.TRANSPORT_SCHEMA and transport.get('scope') == a.SCOPE
         and all(transport.get(k) is True for k in a.TRANSPORT_APPROVALS)
         and all(transport.get(k) is False for k in a.FALSE_FLAGS), 'transport_activation')
    need(transport.get('runtime_acceptance_sha256') == a.sha(encoded(runtime))
         and transport.get('source_hashes') == record['source_hashes']
         and transport.get('proposal_sha256') == a.PROPOSAL_SHA256, 'transport_binding')
    need(all(isinstance(transport.get(k), str) and transport[k].strip()
             for k in ('review_reference', 'security_review_reference',
                       'native_compatibility_review_reference')), 'transport_review')
    return record


class ApiBudget:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.end = clock() + 20
    def remaining(self):
        left = self.end - self.clock()
        if left <= 0:
            raise TimeoutError('control_plane_deadline')
        return left
    def remaining_body_capacity(self, current):
        return API_CAP - current


def capture_api(context, token, sink, connect=None, clock=time.monotonic):
    """One literal API GET. No proxy, redirect, retry, or address fallback."""
    need(re.fullmatch('[1-9][0-9]*', context['run_id']) is not None, 'api_run_id')
    need(isinstance(token, str) and 1 <= len(token) <= 4096
         and re.fullmatch('[A-Za-z0-9_.-]+', token) is not None, 'api_token')
    path = '/repos/' + a.REPOSITORY + '/actions/runs/' + context['run_id']
    budget = ApiBudget(clock)
    sock = plain = None
    try:
        if connect is None:
            # OS DNS cannot be cancelled here; the workflow's 45s timeout is the backstop.
            rows = socket.getaddrinfo(API_HOST, 443, type=socket.SOCK_STREAM,
                                      proto=socket.IPPROTO_TCP)
            budget.remaining()
            need(bool(rows), 'api_dns_empty')
            family, kind, proto, _, address = rows[0]
            need(family in (socket.AF_INET, socket.AF_INET6) and kind == socket.SOCK_STREAM,
                 'api_address')
            plain = socket.socket(family, kind, proto)
            plain.settimeout(budget.remaining())
            plain.connect(address)
            tls = ssl.create_default_context()
            need(tls.check_hostname and tls.verify_mode == ssl.CERT_REQUIRED, 'api_tls')
            plain.settimeout(budget.remaining())
            sock = tls.wrap_socket(plain, server_hostname=API_HOST)
        else:
            sock = connect(budget)
        sock.settimeout(budget.remaining())
        request = ('GET ' + path + ' HTTP/1.1\r\nHost: ' + API_HOST +
                   '\r\nUser-Agent: pv2-sidecar-identity\r\nAccept: application/vnd.github+json'
                   '\r\nAccept-Encoding: identity\r\nX-GitHub-Api-Version: 2026-03-10'
                   '\r\nAuthorization: Bearer ' + token + '\r\nConnection: close\r\n\r\n')
        sock.sendall(request.encode('ascii'))
        response = WireResponse(sock, 'https://' + API_HOST + path, budget)
        headers = {}
        for k, v in response.headers:
            k = k.lower()
            need(k not in headers, 'api_duplicate_header')
            headers[k] = v
        need(response.status == 200, 'api_status')
        need('transfer-encoding' not in headers
             and headers.get('content-encoding', 'identity').lower() == 'identity',
             'api_encoding')
        need('application/json' in headers.get('content-type', '').lower(),
             'api_content_type')
        length = headers.get('content-length', '')
        need(re.fullmatch('[0-9]+', length) is not None and 0 < int(length) <= API_CAP,
             'api_length')
        remaining = int(length)
        while remaining:
            chunk = response.read(min(65536, remaining))
            need(bool(chunk), 'api_truncated')
            sink(chunk)  # Retain the received prefix before the next deadline check.
            remaining -= len(chunk)
            budget.remaining()
    finally:
        if sock is not None:
            sock.close()
        elif plain is not None:
            plain.close()


def issue(raw, digest, lock_digest, env, root=ROOT, fetch=capture_api,
          observe_runtime=None, now=None):
    now = dt.datetime.now(dt.timezone.utc) if now is None else now
    root = Path(root)
    # Inactive/default/expired records fail before filesystem observations or API requests.
    record = validate_activation(raw, digest, lock_digest, env, root, now)
    verify_lock(root, lock_digest)
    context = admission.context_from_env(env)
    output = Path(env['RUNNER_TEMP']) / ('pypi-evidence-' + context['run_id'] + '-1')
    admission.output_policy(env['RUNNER_TEMP'], env['GITHUB_WORKSPACE'], output)
    fs.observe(env['RUNNER_TEMP'], env['GITHUB_WORKSPACE'],
               allow_home_default_acl=record['home_default_acl_disposition_accepted'])
    folder = Path(env['RUNNER_TEMP']) / ('sidecar-admission-' + context['run_id'] + '-1')
    folder.mkdir(mode=0o700, exist_ok=False)
    fs.verify_created(folder)
    try:
        write_bytes(folder / 'activation.json', raw)
        write_bytes(folder / 'started.json', encoded({'status': 'incomplete',
                    'collection_authorized': False}))
        runtime_raw, transport_raw = encoded(record['runtime_record']), encoded(record['transport_record'])
        write_bytes(folder / 'runtime.json', runtime_raw)
        write_bytes(folder / 'transport.json', transport_raw)
        runtime_acceptance.verify_record(folder/'runtime.json', a.sha(runtime_raw),
                                         observe=observe_runtime)
        fd = os.open(folder/'run-api.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        # Timestamp before fetching: the freshness clock cannot be reset after a delay.
        observed = dt.datetime.now(dt.timezone.utc)
        with os.fdopen(fd, 'wb') as stream:
            fs.verify_created(folder/'run-api.json', fd=stream.fileno())
            total = 0
            def sink(chunk):
                nonlocal total
                need(type(chunk) is bytes and total + len(chunk) <= API_CAP, 'api_body_cap')
                stream.write(chunk); stream.flush()
                total += len(chunk)
            fetch(context, env.get('GITHUB_TOKEN'), sink)
            os.fsync(stream.fileno())
        run_raw = (folder/'run-api.json').read_bytes()
        receipt = a.authorization_template()
        receipt.update({k: record[k] for k in a.APPROVALS + a.FALSE_FLAGS})
        receipt.update(proposal_sha256=a.PROPOSAL_SHA256,
            source_hashes=record['source_hashes'], runtime_acceptance_sha256=a.sha(runtime_raw),
            transport_acceptance_sha256=a.sha(transport_raw), context=context,
            workflow_path=WORKFLOW, workflow_sha256=record['workflow_sha256'],
            workflow_id=record['workflow_id'], run_number=record['run_number'],
            run_api_file='run-api.json', run_api_sha256=a.sha(run_raw),
            run_api_observed_utc=observed.isoformat(), issued_utc=record['issued_utc'],
            expires_utc=record['expires_utc'],
            home_default_acl_disposition_accepted=record['home_default_acl_disposition_accepted'],
            activation_sha256=digest, collection_source_lock_sha256=lock_digest,
            provenance='same-run authenticated TLS GitHub API; token never retained')
        a.verify_run(receipt, context, env, root, folder, dt.datetime.now(dt.timezone.utc))
        # Catch expiration/source changes during capture before delivering a usable receipt.
        validate_activation(raw, digest, lock_digest, env, root, dt.datetime.now(dt.timezone.utc))
        verify_lock(root, lock_digest)
        write_bytes(folder/'receipt.json', encoded(receipt))
        fs.verify_evidence_folder(folder)
        return folder
    except BaseException:
        # Deliberately closed summary: no token, URL parameters, raw exception or traceback.
        write_bytes(folder/'failed.json', encoded({'status': 'bootstrap_failed',
                    'collection_authorized': False, 'partial_api_bytes_retained': True}))
        raise


def main():
    env = dict(os.environ)
    try:
        issue(env.get('ACTIVATION_JSON', '{}').encode(), env.get('ACTIVATION_SHA256', ''),
              env.get('COLLECTION_LOCK_SHA256', ''), env)
        return 0
    except BaseException:
        print('sidecar_bootstrap_failed; inspect bounded retained evidence', file=sys.stderr)
        return 1
    finally:
        env.pop('GITHUB_TOKEN', None)


if __name__ == '__main__':
    raise SystemExit(main())
