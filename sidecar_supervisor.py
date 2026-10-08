"""Bounded parent for the sidecar worker; no network capability is acquired.

The independently admitted worker owns the nine GETs.  This parent retains
start/finish evidence, kills a blocked worker at 180 seconds, drains only bounded
allowlisted diagnostics and validates completed files before reporting success.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

import collector
import sidecar_admission
from sidecar_contract import PROPOSAL_SHA256, ROOT_CONSTRAINTS, load_proposal
from worker_diagnostics import Capture

FALSE_RESULT_FLAGS = sidecar_admission.FALSE_FLAGS + (
    'dependency_closure_complete', 'artifact_bytes_verified',
    'installation_selection_approved', 'full_docker_accepted',
)


class LaunchCancelled(BaseException):
    """A cancellation queued until the new child has an owned process handle."""


@contextmanager
def _defer_launch_cancellation():
    """Queue signals only across Popen and assignment; never mask child signals.

    Raising a Python signal exception after OS child creation but before Popen
    returns would leave the supervisor without the process handle.  A bounded
    boolean records cancellation until assignment completes.  Original handlers
    are restored even when process creation fails; cancellation is raised by the
    caller only after its ``proc`` reference exists.
    """
    previous = {}
    pending = {'cancelled': False}
    def defer(signum, frame):
        pending['cancelled'] = True
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, defer)
        yield pending
    finally:
        restore_error = None
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except BaseException as exc:
                # Attempt every restoration even if one fails or is interrupted.
                if restore_error is None:
                    restore_error = exc
        if restore_error is not None:
            raise restore_error


def need(ok, code):
    if not ok:
        raise ValueError(code)


def _regular_bytes(path, cap):
    """Bounded local read, refusing links/reparse entries and replacement races."""
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode)
         and not (getattr(before, 'st_file_attributes', 0) & 0x400)
         and before.st_nlink == 1 and before.st_size <= cap, 'worker_file_layout_rejected')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
             and opened.st_size <= cap
             and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
             'worker_file_changed')
        raw = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    need(len(raw) <= cap and len(raw) == before.st_size
         and (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns),
         'worker_file_changed')
    return raw


def _json(path, cap):
    raw = _regular_bytes(path, cap)
    obj = collector.strict_json(raw)
    need(type(obj) is dict, 'worker_json_object_required')
    return obj, hashlib.sha256(raw).hexdigest()


def validate_worker_outputs(proposal, worker):
    """Read at most nine bounded bodies and bounded receipts/parsed records.

    The parser is not rerun.  Frozen response hashes plus source/run admission
    bind the worker's parsed output; the documented same-UID residual risk still
    applies.  Metadata nominees and unresolved edges never become a lock here.
    """
    worker = Path(worker)
    info = worker.lstat()
    need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
         and not (getattr(info, 'st_file_attributes', 0) & 0x400),
         'worker_directory_layout_rejected')
    report, report_hash = _json(worker / 'report.json', 65536)
    need(report.get('schema') == 'sidecar_collection_report_v1'
         and report.get('status') == 'metadata_collected_not_approved'
         and report.get('proposal_sha256') == PROPOSAL_SHA256,
         'worker_report_identity_rejected')
    need(type(report.get('requests_attempted')) is int and report['requests_attempted'] == 9
         and type(report.get('requests_validated')) is int and report['requests_validated'] == 9,
         'worker_report_count_rejected')
    need(type(report.get('retained_body_bytes')) is int
         and 0 <= report['retained_body_bytes'] <= 2359296,
         'worker_report_size_rejected')
    need(all(report.get(key) is False for key in FALSE_RESULT_FLAGS),
         'worker_report_approval_rejected')
    need(report.get('failures') == [] and report.get('metadata_nominees_only') is True
         and report.get('release_upload_cutoff_utc') == proposal['release_upload_cutoff_utc']
         and report.get('results') == [f'{i:02d}-metadata.json' for i in range(9)],
         'worker_report_results_rejected')
    if 'errors' in report:
        need(report['errors'] == [], 'worker_report_errors_present')
    bindings = []
    groups = {}
    total = 0
    need(len(proposal['requests']) == 9, 'worker_proposal_count_rejected')
    for index, request in enumerate(proposal['requests']):
        prefix = f'{index:02d}'
        raw = _regular_bytes(worker / (prefix + '.body'), 262144)
        digest = hashlib.sha256(raw).hexdigest()
        need(digest == request['expected_response_sha256'], 'worker_body_digest_mismatch')
        total += len(raw)
        receipt, receipt_hash = _json(worker / (prefix + '-receipt.json'), 65536)
        need(receipt.get('schema') == 'sidecar_response_receipt_v1'
             and receipt.get('status') == 'metadata_validated_not_approved'
             and receipt.get('proposal_sha256') == PROPOSAL_SHA256
             and receipt.get('request_id') == request['id']
             and receipt.get('project') == request['project']
             and receipt.get('version') == request['version']
             and receipt.get('url') == request['url'] and receipt.get('method') == 'GET'
             and receipt.get('headers') == request['headers']
             and receipt.get('expected_response_sha256') == digest
             and receipt.get('digest_verified_before_parse') is True
             and receipt.get('retained_file_binding_verified') is True
             and type(receipt.get('http_status')) is int and receipt['http_status'] == 200
             and receipt.get('response_sha256') == digest
             and type(receipt.get('received_retained_bytes')) is int
             and receipt['received_retained_bytes'] == len(raw),
             'worker_receipt_rejected')
        parsed, parsed_hash = _json(worker / (prefix + '-metadata.json'), 1048576)
        need(parsed.get('schema') == 'performance_v2_sidecar_metadata_v1'
             and parsed.get('response_sha256') == digest
             and type(parsed.get('response_bytes')) is int and parsed['response_bytes'] == len(raw)
             and parsed.get('digest_verified_before_parse') is True
             and parsed.get('name') == request['project']
             and parsed.get('version') == request['version']
             and parsed.get('frozen_target') == proposal['target']
             and parsed.get('scope') == 'runtime_no_extras',
             'worker_parsed_identity_rejected')
        need(parsed.get('dependency_closure_complete') is False
             and parsed.get('install_selection_approved') is False
             and parsed.get('automatic_recursion') is False
             and type(parsed.get('edges')) is list
             and type(parsed.get('unresolved_children')) is list
             and len(parsed['edges']) <= 256 and len(parsed['unresolved_children']) <= 256,
             'worker_parsed_scope_rejected')
        for edge_index, edge in enumerate(parsed['edges']):
            need(type(edge) is dict and isinstance(edge.get('name'), str)
                 and isinstance(edge.get('specifier'), str)
                 and edge.get('activity') in ('active', 'inactive', 'unresolved')
                 and 'url' in edge and (edge['url'] is None or isinstance(edge['url'], str))
                 and type(edge.get('self_cycle', False)) is bool,
                 'worker_parsed_edge_rejected')
            group = groups.setdefault(edge['name'], dict(active_edges=[], inactive_edges=[], unresolved_edges=[]))
            ref = dict(parent=parsed['name'], response_sha256=digest, edge_index=edge_index,
                       specifier=edge['specifier'], self_cycle=edge.get('self_cycle', False))
            if edge['activity'] == 'inactive':
                group['inactive_edges'].append(ref)
            elif edge['activity'] == 'unresolved' or edge['url'] is not None:
                ref['reason'] = 'direct_url_not_authorized' if edge['url'] is not None else 'target_marker_value_unknown'
                group['unresolved_edges'].append(ref)
            else:
                group['active_edges'].append(ref)
        bindings.append({'request_id': request['id'], 'response_sha256': digest,
                         'body_bytes': len(raw), 'receipt_sha256': receipt_hash,
                         'parsed_metadata_sha256': parsed_hash})
    need(total == report['retained_body_bytes'] and total <= 2359296,
         'worker_report_total_mismatch')
    conjunction, conjunction_hash = _json(worker / '06-constraints.json', 1048576)
    need(conjunction.get('schema') == 'performance_v2_sidecar_constraint_conjunction_v1'
         and all(conjunction.get(key) is False for key in ('dependency_closure_complete',
             'install_selection_approved', 'automatic_recursion', 'all_intersections_proven'))
         and type(conjunction.get('children')) is list
         and len(conjunction['children']) == len(groups), 'worker_conjunction_rejected')
    known = {'torch': '2.13.0+cpu', 'torchvision': '0.28.0+cpu',
             **{request['project']: request['version'] for request in proposal['requests']}}
    need([child.get('name') if type(child) is dict else None for child in conjunction['children']]
         == sorted(groups), 'worker_conjunction_children_rejected')
    statuses = {'known_nominee_satisfies', 'exact_constraint_witness_only',
                'intersection_unresolved', 'child_version_unselected', 'unresolved', 'inactive_not_applied'}
    for child in conjunction['children']:
        expected = groups[child['name']]
        need(all(child.get(key) == value for key, value in expected.items())
             and child.get('root_constraint') == ROOT_CONSTRAINTS.get(child['name'])
             and child.get('known_nominee_version') == known.get(child['name'])
             and isinstance(child.get('conjoined_specifier'), str)
             and child.get('constraint_status') in statuses
             and child.get('child_metadata_closed') is False
             and child.get('unresolved_requirements_present') is bool(expected['unresolved_edges']),
             'worker_conjunction_binding_rejected')
    return {'report_sha256': report_hash, 'requests_validated': 9,
            'constraints_sha256': conjunction_hash, 'retained_body_bytes': total, 'bindings': bindings}


def _stop(proc, immediate, clock):
    """At most five seconds of waits after failure; never leave a blind wait."""
    deadline = clock() + 5
    if not immediate:
        try:
            proc.terminate()
            proc.wait(timeout=min(1, max(0, deadline - clock())))
            return True
        except BaseException:
            pass
    try:
        proc.kill()
    except BaseException:
        pass
    try:
        proc.wait(timeout=max(0, deadline - clock()))
        return True
    except BaseException:
        return False


def supervised(proposal_path, output, grant, receipt_path, receipt_hash,
               runtime_path, runtime_hash, transport_path, transport_hash,
               popen=None, clock=time.monotonic):
    proposal = load_proposal(proposal_path)
    sidecar_admission.validate_grant(proposal, grant)
    need(grant.get('role') == 'parent', 'sidecar_parent_role_required')
    need(receipt_hash == grant['receipt_sha256']
         and runtime_hash == grant['runtime_acceptance_sha256']
         and transport_hash == grant['transport_acceptance_sha256'],
         'sidecar_launch_binding_mismatch')
    need(Path(grant['output']) == Path(output), 'sidecar_output_binding_mismatch')
    output = collector.validate_output_path(output, grant['output_policy'])
    from sidecar_collector import SidecarEvidence
    evidence = SidecarEvidence(output, verify_created=collector.created_verifier(grant))
    popen = subprocess.Popen if popen is None else popen
    proc = capture = None
    code = None
    error = None
    termination_confirmed = False
    completion = None
    launched = None
    try:
        evidence.write('parent-started.json', {
            'schema': 'sidecar_parent_started_v1', 'status': 'incomplete',
            'proposal_sha256': PROPOSAL_SHA256, 'execution_approved': False,
            'scope': sidecar_admission.SCOPE, 'aggregate_deadline_seconds': 180,
            'scoped_metadata_admission': {key: grant[key] for key in (
                'receipt_sha256', 'runtime_acceptance_sha256',
                'transport_acceptance_sha256', 'run_api_sha256', 'source_hashes')},
        })
        source = Path(__file__).resolve().parent
        args = [sys.executable, '-I', '-B', str(source / 'sidecar_collector.py'),
                '--proposal', str(Path(proposal_path).resolve()),
                '--output', str(Path(output).resolve()),
                '--receipt', str(Path(receipt_path).resolve()), '--receipt-sha256', receipt_hash,
                '--runtime-record', str(Path(runtime_path).resolve()), '--runtime-sha256', runtime_hash,
                '--transport-record', str(Path(transport_path).resolve()), '--transport-sha256', transport_hash,
                '--worker']
        launched = clock()
        with _defer_launch_cancellation() as pending_cancel:
            proc = popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE, close_fds=True)
        if pending_cancel['cancelled']:
            raise LaunchCancelled()
        if getattr(proc, 'stderr', None) is not None:
            capture = Capture(proc.stderr)
        remaining = 180 - (clock() - launched)
        if remaining <= 0:
            raise TimeoutError('worker deadline exceeded')
        code = proc.wait(timeout=remaining)
        termination_confirmed = True
        if clock() - launched >= 180:
            raise TimeoutError('worker deadline exceeded')
        need(type(code) is int and code == 0, 'worker_nonzero_exit')
        completion = validate_worker_outputs(proposal, Path(output) / 'worker')
    except BaseException as exc:
        if isinstance(exc, (subprocess.TimeoutExpired, TimeoutError)):
            error = 'timeout'
        elif not isinstance(exc, Exception):
            error = 'cancelled'
        elif proc is not None and termination_confirmed and code == 0:
            error = 'worker_completion_rejected'
        else:
            error = 'process_failure'
        if proc is not None and not termination_confirmed:
            termination_confirmed = _stop(proc, immediate=error == 'timeout', clock=clock)
    if capture is not None:
        try:
            evidence.write('worker-errors.json', capture.finish())
        except BaseException:
            error = error or 'diagnostic_write_failure'
    finished = {
        'schema': 'sidecar_parent_finished_v1',
        'status': 'metadata_collected_not_approved' if error is None and completion is not None else 'failed',
        'proposal_sha256': PROPOSAL_SHA256, 'exit_code': code, 'error': error,
        'termination_confirmed': termination_confirmed,
        'worker_completion_verified': completion is not None,
        'completion': completion, 'execution_approved': False,
        **{key: False for key in FALSE_RESULT_FLAGS},
    }
    try:
        evidence.write('parent-finished.json', finished)
    except BaseException:
        return 1
    return 0 if finished['status'] == 'metadata_collected_not_approved' else 1
