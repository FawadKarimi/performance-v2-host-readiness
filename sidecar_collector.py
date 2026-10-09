"""Four frozen investigative sidecar GETs. Packaged records do not authorize execution."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

# -I deliberately excludes cwd; load only colocated, hash-bound reviewed helpers.
if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from collector import Evidence, created_verifier, validate_output_path
from sidecar_contract import (PROPOSAL_SHA256, ROOT_CONSTRAINTS, known_nodes,
                              load_proposal, validate_proposal)
from sidecar_admission import FALSE_FLAGS, authorize_network
from sidecar_metadata import MetadataError, parse_metadata, check_collection_constraints
from sidecar_transport import Budget, TLSMetadataTransport, validate_headers

FALSE_RESULT_FLAGS = (*FALSE_FLAGS, 'dependency_closure_complete',
    'artifact_bytes_verified', 'installation_selection_approved', 'full_docker_accepted')


class CollectionError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class Cancelled(BaseException):
    pass


@contextmanager
def cancellation_signals():
    previous = {}
    def stop(signum, frame):
        raise Cancelled()
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, stop)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


class SidecarEvidence(Evidence):
    """Reuse exclusive/no-follow writes with stricter size and report reserve."""
    CAP = 12 * 1024 * 1024
    RESERVE = 65536

    def account(self, n):
        if type(n) is not int or n < 0 or self.written + n > self.CAP - self.RESERVE:
            raise CollectionError('evidence_output_cap')
        self.written += n

    def write(self, name, obj):
        raw = (json.dumps(obj, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')
        terminal = name in ('report.json', 'parent-finished.json')
        if len(raw) > (self.RESERVE if terminal else 1048576):
            raise CollectionError('evidence_json_cap')
        if terminal:
            if self.written + len(raw) > self.CAP:
                raise CollectionError('evidence_output_cap')
            self.written += len(raw)
        else:
            self.account(len(raw))
        with self.open_file(name) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    def write_bytes(self, name, raw):
        self.account(len(raw))
        with self.open_file(name) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())


def failure_code(exc):
    if isinstance(exc, (Cancelled, KeyboardInterrupt, SystemExit)):
        return 'cancelled'
    if isinstance(exc, TimeoutError):
        return 'timeout'
    if isinstance(exc, (CollectionError, MetadataError)):
        return exc.code
    # Never write raw exception strings, tracebacks, environment or stderr.
    if isinstance(exc, ValueError):
        return 'response_policy_rejected'
    if isinstance(exc, OSError):
        return 'io_failure'
    return 'worker_failure'


def retained_body(evidence, name):
    """Bind receipts to actual retained files, including interrupted write/fsync."""
    path = evidence.path / name
    if not os.path.lexists(path):
        return b''
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise CollectionError('retained_body_layout')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        current = os.fstat(stream.fileno())
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or current.st_size > 262144:
            raise CollectionError('retained_body_layout')
        if evidence.verify_created is not None:
            evidence.verify_created(path, fd=stream.fileno())
        raw = stream.read(262145)
        if len(raw) > 262144:
            raise CollectionError('retained_body_cap')
    return raw


def collect(proposal, transport, evidence, clock=time.monotonic, grant=None):
    """Injected transports are for offline tests; production has a second gate."""
    validate_proposal(proposal)
    authorize_network(proposal, grant)
    budget = Budget(proposal, clock)
    report = dict(schema='sidecar_collection_report_v1', proposal_sha256=PROPOSAL_SHA256,
        status='incomplete', requests_attempted=0, requests_validated=0, requests_captured=0, eligibility_blocked=0,
        retained_body_bytes=0, failures=[], results=[], metadata_nominees_only=True,
        release_upload_cutoff_utc=proposal['release_upload_cutoff_utc'])
    report.update({name: False for name in FALSE_RESULT_FLAGS})
    try:
        evidence.write('started.json', dict(schema='sidecar_worker_started_v1',
            proposal_sha256=PROPOSAL_SHA256, status='incomplete',
            scoped_admission=grant, target=proposal['target'],
            bounds=proposal['bounded_transport']))
        nodes = known_nodes(proposal)
        parsed_results = []
        for index, request in enumerate(proposal['requests']):
            prefix = f'{index:02d}'
            body = bytearray()
            response = None
            record = dict(schema='sidecar_response_receipt_v1', status='incomplete',
                request_id=request['id'], project=request['project'], version=request['version'],
                url=request['url'], method=request['method'], headers=request['headers'],
                expected_response_sha256=request['expected_response_sha256'],
                proposal_sha256=PROPOSAL_SHA256, digest_verified_before_parse=False)
            started = clock()
            prior_retained_total = budget.total
            headers_saved = False
            try:
                evidence.write(prefix + '-started.json', record)
                budget.start()
                response = transport.open(request['method'], request['url'], request['headers'], budget)
                raw_headers = getattr(response, 'raw_headers', b'')
                if len(raw_headers) > 16384:
                    raise CollectionError('header_cap')
                evidence.write_bytes(prefix + '.headers', raw_headers)
                headers_saved = True
                record['http_status'] = response.status
                # Only validated literal URL is retained; a foreign redirect URL is data
                # in bounded raw headers and never used as a destination.
                declared = validate_headers(response, request['url'], proposal)
                record['declared_content_length'] = declared
                budget.remaining()
                if declared is not None and declared > budget.remaining_body_capacity(0):
                    raise CollectionError('aggregate_body_cap')
                with evidence.open_file(prefix + '.body') as stream:
                    while declared is None or len(body) < declared:
                        budget.remaining()
                        room = budget.remaining_body_capacity(len(body))
                        if room == 0:
                            # No extra byte/EOF probe beyond the literal body cap.
                            raise CollectionError('unknown_length_at_cap')
                        take = min(16384, room, declared - len(body) if declared is not None else room)
                        chunk = response.read(take)
                        if not isinstance(chunk, bytes) or len(chunk) > take:
                            raise CollectionError('transport_read_contract')
                        if chunk:
                            evidence.account(len(chunk))
                            stream.write(chunk)
                            stream.flush()
                            os.fsync(stream.fileno())
                            body.extend(chunk)
                            budget.account(len(chunk))
                        # Persist bytes already received even if this check times out.
                        budget.remaining()
                        if not chunk:
                            if declared is not None and len(body) != declared:
                                raise CollectionError('truncated_body')
                            break
                if hashlib.sha256(body).hexdigest() != request['expected_response_sha256']:
                    raise CollectionError('digest_mismatch')
                record['digest_verified_before_parse'] = True
                result = parse_metadata(bytes(body), request, proposal['target'], nodes, ROOT_CONSTRAINTS,
                    investigate_missing_python=request['project']=='mpmath' and request['frozen_source']['requires_python'] is None)
                evidence.write(prefix + '-metadata.json', result)
                review = check_collection_constraints([result], ROOT_CONSTRAINTS, nodes, proposal['target'])
                combined = {'schema':'sidecar_alternative_constraints_v1',
                    'candidates':parsed_results + [{'request_id':request['id'], 'metadata':result, 'constraints':review}],
                    'joint_installation_assumed':False, 'dependency_closure_complete':False}
                budget.remaining()
                evidence.write(prefix + '-constraints.json', combined)
                budget.remaining()
                record['status'] = 'metadata_captured_eligibility_blocked' if result['eligibility']=='blocked' else 'metadata_validated_not_approved'
                record['eligibility'] = result['eligibility']
                record['eligibility_reason'] = result['eligibility_reason']
                parsed_results.append(combined['candidates'][-1])
            except BaseException as exc:
                record['status'] = 'cancelled' if failure_code(exc) == 'cancelled' else 'failed'
                record['error_code'] = failure_code(exc)
                raw_headers = getattr(exc, 'partial_response_header_bytes', b'')
                if not headers_saved and isinstance(raw_headers, bytes) and raw_headers:
                    evidence.write_bytes(prefix + '.headers', raw_headers[:16384])
                if isinstance(exc, MetadataError) and exc.evidence:
                    # Parser bounds structured evidence; SidecarEvidence enforces 1MiB.
                    evidence.write(prefix + '-rejected-metadata.json', exc.evidence)
            finally:
                if response is not None:
                    try:
                        response.close()
                    except BaseException as exc:
                        record.update(status='failed', error_code='response_close_failure')
                try:
                    actual_body = retained_body(evidence, prefix + '.body')
                    body = bytearray(actual_body)
                    budget.total = prior_retained_total + len(actual_body)
                    record['retained_file_binding_verified'] = True
                except BaseException:
                    record.update(status='failed', error_code='retained_body_binding_failure',
                                  retained_file_binding_verified=False)
                record.update(received_retained_bytes=len(body),
                    response_sha256=hashlib.sha256(body).hexdigest(),
                    hash_scope='retained body; may be incomplete on failure',
                    elapsed_seconds=max(0, clock() - started))
                evidence.write(prefix + '-receipt.json', record)
            if record['status'] not in ('metadata_validated_not_approved', 'metadata_captured_eligibility_blocked'):
                report['failures'].append(dict(request_id=request['id'], code=record.get('error_code', 'worker_failure')))
                report['status'] = record['status']
                break
            report['requests_captured'] += 1
            report['requests_validated'] += int(record['status']=='metadata_validated_not_approved')
            report['eligibility_blocked'] += int(record['status']=='metadata_captured_eligibility_blocked')
            report['results'].append(prefix + '-metadata.json')
        else:
            report['status'] = 'metadata_capture_complete_not_eligible'
    except BaseException as exc:
        code = failure_code(exc)
        report['status'] = 'cancelled' if code == 'cancelled' else 'failed'
        report['failures'].append(dict(code=code))
    finally:
        report['requests_attempted'] = budget.calls
        report['retained_body_bytes'] = budget.total
        evidence.write('report.json', report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proposal', required=True)
    parser.add_argument('--validate-only', action='store_true')
    for name in ('output', 'receipt', 'receipt-sha256', 'runtime-record',
                 'runtime-sha256', 'transport-record', 'transport-sha256'):
        parser.add_argument('--' + name)
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args(argv)
    proposal = load_proposal(args.proposal)
    if args.validate_only:
        print(json.dumps(dict(proposal_sha256=PROPOSAL_SHA256, valid=True,
                              execution_authorized=False, network_attempts=0)))
        return 0
    if any(getattr(args, name) is None for name in ('output', 'receipt', 'receipt_sha256',
            'runtime_record', 'runtime_sha256', 'transport_record', 'transport_sha256')):
        raise CollectionError('sidecar_admission_inputs_required')
    from sidecar_admission import load_grant
    grant = load_grant(args.proposal, args.receipt, args.receipt_sha256,
        Path(__file__).resolve().parent, args.output, worker=args.worker,
        runtime_path=args.runtime_record, runtime_hash=args.runtime_sha256,
        transport_path=args.transport_record, transport_hash=args.transport_sha256)
    with cancellation_signals():
        if args.worker:
            authorize_network(proposal, grant)
            output = validate_output_path(Path(args.output) / 'worker', grant['output_policy'])
            evidence = SidecarEvidence(output, verify_created=created_verifier(grant))
            report = collect(proposal, TLSMetadataTransport(proposal, grant), evidence, grant=grant)
            return 0 if report['status'] == 'metadata_capture_complete_not_eligible' else 1
        from sidecar_supervisor import supervised
        result = supervised(args.proposal, args.output, grant,
            args.receipt, args.receipt_sha256, args.runtime_record, args.runtime_sha256,
            args.transport_record, args.transport_sha256)
        return result


if __name__ == '__main__':
    try:
        code = main()
    except BaseException as exc:
        from worker_diagnostics import error_record
        print(json.dumps(error_record(exc)), file=sys.stderr)
        code = 1
    raise SystemExit(code)
