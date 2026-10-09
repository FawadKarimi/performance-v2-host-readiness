"""Offline integration. Synthetic bodies never claim the publisher digests."""
import copy
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

import sidecar_collector as sc
import sidecar_contract as contract

SOURCE = Path(__file__).parent


class Response:
    def __init__(self, request, raw, action=None, status=200, headers=None):
        self.final_url = request['url']
        self.status = status
        self.raw_headers = b'HTTP/1.1 200 OK\r\n\r\n'
        self.headers = [('Content-Length', str(len(raw)))] if headers is None else headers
        self.raw = raw
        self.offset = 0
        self.action = action
        self.closed = False
        self.read_sizes = []

    def read(self, n):
        self.read_sizes.append(n)
        if self.action:
            value = self.action(self, n)
            if value is not None:
                return value
        value = self.raw[self.offset:self.offset+n]
        self.offset += len(value)
        return value

    def close(self):
        self.closed = True


class Transport:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def open(self, method, url, headers, budget):
        self.calls.append((method, url, headers))
        result = self.responses[len(self.calls)-1]
        if isinstance(result, BaseException):
            raise result
        return result


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.original = contract.load_proposal(SOURCE / 'sidecar-request-PROPOSED.json')
        self.proposal = copy.deepcopy(self.original)
        self.bodies = []
        for req in self.proposal['requests']:
            raw = (f'Metadata-Version: 2.4\nName: {req["project"]}\nVersion: {req["version"]}\n'
                   f'Requires-Python: {req["frozen_source"]["requires_python"]}\n\n').encode()
            self.bodies.append(raw)
            req['expected_response_sha256'] = hashlib.sha256(raw).hexdigest()
        self.responses = [Response(r,b) for r,b in zip(self.proposal['requests'],self.bodies)]
        self.transport = Transport(self.responses)
        self.evidence = sc.SidecarEvidence(self.root / 'evidence')
        self.now = 0
        self.net = patch('socket.getaddrinfo', side_effect=AssertionError('offline test network forbidden'))
        self.net.start()
        self.addCleanup(self.net.stop)

    def run_collect(self):
        # Only test seam: changed synthetic payload digests cannot pass production contract.
        with patch.object(sc, 'validate_proposal'), patch.object(contract, 'validate_proposal'), \
             patch.object(sc, 'authorize_network'):
            return sc.collect(self.proposal, self.transport, self.evidence,
                              clock=lambda: self.now, grant=None)

    def record(self, name):
        return json.loads((self.evidence.path/name).read_text())

    def replace_body(self, raw, rehash=False):
        self.responses[0] = Response(self.proposal['requests'][0], raw)
        if rehash:
            self.proposal['requests'][0]['expected_response_sha256'] = hashlib.sha256(raw).hexdigest()

    def test_all_nine_exact_order_and_no_approval(self):
        report = self.run_collect()
        self.assertEqual(report['status'], 'metadata_collected_not_approved')
        self.assertEqual(report['requests_attempted'], 9)
        self.assertEqual(report['requests_validated'], 9)
        self.assertEqual(report['retained_body_bytes'], sum(map(len,self.bodies)))
        self.assertEqual(self.transport.calls, [(r['method'],r['url'],r['headers']) for r in self.proposal['requests']])
        for flag in sc.FALSE_RESULT_FLAGS:
            self.assertIs(report[flag], False)
        self.assertTrue(all(x.closed for x in self.responses))
        from sidecar_supervisor import validate_worker_outputs
        proof = validate_worker_outputs(self.proposal, self.evidence.path)
        self.assertEqual(proof['requests_validated'], 9)
        self.assertEqual(proof['retained_body_bytes'], report['retained_body_bytes'])


    def test_binary_mime_wrong_hash_rejects_before_parse(self):
        self.replace_body(b'untrusted metadata')
        self.responses[0].headers.append(('Content-Type', 'binary/octet-stream'))
        with patch.object(sc, 'parse_metadata') as parse:
            report = self.run_collect()
        parse.assert_not_called()
        self.assertEqual(report['failures'][0]['code'], 'digest_mismatch')
        self.assertEqual(report['requests_validated'], 0)
        self.assertEqual(len(self.transport.calls), 1)
        self.assertFalse(self.record('00-receipt.json')['digest_verified_before_parse'])
        self.assertFalse((self.evidence.path/'00-metadata.json').exists())

    def test_binary_mime_hash_matched_invalid_metadata_rejected(self):
        self.replace_body(b'not metadata\n\xff', rehash=True)
        self.responses[0].headers.append(('Content-Type', 'binary/octet-stream'))
        report = self.run_collect()
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['requests_validated'], 0)
        self.assertEqual(len(self.transport.calls), 1)
        self.assertTrue(self.record('00-receipt.json')['digest_verified_before_parse'])
        self.assertFalse((self.evidence.path/'00-metadata.json').exists())

    def test_digest_mismatch_never_parses_and_stops(self):
        self.replace_body(b'untrusted metadata')
        with patch.object(sc, 'parse_metadata') as parse:
            report = self.run_collect()
        parse.assert_not_called()
        self.assertEqual(report['failures'][0]['code'], 'digest_mismatch')
        self.assertEqual((self.evidence.path/'00.body').read_bytes(), b'untrusted metadata')
        self.assertEqual(len(self.transport.calls), 1)

    def test_hash_matched_malformed_metadata_retained(self):
        self.replace_body(b'not a metadata header\n\xff', rehash=True)
        report = self.run_collect()
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['requests_validated'], 0)
        self.assertTrue(self.record('00-receipt.json')['digest_verified_before_parse'])
        self.assertFalse((self.evidence.path/'00-metadata.json').exists())

    def test_identity_conflict_stops(self):
        self.replace_body(self.bodies[0].replace(b'Name: filelock', b'Name: wrong'), rehash=True)
        self.assertEqual(self.run_collect()['status'], 'failed')
        self.assertEqual(len(self.transport.calls), 1)

    def test_missing_sidecar_no_body_read(self):
        self.responses[0].status = 404
        report = self.run_collect()
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(self.responses[0].read_sizes, [])
        self.assertEqual(self.record('00-receipt.json')['http_status'], 404)
        self.assertTrue((self.evidence.path/'00.headers').exists())

    def test_redirect_no_follow(self):
        self.responses[0].status = 302
        self.responses[0].headers = [('Location','https://example.invalid/forbidden')]
        self.assertEqual(self.run_collect()['status'], 'failed')
        self.assertEqual(len(self.transport.calls), 1)

    def test_final_url_substitution_refused(self):
        self.responses[0].final_url += '?changed'
        self.assertEqual(self.run_collect()['status'], 'failed')
        self.assertEqual(self.responses[0].read_sizes, [])

    def test_timeout_after_received_chunk_keeps_bytes(self):
        def advance(response, n):
            self.now = 21
            response.action = None
            return b'partial'
        self.responses[0].action = advance
        report = self.run_collect()
        self.assertEqual(report['failures'][0]['code'], 'timeout')
        self.assertEqual(report['retained_body_bytes'], 7)
        self.assertEqual((self.evidence.path/'00.body').read_bytes(), b'partial')
        self.assertEqual(len(self.transport.calls), 1)

    def test_cancelled_prefix_and_receipts(self):
        for cls in (sc.Cancelled, KeyboardInterrupt, SystemExit):
            with self.subTest(kind=cls):
                path = self.root/cls.__name__
                self.evidence = sc.SidecarEvidence(path)
                def cancel(response, n):
                    if response.offset:
                        raise cls()
                    response.offset = 3
                    return b'abc'
                self.responses[0] = Response(self.proposal['requests'][0], self.bodies[0], action=cancel)
                self.transport = Transport(self.responses)
                report = self.run_collect()
                self.assertEqual(report['status'], 'cancelled')
                self.assertEqual((path/'00.body').read_bytes(), b'abc')
                self.assertEqual(self.record('00-receipt.json')['error_code'], 'cancelled')
                self.assertTrue(self.responses[0].closed)

    def test_open_failure_retains_header_prefix(self):
        exc = TimeoutError()
        exc.partial_response_header_bytes = b'HTTP/1.1 200'
        self.responses[0] = exc
        report = self.run_collect()
        self.assertEqual(report['status'], 'failed')
        self.assertEqual((self.evidence.path/'00.headers').read_bytes(), exc.partial_response_header_bytes)

    def test_fsync_cancellation_reconciles_actual_file(self):
        original = sc.os.fsync
        calls = []
        def interrupt_once(fd):
            calls.append(fd)
            if len(calls) == 4:  # started, request-started, headers, first body chunk
                raise KeyboardInterrupt()
            return original(fd)
        with patch.object(sc.os, 'fsync', side_effect=interrupt_once):
            report = self.run_collect()
        actual = (self.evidence.path/'00.body').read_bytes()
        receipt = self.record('00-receipt.json')
        self.assertEqual(report['status'], 'cancelled')
        self.assertEqual(report['retained_body_bytes'], len(actual))
        self.assertEqual(receipt['response_sha256'], hashlib.sha256(actual).hexdigest())
        self.assertEqual(receipt['received_retained_bytes'], len(actual))
        self.assertTrue(receipt['retained_file_binding_verified'])
        self.assertTrue(actual)

    def test_conflicting_edges_across_responses_rejected(self):
        for i, constraint in enumerate(('child>=2', 'child<2')):
            raw = self.bodies[i].rstrip(b'\n') + b'\nRequires-Dist: ' + constraint.encode() + b'\n\n'
            self.proposal['requests'][i]['expected_response_sha256'] = hashlib.sha256(raw).hexdigest()
            self.responses[i] = Response(self.proposal['requests'][i], raw)
        report = self.run_collect()
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['requests_attempted'], 2)
        self.assertEqual(report['requests_validated'], 1)
        self.assertTrue((self.evidence.path/'01-rejected-metadata.json').exists())

    def test_truncated_body_is_not_digest_success(self):
        self.responses[0].headers = [('Content-Length','10000')]
        report = self.run_collect()
        self.assertEqual(report['failures'][0]['code'], 'truncated_body')

    def test_oversized_declared_length_never_reads(self):
        self.responses[0].headers = [('Content-Length','262145')]
        self.assertEqual(self.run_collect()['status'], 'failed')
        self.assertEqual(self.responses[0].read_sizes, [])

    def test_unknown_length_at_cap_no_overread(self):
        self.responses[0] = Response(self.proposal['requests'][0], b'x'*262144, headers=[])
        report = self.run_collect()
        self.assertEqual(report['failures'][0]['code'], 'unknown_length_at_cap')
        self.assertEqual(sum(self.responses[0].read_sizes), 262144)
        self.assertEqual((self.evidence.path/'00.body').stat().st_size, 262144)

    def test_exact_declared_cap_no_eof_probe(self):
        self.responses[0] = Response(self.proposal['requests'][0], b'x'*262144)
        report = self.run_collect()
        self.assertEqual(report['failures'][0]['code'], 'digest_mismatch')
        self.assertEqual(sum(self.responses[0].read_sizes), 262144)

    def test_close_failure_stops_further_gets(self):
        self.responses[0].close = Mock(side_effect=OSError('PRIVATE'))
        report = self.run_collect()
        self.assertEqual(report['failures'][0]['code'], 'response_close_failure')
        self.assertNotIn('PRIVATE', json.dumps(report))
        self.assertEqual(len(self.transport.calls), 1)

    def test_no_grant_rejected_before_transport_or_writes(self):
        with self.assertRaisesRegex(ValueError,'sidecar_network_disabled'):
            sc.collect(self.original, self.transport, self.evidence)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(list(self.evidence.path.iterdir()), [])

    def test_changed_contract_rejected_without_network(self):
        for mutate in (lambda p:p['requests'][0].update(method='HEAD'),
                       lambda p:p['requests'][0].update(url='https://example.invalid'),
                       lambda p:p['bounded_transport'].update(max_attempts=8),
                       lambda p:p['target'].update(python_full_version='3.14.0')):
            changed = copy.deepcopy(self.original)
            mutate(changed)
            with self.assertRaisesRegex(ValueError,'proposal_content_changed'):
                sc.collect(changed, self.transport, self.evidence)
        self.assertEqual(self.transport.calls, [])

    def test_proposal_reserialization_rejected(self):
        file = self.root/'altered.json'
        file.write_text(json.dumps(self.original))
        with self.assertRaisesRegex(ValueError,'proposal_byte_hash_mismatch'):
            contract.load_proposal(file)

    def test_cli_missing_admission_does_not_construct_transport(self):
        with patch.object(sc, 'TLSMetadataTransport') as transport:
            with self.assertRaisesRegex(sc.CollectionError,'sidecar_admission_inputs_required'):
                sc.main(['--proposal',str(SOURCE/'sidecar-request-PROPOSED.json')])
        transport.assert_not_called()

    def test_report_reservation_after_general_output_cap(self):
        self.evidence.written = self.evidence.CAP - self.evidence.RESERVE
        with self.assertRaises(sc.CollectionError):
            self.evidence.write('ordinary.json', {'a':'b'})
        self.evidence.write('report.json', {'status':'failed'})
        self.assertEqual(self.record('report.json')['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
