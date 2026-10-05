"""Offline parent-process tests; no child or network connection is started."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import sidecar_supervisor as ss


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


class FakeProcess:
    def __init__(self, actions=(0,), stderr=b''):
        self.actions = list(actions)
        self.stderr = io.BytesIO(stderr)
        self.waits = []
        self.kills = 0
        self.terminates = 0

    def wait(self, timeout):
        self.waits.append(timeout)
        action = self.actions.pop(0) if self.actions else 0
        if isinstance(action, BaseException):
            raise action
        if callable(action):
            return action()
        return action

    def kill(self):
        self.kills += 1

    def terminate(self):
        self.terminates += 1


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'excluded-repository'
        self.repo.mkdir()
        self.root = self.base / 'evidence'
        self.root.mkdir()
        self.output = self.root / 'run'
        self.clock = Clock()
        self.proposal_path = Path(__file__).with_name('sidecar-request-PROPOSED.json')
        self.p = json.loads(self.proposal_path.read_bytes())
        self.bodies = [f'offline synthetic metadata fixture {i}\n'.encode() for i in range(7)]
        for request, body in zip(self.p['requests'], self.bodies):
            request['expected_response_sha256'] = hashlib.sha256(body).hexdigest()
        self.grant = {
            'role': 'parent', 'scope': ss.sidecar_admission.SCOPE,
            'receipt_sha256': '1' * 64, 'runtime_acceptance_sha256': '2' * 64,
            'transport_acceptance_sha256': '3' * 64, 'run_api_sha256': '4' * 64,
            'source_hashes': {'offline-fixture': '5' * 64},
            'output': str(self.output),
            'output_policy': {'external_root': str(self.root), 'repository_roots': [str(self.repo)]},
        }
        self.receipt = self.base / 'receipt.json'
        self.runtime = self.base / 'runtime.json'
        self.transport = self.base / 'transport.json'
        for path in (self.receipt, self.runtime, self.transport):
            path.write_text('{}\n', encoding='utf-8')
        patches = {
            'load': patch.object(ss, 'load_proposal', return_value=self.p),
            'grant': patch.object(ss.sidecar_admission, 'validate_grant', return_value=True),
            'network': patch.object(ss.sidecar_admission, 'authorize_network', side_effect=AssertionError('parent network forbidden')),
            'real_process': patch.object(ss.subprocess, 'Popen', side_effect=AssertionError('real process forbidden')),
            'dns': patch('socket.getaddrinfo', side_effect=AssertionError('network forbidden')),
            'socket': patch('socket.socket', side_effect=AssertionError('network forbidden')),
        }
        for name, item in patches.items():
            setattr(self, name + '_mock', item.start())
            self.addCleanup(item.stop)

    def dump(self, path, value):
        path.write_text(json.dumps(value, sort_keys=True) + '\n', encoding='utf-8')

    def worker_files(self, path=None):
        worker = path or self.output / 'worker'
        worker.mkdir(parents=True)
        report = {
            'schema': 'sidecar_collection_report_v1', 'status': 'metadata_collected_not_approved',
            'proposal_sha256': ss.PROPOSAL_SHA256, 'requests_attempted': 7,
            'requests_validated': 7, 'retained_body_bytes': sum(map(len, self.bodies)),
            'failures': [], 'metadata_nominees_only': True,
            'release_upload_cutoff_utc': self.p['release_upload_cutoff_utc'],
            'results': [f'{i:02d}-metadata.json' for i in range(7)],
            'errors': [], **{name: False for name in ss.FALSE_RESULT_FLAGS},
        }
        self.dump(worker / 'report.json', report)
        for i, (request, body) in enumerate(zip(self.p['requests'], self.bodies)):
            prefix = f'{i:02d}'
            digest = hashlib.sha256(body).hexdigest()
            (worker / (prefix + '.body')).write_bytes(body)
            self.dump(worker / (prefix + '-receipt.json'), {
                'schema': 'sidecar_response_receipt_v1', 'proposal_sha256': ss.PROPOSAL_SHA256,
                'request_id': request['id'], 'project': request['project'], 'version': request['version'],
                'url': request['url'], 'method': 'GET', 'headers': request['headers'],
                'expected_response_sha256': digest, 'digest_verified_before_parse': True,
                'retained_file_binding_verified': True, 'http_status': 200,
                'status': 'metadata_validated_not_approved', 'response_sha256': digest,
                'received_retained_bytes': len(body),
            })
            self.dump(worker / (prefix + '-metadata.json'), {
                'schema': 'performance_v2_sidecar_metadata_v1', 'response_sha256': digest,
                'response_bytes': len(body), 'digest_verified_before_parse': True,
                'name': request['project'], 'version': request['version'],
                'frozen_target': self.p['target'], 'scope': 'runtime_no_extras',
                'dependency_closure_complete': False, 'install_selection_approved': False,
                'automatic_recursion': False, 'edges': [], 'unresolved_children': [],
            })
        self.dump(worker / '06-constraints.json', {
            'schema': 'performance_v2_sidecar_constraint_conjunction_v1', 'children': [],
            'dependency_closure_complete': False, 'install_selection_approved': False,
            'automatic_recursion': False, 'all_intersections_proven': False,
        })
        return worker

    def call(self, popen, **overrides):
        args = dict(proposal_path=self.proposal_path, output=self.output,
                    grant=self.grant, receipt_path=self.receipt, receipt_hash='1' * 64,
                    runtime_path=self.runtime, runtime_hash='2' * 64,
                    transport_path=self.transport, transport_hash='3' * 64,
                    popen=popen, clock=self.clock)
        args.update(overrides)
        return ss.supervised(**args)

    def finished(self):
        return json.loads((self.output / 'parent-finished.json').read_bytes())

    def test_success_requires_exact_seven_hash_bound_outputs(self):
        proc = FakeProcess()
        def launch(args, **kwargs):
            self.assertTrue((self.output / 'parent-started.json').is_file())
            self.assertEqual(args[:3], [ss.sys.executable, '-I', '-B'])
            self.assertEqual(Path(args[3]).name, 'sidecar_collector.py')
            for option in ('--proposal', '--output', '--receipt', '--receipt-sha256',
                           '--runtime-record', '--runtime-sha256', '--transport-record',
                           '--transport-sha256', '--worker'):
                self.assertIn(option, args)
            self.assertEqual(kwargs, dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.PIPE, close_fds=True))
            self.worker_files()
            return proc
        self.assertEqual(self.call(launch), 0)
        result = self.finished()
        self.assertEqual(result['status'], 'metadata_collected_not_approved')
        self.assertTrue(result['worker_completion_verified'])
        self.assertTrue(result['termination_confirmed'])
        self.assertEqual(len(result['completion']['bindings']), 7)
        self.assertEqual(result['completion']['retained_body_bytes'], sum(map(len, self.bodies)))
        self.assertTrue(all(result[key] is False for key in ss.FALSE_RESULT_FLAGS))
        self.network_mock.assert_not_called()
        self.real_process_mock.assert_not_called()
        self.dns_mock.assert_not_called()

    def test_authorization_rejection_creates_no_output_and_launches_nothing(self):
        self.grant_mock.side_effect = ValueError('admission rejected')
        launch = Mock()
        with self.assertRaisesRegex(ValueError, 'admission rejected'):
            self.call(launch)
        self.assertFalse(self.output.exists())
        launch.assert_not_called()
        self.network_mock.assert_not_called()

    def test_worker_role_rejected_by_parent(self):
        self.grant['role'] = 'worker'
        launch = Mock()
        with self.assertRaisesRegex(ValueError, 'parent_role'):
            self.call(launch)
        launch.assert_not_called()

    def test_launch_receipt_runtime_transport_hashes_must_match_grant(self):
        for field in ('receipt_hash', 'runtime_hash', 'transport_hash'):
            with self.subTest(field=field):
                launch = Mock()
                with self.assertRaisesRegex(ValueError, 'launch_binding'):
                    self.call(launch, **{field: '9' * 64})
                launch.assert_not_called()

    def test_output_path_bound_and_fresh_and_outside_repository(self):
        launch = Mock()
        with self.assertRaisesRegex(ValueError, 'output_binding'):
            self.call(launch, output=self.root / 'other')
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.call(launch)
        self.output.rmdir()
        self.grant['output'] = str(self.repo / 'bad')
        with self.assertRaises(ValueError):
            self.call(launch, output=self.repo / 'bad')
        launch.assert_not_called()

    def test_zero_exit_without_report_is_failure(self):
        self.assertEqual(self.call(lambda *a, **k: FakeProcess()), 1)
        result = self.finished()
        self.assertEqual(result['error'], 'worker_completion_rejected')
        self.assertFalse(result['worker_completion_verified'])
        self.assertTrue(result['termination_confirmed'])

    def test_nonzero_exit_is_failure_without_reinterpreting_partial_files(self):
        proc = FakeProcess((2,))
        self.assertEqual(self.call(lambda *a, **k: proc), 1)
        self.assertEqual(self.finished()['exit_code'], 2)
        self.assertEqual(self.finished()['error'], 'process_failure')
        self.assertEqual(proc.kills, 0)

    def test_launch_failure_keeps_parent_finish_without_raw_exception(self):
        def launch(*a, **k):
            raise OSError('PRIVATE_TOKEN=do-not-retain')
        self.assertEqual(self.call(launch), 1)
        result = self.finished()
        self.assertEqual(result['error'], 'process_failure')
        self.assertFalse(result['termination_confirmed'])
        self.assertNotIn('PRIVATE_TOKEN', (self.output / 'parent-finished.json').read_text())

    def test_timeout_hard_kills_reaps_and_keeps_partial_body(self):
        proc = FakeProcess((subprocess.TimeoutExpired('private command', 120), -9))
        def launch(*a, **k):
            (self.output / 'worker').mkdir()
            (self.output / 'worker' / '00.body').write_bytes(b'partial bytes')
            return proc
        self.assertEqual(self.call(launch), 1)
        result = self.finished()
        self.assertEqual(result['error'], 'timeout')
        self.assertTrue(result['termination_confirmed'])
        self.assertEqual(proc.kills, 1)
        self.assertEqual(proc.terminates, 0)
        self.assertEqual(proc.waits, [120, 5])
        self.assertEqual((self.output / 'worker' / '00.body').read_bytes(), b'partial bytes')

    def test_deadline_counts_process_launch_elapsed_time(self):
        proc = FakeProcess((2,))
        def launch(*a, **k):
            self.clock.now = 3
            return proc
        self.assertEqual(self.call(launch), 1)
        self.assertEqual(proc.waits, [117])

    def test_late_process_launch_is_killed_without_full_wait(self):
        proc = FakeProcess((-9,))
        def launch(*a, **k):
            self.clock.now = 121
            return proc
        self.assertEqual(self.call(launch), 1)
        self.assertEqual(proc.kills, 1)
        self.assertEqual(proc.waits, [5])

    def test_cancellation_terminates_and_reaps(self):
        proc = FakeProcess((KeyboardInterrupt('private cancellation'), -15))
        self.assertEqual(self.call(lambda *a, **k: proc), 1)
        result = self.finished()
        self.assertEqual(result['error'], 'cancelled')
        self.assertTrue(result['termination_confirmed'])
        self.assertEqual(proc.terminates, 1)
        self.assertEqual(proc.kills, 0)
        self.assertEqual(proc.waits, [120, 1])

    def test_custom_signal_cancellation_base_exception_is_retained(self):
        class SignalCancelled(BaseException):
            pass
        proc = FakeProcess((SignalCancelled(), -15))
        self.assertEqual(self.call(lambda *a, **k: proc), 1)
        self.assertEqual(self.finished()['error'], 'cancelled')
        self.assertTrue(self.finished()['termination_confirmed'])
        self.assertEqual(proc.terminates, 1)

    def test_launch_cancellation_waits_for_child_handle_then_reaps(self):
        before = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        proc = FakeProcess((-15,))
        reached_return = []
        def launch(*args, **kwargs):
            # Model OS child creation followed by signal delivery before Popen
            # returns to the caller. Both signals must queue without throwing.
            for sig in (signal.SIGTERM, signal.SIGINT):
                handler = signal.getsignal(sig)
                self.assertIsNot(handler, before[sig])
                handler(sig, None)
            reached_return.append(True)
            return proc
        self.assertEqual(self.call(launch), 1)
        self.assertEqual(reached_return, [True])
        self.assertEqual(proc.terminates, 1)
        self.assertEqual(proc.waits, [1])
        result = self.finished()
        self.assertEqual(result['error'], 'cancelled')
        self.assertTrue(result['termination_confirmed'])
        self.assertFalse(result['worker_completion_verified'])
        for sig, handler in before.items():
            self.assertIs(signal.getsignal(sig), handler)

    def test_launch_exception_restores_both_signal_handlers(self):
        before = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        def launch(*args, **kwargs):
            self.assertTrue(callable(signal.getsignal(signal.SIGTERM)))
            raise OSError('private process creation failure')
        self.assertEqual(self.call(launch), 1)
        self.assertEqual(self.finished()['error'], 'process_failure')
        for sig, handler in before.items():
            self.assertIs(signal.getsignal(sig), handler)

    def test_system_exit_cancellation_uses_bounded_kill_after_grace(self):
        def grace_timeout():
            self.clock.now = 1
            raise subprocess.TimeoutExpired('private command', 1)
        proc = FakeProcess((SystemExit('private exit'), grace_timeout, -9))
        self.assertEqual(self.call(lambda *a, **k: proc), 1)
        self.assertEqual(self.finished()['error'], 'cancelled')
        self.assertEqual(proc.terminates, 1)
        self.assertEqual(proc.kills, 1)
        self.assertEqual(proc.waits, [120, 1, 4])

    def test_failed_reap_is_explicit(self):
        proc = FakeProcess((subprocess.TimeoutExpired('private', 120),
                            subprocess.TimeoutExpired('private', 5)))
        self.assertEqual(self.call(lambda *a, **k: proc), 1)
        result = self.finished()
        self.assertFalse(result['termination_confirmed'])
        self.assertEqual(result['status'], 'failed')

    def test_stderr_is_bounded_allowlisted_and_never_raw(self):
        stderr = b'SECRET_TOKEN=not-for-evidence\n' + b'X' * 17000 + b'\n'
        stderr += b'{"schema":"worker_error_v1","code":"worker_failure"}\n'
        proc = FakeProcess((2,), stderr)
        self.assertEqual(self.call(lambda *a, **k: proc), 1)
        evidence = json.loads((self.output / 'worker-errors.json').read_bytes())
        self.assertTrue(evidence['overflow'])
        self.assertFalse(evidence['raw_output_retained'])
        self.assertNotIn('SECRET_TOKEN', json.dumps(evidence))
        self.assertLess((self.output / 'worker-errors.json').stat().st_size, 16384)

    def test_completed_worker_past_deadline_is_not_success(self):
        def late_finish():
            self.clock.now = 120
            return 0
        proc = FakeProcess((late_finish,))
        def launch(*a, **k):
            self.worker_files()
            return proc
        self.assertEqual(self.call(launch), 1)
        self.assertEqual(self.finished()['error'], 'timeout')
        self.assertFalse(self.finished()['worker_completion_verified'])

    def test_report_types_counts_hash_and_approval_fields_are_checked(self):
        mutations = [('schema', 'wrong'), ('status', 'success'), ('proposal_sha256', '0' * 64),
                     ('requests_attempted', 6), ('requests_attempted', True),
                     ('requests_validated', 6), ('retained_body_bytes', 1835009),
                     ('retained_body_bytes', True), ('retained_body_bytes', 1),
                     ('errors', ['failure']), ('failures', ['failure']), ('metadata_nominees_only', False),
                     ('release_upload_cutoff_utc', '2099-01-01'), ('results', [])]
        mutations += [(key, True) for key in ss.FALSE_RESULT_FLAGS]
        for index, (key, value) in enumerate(mutations):
            with self.subTest(key=key, value=value):
                worker = self.worker_files(self.base / ('case-' + str(index)))
                report = json.loads((worker / 'report.json').read_bytes())
                report[key] = value
                self.dump(worker / 'report.json', report)
                with self.assertRaises(ValueError):
                    ss.validate_worker_outputs(self.p, worker)

    def test_body_digest_and_missing_receipt_or_parsed_output_rejected(self):
        for index, mutation in enumerate(('digest', 'oversize', 'receipt', 'metadata')):
            with self.subTest(mutation=mutation):
                worker = self.worker_files(self.base / ('case-' + str(index)))
                if mutation == 'digest':
                    (worker / '00.body').write_bytes(b'tampered')
                elif mutation == 'oversize':
                    (worker / '00.body').write_bytes(b'x' * 262145)
                else:
                    (worker / ('00-' + mutation + '.json')).unlink()
                with self.assertRaises((ValueError, FileNotFoundError)):
                    ss.validate_worker_outputs(self.p, worker)

    def test_receipt_identity_and_retained_size_are_checked(self):
        for index, (key, value) in enumerate((('status', 'failed'), ('response_sha256', '0' * 64),
                ('received_retained_bytes', True), ('received_retained_bytes', 0), ('schema', 'wrong'),
                ('proposal_sha256', '0' * 64), ('request_id', 'wrong'), ('project', 'wrong'),
                ('version', 'wrong'), ('url', 'https://wrong.invalid'), ('method', 'HEAD'),
                ('headers', {}), ('expected_response_sha256', '0' * 64),
                ('digest_verified_before_parse', False), ('retained_file_binding_verified', False),
                ('http_status', 404))):
            with self.subTest(key=key):
                worker = self.worker_files(self.base / ('case-' + str(index)))
                receipt = json.loads((worker / '00-receipt.json').read_bytes())
                receipt[key] = value
                self.dump(worker / '00-receipt.json', receipt)
                with self.assertRaises(ValueError):
                    ss.validate_worker_outputs(self.p, worker)

    def test_parsed_identity_scope_and_flags_are_checked(self):
        mutations = [('schema', 'wrong'), ('response_sha256', '0' * 64), ('response_bytes', True),
                     ('digest_verified_before_parse', False), ('name', 'wrong'), ('version', '0'),
                     ('frozen_target', {}), ('scope', 'build'), ('dependency_closure_complete', True),
                     ('install_selection_approved', True), ('automatic_recursion', True),
                     ('edges', {}), ('unresolved_children', {}), ('edges', [{}] * 257)]
        for index, (key, value) in enumerate(mutations):
            with self.subTest(key=key):
                worker = self.worker_files(self.base / ('case-' + str(index)))
                parsed = json.loads((worker / '00-metadata.json').read_bytes())
                parsed[key] = value
                self.dump(worker / '00-metadata.json', parsed)
                with self.assertRaises(ValueError):
                    ss.validate_worker_outputs(self.p, worker)

    def test_duplicate_json_and_oversized_report_rejected(self):
        for index, raw in enumerate((b'{"schema":1,"schema":2}', b'x' * 65537)):
            with self.subTest(index=index):
                worker = self.worker_files(self.base / ('case-' + str(index)))
                (worker / 'report.json').write_bytes(raw)
                with self.assertRaises(ValueError):
                    ss.validate_worker_outputs(self.p, worker)

    def test_final_conjunction_is_required_and_cannot_assert_approval(self):
        mutations = [('schema', 'wrong'), ('dependency_closure_complete', True),
                     ('install_selection_approved', True), ('automatic_recursion', True),
                     ('all_intersections_proven', True), ('children', [{}])]
        for index, (key, value) in enumerate(mutations):
            with self.subTest(key=key):
                worker = self.worker_files(self.base / ('case-' + str(index)))
                data = json.loads((worker / '06-constraints.json').read_bytes())
                data[key] = value
                self.dump(worker / '06-constraints.json', data)
                with self.assertRaises(ValueError):
                    ss.validate_worker_outputs(self.p, worker)
        worker = self.worker_files(self.base / 'missing')
        (worker / '06-constraints.json').unlink()
        with self.assertRaises(FileNotFoundError):
            ss.validate_worker_outputs(self.p, worker)

    def test_conjunction_binds_every_active_inactive_and_unresolved_edge_hash(self):
        worker = self.worker_files(self.base / 'case')
        parsed = json.loads((worker / '00-metadata.json').read_bytes())
        parsed['edges'] = [dict(name='child', specifier='>=1', activity=activity, url=None)
                           for activity in ('active', 'inactive', 'unresolved')]
        self.dump(worker / '00-metadata.json', parsed)
        conjunction = json.loads((worker / '06-constraints.json').read_bytes())
        child = dict(name='child', root_constraint=None, known_nominee_version=None,
                     conjoined_specifier='>=1', constraint_status='child_version_unselected',
                     child_metadata_closed=False, unresolved_requirements_present=True)
        for i, category in enumerate(('active_edges', 'inactive_edges', 'unresolved_edges')):
            ref = dict(parent=parsed['name'], response_sha256=parsed['response_sha256'],
                       edge_index=i, specifier='>=1', self_cycle=False)
            if i == 2:
                ref['reason'] = 'target_marker_value_unknown'
            child[category] = [ref]
        conjunction['children'] = [child]
        self.dump(worker / '06-constraints.json', conjunction)
        result = ss.validate_worker_outputs(self.p, worker)
        self.assertEqual(result['constraints_sha256'], hashlib.sha256((worker / '06-constraints.json').read_bytes()).hexdigest())
        child['inactive_edges'][0]['response_sha256'] = '0' * 64
        self.dump(worker / '06-constraints.json', conjunction)
        with self.assertRaisesRegex(ValueError, 'conjunction_binding'):
            ss.validate_worker_outputs(self.p, worker)

    def test_hardlink_body_rejected(self):
        worker = self.worker_files(self.base / 'case')
        os.link(worker / '00.body', self.base / 'second-link')
        with self.assertRaisesRegex(ValueError, 'layout'):
            ss.validate_worker_outputs(self.p, worker)

    def test_reparse_and_symlink_layout_rejected_before_read(self):
        for mode, attrs in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o600, 0x400)):
            with self.subTest(mode=mode, attrs=attrs):
                path = Mock()
                path.lstat.return_value = SimpleNamespace(st_mode=mode, st_file_attributes=attrs,
                                                          st_nlink=1, st_size=1)
                with self.assertRaisesRegex(ValueError, 'layout'):
                    ss._regular_bytes(path, 10)

    def test_parent_finished_attempted_if_start_record_write_fails(self):
        from sidecar_collector import SidecarEvidence
        real_write = SidecarEvidence.write
        writes = []
        def failing_start(evidence, name, value):
            writes.append(name)
            if name == 'parent-started.json':
                raise OSError('private path failure')
            return real_write(evidence, name, value)
        launch = Mock()
        with patch.object(SidecarEvidence, 'write', failing_start):
            self.assertEqual(self.call(launch), 1)
        self.assertEqual(writes, ['parent-started.json', 'parent-finished.json'])
        launch.assert_not_called()
        self.assertEqual(self.finished()['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
