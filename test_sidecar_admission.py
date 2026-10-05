"""Offline synthetic admission checks. No approval records are issued for a run."""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sidecar_admission as a

ROOT = Path(__file__).resolve().parent


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sources = self.root / 'sources'
        self.sources.mkdir()
        for name in a.SOURCE_FILES:
            (self.sources / name).write_text('# invented offline fixture ' + name, encoding='utf-8')
        self.workflow = '.github/workflows/reviewed-sidecar.yml'
        path = self.sources / self.workflow
        path.parent.mkdir(parents=True)
        path.write_text('# not a runnable workflow; identity fixture only', encoding='utf-8')
        self.folder = self.root / 'sidecar-admission-12345-1'
        self.folder.mkdir()
        self.output = self.root / 'pypi-evidence-12345-1'
        self.context = dict(repository=a.REPOSITORY, commit='a' * 40, run_id='12345',
            attempt='1', runner='offline-invented-runner', boot_id='invented-boot',
            workflow_ref=a.REPOSITORY + '/' + self.workflow + '@refs/heads/main',
            event='workflow_dispatch', os='Linux', arch='X64')
        self.env = dict(RUNNER_TEMP=str(self.root), GITHUB_WORKSPACE=str(self.sources),
            GITHUB_RUN_ATTEMPT='1', GITHUB_RUN_NUMBER='9',
            GITHUB_ACTOR_ID=str(a.OWNER_ID), GITHUB_TRIGGERING_ACTOR_ID=str(a.OWNER_ID))
        self.now = dt.datetime.now(dt.timezone.utc)
        self.identity = {'python': {'fixture': 'invented-interpreter'},
                         'parser': {'fixture': 'invented-parser'}}
        self.runtime = dict(schema='metadata_runtime_acceptance_v1',
            scope='public_pypi_metadata_only', metadata_runtime_accepted=True,
            review_reference='SYNTHETIC OFFLINE TEST ONLY', **self.identity)
        self.runtime.update({k: False for k in ('training_authorized',
            'research_execution_authorized', 'artifact_acquisition_authorized',
            'pilot_execution_authorized')})
        self.runtime_path = self.folder / 'runtime-fixture.json'
        self.runtime_hash = self.write(self.runtime_path, self.runtime)
        self.transport = a.transport_template()
        self.transport.update({k: True for k in a.TRANSPORT_APPROVALS})
        self.transport.update(runtime_acceptance_sha256=self.runtime_hash,
            source_hashes=a.source_hashes(self.sources), review_reference='TEST ONLY',
            security_review_reference='TEST ONLY', native_compatibility_review_reference='TEST ONLY')
        self.transport_path = self.folder / 'transport-fixture.json'
        self.transport_hash = self.write(self.transport_path, self.transport)
        self.run = dict(id=12345, run_attempt=1, workflow_id=456, run_number=9,
            repository=dict(id=a.REPOSITORY_ID, full_name=a.REPOSITORY, private=True),
            head_sha='a' * 40, head_branch='main', event='workflow_dispatch',
            path=self.workflow, status='in_progress', actor={'id': a.OWNER_ID},
            triggering_actor={'id': a.OWNER_ID})
        self.run_path = self.folder / 'run-fixture.json'
        self.run_hash = self.write(self.run_path, self.run)
        self.receipt = a.authorization_template()
        self.receipt.update({k: True for k in a.APPROVALS})
        self.receipt.update(source_hashes=a.source_hashes(self.sources),
            runtime_acceptance_sha256=self.runtime_hash, transport_acceptance_sha256=self.transport_hash,
            context=self.context, workflow_path=self.workflow,
            workflow_sha256=a.sha(path.read_bytes()), workflow_id=456, run_number=9,
            run_api_file=self.run_path.name, run_api_sha256=self.run_hash,
            run_api_observed_utc=self.now.isoformat(),
            issued_utc=(self.now - dt.timedelta(seconds=10)).isoformat(),
            expires_utc=(self.now + dt.timedelta(minutes=15)).isoformat())
        self.receipt_path = self.folder / 'receipt-fixture.json'
        self.proposal_path = ROOT / 'sidecar-request-PROPOSED.json'
        self.proposal = json.loads(self.proposal_path.read_text(encoding='utf-8'))
        self.output_policy = {'external_root': str(self.root), 'repository_roots': [str(self.sources)]}
        self.mocks = []
        for target, kwargs in (
            ('admission.context_from_env', {'return_value': self.context}),
            ('admission.output_policy', {'return_value': self.output_policy}),
            ('output_security.observe', {'return_value': {'acl_mount_checked': True}}),
            ('output_security.verify_created', {'return_value': {}}),
            ('output_security.verify_evidence_folder', {'return_value': []}),
            ('socket.create_connection', {'side_effect': AssertionError('NETWORK MUST NOT RUN')})):
            p = patch(target, **kwargs)
            self.mocks.append(p.start())
            self.addCleanup(p.stop)

    def write(self, path, value):
        raw = (json.dumps(value, sort_keys=True) + '\n').encode()
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def load(self, worker=False, **kw):
        receipt_hash = self.write(self.receipt_path, self.receipt)
        args = dict(env=self.env, worker=worker, runtime_path=self.runtime_path,
            runtime_hash=self.runtime_hash, transport_path=self.transport_path,
            transport_hash=self.transport_hash, runtime_observe=lambda: self.identity)
        args.update(kw)
        return a.load_grant(self.proposal_path, self.receipt_path, receipt_hash,
            self.sources, self.output, **args)

    def test_false_templates_reject_without_host_or_network_checks(self):
        self.receipt = a.authorization_template()
        with self.assertRaisesRegex(ValueError, 'sidecar_approval_missing'):
            self.load()
        self.mocks[0].assert_not_called()
        self.mocks[5].assert_not_called()

    def test_templates_keep_all_approvals_false(self):
        for names, record in ((a.APPROVALS + a.FALSE_FLAGS, a.authorization_template()),
                              (a.TRANSPORT_APPROVALS + a.FALSE_FLAGS, a.transport_template())):
            self.assertTrue(all(record[name] is False for name in names))

    def test_old_discovery_receipt_rejected(self):
        self.receipt.update(schema='pv2_public_metadata_admission_v1', scope='14_pypi_discovery_gets_only')
        with self.assertRaisesRegex(ValueError, 'sidecar_authorization_scope'):
            self.load()

    def test_missing_each_approval_and_broader_authorization_rejected(self):
        for key in a.APPROVALS + a.FALSE_FLAGS:
            with self.subTest(key=key):
                before = self.receipt[key]
                self.receipt[key] = not before
                with self.assertRaises(ValueError):
                    self.load()
                self.receipt[key] = before

    def test_changed_proposal_bytes_rejected_before_admission(self):
        self.proposal_path = self.root / 'changed-proposal.json'
        self.write(self.proposal_path, self.proposal)
        with self.assertRaisesRegex(ValueError, 'sidecar_proposal_hash_mismatch'):
            self.load()

    def test_expired_and_future_and_overlong_receipts_rejected(self):
        cases = ((-120, -1), (60, 120), (-1, 7200))
        for issued, expiry in cases:
            with self.subTest(issued=issued, expiry=expiry):
                self.receipt['issued_utc'] = (self.now + dt.timedelta(seconds=issued)).isoformat()
                self.receipt['expires_utc'] = (self.now + dt.timedelta(seconds=expiry)).isoformat()
                with self.assertRaisesRegex(ValueError, 'sidecar_authorization_expired'):
                    self.load()

    def test_changed_source_rejected(self):
        (self.sources / 'sidecar_transport.py').write_text('# drift', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'sidecar_source_drift'):
            self.load()

    def test_unaccepted_transport_rejected(self):
        self.transport['sidecar_transport_accepted'] = False
        self.transport_hash = self.write(self.transport_path, self.transport)
        self.receipt['transport_acceptance_sha256'] = self.transport_hash
        with self.assertRaisesRegex(ValueError, 'sidecar_transport_not_accepted'):
            self.load()

    def test_transport_source_drift_rejected(self):
        self.transport['source_hashes'] = {}
        self.transport_hash = self.write(self.transport_path, self.transport)
        self.receipt['transport_acceptance_sha256'] = self.transport_hash
        with self.assertRaisesRegex(ValueError, 'sidecar_transport_source_binding'):
            self.load()

    def test_runtime_identity_failure_and_missing_runtime_binding(self):
        with self.assertRaisesRegex(ValueError, 'python_identity_mismatch'):
            self.load(runtime_observe=lambda: {'python': {}, 'parser': {}})
        self.receipt['runtime_acceptance_sha256'] = None
        with self.assertRaisesRegex(ValueError, 'sidecar_runtime_binding'):
            self.load()

    def test_wrong_context_run_snapshot_and_stale_snapshot_rejected(self):
        self.receipt['context'] = dict(self.context, run_id='54321')
        with self.assertRaisesRegex(ValueError, 'sidecar_context_mismatch'):
            self.load()
        self.receipt['context'] = self.context
        self.run['head_sha'] = 'b' * 40
        self.receipt['run_api_sha256'] = self.write(self.run_path, self.run)
        with self.assertRaisesRegex(ValueError, 'sidecar_run_state'):
            self.load()
        self.run['head_sha'] = self.context['commit']
        self.receipt['run_api_sha256'] = self.write(self.run_path, self.run)
        self.receipt['run_api_observed_utc'] = (self.now - dt.timedelta(minutes=6)).isoformat()
        with self.assertRaisesRegex(ValueError, 'sidecar_run_snapshot_stale'):
            self.load()

    def test_api_digest_mismatch_and_path_escape_rejected(self):
        self.run_path.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'sidecar_run_api_hash_mismatch'):
            self.load()
        self.receipt['run_api_file'] = '../run.json'
        with self.assertRaisesRegex(ValueError, 'sidecar_run_api_path'):
            self.load()

    def test_wrong_workflow_and_output_rejected(self):
        self.receipt['workflow_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'sidecar_workflow_hash'):
            self.load()
        self.receipt['workflow_sha256'] = a.sha((self.sources / self.workflow).read_bytes())
        self.output = self.root / 'pypi-evidence-999-1'
        with self.assertRaisesRegex(ValueError, 'sidecar_output_run_binding'):
            self.load()

    def test_parent_then_worker_claims_and_worker_only_network_gate(self):
        parent = self.load()
        self.assertEqual(parent['role'], 'parent')
        a.validate_grant(self.proposal, parent)
        with self.assertRaisesRegex(ValueError, 'sidecar_worker_role_required'):
            a.authorize_network(self.proposal, parent)
        worker = self.load(worker=True)
        self.assertEqual(worker['role'], 'worker')
        self.assertTrue(a.authorize_network(self.proposal, worker))
        self.mocks[2].assert_called()
        self.mocks[4].assert_called()
        self.mocks[5].assert_not_called()

    def test_claim_replay_rejected_and_worker_requires_parent(self):
        with self.assertRaises(FileNotFoundError):
            self.load(worker=True)
        self.load()
        with self.assertRaises(FileExistsError):
            self.load()

    def test_bare_or_old_grants_do_not_enable_network(self):
        for grant in (None, {}, {'scope': '14_pypi_discovery_gets_only', 'receipt_sha256': 'a' * 64},
                      {'scope': a.SCOPE, 'proposal_sha256': a.PROPOSAL_SHA256}):
            with self.subTest(grant=grant):
                with self.assertRaises(ValueError):
                    a.authorize_network(self.proposal, grant)

    def test_fresh_acl_failure_rejects_before_claim(self):
        self.mocks[2].side_effect = ValueError('invented_acl_failure')
        with self.assertRaisesRegex(ValueError, 'invented_acl_failure'):
            self.load()
        self.assertFalse((self.folder / 'sidecar-parent-claimed.json').exists())

    def test_worker_cannot_reuse_altered_parent_claim(self):
        self.load()
        path = self.folder / 'sidecar-parent-claimed.json'
        value = json.loads(path.read_text())
        value['output'] = 'different'
        self.write(path, value)
        with self.assertRaisesRegex(ValueError, 'sidecar_parent_claim'):
            self.load(worker=True)

    def test_expired_worker_grant_cannot_start_another_request(self):
        self.load()
        worker = self.load(worker=True)
        worker['expires_utc'] = (self.now - dt.timedelta(seconds=1)).isoformat()
        with self.assertRaisesRegex(ValueError, 'sidecar_grant_expired'):
            a.authorize_network(self.proposal, worker)


if __name__ == '__main__':
    unittest.main()
