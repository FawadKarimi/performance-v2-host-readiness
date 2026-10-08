"""Offline bootstrap, one-control-GET and parent/worker delivery tests."""
import copy
import datetime as dt
import json
from pathlib import Path
import shutil
import unittest
from unittest.mock import Mock, patch

import sidecar_admission as a
import sidecar_bootstrap as b
import test_sidecar_admission as fixtures

ROOT = Path(__file__).resolve().parent

# Literal fixture contract: admission SOURCE_FILES plus verify_lock requirements.
FIXTURE_SOURCE_FILES = (
    'sidecar_contract.py', 'sidecar_metadata.py', 'sidecar_transport.py',
    'sidecar_collector.py', 'sidecar_supervisor.py', 'sidecar_admission.py',
    'admission.py', 'collector.py', 'runtime_acceptance.py',
    'output_security.py', 'worker_diagnostics.py', 'sidecar_bootstrap.py',
    '.github/workflows/sidecar-collection.yml', 'source-lock.json',
    'sidecar-request-PROPOSED.json',
)


def copy_fixture_sources(source, destination):
    for name in FIXTURE_SOURCE_FILES:
        dest = destination / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, dest)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.AdmissionTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.sources
        copy_fixture_sources(ROOT, self.root)
        # The existing fixture created a folder; bootstrap itself must create it once.
        for p in self.f.folder.iterdir():
            p.unlink()
        self.f.folder.rmdir()
        self.f.context['workflow_ref'] = a.REPOSITORY + '/' + b.WORKFLOW + '@refs/heads/main'
        self.f.run['path'] = b.WORKFLOW
        self.env = dict(self.f.env, GITHUB_REPOSITORY=a.REPOSITORY,
            GITHUB_SHA='a'*40, GITHUB_REF='refs/heads/main', GITHUB_TRIGGERING_ACTOR='FawadKarimi',
            GITHUB_RUN_ID='12345', GITHUB_TOKEN='synthetic_token_never_persist',
            OWNER_AUTHORIZATION='true', BILLING_CONFIRMATION='true')
        self.record = json.loads((ROOT/'review-records/collection-activation-PROPOSED.json').read_bytes())
        self.record.update({k: True for k in b.APPROVALS})
        self.record.update(commit='a'*40,workflow_id=456,run_number=9,
            source_hashes=a.source_hashes(self.root),
            workflow_sha256=a.sha((self.root/b.WORKFLOW).read_bytes()),
            issued_utc=(self.f.now-dt.timedelta(seconds=5)).isoformat(),
            expires_utc=(self.f.now+dt.timedelta(minutes=10)).isoformat(),
            review_reference='SYNTHETIC TEST ONLY',security_review_reference='SYNTHETIC TEST ONLY')
        self.record['native_acceptance']['accepted'] = True
        self.record['runtime_record']['metadata_runtime_accepted'] = True
        self.runtime = self.record['runtime_record']
        self.actual = {k:copy.deepcopy(self.runtime[k]) for k in ('python','parser')}
        self.record['transport_record'].update({k:True for k in a.TRANSPORT_APPROVALS})
        self.record['transport_record'].update(source_hashes=self.record['source_hashes'],
            runtime_acceptance_sha256=a.sha(b.encoded(self.runtime)))
        self.relock()
        self.fetch = Mock(side_effect=lambda context,token,sink:sink(b.encoded(self.f.run)))

    def relock(self):
        lock=dict(schema='sidecar_collection_source_lock_v1',collection_authorized=False,
            files={name:a.sha((self.root/name).read_bytes())
                   for name in FIXTURE_SOURCE_FILES})
        raw=b.encoded(lock);(self.root/b.LOCK_NAME).write_bytes(raw)
        self.lockhash=a.sha(raw);self.record['collection_source_lock_sha256']=self.lockhash

    def issue(self):
        raw=b.encoded(self.record)
        return b.issue(raw,a.sha(raw),self.lockhash,self.env,self.root,fetch=self.fetch,
                       observe_runtime=lambda:self.actual)

    def test_fixture_list_matches_required_bindings(self):
        required=set(a.SOURCE_FILES)|{b.WORKFLOW,'sidecar_bootstrap.py',
                                    'source-lock.json','sidecar-request-PROPOSED.json'}
        self.assertEqual(set(FIXTURE_SOURCE_FILES),required)
        self.assertEqual(len(FIXTURE_SOURCE_FILES),len(required))
        self.assertEqual(set(json.loads((self.root/b.LOCK_NAME).read_bytes())['files']),required)
        self.assertLessEqual(len(required),100)

    def test_populated_git_caches_and_unrelated_files_do_not_change_fixture(self):
        source=self.f.root/'polluted';source.mkdir()
        copy_fixture_sources(ROOT,source)
        for i in range(125):
            path=source/'.git/objects'/str(i);path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(b'invented git object')
        for name in ('__pycache__/unrelated.pyc','.pytest_cache/state','unrelated.txt'):
            path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'unrelated')
        clean=self.f.root/'clean';dirty=self.f.root/'dirty'
        copy_fixture_sources(ROOT,clean);copy_fixture_sources(source,dirty)
        inventory=lambda folder:{p.relative_to(folder).as_posix():p.read_bytes() for p in folder.rglob('*') if p.is_file()}
        self.assertEqual(inventory(clean),inventory(dirty))
        self.assertEqual(set(inventory(dirty)),set(FIXTURE_SOURCE_FILES))
        # Relocking is explicit too: destination pollution cannot expand membership.
        (self.root/'unrelated.txt').write_bytes(b'unrelated')
        before=(self.root/b.LOCK_NAME).read_bytes();self.relock()
        self.assertEqual((self.root/b.LOCK_NAME).read_bytes(),before)
        (self.root/'sidecar_bootstrap.py').write_bytes(b'drift')
        with self.assertRaisesRegex(ValueError,'collection_source_drift'):self.issue()
        self.fetch.assert_not_called()

    def admit(self,worker=False):
        folder=self.f.folder
        return a.load_grant(self.root/'sidecar-request-PROPOSED.json',folder/'receipt.json',
            a.sha((folder/'receipt.json').read_bytes()),self.root,self.f.output,
            env=self.env,worker=worker,runtime_path=folder/'runtime.json',
            runtime_hash=a.sha((folder/'runtime.json').read_bytes()),
            transport_path=folder/'transport.json',
            transport_hash=a.sha((folder/'transport.json').read_bytes()),
            runtime_observe=lambda:self.actual)

    def test_delivery_reaches_real_parent_and_worker_admission(self):
        folder=self.issue()
        self.fetch.assert_called_once()
        parent=self.admit();worker=self.admit(worker=True)
        self.assertEqual((parent['role'],worker['role']),('parent','worker'))
        self.assertEqual(parent['run_api_sha256'],worker['run_api_sha256'])
        self.assertEqual(parent['context']['run_id'],'12345')
        for k in a.FALSE_FLAGS:self.assertIs(worker[k],False)
        self.assertTrue((folder/'sidecar-parent-claimed.json').exists())
        self.assertTrue((folder/'sidecar-worker-claimed.json').exists())
        self.assertNotIn(self.env['GITHUB_TOKEN'].encode(),b''.join(p.read_bytes() for p in folder.iterdir()))

    def test_inactive_record_rejected_before_capture(self):
        self.record=json.loads((ROOT/'review-records/collection-activation-PROPOSED.json').read_bytes())
        with self.assertRaisesRegex(ValueError,'activation_inactive'):self.issue()
        self.fetch.assert_not_called()
        self.assertFalse(self.f.folder.exists())

    def test_each_confirmation_required_and_no_broader_scope(self):
        for key in b.APPROVALS+a.FALSE_FLAGS:
            with self.subTest(key=key):
                before=self.record[key];self.record[key]=not before
                with self.assertRaises(ValueError):self.issue()
                self.record[key]=before
        self.fetch.assert_not_called()

    def test_commit_workflow_run_and_expiry_bindings_reject(self):
        mutations={'commit':'b'*40,'workflow_sha256':'0'*64,'run_number':10,
            'workflow_id':None,'collection_source_lock_sha256':'0'*64,
            'expires_utc':(self.f.now-dt.timedelta(seconds=1)).isoformat()}
        for k,v in mutations.items():
            with self.subTest(key=k):
                old=self.record[k];self.record[k]=v
                with self.assertRaises(ValueError):self.issue()
                self.record[k]=old
        self.fetch.assert_not_called()

    def test_default_dispatch_flags_and_rerun_rejected(self):
        for k,v in [('OWNER_AUTHORIZATION','false'),('BILLING_CONFIRMATION','false'),
                    ('GITHUB_RUN_ATTEMPT','2'),('GITHUB_ACTOR_ID','1')]:
            old=self.env[k];self.env[k]=v
            with self.assertRaises(ValueError):self.issue()
            self.env[k]=old
        self.fetch.assert_not_called()

    def test_native_evidence_or_unaccepted_transport_rejected(self):
        self.record['native_acceptance']['evidence']['run_id']=37301817652
        with self.assertRaisesRegex(ValueError,'native_acceptance'):self.issue()
        self.fetch.assert_not_called()

    def test_source_drift_rejected_before_capture(self):
        (self.root/'sidecar_bootstrap.py').write_bytes(b'drift')
        with self.assertRaisesRegex(ValueError,'collection_source_drift'):self.issue()
        self.fetch.assert_not_called()

    def test_runtime_drift_rejected_before_capture(self):
        self.actual['python']['version']='0'
        with self.assertRaisesRegex(ValueError,'python_identity_mismatch'):self.issue()
        self.fetch.assert_not_called()
        self.assertTrue((self.f.folder/'failed.json').exists())

    def test_wrong_api_identity_retained_without_receipt(self):
        self.f.run['id']=999
        with self.assertRaisesRegex(ValueError,'sidecar_run_identity'):self.issue()
        self.assertTrue((self.f.folder/'run-api.json').exists())
        self.assertFalse((self.f.folder/'receipt.json').exists())

    def test_malformed_api_json_retained(self):
        self.fetch.side_effect=lambda c,t,s:s(b'{bad')
        with self.assertRaises(ValueError):self.issue()
        self.assertEqual((self.f.folder/'run-api.json').read_bytes(),b'{bad')
        self.assertFalse((self.f.folder/'receipt.json').exists())

    def test_timeout_retains_prefix_and_does_not_retry(self):
        def fail(c,t,s):
            s(b'partial');raise TimeoutError()
        self.fetch.side_effect=fail
        with self.assertRaises(TimeoutError):self.issue()
        self.fetch.assert_called_once()
        self.assertEqual((self.f.folder/'run-api.json').read_bytes(),b'partial')
        self.assertTrue((self.f.folder/'failed.json').exists())

    def test_cancellation_retains_prefix(self):
        def fail(c,t,s):
            s(b'partial');raise KeyboardInterrupt()
        self.fetch.side_effect=fail
        with self.assertRaises(KeyboardInterrupt):self.issue()
        self.assertTrue((self.f.folder/'failed.json').exists())

    def test_existing_folder_refuses_replay_without_second_get(self):
        self.issue()
        with self.assertRaises(FileExistsError):self.issue()
        self.fetch.assert_called_once()

    def test_changed_snapshot_rejected_by_worker(self):
        self.issue();self.admit()
        (self.f.folder/'run-api.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'sidecar_run_api_hash_mismatch'):self.admit(True)

    def test_worker_cannot_admit_without_parent_claim(self):
        self.issue()
        with self.assertRaises(FileNotFoundError):self.admit(True)

    def test_worker_rechecks_snapshot_age(self):
        self.issue();self.admit()
        receipt=json.loads((self.f.folder/'receipt.json').read_bytes())
        receipt['run_api_observed_utc']=(self.f.now-dt.timedelta(minutes=6)).isoformat()
        (self.f.folder/'receipt.json').write_bytes(b.encoded(receipt))
        with self.assertRaisesRegex(ValueError,'sidecar_run_snapshot_stale'):self.admit(True)

    def test_expiry_during_capture_prevents_receipt(self):
        # Simulate elapsed wall time, preserving the original activation bytes.
        future=self.f.now+dt.timedelta(minutes=20)
        raw=b.encoded(self.record)
        with patch.object(b.dt,'datetime',wraps=dt.datetime) as clock:
            clock.now.return_value=future
            with self.assertRaisesRegex(ValueError,'activation_expired'):
                b.issue(raw,a.sha(raw),self.lockhash,self.env,self.root,fetch=self.fetch,
                        observe_runtime=lambda:self.actual,now=self.f.now)
        self.fetch.assert_called_once()
        self.assertFalse((self.f.folder/'receipt.json').exists())
        self.assertTrue((self.f.folder/'failed.json').exists())

    def test_source_drift_during_capture_prevents_receipt(self):
        def fetch(c,t,s):
            s(b.encoded(self.f.run))
            (self.root/'sidecar_bootstrap.py').write_bytes(b'drift')
        self.fetch.side_effect=fetch
        with self.assertRaisesRegex(ValueError,'collection_source_drift'):self.issue()
        self.assertFalse((self.f.folder/'receipt.json').exists())

    def test_workflow_defaults_lock_checks_and_token_separation(self):
        workflow=(ROOT/b.WORKFLOW).read_text()
        self.assertIn("for name,digest in lock['files'].items():",workflow)
        self.assertIn('default: false',workflow)
        self.assertNotIn('push:',workflow)
        self.assertIn('github.run_attempt == 1',workflow)
        collection=workflow.split('- name: Independently admit parent and worker;',1)[1].split('- name: Retain bounded',1)[0]
        self.assertIn('/usr/bin/env -i',collection)
        self.assertNotIn('GITHUB_TOKEN',collection)
        self.assertNotIn('ACTIVATION_JSON',collection)


class FakeSocket:
    def __init__(self,raw):self.raw=bytearray(raw);self.sent=[];self.closed=False
    def settimeout(self,n):pass
    def sendall(self,raw):self.sent.append(raw)
    def recv(self,n):
        chunk=bytes(self.raw[:n]);del self.raw[:n];return chunk
    def close(self):self.closed=True


class ApiTransportTests(unittest.TestCase):
    def wire(self,status=200,headers=None,body=b'{}'):
        headers=({'Content-Length':str(len(body)),'Content-Type':'application/json'}
                 if headers is None else headers)
        return ('HTTP/1.1 '+str(status)+' test\r\n'+''.join(k+': '+v+'\r\n'
                for k,v in headers.items())+'\r\n').encode()+body
    def call(self,raw,clock=lambda:0):
        sock=FakeSocket(raw);chunks=[]
        connect=Mock(return_value=sock)
        b.capture_api({'run_id':'123'},'synthetic-token',chunks.append,connect=connect,clock=clock)
        return sock,chunks,connect

    def test_literal_single_get_and_closed_socket(self):
        s,chunks,connect=self.call(self.wire())
        self.assertEqual(chunks,[b'{}']);connect.assert_called_once()
        self.assertEqual(len(s.sent),1);self.assertTrue(s.closed)
        self.assertTrue(s.sent[0].startswith(b'GET /repos/FawadKarimi/performance-v2-host-readiness/actions/runs/123 HTTP/1.1'))
        self.assertIn(b'Host: api.github.com\r\n',s.sent[0])

    def test_redirect_errors_encodings_and_oversize_rejected(self):
        cases=[self.wire(status=302),self.wire(status=404),
          self.wire(headers={'Transfer-Encoding':'chunked'}),
          self.wire(headers={'Content-Length':str(b.API_CAP+1)}),
          self.wire(headers={'Content-Length':'2','Content-Type':'application/json','Content-Encoding':'gzip'})]
        for raw in cases:
            sock=FakeSocket(raw);connect=Mock(return_value=sock)
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                b.capture_api({'run_id':'123'},'token',lambda x:None,connect=connect,clock=lambda:0)
            connect.assert_called_once();self.assertTrue(sock.closed);self.assertEqual(len(sock.sent),1)

    def test_header_bound_and_malformed_status(self):
        for raw in (b'x'*16385,b'BAD\r\n\r\n'):
            with self.assertRaises(ValueError):self.call(raw)

    def test_truncation_retains_prefix_and_closes(self):
        sock=FakeSocket(self.wire(headers={'Content-Length':'5','Content-Type':'application/json'},body=b'abc'))
        chunks=[]
        with self.assertRaisesRegex(ValueError,'api_truncated'):
            b.capture_api({'run_id':'123'},'token',chunks.append,connect=lambda _:sock,clock=lambda:0)
        self.assertEqual(chunks,[b'abc']);self.assertTrue(sock.closed)

    def test_token_or_run_injection_rejected_before_connect(self):
        connect=Mock()
        for context,token in [({'run_id':'../1'},'token'),({'run_id':'1'},'bad\r\nHost: other')]:
            with self.assertRaises(ValueError):b.capture_api(context,token,lambda x:None,connect=connect)
        connect.assert_not_called()

    def test_deadline_has_no_retry(self):
        clock=Mock(side_effect=[0,21])
        connect=Mock(return_value=FakeSocket(b''))
        with self.assertRaises(TimeoutError):
            b.capture_api({'run_id':'123'},'token',lambda x:None,connect=connect,clock=clock)
        connect.assert_called_once()


if __name__=='__main__':unittest.main()
