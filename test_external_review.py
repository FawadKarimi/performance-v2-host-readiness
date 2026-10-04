"""Invented external approvals only; OS/API/network boundaries remain mocked."""
import copy,datetime as dt,hashlib,importlib.util,json,os
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
import external_review as e
import output_security as fs
import test_collector as fixtures

ROOT=Path(__file__).parent
spec=importlib.util.spec_from_file_location('compat_driver',ROOT/'scripts/run_linux_compatibility.py')
compat=importlib.util.module_from_spec(spec);spec.loader.exec_module(compat)
setUpModule=fixtures.setUpModule
tearDownModule=fixtures.tearDownModule

class Tests(unittest.TestCase):
    def setUp(self):
        probe=patch.object(compat,'package_revisions',return_value={'status':'invented_unresolved'});probe.start();self.addCleanup(probe.stop)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.folder=Path(self.tmp.name)
        self.now=dt.datetime(2026,10,5,tzinfo=dt.timezone.utc)
        self.ctx=dict(repository=e.REPO,commit='a'*40,run_id='123',attempt='1',runner='invented',boot_id='invented-boot',workflow_ref=e.REPO+'/'+e.WORKFLOW+'@refs/heads/main',event='workflow_dispatch',os='Linux',arch='X64')
        self.env={'GITHUB_RUN_ATTEMPT':'1','GITHUB_ACTOR_ID':str(e.OWNER_ID),'GITHUB_RUN_NUMBER':'7'}
        self.hashes={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in e.BOUND}
        self.runtime_hash='b'*64
        self.record=json.loads((ROOT/'external-review-TEMPLATE.json').read_text())
        self.record.update({k:True for k in e.TRUE_FLAGS})
        self.record.update(commit='a'*40,workflow_id=55,run_number=7,run_id=None,
           issued_utc='2026-10-04T23:59:00Z',expires_utc='2026-10-05T00:30:00Z',sources=self.hashes,
           runtime_acceptance_sha256=self.runtime_hash,manifest_sha256=e.sha((ROOT/'request-manifest.json').read_bytes()),
           review_reference='INVENTED',security_review_reference='INVENTED',compatibility_evidence_sha256='c'*64)
        self.run={'id':123,'run_attempt':1,'workflow_id':55,'run_number':7,
           'repository':{'id':e.REPO_ID,'full_name':e.REPO,'private':True},'head_sha':'a'*40,'head_branch':'main',
           'event':'workflow_dispatch','path':e.WORKFLOW,'actor':{'id':e.OWNER_ID},'triggering_actor':{'id':e.OWNER_ID},'status':'in_progress'}
    def check(self):return e.validate(self.record,self.ctx,self.run,self.hashes,self.runtime_hash,self.now,self.env)
    def test_invented_valid_binding_does_not_require_protected_environment(self):
        self.assertTrue(self.check());self.assertIs(self.record['protected_environment_verified'],False)
    def test_unapproved_template_rejected(self):
        self.record=json.loads((ROOT/'external-review-TEMPLATE.json').read_text())
        with self.assertRaisesRegex(ValueError,'approval_missing'):self.check()
    def test_expired_authorization(self):
        self.record['expires_utc']='2026-10-04T23:59:59Z'
        with self.assertRaisesRegex(ValueError,'expired'):self.check()
    def test_wrong_repository_commit_run(self):
        for key,value in [('repository','invented/other'),('commit','d'*40),('run_id','124')]:
            before=self.ctx.copy();self.ctx[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.check()
            self.ctx=before
    def test_replayed_attempt_or_next_dispatch(self):
        self.ctx['attempt']='2'
        with self.assertRaisesRegex(ValueError,'replay_attempt'):self.check()
        self.ctx['attempt']='1';self.run['run_number']=8
        with self.assertRaisesRegex(ValueError,'replayed_dispatch'):self.check()
    def test_recreated_workflow_or_repository_id_rejected(self):
        self.run['workflow_id']=56
        with self.assertRaises(ValueError):self.check()
        self.run['workflow_id']=55;self.run['repository']['id']+=1
        with self.assertRaises(ValueError):self.check()
    def test_wrong_actor_and_runtime_binding(self):
        self.run['actor']['id']=1
        with self.assertRaises(ValueError):self.check()
        self.run['actor']['id']=e.OWNER_ID;self.record['runtime_acceptance_sha256']='e'*64
        with self.assertRaisesRegex(ValueError,'runtime_binding'):self.check()
    def test_no_false_protected_environment_or_scope_expansion(self):
        for flag in e.FALSE_FLAGS:
            self.record[flag]=True
            with self.subTest(flag=flag),self.assertRaisesRegex(ValueError,'scope_expansion'):self.check()
            self.record[flag]=False
    def test_reservation_never_overwrites_on_replay(self):
        first=e.reserve(self.folder,'f'*64,self.ctx)
        raw=(self.folder/'dispatch-reserved.json').read_bytes()
        with self.assertRaises(FileExistsError):e.reserve(self.folder,'f'*64,self.ctx)
        self.assertEqual(raw,(self.folder/'dispatch-reserved.json').read_bytes())
    def test_parent_worker_claims_reconstruct_without_bypassing_validator(self):
        e.write_new(self.folder/'external-record.json',self.record)
        e.write_new(self.folder/'dispatch-binding.json',self.run)
        digest=e.sha((self.folder/'external-record.json').read_bytes())
        e.reserve(self.folder,digest,self.ctx)
        receipt={'external_review':{'record_sha256':digest},'runtime_acceptance_sha256':self.runtime_hash}
        class Clock(dt.datetime):
            @classmethod
            def now(cls,tz=None):return dt.datetime(2026,10,5,tzinfo=dt.timezone.utc)
        with patch.dict(os.environ,self.env),patch.object(e.dt,'datetime',Clock):
            e.reconstruct(receipt,self.folder/'receipt.json',self.ctx,False)
            e.reconstruct(receipt,self.folder/'receipt.json',self.ctx,True)
            with self.assertRaises(FileExistsError):e.reconstruct(receipt,self.folder/'receipt.json',self.ctx,True)
            with self.assertRaises(FileExistsError):e.reconstruct(receipt,self.folder/'receipt.json',self.ctx,False)
    def test_issue_false_record_never_contacts_api(self):
        raw=(ROOT/'external-review-TEMPLATE.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'approval_missing'):
            e.issue(raw,e.sha(raw),self.folder,self.ctx,self.env,fetch=lambda *a:self.fail('API touched'))
    def test_gate_failure_retains_started_and_failed_without_secret(self):
        raw=(ROOT/'external-review-TEMPLATE.json').read_bytes()
        env={'RUNNER_TEMP':str(self.folder),'GITHUB_WORKSPACE':str(self.folder/'repo'),
             'EXTERNAL_RECORD_JSON':raw.decode(),'EXTERNAL_RECORD_SHA256':e.sha(raw),
             'GITHUB_TOKEN':'invented-secret-never-export'}
        # Windows filesystem admission boundary only; real gate rejects false flags.
        with patch.dict(os.environ,env),patch.object(e.admission,'context_from_env',return_value=self.ctx),patch.object(e.admission,'output_policy'):
            self.assertEqual(e.main(),2)
        out=self.folder/'external-review-123-1'
        self.assertTrue((out/'started.json').exists());self.assertTrue((out/'failed.json').exists())
        self.assertFalse((out/'receipt.json').exists())
        self.assertNotIn('invented-secret', ''.join(p.read_text() for p in out.iterdir()))
    def test_api_redirect_rejected_without_retry(self):
        from unittest.mock import Mock
        connection=Mock();response=Mock();response.status=302
        connection.getresponse.return_value=response
        with patch.object(e.http.client,'HTTPSConnection',return_value=connection):
            with self.assertRaisesRegex(ValueError,'external_api_response'):e.api_run('123','invented')
        self.assertEqual(connection.request.call_count,1);connection.close.assert_called_once()
    def test_basic_acl_rejects_extended_default_and_write(self):
        self.assertEqual(len(fs.basic_acl('user::rwx\ngroup::r-x\nother::r-x\n')),3)
        for text in ('user::rwx\ngroup::rwx\nother::r-x','user::rwx\ngroup::r-x\nother::r-x\ndefault:user::rwx','user::rwx\ngroup::r-x\nother::r-x\nuser:1002:rwx'):
            with self.assertRaises(ValueError):fs.basic_acl(text)
    def test_mount_checks_device_type_and_ambiguity(self):
        # os.major/minor are Linux-only OS observations, faked for Windows.
        root=Path(self.folder.anchor)
        text=f'1 0 8:1 / {root} rw - ext4 /dev/fake rw\n'
        with patch.object(fs.os,'major',return_value=8,create=True),patch.object(fs.os,'minor',return_value=1,create=True):
            self.assertEqual(fs.mount_for(self.folder,text,999)['filesystem'],'ext4')
            with self.assertRaises(ValueError):fs.mount_for(self.folder,text.replace('ext4','nfs'),999)
            with self.assertRaises(ValueError):fs.mount_for(self.folder,text+text,999)
    def test_compatibility_runtime_drift_retains_partial_details(self):
        ref={'python':{'version':'invented'},'parser':{'version':'invented'}}
        out=self.folder/'compat';out.mkdir()
        code=compat.execute(out,'fake-parent',123,ref,observe=lambda:{'python':{'version':'drift'},'parser':ref['parser']},
          network_check=lambda *a:{'fake_network_namespace':True},run_tests=lambda:self.fail('tests ran despite drift'))
        self.assertEqual(code,2);self.assertTrue((out/'runtime-observed.json').exists());self.assertTrue((out/'failed.json').exists())
        self.assertFalse((out/'finished.json').exists())
    def test_compatibility_admitted_mock_run_not_accepted(self):
        ref={'python':{'version':'invented'},'parser':{'version':'invented'}}
        out=self.folder/'compat';out.mkdir()
        code=compat.execute(out,'fake-parent',123,ref,observe=lambda:ref,network_check=lambda *a:{'fake':True},run_tests=lambda:{'count':1})
        self.assertEqual(code,0);self.assertIs(json.loads((out/'finished.json').read_text())['native_linux_accepted'],False)
    def test_compatibility_failed_isolation_never_runs_tests(self):
        out=self.folder/'compat';out.mkdir()
        def fail(*a):raise ValueError('invented isolation failure')
        code=compat.execute(out,'parent',123,{},observe=lambda:self.fail('runtime accessed'),network_check=fail)
        self.assertEqual(code,2);self.assertTrue((out/'started.json').exists());self.assertTrue((out/'failed.json').exists())

if __name__=='__main__':unittest.main()
