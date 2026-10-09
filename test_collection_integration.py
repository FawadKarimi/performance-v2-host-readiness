import copy,datetime as dt,hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,Mock
import two_index_collection as i
class IntegrationTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name);self.now=dt.datetime(2026,10,9,3,tzinfo=dt.timezone.utc)
  self.record={k:True for k in i.e.TRUE_FLAGS};self.record.update(collection_source_lock_sha256='a'*64,compatibility_evidence_sha256=i.NATIVE,issued_utc='2026-10-09T03:00:00Z',expires_utc='2026-10-09T03:15:00Z',commit='b'*40,scope='2_pypi_discovery_gets_only',github_identity_get_authorized=True,github_identity_url_template=f'https://api.github.com/repos/{i.e.REPO}/actions/runs/{{run_id}}');self.context={'commit':'b'*40,'attempt':'1'}
 def activate(self):
  raw=json.dumps(self.record).encode();return i.activation(raw,i.c.sha(raw),'a'*64,self.context,self.now)
 def test_exact_window_and_evidence(self):self.assertEqual(self.activate()['commit'],'b'*40)
 def test_inactive_candidate_before_network(self):
  r=json.loads((i.ROOT/'COLLECTION-AUTHORIZATION-INACTIVE.json').read_bytes());raw=json.dumps(r).encode()
  with patch.object(i.e,'api_run') as fetch,self.assertRaises(ValueError):i.activation(raw,i.c.sha(raw),'a'*64,self.context,self.now)
  fetch.assert_not_called()
 def test_window_expired_future_overlong(self):
  for issued,expiry in [('2026-10-09T03:00:01Z','2026-10-09T03:15:00Z'),('2026-10-09T02:45:00Z','2026-10-09T03:00:00Z'),('2026-10-09T03:00:00Z','2026-10-09T03:15:01Z')]:
   self.record.update(issued_utc=issued,expires_utc=expiry)
   with self.assertRaises(ValueError):self.activate()
 def test_lock_evidence_commit_and_identity_scope_drift(self):
  for key,val in [('collection_source_lock_sha256','x'),('compatibility_evidence_sha256','x'),('commit','c'*40),('scope','14_pypi_discovery_gets_only'),('github_identity_get_authorized',False),('github_identity_url_template','https://api.github.com/user')]:
   with self.subTest(key=key):
    old=self.record[key];self.record[key]=val
    with self.assertRaises(ValueError):self.activate()
    self.record[key]=old
 def test_repeat_attempt_and_exclusive_reservation(self):
  self.context['attempt']='2'
  with self.assertRaises(ValueError):self.activate()
  i.e.reserve(self.root,'a'*64,self.context)
  with self.assertRaises(FileExistsError):i.e.reserve(self.root,'a'*64,self.context)
 def fixture(self):
  d={};total=0
  for idx,name in enumerate(i.c.PROJECTS):
   p=f'worker/{idx:02d}';body=b'invented-index';total+=len(body);d[p+'.body']=body;url=f'https://pypi.org/simple/{name}/'
   d[p+'-receipt.json']=json.dumps(dict(project=name,url=url,method='GET',status='metadata_validated_not_approved',response_sha256=i.c.sha(body),received_retained_bytes=len(body))).encode()
   d[p+'-body-captured.json']=json.dumps(dict(url=url,hash_scope='complete captured body before parsing',response_sha256=i.c.sha(body),bytes=len(body))).encode()
   d[p+'-index.json']=json.dumps(dict(project=name,selected_versions=None,artifact_bytes_verified=False)).encode()
  d['worker/report.json']=json.dumps(dict(status='metadata_collected_not_approved',requests_attempted=2,dependency_closure_complete=False,execution_approved=False,retained_body_bytes=total)).encode();d['parent-finished.json']=json.dumps(dict(exit_code=0,termination_confirmed=True,error=None)).encode();return d
 def test_two_complete_records_without_reparse(self):
  with patch.object(i.c,'parse_index') as parser:result=i.validate_completion(self.fixture());parser.assert_not_called()
  self.assertEqual(result['requests_validated'],2);self.assertFalse(result['dependency_lock_complete'])
 def test_missing_second_body_and_tampering(self):
  for mode in ['missing','tamper']:
   d=self.fixture()
   if mode=='missing':del d['worker/01.body']
   else:d['worker/01.body']=b'wrong'
   with self.assertRaises((ValueError,KeyError)):i.validate_completion(d)
 def test_failed_parent_and_wrong_count(self):
  for n,k,v in [('parent-finished.json','exit_code',1),('parent-finished.json','termination_confirmed',False),('worker/report.json','requests_attempted',3)]:
   d=self.fixture();obj=json.loads(d[n]);obj[k]=v;d[n]=json.dumps(obj).encode()
   with self.assertRaises(ValueError):i.validate_completion(d)
 def test_partial_finalization_retains_original_and_source_failure(self):
  launch=self.root/'two-index-collection-launch-7-1';launch.mkdir();(launch/'started.json').write_text('{"original":true}')
  with patch.object(i,'verify_sources',side_effect=ValueError('drift')):self.assertEqual(i.finalize(self.root,self.root,'7','1','a'*64),2)
  record=json.loads((launch/'collection-evidence-ledger.json').read_bytes());self.assertIn('post_source_verification_failed',record['errors']);self.assertIn('required_completion_failed',record['errors']);self.assertEqual((launch/'started.json').read_text(),'{"original":true}')
 def test_admission_get_not_repeated_by_parent_or_worker(self):
  import inspect
  self.assertEqual(inspect.getsource(i.e.issue).count("fetch(context['run_id']"),1)
  self.assertNotIn('api_run(',inspect.getsource(i.e.reconstruct));self.assertNotIn('fetch(',inspect.getsource(i.e.reconstruct))
 def test_workflow_token_scope_and_embedded_gate(self):
  text=(i.ROOT/'.github/workflows/two-index-collection.yml').read_text();self.assertEqual(text.count('GITHUB_TOKEN:'),1)
  for x in ('default: false','--kill-after=5s 45s','--kill-after=5s 60s','if: ${{ always() }}','overwrite: false','two_index_collection.py admit'):self.assertIn(x,text)
  block=text.split("<<'PY'",1)[1].split('\n',1)[1].split('\n          PY',1)[0];compile('\n'.join(x[10:] for x in block.splitlines()),'workflow','exec')
 def test_existing_server_validation_rejects_old_workflow(self):
  import test_external_review as fixtures
  f=fixtures.Tests('test_invented_valid_binding_does_not_require_protected_environment');f.setUp()
  try:
   self.assertTrue(f.check());f.ctx['workflow_ref']=i.e.REPO+'/.github/workflows/two-index-discovery.yml@refs/heads/main'
   with self.assertRaisesRegex(ValueError,'external_workflow'):f.check()
  finally:f.doCleanups()
 def test_new_workflow_parent_worker_single_use_handoff(self):
  import test_external_review as fixtures
  f=fixtures.Tests('test_parent_worker_claims_reconstruct_without_bypassing_validator');f.setUp()
  try:f.test_parent_worker_claims_reconstruct_without_bypassing_validator()
  finally:f.doCleanups()
 def test_new_workflow_identity_only(self):
  self.assertEqual(i.e.WORKFLOW,'.github/workflows/two-index-collection.yml')
  self.assertIn(i.e.WORKFLOW,i.e.BOUND)
if __name__=='__main__':unittest.main()
