import copy,hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import collector as c
from test_collector import document,Response,Fake
ROOT=Path(__file__).parent
class TwoIndexTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.out=Path(self.temp.name)/'out';self.m=c.load_manifest(ROOT/'request-manifest.json')
 def run_fake(self,responses):
  f=Fake(responses);r=c.collect(self.m,f,c.Evidence(self.out));return r,f
 def test_exact_scope_and_bound_manifest(self):
  self.assertEqual(c.PROJECTS,('markupsafe','mpmath'));self.assertEqual(self.m['bounds']['requests'],2)
  self.assertEqual(self.m['bounds']['request_wall_seconds'],20);self.assertEqual(self.m['bounds']['aggregate_wall_seconds'],45)
  for method,url in [('HEAD',self.m['requests'][0]['url']),('GET','https://pypi.org/simple/numpy/'),('GET','https://pypi.org/simple/markupsafe/?x=1'),('GET','https://files.pythonhosted.org/f.whl')]:self.assertFalse(c.allowed(self.m,method,url))
 def test_manifest_tampering_rejected(self):
  p=Path(self.temp.name)/'manifest';p.write_bytes((ROOT/'request-manifest.json').read_bytes()+b' ')
  with self.assertRaisesRegex(ValueError,'hash mismatch'):c.load_manifest(p)
 def test_two_success_no_artifact_following(self):
  rs=[Response(document(x),final='https://pypi.org/simple/'+x+'/') for x in c.PROJECTS];r,f=self.run_fake(rs)
  self.assertEqual(len(f.calls),2);self.assertEqual(r['status'],'metadata_collected_not_approved');self.assertFalse(r['dependency_closure_complete'])
  for i in range(2):self.assertIsNone(json.loads((self.out/f'{i:02d}-index.json').read_bytes())['selected_versions'])
 def test_hash_record_exists_before_parser(self):
  real=c.parse_index
  def check(raw,project,cutoff):
   i=c.PROJECTS.index(project);d=json.loads((self.out/f'{i:02d}-body-captured.json').read_bytes());self.assertEqual(d['response_sha256'],hashlib.sha256(raw).hexdigest());return real(raw,project,cutoff)
  with patch.object(c,'parse_index',check):self.run_fake([Response(document(x),final='https://pypi.org/simple/'+x+'/') for x in c.PROJECTS])
 def test_malformed_capture_and_stop(self):
  for idx,raw in enumerate([b'{"name":1,"name":2}',b'{"x":NaN}',b'\xff',b'[]',b'{']):
   with self.subTest(raw=raw):
    self.out=Path(self.temp.name)/str(idx);r,f=self.run_fake([Response(raw)]);self.assertEqual(r['status'],'failed');self.assertEqual(len(f.calls),1);self.assertEqual((self.out/'00.body').read_bytes(),raw);self.assertTrue((self.out/'00-body-captured.json').exists())
 def test_overflow_retains_only_cap(self):
  self.m['bounds']['body_per_response_bytes']=5
  r,f=self.run_fake([Response(b'123456',headers=[('Content-Type',c.MEDIA)])]);self.assertEqual(r['status'],'failed');self.assertEqual((self.out/'00.body').read_bytes(),b'12345');self.assertFalse((self.out/'00-body-captured.json').exists());self.assertTrue((self.out/'00-receipt.json').exists())
 def test_request_and_aggregate_deadlines(self):
  t=[0];b=c.Budget(self.m['bounds'],lambda:t[0]);b.start();t[0]=20
  with self.assertRaises(TimeoutError):b.remaining()
  t[0]=19;b.remaining();t[0]=19.5;b.start();t[0]=39.5
  with self.assertRaises(TimeoutError):b.remaining()
  b.request_end=None;t[0]=45
  with self.assertRaises(TimeoutError):b.remaining()
 def test_timeout_retains_partial_and_no_retry(self):
  class Partial(Response):
   def read(self,n):
    if getattr(self,'read_once',False):raise TimeoutError('invented')
    self.read_once=True;return b'{'
  r,f=self.run_fake([Partial(headers=[('Content-Type',c.MEDIA)])]);self.assertEqual(r['status'],'failed');self.assertEqual(len(f.calls),1);self.assertEqual((self.out/'00.body').read_bytes(),b'{');self.assertTrue((self.out/'report.json').exists())
 def test_second_failure_preserves_first(self):
  r,f=self.run_fake([Response(document('markupsafe')),TimeoutError('invented')]);self.assertEqual(r['requests_attempted'],2);self.assertTrue((self.out/'00-index.json').exists());self.assertEqual(json.loads((self.out/'01-receipt.json').read_bytes())['status'],'failed')
 def test_redirect_rejected_without_body(self):
  r,f=self.run_fake([Response(status=302)]);self.assertEqual(len(f.calls),1);self.assertEqual(r['status'],'failed');self.assertFalse((self.out/'00.body').exists())
 def test_cutoff_and_no_selection(self):
  d=json.loads(document('markupsafe'));d['files'][0]['upload-time']='2026-10-05T00:00:00Z';r=c.parse_index(json.dumps(d).encode(),'markupsafe',self.m['release_upload_cutoff_utc']);self.assertIn('after release cutoff',r['gaps'][0]['reasons']);self.assertIsNone(r['selected_versions'])
 def test_capture_record_failure_prevents_parse_and_retains_body(self):
  real=c.Evidence.write
  def fail(e,name,obj):
   if name.endswith('-body-captured.json'):raise OSError('invented disk failure')
   return real(e,name,obj)
  with patch.object(c.Evidence,'write',fail),patch.object(c,'parse_index') as parse:
   r,f=self.run_fake([Response(document('markupsafe'))]);parse.assert_not_called()
  self.assertEqual(r['status'],'failed');self.assertEqual(len(f.calls),1);self.assertTrue((self.out/'00.body').exists());self.assertTrue((self.out/'00-receipt.json').exists())
 def test_third_request_budget_rejected(self):
  b=c.Budget(self.m['bounds']);b.start();b.start()
  with self.assertRaisesRegex(ValueError,'request count'):b.start()
 def test_old_scope_grant_rejected(self):
  with self.assertRaises(ValueError):c.authorize_network(self.m,{'scope':'14_pypi_discovery_gets_only','receipt_sha256':'a'*64})
if __name__=='__main__':unittest.main()
