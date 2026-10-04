"""Offline only: deny DNS/socket/HTTP entry points for this whole test module."""
import copy
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.request
import http.client
import collector as c

ROOT=Path(__file__).parent
def setUpModule():
    global guards
    guards=[patch.object(socket,'socket',side_effect=AssertionError('NETWORK FORBIDDEN')),patch.object(socket,'create_connection',side_effect=AssertionError('NETWORK FORBIDDEN')),patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS FORBIDDEN')),patch.object(urllib.request,'urlopen',side_effect=AssertionError('HTTP FORBIDDEN')),patch.object(http.client.HTTPConnection,'connect',side_effect=AssertionError('HTTP FORBIDDEN'))]
    for guard in guards: guard.start()
def tearDownModule():
    for guard in reversed(guards): guard.stop()

def document(project='filelock',versions=('2.10','2.9')):
    return json.dumps({'meta':{'api-version':'1.4'},'name':project,'files':[{
        'filename':f'{project}-{v}-py3-none-any.whl','url':f'https://files.pythonhosted.org/packages/{project}-{v}-py3-none-any.whl',
        'hashes':{'sha256':'a'*64},'size':10,'requires-python':'>=3.10','yanked':False,
        'upload-time':'2026-01-01T00:00:00Z','core-metadata':{'sha256':'b'*64}} for v in versions]}).encode()

class Response:
    def __init__(self,raw=None,status=200,headers=None,final=None):
        self.raw=document() if raw is None else raw; self.status=status; self.final_url=final or 'https://pypi.org/simple/filelock/'
        self.headers=headers if headers is not None else [('Content-Type',c.MEDIA),('Content-Length',str(len(self.raw)))]; self.closed=False
    def read(self,n): b=self.raw[:n]; self.raw=self.raw[n:]; return b
    def close(self): self.closed=True
class Fake:
    def __init__(self,responses): self.responses=iter(responses); self.calls=[]
    def open(self,method,url,headers,budget):
        self.calls.append((method,url)); r=next(self.responses)
        if isinstance(r,Exception): raise r
        return r

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'out'; self.m=c.load_manifest(ROOT/'request-manifest.json')
        self.m['requests']=self.m['requests'][:1]  # fake-core fixture only; cannot pass pinned loader
    def run_fake(self,response=None):
        fake=Fake([response or Response()]); report=c.collect(self.m,fake,c.Evidence(self.path))
        return report,fake
    def test_approval_rejection(self):
        with self.assertRaisesRegex(ValueError,'disabled'): c.TLSMetadataTransport(self.m)
        with patch('sys.argv',['collector','--manifest',str(ROOT/'request-manifest.json'),'--output',str(self.path)]):
            with self.assertRaisesRegex(ValueError,'disabled'): c.main()
        self.assertFalse(self.path.exists())
    def test_changed_manifest_hash(self):
        p=Path(self.temp.name)/'m.json'; p.write_text(json.dumps(self.m))
        with self.assertRaisesRegex(ValueError,'hash'): c.load_manifest(p)
    def test_altered_urls_and_method(self):
        for url in ['http://pypi.org/simple/filelock/','https://pypi.org/simple/filelock/?x=1','https://evil.invalid/simple/filelock/','https://pypi.org/simple/filelock/a.whl']:
            self.assertFalse(c.allowed(self.m,'GET',url))
        self.assertFalse(c.allowed(self.m,'HEAD',self.m['requests'][0]['url']))
        self.m['requests'][0]['url']+='?bad=1'; r,f=self.run_fake()
        self.assertEqual(r['status'],'failed'); self.assertEqual(f.calls,[])
    def test_redirect(self):
        r,f=self.run_fake(Response(status=302,headers=[('Location','https://other.invalid/')]))
        self.assertEqual(len(f.calls),1); self.assertIn('redirect',r['errors'][0])
    def test_wrong_status(self):
        self.assertEqual(self.run_fake(Response(status=404))[0]['status'],'failed')
    def test_wrong_content_type(self):
        self.assertEqual(self.run_fake(Response(headers=[('Content-Type','application/json')]))[0]['status'],'failed')
    def test_wrong_final_url(self):
        self.assertEqual(self.run_fake(Response(final='https://pypi.org/simple/other/'))[0]['status'],'failed')
    def test_encoding(self):
        self.assertEqual(self.run_fake(Response(headers=[('Content-Type',c.MEDIA),('Content-Encoding','gzip')]))[0]['status'],'failed')
    def test_malformed_json_and_retained_bytes(self):
        r,_=self.run_fake(Response(raw=b'{bad'))
        self.assertEqual(r['status'],'failed'); self.assertEqual((self.path/'00.body').read_bytes(),b'{bad')
        self.assertTrue((self.path/'00-receipt.json').exists())
    def test_duplicate_json_and_nonfinite(self):
        for raw in [b'{"x":1,"x":2}',b'{"x":NaN}']:
            with self.assertRaises(ValueError): c.strict_json(raw)
    def test_project_mismatch(self):
        self.assertEqual(self.run_fake(Response(raw=document('other')))[0]['status'],'failed')
    def test_upload_time_rejects_offsets(self):
        for value in ['2026-01-01T00:00:00+00:00','2026-01-01T07:00:00+07:00','2026-01-01T00:00:00-01:00']:
            with self.subTest(value=value):
                d=json.loads(document()); d['files'][0]['upload-time']=value
                with self.assertRaisesRegex(ValueError,'upload-time'):
                    c.parse_index(json.dumps(d).encode(),'filelock',self.m['release_upload_cutoff_utc'])
    def test_upload_time_rejects_excess_fraction_and_malformed(self):
        for value in ['2026-01-01T00:00:00.1234567Z','2026-01-01T00:00:00.Z','2026-01-01T00:00:00.1+00:00','2026-01-01T00:00:00,1Z','2026-01-01 00:00:00Z','2026-01-01T00:00:00z','2026-01-01T00:00:00','2026-1-1T00:00:00Z','2026-02-30T00:00:00Z','2026-02-30T00:00:00.1Z','2026-01-01T24:00:00Z','2026-01-01T00:00:60Z']:
            with self.subTest(value=value):
                d=json.loads(document()); d['files'][0]['upload-time']=value
                with self.assertRaises(ValueError): c.parse_index(json.dumps(d).encode(),'filelock',self.m['release_upload_cutoff_utc'])
    def test_upload_time_accepts_one_through_six_fraction_digits(self):
        for fraction in ['1','12','123','1234','12345','123456','000000']:
            with self.subTest(fraction=fraction):
                d=json.loads(document()); d['files'][0]['upload-time']='2026-01-01T00:00:00.'+fraction+'Z'
                self.assertEqual(c.parse_index(json.dumps(d).encode(),'filelock',self.m['release_upload_cutoff_utc'])['gaps'],[])
    def test_upload_time_fraction_preserved_at_cutoff(self):
        d=json.loads(document()); d['files'][0]['upload-time']='2026-10-04T17:37:33.000001Z'
        d['files'][1]['upload-time']='2026-10-04T17:37:33.000000Z'
        r=c.parse_index(json.dumps(d).encode(),'filelock',self.m['release_upload_cutoff_utc'])
        self.assertEqual(len(r['gaps']),1); self.assertEqual(r['gaps'][0]['filename'],d['files'][0]['filename'])
    def test_upload_time_exact_z_and_cutoff(self):
        d=json.loads(document()); d['files'][0]['upload-time']=self.m['release_upload_cutoff_utc']
        d['files'][1]['upload-time']='2026-10-04T17:37:34Z'
        r=c.parse_index(json.dumps(d).encode(),'filelock',self.m['release_upload_cutoff_utc'])
        self.assertEqual(len(r['gaps']),1); self.assertEqual(r['gaps'][0]['reasons'],['after release cutoff'])
    def test_api_v10_rejected_even_with_new_fields(self):
        d=json.loads(document()); d['meta']['api-version']='1.0'
        with self.assertRaisesRegex(ValueError,'require 1.1 through 1.4'):
            c.parse_index(json.dumps(d).encode(),'filelock',self.m['release_upload_cutoff_utc'])
    def test_supported_api_versions(self):
        for api in ['1.1','1.2','1.3','1.4']:
            d=json.loads(document()); d['meta']['api-version']=api
            self.assertEqual(c.parse_index(json.dumps(d).encode(),'filelock',self.m['release_upload_cutoff_utc'])['wheel_records'],2)
    def test_invalid_content_length(self):
        for value in ['1e3','-1','1,1','']:
            with self.assertRaises(ValueError): c.validate_headers(Response(headers=[('Content-Type',c.MEDIA),('Content-Length',value)]),self.m['requests'][0]['url'],self.m['bounds'])
    def test_duplicate_framing(self):
        with self.assertRaises(ValueError): c.validate_headers(Response(headers=[('Content-Type',c.MEDIA),('Content-Length','1'),('Content-Length','1')]),self.m['requests'][0]['url'],self.m['bounds'])
    def test_length_mismatch(self):
        r,_=self.run_fake(Response(raw=b'{}',headers=[('Content-Type',c.MEDIA),('Content-Length','3')]))
        self.assertIn('Content-Length mismatch',r['errors'][0])
    def test_header_limit_before_parse(self):
        class FakeSocket:
            def settimeout(self,value): pass
            def recv(self,n): return b'x'
        b=copy.deepcopy(self.m['bounds']); b['headers_per_response_bytes']=8
        with self.assertRaisesRegex(ValueError,'header limit'):
            c.WireResponse(FakeSocket(),self.m['requests'][0]['url'],c.Budget(b))
    def test_request_bound(self):
        self.m['bounds']['requests']=0
        r,f=self.run_fake(); self.assertEqual(f.calls,[]); self.assertIn('request count',r['errors'][0])
    def test_network_denial_tripwire(self):
        with self.assertRaisesRegex(AssertionError,'NETWORK FORBIDDEN'): socket.create_connection(('example.invalid',443))
    def test_oversized_content_length(self):
        r,_=self.run_fake(Response(headers=[('Content-Type',c.MEDIA),('Content-Length',str(8388609))])); self.assertIn('oversized',r['errors'][0])
    def test_body_limit(self):
        self.m['bounds']['body_per_response_bytes']=3
        r,_=self.run_fake(Response(raw=b'1234',headers=[('Content-Type',c.MEDIA)]))
        self.assertEqual(r['status'],'failed'); self.assertEqual((self.path/'00.body').read_bytes(),b'123')
    def test_aggregate_limit(self):
        raw=document(); self.m['requests'].append({'project':'numpy','url':'https://pypi.org/simple/numpy/','scope':'fake'})
        self.m['bounds']['aggregate_body_bytes']=len(raw)+2
        r=c.collect(self.m,Fake([Response(raw=raw),Response(raw=b'123',headers=[('Content-Type',c.MEDIA)],final='https://pypi.org/simple/numpy/')]),c.Evidence(self.path))
        self.assertEqual(r['retained_body_bytes'],len(raw)+2); self.assertEqual(r['status'],'failed')
        self.assertEqual(json.loads((self.path/'00-receipt.json').read_text())['status'],'metadata_validated_not_approved')
    def test_timeout_partial(self):
        r,_=self.run_fake(TimeoutError('invented socket deadline'))
        self.assertIn('TimeoutError',r['errors'][0]); self.assertTrue((self.path/'started.json').exists())
    def test_backend_overrun(self):
        clock=[0.0]
        class Slow(Fake):
            def open(self,*a): clock[0]=121; return Response()
        r=c.collect(self.m,Slow([]),c.Evidence(self.path),clock=lambda:clock[0]); self.assertEqual(r['status'],'failed')
    def test_pep440_order_and_no_selection(self):
        r,_=self.run_fake(); self.assertEqual(r['status'],'metadata_collected_not_approved')
        d=json.loads((self.path/'00-index.json').read_text()); self.assertEqual(d['display_versions'],['2.9','2.10']); self.assertIsNone(d['selected_versions'])
    def test_artifact_identity_size_and_yanked(self):
        d=json.loads(document())
        for key,value in [('size',True),('yanked',1),('url','https://files.pythonhosted.org/wrong.whl')]:
            altered=copy.deepcopy(d); altered['files'][0][key]=value
            with self.assertRaises(ValueError): c.parse_index(json.dumps(altered).encode(),'filelock',self.m['release_upload_cutoff_utc'])
    def test_no_overwrite(self):
        c.Evidence(self.path)
        with self.assertRaises(FileExistsError): c.Evidence(self.path)
    def test_parent_timeout_mock_only(self):
        class Child:
            calls=0
            def wait(self,timeout):
                self.calls+=1
                if self.calls==1: raise subprocess.TimeoutExpired('fake',timeout)
                return -9
            def kill(self): pass
        # Unit seam only; no actual authorization file/flag modified or process.
        repo=Path(self.temp.name)/'repo'; repo.mkdir()
        policy={'external_root':self.temp.name,'repository_roots':[str(repo)]}
        with patch.object(c,'authorize_network',return_value=None), patch.object(c,'REVIEWED_OUTPUT_POLICY',policy):
            self.assertEqual(c.supervised(ROOT/'request-manifest.json',self.path,popen=lambda *a,**k:Child()),1)
        d=json.loads((self.path/'parent-finished.json').read_text()); self.assertTrue(d['termination_confirmed']); self.assertEqual(d['status'],'failed')

    def path_fixture(self):
        root=Path(self.temp.name)/'external'; root.mkdir()
        repo=Path(self.temp.name)/'repo'; repo.mkdir()
        return root,repo,{'external_root':str(root),'repository_roots':[str(repo)]}
    def test_output_root_unapproved(self):
        with self.assertRaisesRegex(ValueError,'root missing'): c.validate_output_path(self.path,None)
        self.assertFalse(self.path.exists())
    def test_output_outside_root(self):
        root,repo,policy=self.path_fixture()
        with self.assertRaises(ValueError): c.validate_output_path(self.path,policy)
        self.assertFalse(self.path.exists())
    def test_output_inside_repository(self):
        root,repo,policy=self.path_fixture()
        policy['external_root']=self.temp.name
        with self.assertRaisesRegex(ValueError,'inside repository'): c.validate_output_path(repo/'out',policy)
        self.assertFalse((repo/'out').exists())
    def test_root_inside_repository(self):
        root,repo,policy=self.path_fixture(); policy['external_root']=str(repo)
        with self.assertRaisesRegex(ValueError,'root inside repository'): c.validate_output_path(repo/'out',policy)
    def test_existing_output_rejected(self):
        root,repo,policy=self.path_fixture(); out=root/'out'; out.mkdir()
        with self.assertRaisesRegex(ValueError,'already exists'): c.validate_output_path(out,policy)
    def test_traversal_rejected(self):
        root,repo,policy=self.path_fixture()
        with self.assertRaisesRegex(ValueError,'traversal'): c.validate_output_path(root/'..'/'out',policy)
    def test_symlink_ancestor_mocked(self):
        root,repo,policy=self.path_fixture(); link=root/'link'; link.mkdir()
        original=Path.lstat
        def fake(path,*a,**kw):
            if path==link:
                class Info: st_mode=c.stat.S_IFLNK; st_file_attributes=0
                return Info()
            return original(path,*a,**kw)
        with patch.object(Path,'lstat',fake):
            with self.assertRaisesRegex(ValueError,'symlink/reparse'): c.validate_output_path(link/'out',policy)
    def test_valid_temporary_external_path(self):
        root,repo,policy=self.path_fixture(); out=root/'out'
        self.assertEqual(c.validate_output_path(out,policy),out)
        self.assertFalse(out.exists())
    def test_no_output_before_path_checks(self):
        with patch.object(c,'authorize_network',return_value=None):
            with self.assertRaisesRegex(ValueError,'root missing'): c.supervised(ROOT/'request-manifest.json',self.path,popen=lambda *a,**k:self.fail('process started'))
        self.assertFalse(self.path.exists())
    def test_replaced_ancestor_resolves_outside(self):
        root,repo,policy=self.path_fixture(); parent=root/'parent'; parent.mkdir()
        original=Path.resolve
        def fake(path,*a,**kw):
            if path==parent: return repo
            return original(path,*a,**kw)
        with patch.object(Path,'resolve',fake):
            with self.assertRaisesRegex(ValueError,'escapes'): c.validate_output_path(parent/'out',policy)
        self.assertFalse((parent/'out').exists())
    def test_replacement_by_symlink_on_repeat_preflight(self):
        root,repo,policy=self.path_fixture(); parent=root/'parent'; parent.mkdir()
        out=parent/'out'; c.validate_output_path(out,policy)
        original=Path.lstat
        def replaced(path,*a,**kw):
            if path==parent:
                class Info: st_mode=c.stat.S_IFLNK; st_file_attributes=0
                return Info()
            return original(path,*a,**kw)
        with patch.object(Path,'lstat',replaced):
            with self.assertRaisesRegex(ValueError,'symlink'): c.validate_output_path(out,policy)
        self.assertFalse(out.exists())
    def test_destination_appears_after_preflight(self):
        root,repo,policy=self.path_fixture(); out=root/'out'
        checked=c.validate_output_path(out,policy); out.mkdir()
        sentinel=out/'preserve'; sentinel.write_text('invented fixture')
        with self.assertRaises(FileExistsError): c.Evidence(checked)
        self.assertEqual(sentinel.read_text(),'invented fixture')
    def test_live_gate_prevents_creation_even_with_invented_root(self):
        root,repo,policy=self.path_fixture(); out=root/'out'
        with patch.object(c,'REVIEWED_OUTPUT_POLICY',policy), patch.object(c,'validate_output_path',side_effect=AssertionError('must reject authorization first')):
            with self.assertRaisesRegex(ValueError,'disabled'): c.supervised(ROOT/'request-manifest.json',out,popen=lambda *a,**k:self.fail('process launched'))
        self.assertFalse(out.exists())

if __name__=='__main__': unittest.main()
