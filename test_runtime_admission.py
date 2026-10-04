"""Offline invented runtime/host observations; parent and worker run in-process.

No subprocess, live HTTP, native Linux acceptance or actual approval. Only OS
identity, process and HTTP boundaries are faked; admission checks are real.
"""
import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import collector as c
import runtime_acceptance as runtime
import worker_diagnostics as wd
import test_collector as fixtures

setUpModule=fixtures.setUpModule
tearDownModule=fixtures.tearDownModule
ROOT=Path(__file__).parent
digest=lambda b:hashlib.sha256(b).hexdigest()

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.out=self.base/'pypi-evidence-123-1'
        self.repo=self.base/'repo';self.repo.mkdir()
        self.observed={'python':{'implementation':'CPython','version':'invented-3.12',
                       'cache_tag':'fake-cpython-312','executable_path':'/invented/python',
                       'executable_sha256':'a'*64},
                       'parser':{'name':'packaging','version':'invented-parser',
                       'root':'/invented/packaging','tree_sha256':'b'*64,'files':{'__init__.py':'c'*64}}}
        self.record={'schema':'metadata_runtime_acceptance_v1','scope':'public_pypi_metadata_only',
                     'metadata_runtime_accepted':True,'review_reference':'INVENTED TEST ONLY',
                     **copy.deepcopy(self.observed),'training_authorized':False,
                     'research_execution_authorized':False,'artifact_acquisition_authorized':False,
                     'pilot_execution_authorized':False}
        self.record_path=self.base/'runtime.json';self.receipt_path=self.base/'receipt.json'
    def save_record(self):
        self.record_path.write_text(json.dumps(self.record))
        return digest(self.record_path.read_bytes())
    def test_unaccepted_runtime_rejected_before_observation(self):
        raw=(ROOT/'metadata-runtime-acceptance.json').read_bytes()
        with self.assertRaisesRegex(runtime.RuntimeRejected,'runtime_not_accepted'):
            runtime.verify_record(ROOT/'metadata-runtime-acceptance.json',digest(raw),observe=lambda:self.fail('observed before approval'))
    def test_python_and_parser_mismatch(self):
        h=self.save_record()
        for part in ('python','parser'):
            for field in self.observed[part]:
                bad=copy.deepcopy(self.observed);bad[part][field]='wrong'
                with self.subTest(part=part,field=field),self.assertRaisesRegex(runtime.RuntimeRejected,part+'_identity_mismatch'):
                    runtime.verify_record(self.record_path,h,observe=lambda:bad)
    def test_runtime_hash_and_scope_rejection(self):
        h=self.save_record()
        with self.assertRaisesRegex(runtime.RuntimeRejected,'hash_mismatch'):
            runtime.verify_record(self.record_path,'0'*64,observe=lambda:self.observed)
        for flag in ('training_authorized','research_execution_authorized','artifact_acquisition_authorized','pilot_execution_authorized'):
            self.record[flag]=True;h=self.save_record()
            with self.assertRaisesRegex(runtime.RuntimeRejected,'scope_rejected'):
                runtime.verify_record(self.record_path,h,observe=lambda:self.observed)
            self.record[flag]=False
    def integration(self, worker_mismatch=False, parent_mismatch=False, receipt_corruption=False):
        h=self.save_record()
        ctx={'repository':'invented/private','commit':'a'*40,'run_id':'123','attempt':'1',
             'runner':'invented','boot_id':'invented-boot','workflow_ref':'invented/ref',
             'event':'workflow_dispatch','os':'Linux','arch':'X64'}
        sources={n:digest((ROOT/n).read_bytes()) for n in ('collector.py','admission.py','runtime_acceptance.py','worker_diagnostics.py')}
        now=dt.datetime.now(dt.timezone.utc)
        receipt=json.loads((ROOT/'authorization-TEMPLATE.json').read_text())
        receipt.update(owner_authorized=True,independent_workflow_reviewed=True,zero_paid_usage_confirmed=True,
                       same_uid_residual_risk_accepted=True,context=ctx,source_hashes=sources,
                       runtime_acceptance_sha256=h,issued_utc=(now-dt.timedelta(seconds=1)).isoformat(),
                       expires_utc=(now+dt.timedelta(minutes=5)).isoformat())
        self.receipt_path.write_text(json.dumps(receipt));rh=digest(self.receipt_path.read_bytes())
        mapping={'repository':'GITHUB_REPOSITORY','commit':'GITHUB_SHA','run_id':'GITHUB_RUN_ID',
                 'attempt':'GITHUB_RUN_ATTEMPT','runner':'RUNNER_NAME','workflow_ref':'GITHUB_WORKFLOW_REF',
                 'event':'GITHUB_EVENT_NAME','os':'RUNNER_OS','arch':'RUNNER_ARCH'}
        env={v:ctx[k] for k,v in mapping.items()}
        env.update(GITHUB_ACTIONS='true',RUNNER_TEMP=str(self.base),GITHUB_WORKSPACE=str(self.repo),INVENTED_SECRET='NEVER_RETAIN_THIS')
        argv=['--manifest',str(ROOT/'request-manifest.json'),'--output',str(self.out),
              '--authorization',str(self.receipt_path),'--authorization-sha256',rh,
              '--runtime-acceptance',str(self.record_path),'--runtime-acceptance-sha256',h]
        bad=copy.deepcopy(self.observed);bad['parser']['version']='changed-between-processes'
        observations=[bad] if parent_mismatch else [self.observed,bad if worker_mismatch else self.observed]
        original_read=Path.read_text;original_stat=Path.stat;original_lstat=Path.lstat
        def read(path,*args,**kwargs):
            if str(path).replace('\\','/')=='/proc/sys/kernel/random/boot_id':return ctx['boot_id']
            return original_read(path,*args,**kwargs)
        def linux_info(original,path,*args,**kwargs):
            info=original(path,*args,**kwargs)
            if stat.S_ISDIR(info.st_mode):return SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o700)
            return info
        process_calls=[]
        def fake_popen(args,**kwargs):
            process_calls.append(args)
            if receipt_corruption:self.receipt_path.write_text('{}')
            stderr=io.StringIO()
            with contextlib.redirect_stderr(stderr):code=c.entry(args[4:])
            return SimpleNamespace(stderr=io.BytesIO(stderr.getvalue().encode()),wait=lambda timeout:code,kill=lambda:None)
        # Full manifest traverses the real loaders; only HTTP is invented. The
        # second request fails so partial evidence, not research output, results.
        fake_http=fixtures.Fake([fixtures.Response(),TimeoutError('invented timeout')])
        def fake_transport(manifest,grant):
            c.authorize_network(manifest,grant)
            return fake_http
        err=io.StringIO()
        old_umask=os.umask(0o077)
        try:
            with patch.dict(os.environ,env),patch.object(Path,'read_text',read),\
                 patch.object(Path,'lstat',lambda path,*args,**kw:linux_info(original_lstat,path,*args,**kw)),\
                 patch.object(Path,'stat',lambda path,*args,**kw:linux_info(original_stat,path,*args,**kw)),\
                 patch('admission.os.getuid',return_value=0,create=True),\
                 patch.object(runtime,'observed_identity',side_effect=observations),\
                 patch.object(c.subprocess,'Popen',side_effect=fake_popen),\
                 patch.object(c,'TLSMetadataTransport',side_effect=fake_transport),contextlib.redirect_stderr(err):
                code=c.entry(argv)
        finally:os.umask(old_umask)
        return code,process_calls,fake_http,err.getvalue()
    def test_parent_runtime_mismatch_no_output_or_worker(self):
        code,calls,http,err=self.integration(parent_mismatch=True)
        self.assertEqual(code,2);self.assertEqual(calls,[]);self.assertEqual(http.calls,[])
        self.assertFalse(self.out.exists());self.assertIn('parser_identity_mismatch',err)
    def test_worker_reconstructs_runtime_and_retains_mismatch(self):
        code,calls,http,err=self.integration(worker_mismatch=True)
        self.assertEqual(code,1);self.assertEqual(len(calls),1);self.assertEqual(http.calls,[])
        d=json.loads((self.out/'worker-errors.json').read_text())
        self.assertEqual(d['records'],[{'schema':'worker_error_v1','code':'parser_identity_mismatch'}])
        self.assertTrue(d['drain_complete']);self.assertFalse((self.out/'worker').exists())
    def test_worker_reconstructs_receipt_and_retains_admission_failure(self):
        code,calls,http,err=self.integration(receipt_corruption=True)
        self.assertEqual(code,1);self.assertEqual(http.calls,[])
        d=json.loads((self.out/'worker-errors.json').read_text())
        self.assertEqual(d['records'][0]['code'],'authorization_hash_mismatch')
    def test_reconstruction_passes_then_partial_http_evidence(self):
        code,calls,http,err=self.integration()
        self.assertEqual(code,1);self.assertEqual(len(calls),1);self.assertEqual(len(http.calls),2)
        self.assertTrue((self.out/'worker/00-index.json').exists())
        self.assertTrue((self.out/'worker/01-receipt.json').exists())
        started=json.loads((self.out/'worker/started.json').read_text())
        self.assertEqual(started['scoped_metadata_admission']['runtime_acceptance']['parser'],self.observed['parser'])
        self.assertEqual(json.loads((self.out/'worker/report.json').read_text())['status'],'failed')
        self.assertNotIn('NEVER_RETAIN_THIS',''.join(p.read_text() for p in self.out.rglob('*.json')))
    def test_bounded_failure_channel_drops_raw_and_extra_fields(self):
        valid=json.dumps({'schema':'worker_error_v1','code':'parser_identity_mismatch'}).encode()+b'\n'
        invalid=json.dumps({'schema':'worker_error_v1','code':'worker_failure','secret':'NEVER_RETAIN_THIS'}).encode()+b'\n'
        cap=wd.Capture(io.BytesIO(valid+invalid+b'NEVER_RETAIN_THIS\n'+b'x'*20000))
        d=cap.finish();self.assertTrue(d['overflow']);self.assertTrue(d['drain_complete'])
        self.assertEqual(len(d['records']),1);self.assertNotIn('NEVER_RETAIN_THIS',json.dumps(d))
        self.assertEqual(wd.error_record(ValueError('NEVER_RETAIN_THIS'))['code'],'worker_failure')

if __name__=='__main__':unittest.main()
