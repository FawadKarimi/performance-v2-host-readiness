"""Offline failure preservation and redaction; no API calls or native runner."""
import copy,hashlib,json,os,stat,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
import external_review as e
import runtime_acceptance as r
import output_security as fs
import test_collector as fixture
setUpModule=fixture.setUpModule
tearDownModule=fixture.tearDownModule

class Tests(unittest.TestCase):
    def test_failure_code_and_stage_are_closed(self):
        for exc,stage,code in [
            (r.RuntimeRejected('python_identity_mismatch'),'runtime_verification','python_identity_mismatch'),
            (ValueError('external_api_response'),'github_identity_request','external_api_response'),
            (ValueError('extended_or_default_acl_rejected'),'acl_mount_observation','extended_or_default_acl_rejected'),
            (ValueError('mount_filesystem_not_reviewed'),'acl_mount_observation','mount_filesystem_not_reviewed'),
            (TimeoutError('SECRET'),'github_identity_request','operation_timeout'),
            (PermissionError('SECRET'),'output_evidence_write','filesystem_permission_denied'),
            (FileExistsError('SECRET'),'reservation','exclusive_creation_rejected')]:
            with self.subTest(code=code):
                result=e.admission_failure(exc,stage)
                self.assertEqual(result['code'],code);self.assertEqual(result['stage'],stage)
                self.assertNotIn('SECRET',json.dumps(result));self.assertIs(result['raw_exception_retained'],False)
    def test_unknown_payloads_are_redacted(self):
        for exc in [ValueError('Bearer SECRET /private/path'),RuntimeError('SECRET'),r.RuntimeRejected('SECRET')]:
            result=e.admission_failure(exc,'SECRET')
            self.assertEqual(result['code'],'unexpected_error');self.assertEqual(result['stage'],'unknown_stage')
            self.assertNotIn('SECRET',json.dumps(result))
    def test_main_retains_failure_and_exit_two_for_each_boundary(self):
        for stage,exc,code in [
            ('runtime_verification',r.RuntimeRejected('parser_identity_mismatch'),'parser_identity_mismatch'),
            ('github_identity_request',ValueError('external_api_response'),'external_api_response'),
            ('acl_mount_observation',ValueError('mount_device_mismatch'),'mount_device_mismatch'),
            ('receipt_write',RuntimeError('SECRET'),'unexpected_error')]:
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as td:
                raw=b'{}';env={'RUNNER_TEMP':td,'GITHUB_WORKSPACE':td,'EXTERNAL_RECORD_JSON':raw.decode(),'EXTERNAL_RECORD_SHA256':hashlib.sha256(raw).hexdigest()}
                def fail(*args,progress=None,**kwargs):progress(stage);raise exc
                with patch.dict(os.environ,env),patch.object(e.admission,'context_from_env',return_value={'run_id':'123','attempt':'1'}),patch.object(e.admission,'output_policy'),patch.object(e,'issue',side_effect=fail):
                    self.assertEqual(e.main(),2)
                folder=Path(td)/'external-review-123-1'
                self.assertTrue((folder/'started.json').is_file())
                data=json.loads((folder/'failed.json').read_text())
                self.assertEqual(data['stage'],stage);self.assertEqual(data['code'],code)
                self.assertNotIn('SECRET',(folder/'failed.json').read_text())
                self.assertFalse((folder/'finished.json').exists());self.assertFalse((folder/'receipt.json').exists())
    def test_runtime_failure_stage_precedes_api(self):
        with tempfile.TemporaryDirectory() as td:
            record={'issued_utc':'2020-01-01T00:00:00Z','expires_utc':'2099-01-01T00:00:00Z',**{k:True for k in e.TRUE_FLAGS}}
            raw=json.dumps(record).encode();stages=[]
            env={'OWNER_CONFIRMATION':'true','BILLING_CONFIRMATION':'true','GITHUB_TOKEN':'SECRET'}
            with patch.object(e.runtime_acceptance,'verify_record',side_effect=r.RuntimeRejected('python_identity_mismatch')):
                with self.assertRaisesRegex(r.RuntimeRejected,'python_identity_mismatch'):
                    e.issue(raw,e.sha(raw),Path(td),{},env,fetch=lambda *args:self.fail('API invoked'),progress=stages.append)
            self.assertEqual(stages[-1],'runtime_verification')
    def test_exact_validation_codes_do_not_accept_prefixes(self):
        for code in ('external_api_response SECRET','python_identity_mismatch\nSECRET','path_owner_mode:SECRET'):
            self.assertEqual(e.admission_failure(ValueError(code),'input_validation')['code'],'unexpected_error')

class ACLDiagnostics(unittest.TestCase):
    def observation(self,raw):
        before=types.SimpleNamespace(st_uid=1001,st_gid=1001,st_mode=stat.S_IFDIR|0o700,st_dev=8,st_ino=123)
        return fs.acl_diagnostic(raw,'runner_temp',1,before)
    def rejected(self,raw):
        return fs.ACLRejected('extended_or_default_acl_rejected',self.observation(raw))
    def test_basic_policy_unchanged(self):
        self.assertEqual(len(fs.basic_acl('user::rwx\ngroup::r-x\nother::---\n')),3)
        for text in ('user::rwx\ngroup::rwx\nother::---\n',
                     'user::rwx\ngroup::r-x\nother::---\nmask::rwx\n',
                     'user::rwx\ngroup::r-x\nother::---\ndefault:user::rwx\n',
                     'user::rwx\nuser:1002:r-x\ngroup::r-x\nother::---\n'):
            with self.subTest(text=text),self.assertRaises(ValueError):fs.basic_acl(text)
    def test_named_default_mask_and_effective_are_numeric_projection(self):
        raw=b'user::rwx\nuser:1002:rwx\t#effective:r-x\ngroup::r-x\nmask::r-x\nother::---\ndefault:group:1000:rwx\n'
        result=fs.safe_acl_diagnostic(self.observation(raw));self.assertIsNotNone(result)
        self.assertEqual(result['entries'][1],{'default':False,'kind':'user','qualifier':1002,'permissions':'rwx','reported_effective':'r-x'})
        self.assertEqual(result['entries'][3]['kind'],'mask')
        self.assertTrue(result['entries'][5]['default']);self.assertIs(result['policy_accepted'],False)
    def test_malformed_nonascii_and_named_strings_never_retained(self):
        raw=b'user:SECRET:rwx\n/private/SECRET\n\xff\nuser:4294967296:rwx\nmask:10:r-x\n# SECRET\n'
        result=fs.safe_acl_diagnostic(self.observation(raw))
        self.assertEqual(result['unparsed_lines'],5);self.assertEqual(result['comment_lines'],1)
        self.assertEqual(result['entries'],[]);self.assertNotIn('SECRET',json.dumps(result));self.assertNotIn('/private',json.dumps(result))
    def test_entry_and_line_bounds_preserve_incompleteness(self):
        raw=b'user:1002:rwx\n'*20+b'x'*257+b'\n'
        result=fs.safe_acl_diagnostic(self.observation(raw))
        self.assertEqual(len(result['entries']),16);self.assertEqual(result['omitted_entries'],4)
        self.assertEqual(result['unparsed_lines'],1)
        self.assertLessEqual(len(json.dumps(result).encode()),fs.ACL_EVIDENCE_LIMIT)
    def test_projection_revalidation_discards_injected_fields(self):
        good=self.observation(b'user::rwx\n')
        for mutate in (lambda v:v.update(path='SECRET'),lambda v:v.update(anchor='SECRET'),
                       lambda v:v.update(policy_accepted=True),lambda v:v.update(nonblank_lines=100),
                       lambda v:v['entries'][0].update(permissions='SECRET'),
                       lambda v:v['entries'][0].update(qualifier='SECRET'),
                       lambda v:v.update(input_bytes=True)):
            value=copy.deepcopy(good);mutate(value)
            result=e.admission_failure(fs.ACLRejected('acl_format',value),'acl_mount_observation')
            self.assertNotIn('acl_observation',result);self.assertNotIn('SECRET',json.dumps(result))
    def test_wrong_stage_and_code_do_not_export_observation(self):
        result=e.admission_failure(self.rejected(b'user::rwx\n'),'runtime_verification')
        self.assertNotIn('acl_observation',result)
        result=e.admission_failure(fs.ACLRejected('SECRET',self.observation(b'user::rwx\n')),'acl_mount_observation')
        self.assertEqual(result['code'],'unexpected_error');self.assertNotIn('acl_observation',result)
    def test_observe_rejection_links_directory_without_raw_path_or_stderr(self):
        with tempfile.TemporaryDirectory() as td:
            raw=b'user::rwx\nuser:1002:rwx\ngroup::---\nmask::rwx\nother::---\n'
            def command(args,**kwargs):
                self.assertEqual(args[0],'/usr/bin/getfacl');self.assertIn('--numeric',args)
                self.assertLessEqual(kwargs['timeout'],12)
                return types.SimpleNamespace(returncode=0,stdout=raw,stderr=b'SECRET')
            with patch.object(Path,'read_text',return_value=''),self.assertRaises(fs.ACLRejected) as caught:
                fs.observe(td,td,command=command)
            result=e.admission_failure(caught.exception,'acl_mount_observation')
            self.assertEqual(result['acl_observation']['anchor'],'runner_temp')
            self.assertEqual(result['acl_observation']['ancestor_depth'],0)
            self.assertEqual(result['acl_observation']['inode'],Path(td).stat().st_ino)
            self.assertNotIn(td,json.dumps(result));self.assertNotIn('SECRET',json.dumps(result))
    def test_changed_path_retains_failure_without_stable_acl_claim(self):
        first=types.SimpleNamespace(st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o700,st_dev=8,st_ino=1)
        second=copy.copy(first);second.st_ino=2
        def command(*args,**kwargs):return types.SimpleNamespace(returncode=0,stdout=b'mask::rwx\n',stderr=b'')
        with patch.object(Path,'read_text',return_value=''),patch.object(Path,'lstat',side_effect=[first,second]),patch.object(Path,'is_symlink',return_value=False),patch.object(fs.os,'getuid',return_value=0):
            with self.assertRaisesRegex(ValueError,'path_changed') as caught:fs.observe('/invented/root','/invented/workspace',command=command)
        self.assertNotIn('acl_observation',e.admission_failure(caught.exception,'acl_mount_observation'))
    def test_ancestor_depth_and_group_change(self):
        first=types.SimpleNamespace(st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o700,st_dev=8,st_ino=1)
        outputs=[b'user::rwx\ngroup::---\nother::---\n',b'mask::rwx\n']
        def command(*args,**kwargs):return types.SimpleNamespace(returncode=0,stdout=outputs.pop(0),stderr=b'')
        with patch.object(Path,'read_text',return_value=''),patch.object(Path,'lstat',return_value=first),patch.object(Path,'is_symlink',return_value=False),patch.object(fs.os,'getuid',return_value=0),patch.object(fs,'mount_for',return_value={}):
            with self.assertRaises(fs.ACLRejected) as caught:fs.observe('/invented/root','/invented/workspace',command=command)
        result=e.admission_failure(caught.exception,'acl_mount_observation')['acl_observation']
        self.assertEqual(result['anchor'],'runner_temp');self.assertEqual(result['ancestor_depth'],1)
        second=copy.copy(first);second.st_gid=10
        def bad(*args,**kwargs):return types.SimpleNamespace(returncode=0,stdout=b'mask::rwx\n',stderr=b'')
        with patch.object(Path,'read_text',return_value=''),patch.object(Path,'lstat',side_effect=[first,second]),patch.object(Path,'is_symlink',return_value=False),patch.object(fs.os,'getuid',return_value=0):
            with self.assertRaisesRegex(ValueError,'path_changed'):fs.observe('/invented/root','/invented/workspace',command=bad)
    def test_nonascii_native_output_is_rejected_and_redacted(self):
        with tempfile.TemporaryDirectory() as td:
            def command(*args,**kwargs):return types.SimpleNamespace(returncode=0,stdout=b'\xffSECRET\n',stderr=b'')
            with patch.object(Path,'read_text',return_value=''),self.assertRaises(fs.ACLRejected) as caught:fs.observe(td,td,command=command)
            result=e.admission_failure(caught.exception,'acl_mount_observation')
            self.assertEqual(result['code'],'acl_format');self.assertEqual(result['acl_observation']['unparsed_lines'],1)
            self.assertNotIn('SECRET',json.dumps(result))
    def test_main_preserves_acl_evidence_and_exit_two(self):
        with tempfile.TemporaryDirectory() as td:
            raw=b'{}';env={'RUNNER_TEMP':td,'GITHUB_WORKSPACE':td,'EXTERNAL_RECORD_JSON':raw.decode(),'EXTERNAL_RECORD_SHA256':hashlib.sha256(raw).hexdigest()}
            def fail(*args,progress=None,**kwargs):progress('acl_mount_observation');raise self.rejected(b'user:1002:rwx\n')
            with patch.dict(os.environ,env),patch.object(e.admission,'context_from_env',return_value={'run_id':'123','attempt':'1'}),patch.object(e.admission,'output_policy'),patch.object(e,'issue',side_effect=fail):self.assertEqual(e.main(),2)
            folder=Path(td)/'external-review-123-1';result=json.loads((folder/'failed.json').read_text())
            self.assertEqual(result['acl_observation']['entries'][0]['qualifier'],1002)
            self.assertTrue((folder/'started.json').exists());self.assertFalse((folder/'finished.json').exists());self.assertFalse((folder/'receipt.json').exists())

if __name__=='__main__':unittest.main()
