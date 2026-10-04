"""Offline failure preservation and redaction; no API calls or native runner."""
import hashlib,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import external_review as e
import runtime_acceptance as r
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

if __name__=='__main__':unittest.main()
