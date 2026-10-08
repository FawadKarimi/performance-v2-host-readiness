"""Local mocked adapter regressions, separate from the frozen 176-test suite."""
import copy
import json
from pathlib import Path
import shutil
import signal
import tempfile
import unittest
from unittest.mock import Mock, patch
import nine_delta as d


def result():
    return dict(tests=176,failures=0,errors=0,skipped=0,successful=True,
                network_and_subprocess_audit_deny=True,execution_authorized=False,
                source_lock_sha256=d.COLLECTION_SHA)


class DeltaTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'source'
        shutil.copytree(d.ROOT,self.root,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        self.output=Path(self.temp.name)/'evidence'
        self.digest=d.n.sha((self.root/'native-delta-lock.json').read_bytes())
        reference=json.loads((self.root/'reference/metadata-runtime-acceptance.json').read_bytes())
        self.actual={k:copy.deepcopy(reference[k]) for k in ('python','parser')}
        self.observe=Mock(return_value=self.actual)
        self.run_tests=Mock(return_value=result())

    def execute(self, paths=None):
        return d.execute(self.root,self.output,self.digest,'net:parent',1001,
            observe=self.observe,network=Mock(return_value={'isolated':True}),
            run_tests=self.run_tests,run_context=Mock(return_value={'synthetic':True}),
            paths=paths or Mock(return_value={'private':True}))

    def test_current_collection_and_overlay_bindings(self):
        binding=d.verify_sources(self.root,self.digest)
        self.assertEqual(binding['collection_source_lock_sha256'],d.COLLECTION_SHA)
        self.assertEqual(len(binding['files']),46)

    def test_historical_lock_cannot_substitute(self):
        old=d.n.sha((self.root/'source-lock.json').read_bytes())
        with self.assertRaisesRegex(d.n.Rejected,'delta_lock_digest'):d.verify_sources(self.root,old)

    def test_no_runtime_or_tests_on_source_drift(self):
        (self.root/'sidecar_contract.py').write_text('changed')
        self.assertEqual(self.execute(),2)
        self.observe.assert_not_called();self.run_tests.assert_not_called()

    def test_runtime_drift_blocks_tests(self):
        self.actual['parser']['version']='0'
        self.assertEqual(self.execute(),2);self.run_tests.assert_not_called()

    def test_success_is_evidence_not_authorization(self):
        self.assertEqual(self.execute(),0)
        finish=json.loads((self.output/'finished.json').read_bytes())
        self.assertEqual(finish['status'],'synthetic_delta_passed_not_accepted')
        for k in d.n.FALSE_FLAGS:self.assertIs(finish[k],False)
        ledger=json.loads((self.output/'evidence-ledger.json').read_bytes())
        for name,row in ledger['files'].items():self.assertEqual(d.n.sha((self.output/name).read_bytes()),row['sha256'])

    def test_exact_counts_and_flags_required(self):
        for key,value in [('tests',175),('tests',177),('tests',True),('failures',1),('errors',1),('skipped',1),('successful',False),('execution_authorized',True),('source_lock_sha256','0'*64)]:
            r=result();r[key]=value
            with self.subTest(key=key,value=value):
                with self.assertRaisesRegex(d.n.Rejected,'synthetic_test_results'):d.validate_result(r)

    def test_test_failure_retains_post_source_and_ledger(self):
        self.run_tests.side_effect=d.n.Rejected('synthetic_test_exit')
        self.assertEqual(self.execute(),2)
        self.assertTrue((self.output/'source-after.json').exists())
        self.assertTrue((self.output/'evidence-ledger.json').exists())

    def test_interruption_retained_and_handlers_restored(self):
        before=signal.getsignal(signal.SIGTERM)
        self.run_tests.side_effect=KeyboardInterrupt()
        self.assertEqual(self.execute(),2)
        self.assertEqual(signal.getsignal(signal.SIGTERM),before)
        finish=json.loads((self.output/'finished.json').read_bytes())
        self.assertIn('interrupted',finish['errors'])

    def test_post_source_drift_fails(self):
        def changed(*args):
            (self.root/'sidecar_metadata.py').write_text('changed')
            return result()
        self.run_tests.side_effect=changed
        self.assertEqual(self.execute(),2)

    def test_write_failure_still_attempts_exit_finish_and_ledger(self):
        original=d.n.Evidence.write
        called=[]
        def failing(evidence,name,raw):
            called.append(name)
            if name=='test-results.json':raise OSError('invented failure')
            return original(evidence,name,raw)
        with patch.object(d.n.Evidence,'write',failing):self.assertEqual(self.execute(),2)
        self.assertTrue({'source-after.json','exit-status.json','finished.json','evidence-ledger.json'}<=set(called))

    def test_existing_output_is_never_overwritten(self):
        self.output.mkdir();(self.output/'original').write_bytes(b'unchanged')
        with self.assertRaises(FileExistsError):self.execute()
        self.assertEqual((self.output/'original').read_bytes(),b'unchanged')

    def test_synthetic_test_status_preserved(self):
        evidence=d.n.Evidence(self.output)
        with patch.object(d.runpy,'run_path',side_effect=SystemExit(7)):
            with self.assertRaisesRegex(d.n.Rejected,'synthetic_test_exit'):d.synthetic(self.root,evidence)
        self.assertEqual(json.loads((self.output/'test-exit-status.json').read_bytes())['exit_code'],7)

    def rejected_paths(self,exc,created=False):
        import output_security as o
        with patch.object(o,'observe',return_value={},side_effect=None if created else exc) as observed, patch.object(o,'verify_created',side_effect=exc if created else None) as made:
            self.assertEqual(self.execute(paths=d.private_paths),2)
            observed.assert_called_once_with(self.output.parent,self.root,allow_home_default_acl=True)
            if not created:made.assert_not_called()
        self.observe.assert_not_called();self.run_tests.assert_not_called()
        for name in ('failure.json','source-after.json','exit-status.json','finished.json','evidence-ledger.json'):
            self.assertTrue((self.output/name).is_file(),name)
        ledger=json.loads((self.output/'evidence-ledger.json').read_bytes())
        for name,row in ledger['files'].items():
            raw=(self.output/name).read_bytes()
            self.assertEqual({'bytes':len(raw),'sha256':d.n.sha(raw)},row)
            self.assertNotIn(b'SECRET',raw)
        failure=json.loads((self.output/'failure.json').read_bytes())
        self.assertEqual(failure['stage'],'private_paths.created' if created else 'private_paths.observe')
        return failure

    def test_acl_rejection_retains_sanitized_projection(self):
        import output_security as o
        from types import SimpleNamespace
        st=SimpleNamespace(st_uid=1001,st_gid=1001,st_mode=0o755,st_dev=1,st_ino=2)
        obs=o.acl_diagnostic(b'# SECRET /unrestricted\nuser::rwx\ngroup::r-x\nother::r-x\ndefault:user:1001:rwx\n','runner_temp',2,st)
        failure=self.rejected_paths(o.ACLRejected('extended_or_default_acl_rejected',obs))
        self.assertEqual(failure['code'],'extended_or_default_acl_rejected')
        self.assertEqual(failure['acl_observation'],o.safe_acl_diagnostic(obs))

    def test_forged_acl_observation_discarded(self):
        import output_security as o
        failure=self.rejected_paths(o.ACLRejected('acl_format',{'path':'SECRET'}))
        self.assertNotIn('acl_observation',failure)

    def test_owner_mode_rejection(self):
        self.assertEqual(self.rejected_paths(ValueError('path_owner_mode'))['code'],'path_owner_mode')

    def test_unavailable_getfacl(self):
        self.assertEqual(self.rejected_paths(FileNotFoundError('SECRET /getfacl'))['code'],'acl_unavailable')

    def test_getfacl_failed_status(self):
        self.assertEqual(self.rejected_paths(ValueError('acl_unavailable'))['code'],'acl_unavailable')

    def test_created_directory_rejection(self):
        self.assertEqual(self.rejected_paths(ValueError('created_evidence_identity_rejected'),created=True)['code'],'created_evidence_identity_rejected')

    def test_unexpected_path_error_sanitized(self):
        failure=self.rejected_paths(RuntimeError('SECRET credential /unrestricted'))
        self.assertEqual(failure,{'stage':'private_paths.observe','code':'output_security_unexpected','category':'unexpected_exception'})

    def test_unallowlisted_value_error_sanitized(self):
        self.assertEqual(self.rejected_paths(ValueError('SECRET'))['category'],'value_error')

    def test_unexpected_injected_paths_error_has_stage(self):
        self.assertEqual(self.execute(paths=Mock(side_effect=TypeError('SECRET'))),2)
        self.observe.assert_not_called();self.run_tests.assert_not_called()
        failure=json.loads((self.output/'failure.json').read_bytes())
        self.assertEqual(failure,{'stage':'private_paths','code':'unexpected_failure','category':'type_error'})
        self.assertTrue((self.output/'evidence-ledger.json').exists())

    def home_policy(self,text=None,path='/home',depth=3,owner=0,gid=0,mode=0o755,uid=1001,euid=1001,accepted=True):
        import output_security as o
        from types import SimpleNamespace
        if text is None:text=self.home_acl()
        with patch.object(o.os,'getuid',return_value=uid,create=True),patch.object(o.os,'geteuid',return_value=euid,create=True):
            return o.reviewed_home_acl(text,Path(path),depth,SimpleNamespace(st_uid=owner,st_gid=gid,st_mode=mode),accepted)

    def home_acl(self,uid=1001):
        return 'user::rwx\ngroup::r-x\nother::r-x\ndefault:user::rwx\ndefault:user:'+str(uid)+':rwx\ndefault:group::r-x\ndefault:mask::rwx\ndefault:other::r-x\n'

    def test_exact_observed_home_pattern_accepted(self):
        access,record=self.home_policy()
        self.assertEqual(access,['user::rwx','group::r-x','other::r-x'])
        self.assertEqual(record['policy'],'exact_home_default_acl_v1')
        self.assertEqual(record['real_uid'],1001)

    def test_current_uid_not_historical_uid(self):
        self.assertEqual(self.home_policy(text=self.home_acl(2002),uid=2002,euid=2002)[1]['real_uid'],2002)
        with self.assertRaises(ValueError):self.home_policy(uid=2002,euid=2002)

    def test_home_identity_and_scope_negative_matrix(self):
        for change in ({'path':'/home/runner'},{'path':'/tmp'},{'depth':0},{'owner':1001},{'gid':1001},{'mode':0o775},{'mode':0o700},{'uid':0,'euid':0},{'euid':2002},{'accepted':False}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.home_policy(**change)

    def test_other_acl_patterns_rejected(self):
        text=self.home_acl()
        for altered in (text+'default:user:2002:rwx\n',text+'user::rwx\n',text.replace('group::r-x','group::rwx'),text.replace('default:mask::rwx','default:mask::r-x'),text.replace('default:user:1001:rwx','default:user:1002:rwx'),text.replace('other::r-x','other::---'),text+'# comment\n',text.replace('default:user:1001:rwx','default:user:1001:rwx #effective:r-x')):
            with self.subTest(acl=altered),self.assertRaises(ValueError):self.home_policy(text=altered)

    def test_adapter_exact_policy_does_not_bypass_created_check(self):
        import output_security as o
        def observed(*args,**kwargs):
            self.assertIs(kwargs['allow_home_default_acl'],True)
            access,record=self.home_policy()
            return {'reviewed_default_acl_exception':record}
        with patch.object(o,'observe',side_effect=observed),patch.object(o,'verify_created',side_effect=ValueError('created_evidence_acl_rejected')) as created:
            self.assertEqual(self.execute(paths=d.private_paths),2)
            created.assert_called_once_with(self.output)
        self.observe.assert_not_called();self.run_tests.assert_not_called()
        self.assertEqual(json.loads((self.output/'failure.json').read_bytes())['stage'],'private_paths.created')

    def test_created_file_and_directory_reject_default_acl(self):
        import output_security as o
        from types import SimpleNamespace
        for mode in (0o40700,0o100600):
            st=SimpleNamespace(st_mode=mode,st_uid=1001,st_gid=1001,st_dev=1,st_ino=2,st_nlink=1)
            with self.subTest(mode=mode),patch.object(o.os,'getuid',return_value=1001,create=True),patch.object(o.os,'geteuid',return_value=1001,create=True),patch.object(Path,'lstat',return_value=st):
                command=Mock(return_value=SimpleNamespace(returncode=0,stdout=self.home_acl().encode(),stderr=b''))
                with self.assertRaisesRegex(ValueError,'created_evidence_acl_rejected'):o.verify_created(Path('invented'),command=command)
