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

    def execute(self):
        return d.execute(self.root,self.output,self.digest,'net:parent',1001,
            observe=self.observe,network=Mock(return_value={'isolated':True}),
            run_tests=self.run_tests,run_context=Mock(return_value={'synthetic':True}),
            paths=Mock(return_value={'private':True}))

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
