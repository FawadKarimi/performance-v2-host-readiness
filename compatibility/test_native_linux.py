"""Synthetic control/failure tests; no namespace, subprocess, DNS or collection."""
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import signal
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import native_linux as n


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'source';self.root.mkdir()
        # Copy only frozen review members, never a future checkout's .git or data.
        reviewed=json.loads((n.ROOT/'source-lock.json').read_bytes())['files']
        for name in reviewed:
            path=n.ROOT/name
            dest=self.root/name
            dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(path.read_bytes())
        self.lock=dict(schema='sidecar_linux_compatibility_source_lock_v1',
            input_package_sha256=n.INPUT_SHA,proposal_sha256=n.PROPOSAL_SHA,
            execution_authorized=False,expected_synthetic_tests=1234,
            files={p.relative_to(self.root).as_posix():n.sha(p.read_bytes())
                   for p in self.root.rglob('*') if p.is_file()})
        self.save_lock()
        self.output=Path(self.tmp.name)/'evidence'
        self.reference=json.loads((self.root/'reference/metadata-runtime-acceptance.json').read_bytes())
        self.actual={key:self.reference[key] for key in ('python','parser')}
        self.network=Mock(return_value={'interfaces':[[1,'lo']],'loopback_up':False})
        self.observe=Mock(return_value=self.actual)
        self.tests=Mock(return_value={'tests':1234,'successful':True})
        self.ctx=Mock(return_value={'values':{'run_id':'synthetic'},'provenance':'synthetic'})

    def save_lock(self):
        raw=json.dumps(self.lock,sort_keys=True).encode()
        (self.root/'source-lock.json').write_bytes(raw)
        self.digest=n.sha(raw)

    def execute(self):
        return n.execute(self.root,self.output,self.digest,'net:[parent]',1001,
            observe=self.observe,network=self.network,run_tests=self.tests,run_context=self.ctx)

    def record(self,name):
        return json.loads((self.output/name).read_bytes())

    def test_pass_is_not_acceptance_and_seals_bindings(self):
        self.assertEqual(self.execute(),0)
        result=self.record('finished.json')
        for key in n.FALSE_FLAGS:self.assertIs(result[key],False)
        self.assertEqual(result['source_lock_sha256'],self.digest)
        self.assertEqual(result['workflow_sha256'],self.lock['files'][n.WORKFLOW])
        self.assertEqual(result['test_results_sha256'],n.sha((self.output/'test-results.json').read_bytes()))
        ledger=self.record('evidence-ledger.json')
        for name,entry in ledger['files'].items():
            self.assertEqual(n.sha((self.output/name).read_bytes()),entry['sha256'])

    def test_lock_mismatch_prevents_runtime_and_tests(self):
        self.digest='0'*64
        self.assertEqual(self.execute(),2)
        self.observe.assert_not_called();self.tests.assert_not_called()
        self.assertEqual(self.record('failed.json')['error_code'],'source_lock_digest')

    def test_source_mutation_refused(self):
        (self.root/'sidecar_collector.py').write_text('# altered')
        self.assertEqual(self.execute(),2)
        self.tests.assert_not_called()

    def test_source_changed_during_tests_refused(self):
        def tests(*args):
            (self.root/'sidecar_metadata.py').write_text('# changed')
            return {'tests':1234}
        self.tests.side_effect=tests
        self.assertEqual(self.execute(),2)
        self.assertFalse((self.output/'finished.json').exists())

    def test_proposal_change_fails_even_if_lock_updated(self):
        path=self.root/'sidecar-request-PROPOSED.json';path.write_bytes(path.read_bytes()+b' ')
        self.lock['files'][path.name]=n.sha(path.read_bytes());self.save_lock()
        self.assertEqual(self.execute(),2)
        self.assertEqual(self.record('failed.json')['error_code'],'proposal_drift')

    def test_traversal_lock_rejected(self):
        self.lock['files']['../escape']='0'*64;self.save_lock()
        with self.assertRaisesRegex(n.Rejected,'source_lock_path'):n.verify_sources(self.root,self.digest)

    def test_duplicate_lock_json_rejected(self):
        raw=b'{"schema":1,"schema":2}'
        (self.root/'source-lock.json').write_bytes(raw)
        with self.assertRaisesRegex(n.Rejected,'duplicate_json_key'):n.verify_sources(self.root,n.sha(raw))

    def test_wrong_scope_lock_rejected(self):
        self.lock['execution_authorized']=True;self.save_lock()
        self.assertEqual(self.execute(),2)
        self.observe.assert_not_called()

    def test_network_failure_preserves_start_and_failure(self):
        self.network.side_effect=n.Rejected('network_namespace_not_separate')
        self.assertEqual(self.execute(),2)
        self.assertTrue((self.output/'started.json').exists())
        self.assertTrue((self.output/'evidence-ledger.json').exists())
        self.observe.assert_not_called();self.tests.assert_not_called()

    def test_runtime_drift_retained_without_tests(self):
        actual=copy.deepcopy(self.actual);actual['python']['version']='3.12.99'
        self.observe.return_value=actual
        self.assertEqual(self.execute(),2)
        self.assertEqual(self.record('runtime-observed.json'),actual)
        self.tests.assert_not_called()

    def test_parser_drift_retained_without_tests(self):
        actual=copy.deepcopy(self.actual);actual['parser']['tree_sha256']='0'*64
        self.observe.return_value=actual
        self.assertEqual(self.execute(),2)
        self.tests.assert_not_called()

    def test_cancellation_retains_partial_logs_and_restores_handlers(self):
        before={s:signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT)}
        def tests(root,evidence):
            evidence.write('partial.log',b'bounded partial test evidence')
            raise n.Cancelled()
        self.tests.side_effect=tests
        self.assertEqual(self.execute(),2)
        self.assertEqual(self.record('failed.json')['status'],'cancelled')
        self.assertEqual((self.output/'partial.log').read_bytes(),b'bounded partial test evidence')
        self.assertEqual(before,{s:signal.getsignal(s) for s in before})

    def test_timeout_stops_without_success(self):
        self.tests.side_effect=TimeoutError('PRIVATE')
        self.assertEqual(self.execute(),2)
        self.assertNotIn('PRIVATE',(self.output/'failed.json').read_text())
        self.assertFalse((self.output/'finished.json').exists())

    def test_missing_runtime_keeps_failure(self):
        self.observe.side_effect=FileNotFoundError('PRIVATE')
        self.assertEqual(self.execute(),2)
        self.assertTrue((self.output/'failed.json').exists())

    def test_output_replay_rejected(self):
        self.output.mkdir()
        with self.assertRaises(FileExistsError):self.execute()

    def test_bounded_output_prefix_retained(self):
        path=Path(self.tmp.name)/'bounded.log';stream=n.BoundedText(path,cap=5)
        try:
            with self.assertRaisesRegex(n.Rejected,'test_log_cap'):stream.write('123456789')
        finally:stream.close()
        self.assertEqual(path.read_bytes(),b'12345')

    def test_evidence_oversize_rejected(self):
        evidence=n.Evidence(self.output)
        with self.assertRaisesRegex(n.Rejected,'evidence_size'):evidence.write('large',b'x'*1048577)

    def test_synthetic_result_requires_count_and_false_authorization(self):
        cases=[{'tests':0},{'execution_authorized':True},{'errors':1},{'skipped':1},
               {'successful':False},{'network_and_subprocess_audit_deny':False},{'source_lock_sha256':'bad'}]
        for i,change in enumerate(cases):
            evidence=n.Evidence(Path(self.tmp.name)/str(i))
            result=dict(tests=1234,successful=True,failures=0,errors=0,skipped=0,
                        network_and_subprocess_audit_deny=True,execution_authorized=False,source_lock_sha256=self.digest)
            result.update(change)
            def run(*args,**kwargs):print(json.dumps(result));raise SystemExit(0)
            with patch.object(n.runpy,'run_path',side_effect=run):
                with self.assertRaisesRegex(n.Rejected,'synthetic_test_results'):n.synthetic(self.root,evidence)

    def test_synthetic_run_is_in_process_and_no_collection_cli(self):
        evidence=n.Evidence(self.output)
        result=dict(tests=1234,successful=True,failures=0,errors=0,skipped=0,
                    network_and_subprocess_audit_deny=True,execution_authorized=False,source_lock_sha256=self.digest)
        def run(path,run_name):
            self.assertEqual(Path(path),self.root/'compatibility/review_offline_tests.py')
            print(json.dumps(result));raise SystemExit(0)
        with patch.object(n.runpy,'run_path',side_effect=run):self.assertEqual(n.synthetic(self.root,evidence),result)

    def test_synthetic_failure_log_retained(self):
        evidence=n.Evidence(self.output)
        def run(*args,**kwargs):print('synthetic failure',file=sys.stderr);raise SystemExit(1)
        with patch.object(n.runpy,'run_path',side_effect=run):
            with self.assertRaisesRegex(n.Rejected,'synthetic_test_exit'):n.synthetic(self.root,evidence)
        self.assertIn('synthetic failure',(self.output/'tests.log').read_text())

    def test_isolation_requires_nonroot_and_distinct_namespace(self):
        with patch.object(n.sys,'platform','linux'),patch.object(n.os,'getuid',return_value=0,create=True),patch.object(n.os,'geteuid',return_value=0,create=True):
            with self.assertRaisesRegex(n.Rejected,'linux_unprivileged_uid'):n.isolation('net:[1]',0)
        with patch.object(n.sys,'platform','linux'),patch.object(n.os,'getuid',return_value=1001,create=True),patch.object(n.os,'geteuid',return_value=1001,create=True),patch.object(n.os,'readlink',return_value='net:[1]'):
            with self.assertRaisesRegex(n.Rejected,'network_namespace_not_separate'):n.isolation('net:[1]',1001)

    def test_isolation_rejects_extra_interface(self):
        with patch.object(n.sys,'platform','linux'),patch.object(n.os,'getuid',return_value=1001,create=True),patch.object(n.os,'geteuid',return_value=1001,create=True),patch.object(n.os,'readlink',return_value='net:[2]'),patch.object(n.socket,'if_nameindex',return_value=[(1,'lo'),(2,'eth0')]):
            with self.assertRaisesRegex(n.Rejected,'network_interfaces'):n.isolation('net:[1]',1001)

    def test_missing_context_cannot_succeed(self):
        with self.assertRaisesRegex(n.Rejected,'run_context_incomplete'):n.context({})

    def test_loopback_and_privilege_controls(self):
        for flags,status,passes in ((8,'NoNewPrivs:\t1\nCapEff:\t0\n',True),
                                    (9,'NoNewPrivs:\t1\nCapEff:\t0\n',False),
                                    (8,'NoNewPrivs:\t0\nCapEff:\t0\n',False),
                                    (8,'NoNewPrivs:\t1\nCapEff:\t1\n',False)):
            fake=SimpleNamespace(ioctl=Mock(return_value=struct.pack('16sH22x',b'lo',flags)))
            with patch.object(n.sys,'platform','linux'),patch.object(n.os,'getuid',return_value=1001,create=True),patch.object(n.os,'geteuid',return_value=1001,create=True),patch.object(n.os,'readlink',return_value='net:[2]'),patch.object(n.socket,'if_nameindex',return_value=[(1,'lo')]),patch.object(n.socket,'socket') as sock,patch.dict(sys.modules,{'fcntl':fake}),patch.object(Path,'read_text',return_value=status):
                sock.return_value.__enter__.return_value.fileno.return_value=99
                if passes:self.assertTrue(n.isolation('net:[1]',1001)['no_new_privs'])
                else:
                    with self.assertRaises(n.Rejected):n.isolation('net:[1]',1001)

    def test_run_context_binding_and_provenance(self):
        env=dict(GITHUB_REPOSITORY='FawadKarimi/performance-v2-host-readiness',
                 GITHUB_SHA='a'*40,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',
                 GITHUB_RUN_NUMBER='4',GITHUB_WORKFLOW_REF='FawadKarimi/performance-v2-host-readiness/'+n.WORKFLOW+'@refs/heads/main',
                 GITHUB_ACTOR_ID='108207574',GITHUB_TRIGGERING_ACTOR='FawadKarimi',RUNNER_NAME='synthetic')
        with patch.object(Path,'read_text',return_value='synthetic-boot'):
            self.assertIn('not independently authenticated',n.context(env)['provenance'])
            for key,value in (('GITHUB_RUN_ATTEMPT','2'),('GITHUB_SHA','bad'),('GITHUB_WORKFLOW_REF','wrong')):
                with self.assertRaises(n.Rejected):n.context({**env,key:value})

    def test_manual_workflow_has_no_install_collection_or_index_step(self):
        text=(self.root/n.WORKFLOW).read_text()
        self.assertIn('workflow_dispatch:',text)
        self.assertNotRegex(text,r'(?m)^  (push|pull_request|schedule):')
        self.assertEqual(text.count('default: false'),2)
        self.assertNotRegex(text,r'(?i)(pip install|apt-get|curl |wget |sidecar_collector.py|pypi.org|files.pythonhosted.org|download-artifact)')
        self.assertIn('/usr/bin/unshare --net',text)
        self.assertIn('/usr/bin/setpriv --no-new-privs',text)
        self.assertIn('/usr/bin/python3.12 -I -B compatibility/native_linux.py',text)
        self.assertIn('trap finish EXIT',text)
        self.assertIn('if: ${{ always() }}',text)
        self.assertLess(text.index('bootstrap-started.json'),text.index('uses: actions/checkout@'))
        self.assertEqual(len(re.findall(r'uses: actions/[^@]+@[0-9a-f]{40}',text)),2)


if __name__=='__main__':unittest.main()
