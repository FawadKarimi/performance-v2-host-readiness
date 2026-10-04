"""Synthetic/static only. No live inventory invocation or network permitted."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import test_collector as fixtures

setUpModule=fixtures.setUpModule
tearDownModule=fixtures.tearDownModule
ROOT=Path(__file__).parent
SCRIPT=ROOT/'scripts/inspect_metadata_runtime.py'
spec=importlib.util.spec_from_file_location('synthetic_inventory',SCRIPT)
inventory=importlib.util.module_from_spec(spec);spec.loader.exec_module(inventory)

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.repo=self.base/'repo';self.repo.mkdir()
        self.root=self.base/'external';self.root.mkdir()
        self.output=self.root/'metadata-runtime-inventory-123-1'
    def test_synthetic_tree_hash_uses_acceptance_convention(self):
        root=self.base/'parser';root.mkdir();(root/'__init__.py').write_bytes(b'# invented\n')
        (root/'version.py').write_bytes(b'# invented version\n')
        cache=root/'__pycache__';cache.mkdir();(cache/'ignored.pyc').write_bytes(b'ignored')
        result=inventory.parser_tree(root)
        expected={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ('__init__.py','version.py')}
        self.assertEqual(result['files'],expected)
        self.assertEqual(result['tree_sha256'],hashlib.sha256(json.dumps(expected,sort_keys=True,separators=(',',':')).encode()).hexdigest())
    def test_missing_parser_does_not_prevent_later_snapshot(self):
        out=inventory.prepare_output(self.root,self.repo,self.output)
        def missing():raise FileNotFoundError('invented private value not for report')
        code=inventory.run(out,[('python',lambda:{'fake':True}),('packaging',missing),('paths',lambda:{'fake':True})])
        self.assertEqual(code,1);self.assertTrue((out/'01-python.json').exists());self.assertTrue((out/'03-paths.json').exists())
        report=json.loads((out/'report.json').read_text())
        self.assertEqual(report['status'],'partial_not_accepted');self.assertEqual(report['errors'][0]['step'],'packaging')
        self.assertNotIn('invented private value',json.dumps(report))
        self.assertTrue(all(report[k] is False for k in inventory.FLAGS))
        ledger=json.loads((out/'manifest.json').read_text())['files']
        for n,v in ledger.items():self.assertEqual(hashlib.sha256((out/n).read_bytes()).hexdigest(),v['sha256'])
    def test_success_is_observation_never_acceptance(self):
        out=inventory.prepare_output(self.root,self.repo,self.output)
        self.assertEqual(inventory.run(out,[('invented',lambda:{'value':'fake'})]),0)
        r=json.loads((out/'report.json').read_text());self.assertEqual(r['status'],'observed_not_accepted')
        self.assertTrue(all(r[k] is False for k in inventory.FLAGS))
    def test_interruption_leaves_started_and_prior_evidence(self):
        out=inventory.prepare_output(self.root,self.repo,self.output)
        def interrupted():raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):inventory.run(out,[('first',lambda:1),('interrupted',interrupted)])
        self.assertTrue((out/'00-started.json').exists());self.assertTrue((out/'01-first.json').exists())
        self.assertFalse((out/'report.json').exists())
    def test_no_overwrite_and_path_boundaries(self):
        inventory.prepare_output(self.root,self.repo,self.output)
        with self.assertRaisesRegex(ValueError,'already_exists'):inventory.prepare_output(self.root,self.repo,self.output)
        with self.assertRaises(ValueError):inventory.prepare_output(self.repo,self.repo,self.repo/self.output.name)
        with self.assertRaises(ValueError):inventory.prepare_output(self.root,self.repo,self.root/'..'/self.output.name)
    def test_bounded_hash_and_tree_file_count(self):
        p=self.base/'big';p.write_bytes(b'12345')
        with self.assertRaisesRegex(ValueError,'size_limit'):inventory.file_hash(p,4)
        root=self.base/'tree';root.mkdir();(root/'__init__.py').write_bytes(b'x');(root/'a.py').write_bytes(b'x')
        with patch.object(inventory,'MAX_FILES',1),self.assertRaisesRegex(ValueError,'file_limit'):inventory.parser_tree(root)
    def test_script_has_no_network_subprocess_or_collector_import(self):
        tree=ast.parse(SCRIPT.read_text())
        imports=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imports.extend(a.name.split('.')[0] for a in node.names)
            if isinstance(node,ast.ImportFrom):imports.append(node.module.split('.')[0])
        self.assertTrue(set(imports)<=set('argparse hashlib importlib json os pathlib platform stat sys'.split()))
    def test_workflow_is_separate_pinned_manual_bounded_and_retains_failure(self):
        import yaml
        path=ROOT/'.github/workflows/metadata-runtime-inventory.yml'
        text=path.read_text();d=yaml.load(text,Loader=yaml.BaseLoader)
        self.assertEqual(set(d['on']),{'workflow_dispatch'})
        self.assertTrue(all(i['default']=='false' for i in d['on']['workflow_dispatch']['inputs'].values()))
        job=d['jobs']['inventory'];self.assertNotIn('environment',job)
        self.assertEqual(job['runs-on'],'ubuntu-24.04');self.assertEqual(job['timeout-minutes'],'3')
        self.assertEqual(d['permissions'],{'contents':'read'})
        steps=job['steps'];run=steps[1]['run']
        self.assertIn(hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),run)
        self.assertIn('/usr/bin/python3 -I -B scripts/inspect_metadata_runtime.py',run)
        self.assertIn('--kill-after=5s 60s',run);self.assertIn('immediate-exit-status.txt',run)
        self.assertNotIn('collector.py',text);self.assertNotIn('secrets.',text)
        self.assertEqual(steps[-1]['if'],'${{ always() }}')
        self.assertEqual(steps[-1]['with']['overwrite'],'false')
        for step in steps:
            if 'uses' in step:self.assertRegex(step['uses'],r'@[0-9a-f]{40}$')

if __name__=='__main__':unittest.main()
