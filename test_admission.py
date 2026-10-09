"""Invented grants and OS context only; no real receipt is approved."""
import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import stat
import admission as a
import collector as c
import test_collector as fixtures

setUpModule=fixtures.setUpModule
tearDownModule=fixtures.tearDownModule

class Tests(unittest.TestCase):
    def setUp(self):
        self.now=dt.datetime(2026,10,5,tzinfo=dt.timezone.utc)
        self.ctx=dict(repository='invented/private',commit='a'*40,run_id='123',attempt='1',runner='fake',boot_id='fake-boot',workflow_ref='fake-ref',event='workflow_dispatch',os='Linux',arch='X64')
        self.sources={'collector.py':'b'*64,'admission.py':'c'*64}
        self.r=dict(schema='pv2_public_metadata_admission_v1',scope='2_pypi_discovery_gets_only',owner_authorized=True,independent_workflow_reviewed=True,zero_paid_usage_confirmed=True,same_uid_residual_risk_accepted=True,security_approved=False,pilot_execution_authorized=False,research_execution_authorized=False,artifact_acquisition_authorized=False,manifest_sha256=c.MANIFEST_SHA256,source_hashes=self.sources,context=self.ctx,issued_utc='2026-10-04T23:59:00Z',expires_utc='2026-10-05T00:30:00Z')
    def grant(self): return a.authorize(c.MANIFEST_SHA256,self.r,self.ctx,self.sources,self.now)
    def test_false_template_rejected(self):
        r=json.loads((Path(__file__).parent/'authorization-TEMPLATE.json').read_text())
        with self.assertRaisesRegex(ValueError,'approval missing'): a.authorize(c.MANIFEST_SHA256,r,self.ctx,self.sources,self.now)
    def test_each_missing_acceptance_rejected(self):
        for flag in ['owner_authorized','independent_workflow_reviewed','zero_paid_usage_confirmed','same_uid_residual_risk_accepted']:
            with self.subTest(flag=flag):
                saved=self.r[flag];self.r[flag]=False
                with self.assertRaises(ValueError):self.grant()
                self.r[flag]=saved
    def test_run_substitution(self):
        self.r['context']=dict(self.ctx,attempt='2')
        with self.assertRaisesRegex(ValueError,'identity mismatch'):self.grant()
    def test_source_mismatch(self):
        self.r['source_hashes']={}
        with self.assertRaisesRegex(ValueError,'implementation'):self.grant()
    def test_expired(self):
        self.r['expires_utc']='2026-10-04T23:59:59Z'
        with self.assertRaisesRegex(ValueError,'expired'):self.grant()
    def test_scope_expansion(self):
        self.r['artifact_acquisition_authorized']=True
        with self.assertRaisesRegex(ValueError,'broader'):self.grant()
    def test_admitted_fake_collection_partial_evidence(self):
        grant=self.grant(); m=c.load_manifest(Path(__file__).parent/'request-manifest.json')
        c.authorize_network(m,grant)  # genuine authorization code, not patched
        m['requests']=m['requests'][:2] # bounded fake fixture, never passed to CLI
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'evidence'
            report=c.collect(m,fixtures.Fake([fixtures.Response(),TimeoutError('invented network failure')]),c.Evidence(out),grant=grant)
            self.assertEqual(report['status'],'failed')
            self.assertTrue((out/'00-index.json').exists())
            self.assertTrue((out/'01-receipt.json').exists())
            self.assertEqual(json.loads((out/'started.json').read_text())['scoped_metadata_admission']['receipt_sha256'],grant['receipt_sha256'])
    def test_admitted_fake_collection_success_not_security_approval(self):
        grant=self.grant();m=c.load_manifest(Path(__file__).parent/'request-manifest.json');c.authorize_network(m,grant)
        m['requests']=m['requests'][:1]
        with tempfile.TemporaryDirectory() as d:
            r=c.collect(m,fixtures.Fake([fixtures.Response()]),c.Evidence(Path(d)/'evidence'),grant=grant)
            self.assertEqual(r['status'],'metadata_collected_not_approved');self.assertFalse(r['security_approved'])
    def test_no_grant_rejected(self):
        m=c.load_manifest(Path(__file__).parent/'request-manifest.json')
        with self.assertRaises(ValueError):c.authorize_network(m)
    def test_output_admission_fake_owned_external_root(self):
        root=Path.cwd().anchor
        temp=Path(root)/'invented-runner'/'temp'; repo=Path(root)/'invented-runner'/'workspace'
        info=SimpleNamespace(st_uid=123,st_mode=stat.S_IFDIR|0o700)
        with patch.object(Path,'lstat',return_value=info), patch.object(Path,'stat',return_value=info), patch('admission.os.path.lexists',return_value=False):
            policy=a.output_policy(temp,repo,temp/'pypi-evidence-123-1',uid=123)
            self.assertEqual(policy['external_root'],str(temp))
            a.output_policy(temp,repo,temp/'pypi-evidence-123-1',uid=123,worker=True)
    def test_output_admission_rejects_unsafe_fake_ancestors(self):
        root=Path.cwd().anchor; temp=Path(root)/'invented-runner'/'temp';repo=Path(root)/'invented-runner'/'workspace'
        for mode in (stat.S_IFDIR|0o777,stat.S_IFLNK|0o700):
            with self.subTest(mode=mode),patch.object(Path,'lstat',return_value=SimpleNamespace(st_uid=123,st_mode=mode)):
                with self.assertRaises(ValueError):a.output_policy(temp,repo,temp/'pypi-evidence-123-1',uid=123)
    def test_candidate_workflow_static_gate_and_python(self):
        text=(Path(__file__).parent/'.github/workflows/two-index-discovery.yml').read_text()
        self.assertIn('  workflow_dispatch:',text)
        self.assertIn('    runs-on: ubuntu-24.04',text)
        self.assertIn('  synthetic:',text)
        self.assertNotIn('  collect:',text)
        policy=json.loads((Path(__file__).parent/'release-decision.json').read_text())
        self.assertIs(policy['independent_workflow_reviewed'],False)
        self.assertIs(policy['public_metadata_threat_model_accepted'],False)

if __name__=='__main__':unittest.main()
