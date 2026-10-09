"""Four alternatives: synthetic bytes only, production manifest never altered."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sidecar_contract as contract
import sidecar_collector as sc
import sidecar_supervisor as parent
from sidecar_metadata import parse_metadata
from test_sidecar_collector import Response, Transport

class FourTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.original=contract.load_proposal(Path(__file__).parent/'sidecar-request-PROPOSED.json')
        self.p=copy.deepcopy(self.original);self.bodies=[]
        for r in self.p['requests']:
            text=f'Metadata-Version: 2.4\nName: {r["project"]}\nVersion: {r["version"]}\n'
            if r['frozen_source']['requires_python'] is not None:
                text+=f'Requires-Python: {r["frozen_source"]["requires_python"]}\n'
            raw=(text+'\n').encode();self.bodies.append(raw)
            r['expected_response_sha256']=hashlib.sha256(raw).hexdigest()
        self.responses=[Response(r,b) for r,b in zip(self.p['requests'],self.bodies)]
        self.transport=Transport(self.responses);self.evidence=sc.SidecarEvidence(self.root/'evidence')
    def replace(self,index,raw,rehash=True):
        self.bodies[index]=raw;self.responses[index]=Response(self.p['requests'][index],raw)
        if rehash:self.p['requests'][index]['expected_response_sha256']=hashlib.sha256(raw).hexdigest()
    def run_capture(self):
        with patch.object(sc,'validate_proposal'),patch.object(contract,'validate_proposal'),patch.object(sc,'authorize_network'):
            return sc.collect(self.p,self.transport,self.evidence,clock=lambda:0,grant=None)
    def read(self,name):return json.loads((self.evidence.path/name).read_text())
    def validate(self):
        with patch.object(contract,'validate_proposal'):
            return parent.validate_worker_outputs(self.p,self.evidence.path)
    def rewrite(self,name,obj):
        (self.evidence.path/name).write_text(json.dumps(obj))
    def test_four_capture_two_blocked_continue(self):
        r=self.run_capture();self.assertEqual(r['status'],'metadata_capture_complete_not_eligible')
        self.assertEqual((r['requests_attempted'],r['requests_captured'],r['requests_validated'],r['eligibility_blocked']),(4,4,2,2))
        self.assertEqual(len(self.transport.calls),4)
        self.assertTrue(all(r[k] is False for k in sc.FALSE_RESULT_FLAGS))
        for i in (2,3):
            m=self.read(f'{i:02d}-metadata.json');self.assertIsNone(m['requires_python']);self.assertEqual(m['eligibility'],'blocked')
            self.assertEqual(m['eligibility_reason'],'requires_python_missing_in_index_and_sidecar')
            self.assertTrue(self.read(f'{i:02d}-receipt.json')['digest_verified_before_parse'])
        self.validate()
    def test_sidecar_python_present_still_index_blocked(self):
        self.replace(2,self.bodies[2].replace(b'\n\n',b'\nRequires-Python: >=3.8\n\n'))
        self.assertEqual(self.run_capture()['requests_captured'],4)
        self.assertEqual(self.read('02-metadata.json')['eligibility_reason'],'requires_python_missing_in_index');self.validate()
    def test_strict_parser_missing_python_rejected(self):
        with self.assertRaises(ValueError):parse_metadata(self.bodies[2],self.p['requests'][2],self.p['target'],{},contract.ROOT_CONSTRAINTS)
    def test_investigative_scope_does_not_expand(self):
        with self.assertRaisesRegex(ValueError,'investigation_scope_rejected'):
            parse_metadata(self.bodies[0],self.p['requests'][0],self.p['target'],{},contract.ROOT_CONSTRAINTS,investigate_missing_python=True)
    def test_incompatible_python_not_expected_gap(self):
        self.replace(2,self.bodies[2].replace(b'\n\n',b'\nRequires-Python: <3\n\n'))
        self.assertEqual(self.run_capture()['requests_attempted'],3);self.assertFalse((self.evidence.path/'03.body').exists())
    def test_hash_mismatch_retains_and_stops_before_parse(self):
        self.replace(2,b'wrong body',False);r=self.run_capture()
        self.assertEqual(r['requests_attempted'],3);self.assertEqual((self.evidence.path/'02.body').read_bytes(),b'wrong body')
        self.assertFalse((self.evidence.path/'02-metadata.json').exists());self.assertFalse((self.evidence.path/'03.body').exists())
    def test_wrong_name_is_not_expected_gap(self):
        self.replace(2,self.bodies[2].replace(b'Name: mpmath',b'Name: wrong'))
        self.assertEqual(self.run_capture()['requests_captured'],2)
    def test_invalid_requirement_is_not_expected_gap(self):
        self.replace(2,self.bodies[2].replace(b'\n\n',b'\nRequires-Dist: child=>1\n\n'))
        self.assertEqual(self.run_capture()['requests_captured'],2)
    def test_dependency_edges_retained_while_blocked(self):
        self.replace(2,self.bodies[2].replace(b'\n\n',b'\nRequires-Dist: child>=1\nRequires-Dist: optional; extra == "test"\n\n'))
        self.assertEqual(self.run_capture()['requests_captured'],4)
        m=self.read('02-metadata.json');self.assertIn('child',json.dumps(m));self.assertIn('optional',json.dumps(m));self.validate()
    def test_alternatives_are_not_joint_installation(self):
        self.run_capture();c=self.read('03-constraints.json')
        self.assertIs(c['joint_installation_assumed'],False);self.assertEqual(len(c['candidates']),4)
        self.assertIs(c['dependency_closure_complete'],False)
        self.assertNotIn('mpmath',contract.known_nodes(self.original))
    def test_transport_failure_retains_partial(self):
        self.responses[2]=TimeoutError();r=self.run_capture();self.assertEqual(r['requests_attempted'],3)
        self.assertEqual(r['requests_captured'],2);self.assertTrue((self.evidence.path/'report.json').exists())
    def test_write_failure_retains_report(self):
        original=self.evidence.write
        def fail(name,obj):
            if name=='02-metadata.json':raise OSError('synthetic')
            return original(name,obj)
        with patch.object(self.evidence,'write',side_effect=fail):r=self.run_capture()
        self.assertEqual(r['requests_captured'],2);self.assertTrue((self.evidence.path/'02.body').exists());self.assertTrue((self.evidence.path/'report.json').exists())
    def test_missing_final_rejected(self):
        self.run_capture();(self.evidence.path/'03-constraints.json').unlink()
        with self.assertRaises((ValueError,OSError)):self.validate()
    def test_wrong_intermediate_rejected(self):
        self.run_capture();self.rewrite('01-constraints.json',self.read('00-constraints.json'))
        with self.assertRaises(ValueError):self.validate()
    def test_tampered_body_rejected(self):
        self.run_capture();(self.evidence.path/'02.body').write_bytes(b'tampered')
        with self.assertRaises(ValueError):self.validate()
    def test_forged_eligibility_rejected(self):
        self.run_capture();m=self.read('02-metadata.json');m['eligibility']='approved';self.rewrite('02-metadata.json',m)
        with self.assertRaises(ValueError):self.validate()
    def test_inconsistent_count_rejected(self):
        self.run_capture();r=self.read('report.json');r['eligibility_blocked']=0;self.rewrite('report.json',r)
        with self.assertRaises(ValueError):self.validate()
    def test_exact_manifest_and_inactive(self):
        self.assertEqual(len(self.original['requests']),4);self.assertIs(self.original['authorization']['execution_authorized'],False)
        self.assertEqual([r['version'] for r in self.original['requests']],['3.0.3','3.0.4','1.2.1','1.3.0'])
        import sidecar_bootstrap as bootstrap
        import shutil
        source=Path(__file__).parent
        digest=hashlib.sha256((source/'collection-source-lock.json').read_bytes()).hexdigest()
        bootstrap.verify_lock(source,digest)
        self.assertEqual(json.loads((source/'source-lock.json').read_bytes())['schema'],'two_index_review_source_lock_v1')
        isolated=self.root/'source';isolated.mkdir()
        for filename in [*json.loads((source/'collection-source-lock.json').read_bytes())['files'], 'collection-source-lock.json']:
            destination=isolated/filename;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source/filename,destination)
        legacy=isolated/'reference/sidecar-compatibility-source-lock.json'
        legacy.write_bytes((isolated/'source-lock.json').read_bytes())
        with self.assertRaises(ValueError):bootstrap.verify_lock(isolated,digest)

        changed=copy.deepcopy(self.original);changed['requests'][0]['url']+='?x=1'
        with self.assertRaises(ValueError):contract.validate_proposal(changed)
    def test_completed_capture_is_not_package_approval(self):
        self.run_capture();r=self.read('report.json');r['installation_selection_approved']=True;self.rewrite('report.json',r)
        with self.assertRaises(ValueError):self.validate()

    def test_inactive_admission_rejects_before_transport(self):
        import sidecar_admission as admission
        with self.assertRaises(ValueError):admission.authorize_network(self.original,None)
        self.assertEqual(self.transport.calls,[])

    def test_exact_mime_does_not_bypass_hash(self):
        self.replace(0,b'wrong',False)
        self.responses[0].headers=[('Content-Type','binary/octet-stream'),('Content-Length','5')]
        self.assertEqual(self.run_capture()['requests_captured'],0)
        self.assertFalse((self.evidence.path/'00-metadata.json').exists())
    def test_missing_markupsafe_python_remains_fatal(self):
        self.replace(0,self.bodies[0].replace(b'Requires-Python: >=3.9\n',b''))
        self.assertEqual(self.run_capture()['requests_captured'],0)
    def test_empty_mpmath_python_remains_fatal(self):
        self.replace(2,self.bodies[2].replace(b'\n\n',b'\nRequires-Python: \n\n'))
        self.assertEqual(self.run_capture()['requests_captured'],2)
    def test_duplicate_mpmath_python_remains_fatal(self):
        self.replace(2,self.bodies[2].replace(b'\n\n',b'\nRequires-Python: >=3\nRequires-Python: >=3\n\n'))
        self.assertEqual(self.run_capture()['requests_captured'],2)
    def test_dynamic_final_name_preserved(self):
        self.assertEqual(parent.final_constraints_filename(4),'03-constraints.json')
        self.assertEqual(parent.final_constraints_filename(7),'06-constraints.json')
        self.assertEqual(parent.final_constraints_filename(9),'08-constraints.json')
    def test_boolean_approval_cannot_be_integer_zero(self):
        self.run_capture();m=self.read('02-metadata.json');m['install_selection_approved']=0;self.rewrite('02-metadata.json',m)
        with self.assertRaises(ValueError):self.validate()
