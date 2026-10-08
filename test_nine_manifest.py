"""Nine-request scope and native nominees; invented bytes, never publisher claims."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import sidecar_contract as c
import sidecar_metadata as m
import sidecar_transport as t
from test_sidecar_metadata import body

ROOT = Path(__file__).parent

class NineManifestTests(unittest.TestCase):
    def setUp(self):
        self.p = c.load_proposal(ROOT/'sidecar-request-PROPOSED.json')

    def test_exact_raw_identity_and_nine_literal_gets(self):
        raw = (ROOT/'sidecar-request-PROPOSED.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), '3d24522de536bb1d64617b9efc5a7ddac1a414b199a65a59ad37c5146ed69283')
        self.assertEqual(tuple(r['url'] for r in self.p['requests']), t.URLS)
        self.assertEqual(len(set(t.URLS)), 9)
        self.assertTrue(all(r['method']=='GET' for r in self.p['requests']))
        self.assertEqual(json.loads(raw)['transport'], self.p['bounded_transport'])

    def test_no_transport_expansion_or_authorization(self):
        b=self.p['bounded_transport']
        self.assertEqual((b['max_attempts'],b['aggregate_deadline_seconds'],b['aggregate_response_byte_cap']), (9,180,2359296))
        for key in ['retries','redirects','head_requests','additional_indexes']:
            self.assertEqual(b[key],0)
        for key in ['automatic_recursion','binary_fallback','sidecar_url_rewriting']:
            self.assertIs(b[key],False)
        self.assertIs(self.p['production_execution_authorized'],False)
        self.assertIs(self.p['loading_authorized'],False)

    def test_any_request_or_bound_mutation_rejected(self):
        for index in range(9):
            for key,value in [('url','https://files.pythonhosted.org/other.metadata'),('method','HEAD'),('expected_response_sha256','0'*64),('max_response_bytes',262145)]:
                with self.subTest(index=index,key=key):
                    p=copy.deepcopy(self.p);p['requests'][index][key]=value
                    with self.assertRaisesRegex(ValueError,'proposal_content_changed'):c.validate_proposal(p)
        for key in ['requests','transport','bounded_transport']:
            p=copy.deepcopy(self.p);del p[key]
            with self.assertRaises(ValueError):c.validate_proposal(p)

    def test_native_nominee_exact_bindings(self):
        for req,name,version,digest in zip(self.p['requests'][7:],['numpy','pillow'],['2.5.3','12.3.0'],['451a9b8028000588e66b0b415587b6aef0bbc51a96d8e8a0cba0dc23acf64f99','8fc07146cab33ef7582361dab6eac596d340b03ec648f18217da7894f73838c8']):
            self.assertEqual((req['project'],req['version'],req['expected_response_sha256']),(name,version,digest))
            self.assertIn('cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl.metadata',req['url'])
            self.assertIs(req['install_selection_approved'],False)

    def parse_fixture(self,req,**kwargs):
        req=copy.deepcopy(req)
        raw=body(name=kwargs.pop('name',req['project']),version=kwargs.pop('version',req['version']),python=kwargs.pop('python',req['frozen_source']['requires_python']),**kwargs)
        req['expected_response_sha256']=hashlib.sha256(raw).hexdigest()
        return m.parse_metadata(raw,req,self.p['target'],c.known_nodes(self.p),c.ROOT_CONSTRAINTS)

    def test_numpy_and_pillow_synthetic_metadata(self):
        for req in self.p['requests'][7:]:
            result=self.parse_fixture(req)
            self.assertEqual(result['name'],req['project'])
            self.assertTrue(result['digest_verified_before_parse'])

    def test_native_digest_failure_precedes_parser(self):
        for req in self.p['requests'][7:]:
            with patch.object(m,'_headers',side_effect=AssertionError('parser called')):
                with self.assertRaisesRegex(m.MetadataError,'metadata_digest_mismatch'):
                    m.parse_metadata(b'not publisher bytes',req,self.p['target'],{},c.ROOT_CONSTRAINTS)

    def test_native_identity_and_python_drift_rejected(self):
        for req in self.p['requests'][7:]:
            for values in [{'name':'substitute'},{'version':'0.0.1'},{'python':'>=3.13'}]:
                with self.subTest(project=req['project'],values=values):
                    with self.assertRaises(m.MetadataError):self.parse_fixture(req,**values)

    def test_native_edges_retained_without_recursive_approval(self):
        for req in self.p['requests'][7:]:
            result=self.parse_fixture(req,dependencies=['invented-child>=1; python_version >= "3.12"','inactive-child; python_version < "3.12"','unknown-child; platform_release == "unknown"'])
            self.assertEqual([e['activity'] for e in result['edges']],['active','inactive','unresolved'])
            summary=m.check_collection_constraints([result],c.ROOT_CONSTRAINTS,c.known_nodes(self.p),self.p['target'])
            self.assertFalse(summary['dependency_closure_complete'])
            self.assertFalse(summary['automatic_recursion'])

    def test_tenth_result_rejected(self):
        with self.assertRaisesRegex(m.MetadataError,'collection_results_invalid'):
            m.check_collection_constraints([{}]*10,{}, {},self.p['target'])

    def test_numpy_and_pillow_failure_retains_prefix_without_fallback(self):
        from test_sidecar_collector import CollectorTests,Response
        for index in (7,8):
            with self.subTest(index=index):
                fixture=CollectorTests()
                fixture.setUp()
                try:
                    fixture.responses[index]=Response(fixture.proposal['requests'][index],b'invented mismatch')
                    report=fixture.run_collect()
                    self.assertEqual(report['status'],'failed')
                    self.assertEqual(report['requests_validated'],index)
                    self.assertEqual(len(fixture.transport.calls),index+1)
                    self.assertEqual(report['failures'][0]['code'],'digest_mismatch')
                    self.assertEqual((fixture.evidence.path/f'{index:02d}.body').read_bytes(),b'invented mismatch')
                    self.assertFalse((fixture.evidence.path/f'{index:02d}-metadata.json').exists())
                finally:
                    fixture.doCleanups()
