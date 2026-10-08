import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import sidecar_contract as contract
import sidecar_transport as transport

ROOT = Path(__file__).parent


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.proposal = contract.load_proposal(ROOT/'sidecar-request-PROPOSED.json')

    def test_original_bytes_and_canonical_content(self):
        raw = (ROOT/'sidecar-request-PROPOSED.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), contract.PROPOSAL_SHA256)
        self.assertEqual(contract.validate_proposal(self.proposal), self.proposal)

    def test_literals_match_frozen_order(self):
        self.assertEqual(tuple(x['url'] for x in self.proposal['requests']), transport.URLS)
        self.assertEqual(len(transport.URLS), 9)
        self.assertEqual(len(set(transport.URLS)), 9)
        self.assertTrue(all(x.endswith('.whl.metadata') for x in transport.URLS))

    def test_target_and_cutoff_preserved(self):
        self.assertEqual(self.proposal['target']['python_full_version'], '3.12.15')
        self.assertEqual(self.proposal['target']['extra'], '')
        self.assertEqual(self.proposal['release_upload_cutoff_utc'], '2026-10-04T17:37:33+00:00')
        self.assertEqual(self.proposal['target']['platform_release'], '')

    def test_any_authorization_change_invalidates_contract(self):
        changed = copy.deepcopy(self.proposal)
        changed['authorization']['execution_authorized'] = True
        with self.assertRaisesRegex(ValueError, 'proposal_content_changed'):
            contract.validate_proposal(changed)

    def test_nominees_not_approved(self):
        self.assertTrue(all(r['artifact_bytes_verified'] is False and
                            r['install_selection_approved'] is False
                            for r in self.proposal['requests']))
        nodes = contract.known_nodes(self.proposal)
        self.assertEqual(nodes['torch'], '2.13.0+cpu')
        self.assertEqual(nodes['torchvision'], '0.28.0+cpu')
        self.assertEqual(len(nodes), 11)

    def test_runtime_roots_keep_optional_scopes_out(self):
        self.assertNotIn('pytest', contract.ROOT_CONSTRAINTS)
        self.assertNotIn('pydicom', contract.ROOT_CONSTRAINTS)
        self.assertNotIn('transformers', contract.ROOT_CONSTRAINTS)
        self.assertEqual(contract.ROOT_CONSTRAINTS['numpy'], '>=1.24,<3')
        self.assertEqual(contract.ROOT_CONSTRAINTS['setuptools'], '>=77.0.3')


if __name__ == '__main__':
    unittest.main()
