import importlib.util
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative_path):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load('candidate_collector', 'scripts/collect_native_inventory.py')
binding = load('candidate_sitecustomize_binding', 'scripts/sitecustomize_binding.py')


class RuntimeCandidateEnumerationTests(unittest.TestCase):
    def test_workflow_pins_exact_revised_collector_bytes(self):
        path = ROOT / 'scripts' / 'collect_native_inventory.py'
        workflow = (ROOT / '.github' / 'workflows' / 'pre-provision-inventory.yml').read_text()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertIn('COLLECTOR_SHA256: ' + digest, workflow)

    def test_out_of_root_link_does_not_abort_allowlisted_inventory(self):
        link = '/synthetic/stdlib/sitecustomize.py'
        safe = '/synthetic/stdlib/regular.py'
        target = '/etc/python3.12/sitecustomize.py'
        resolved = {link: target, safe: '/usr/lib/python3.12/regular.py',
                    '/usr/bin/python3': '/usr/bin/python3'}
        reader = collector.Reader()
        with patch.object(collector.sysconfig, 'get_path', return_value='/synthetic/stdlib'), \
             patch.object(collector.os, 'walk', return_value=[('/synthetic/stdlib', [],
                   ['regular.py', 'sitecustomize.py'])]), \
             patch.object(collector.os.path, 'realpath', side_effect=lambda p: resolved.get(p, p)), \
             patch.object(collector.os.path, 'islink', return_value=False), \
             patch.object(reader, 'text', return_value=''), \
             patch.object(collector.sys, 'path', []), \
             patch.object(collector.sys, 'executable', '/usr/bin/python3'):
            approved = reader.runtime_paths()

        self.assertEqual(approved, ['/usr/bin/python3', '/usr/lib/python3.12/regular.py'])
        self.assertEqual(len(reader.runtime_rejections), 1)
        rejection = reader.runtime_rejections[0]
        self.assertEqual(rejection['resolved_candidate_path'], target)
        self.assertEqual(rejection['candidate_sources'], [
            {'origin': 'stdlib_walk', 'path': link}])
        self.assertFalse(rejection['candidate_hashed'])
        self.assertIn('/usr/lib/', rejection['approved_roots'])
        self.assertNotIn('/etc/', rejection['approved_roots'])

    def test_every_rejection_is_recorded_and_never_hashed(self):
        safe = '/usr/lib/python3.12/regular.py'
        rejected = [
            {'resolved_candidate_path': '/etc/python3.12/sitecustomize.py',
             'candidate_sources': [{'origin': 'stdlib_walk',
                                   'path': '/usr/lib/python3.12/sitecustomize.py'}],
             'approved_roots': ['/usr/lib/'], 'candidate_hashed': False,
             'validation_stage': 'runtime_paths_before_artifact_hashing'},
            {'resolved_candidate_path': '/opt/unexpected.py',
             'candidate_sources': [{'origin': 'proc_self_maps', 'path': '/opt/unexpected.py'}],
             'approved_roots': ['/usr/lib/'], 'candidate_hashed': False,
             'validation_stage': 'runtime_paths_before_artifact_hashing'}]

        class FakeReader:
            runtime_rejections = rejected

            def runtime_paths(self):
                return [safe]

            def artifact(self, path):
                self.hashed_paths.append(path)
                return {'sha256': 'a' * 64}

            hashed_paths = []

        reader = FakeReader()
        report = {'runtime_candidates': {}, 'errors': []}
        collector.capture_runtime_candidates(reader, report)

        self.assertEqual(reader.hashed_paths, [safe])
        self.assertEqual(report['runtime_candidates'], {safe: {'sha256': 'a' * 64}})
        self.assertEqual(len(report['errors']), 2)
        self.assertEqual([e['context'] for e in report['errors']], rejected)
        self.assertTrue(all(e['context']['candidate_hashed'] is False
                            for e in report['errors']))

    def test_exact_pair_gate_survives_additional_unapproved_candidates(self):
        exact = {'item': 'runtime enumeration', 'error': 'not hashed', 'context': {
            'resolved_candidate_path': '/etc/python3.12/sitecustomize.py',
            'candidate_sources': [{'origin': 'stdlib_walk',
                                  'path': '/usr/lib/python3.12/sitecustomize.py'}],
            'candidate_hashed': False,
            'validation_stage': 'runtime_paths_before_artifact_hashing'}}
        unrelated = {'item': 'runtime enumeration', 'error': 'not hashed', 'context': {
            'resolved_candidate_path': '/opt/unexpected.py',
            'candidate_sources': [{'origin': 'proc_self_maps', 'path': '/opt/unexpected.py'}],
            'candidate_hashed': False,
            'validation_stage': 'runtime_paths_before_artifact_hashing'}}
        self.assertTrue(binding.exact_pair({'errors': [unrelated, exact]}))
        self.assertFalse(binding.exact_pair({'errors': [unrelated]}))

    def test_absent_preprovision_setup_paths_remain_evidence_gaps(self):
        paths = ('/var/lib/pv2-acceptance', '/opt/pv2-native-acceptance',
                 '/run/pv2-authorization')

        class FakeReader:
            runtime_rejections = []

            def path(self, path):
                raise FileNotFoundError(path)

            def text(self, path):
                raise FileNotFoundError(path)

            def command(self, argv):
                return {'argv': argv, 'exit_code': 0, 'text': ''}

            def artifact(self, path):
                return {'resolved_path': path, 'sha256': 'b' * 64}

            def runtime_paths(self):
                return []

        with patch.object(collector, 'FILES', ()), \
             patch.object(collector, 'PATHS', paths), \
             patch.object(collector, 'EXECUTABLES', ()):
            report = collector.collect(FakeReader(), {}, 'pre-provision')

        observed = {item['item'] for item in report['errors']}
        self.assertTrue(set(paths).issubset(observed))
        self.assertEqual(report['stage'], 'pre-provision')
        self.assertEqual(report['status'], 'observed_with_gaps')
        self.assertFalse(any(e['item'] == 'runtime enumeration' for e in report['errors']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
