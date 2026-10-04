import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'supplemental_host_evidence.py'
spec = importlib.util.spec_from_file_location('supplemental_host_evidence', SCRIPT)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class SupplementalEvidenceTests(unittest.TestCase):
    def test_workflow_pins_and_runs_supplemental_read_after_bound_observations(self):
        workflow = (SCRIPT.parents[1] / '.github' / 'workflows' / 'pre-provision-inventory.yml').read_text()
        digest = __import__('hashlib').sha256(SCRIPT.read_bytes()).hexdigest()
        self.assertIn('SUPPLEMENTAL_SHA256: ' + digest, workflow)
        self.assertLess(workflow.index("id: diagnostic"), workflow.index("id: supplemental"))
        self.assertLess(workflow.index("id: supplemental"), workflow.index("id: seal"))
        self.assertIn('--kill-after=2s 30s /usr/bin/python3 -I -S -B scripts/supplemental_host_evidence.py', workflow)
        self.assertIn("extra['script_sha256'] == os.environ['SUPPLEMENTAL_SHA256']", workflow)
        self.assertIn("extra['read_only'] is True", workflow)

    def test_parse_membership_requires_single_safe_v2_path(self):
        self.assertEqual(evidence.parse_membership('0::/system.slice/job.service\n'),
                         '/system.slice/job.service')
        for value in ('', '0::/a\n0::/b\n', '0::/../outside\n', '0::/a//b\n',
                      '0::/a/\n', '1:cpu:/legacy\n'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                evidence.parse_membership(value)

    def test_ancestry_maps_only_within_cgroup_mount_root(self):
        self.assertEqual(evidence.ancestry('/sys/fs/cgroup', '/', '/system.slice/job.service'),
                         ['/sys/fs/cgroup', '/sys/fs/cgroup/system.slice',
                          '/sys/fs/cgroup/system.slice/job.service'])
        self.assertEqual(evidence.ancestry('/sys/fs/cgroup/sub', '/sub', '/sub/a/b'),
                         ['/sys/fs/cgroup/sub', '/sys/fs/cgroup/sub/a', '/sys/fs/cgroup/sub/a/b'])
        for args in (('/sys/fs/cgroup', '/other', '/system.slice/job.service'),
                     ('/sys/fs/cgroup-escape', '/', '/a')):
            with self.subTest(args=args), self.assertRaises(ValueError):
                evidence.ancestry(*args)

    def test_limit_parsers_and_effective_parent_caps(self):
        self.assertAlmostEqual(evidence.parse_cpu_max('50000 100000'), .5)
        self.assertIsNone(evidence.parse_cpu_max('max 100000'))
        levels = [{'cpu.max': 'max 100000', 'memory.max': 'max', 'pids.max': '5000', 'cpuset.cpus.effective': '0-7'},
                  {'cpu.max': '200000 100000', 'memory.max': '8192', 'pids.max': '1000', 'cpuset.cpus.effective': '0-3'},
                  {'cpu.max': '50000 100000', 'memory.max': '4096', 'pids.max': 'max', 'cpuset.cpus.effective': '1-2'}]
        caps = evidence.effective_caps(levels)
        self.assertEqual(caps['minimum_finite_cpu_quota_cores'], .5)
        self.assertEqual(caps['current_effective_cpuset_cpu_count'], 2)
        self.assertEqual(caps['minimum_observed_ancestor_or_leaf_cpuset_count'], 2)
        self.assertEqual(caps['upper_bound_cpu_capacity_cores'], .5)
        self.assertEqual(caps['minimum_finite_memory_bytes'], 4096)
        self.assertEqual(caps['minimum_finite_pids'], 1000)
        self.assertIn('does not prove child-cgroup delegation', caps['interpretation'])
        for value in ('max 0', 'x 100', '0 100'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                evidence.parse_cpu_max(value)

    def test_installed_package_checksum_row_is_exact_and_unique(self):
        row = '0123456789abcdef0123456789abcdef  etc/python3.12/sitecustomize.py\n'
        self.assertEqual(evidence.package_md5_record(row, 'etc/python3.12/sitecustomize.py'),
                         '0123456789abcdef0123456789abcdef')
        for text in ('', row + row, '0123456789abcdef0123456789abcdef  ../etc/python3.12/sitecustomize.py\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                evidence.package_md5_record(text, 'etc/python3.12/sitecustomize.py')

    def test_cgroup_readback_lists_every_ancestor_and_reports_missing_levels(self):
        raw = {'mounts': [{'filesystem': 'cgroup2', 'mount': '/sys/fs/cgroup', 'root': '/'}],
               'files': {'/proc/self/cgroup': '0::/system.slice/job.service\n'}}
        values = {
            '/sys/fs/cgroup/cpu.max': 'max 100000', '/sys/fs/cgroup/memory.max': 'max',
            '/sys/fs/cgroup/memory.swap.max': 'max',
            '/sys/fs/cgroup/pids.max': '9000',
            '/sys/fs/cgroup/cpuset.cpus.effective': '0-7',
            '/sys/fs/cgroup/system.slice/cpu.max': '200000 100000',
            '/sys/fs/cgroup/system.slice/memory.max': '8192',
            '/sys/fs/cgroup/system.slice/memory.swap.max': 'max',
            '/sys/fs/cgroup/system.slice/pids.max': '4000',
            '/sys/fs/cgroup/system.slice/cpuset.cpus.effective': '0-3',
            '/sys/fs/cgroup/system.slice/job.service/cpu.max': '50000 100000',
            '/sys/fs/cgroup/system.slice/job.service/memory.max': '4096',
            '/sys/fs/cgroup/system.slice/job.service/memory.swap.max': '2048',
            '/sys/fs/cgroup/system.slice/job.service/pids.max': '1000',
            '/sys/fs/cgroup/system.slice/job.service/cpuset.cpus.effective': '1-2',
        }
        def fake_read(path, bound):
            if path == '/proc/self/cgroup':
                return b'0::/system.slice/job.service\n', SimpleNamespace()
            if path not in values:
                raise FileNotFoundError(path)
            return values[path].encode(), SimpleNamespace()
        with patch.object(evidence, 'read_bounded', side_effect=fake_read):
            report = evidence.cgroup_observation(raw)
        self.assertEqual([x['path'] for x in report['ancestors_root_to_current']],
                         ['/sys/fs/cgroup', '/sys/fs/cgroup/system.slice',
                          '/sys/fs/cgroup/system.slice/job.service'])
        self.assertTrue(report['critical_limit_chain_complete'])
        self.assertTrue(report['membership_matches_collector'])
        self.assertTrue(report['supplemental_membership_stable_during_observation'])
        self.assertFalse(report['child_cgroup_creation_tested'])
        self.assertEqual(report['effective_caps']['minimum_finite_memory_bytes'], 4096)
        self.assertEqual(report['effective_caps']['current_effective_cpuset_cpu_count'], 2)
        # If the leaf cpuset is unavailable, never report an ancestor count as current.
        del values['/sys/fs/cgroup/system.slice/job.service/cpuset.cpus.effective']
        with patch.object(evidence, 'read_bounded', side_effect=fake_read):
            report = evidence.cgroup_observation(raw)
        self.assertIsNone(report['effective_caps']['current_effective_cpuset_cpu_count'])
        self.assertFalse(report['critical_limit_chain_complete'])

        # A different helper cgroup is explicitly visible and cannot be called complete.
        def changed_membership(path, bound):
            if path == '/proc/self/cgroup':
                return b'0::/system.slice/job.service/child\n', SimpleNamespace()
            parent_path = path.replace('/system.slice/job.service/child/', '/system.slice/job.service/')
            if parent_path not in values:
                raise FileNotFoundError(parent_path)
            return values[parent_path].encode(), SimpleNamespace()
        with patch.object(evidence, 'read_bounded', side_effect=changed_membership):
            report = evidence.cgroup_observation(raw)
        self.assertFalse(report['membership_matches_collector'])

        # Membership is read again after the ancestry walk to detect a move mid-read.
        values['/sys/fs/cgroup/system.slice/job.service/cpuset.cpus.effective'] = '1-2'
        count = {'proc_reads': 0}
        def moving_membership(path, bound):
            if path == '/proc/self/cgroup':
                count['proc_reads'] += 1
                value = ('0::/system.slice/job.service\n' if count['proc_reads'] == 1
                         else '0::/system.slice/job.service/child\n')
                return value.encode(), SimpleNamespace()
            if path not in values:
                raise FileNotFoundError(path)
            return values[path].encode(), SimpleNamespace()
        count['proc_reads'] = 0
        with patch.object(evidence, 'read_bounded', side_effect=moving_membership):
            report = evidence.cgroup_observation(raw)
        self.assertFalse(report['supplemental_membership_stable_during_observation'])
        self.assertTrue(report['critical_limit_chain_complete'])
        del values['/sys/fs/cgroup/system.slice/memory.swap.max']
        with patch.object(evidence, 'read_bounded', side_effect=fake_read):
            report = evidence.cgroup_observation(raw)
        self.assertFalse(report['critical_limit_chain_complete'])
        values['/sys/fs/cgroup/system.slice/memory.swap.max'] = 'max'
        del values['/sys/fs/cgroup/system.slice/memory.max']
        with patch.object(evidence, 'read_bounded', side_effect=fake_read):
            report = evidence.cgroup_observation(raw)
        self.assertFalse(report['critical_limit_chain_complete'])

    def test_package_checksum_comparison_does_not_claim_publisher_authentication(self):
        checksum = '0123456789abcdef0123456789abcdef'
        content = b'synthetic target bytes'
        md5 = __import__('hashlib').md5(content, usedforsecurity=False).hexdigest()
        self.assertNotEqual(md5, checksum)
        raw = {'metadata': {'packages': {'text':
                'libpython3.12-minimal:amd64\t3.12.3-1\tamd64\tpython3.12\t3.12.3-1\tinstalled\n'}}}
        stat_record = SimpleNamespace(st_uid=0, st_mode=0o100644)
        manifest = b'0123456789abcdef0123456789abcdef  etc/python3.12/sitecustomize.py\n'
        target = {'target_md5': '0123456789abcdef0123456789abcdef', 'target_sha256': 'a' * 64,
                  'target_contents_disclosed': False, 'target_imported_or_executed': False}
        with patch.object(evidence, 'read_bounded', return_value=(manifest, stat_record)), \
             patch.object(evidence, 'hash_target', return_value=target.copy()):
            result = evidence.package_integrity(raw)
        self.assertTrue(result['local_package_record_match'])
        self.assertFalse(result['publisher_signature_verified'])
        self.assertEqual(result['package_version'], '3.12.3-1')

    def test_no_dependency_or_mutating_backend(self):
        source = SCRIPT.read_text()
        self.assertNotRegex(source, r'(?im)^\s*(?:import|from)\s+(?:subprocess|requests|urllib)\b')
        self.assertIn("'docker_invoked': False", source)
        self.assertIn("'child_cgroup_creation_tested': False", source)
        self.assertIn("'resource_controls_mutated': False", source)
        self.assertNotRegex(source, r'(?m)\b(?:mkdir|write_text|unlink|rmtree)\s*\(')


if __name__ == '__main__':
    unittest.main(verbosity=2)
