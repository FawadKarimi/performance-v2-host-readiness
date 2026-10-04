"""Local static checks; PyYAML is test-only, not a native compatibility dependency."""
from pathlib import Path
import unittest,yaml
ROOT=Path(__file__).parent
class Tests(unittest.TestCase):
    def test_external_route_is_manual_and_has_no_environment_gate(self):
        d=yaml.load((ROOT/'.github/workflows/public-metadata-candidate.yml').read_text(),Loader=yaml.BaseLoader)
        self.assertEqual(set(d['on']),{'workflow_dispatch'});self.assertNotIn('environment',d['jobs']['collect'])
        self.assertEqual(d['permissions'],{'contents':'read','actions':'read'})
        self.assertEqual(d['on']['workflow_dispatch']['inputs']['external_record_json']['default'],'{}')
        self.assertEqual(d['on']['workflow_dispatch']['inputs']['owner_authorizes_requests']['default'],'false')
    def test_native_workflow_is_network_isolated_and_noninstalling(self):
        text=(ROOT/'.github/workflows/metadata-linux-compatibility.yml').read_text()
        d=yaml.load(text,Loader=yaml.BaseLoader);job=d['jobs']['compatibility']
        self.assertEqual(set(d['on']),{'workflow_dispatch'});self.assertEqual(job['timeout-minutes'],'5')
        self.assertEqual(job['runs-on'],'ubuntu-24.04')
        self.assertIn('/usr/bin/unshare --net /usr/sbin/runuser',text)
        self.assertIn('/usr/bin/env -i ',text)
        self.assertIn('--kill-after=5s 120s',text)
        self.assertIn('immediate-exit-status.txt',text)
        self.assertEqual(job['steps'][-1]['if'],'${{ always() }}')
        for prohibited in ('pip install','apt-get','curl ','wget ','collector.py --manifest','--net=host'):
            self.assertNotIn(prohibited,text)
        self.assertEqual(d['on']['workflow_dispatch']['inputs']['authorize_synthetic_only']['default'],'false')
if __name__=='__main__':unittest.main()
