import json,unittest
from pathlib import Path
ROOT=Path(__file__).parent
class WorkflowTests(unittest.TestCase):
 def test_synthetic_isolation_and_inactive_collection(self):
  text=(ROOT/'.github/workflows/two-index-discovery.yml').read_text()
  for literal in ('unshare --net','setpriv --no-new-privs','env -i','--kill-after=5s 120s','persist-credentials: false','if: ${{ always() }}','overwrite: false'):
   self.assertIn(literal,text)
  for forbidden in ('pip install','collector.py --','external_review.py --','curl ','wget '):self.assertNotIn(forbidden,text)
  self.assertFalse(json.loads((ROOT/'external-review-TEMPLATE.json').read_bytes())['owner_accepted'])
 def test_embedded_python_compiles(self):
  lines=(ROOT/'.github/workflows/two-index-discovery.yml').read_text().splitlines();blocks=[];block=None
  for line in lines:
   if "<<'PY'" in line:block=[]
   elif block is not None:
    if line.strip()=='PY':blocks.append('\n'.join(x[10:] for x in block));block=None
    else:block.append(line)
  self.assertEqual(len(blocks),2)
  for source in blocks:compile(source,'workflow-embedded','exec')
 def test_collection_contract_unchanged(self):
  p=json.loads((ROOT/'NEXT-METADATA-PROPOSAL.json').read_bytes());m=json.loads((ROOT/'request-manifest.json').read_bytes())
  self.assertEqual([x['url'] for x in p['requests']],[x['url'] for x in m['requests']]);self.assertEqual(m['bounds']['requests'],2);self.assertEqual(m['bounds']['request_wall_seconds'],20);self.assertEqual(m['bounds']['aggregate_wall_seconds'],45);self.assertEqual(m['release_upload_cutoff_utc'],p['upload_cutoff_utc']);self.assertFalse(p['execution_authorized'])
