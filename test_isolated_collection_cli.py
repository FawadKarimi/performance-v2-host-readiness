"""Real -I -B child entry checks; child and parent deny socket/DNS operations."""
import hashlib,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent
APPROVED=None
RESULTS=[]
def parent_guard(event,args):
 if event.startswith('socket.') or event in ('os.system','os.exec','os.posix_spawn','os.spawn'):raise RuntimeError('offline parent denied')
 if event=='subprocess.Popen':
  if APPROVED is None:raise RuntimeError('unapproved child denied')
  expected=subprocess.list2cmdline(APPROVED) if isinstance(args[1],str) else APPROVED
  if args[0]!=APPROVED[0] or args[1]!=expected:raise RuntimeError('unapproved child denied')
sys.addaudithook(parent_guard)
CHILD_GUARD='''
import sys as _guard_sys, os as _guard_os, json as _guard_json
from pathlib import Path as _GuardPath
def _offline_guard(event,args):
    if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn','os.spawn'):
        raise RuntimeError('offline child denied')
_guard_sys.addaudithook(_offline_guard)
_checks=[]
for _event in ('socket.__new__','socket.getaddrinfo','subprocess.Popen'):
    try: _guard_sys.audit(_event)
    except RuntimeError: _checks.append(_event)
    else: raise AssertionError('guard not enforced')
with _GuardPath(_guard_os.environ['GUARD_RECORD_PATH']).open('x') as _f:
    _guard_json.dump({'pid':_guard_os.getpid(),'isolated':_guard_sys.flags.isolated,'dont_write_bytecode':_guard_sys.dont_write_bytecode,'denied_events':_checks},_f)
'''
class IsolatedEntryTests(unittest.TestCase):
 def execute(self,mode,old=False):
  global APPROVED
  with tempfile.TemporaryDirectory(prefix='two-index-cli-') as td:
   temp=Path(td);source=temp/'source';shutil.copytree(ROOT,source,ignore=shutil.ignore_patterns('__pycache__','*.pyc'));cwd=temp/'unrelated';cwd.mkdir();(cwd/'collector.py').write_text("raise AssertionError('unrelated cwd imported')")
   if old:shutil.copyfile(ROOT.parent/'baseline/two_index_collection.py',source/'two_index_collection.py')
   p=source/'collector.py';text=p.read_text();needle='from __future__ import annotations\n';assert needle in text;p.write_text(text.replace(needle,needle+CHILD_GUARD,1),encoding='utf-8',newline='\n')
   # Only this disposable fixture is instrumented; reviewed production files stay unchanged.
   lock=json.loads((source/'two-index-collection-lock.json').read_bytes())
   for n in lock['files']:lock['files'][n]=hashlib.sha256((source/n).read_bytes()).hexdigest()
   lp=source/'two-index-collection-lock.json';lp.write_text(json.dumps(lock,sort_keys=True)+'\n');digest=hashlib.sha256(lp.read_bytes()).hexdigest()
   guard=temp/'guard.json';launch=temp/'two-index-collection-launch-7-1';launch.mkdir()
   env={k:os.environ[k] for k in ('SystemRoot','WINDIR') if k in os.environ};env.update(GUARD_RECORD_PATH=str(guard),RUNNER_TEMP=str(temp),GITHUB_RUN_ID='7',GITHUB_RUN_ATTEMPT='1',REVIEWED_COLLECTION_LOCK_SHA256=digest,OWNER_CONFIRMATION='false',BILLING_CONFIRMATION='false',TEMP=str(temp),TMP=str(temp))
   cmd=[sys.executable,'-I','-B',str(source/'two_index_collection.py'),mode];APPROVED=cmd
   try:r=subprocess.run(cmd,executable=sys.executable,cwd=cwd,env=env,capture_output=True,text=True,timeout=10,check=False)
   finally:APPROVED=None
   item={'mode':mode,'historical_wrapper':old,'argv':cmd,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'guard':json.loads(guard.read_bytes()) if guard.exists() else None}
   if old:
    self.assertNotEqual(r.returncode,0);self.assertIn("ModuleNotFoundError: No module named 'collector'",r.stderr);self.assertIsNone(item['guard'])
   else:
    self.assertEqual(r.returncode,2);self.assertNotIn('ModuleNotFoundError',r.stderr);self.assertEqual(item['guard']['isolated'],1);self.assertTrue(item['guard']['dont_write_bytecode']);self.assertNotEqual(item['guard']['pid'],os.getpid());self.assertEqual(len(item['guard']['denied_events']),3)
    if mode=='admit':self.assertEqual(json.loads(r.stderr)['status'],'admission_failed');self.assertFalse((temp/'external-review-7-1').exists())
    else:
     final=json.loads((launch/'collection-evidence-ledger.json').read_bytes());self.assertEqual(final['status'],'failed');self.assertIn('required_completion_failed',final['errors']);self.assertIsNotNone(final['source_after']);item['finalization']=final
   RESULTS.append(item)
 def test_admission_exact_isolated_cli(self):
  self.execute('admit',old=True);self.execute('admit')
 def test_finalization_exact_isolated_cli(self):
  self.execute('finalize',old=True);self.execute('finalize')
if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IsolatedEntryTests))
 report={'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'processes':RESULTS,'network_control':'Python audit denial in parent and instrumented disposable child sibling; no OS network namespace claimed','python':sys.version}
 (ROOT.parent/'subprocess-results.json').write_text(json.dumps(report,indent=2)+'\n');raise SystemExit(0 if result.wasSuccessful() else 1)
