"""Offline synthetic suite. Native mode includes real POSIX temporary-file checks."""
import contextlib,hashlib,json,os,platform,sys,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT),str(ROOT/'compatibility')]
MODULES=['test_collector','test_admission','test_admission_diagnostics','test_runtime_admission','test_external_review','test_home_acl_policy','test_two_index','test_two_index_delta','test_workflow_candidate']
EXPECTED=165
EXCLUDED_WINDOWS={'test_admission_diagnostics.ACLDiagnostics.test_nonascii_native_output_is_rejected_and_redacted','test_admission_diagnostics.ACLDiagnostics.test_observe_rejection_links_directory_without_raw_path_or_stderr','test_home_acl_policy.Tests.test_observe_records_exception_and_detects_replacement_before_return','test_home_acl_policy.Tests.test_inherited_named_default_or_nonprivate_created_acl_rejected','test_home_acl_policy.Tests.test_created_symlink_mode_hardlink_replacement_and_fd_mismatch_rejected','test_home_acl_policy.Tests.test_actual_created_directory_and_fd_checked_with_strict_acl','test_home_acl_policy.Tests.test_created_private_file_checked_before_body_write'}
def deny(event,args):
 if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn','os.spawn'):raise RuntimeError('offline network/subprocess denied')
sys.addaudithook(deny)
def flat(s):
 for t in s:
  if isinstance(t,unittest.TestSuite):yield from flat(t)
  else:yield t
with contextlib.ExitStack() as stack:
 stack.enter_context(patch('platform.uname',return_value=SimpleNamespace(system='Linux',node='synthetic',release='0',version='0',machine='x86_64',processor='')))
 if sys.platform=='win32':
  for name in ('getuid','geteuid','getgid','getegid'):stack.enter_context(patch.object(os,name,return_value=1001,create=True))
 suite=list(flat(unittest.defaultTestLoader.loadTestsFromNames(MODULES)))
 assert len(suite)==EXPECTED,(len(suite),EXPECTED)
 excluded=sorted(EXCLUDED_WINDOWS) if sys.platform=='win32' else []
 selected=[t for t in suite if t.id() not in excluded]
 result=unittest.TextTestRunner(stream=sys.stderr,verbosity=2).run(unittest.TestSuite(selected))
record=dict(tests=result.testsRun,expected_native_tests=EXPECTED,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),successful=result.wasSuccessful(),network_and_subprocess_audit_deny=True,execution_authorized=False,source_lock_sha256=hashlib.sha256((ROOT/'source-lock.json').read_bytes()).hexdigest(),excluded_platform_tests=excluded,python=sys.version,packaging=__import__('packaging').__version__)
print(json.dumps(record,indent=2));raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
