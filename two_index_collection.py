"""Thin collection workflow integration; existing collector/admission own transport."""
import datetime as dt
import hashlib,json,os,re,stat,sys
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import collector as c
import external_review as e
LOCK='two-index-collection-lock.json'
NATIVE='f41c546729c9063004bb943e64378ec4a9adc5775d292846dc1e645158d100ab'
def verify_sources(root,expected):
 raw=(root/LOCK).read_bytes();c.require(c.sha(raw)==expected,'collection_lock_hash')
 lock=c.strict_json(raw);c.require(lock['collection_authorized'] is False,'collection_lock_scope')
 for name,digest in lock['files'].items():
  p=PurePosixPath(name);c.require(not p.is_absolute() and '..' not in p.parts and '\\' not in name and ':' not in name,'source_path')
  q=root/name;s=q.lstat();c.require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and not any(x.is_symlink() for x in (q,*q.parents)),'source_layout');c.require(c.sha(q.read_bytes())==digest,'source_drift')
 return {'lock_sha256':expected,'files':lock['files']}
def activation(raw,digest,lock,context,now):
 c.require(c.sha(raw)==digest,'activation_hash');record=e.decode(raw)
 c.require(all(record.get(k) is True for k in e.TRUE_FLAGS),'activation_inactive')
 c.require(record.get('collection_source_lock_sha256')==lock and record.get('compatibility_evidence_sha256')==NATIVE,'activation_evidence_binding')
 issued=e.utc(record['issued_utc']);expires=e.utc(record['expires_utc'])
 c.require(issued<=now<expires and dt.timedelta(0)<expires-issued<=dt.timedelta(minutes=15),'activation_window')
 c.require(record.get('commit')==context['commit'] and context['attempt']=='1','activation_run_binding')
 c.require(record.get('scope')=='2_pypi_discovery_gets_only' and record.get('github_identity_get_authorized') is True,'activation_scope')
 c.require(record.get('github_identity_url_template')==f'https://api.github.com/repos/{e.REPO}/actions/runs/{{run_id}}','identity_url')
 return record

def preflight(root,env):
 binding=verify_sources(root,env['REVIEWED_COLLECTION_LOCK_SHA256'])
 c.require(env.get('OWNER_CONFIRMATION')=='true' and env.get('BILLING_CONFIRMATION')=='true','dispatch_confirmation')
 context=e.admission.context_from_env(env)
 activation(env['EXTERNAL_RECORD_JSON'].encode(),env['EXTERNAL_RECORD_SHA256'],binding['lock_sha256'],context,dt.datetime.now(dt.timezone.utc))
 return binding

def validate_completion(data):
 """Validate retained bytes only; do not parse indexes again or follow links."""
 report=c.strict_json(data['worker/report.json']);c.require(report['status']=='metadata_collected_not_approved' and type(report['requests_attempted']) is int and report['requests_attempted']==2,'report_incomplete')
 c.require(report['dependency_closure_complete'] is False and report['execution_approved'] is False,'report_scope')
 parent=c.strict_json(data['parent-finished.json']);c.require(parent['exit_code']==0 and parent['termination_confirmed'] is True and parent['error'] is None,'parent_incomplete')
 total=0
 for i,project in enumerate(c.PROJECTS):
  prefix=f'worker/{i:02d}';body=data[prefix+'.body'];receipt=c.strict_json(data[prefix+'-receipt.json']);capture=c.strict_json(data[prefix+'-body-captured.json']);index=c.strict_json(data[prefix+'-index.json'])
  c.require(len(body)<=8388608 and receipt['url']==f'https://pypi.org/simple/{project}/' and receipt['project']==project and receipt['method']=='GET' and receipt['status']=='metadata_validated_not_approved','receipt_scope')
  c.require(receipt['response_sha256']==capture['response_sha256']==c.sha(body) and receipt['received_retained_bytes']==capture['bytes']==len(body),'body_binding')
  c.require(capture['url']==receipt['url'] and capture['hash_scope']=='complete captured body before parsing','capture_binding')
  c.require(index['project']==project and index['selected_versions'] is None and index['artifact_bytes_verified'] is False,'index_scope');total+=len(body)
 c.require(total<=16777216 and total==report['retained_body_bytes'],'aggregate_binding')
 return {'requests_validated':2,'retained_body_bytes':total,'collection_approved':False,'dependency_lock_complete':False}

def finalize(root,temp,run,attempt,expected):
 c.require(re.fullmatch('[1-9][0-9]*',run) and attempt=='1','run_syntax')
 launch=temp/f'two-index-collection-launch-{run}-{attempt}';admission=temp/f'external-review-{run}-{attempt}';output=temp/f'pypi-evidence-{run}-{attempt}'
 errors=[];entries={};data={};total=0;binding=None;completion=None
 # Every directory/file failure is independent; no original receipt is rewritten.
 for folder in (launch,admission,output):
  try:
   s=folder.lstat();c.require(stat.S_ISDIR(s.st_mode) and not folder.is_symlink(),'evidence_directory')
   paths=list(folder.rglob('*'));c.require(len(paths)<=100,'evidence_count')
  except BaseException:errors.append('evidence_directory_unavailable');continue
  for p in sorted(paths):
   if folder==launch and p.name in {'collection-evidence-ledger.json','finalization-stdout.log','finalization-stderr.log','finalization-exit.txt'}:continue
   try:
    s=p.lstat();c.require(not any(x.is_symlink() for x in (p,*p.parents)),'evidence_link')
    if stat.S_ISDIR(s.st_mode):continue
    c.require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=16777216,'evidence_file');total+=s.st_size;c.require(total<=134217728,'evidence_total')
    raw=p.read_bytes();key=p.relative_to(temp).as_posix();entries[key]={'sha256':c.sha(raw),'bytes':len(raw)}
    if folder==output:data[p.relative_to(output).as_posix()]=raw
   except BaseException:errors.append('evidence_file_unavailable')
 try:binding=verify_sources(root,expected)
 except BaseException:errors.append('post_source_verification_failed')
 try:
  c.require((launch/'admission-exit.txt').read_text().strip()=='0' and (launch/'collection-exit.txt').read_text().strip()=='0','execution_exit')
  before=c.strict_json((launch/'source-before.json').read_bytes());c.require(before==binding,'source_changed')
  for name in ('dispatch-reserved.json','parent-claimed.json','worker-claimed.json'):
   c.require(c.strict_json((admission/name).read_bytes())==c.strict_json((admission/'dispatch-reserved.json').read_bytes()),'claim_binding')
  completion=validate_completion(data)
 except BaseException:errors.append('required_completion_failed')
 record={'status':'complete_metadata_evidence_not_approval' if not errors else 'failed','errors':errors,'files':entries,'completion':completion,'source_after':binding,'collection_authorized':False,'production_authorized':False,'excludes_itself':True,'late_finalization_logs_not_hashed':['finalization-stdout.log','finalization-stderr.log','finalization-exit.txt']}
 e.write_new(launch/'collection-evidence-ledger.json',record)
 return 0 if not errors else 2

def main():
 try:
  mode=sys.argv[1]
  if mode=='preflight':print(json.dumps(preflight(ROOT,os.environ)));return 0
  if mode=='admit':preflight(ROOT,os.environ);return e.main()
  if mode=='finalize':return finalize(ROOT,Path(os.environ['RUNNER_TEMP']),os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'],os.environ['REVIEWED_COLLECTION_LOCK_SHA256'])
  raise ValueError('mode')
 except BaseException as exc:
  print(json.dumps(e.admission_failure(exc,'input_validation')),file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
