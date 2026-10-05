"""External owner-reviewed decision -> one dispatch -> parent/worker claims.

Single-use authority is GitHub's workflow-id/run-number pair plus attempt=1,
confirmed by one authenticated API GET. Local exclusive claims prevent duplicate
roles on the same host. No assertion that hashes authenticate a human reviewer.
"""
import datetime as dt,hashlib,http.client,json,os,re,ssl,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import admission,runtime_acceptance,output_security

REPO='FawadKarimi/performance-v2-host-readiness'
REPO_ID=1392457611
OWNER_ID=108207574
WORKFLOW='.github/workflows/public-metadata-candidate.yml'
CORE=('collector.py','admission.py','runtime_acceptance.py','worker_diagnostics.py')
BOUND=CORE+('external_review.py','output_security.py',WORKFLOW)
FALSE_FLAGS=('protected_environment_verified','training_authorized','research_execution_authorized','artifact_acquisition_authorized','pilot_execution_authorized','security_approved')
TRUE_FLAGS=('owner_accepted','independent_review_accepted','metadata_scope_security_disposition_accepted','same_uid_trust_accepted','output_mount_risk_accepted','native_compatibility_evidence_accepted')
sha=lambda b:hashlib.sha256(b).hexdigest()
def need(ok,code):
    if not ok:raise ValueError(code)
def decode(raw):
    need(len(raw)<=65536,'external_record_size')
    def pairs(items):
        d={}
        for k,v in items:need(k not in d,'duplicate_external_key');d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=pairs)
def utc(s):
    need(isinstance(s,str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',s),'external_time_format')
    return dt.datetime.strptime(s,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc)

def validate(record,context,run,hashes,runtime_hash,now,env):
    need(record.get('schema')=='external_metadata_review_v1','external_schema')
    need(record.get('approval_mechanism')=='externally_reviewed_record','external_mechanism')
    need(all(record.get(k) is True for k in TRUE_FLAGS),'external_approval_missing')
    need(all(record.get(k) is False for k in FALSE_FLAGS),'external_scope_expansion')
    need(type(record.get('home_default_acl_disposition_accepted',False)) is bool,'home_acl_disposition_invalid')
    need(record.get('scope')=='14_pypi_discovery_gets_only','external_scope')
    need(record.get('owner_login')=='FawadKarimi' and record.get('owner_id')==OWNER_ID,'external_owner')
    need(all(isinstance(record.get(k),str) and record[k] for k in ('review_reference','security_review_reference','compatibility_evidence_sha256')),'external_evidence_missing')
    need(re.fullmatch('[0-9a-f]{64}',record['compatibility_evidence_sha256']) is not None,'external_compatibility_hash')
    issued=utc(record['issued_utc']);expires=utc(record['expires_utc'])
    need(issued<=now<expires and dt.timedelta(0)<expires-issued<=dt.timedelta(hours=1),'external_expired')
    need(record.get('sources')==hashes and set(hashes)==set(BOUND),'external_source_drift')
    need(record.get('runtime_acceptance_sha256')==runtime_hash,'external_runtime_binding')
    need(record.get('manifest_sha256')==sha((Path(__file__).parent/'request-manifest.json').read_bytes()),'external_manifest')
    need(context['repository']==record.get('repository')==REPO,'external_repository')
    need(context['commit']==record.get('commit') and re.fullmatch('[0-9a-f]{40}',context['commit']),'external_commit')
    need(context['workflow_ref']==REPO+'/'+WORKFLOW+'@refs/heads/main','external_workflow')
    need(context['event']=='workflow_dispatch' and context['os']=='Linux' and context['arch']=='X64','external_event')
    need(context['attempt']=='1' and env.get('GITHUB_RUN_ATTEMPT')=='1','external_replay_attempt')
    need(env.get('GITHUB_ACTOR_ID')==env.get('GITHUB_TRIGGERING_ACTOR_ID',env.get('GITHUB_ACTOR_ID'))==str(OWNER_ID),'external_actor')
    need(type(record.get('workflow_id')) is int and record['workflow_id']>0,'external_workflow_id')
    need(type(record.get('run_number')) is int and record['run_number']>0,'external_run_number')
    need(run.get('id')==int(context['run_id']) and run.get('run_attempt')==1,'external_run')
    need(run.get('workflow_id')==record['workflow_id'] and run.get('run_number')==record['run_number']==int(env['GITHUB_RUN_NUMBER']),'external_replayed_dispatch')
    need(record.get('run_id') in (None,run['id']),'external_expected_run_id')
    need(run.get('repository',{}).get('id')==REPO_ID and run['repository'].get('full_name')==REPO and run['repository'].get('private') is True,'external_repository_identity')
    need(run.get('head_sha')==context['commit'] and run.get('head_branch')=='main' and run.get('event')=='workflow_dispatch','external_server_context')
    need(run.get('path')==WORKFLOW and run.get('actor',{}).get('id')==OWNER_ID and run.get('triggering_actor',{}).get('id')==OWNER_ID,'external_server_actor')
    need(run.get('status')=='in_progress','external_run_not_active')
    return True

def api_run(run_id,token):
    need(re.fullmatch('[0-9]+',run_id) is not None and token,'external_api_parameters')
    end=time.monotonic()+8
    conn=http.client.HTTPSConnection('api.github.com',timeout=8,context=ssl.create_default_context())
    try:
        conn.request('GET',f'/repos/{REPO}/actions/runs/{run_id}',headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'reviewed-metadata-admission'})
        r=conn.getresponse();need(time.monotonic()<end,'external_api_timeout')
        need(r.status==200 and r.getheader('Content-Type','').split(';')[0]=='application/json','external_api_response')
        need(r.getheader('Content-Encoding','identity')=='identity','external_api_encoding')
        raw=bytearray()
        while True:
            left=end-time.monotonic();need(left>0,'external_api_timeout')
            if conn.sock is not None:conn.sock.settimeout(left)
            b=r.read1(min(16384,1048577-len(raw)))
            if not b:break
            raw.extend(b);need(len(raw)<=1048576,'external_api_size')
        need(time.monotonic()<end,'external_api_timeout')
        return json.loads(raw),sha(raw)
    finally:conn.close()

def write_new(path,data):
    raw=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    if sys.platform=='linux':
        fd=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    return sha(raw)

def reserve(folder,record_hash,context):
    # Atomic role-local reservation; no release, retries or overwrite after failure.
    value={'record_sha256':record_hash,'context':context}
    write_new(Path(folder)/'dispatch-reserved.json',value)
    return value

def reconstruct(receipt,receipt_path,context,worker):
    evidence=receipt['external_review'];folder=Path(receipt_path).parent
    record=decode((folder/'external-record.json').read_bytes())
    record_hash=sha((folder/'external-record.json').read_bytes())
    need(record_hash==evidence['record_sha256'],'external_record_changed')
    run=decode((folder/'dispatch-binding.json').read_bytes())
    hashes={n:sha((Path(__file__).parent/n).read_bytes()) for n in BOUND}
    validate(record,context,run,hashes,receipt['runtime_acceptance_sha256'],dt.datetime.now(dt.timezone.utc),os.environ)
    reserved=decode((folder/'dispatch-reserved.json').read_bytes())
    need(reserved=={'record_sha256':record_hash,'context':context},'external_reservation_mismatch')
    if worker:need(decode((folder/'parent-claimed.json').read_bytes())==reserved,'external_parent_claim')
    write_new(folder/('worker-claimed.json' if worker else 'parent-claimed.json'),reserved)
    return record

def issue(record_raw,expected_hash,folder,context,env,fetch=api_run,observe_runtime=None,observe_output=output_security.observe,progress=None):
    mark=(lambda stage:None) if progress is None else progress
    mark('input_validation')
    need(sha(record_raw)==expected_hash,'external_hash_mismatch')
    record=decode(record_raw)
    # Reject default/expired inputs before the one GitHub API request.
    need(all(record.get(k) is True for k in TRUE_FLAGS),'external_approval_missing')
    need(type(record.get('home_default_acl_disposition_accepted',False)) is bool,'home_acl_disposition_invalid')
    need(utc(record['issued_utc'])<=dt.datetime.now(dt.timezone.utc)<utc(record['expires_utc']),'external_expired')
    root=Path(__file__).parent
    mark('dispatch_confirmation')
    need(env.get('OWNER_CONFIRMATION')=='true' and env.get('BILLING_CONFIRMATION')=='true','external_dispatch_confirmation')
    runtime_path=root/'metadata-runtime-acceptance.json';runtime_hash=sha(runtime_path.read_bytes())
    mark('runtime_verification')
    runtime=runtime_acceptance.verify_record(runtime_path,runtime_hash,observe=observe_runtime)
    mark('source_binding')
    hashes={n:sha((root/n).read_bytes()) for n in BOUND}
    mark('github_identity_request')
    run,api_hash=fetch(context['run_id'],env.get('GITHUB_TOKEN',''))
    mark('github_identity_validation')
    validate(record,context,run,hashes,runtime_hash,dt.datetime.now(dt.timezone.utc),env)
    out=Path(env['RUNNER_TEMP'])/('pypi-evidence-'+context['run_id']+'-'+context['attempt'])
    mark('output_path_validation')
    admission.output_policy(env['RUNNER_TEMP'],env['GITHUB_WORKSPACE'],out)
    mark('acl_mount_observation')
    kwargs={'allow_home_default_acl':True} if record.get('home_default_acl_disposition_accepted') is True else {}
    paths=observe_output(env['RUNNER_TEMP'],env['GITHUB_WORKSPACE'],**kwargs)
    paths['created_admission_evidence']=output_security.verify_evidence_folder(folder)
    mark('output_evidence_write')
    write_new(folder/'output-checks.json',paths)
    # Bind only reviewed fields needed by reconstruct; never API credentials.
    fields=('id','run_attempt','workflow_id','run_number','repository','head_sha','head_branch','event','path','actor','triggering_actor','status')
    clean={k:run[k] for k in fields}
    clean['repository']={k:run['repository'][k] for k in ('id','full_name','private')}
    clean['actor']={'id':run['actor']['id']};clean['triggering_actor']={'id':run['triggering_actor']['id']}
    mark('dispatch_record_write')
    write_new(folder/'dispatch-binding.json',clean)
    fd=os.open(folder/'external-record-original.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as f:f.write(record_raw);f.flush();os.fsync(f.fileno())
    write_new(folder/'external-record.json',record)
    # Hash in receipts refers to stored canonical bytes, with original bytes/hash
    # separately retained so approved input whitespace remains auditable.
    stored_hash=sha((folder/'external-record.json').read_bytes())
    mark('reservation')
    reserve(folder,stored_hash,context)
    now=dt.datetime.now(dt.timezone.utc)
    expiry=min(now+dt.timedelta(minutes=15),utc(record['expires_utc']))
    receipt=json.loads((root/'authorization-TEMPLATE.json').read_text())
    receipt.update(owner_authorized=True,independent_workflow_reviewed=True,zero_paid_usage_confirmed=True,
      same_uid_residual_risk_accepted=True,context=context,source_hashes={n:hashes[n] for n in CORE},
      runtime_acceptance_sha256=runtime_hash,issued_utc=now.isoformat(),expires_utc=expiry.isoformat(),
      external_review={'record_sha256':stored_hash,'original_record_sha256':expected_hash,'api_response_sha256':api_hash})
    mark('receipt_write')
    write_new(folder/'runtime-observed.json',runtime)
    digest=write_new(folder/'receipt.json',receipt)
    write_new(folder/'receipt-binding.json',{'sha256':digest,'runtime_sha256':runtime_hash})
    return receipt


# Closed projections only: never persist raw messages, tracebacks or env values.
ADMISSION_FAILURE_CODES=frozenset((
    'home_acl_disposition_invalid',
    'home_acl_identity_rejected',
    'home_acl_pattern_rejected',
    'created_evidence_identity_rejected',
    'created_evidence_acl_rejected',
    'created_evidence_changed',
    'created_evidence_count_rejected',
    'acl_format',
    'acl_unavailable',
    'acl_write_permission',
    'duplicate_external_key',
    'extended_or_default_acl_rejected',
    'external_actor',
    'external_api_encoding',
    'external_api_parameters',
    'external_api_response',
    'external_api_size',
    'external_api_timeout',
    'external_approval_missing',
    'external_commit',
    'external_compatibility_hash',
    'external_dispatch_confirmation',
    'external_event',
    'external_evidence_missing',
    'external_expected_run_id',
    'external_expired',
    'external_hash_mismatch',
    'external_manifest',
    'external_mechanism',
    'external_owner',
    'external_parent_claim',
    'external_record_changed',
    'external_record_size',
    'external_replay_attempt',
    'external_replayed_dispatch',
    'external_repository',
    'external_repository_identity',
    'external_reservation_mismatch',
    'external_run',
    'external_run_not_active',
    'external_run_number',
    'external_run_syntax',
    'external_runtime_binding',
    'external_schema',
    'external_scope',
    'external_scope_expansion',
    'external_server_actor',
    'external_server_context',
    'external_source_drift',
    'external_time_format',
    'external_workflow',
    'external_workflow_id',
    'mount_ambiguous',
    'mount_device_mismatch',
    'mount_filesystem_not_reviewed',
    'mount_missing',
    'mount_read_only',
    'mountinfo_size',
    'output_check_deadline',
    'output_root_uid',
    'parser_identity_mismatch',
    'parser_layout_rejected',
    'parser_missing',
    'path_changed',
    'path_not_directory',
    'path_owner_mode',
    'python_identity_mismatch',
    'runtime_not_accepted',
    'runtime_record_duplicate_key',
    'runtime_record_hash_mismatch',
    'runtime_record_oversized',
    'runtime_record_schema',
    'runtime_review_missing',
    'runtime_scope_rejected',
))
ADMISSION_STAGES=frozenset(('input_validation','dispatch_confirmation',
 'runtime_verification','source_binding','github_identity_request',
 'github_identity_validation','output_path_validation','acl_mount_observation',
 'output_evidence_write','dispatch_record_write','reservation','receipt_write'))

def admission_failure(exc,stage):
    code='unexpected_error'
    observation=None
    if type(exc) is output_security.ACLRejected:
        if len(exc.args)==1 and type(exc.args[0]) is str and exc.args[0] in output_security.ACL_CODES:
            code=exc.args[0]
            if stage=='acl_mount_observation':observation=output_security.safe_acl_diagnostic(exc.observation)
    elif isinstance(exc,runtime_acceptance.RuntimeRejected):
        candidate=exc.code
        if type(candidate) is str and candidate in ADMISSION_FAILURE_CODES:code=candidate
    elif type(exc) is ValueError and len(exc.args)==1:
        candidate=exc.args[0]
        if type(candidate) is str and candidate in ADMISSION_FAILURE_CODES:code=candidate
    elif isinstance(exc,TimeoutError):code='operation_timeout'
    elif isinstance(exc,FileNotFoundError):code='required_file_missing'
    elif isinstance(exc,PermissionError):code='filesystem_permission_denied'
    elif isinstance(exc,FileExistsError):code='exclusive_creation_rejected'
    elif isinstance(exc,OSError):code='os_operation_failed'
    elif isinstance(exc,http.client.HTTPException):code='http_transport_failed'
    result={'schema':'admission_failure_v1','status':'admission_failed',
            'stage':stage if type(stage) is str and stage in ADMISSION_STAGES else 'unknown_stage',
            'code':code,'protected_environment_verified':False,
            'raw_exception_retained':False}
    if observation is not None:result['acl_observation']=observation
    return result

def main():
    env=os.environ;os.umask(0o077)
    context=admission.context_from_env(env)
    need(re.fullmatch('[0-9]+',context['run_id']) and re.fullmatch('[0-9]+',context['attempt']),'external_run_syntax')
    admission.output_policy(env['RUNNER_TEMP'],env['GITHUB_WORKSPACE'],Path(env['RUNNER_TEMP'])/('pypi-evidence-'+context['run_id']+'-'+context['attempt']))
    folder=Path(env['RUNNER_TEMP'])/('external-review-'+context['run_id']+'-'+context['attempt'])
    folder.mkdir(mode=0o700,exist_ok=False)
    write_new(folder/'started.json',{'status':'incomplete','protected_environment_verified':False})
    stage='input_validation'
    def progress(value):
        nonlocal stage
        stage=value
    try:
        raw=env.get('EXTERNAL_RECORD_JSON','').encode();need(len(raw)<=65536,'external_record_size')
        # Keep approved public decision bytes, never arbitrary environment values.
        need(sha(raw)==env.get('EXTERNAL_RECORD_SHA256'),'external_hash_mismatch')
        issue(raw,env['EXTERNAL_RECORD_SHA256'],folder,context,env,progress=progress)
        write_new(folder/'finished.json',{'status':'receipt_prepared_not_collection','protected_environment_verified':False})
        return 0
    except Exception as exc:
        write_new(folder/'failed.json',admission_failure(exc,stage))
        return 2

if __name__=='__main__':raise SystemExit(main())
