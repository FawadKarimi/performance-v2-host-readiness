"""Explicit scoped authorization, not an override of historical false flags."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat

def need(ok,msg):
    if not ok: raise ValueError(msg)

def authorize(manifest, receipt, context, source_hashes, now):
    need(receipt.get('schema')=='pv2_public_metadata_admission_v1','authorization schema')
    need(receipt.get('owner_authorized') is True and receipt.get('independent_workflow_reviewed') is True,'explicit owner/review approval missing')
    need(receipt.get('zero_paid_usage_confirmed') is True,'fresh billing confirmation missing')
    need(receipt.get('scope')=='14_pypi_discovery_gets_only','scope mismatch')
    need(receipt.get('manifest_sha256')==manifest,'manifest binding mismatch')
    need(receipt.get('source_hashes')==source_hashes and source_hashes,'implementation binding mismatch')
    need(receipt.get('context')==context,'run/attempt/commit/runner identity mismatch')
    need(context.get('event')=='workflow_dispatch' and context.get('os')=='Linux' and context.get('arch')=='X64','unsupported runner/event')
    need(all(context.get(k) for k in ('repository','commit','run_id','attempt','runner','boot_id','workflow_ref')),'incomplete runtime identity')
    need(all(receipt.get(k) is False for k in ('security_approved','pilot_execution_authorized','research_execution_authorized','artifact_acquisition_authorized')),'broader authorization refused')
    issued=dt.datetime.fromisoformat(receipt['issued_utc'].replace('Z','+00:00'))
    expires=dt.datetime.fromisoformat(receipt['expires_utc'].replace('Z','+00:00'))
    need(issued.utcoffset()==dt.timedelta(0) and expires.utcoffset()==dt.timedelta(0),'UTC authorization times required')
    need(issued<=now<expires and dt.timedelta(0)<expires-issued<=dt.timedelta(hours=1),'expired/future/overlong authorization')
    need(receipt.get('same_uid_residual_risk_accepted') is True,'same-UID threat-model amendment not accepted')
    return {'receipt_sha256':hashlib.sha256(json.dumps(receipt,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'scope':receipt['scope'],'context':context}

def output_policy(runner_temp,workspace,output,uid=None,worker=False):
    """Public-metadata-only trusted ephemeral job: no untrusted concurrent code."""
    uid=os.getuid() if uid is None else uid
    root=Path(runner_temp); repo=Path(workspace); out=Path(output)
    need(root.is_absolute() and repo.is_absolute() and out.is_absolute(),'absolute paths required')
    need('..' not in root.parts and '..' not in out.parts and '..' not in repo.parts,'traversal refused')
    for p in (root,repo):
        for a in (p,*p.parents):
            info=a.lstat()
            need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'unsafe path ancestor')
            # Runner-owned ancestors accepted by the explicit scoped amendment;
            # group/other-writable ancestors are not, including sticky /tmp.
            need(info.st_uid in (0,uid) and info.st_mode&0o022==0,'untrusted/writable ancestor')
    need(root.stat().st_uid==uid,'runner temp not owned by collector UID')
    need(out.parent==root and out.name.startswith('pypi-evidence-'),'output must be named direct child of runner temp')
    need(root!=repo and repo not in root.parents and out!=repo and repo not in out.parents,'output overlaps repository')
    if worker:
        info=out.lstat()
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid==uid and stat.S_IMODE(info.st_mode)==0o700,'worker parent identity/mode invalid')
    else: need(not os.path.lexists(out),'output exists/replayed run')
    return {'external_root':str(root),'repository_roots':[str(repo)]}

def context_from_env(env):
    keys={'repository':'GITHUB_REPOSITORY','commit':'GITHUB_SHA','run_id':'GITHUB_RUN_ID','attempt':'GITHUB_RUN_ATTEMPT','runner':'RUNNER_NAME','workflow_ref':'GITHUB_WORKFLOW_REF','event':'GITHUB_EVENT_NAME','os':'RUNNER_OS','arch':'RUNNER_ARCH'}
    need(env.get('GITHUB_ACTIONS')=='true','GitHub Actions context required')
    result={k:env.get(v) for k,v in keys.items()}
    result['boot_id']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    return result

def load_grant(manifest_path,receipt_path,expected_raw_hash,source_dir,output,env=None,worker=False,runtime_path=None,runtime_hash=None,runtime_observe=None):
    env=os.environ if env is None else env
    with Path(receipt_path).open('rb') as stream:
        raw=stream.read(65537)
    need(len(raw)<=65536,'authorization size bound')
    need(hashlib.sha256(raw).hexdigest()==expected_raw_hash,'authorization byte hash mismatch')
    def pairs(items):
        d={}
        for k,v in items:
            need(k not in d,'duplicate authorization key');d[k]=v
        return d
    receipt=json.loads(raw,object_pairs_hook=pairs)
    sources={name:hashlib.sha256((Path(source_dir)/name).read_bytes()).hexdigest() for name in ('collector.py','admission.py','runtime_acceptance.py','worker_diagnostics.py')}
    grant=authorize(hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest(),receipt,context_from_env(env),sources,dt.datetime.now(dt.timezone.utc))
    grant['raw_receipt_sha256']=expected_raw_hash
    need(runtime_path is not None and runtime_hash and receipt.get('runtime_acceptance_sha256')==runtime_hash,'runtime acceptance binding missing')
    import runtime_acceptance
    kwargs={} if runtime_observe is None else {'observe':runtime_observe}
    grant['runtime_acceptance']=runtime_acceptance.verify_record(runtime_path,runtime_hash,**kwargs)
    need(Path(output).name=='pypi-evidence-'+grant['context']['run_id']+'-'+grant['context']['attempt'],'output/run binding mismatch')
    policy=output_policy(env['RUNNER_TEMP'],env['GITHUB_WORKSPACE'],output,worker=worker)
    if 'external_review' in receipt:
        import external_review,output_security
        grant['fresh_output_checks']=output_security.observe(env['RUNNER_TEMP'],env['GITHUB_WORKSPACE'])
        external_review.reconstruct(receipt,receipt_path,grant['context'],worker)
    grant['output_policy']=policy; grant['output']=str(output)
    return grant
