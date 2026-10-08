"""Nine-sidecar synthetic-only adapter; reuses reviewed native evidence controls."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import signal
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_linux as n

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = '.github/workflows/sidecar-native-delta.yml'
COLLECTION_SHA = 'ed7b3fa17cab42d9c2cfab059454340164af5ad68f6ebc16540d3c5317fbbc37'
PROPOSAL_SHA = '3d24522de536bb1d64617b9efc5a7ddac1a414b199a65a59ad37c5146ed69283'
OVERLAY_FILES = {WORKFLOW, 'compatibility/nine_delta.py', 'compatibility/test_nine_delta.py'}


def verify_sources(root, expected):
    n.need(isinstance(expected,str) and re.fullmatch('[0-9a-f]{64}',expected), 'delta_lock_digest_required')
    raw=n.read_file(root/'native-delta-lock.json')
    n.need(n.sha(raw)==expected,'delta_lock_digest')
    overlay=n.strict_json(raw)
    n.need(overlay.get('schema')=='nine_sidecar_native_delta_lock_v1' and
           overlay.get('execution_authorized') is False and
           overlay.get('collection_source_lock_sha256')==COLLECTION_SHA and
           set(overlay.get('files',{}))==OVERLAY_FILES,'delta_lock_scope')
    collection_raw=n.read_file(root/'collection-source-lock.json')
    n.need(n.sha(collection_raw)==COLLECTION_SHA,'collection_lock_digest')
    collection=n.strict_json(collection_raw)
    n.need(collection.get('schema')=='sidecar_collection_source_lock_v1' and
           collection.get('collection_authorized') is False and
           collection.get('expected_offline_tests')==176 and
           len(collection.get('files',{}))==43,'collection_lock_scope')
    files={**collection['files'],**overlay['files']}
    n.need(len(files)==46,'delta_overlap')
    for name,digest in files.items():
        p=PurePosixPath(name)
        n.need(not p.is_absolute() and '..' not in p.parts and '\\' not in name and ':' not in name,'source_path')
        path=root/name
        n.need(all(not parent.is_symlink() for parent in path.parents),'source_ancestor_link')
        n.need(n.sha(n.read_file(path))==digest,'source_file_drift')
    n.need(n.sha(n.read_file(root/'sidecar-request-PROPOSED.json'))==PROPOSAL_SHA,'proposal_drift')
    return dict(native_delta_lock_sha256=expected,collection_source_lock_sha256=COLLECTION_SHA,
                workflow_sha256=files[WORKFLOW],files=files)


def context():
    keys=('GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT',
          'GITHUB_RUN_NUMBER','GITHUB_WORKFLOW_REF','GITHUB_ACTOR_ID','GITHUB_TRIGGERING_ACTOR','RUNNER_NAME')
    values={k:os.environ.get(k,'') for k in keys}
    n.need(all(values.values()),'run_context_incomplete')
    n.need(values['GITHUB_REPOSITORY']=='FawadKarimi/performance-v2-host-readiness' and
           values['GITHUB_RUN_ATTEMPT']=='1' and values['GITHUB_ACTOR_ID']=='108207574' and
           values['GITHUB_TRIGGERING_ACTOR']=='FawadKarimi','run_context_scope')
    n.need(re.fullmatch('[0-9a-f]{40}',values['GITHUB_SHA']) and
           all(re.fullmatch('[1-9][0-9]*',values[k]) for k in ('GITHUB_RUN_ID','GITHUB_RUN_NUMBER')),'run_context_format')
    n.need(values['GITHUB_WORKFLOW_REF']==values['GITHUB_REPOSITORY']+'/'+WORKFLOW+'@refs/heads/main','run_workflow_ref')
    return dict(values=values,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                provenance='runner environment only; no authenticated API call or collection admission')


def private_paths(root, output):
    sys.path.insert(0,str(root))
    import output_security
    paths=output_security.observe(output.parent,root,allow_home_default_acl=False)
    paths['created']=output_security.verify_created(output)
    return paths


def validate_result(result):
    n.need(type(result) is dict and type(result.get('tests')) is int and result['tests']==176 and
           all(type(result.get(k)) is int and result[k]==0 for k in ('failures','errors','skipped')) and
           result.get('successful') is True and result.get('network_and_subprocess_audit_deny') is True and
           result.get('execution_authorized') is False and
           result.get('source_lock_sha256')==COLLECTION_SHA,'synthetic_test_results')
    return result


def synthetic(root,evidence):
    stdout=n.BoundedText(evidence.path/'test-result-stdout.json')
    stderr=n.BoundedText(evidence.path/'tests.log')
    code=None
    try:
        with redirect_stdout(stdout),redirect_stderr(stderr):
            try:runpy.run_path(str(root/'run_collection_offline_tests.py'),run_name='__main__')
            except SystemExit as exc:code=exc.code
    finally:
        stdout.close();stderr.close()
        evidence.write('test-exit-status.json',{'exit_code':code})
    n.need(type(code) is int and code==0,'synthetic_test_exit')
    return validate_result(n.strict_json(n.read_file(evidence.path/'test-result-stdout.json')))


def execute(root,output,expected,parent,uid,observe=n.runtime,network=n.isolation,
            run_tests=synthetic,run_context=context,paths=private_paths):
    evidence=n.Evidence(output)
    errors=[];binding=None;code=2;old={}
    def record(name,obj):
        try:evidence.write(name,obj)
        except BaseException:errors.append('evidence_write_'+name)
    def cancelled(signum,frame):raise n.Cancelled()
    try:
        for sig in (signal.SIGTERM,signal.SIGINT):old[sig]=signal.signal(sig,cancelled)
        evidence.write('started.json',dict(status='incomplete',**n.FALSE_FLAGS))
        binding=verify_sources(root,expected);evidence.write('source-before.json',binding)
        evidence.write('run-context.json',run_context())
        evidence.write('network-isolation.json',network(parent,uid))
        evidence.write('private-paths.json',paths(root,output))
        actual=observe(root);evidence.write('runtime-observed.json',actual)
        reference=n.strict_json(n.read_file(root/'reference/metadata-runtime-acceptance.json'))
        n.need(reference.get('metadata_runtime_accepted') is True and
               reference.get('scope')=='public_pypi_metadata_only' and
               all(actual[k]==reference[k] for k in ('python','parser')),'runtime_identity_drift')
        result=validate_result(run_tests(root,evidence))
        evidence.write('test-results.json',result);code=0
    except BaseException as exc:
        errors.append(str(exc) if isinstance(exc,n.Rejected) else
                      'interrupted' if isinstance(exc,(n.Cancelled,KeyboardInterrupt,SystemExit)) else 'delta_failure')
    finally:
        try:
            after=verify_sources(root,expected)
            n.need(binding is not None and after==binding,'source_changed_during_tests')
            record('source-after.json',after)
        except BaseException:errors.append('post_source_verification_failed')
        code=code if not errors else (code if code else 2)
        record('exit-status.json',{'exit_code':code,'errors':list(errors),**n.FALSE_FLAGS})
        record('finished.json',dict(status='synthetic_delta_passed_not_accepted' if code==0 and not errors else 'failed',
            exit_code=code,errors=list(errors),collection_source_lock_sha256=COLLECTION_SHA,
            native_delta_lock_sha256=expected,**n.FALSE_FLAGS))
        try:evidence.seal()
        except BaseException:errors.append('evidence_seal_failed')
        for sig,handler in old.items():signal.signal(sig,handler)
    return code if not errors else (code if code else 2)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--delta-lock-sha256',required=True)
    parser.add_argument('--parent-net',required=True)
    parser.add_argument('--uid',type=int,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    temp=Path(os.environ['RUNNER_TEMP'])
    n.need(args.output.is_absolute() and args.output.parent==temp and
           args.output.name=='nine-delta-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT'],'output_run_binding')
    n.need(temp.is_absolute() and ROOT!=temp and ROOT not in temp.parents,'output_inside_source')
    n.need(not os.path.lexists(args.output),'output_replay_or_link')
    for p in (temp,*temp.parents):
        s=p.lstat();n.need(stat.S_ISDIR(s.st_mode) and not p.is_symlink(),'output_ancestor_link')
    return execute(ROOT,args.output,args.delta_lock_sha256,args.parent_net,args.uid)


if __name__=='__main__':raise SystemExit(main())
