"""Offline synthetic compatibility harness; never invoke collection or admission."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import signal
import socket
import stat
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
INPUT_SHA = 'b5e13eef5dd4e66dd9301a31f19b7f4924bfb570916ab9d99ca7bbcb5be6e3ec'
PROPOSAL_SHA = 'ad7c7e726ba0c5df2ecd74c601f9036570c5bbc92206f7e98dda230d6054fe9b'
WORKFLOW = '.github/workflows/sidecar-linux-compatibility.yml'
FALSE_FLAGS = dict(collection_authorized=False, execution_authorized=False,
    native_linux_accepted=False, sidecar_transport_accepted=False,
    stage_b_authorized=False, gpu_pilot_authorized=False, dependency_closure_complete=False,
    metadata_runtime_accepted=False, security_approved=False, full_docker_accepted=False)


class Rejected(ValueError):
    pass


class Cancelled(BaseException):
    pass


def need(ok, code):
    if not ok:
        raise Rejected(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    def bad(value):
        raise Rejected('nonfinite_json')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=bad)


def read_file(path, cap=1048576):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         not (getattr(before, 'st_file_attributes', 0) & 0x400), 'input_file_layout')
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        need((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino), 'input_file_replaced')
        raw = stream.read(cap+1)
    need(len(raw)<=cap, 'input_file_size')
    return raw


def verify_sources(root, expected):
    need(isinstance(expected,str) and re.fullmatch('[0-9a-f]{64}',expected), 'lock_digest_required')
    raw = read_file(root/'source-lock.json')
    need(sha(raw)==expected, 'source_lock_digest')
    lock = strict_json(raw)
    need(lock.get('schema')=='sidecar_linux_compatibility_source_lock_v1' and
         lock.get('input_package_sha256')==INPUT_SHA and
         lock.get('proposal_sha256')==PROPOSAL_SHA and
         lock.get('execution_authorized') is False, 'source_lock_scope')
    files=lock.get('files')
    need(type(files) is dict and 20<=len(files)<=100, 'source_lock_inventory')
    for name,digest in files.items():
        p=PurePosixPath(name)
        need(not p.is_absolute() and '..' not in p.parts and '\\' not in name and ':' not in name,
             'source_lock_path')
        path=root/name
        need(all(not parent.is_symlink() for parent in path.parents if parent!=root.parent),
             'source_ancestor_link')
        need(sha(read_file(path))==digest, 'source_file_drift')
    need(WORKFLOW in files and 'compatibility/native_linux.py' in files and
         'run_offline_tests.py' in files and
         'reference/metadata-runtime-acceptance.json' in files, 'source_lock_required_files')
    need(sha(read_file(root/'sidecar-request-PROPOSED.json'))==PROPOSAL_SHA,
         'proposal_drift')
    return {'source_lock_sha256':expected,'workflow_sha256':files[WORKFLOW],
            'files':files,'input_package_sha256':INPUT_SHA,'proposal_sha256':PROPOSAL_SHA}


class Evidence:
    def __init__(self,path):
        self.path=Path(path)
        self.path.mkdir(mode=0o700,exist_ok=False)
        self.total=0
    def write(self,name,raw):
        need(Path(name).name==name, 'output_name')
        if not isinstance(raw,bytes):
            raw=(json.dumps(raw,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
        need(len(raw)<=1048576 and self.total+len(raw)<=16*1048576, 'evidence_size')
        fd=os.open(self.path/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as stream:
            need(os.fstat(stream.fileno()).st_nlink==1, 'evidence_links')
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        self.total+=len(raw)
    def seal(self):
        items={}
        for path in sorted(self.path.iterdir()):
            raw=read_file(path)
            items[path.name]={'bytes':len(raw),'sha256':sha(raw)}
        self.write('evidence-ledger.json',dict(schema='sidecar_compatibility_evidence_ledger_v1',
            excludes_itself=True,files=items,**FALSE_FLAGS))


def isolation(parent,uid):
    need(sys.platform=='linux' and os.getuid()==os.geteuid()==uid and uid!=0,'linux_unprivileged_uid')
    current=os.readlink('/proc/self/ns/net')
    need(current!=parent, 'network_namespace_not_separate')
    pairs=socket.if_nameindex()
    need(len(pairs)==1 and pairs[0][1]=='lo', 'network_interfaces')
    import fcntl
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as channel:
        result=fcntl.ioctl(channel.fileno(),0x8913,struct.pack('16sH22x',b'lo',0))
    flags=struct.unpack_from('H',result,16)[0]
    need(flags&1==0 and flags&8!=0,'loopback_not_down')
    status={line.split(':',1)[0]:line.split(':',1)[1].strip()
            for line in Path('/proc/self/status').read_text().splitlines() if ':' in line}
    need(status.get('NoNewPrivs')=='1' and int(status.get('CapEff','1'),16)==0,
         'privilege_controls')
    need(os.readlink('/proc/self/ns/net')==current,'namespace_changed')
    return dict(parent_namespace=parent,test_namespace=current,uid=uid,interfaces=pairs,
                flags=flags,loopback_up=False,no_new_privs=True,effective_capabilities='0',
                query='namespace-local if_nameindex and SIOCGIFFLAGS; not sysfs')


def context(env=None):
    env=os.environ if env is None else env
    keys=('GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT',
          'GITHUB_RUN_NUMBER','GITHUB_WORKFLOW_REF','GITHUB_ACTOR_ID',
          'GITHUB_TRIGGERING_ACTOR','RUNNER_NAME')
    values={k:env.get(k,'') for k in keys}
    need(all(values.values()),'run_context_incomplete')
    need(values['GITHUB_REPOSITORY']=='FawadKarimi/performance-v2-host-readiness' and
         values['GITHUB_RUN_ATTEMPT']=='1' and values['GITHUB_ACTOR_ID']=='108207574',
         'run_context_scope')
    need(re.fullmatch('[0-9a-f]{40}',values['GITHUB_SHA']) and
         all(re.fullmatch('[1-9][0-9]*',values[k]) for k in ('GITHUB_RUN_ID','GITHUB_RUN_NUMBER')),
         'run_context_format')
    need(values['GITHUB_WORKFLOW_REF']==values['GITHUB_REPOSITORY']+'/'+WORKFLOW+'@refs/heads/main',
         'run_workflow_ref')
    values['boot_id']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    return dict(values=values,provenance='runner environment; not independently authenticated API evidence')


def runtime(root):
    sys.path.insert(0,str(root))
    import runtime_acceptance
    return runtime_acceptance.observed_identity()


class BoundedText:
    def __init__(self,path,cap=524288):
        self.stream=path.open('x',encoding='utf-8',newline='\n')
        os.chmod(path,0o600)
        self.cap=cap;self.count=0
    def write(self,text):
        raw=text.encode('utf-8')
        allowed=raw[:max(0,self.cap-self.count)]
        self.stream.write(allowed.decode('utf-8',errors='ignore'));self.stream.flush()
        self.count+=len(allowed)
        need(len(raw)==len(allowed),'test_log_cap')
        return len(text)
    def flush(self):
        self.stream.flush()
    def close(self):
        self.stream.flush();os.fsync(self.stream.fileno());self.stream.close()


def synthetic(root,evidence):
    stdout=BoundedText(evidence.path/'test-result-stdout.json')
    stderr=BoundedText(evidence.path/'tests.log')
    code=None
    try:
        with redirect_stdout(stdout),redirect_stderr(stderr):
            try:
                runpy.run_path(str(root/'compatibility/review_offline_tests.py'),run_name='__main__')
            except SystemExit as exc:
                code=exc.code
    finally:
        stdout.close();stderr.close()
    need(type(code) is int and code==0,'synthetic_test_exit')
    result=strict_json(read_file(evidence.path/'test-result-stdout.json'))
    expected=strict_json(read_file(root/'source-lock.json'))['expected_synthetic_tests']
    need(type(expected) is int and expected>=140 and result.get('tests')==expected and result.get('successful') is True and
         result.get('failures')==result.get('errors')==result.get('skipped')==0 and
         result.get('network_and_subprocess_audit_deny') is True and
         result.get('execution_authorized') is False and
         result.get('source_lock_sha256')==sha(read_file(root/'source-lock.json')), 'synthetic_test_results')
    return result


def execute(root,output,expected,parent,uid,observe=runtime,network=isolation,
            run_tests=synthetic,run_context=context):
    evidence=Evidence(output)
    old={}
    def cancelled(signum,frame):
        raise Cancelled()
    try:
        for sig in (signal.SIGTERM,signal.SIGINT):old[sig]=signal.signal(sig,cancelled)
        evidence.write('started.json',dict(status='incomplete',expected_source_lock_sha256=expected,**FALSE_FLAGS))
        binding=verify_sources(root,expected);evidence.write('source-binding.json',binding)
        evidence.write('run-context.json',run_context())
        evidence.write('network-isolation.json',network(parent,uid))
        actual=observe(root);evidence.write('runtime-observed.json',actual)
        reference=strict_json(read_file(root/'reference/metadata-runtime-acceptance.json'))
        need(reference.get('metadata_runtime_accepted') is True and
             reference.get('scope')=='public_pypi_metadata_only','historical_runtime_record')
        need(all(actual[k]==reference[k] for k in ('python','parser')),'runtime_identity_drift')
        result=run_tests(root,evidence)
        evidence.write('test-results.json',result)
        # Detect changes during tests; no fresh acceptance can be inferred.
        need(verify_sources(root,expected)==binding,'source_changed_during_tests')
        evidence.write('finished.json',dict(status='synthetic_compatibility_passed_not_accepted',
            source_lock_sha256=expected,workflow_sha256=binding['workflow_sha256'],
            runtime_record_sha256=sha(read_file(root/'reference/metadata-runtime-acceptance.json')),
            test_results_sha256=sha(read_file(evidence.path/'test-results.json')),**FALSE_FLAGS))
        code=0
    except BaseException as exc:
        kind='cancelled' if isinstance(exc,(Cancelled,KeyboardInterrupt,SystemExit)) else 'failed'
        # Closed error codes only; no arbitrary exception text or environment.
        safe=str(exc) if isinstance(exc,Rejected) else 'compatibility_failure'
        evidence.write('failed.json',dict(status=kind,error_code=safe,**FALSE_FLAGS))
        code=2
    finally:
        for sig,handler in old.items():signal.signal(sig,handler)
        evidence.seal()
    return code


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-lock-sha256',required=True)
    parser.add_argument('--parent-net',required=True)
    parser.add_argument('--uid',type=int,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    root=Path(os.environ['RUNNER_TEMP'])
    expected='sidecar-compat-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
    need(args.output.is_absolute() and args.output.parent==root and args.output.name==expected,
         'output_run_binding')
    need(root.is_absolute() and ROOT!=root and ROOT not in root.parents,'output_inside_source')
    need(not os.path.lexists(args.output),'output_replay_or_link')
    for parent in (root,*root.parents):
        info=parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
             not (getattr(info,'st_file_attributes',0)&0x400),'output_ancestor_link')
    return execute(ROOT,args.output,args.source_lock_sha256,args.parent_net,args.uid)


if __name__=='__main__':
    raise SystemExit(main())
