"""Read-only local runtime observations, not runtime acceptance or collection.

Stdlib only. Never import packaging, invoke the collector or issue HTTP. Output
is a new external evidence directory. Caller supplies an outer 60-second limit.
"""
import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import sys

MAX_FILE=256*1024*1024
MAX_TREE=64*1024*1024
MAX_FILES=1000
FLAGS={'metadata_runtime_accepted':False,'protected_environment_verified':False,
       'native_linux_accepted':False,'training_authorized':False,
       'research_execution_authorized':False,'artifact_acquisition_authorized':False,
       'pilot_execution_authorized':False}

def require(ok,msg):
    if not ok:raise ValueError(msg)

def file_hash(path,limit):
    path=Path(path); before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink(),'regular_file_required')
    require(before.st_size<=limit,'file_size_limit')
    digest=hashlib.sha256();total=0
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as f:
        opened=os.fstat(f.fileno())
        require((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino),'file_identity_changed')
        while True:
            b=f.read(min(65536,limit-total+1))
            if not b:break
            total+=len(b);require(total<=limit,'file_size_limit');digest.update(b)
        after=os.fstat(f.fileno())
    require((before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns) and total==before.st_size,'file_changed')
    return {'sha256':digest.hexdigest(),'size_bytes':total}

def parser_tree(root):
    root=Path(root);require(root.is_dir() and not root.is_symlink(),'parser_root_rejected')
    files={};sizes={};total=0;visited=0
    # Bound traversal before expanding a complete recursive list.
    def walk(folder):
        nonlocal total,visited
        with os.scandir(folder) as entries:
            for entry in entries:
                visited+=1;require(visited<=MAX_FILES*2,'parser_entry_limit')
                require(not entry.is_symlink(),'parser_symlink_rejected')
                if entry.name=='__pycache__' and entry.is_dir(follow_symlinks=False):continue
                p=Path(entry.path)
                if entry.is_dir(follow_symlinks=False):walk(p)
                else:
                    require(entry.is_file(follow_symlinks=False),'parser_special_file')
                    require(len(files)<MAX_FILES,'parser_file_limit')
                    h=file_hash(p,MAX_TREE-total);total+=h['size_bytes']
                    n=p.relative_to(root).as_posix();files[n]=h['sha256'];sizes[n]=h['size_bytes']
    walk(root)
    require('__init__.py' in files,'parser_init_missing')
    files=dict(sorted(files.items()))
    raw=json.dumps(files,sort_keys=True,separators=(',',':')).encode()
    return {'files':files,'tree_sha256':hashlib.sha256(raw).hexdigest(),
            'size_bytes_by_file':dict(sorted(sizes.items())),'total_size_bytes':total}

def python_identity():
    executable=Path(sys.executable).resolve(strict=True)
    return {'implementation':platform.python_implementation(),'version':platform.python_version(),
            'cache_tag':sys.implementation.cache_tag,'executable_path':str(executable),
            'executable_sha256':file_hash(executable,MAX_FILE)['sha256'],
            'invoked_executable':sys.executable,'sys_flags':{'isolated':sys.flags.isolated,'no_site':sys.flags.no_site,
            'dont_write_bytecode':sys.flags.dont_write_bytecode}}

def parser_identity():
    # Top-level find_spec and distribution metadata; no packaging import.
    spec=importlib.util.find_spec('packaging')
    require(spec is not None and spec.origin is not None,'packaging_missing')
    root=Path(spec.origin).parent
    tree=parser_tree(root)
    return {'name':'packaging','version':importlib.metadata.version('packaging'),
            'root':str(root.resolve(strict=True)),**tree,'package_imported':False}

def bounded_text(path,size=4096):
    with Path(path).open('rb') as f:b=f.read(size+1)
    require(len(b)<=size,'text_size_limit')
    return b.decode('utf-8',errors='strict').strip()

def runner_identity(env):
    names=('GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_WORKFLOW_REF','GITHUB_RUN_ID',
           'GITHUB_RUN_ATTEMPT','GITHUB_EVENT_NAME','RUNNER_NAME','RUNNER_OS','RUNNER_ARCH',
           'ImageOS','ImageVersion')
    result={n:env.get(n) for n in names}
    require(all(v is None or len(v)<=2048 for v in result.values()),'identity_size_limit')
    result['boot_id']=bounded_text('/proc/sys/kernel/random/boot_id',128)
    result['os_release']=bounded_text('/etc/os-release')
    result['kernel_release']=platform.release()
    result['machine']=platform.machine()
    result['missing_environment_identifiers']=[k for k,v in result.items() if v is None]
    result['image_identifiers_are_environment_reported']=True
    return result

def path_metadata(path):
    info=Path(path).lstat()
    return {'path':str(path),'uid':info.st_uid,'gid':info.st_gid,
            'mode_octal':oct(stat.S_IMODE(info.st_mode)),'device':info.st_dev,'inode':info.st_ino,
            'is_symlink':stat.S_ISLNK(info.st_mode),'is_directory':stat.S_ISDIR(info.st_mode)}

def path_inventory(root,workspace,output):
    paths=[];seen=set()
    for p in (Path(root),Path(workspace),Path(output)):
        for a in (p,*p.parents):
            if str(a) in seen:continue
            seen.add(str(a));paths.append(path_metadata(a))
    uid=os.getuid();gaps=[]
    for p in paths:
        if not p['is_directory'] or p['is_symlink'] or p['uid'] not in (0,uid) or int(p['mode_octal'],8)&0o022:
            gaps.append({'path':p['path'],'reason':'does_not_meet_proposed_mode_owner_policy'})
    if Path(root).stat().st_uid!=uid:
        gaps.append({'path':str(root),'reason':'runner_temp_not_owned_by_runner_uid'})
    return {'uid':uid,'gid':os.getgid(),'ancestors':paths,'policy_gaps':gaps,
            'intended_later_output':str(Path(root)/'pypi-evidence-<run_id>-<attempt>'),
            'acl_checked':False,'mount_options_checked':False,'same_uid_isolation':False,
            'inventory_output_is_not_a_collection_output_approval':True}

def prepare_output(root,workspace,output):
    root=Path(root);workspace=Path(workspace);output=Path(output)
    for p in (root,workspace,output):require(p.is_absolute() and '..' not in p.parts,'absolute_safe_path_required')
    require(output.parent==root and output.name.startswith('metadata-runtime-inventory-'),'output_location_rejected')
    for p in (root,workspace):
        for a in (p,*p.parents):
            info=a.lstat()
            require(stat.S_ISDIR(info.st_mode) and not a.is_symlink() and not getattr(info,'st_file_attributes',0)&0x400,'unsafe_ancestor')
    require(workspace!=root and workspace not in root.parents,'output_in_repository')
    require(not os.path.lexists(output),'output_already_exists')
    output.mkdir(mode=0o700)
    return output

def write_json(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    require(len(raw)<=1024*1024,'report_size_limit')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

def run(output,operations):
    report={'schema':'metadata_runtime_inventory_v1','status':'incomplete',**FLAGS,
            'script_sha256':file_hash(Path(__file__),MAX_FILE)['sha256'],
            'observations':{},'errors':[],'scope':'local_runtime_metadata_only'}
    write_json(output/'00-started.json',report)
    for i,(name,operation) in enumerate(operations,1):
        try:report['observations'][name]=operation()
        except Exception:
            # No raw exception, arbitrary environment, source text or traceback.
            report['errors'].append({'step':name,'code':'observation_failed'})
        write_json(output/f'{i:02d}-{name}.json',report)
    report['status']='observed_not_accepted' if not report['errors'] else 'partial_not_accepted'
    write_json(output/'report.json',report)
    ledger={p.name:file_hash(p,1024*1024) for p in sorted(output.glob('*.json'))}
    write_json(output/'manifest.json',{'files':ledger,'status':report['status'],**FLAGS})
    return 1 if report['errors'] else 0

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    env=os.environ
    require(env.get('GITHUB_ACTIONS')=='true' and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch','manual_actions_only')
    require(env.get('RUNNER_OS')=='Linux' and env.get('RUNNER_ARCH')=='X64','runner_not_supported')
    require(a.output.name=='metadata-runtime-inventory-'+env['GITHUB_RUN_ID']+'-'+env['GITHUB_RUN_ATTEMPT'],'run_output_mismatch')
    os.umask(0o077)
    out=prepare_output(env['RUNNER_TEMP'],env['GITHUB_WORKSPACE'],a.output)
    return run(out,[('runner',lambda:runner_identity(env)),('python',python_identity),
                    ('packaging',parser_identity),('paths',lambda:path_inventory(env['RUNNER_TEMP'],env['GITHUB_WORKSPACE'],out))])

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print('{"status":"inventory_failed_partial_evidence_may_exist","accepted":false}',file=sys.stderr)
        raise SystemExit(2)
