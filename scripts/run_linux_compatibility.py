"""Selected synthetic suite inside an already-created no-network namespace.

No installation or collector CLI. Compare observed runtime to reviewed reference,
not to an accepted grant; successful compatibility never grants acceptance.
"""
import argparse,hashlib,json,os,socket,struct,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import runtime_acceptance
from external_review import write_new

MODULES=('test_collector','test_runtime_admission','test_external_review','test_namespace_correction')
def need(ok,msg):
    if not ok:raise ValueError(msg)
def interface_flags(name):
    # Linux SIOCGIFFLAGS on a namespace-local datagram socket. No packets sent.
    import fcntl
    request=struct.pack('16sH22x',name.encode('ascii'),0)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as channel:
        result=fcntl.ioctl(channel.fileno(),0x8913,request)
    need(isinstance(result,bytes) and len(result)==40,'interface_flags_query_format')
    return struct.unpack_from('H',result,16)[0]

def isolated(parent,uid,readlink=os.readlink):
    need(os.getuid()==uid and uid!=0,'test_uid_not_unprivileged')
    current=readlink('/proc/self/ns/net');need(current!=parent,'network_namespace_not_separate')
    # sysfs may still describe the host's namespace after unshare --net.
    pairs=socket.if_nameindex()
    need(len(pairs)==1 and type(pairs[0][0]) is int and pairs[0][0]>0,'interface_inventory_invalid')
    names=[name for _,name in pairs]
    need(names==['lo'],'unexpected_network_interface')
    flags=interface_flags('lo')
    need(flags&1==0,'loopback_is_up')
    need(flags&8!=0,'interface_not_loopback')
    need(readlink('/proc/self/ns/net')==current,'network_namespace_changed')
    return {'parent_namespace':parent,'test_namespace':current,'interfaces':pairs,'loopback_up':False,'uid':uid,
            'query':'if_nameindex_and_SIOCGIFFLAGS','flags':flags,'sysfs_used':False}

def package_revisions(command=subprocess.run):
    names=('python3.12','libpython3.12-stdlib','libpython3.12t64','python3-packaging')
    result={'status':'unresolved','patched_status':'not_inferred','packages':list(names)}
    if sys.platform!='linux':return result
    try:
        r=command(['/usr/bin/dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\\n',*names],
            timeout=4,capture_output=True,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        need(len(r.stdout)<=16384 and len(r.stderr)<=4096,'package_query_output_limit')
        result.update(exit_status=r.returncode,stdout=r.stdout.decode('utf-8','strict'),stderr=r.stderr.decode('utf-8','strict'))
        result['status']='observed_not_security_clearance' if r.returncode==0 else 'partial_unresolved'
    except Exception as exc:result['failure_type']=type(exc).__name__
    return result
def compare(reference,actual):
    for k in ('python','parser'):need(reference[k]==actual[k],k+'_runtime_drift')
def execute(output,parent,uid,reference,observe=runtime_acceptance.observed_identity,network_check=isolated,run_tests=None):
    write_new(output/'started.json',{'status':'incomplete','metadata_runtime_accepted':False})
    try:
        network=network_check(parent,uid);write_new(output/'network-isolation.json',network)
        write_new(output/'ubuntu-package-revisions.json',package_revisions())
        actual=observe();write_new(output/'runtime-observed.json',actual);compare(reference,actual)
        if run_tests is None:
            suite=unittest.defaultTestLoader.loadTestsFromNames(MODULES)
            with (output/'tests.log').open('x',encoding='utf-8') as stream:
                result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
            tests={'count':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped)}
            need(result.wasSuccessful() and not result.skipped,'synthetic_suite_failed')
        else:tests=run_tests()
        write_new(output/'finished.json',{'status':'synthetic_compatibility_passed_not_accepted','tests':tests,
          'metadata_runtime_accepted':False,'protected_environment_verified':False,'native_linux_accepted':False})
        return 0
    except Exception:
        write_new(output/'failed.json',{'status':'compatibility_failed','metadata_runtime_accepted':False,
          'protected_environment_verified':False,'native_linux_accepted':False})
        return 2
def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--parent-net',required=True);p.add_argument('--uid',type=int,required=True);a=p.parse_args()
    lock=json.loads((ROOT/'compatibility-source-lock.json').read_text())
    for n,digest in lock['files'].items():need(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==digest,'source_lock_mismatch')
    need(a.output.parent==Path(os.environ['RUNNER_TEMP']) and not a.output.exists(),'compatibility_output')
    a.output.mkdir(mode=0o700)
    reference=json.loads((ROOT/'runtime-identity-reference.json').read_text())
    return execute(a.output,a.parent_net,a.uid,reference)
if __name__=='__main__':raise SystemExit(main())
