"""Manifest-pinned PyPI metadata collection; CLI fails closed in this review.

No artifact client, installer, redirects, retries, proxy or executable metadata.
Tests inject transports, never a network-enabled authorization.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit, unquote

MANIFEST_SHA256 = '587b0eb7e124783ec6a62d7f316fdd263f40cf3b9130b64eaf6f8855395dd551'
PROJECTS = ('filelock','typing-extensions','setuptools','sympy','networkx','jinja2','fsspec','numpy','pillow','pyyaml','pandas','opencv-python','pytest','wheel')
FLAGS = ('network_authorized','acquisition_authorized','execution_approved','security_approved','pilot_execution_authorized')
MEDIA = 'application/vnd.pypi.simple.v1+json'
# No live root or repository boundary has been approved. Not CLI-configurable.
REVIEWED_OUTPUT_POLICY = None

def validate_output_path(output, policy):
    """Read-only preflight; tests supply invented temporary paths, not approval."""
    require(isinstance(policy,dict) and set(policy)=={'external_root','repository_roots'}, 'reviewed external evidence root missing')
    def clean(value):
        p=Path(value)
        require(p.is_absolute() and '..' not in p.parts and '.' not in p.parts,'absolute traversal-free path required')
        require(not any(':' in part for part in p.parts[1:]),'alternate stream/path syntax refused')
        return p
    root=clean(policy['external_root']); out=clean(output)
    repos=[clean(x) for x in policy['repository_roots']]
    require(repos,'repository exclusion boundaries missing')
    def within(p,r): return p==r or r in p.parents
    def safe_existing(p):
        for item in reversed((p,*p.parents)):
            info=item.lstat()
            require(not stat.S_ISLNK(info.st_mode) and not (getattr(info,'st_file_attributes',0)&0x400),'symlink/reparse path refused')
            require(stat.S_ISDIR(info.st_mode),'non-directory ancestor')
    safe_existing(root)
    require(not any(within(root,r) for r in repos),'evidence root inside repository')
    require(out!=root and within(out,root),'output outside reviewed external root')
    require(not any(within(out,r) for r in repos),'output inside repository')
    require(not os.path.lexists(out),'output already exists')
    safe_existing(out.parent)
    resolved_root=root.resolve(strict=True); resolved_parent=out.parent.resolve(strict=True)
    require(within(resolved_parent,resolved_root),'resolved path escapes evidence root')
    for repo in repos:
        resolved_repo=repo.resolve(strict=True)
        require(not within(resolved_parent,resolved_repo),'resolved output inside repository')
    return out

def require(ok, message):
    if not ok: raise ValueError(message)

def sha(raw): return hashlib.sha256(raw).hexdigest()
def utc(): return dt.datetime.now(dt.timezone.utc).isoformat()

def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def bad(value): raise ValueError('nonfinite JSON constant: '+value)
    return json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs, parse_constant=bad)

def load_manifest(path):
    raw = Path(path).read_bytes()
    require(sha(raw) == MANIFEST_SHA256, 'reviewed manifest hash mismatch')
    m = strict_json(raw)
    require(m['method']=='GET' and m['approved_redirects']==[], 'method/redirect mismatch')
    require([(x['project'],x['url']) for x in m['requests']] == [(p,f'https://pypi.org/simple/{p}/') for p in PROJECTS], 'exact allowlist mismatch')
    require(all(m[k] is False for k in FLAGS), 'review flags changed')
    return m

def authorize_network(m,grant=None):
    # Historical request flags stay false. A separately hash-bound, run-scoped
    # grant is produced by admission.load_grant after all receipt/path checks.
    require(grant is not None and grant.get('scope')=='14_pypi_discovery_gets_only' and grant.get('receipt_sha256'), 'network access disabled: no reviewed authorization')
    require(all(m[k] is False for k in FLAGS),'historical manifest flags changed')

class Budget:
    def __init__(self, bounds, clock=time.monotonic):
        self.clock=clock; self.bounds=bounds; self.end=clock()+bounds['aggregate_wall_seconds']; self.total=0; self.calls=0
    def remaining(self):
        left=self.end-self.clock()
        if left<=0: raise TimeoutError('aggregate deadline exceeded')
        return min(self.bounds['socket_timeout_seconds'],left)
    def start(self):
        self.remaining(); self.calls+=1
        require(self.calls<=self.bounds['requests'],'request count exceeded')
    def account(self,n):
        self.total+=n
        require(self.total<=self.bounds['aggregate_body_bytes'],'aggregate body limit exceeded')
        self.remaining()

def allowed(m, method, url):
    return method==m['method']=='GET' and url in {x['url'] for x in m['requests']} and url in {f'https://pypi.org/simple/{p}/' for p in PROJECTS}

class WireResponse:
    def __init__(self, sock, url, budget):
        self.sock=sock; self.final_url=url; self.budget=budget
        raw=bytearray()
        while not raw.endswith(b'\r\n\r\n'):
            require(len(raw)<budget.bounds['headers_per_response_bytes'],'header limit exceeded')
            sock.settimeout(budget.remaining()); b=sock.recv(1); budget.remaining()
            require(b,'truncated HTTP headers'); raw.extend(b)
        lines=bytes(raw).decode('iso-8859-1').split('\r\n')
        match=re.fullmatch(r'HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?',lines[0])
        require(match is not None,'malformed HTTP status'); self.status=int(match[1]); self.headers=[]
        for line in lines[1:-2]:
            require(':' in line and not line.startswith((' ','\t')),'malformed/folded header')
            name,value=line.split(':',1)
            require(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) is not None,'invalid header name')
            require(all(ord(c)>=32 or c=='\t' for c in value),'invalid header value')
            self.headers.append((name,value.strip()))
    def read(self,n):
        self.sock.settimeout(self.budget.remaining()); b=self.sock.recv(n); self.budget.remaining(); return b
    def close(self): self.sock.close()

class TLSMetadataTransport:
    def __init__(self,m,grant=None):
        authorize_network(m,grant); self.m=m
    def open(self,method,url,headers,budget):
        require(allowed(self.m,method,url),'unapproved URL/method')
        # Exact pypi.org host, default OS CA verification; no environment proxy.
        u=urlsplit(url); context=ssl.create_default_context()
        require(context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED,'TLS verification disabled')
        plain=socket.create_connection(('pypi.org',443),timeout=budget.remaining())
        try:
            budget.remaining(); plain.settimeout(budget.remaining())
            sock=context.wrap_socket(plain,server_hostname='pypi.org')
        except BaseException:
            plain.close(); raise
        try:
            sock.settimeout(budget.remaining())
            request=(f'GET {u.path} HTTP/1.1\r\nHost: pypi.org\r\nAccept: {MEDIA}\r\nAccept-Encoding: identity\r\nConnection: close\r\nUser-Agent: pv2-metadata-review\r\n\r\n').encode('ascii')
            sock.sendall(request); budget.remaining()
            return WireResponse(sock,url,budget)
        except BaseException:
            sock.close(); raise

def validate_headers(response,url,bounds):
    require(response.final_url==url,'final URL mismatch')
    require(response.status==200,'unexpected HTTP status; redirects forbidden')
    h={}; total=0
    for key,value in response.headers:
        total+=len(key.encode('utf-8'))+len(value.encode('utf-8'))+4
        require(total<=bounds['headers_per_response_bytes'],'header limit exceeded')
        key=key.lower()
        require(key not in h,'duplicate HTTP header')
        h[key]=value
    require(re.fullmatch(re.escape(MEDIA)+r'(?:\s*;\s*charset=utf-8)?',h.get('content-type',''),re.I) is not None,'wrong content type')
    require(h.get('content-encoding','identity').lower()=='identity','content encoding refused')
    require('transfer-encoding' not in h,'transfer encoding unsupported; no fallback')
    size=None
    if 'content-length' in h:
        require(re.fullmatch(r'[0-9]+',h['content-length']) is not None,'invalid Content-Length')
        size=int(h['content-length'])
        require(size<=bounds['body_per_response_bytes'],'oversized Content-Length')
    return size

def parse_index(raw,project,cutoff):
    # Existing local packaging is used for standards parsing only. No pip,
    # vendored fallback, download or installation. Deployment version unapproved.
    import packaging
    from packaging.utils import canonicalize_name, parse_wheel_filename
    from packaging.version import Version
    from packaging.specifiers import SpecifierSet
    d=strict_json(raw)
    require(isinstance(d,dict),'JSON root must be object')
    require(isinstance(d.get('name'),str) and canonicalize_name(d['name'])==project,'project-name mismatch')
    api=d.get('meta',{}).get('api-version')
    # size and upload-time were added in Simple API 1.1 (PEP 700).
    require(isinstance(api,str) and re.fullmatch(r'1\.[1-4]',api) is not None,'unsupported Simple API version: require 1.1 through 1.4')
    files=d.get('files'); require(isinstance(files,list),'files must be list')
    seen=set(); versions=set(); gaps=[]; excluded=0; wheels=0
    for f in files:
        require(isinstance(f,dict),'file record must be object')
        filename=f.get('filename'); require(isinstance(filename,str) and filename,'invalid filename')
        require(filename not in seen,'duplicate artifact identity'); seen.add(filename)
        if not filename.endswith('.whl'): excluded+=1; continue
        name,version,build,tags=parse_wheel_filename(filename)
        require(name==project,'wheel project mismatch')
        require(tags,'wheel tags missing')
        url=f.get('url'); require(isinstance(url,str),'artifact URL missing')
        u=urlsplit(url)
        require(u.scheme=='https' and u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.port in (None,443),'invalid artifact URL')
        require(unquote(u.path.rsplit('/',1)[-1])==filename,'artifact filename/URL mismatch')
        digest=f.get('hashes',{}).get('sha256')
        require(isinstance(digest,str) and re.fullmatch('[0-9a-f]{64}',digest),'missing/invalid artifact hash')
        size=f.get('size')
        require(type(size) is int and size>0,'missing/invalid publisher-declared artifact size')
        y=f.get('yanked',False); require(type(y) is bool or isinstance(y,str),'invalid yanked value')
        rp=f.get('requires-python')
        require(rp is None or isinstance(rp,str),'invalid Requires-Python'); SpecifierSet(rp or '')
        uploaded=f.get('upload-time')
        gap=[]
        if uploaded is None: gap.append('upload-time missing')
        else:
            require(isinstance(uploaded,str) and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z',uploaded) is not None,
                    'invalid upload-time: require UTC Z with optional 1-6 fractional digits; no offsets')
            # strptime additionally rejects invalid calendar dates and times.
            fmt='%Y-%m-%dT%H:%M:%S.%fZ' if '.' in uploaded else '%Y-%m-%dT%H:%M:%SZ'
            timestamp=dt.datetime.strptime(uploaded,fmt).replace(tzinfo=dt.timezone.utc)
            if timestamp>dt.datetime.fromisoformat(cutoff.replace('Z','+00:00')): gap.append('after release cutoff')
        cm=f.get('core-metadata',f.get('dist-info-metadata'))
        if not isinstance(cm,dict) or not isinstance(cm.get('sha256'),str) or not re.fullmatch('[0-9a-f]{64}',cm['sha256']): gap.append('hash-bound sidecar metadata missing')
        if y is True or isinstance(y,str): gap.append('yanked')
        if version.is_prerelease or version.is_devrelease: gap.append('prerelease/development')
        if version.local is not None: gap.append('local version needs review')
        if rp and not SpecifierSet(rp).contains('3.12.15',prereleases=False): gap.append('Requires-Python excludes target')
        if rp is None: gap.append('Requires-Python missing')
        # All files remain unselected: tag/platform, support/security and
        # whole-graph constraints need independent review.
        versions.add(version); wheels+=1
        if gap: gaps.append({'filename':filename,'reasons':gap})
    return {'project':project,'display_versions':[str(v) for v in sorted(versions)],
            'version_order':'parsed PEP 440; presentation only','packaging_version':packaging.__version__,
            'wheel_records':wheels,'nonwheel_records_excluded':excluded,'gaps':gaps,
            'support_security_and_target_tags':'unresolved','selected_versions':None,'artifact_bytes_verified':False}

class Evidence:
    def __init__(self,path):
        self.path=Path(path); self.path.mkdir(mode=0o700,exist_ok=False); self.written=0
    def account(self,n):
        require(self.written+n<=128*1024**2-65536,'evidence output reservation exceeded')
        self.written+=n
    def write(self,name,obj):
        raw=(json.dumps(obj,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
        require(len(raw)<=16*1024**2,'evidence JSON cap exceeded')
        self.account(len(raw))
        with self.open_file(name) as f: f.write(raw); f.flush(); os.fsync(f.fileno())
    def open_file(self,name):
        require(Path(name).name==name and name not in ('.','..'),'evidence filename invalid')
        fd=os.open(self.path/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        return os.fdopen(fd,'wb')

def collect(m,transport,evidence,clock=time.monotonic,grant=None):
    """Core for injected transport tests; production transport has its own gate."""
    budget=Budget(m['bounds'],clock); errors=[]
    evidence.write('started.json',{'status':'incomplete','script_sha256':sha(Path(__file__).read_bytes()),'manifest':m,'utc':utc(),'network_authorized':False,'execution_approved':False,'scoped_metadata_admission':grant})
    for index,request in enumerate(m['requests']):
        url=request['url']; record={'project':request['project'],'url':url,'method':m['method'],'utc':utc(),'request_headers':m['headers'],'status':'incomplete'}
        prefix=f'{index:02d}'; response=None; body=bytearray(); start=clock()
        evidence.write(prefix+'-started.json',record)
        try:
            require(allowed(m,m['method'],url),'unapproved URL/method')
            budget.start(); response=transport.open(m['method'],url,m['headers'],budget); budget.remaining()
            record.update(http_status=response.status,final_url=response.final_url,
                          response_headers=[(k,v[:2048]) for k,v in response.headers if k.lower() in ('content-type','content-length','content-encoding','transfer-encoding','location','etag','last-modified')][:32])
            expected=validate_headers(response,url,m['bounds'])
            if expected is not None: require(expected<=m['bounds']['aggregate_body_bytes']-budget.total,'declared size exceeds remaining aggregate limit')
            with evidence.open_file(prefix+'.body') as f:
                while True:
                    budget.remaining()
                    room=min(m['bounds']['body_per_response_bytes']-len(body),m['bounds']['aggregate_body_bytes']-budget.total)
                    chunk=response.read(min(16384,room+1))
                    # Preserve only cap-compliant bytes; record overflow without
                    # retaining the sentinel beyond the permitted body bound.
                    accepted=chunk[:max(0,room)]; evidence.account(len(accepted)); body.extend(accepted); f.write(accepted); f.flush()
                    budget.account(len(accepted))
                    require(len(chunk)<=room,'response or aggregate body limit exceeded')
                    if not chunk: break
                os.fsync(f.fileno())
            require(expected is None or len(body)==expected,'Content-Length mismatch')
            result=parse_index(bytes(body),request['project'],m['release_upload_cutoff_utc'])
            budget.remaining(); evidence.write(prefix+'-index.json',result); budget.remaining()
            record['status']='metadata_validated_not_approved'
        except Exception as exc:
            record.update(status='failed',error=f'{type(exc).__name__}: {str(exc)[:4096]}'); errors.append(record['error'])
        finally:
            if response is not None:
                try: response.close()
                except Exception as exc:
                    record['close_error']=str(exc)[:1024]; record['status']='failed'; errors.append('response close failed')
            record.update(received_retained_bytes=len(body),response_sha256=sha(body),hash_scope='retained body only; may be partial on failure',elapsed_seconds=clock()-start)
            evidence.write(prefix+'-receipt.json',record)
        if errors: break  # fail closed; no retries or further requests
    report={'status':'failed' if errors else 'metadata_collected_not_approved','errors':errors,'requests_attempted':budget.calls,'retained_body_bytes':budget.total,'network_authorized':False,'execution_approved':False,'security_approved':False,'pilot_execution_authorized':False,'dependency_closure_complete':False,'artifact_bytes_verified':False}
    evidence.write('report.json',report); return report

def supervised(manifest,output,popen=None,grant=None,receipt=None,receipt_hash=None,runtime_path=None,runtime_hash=None):
    popen=subprocess.Popen if popen is None else popen
    m=load_manifest(manifest); authorize_network(m,grant)
    output=validate_output_path(output,grant['output_policy'] if grant else REVIEWED_OUTPUT_POLICY)
    evidence=Evidence(output)
    evidence.write('parent-started.json',{'status':'incomplete','execution_approved':False,'scoped_metadata_admission':grant})
    proc=None; error=None; code=None; termination_confirmed=False; capture=None
    try:
        args=[sys.executable,'-I','-B',str(Path(__file__).resolve()),'--manifest',str(Path(manifest).resolve()),'--output',str(Path(output).resolve()),'--worker']
        if receipt: args += ['--authorization',str(Path(receipt).resolve()),'--authorization-sha256',receipt_hash]
        if runtime_path: args += ['--runtime-acceptance',str(Path(runtime_path).resolve()),'--runtime-acceptance-sha256',runtime_hash]
        proc=popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        if getattr(proc,'stderr',None) is not None:
            from worker_diagnostics import Capture
            capture=Capture(proc.stderr)
        code=proc.wait(timeout=m['bounds']['aggregate_wall_seconds']); termination_confirmed=True
    except Exception as exc:
        error='timeout' if isinstance(exc,subprocess.TimeoutExpired) else 'process_failure'
        if proc is not None:
            try:
                proc.kill(); proc.wait(timeout=5); termination_confirmed=True
            except Exception as cleanup:
                error+='; cleanup_failed'
    if capture is not None:evidence.write('worker-errors.json',capture.finish())
    evidence.write('parent-finished.json',{'exit_code':code,'error':error,'termination_confirmed':termination_confirmed,'execution_approved':False,'status':'failed' if error or code!=0 else 'worker_returned_not_approved'})
    return 1 if error or code!=0 else 0

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument('--manifest',type=Path,required=True); p.add_argument('--output',type=Path,required=True)
    p.add_argument('--worker',action='store_true')
    p.add_argument('--authorization',type=Path); p.add_argument('--authorization-sha256')
    p.add_argument('--runtime-acceptance',type=Path); p.add_argument('--runtime-acceptance-sha256')
    a=p.parse_args(argv); m=load_manifest(a.manifest)
    require(a.authorization is not None and a.authorization_sha256,'network access disabled: authorization receipt required')
    # Pin local import location; no current-directory or PYTHONPATH resolution.
    sys.path[:]=[str(Path(__file__).resolve().parent)]+[x for x in sys.path if x and x!=str(Path.cwd())]
    import admission
    grant=admission.load_grant(a.manifest,a.authorization,a.authorization_sha256,Path(__file__).parent,a.output,worker=a.worker,runtime_path=a.runtime_acceptance,runtime_hash=a.runtime_acceptance_sha256)
    authorize_network(m,grant)
    os.umask(0o077)
    if a.worker:
        # Reserved worker child directory, exclusive creation; parent evidence
        # survives child timeout. Direct worker invocation has the same gate.
        target=validate_output_path(a.output/'worker',grant['output_policy'])
        result=collect(m,TLSMetadataTransport(m,grant),Evidence(target),grant=grant)
        return 1 if result['status']=='failed' else 0
    return supervised(a.manifest,a.output,grant=grant,receipt=a.authorization,receipt_hash=a.authorization_sha256,runtime_path=a.runtime_acceptance,runtime_hash=a.runtime_acceptance_sha256)

def entry(argv=None):
    sys.path[:]=[str(Path(__file__).resolve().parent)]+[x for x in sys.path if x and x!=str(Path.cwd())]
    try:return main(argv)
    except Exception as exc:
        from worker_diagnostics import error_record
        print(json.dumps(error_record(exc),sort_keys=True),file=sys.stderr,flush=True)
        return 2

if __name__=='__main__':
    raise SystemExit(entry())
