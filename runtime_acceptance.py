"""Metadata-only runtime gate. No installation or automatic acceptance."""
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import platform
import sys

class RuntimeRejected(ValueError):
    def __init__(self, code):
        self.code=code
        super().__init__(code)

def require(ok, code):
    if not ok: raise RuntimeRejected(code)

def observed_identity():
    """Hash interpreter and complete installed parser tree before parser import.

    Ignore only bytecode caches; reject symlinks. Paths identify deployment and
    hashes bind bytes, not their safety. Native/stdlib/image clearance remains
    a separate acceptance prerequisite, not inferred from these hashes.
    """
    spec=importlib.util.find_spec('packaging')
    require(spec is not None and spec.origin is not None,'parser_missing')
    root=Path(spec.origin).parent
    require(not root.is_symlink(),'parser_layout_rejected')
    files={}
    for p in sorted(root.rglob('*')):
        require(not p.is_symlink(),'parser_layout_rejected')
        if '__pycache__' in p.parts: continue
        if p.is_file(): files[p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
    require('__init__.py' in files,'parser_layout_rejected')
    canonical=json.dumps(files,sort_keys=True,separators=(',',':')).encode()
    executable=Path(sys.executable).resolve(strict=True)
    return {'python':{'implementation':platform.python_implementation(),
                     'version':platform.python_version(),'cache_tag':sys.implementation.cache_tag,
                     'executable_path':str(executable),'executable_sha256':hashlib.sha256(executable.read_bytes()).hexdigest()},
            'parser':{'name':'packaging','version':importlib.metadata.version('packaging'),
                      'root':str(root.resolve(strict=True)),'tree_sha256':hashlib.sha256(canonical).hexdigest(),
                      'files':files}}

def verify_record(path, expected_hash, observe=None):
    with Path(path).open('rb') as f: raw=f.read(1048577)
    require(len(raw)<=1048576,'runtime_record_oversized')
    require(hashlib.sha256(raw).hexdigest()==expected_hash,'runtime_record_hash_mismatch')
    def pairs(items):
        d={}
        for k,v in items:
            require(k not in d,'runtime_record_duplicate_key');d[k]=v
        return d
    r=json.loads(raw,object_pairs_hook=pairs)
    require(r.get('schema')=='metadata_runtime_acceptance_v1','runtime_record_schema')
    require(r.get('scope')=='public_pypi_metadata_only','runtime_scope_rejected')
    require(r.get('metadata_runtime_accepted') is True,'runtime_not_accepted')
    require(all(r.get(k) is False for k in ('training_authorized','research_execution_authorized','artifact_acquisition_authorized','pilot_execution_authorized')),'runtime_scope_rejected')
    require(isinstance(r.get('review_reference'),str) and bool(r['review_reference']),'runtime_review_missing')
    actual=(observed_identity if observe is None else observe)()
    for part in ('python','parser'):
        require(isinstance(r.get(part),dict) and r[part]==actual[part],part+'_identity_mismatch')
    return {'record_sha256':expected_hash,'scope':r['scope'],'review_reference':r['review_reference'],'python':actual['python'],
            'parser':actual['parser'],'metadata_runtime_accepted':True,
            'training_authorized':False,'research_execution_authorized':False,
            'artifact_acquisition_authorized':False,'pilot_execution_authorized':False}
