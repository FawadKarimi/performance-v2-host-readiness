"""Immutable seven-request proposal contract, not network authorization."""
import hashlib
import json
from pathlib import Path

PROPOSAL_SHA256 = 'ad7c7e726ba0c5df2ecd74c601f9036570c5bbc92206f7e98dda230d6054fe9b'
CANONICAL_SHA256 = '222345f191eee71a76886cbb32a75d30ba02e32a0a3f3f177f47d0c031f05524'
SCOPE = '7_hash_bound_metadata_gets_only'
ROOT_CONSTRAINTS = {'filelock':'','typing-extensions':'>=4.10.0','setuptools':'>=77.0.3',
                   'sympy':'>=1.13.3','networkx':'>=2.5.1','jinja2':'','fsspec':'>=0.8.5',
                   'numpy':'>=1.24,<3','pillow':'>=5.3.0,!=8.3.*','pyyaml':'>=6,<7',
                   'pandas':'>=2,<3','torch':'==2.13.0',
                   'torchvision':'==0.28.0+cpu','opencv-python':''}

def validate_proposal(proposal):
    try:
        canonical=json.dumps(proposal,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
    except (TypeError,ValueError,UnicodeError) as exc:
        raise ValueError('proposal_structure_rejected') from exc
    if hashlib.sha256(canonical).hexdigest()!=CANONICAL_SHA256:
        raise ValueError('proposal_content_changed')
    return proposal

def load_proposal(path):
    with Path(path).open('rb') as f: raw=f.read(32769)
    if len(raw)>32768 or hashlib.sha256(raw).hexdigest()!=PROPOSAL_SHA256:
        raise ValueError('proposal_byte_hash_mismatch')
    from collector import strict_json
    return validate_proposal(strict_json(raw))

def known_nodes(proposal):
    validate_proposal(proposal)
    return {'torch':'2.13.0+cpu','torchvision':'0.28.0+cpu',
            **{r['project']:r['version'] for r in proposal['requests']}}
