"""Immutable four-request proposal contract, not network authorization."""
import hashlib
import json
from pathlib import Path

PROPOSAL_SHA256 = '3e698d6e50f6e03e8c27894a80822d0210d45ff1efad654920597f81b5aff0ba'
CANONICAL_SHA256 = '4af82ef69784572148375803dbd12698592e6260626c2162e47ad90984ee9d73'
SCOPE = '4_hash_bound_investigative_metadata_gets_only'
ROOT_CONSTRAINTS = {'filelock':'','typing-extensions':'>=4.10.0','setuptools':'>=77.0.3',
                   'sympy':'>=1.13.3','networkx':'>=2.5.1','jinja2':'','fsspec':'>=0.8.5',
                   'numpy':'>=1.24,<3','pillow':'>=5.3.0,!=8.3.*','pyyaml':'>=6,<7',
                   'pandas':'>=2,<3','torch':'==2.13.0',
                   'torchvision':'==0.28.0+cpu','opencv-python':'','markupsafe':'>=2.0','mpmath':'>=1.1.0,<1.4'}

def _runtime_view(proposal):
    # Called only after exact raw SHA validation. No scope or URL synthesis.
    proposal['bounded_transport'] = proposal['transport'].copy()
    proposal['release_upload_cutoff_utc'] = proposal['cutoff']
    proposal['authorization'] = {'execution_authorized': False}
    for request in proposal['requests']:
        request.setdefault('artifact_bytes_verified', False)
    return proposal


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
    return validate_proposal(_runtime_view(strict_json(raw)))

def known_nodes(proposal):
    validate_proposal(proposal)
    # Alternatives are not jointly installed and must not overwrite each other.
    return {'torch':'2.13.0+cpu','torchvision':'0.28.0+cpu',
            'jinja2':'3.1.6','sympy':'1.14.0','filelock':'4.0.10',
            'fsspec':'2026.7.0','typing-extensions':'4.16.0','networkx':'3.7',
            'setuptools':'84.0.0','numpy':'2.5.3','pillow':'12.3.0'}
