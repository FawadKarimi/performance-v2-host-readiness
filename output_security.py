"""Fresh fail-closed Linux ACL/mount observations; no repairs."""
import itertools,json,os,re,stat,subprocess,time
from pathlib import Path

def need(ok,code):
    if not ok:raise ValueError(code)

def basic_acl(text):
    lines=[s.strip() for s in text.splitlines() if s.strip() and not s.startswith('#')]
    need(len(lines)==3 and set(s.split('::')[0] for s in lines)=={'user','group','other'},'extended_or_default_acl_rejected')
    need(all(re.fullmatch(r'(user|group|other)::[r-][w-][x-]',s) for s in lines),'acl_format')
    need(all('w' not in s.split('::')[1] for s in lines if not s.startswith('user::')),'acl_write_permission')
    return lines

def reviewed_home_acl(text,path,depth,before,accepted=False):
    """One explicit inheritance disposition; basic access policy is unchanged."""
    try:return basic_acl(text),None
    except ValueError as exc:
        if exc.args!=('extended_or_default_acl_rejected',):raise
    uid=os.getuid();effective_uid=os.geteuid()
    need(accepted is True and Path(path)==Path('/home') and depth>0,
         'extended_or_default_acl_rejected')
    need(uid==effective_uid and uid>0 and before.st_uid==before.st_gid==0
         and stat.S_IMODE(before.st_mode)==0o755,'home_acl_identity_rejected')
    # No lexical normalization, ignored comments, duplicate rows or effective
    # annotations. Fresh UID comparison, never a hard-coded runner UID.
    lines=[s.strip() for s in text.splitlines() if s.strip()]
    access=['user::rwx','group::r-x','other::r-x']
    defaults=['default:user::rwx',f'default:user:{uid}:rwx',
              'default:group::r-x','default:mask::rwx','default:other::r-x']
    need(len(lines)==8 and set(lines)==set(access+defaults),'home_acl_pattern_rejected')
    basic_acl('\n'.join(access))
    return access,{'policy':'exact_home_default_acl_v1','path':'/home',
                  'real_uid':uid,'effective_uid':effective_uid,'default_entries':defaults,
                  'interpretation':'inheritance_only_current_access_remains_basic'}

ACL_CODES=frozenset(('extended_or_default_acl_rejected','acl_format','acl_write_permission',
                     'home_acl_identity_rejected','home_acl_pattern_rejected'))
ACL_ENTRY_LIMIT=16
ACL_EVIDENCE_LIMIT=4096

class ACLRejected(ValueError):
    """Rejected policy check with a bounded diagnostic, never raw command text."""
    def __init__(self,code,observation):
        super().__init__(code)
        self.observation=observation

def acl_diagnostic(raw,anchor,depth,before):
    """Projection for diagnosis only; never used to accept an ACL."""
    entries=[];unparsed=omitted=comments=nonblank=0
    for line in raw.splitlines():
        line=line.strip()
        if not line:continue
        nonblank+=1
        if line.startswith(b'#'):
            comments+=1;continue
        if len(line)>256:
            unparsed+=1;continue
        match=re.fullmatch(rb'(default:)?(user|group|other|mask):([0-9]{0,10}):([r-][w-][x-])(?:[ \t]+#effective:([r-][w-][x-]))?',line)
        if match is None:
            unparsed+=1;continue
        default,kind,qualifier,permissions,effective=match.groups()
        if (qualifier and (kind not in (b'user',b'group') or int(qualifier)>4294967295)):
            unparsed+=1;continue
        entry={'default':bool(default),'kind':kind.decode('ascii'),
               'qualifier':int(qualifier) if qualifier else None,
               'permissions':permissions.decode('ascii'),
               'reported_effective':effective.decode('ascii') if effective else None}
        if len(entries)<ACL_ENTRY_LIMIT:entries.append(entry)
        else:omitted+=1
    return {'schema':'rejected_acl_observation_v1','anchor':anchor,'ancestor_depth':depth,
            'uid':before.st_uid,'gid':before.st_gid,'mode':stat.S_IMODE(before.st_mode),
            'device':before.st_dev,'inode':before.st_ino,'path_stable':True,
            'input_bytes':len(raw),'nonblank_lines':nonblank,'comment_lines':comments,
            'unparsed_lines':unparsed,'omitted_entries':omitted,'entries':entries,
            'policy_accepted':False,'interpretation':'diagnostic_only_not_security_clearance'}

def safe_acl_diagnostic(value):
    """Revalidate the closed projection before persistence; discard forged fields."""
    if type(value) is not dict:return None
    keys={'schema','anchor','ancestor_depth','uid','gid','mode','device','inode',
          'path_stable','input_bytes','nonblank_lines','comment_lines',
          'unparsed_lines','omitted_entries','entries','policy_accepted','interpretation'}
    if set(value)!=keys:return None
    if value['schema']!='rejected_acl_observation_v1' or value['anchor'] not in ('runner_temp','workspace'):return None
    limits={'ancestor_depth':256,'uid':4294967295,'gid':4294967295,'mode':4095,
            'device':2**64-1,'inode':2**64-1,'input_bytes':16384,
            'nonblank_lines':16384,'comment_lines':16384,'unparsed_lines':16384,'omitted_entries':16384}
    if any(type(value[k]) is not int or not 0<=value[k]<=limit for k,limit in limits.items()):return None
    if value['path_stable'] is not True or value['policy_accepted'] is not False:return None
    if value['interpretation']!='diagnostic_only_not_security_clearance':return None
    if type(value['entries']) is not list or len(value['entries'])>ACL_ENTRY_LIMIT:return None
    entries=[]
    for row in value['entries']:
        if type(row) is not dict or set(row)!={'default','kind','qualifier','permissions','reported_effective'}:return None
        if type(row['default']) is not bool or row['kind'] not in ('user','group','other','mask'):return None
        q=row['qualifier']
        if q is not None and (type(q) is not int or not 0<=q<=4294967295 or row['kind'] not in ('user','group')):return None
        if type(row['permissions']) is not str or re.fullmatch('[r-][w-][x-]',row['permissions']) is None:return None
        effective=row['reported_effective']
        if effective is not None and (type(effective) is not str or re.fullmatch('[r-][w-][x-]',effective) is None):return None
        entries.append(dict(row))
    if value['nonblank_lines']!=value['comment_lines']+value['unparsed_lines']+value['omitted_entries']+len(entries):return None
    result=dict(value);result['entries']=entries
    if len(json.dumps(result,sort_keys=True).encode('ascii'))>ACL_EVIDENCE_LIMIT:return None
    return result

def mount_for(path,text,device):
    matches=[]
    def decode(s):
        return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),s)
    for line in text.splitlines():
        left,right=line.split(' - ',1);a=left.split();b=right.split()
        point=Path(decode(a[4]));p=Path(path)
        if point==p or point in p.parents:matches.append((len(point.parts),a,b,point))
    need(bool(matches),'mount_missing')
    longest=max(m[0] for m in matches);selected=[m for m in matches if m[0]==longest]
    need(len(selected)==1,'mount_ambiguous')
    _,a,b,point=selected[0]
    need(a[2]==f'{os.major(device)}:{os.minor(device)}','mount_device_mismatch')
    need(b[0] in ('ext4','xfs'),'mount_filesystem_not_reviewed')
    need('rw' in a[5].split(',') and 'rw' in b[2].split(','),'mount_read_only')
    return {'mountpoint':str(point),'mount_id':a[0],'device':a[2],'filesystem':b[0],
            'options':a[5].split(','),'super_options':b[2].split(','),'optional_fields':a[6:]}

def observe(root,workspace,deadline_seconds=12,command=subprocess.run,allow_home_default_acl=False):
    end=time.monotonic()+deadline_seconds;uid=os.getuid();rows=[];seen=set()
    mounts=Path('/proc/self/mountinfo').read_text()
    need(len(mounts)<=1048576,'mountinfo_size')
    for anchor,target in (('runner_temp',Path(root)),('workspace',Path(workspace))):
        for depth,p in enumerate((target,*target.parents)):
            if str(p) in seen:continue
            seen.add(str(p));before=p.lstat()
            need(stat.S_ISDIR(before.st_mode) and not p.is_symlink(),'path_not_directory')
            need(before.st_uid in (0,uid) and before.st_mode&0o022==0,'path_owner_mode')
            left=end-time.monotonic();need(left>0,'output_check_deadline')
            # No installation/fallback when getfacl is absent. Numeric output;
            # Default/named ACLs remain rejected except for the explicit exact
            # /home inheritance disposition. No host ACL is changed.
            r=command(['/usr/bin/getfacl','--absolute-names','--numeric','--omit-header','--',str(p)],
                      capture_output=True,timeout=left,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            need(time.monotonic()<end,'output_check_deadline')
            need(r.returncode==0 and len(r.stdout)<=16384 and len(r.stderr)<=16384,'acl_unavailable')
            rejection=None
            exception=None
            try:acl,exception=reviewed_home_acl(r.stdout.decode('ascii'),p,depth,before,allow_home_default_acl)
            except UnicodeDecodeError:rejection='acl_format'
            except ValueError as exc:
                if len(exc.args)!=1 or exc.args[0] not in ACL_CODES:raise
                rejection=exc.args[0]
            after=p.lstat();need((before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid)==(after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid),'path_changed')
            if rejection:
                observation=safe_acl_diagnostic(acl_diagnostic(r.stdout,anchor,depth,before))
                raise ACLRejected(rejection,observation)
            row={'path':str(p),'uid':before.st_uid,'mode':oct(stat.S_IMODE(before.st_mode)),
                         'inode':before.st_ino,'device':before.st_dev,'acl':acl,
                         'mount':mount_for(p,mounts,before.st_dev)}
            if exception is not None:row['reviewed_default_acl_exception']=exception
            rows.append(row)
    need(Path(root).stat().st_uid==uid,'output_root_uid')
    return {'paths':rows,'same_uid_isolation':False,'acl_mount_checked':True,
            'trust_requirement':'owner_accepts_trusted_ephemeral_job_no_hostile_same_uid'}

def verify_created(path,fd=None,command=subprocess.run,deadline_seconds=3):
    """Actual evidence object, never the ancestor exception; no repairs."""
    path=Path(path);before=path.lstat();uid=os.getuid()
    is_dir=stat.S_ISDIR(before.st_mode);is_file=stat.S_ISREG(before.st_mode)
    need(uid==os.geteuid() and before.st_uid==uid and (is_dir or is_file)
         and stat.S_IMODE(before.st_mode)==(0o700 if is_dir else 0o600),
         'created_evidence_identity_rejected')
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink)
    if fd is not None:need(identity(os.fstat(fd))==identity(before),'created_evidence_changed')
    if is_file:need(before.st_nlink==1,'created_evidence_identity_rejected')
    end=time.monotonic()+deadline_seconds
    r=command(['/usr/bin/getfacl','--absolute-names','--numeric','--omit-header','--',str(path)],
              capture_output=True,timeout=deadline_seconds,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    need(time.monotonic()<end and r.returncode==0 and len(r.stdout)<=16384
         and len(r.stderr)<=16384,'acl_unavailable')
    try:acl=basic_acl(r.stdout.decode('ascii'))
    except (UnicodeDecodeError,ValueError):raise ValueError('created_evidence_acl_rejected') from None
    expected={'user::rwx','group::---','other::---'} if is_dir else {'user::rw-','group::---','other::---'}
    need(set(acl)==expected,'created_evidence_acl_rejected')
    after=path.lstat();need(identity(before)==identity(after),'created_evidence_changed')
    if fd is not None:need(identity(os.fstat(fd))==identity(after),'created_evidence_changed')
    return {'path':str(path),'uid':uid,'mode':oct(stat.S_IMODE(before.st_mode)),
            'inode':before.st_ino,'device':before.st_dev,'acl':acl,
            'default_acl_present':False,'path_stable':True}

def verify_evidence_folder(folder):
    folder=Path(folder)
    end=time.monotonic()+12
    def check(path):
        left=end-time.monotonic();need(left>0,'output_check_deadline')
        row=verify_created(path,deadline_seconds=min(3,left))
        need(time.monotonic()<end,'output_check_deadline')
        return row
    rows=[check(folder)]
    children=sorted(itertools.islice(folder.iterdir(),17))
    need(len(children)<=16,'created_evidence_count_rejected')
    for path in children:
        need(stat.S_ISREG(path.lstat().st_mode),'created_evidence_identity_rejected')
        rows.append(check(path))
    return rows
