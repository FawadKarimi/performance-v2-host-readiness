"""Fresh fail-closed Linux ACL/mount observations; no repairs."""
import json,os,re,stat,subprocess,time
from pathlib import Path

def need(ok,code):
    if not ok:raise ValueError(code)

def basic_acl(text):
    lines=[s.strip() for s in text.splitlines() if s.strip() and not s.startswith('#')]
    need(len(lines)==3 and set(s.split('::')[0] for s in lines)=={'user','group','other'},'extended_or_default_acl_rejected')
    need(all(re.fullmatch(r'(user|group|other)::[r-][w-][x-]',s) for s in lines),'acl_format')
    need(all('w' not in s.split('::')[1] for s in lines if not s.startswith('user::')),'acl_write_permission')
    return lines

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

def observe(root,workspace,deadline_seconds=12,command=subprocess.run):
    end=time.monotonic()+deadline_seconds;uid=os.getuid();rows=[];seen=set()
    mounts=Path('/proc/self/mountinfo').read_text()
    need(len(mounts)<=1048576,'mountinfo_size')
    for target in (Path(root),Path(workspace)):
        for p in (target,*target.parents):
            if str(p) in seen:continue
            seen.add(str(p));before=p.lstat()
            need(stat.S_ISDIR(before.st_mode) and not p.is_symlink(),'path_not_directory')
            need(before.st_uid in (0,uid) and before.st_mode&0o022==0,'path_owner_mode')
            left=end-time.monotonic();need(left>0,'output_check_deadline')
            # No installation/fallback when getfacl is absent. Numeric output;
            # inherited/default/named ACLs are rejected, not silently ignored.
            r=command(['/usr/bin/getfacl','--absolute-names','--numeric','--omit-header','--',str(p)],
                      capture_output=True,timeout=left,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            need(time.monotonic()<end,'output_check_deadline')
            need(r.returncode==0 and len(r.stdout)<=16384 and len(r.stderr)<=16384,'acl_unavailable')
            acl=basic_acl(r.stdout.decode('ascii'))
            after=p.lstat();need((before.st_dev,before.st_ino,before.st_mode,before.st_uid)==(after.st_dev,after.st_ino,after.st_mode,after.st_uid),'path_changed')
            rows.append({'path':str(p),'uid':before.st_uid,'mode':oct(stat.S_IMODE(before.st_mode)),
                         'inode':before.st_ino,'device':before.st_dev,'acl':acl,
                         'mount':mount_for(p,mounts,before.st_dev)})
    need(Path(root).stat().st_uid==uid,'output_root_uid')
    return {'paths':rows,'same_uid_isolation':False,'acl_mount_checked':True,
            'trust_requirement':'owner_accepts_trusted_ephemeral_job_no_hostile_same_uid'}
