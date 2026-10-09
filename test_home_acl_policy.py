"""Offline exact-ACL disposition and pre-request evidence checks; OS mocked."""
import copy,datetime as dt,json,os,stat,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch,Mock
import collector as c
import external_review as e
import output_security as fs
import admission
import test_collector as fixtures
import test_external_review as external_fixtures
setUpModule=fixtures.setUpModule
tearDownModule=fixtures.tearDownModule

ACCESS='user::rwx\ngroup::r-x\nother::r-x\n'
HOME=ACCESS+'default:user::rwx\ndefault:user:1001:rwx\ndefault:group::r-x\ndefault:mask::rwx\ndefault:other::r-x\n'

def info(uid=0,gid=0,mode=0o755,inode=10):
    return types.SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=stat.S_IFDIR|mode,
                                 st_dev=1,st_ino=inode,st_nlink=1)
def response(text):return types.SimpleNamespace(returncode=0,stdout=text.encode(),stderr=b'')

class Tests(unittest.TestCase):
    def home(self,text=HOME,path='/home',depth=3,before=None,accepted=True,uid=1001,euid=1001):
        with patch.object(fs.os,'getuid',return_value=uid),patch.object(fs.os,'geteuid',return_value=euid):
            return fs.reviewed_home_acl(text,path,depth,before or info(),accepted)
    def test_basic_policy_unchanged_and_disposition_off_by_default(self):
        self.assertEqual(fs.basic_acl(ACCESS),ACCESS.splitlines())
        with self.assertRaisesRegex(ValueError,'extended_or_default'):fs.basic_acl(HOME)
        for accepted in (False,None,1,'true'):
            with self.subTest(accepted=accepted),self.assertRaisesRegex(ValueError,'extended_or_default'):
                self.home(accepted=accepted)
        template=json.loads((Path(__file__).parent/'external-review-TEMPLATE.json').read_text())
        self.assertIs(template['home_default_acl_disposition_accepted'],False)
    def test_exact_observed_pattern_returns_explicit_record_with_fresh_uid(self):
        access,record=self.home()
        self.assertEqual(access,ACCESS.splitlines());self.assertEqual(record['real_uid'],1001)
        self.assertEqual(record['policy'],'exact_home_default_acl_v1')
        _,record=self.home(HOME.replace('1001','2002'),uid=2002,euid=2002)
        self.assertEqual(record['effective_uid'],2002)
    def test_foreign_named_user_or_group_and_extra_access_rejected(self):
        for text in (HOME.replace('1001','1002'),HOME+'default:group:1001:rwx\n',
                     HOME+'user:1001:rwx\n',HOME+'mask::rwx\n'):
            with self.subTest(text=text),self.assertRaisesRegex(ValueError,'home_acl_pattern'):self.home(text)
    def test_changed_identity_or_privileged_uid_rejected(self):
        for kw in ({'uid':0,'euid':0},{'euid':1002},{'before':info(uid=1001)},
                   {'before':info(gid=1001)},{'before':info(mode=0o775)},
                   {'before':info(mode=0o1755)}):
            with self.subTest(kw=kw),self.assertRaisesRegex(ValueError,'home_acl_identity'):self.home(**kw)
    def test_exact_location_not_evidence_root_or_normalized_alias(self):
        for kw in ({'path':'/home/runner'},{'path':'/other'},{'path':'/x/../home'},{'depth':0}):
            with self.subTest(kw=kw),self.assertRaisesRegex(ValueError,'extended_or_default'):self.home(**kw)
    def test_writable_basic_access_or_default_pattern_rejected(self):
        for text in (HOME.replace('group::r-x','group::rwx',1),HOME.replace('other::r-x','other::rwx',1),
                     HOME.replace('default:other::r-x','default:other::rwx'),HOME.replace('default:mask::rwx','default:mask::r-x')):
            with self.subTest(text=text),self.assertRaises(ValueError):self.home(text)
    def test_duplicates_comments_effective_annotations_and_truncation_rejected(self):
        for text in (HOME+'default:mask::rwx\n',HOME+'#ignored\n',
                     HOME.replace('1001:rwx','1001:rwx #effective:r-x'),
                     HOME.replace('default:other::r-x\n',''),HOME+'malformed\n'):
            with self.subTest(text=text),self.assertRaisesRegex(ValueError,'home_acl_pattern'):self.home(text)
    def test_observe_records_exception_and_detects_replacement_before_return(self):
        def command(args,**kwargs):return response(HOME if args[-1]=='/home' else ACCESS)
        def fake_info(p):return info(uid=1001 if str(p)=='/home/runner' else 0)
        with patch.object(Path,'read_text',return_value=''),patch.object(Path,'lstat',autospec=True,side_effect=fake_info),\
             patch.object(Path,'stat',autospec=True,side_effect=fake_info),patch.object(Path,'is_symlink',return_value=False),\
             patch.object(fs.os,'getuid',return_value=1001),patch.object(fs.os,'geteuid',return_value=1001),\
             patch.object(fs,'mount_for',return_value={}):
            result=fs.observe('/home/runner','/home/runner',command=command,allow_home_default_acl=True)
        row=next(row for row in result['paths'] if row['path']=='/home')
        self.assertIn('reviewed_default_acl_exception',row)
        with patch.object(Path,'read_text',return_value=''),patch.object(Path,'lstat',side_effect=[info(),info(inode=11)]),\
             patch.object(Path,'is_symlink',return_value=False),patch.object(fs.os,'getuid',return_value=1001),\
             patch.object(fs.os,'geteuid',return_value=1001):
            with self.assertRaisesRegex(ValueError,'path_changed'):
                fs.observe('/home/runner','/home/runner',command=lambda *a,**k:response(ACCESS),allow_home_default_acl=True)
    def test_actual_created_directory_and_fd_checked_with_strict_acl(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'evidence';path.mkdir(mode=0o700)
            result=fs.verify_created(path,command=lambda *a,**k:response('user::rwx\ngroup::---\nother::---\n'))
            self.assertIs(result['default_acl_present'],False)
            file=path/'a.json';fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            try:
                result=fs.verify_created(file,fd=fd,command=lambda *a,**k:response('user::rw-\ngroup::---\nother::---\n'))
                self.assertEqual(result['mode'],'0o600')
            finally:os.close(fd)
    def test_inherited_named_default_or_nonprivate_created_acl_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'evidence';path.mkdir(mode=0o700)
            for text in ('user::rwx\ngroup::---\nother::---\n'+HOME.split('default:',1)[1],
                         'user::rwx\ngroup::---\nother::---\nuser:1001:rwx\nmask::---\n',
                         'user::rwx\ngroup::r--\nother::---\n',HOME):
                with self.subTest(text=text),self.assertRaisesRegex(ValueError,'created_evidence_acl'):
                    fs.verify_created(path,command=lambda *a,**k:response(text))
    def test_created_symlink_mode_hardlink_replacement_and_fd_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'evidence';path.mkdir(mode=0o700)
            link=Path(td)/'link';link.symlink_to(path)
            with self.assertRaisesRegex(ValueError,'created_evidence_identity'):fs.verify_created(link)
            file=path/'a';fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            try:
                with self.assertRaisesRegex(ValueError,'created_evidence_changed'):fs.verify_created(path,fd=fd)
                os.link(file,path/'hardlink')
                with self.assertRaisesRegex(ValueError,'created_evidence_identity'):fs.verify_created(file,fd=fd)
            finally:os.close(fd)
            def replaced(*args,**kwargs):
                path.rename(Path(td)/'old');path.mkdir(mode=0o700)
                return response('user::rwx\ngroup::---\nother::---\n')
            with self.assertRaisesRegex(ValueError,'created_evidence_changed'):fs.verify_created(path,command=replaced)
    def test_created_acl_failure_closes_new_fd_and_preserves_empty_failure_file(self):
        with tempfile.TemporaryDirectory() as td:
            calls=[]
            def check(path,fd=None):
                calls.append((Path(path),fd))
                if fd is not None:raise ValueError('created_evidence_acl_rejected')
            evidence=c.Evidence(Path(td)/'out',verify_created=check)
            with self.assertRaisesRegex(ValueError,'created_evidence_acl'):
                evidence.write('started.json',{'test':True})
            with self.assertRaises(OSError):os.fstat(calls[-1][1])
            self.assertEqual((evidence.path/'started.json').read_bytes(),b'')
    def test_pre_request_file_rejection_invokes_no_transport(self):
        with tempfile.TemporaryDirectory() as td:
            def check(path,fd=None):
                if fd is not None:raise ValueError('created_evidence_acl_rejected')
            evidence=c.Evidence(Path(td)/'out',verify_created=check);transport=Mock()
            m=c.load_manifest(Path(__file__).parent/'request-manifest.json')
            with self.assertRaisesRegex(ValueError,'created_evidence_acl'):c.collect(m,transport,evidence)
            transport.open.assert_not_called()
    def test_worker_creation_rejection_precedes_production_transport_creation(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'out';out.mkdir()
            grant={'scope':'2_pypi_discovery_gets_only','receipt_sha256':'a'*64,
                   'output_policy':{},'verify_created_acl':True}
            with patch('admission.load_grant',return_value=grant),\
                 patch.object(c,'validate_output_path',side_effect=lambda p,*a:Path(p)),\
                 patch.object(fs,'verify_created',side_effect=ValueError('created_evidence_acl_rejected')),\
                 patch.object(c,'TLSMetadataTransport') as transport:
                with self.assertRaisesRegex(ValueError,'created_evidence_acl'):
                    c.main(['--manifest',str(Path(__file__).parent/'request-manifest.json'),
                            '--output',str(out),'--authorization','invented','--authorization-sha256','a'*64,'--worker'])
                transport.assert_not_called()
    def test_created_private_file_checked_before_body_write(self):
        with tempfile.TemporaryDirectory() as td:
            calls=[]
            def check(path,fd=None):
                calls.append(Path(path).name)
                if fd is not None:
                    self.assertEqual(os.fstat(fd).st_size,0)
                    self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode),0o600)
            evidence=c.Evidence(Path(td)/'out',verify_created=check)
            evidence.write('a.json',{'accepted':False})
            self.assertEqual(calls,['out','a.json'])
    def test_created_folder_rejects_child_directory_before_collection(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'evidence';path.mkdir(mode=0o700);(path/'unexpected').mkdir()
            with patch.object(fs,'verify_created',return_value={}):
                with self.assertRaisesRegex(ValueError,'created_evidence_identity'):fs.verify_evidence_folder(path)
    def test_admission_failure_codes_are_closed_without_raw_error(self):
        for code in ('home_acl_identity_rejected','home_acl_pattern_rejected','home_acl_disposition_invalid',
                     'created_evidence_acl_rejected','created_evidence_changed'):
            result=e.admission_failure(ValueError(code),'acl_mount_observation')
            self.assertEqual(result['code'],code);self.assertNotIn('traceback',result)

class BoundAdmissionTests(unittest.TestCase):
    setUp=external_fixtures.Tests.setUp
    def test_nonboolean_disposition_rejected_before_github_request(self):
        self.record['home_default_acl_disposition_accepted']='true'
        self.record.update(issued_utc=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                           expires_utc=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        raw=json.dumps(self.record).encode()
        with self.assertRaisesRegex(ValueError,'home_acl_disposition_invalid'):
            e.issue(raw,e.sha(raw),self.folder,self.ctx,self.env,fetch=lambda *a:self.fail('API touched'))
    def test_issue_passes_only_explicit_disposition_and_preserves_false_scope(self):
        for accepted in (False,True):
            with self.subTest(accepted=accepted):
                folder=self.folder/str(accepted);folder.mkdir(mode=0o700)
                self.record['home_default_acl_disposition_accepted']=accepted
                self.record['runtime_acceptance_sha256']=e.sha((Path(e.__file__).parent/'metadata-runtime-acceptance.json').read_bytes())
                now=dt.datetime.now(dt.timezone.utc)
                self.record.update(issued_utc=(now-dt.timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                                   expires_utc=(now+dt.timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ'))
                env={**self.env,'OWNER_CONFIRMATION':'true','BILLING_CONFIRMATION':'true',
                     'RUNNER_TEMP':str(self.folder),'GITHUB_WORKSPACE':str(self.folder/'repo')}
                raw=json.dumps(self.record).encode();observer=Mock(return_value={'paths':[]})
                with patch.object(e.runtime_acceptance,'verify_record',return_value={'invented':True}),\
                     patch.object(e.admission,'output_policy'),patch.object(fs,'verify_evidence_folder',return_value=[{'invented':True}]) as created:
                    receipt=e.issue(raw,e.sha(raw),folder,self.ctx,env,
                                    fetch=lambda *a:(self.run,'a'*64),observe_output=observer)
                kwargs={'allow_home_default_acl':True} if accepted else {}
                observer.assert_called_once_with(str(self.folder),str(self.folder/'repo'),**kwargs)
                created.assert_called_once_with(folder)
                self.assertFalse(receipt['pilot_execution_authorized']);self.assertFalse(receipt['security_approved'])
                stored=json.loads((folder/'external-record.json').read_text())
                self.assertIs(stored['home_default_acl_disposition_accepted'],accepted)
    def test_parent_and_worker_reconstruct_before_fresh_acl_and_created_checks(self):
        receipt_path=self.folder/'receipt.json'
        receipt={'external_review':{},'runtime_acceptance_sha256':'b'*64}
        raw=json.dumps(receipt).encode();receipt_path.write_bytes(raw)
        for worker in (False,True):
            for accepted in (False,True):
                calls=[]
                def reconstruct(*args):calls.append('reconstruct');return {'home_default_acl_disposition_accepted':accepted}
                def observe(*args,**kwargs):
                    calls.append('observe');self.assertEqual(kwargs,{'allow_home_default_acl':True} if accepted else {})
                    return {}
                def created(*args):calls.append('created');return []
                grant={'context':self.ctx}
                with patch.object(admission,'authorize',return_value=grant.copy()),\
                     patch.object(admission,'context_from_env',return_value=self.ctx),\
                     patch.object(admission,'output_policy',return_value={'external_root':'invented'}),\
                     patch.object(e,'reconstruct',side_effect=reconstruct),\
                     patch.object(fs,'observe',side_effect=observe),patch.object(fs,'verify_evidence_folder',side_effect=created),\
                     patch.object(e.runtime_acceptance,'verify_record',return_value={}):
                    result=admission.load_grant(Path(e.__file__).parent/'request-manifest.json',receipt_path,e.sha(raw),
                                               Path(e.__file__).parent,self.folder/'pypi-evidence-123-1',
                                               env={'RUNNER_TEMP':'invented','GITHUB_WORKSPACE':'invented-repo'},
                                               worker=worker,runtime_path='invented',runtime_hash='b'*64)
                self.assertEqual(calls,['reconstruct','observe','created']);self.assertIs(result['verify_created_acl'],True)


if __name__=='__main__':unittest.main()
