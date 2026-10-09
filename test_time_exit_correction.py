"""Offline exact GitHub shell invocation using extracted workflow blocks/stubs."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import authorization_timestamps as timestamps
BASH = os.environ.get('REVIEW_BASH', r'C:\Program Files\Git\bin\bash.exe' if os.name == 'nt' else '/bin/bash')
RECORDS = []
APPROVED = None

def guard(event, args):
    if event.startswith('socket.') or event in ('os.system','os.exec','os.posix_spawn','os.spawn'):
        raise RuntimeError('offline denied')
    if event == 'subprocess.Popen':
        if APPROVED is None:
            raise RuntimeError('unapproved child')
        expected = subprocess.list2cmdline(APPROVED) if isinstance(args[1], str) else APPROVED
        if args[0] != BASH or args[1] != expected:
            raise RuntimeError('unapproved child')
sys.addaudithook(guard)

def block(path, stage):
    names = {'preflight':'Verify current collection sources and inactive-record gates',
             'admission':'One bounded GitHub identity GET and existing parent-worker admission',
             'finalization':'Independently retain available evidence and fail closed on missing completion'}
    text = path.read_text().split('      - name: '+names[stage]+'\n',1)[1]
    text = text.split('        run: |\n',1)[1].split('      - name:',1)[0]
    return ''.join(line[10:]+'\n' for line in text.splitlines())

class ShellTests(unittest.TestCase):
    def case(self, stage, code, broken=None, old=False):
        global APPROVED
        with tempfile.TemporaryDirectory(prefix='two-index-shell-') as td:
            root=Path(td); launch=root/'two-index-collection-launch-7-1';launch.mkdir()
            if broken: (launch/f'{stage}-{broken}').mkdir()
            stub=root/'stub.sh'
            stub.write_text('#!/usr/bin/bash\nprintf "invented stdout\\n"\nprintf "invented stderr\\n" >&2\nif [ "$STUB_CODE" = 124 ]; then /usr/bin/timeout --signal=TERM --kill-after=0.1s 0.05s /usr/bin/sleep 1; exit $?; fi\nexit "$STUB_CODE"\n',newline='\n')
            base=ROOT.parent/'baseline' if old else ROOT
            script=block(base/'.github/workflows/two-index-collection.yml',stage)
            # Replace only the interpreter command, never the status/finalization shell logic.
            script=script.replace('/usr/bin/python3.12','/usr/bin/bash "$STUB_PATH"')
            entry=root/'entry.sh';entry.write_text(script,newline='\n')
            env={k:os.environ[k] for k in ('SystemRoot','WINDIR') if k in os.environ}
            env.update(PATH='/usr/bin:/bin',RUNNER_TEMP=root.as_posix(),GITHUB_RUN_ID='7',GITHUB_RUN_ATTEMPT='1',STUB_PATH=stub.as_posix(),STUB_CODE=str(code))
            command=[BASH,'--noprofile','--norc','-e','-o','pipefail',entry.as_posix()];APPROVED=command
            try: result=subprocess.run(command,executable=BASH,env=env,capture_output=True,text=True,timeout=10)
            finally: APPROVED=None
            expected=code if code else (74 if broken else 0)
            self.assertEqual(result.returncode,expected,result.stderr)
            if old:
                self.assertFalse((launch/f'{stage}-exit.txt').exists())
            else:
                if broken!='exit.txt': self.assertEqual((launch/f'{stage}-exit.txt').read_text().strip(),str(code))
                if broken!='status.json': self.assertEqual(json.loads((launch/f'{stage}-status.json').read_text())['exit_code'],code)
                self.assertIn(f'original_exit={code}',result.stdout)
            RECORDS.append({'stage':stage,'original_status':code,'broken_destination':broken,'historical':old,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'argv':command})
    def test_success_rejection_timeout(self):
        for stage in ('preflight','admission','finalization'):
            for code in (0,7,124):
                with self.subTest(stage=stage,code=code):self.case(stage,code)
    def test_independent_writes_and_original_status(self):
        for stage in ('preflight','admission','finalization'):
            for code in (0,7):
                for broken in ('exit.txt','status.json'):
                    with self.subTest(stage=stage,code=code,broken=broken):self.case(stage,code,broken)
    def test_original_errexit_failure(self):
        for stage in ('preflight','admission','finalization'):
            with self.subTest(stage=stage):self.case(stage,7,old=True)

class TimestampTests(unittest.TestCase):
    NOW=dt.datetime(2026,10,9,3,0,0,123456,tzinfo=dt.timezone.utc)
    def test_exact_z_and_unchanged_flags(self):
        original={'owner_accepted':False,'training_authorized':False,'run_number':2}
        result=timestamps.stamp(original,self.NOW)
        self.assertEqual(result['issued_utc'],'2026-10-09T03:00:00Z')
        self.assertEqual(result['expires_utc'],'2026-10-09T03:15:00Z')
        self.assertEqual({k:result[k] for k in original},original)
        self.assertNotIn('issued_utc',original)
    def test_convert_timezone(self):
        self.assertEqual(timestamps.stamp({},self.NOW.astimezone(dt.timezone(dt.timedelta(hours=7))))['issued_utc'],'2026-10-09T03:00:00Z')
    def test_reject_old_offset_and_fraction(self):
        for bad in ('2026-10-09T03:00:00+00:00','2026-10-09T03:00:00.123Z'):
            with self.assertRaisesRegex(ValueError,'external_time_format'):timestamps.validate_window({'issued_utc':bad,'expires_utc':'2026-10-09T03:15:00Z'},self.NOW)
    def test_reject_bad_bounds_and_naive(self):
        for minutes in (0,16,True):
            with self.assertRaises(ValueError):timestamps.stamp({},self.NOW,minutes)
        with self.assertRaises(ValueError):timestamps.stamp({},self.NOW.replace(tzinfo=None))
    def test_reject_expired_future_and_long_window(self):
        record=timestamps.stamp({},self.NOW)
        for now in (self.NOW-dt.timedelta(minutes=1),self.NOW+dt.timedelta(minutes=15)):
            with self.assertRaises(ValueError):timestamps.validate_window(record,now)
        record['expires_utc']='2026-10-09T03:16:00Z'
        with self.assertRaisesRegex(ValueError,'window_bound'):timestamps.validate_window(record,self.NOW)
    def test_predispatch_hash_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/'input.json';output=Path(td)/'output.json';source.write_text('{"owner_accepted":false}')
            before=sys.argv[:]
            try:
                sys.argv=['tool','generate',str(source),str(output)];timestamps.main()
                self.assertFalse(json.loads(output.read_bytes())['owner_accepted'])
                with self.assertRaises(FileExistsError):timestamps.main()
                sys.argv=['tool','check',str(output),hashlib.sha256(output.read_bytes()).hexdigest()];timestamps.main()
                sys.argv[-1]='0'*64
                with self.assertRaisesRegex(ValueError,'activation_hash'):timestamps.main()
            finally:sys.argv=before

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    (ROOT.parent/'time-exit-results.json').write_text(json.dumps({'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'shell_cases':RECORDS,'python':sys.version,'bash':BASH,'network':'Parent audit denies socket/DNS; shell fixtures execute only reviewed stub, printf, Bash, timeout and sleep. No OS network isolation claimed.'},indent=2)+'\n')
    sys.exit(0 if result.wasSuccessful() else 1)
