"""Finite source-contract tests. No engine, Docker, DB, or Linux host execution."""
import json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from onecdb2src.xml import export_local as m

def job(**updates):
    result=dict(backend='linux-posix',processgroups_closed=True,surviving_pids=[],cleanup_errors=[],observation_status='OBSERVED',failure=None,exit_code=0,seconds=.01)
    result.update(updates);return result

class LocalTests(unittest.TestCase):
    def test_command_fixed_loader_and_environment(self):
        command=m.engine_command('source.cf','tree','8.5.1')
        self.assertEqual(command[:4],m.prefix());self.assertEqual(command[-5:],['--platform','8.5.1','--compression','raw-deflate','--fail-on-opaque'])
        self.assertEqual(set(m.environment(2)),{'PATH','LANG','LC_ALL','RAYON_NUM_THREADS'})
        self.assertTrue(Path(command[0]).name.startswith('ld-linux-'))
        self.assertFalse(any(Path(part).name.lower() in ('docker','docker.exe') for part in command[:4]))
        with self.assertRaises(ValueError):m.engine_command('a','b','unknown')

    def test_closure_unknown_rejected(self):
        self.assertTrue(m.closed(job()))
        for updates in ({'processgroups_closed':False},{'surviving_pids':[7]},{'cleanup_errors':['x']},{'observation_status':'UNKNOWN'},{'backend':'windows'}):
            self.assertFalse(m.closed(job(**updates)))

    def test_preflight_static_exact_hashes(self):
        with patch.object(m.platform,'system',return_value='Linux'),patch.object(m.platform,'machine',return_value='x86_64'),patch.object(m.os,'access',return_value=True):
            result=m.preflight(verify_version=False)
        self.assertEqual(len(result['files']),7);self.assertFalse(result['version_verified'])

    def test_hash_mismatch(self):
        original=m.fact
        def changed(path):return {'bytes':1,'sha256':'0'*64} if Path(path).name=='ibcmd-rs' else original(path)
        with patch.object(m.platform,'system',return_value='Linux'),patch.object(m.platform,'machine',return_value='x86_64'),patch.object(m,'fact',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'hash mismatch'):m.preflight(verify_version=False)

    def test_unsupported_host(self):
        with patch.object(m.platform,'system',return_value='Windows'):
            with self.assertRaisesRegex(ValueError,'Linux'):m.preflight(verify_version=False)

    def test_version_receipts_success_and_failure(self):
        for failure,version in ((None,'ibcmd-rs 0.4.1\n'),('Timeout',None),(None,'wrong\n')):
            with self.subTest(failure=failure,version=version),tempfile.TemporaryDirectory() as raw:
                resultjob=job(failure=failure,exit_code=0 if failure is None else -9)
                def run(argv,out,err,receipt,*args,**kw):
                    Path(out).write_text(version or '',encoding='utf-8');Path(err).write_bytes(b'');m.save(receipt,resultjob);return resultjob
                with patch.object(m.platform,'system',return_value='Linux'),patch.object(m.platform,'machine',return_value='x86_64'),patch.object(m.os,'access',return_value=True),patch('onecdb2src.control.bounded_process.run',side_effect=run):
                    if failure is not None or version=='wrong\n':
                        with self.assertRaises(m.LocalPreflightError) as caught:m.preflight({'root':raw})
                        self.assertEqual(caught.exception.job,resultjob)
                    else:self.assertTrue(m.preflight({'root':raw})['version_verified'])
                self.assertEqual(len(list(Path(raw).glob('native-version-*/process.json'))),1)

    def test_version_cancel_retains_job_and_cleanup(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);cf=root/'source.cf';cf.write_bytes(b'own');profilepath=root/'profile.json';profilepath.write_text('{}')
            profile=dict(platform_profile='8.5.1',xml_version='2.21',profile_id='own')
            cancelled=job(failure='CANCELLED',cancelled=True,exit_code=-9)
            args=SimpleNamespace(cf=str(cf),output=str(root/'out'),provider='fixture',side='main',memory_mib=512,workers=2,timeout=1,platform='auto',profile_receipt=str(profilepath))
            def run(argv,out,err,receipt,*rest,**kw):
                Path(out).write_bytes(b'');Path(err).write_bytes(b'');m.save(receipt,cancelled);return cancelled
            with patch.object(m.platform,'system',return_value='Linux'),patch.object(m.platform,'machine',return_value='x86_64'),patch.object(m.os,'access',return_value=True),patch.object(m.profiles,'load',return_value=profile),patch('onecdb2src.control.bounded_process.run',side_effect=run):
                with self.assertRaises(KeyboardInterrupt):m.export(args)
            receipt=json.loads((root/'out/receipt.json').read_text(encoding='utf-8'))
            self.assertEqual(receipt['status'],'CANCELLED');self.assertEqual(receipt['preflight_failed_job'],cancelled)
            self.assertTrue(receipt['cleanup']['confirmed']);self.assertFalse(receipt['cleanup']['engine_process_started'])
            self.assertEqual(len(list((root/'out').glob('native-version-*/process.json'))),1)

    def export_case(self,resultjob,opaque=0):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);cf=root/'source.cf';cf.write_bytes(b'own fixture');profilefile=root/'profile.json';profilefile.write_text('{}')
            profile=dict(platform_profile='8.5.1',xml_version='2.21',profile_id='own-fixture')
            args=SimpleNamespace(cf=str(cf),output=str(root/'out'),provider='fixture',side='main',memory_mib=512,workers=2,timeout=1,platform='auto',profile_receipt=str(profilefile))
            report={'ok':opaque==0,'command':'export','source_version':'2.21','export':{'source_version':'2.21','files_written':1,'storage':dict(physical_entries=1,logical_entries=1,supported=1,opaque=opaque,failed=0)},'errors':[]}
            def run(argv,out,err,receipt,*rest,**kw):
                (root/'out/tree/xml').mkdir();m.save(out,report);Path(err).write_bytes(b'');m.save(receipt,resultjob);return resultjob
            with patch.object(m.profiles,'load',return_value=profile),patch.object(m,'preflight',return_value={'version_verified':True}),patch('onecdb2src.control.bounded_process.run',side_effect=run):
                try:m.export(args)
                except (ValueError,KeyboardInterrupt):pass
            receipt=json.loads((root/'out/receipt.json').read_text(encoding='utf-8'))
            self.assertEqual(receipt['runtime_backend'],'native');self.assertEqual(receipt['memory_oom_status'],'NOT_OBSERVED')
            self.assertEqual(receipt['process']['job'],resultjob);self.assertEqual(receipt['cleanup']['confirmed'],m.closed(resultjob))
            self.assertEqual(receipt['source']['sha256'],receipt['source']['sha256_after']);self.assertEqual(receipt['profile'],profile)
            self.assertFalse({'container','container_id','oom_killed'}&set(receipt))
            return receipt

    def test_export_success(self):self.assertEqual(self.export_case(job())['status'],'ENGINE_EXPORT_OK_VERIFICATION_PENDING')
    def test_opaque_raw_preserved(self):
        receipt=self.export_case(job(exit_code=2),3);self.assertEqual(receipt['status'],'FAILED');self.assertEqual(receipt['summary']['storage']['opaque'],3)
    def test_timeout(self):self.assertEqual(self.export_case(job(failure='Timeout',exit_code=-9))['status'],'FAILED')
    def test_cancel(self):self.assertEqual(self.export_case(job(failure='CANCELLED',cancelled=True,exit_code=-9))['status'],'CANCELLED')
    def test_surviving_process_rejected(self):self.assertEqual(self.export_case(job(processgroups_closed=False,surviving_pids=[7]))['status'],'FAILED')

    def test_engine_run_raises_cannot_reuse_closed_version_job(self):
        for error in (OSError('receipt write failed'),KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__),tempfile.TemporaryDirectory() as raw:
                root=Path(raw);cf=root/'source.cf';cf.write_bytes(b'own');profilepath=root/'profile.json';profilepath.write_text('{}')
                profile=dict(platform_profile='8.5.1',xml_version='2.21',profile_id='own')
                args=SimpleNamespace(cf=str(cf),output=str(root/'out'),provider='fixture',side='main',memory_mib=512,workers=2,timeout=1,platform='auto',profile_receipt=str(profilepath))
                with patch.object(m.profiles,'load',return_value=profile),patch.object(m,'preflight',return_value={'version_supervision':{'job':job()}}),patch('onecdb2src.control.bounded_process.run',side_effect=error):
                    with self.assertRaises(type(error)):m.export(args)
                receipt=json.loads((root/'out/receipt.json').read_text(encoding='utf-8'))
                self.assertFalse(receipt['cleanup']['confirmed']);self.assertTrue(receipt['cleanup']['engine_attempted'])
                self.assertIsNone(receipt['cleanup']['processgroups_closed']);self.assertIsNone(receipt['cleanup']['surviving_pids'])
                self.assertIsNone(receipt['cleanup']['engine_process_started'])

if __name__=='__main__':unittest.main()
