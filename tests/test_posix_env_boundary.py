"""Real /proc checks of dummy-only capture/later-stage bootstrap boundaries."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

PACKAGE=Path(__file__).resolve().parents[1]/'app'
sys.path.insert(0,str(PACKAGE))
from onecdb2src.control.bounded_process import run

@unittest.skipUnless(sys.platform.startswith('linux'),'real Linux required')
class BootstrapEnvTests(unittest.TestCase):
    def exercise(self,mode):
        token='DUMMY_ONLY_CAPTURE_SENTINEL_'+os.urandom(12).hex()
        key='onecdb2src_DUMMY_CAPTURE_PASSWORD'
        parent_only='onecdb2src_DUMMY_PARENT_OTHER'
        baseline={k:os.environ[k] for k in ('PATH','LD_LIBRARY_PATH','PYTHONHOME','LANG','LC_ALL','TMPDIR') if k in os.environ}
        baseline.update({key:token,parent_only:'dummy_parent_only'})
        capture=mode=='capture'
        target_env=None if mode=='inherit' else {'PATH':'/usr/bin:/bin','LANG':'C','LD_LIBRARY_PATH':'/neutral-target-only'}
        if capture:target_env[key]=token
        observed={};errors=[]
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,baseline,clear=True):
            root=Path(td);pidfile=root/'pids'
            # Dummy VALUE never appears in argv or shell code.
            script='printf "%s %s" "$$" "$PPID" > '+str(pidfile)+'; /bin/sleep 0.6'
            def observer():
                try:
                    deadline=time.monotonic()+4
                    while not pidfile.exists() and time.monotonic()<deadline:time.sleep(.005)
                    target,bootstrap=map(int,pidfile.read_text().split())
                    def environ(pid):
                        return dict(item.split(b'=',1) for item in Path('/proc',str(pid),'environ').read_bytes().split(b'\0') if b'=' in item)
                    target_seen,bootstrap_seen=environ(target),environ(bootstrap)
                    expected_secret=mode in ('capture','inherit')
                    observed['target_dummy_correct']=(target_seen.get(key.encode())==token.encode())==expected_secret
                    observed['bootstrap_dummy_correct']=(bootstrap_seen.get(key.encode())==token.encode())==expected_secret
                    observed['unrelated_parent_correct']=(parent_only.encode() in bootstrap_seen)==(mode=='inherit')
                    observed['bootstrap_loader_from_parent']=bootstrap_seen.get(b'LD_LIBRARY_PATH')==baseline.get('LD_LIBRARY_PATH','').encode()
                    observed['target_loader_unchanged']=(target_seen.get(b'LD_LIBRARY_PATH')==(baseline.get('LD_LIBRARY_PATH','').encode() if target_env is None else target_env['LD_LIBRARY_PATH'].encode()))
                    target_cmd=Path('/proc',str(target),'cmdline').read_bytes()
                    bootstrap_cmd=Path('/proc',str(bootstrap),'cmdline').read_bytes()
                    observed['argv_clean']=token.encode() not in target_cmd+bootstrap_cmd
                    state=next(Path(item.decode()) for item in bootstrap_cmd.split(b'\0') if item.endswith(b'/status.json'))
                    observed['status_clean']=token.encode() not in state.read_bytes()
                except BaseException as error:errors.append(type(error).__name__)
            thread=threading.Thread(target=observer);thread.start()
            result=run(['/bin/sh','-c',script],root/'out',root/'err',root/'receipt',5,10000,10000,256*1024**2,env=target_env)
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors,[])
            self.assertEqual(len(observed),7)
            self.assertTrue(all(observed.values()),{k:v for k,v in observed.items() if not v})
            self.assertIsNone(result['failure'],result)
            self.assertTrue(result['processgroups_closed'],result)
            self.assertEqual(result['surviving_pids'],[])
            self.assertNotIn(token,json.dumps(result))
            for path in (root/'out',root/'err',root/'receipt'):
                self.assertTrue(token.encode() not in path.read_bytes())

    def test_capture_explicit_dummy_env_is_present_only_as_requested(self):self.exercise('capture')
    def test_later_stage_bootstrap_and_target_exclude_parent_dummy_secret(self):self.exercise('later')
    def test_env_none_preserves_explicit_inheritance_contract(self):self.exercise('inherit')

if __name__=='__main__':unittest.main()
