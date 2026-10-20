"""Linux-only real tiny subprocess tests; no DB, Docker, or native engine calls."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest

PACKAGE=Path(__file__).resolve().parents[1]/'app'
sys.path.insert(0,str(PACKAGE))
from onecdb2src.control.bounded_process import run

@unittest.skipUnless(sys.platform.startswith('linux'),'real Linux required')
class PosixTests(unittest.TestCase):
    def launch(self,source,seconds=5,stdout_cap=1000000,stderr_cap=1000000,rss_cap=256*1024**2):
        with tempfile.TemporaryDirectory(prefix='onecdb2src process with spaces ') as td:
            root=Path(td)
            result=run([sys.executable,'-B','-c',source],root/'stdout',root/'stderr',root/'receipt.json',
                       seconds,stdout_cap,stderr_cap,rss_cap)
            self.assertEqual(json.loads((root/'receipt.json').read_text()),result)
            stdout,stderr=(root/'stdout').read_bytes(),(root/'stderr').read_bytes()
            self.assertEqual(hashlib.sha256(stdout).hexdigest(),result['stdout']['sha256'])
            self.assertEqual(hashlib.sha256(stderr).hexdigest(),result['stderr']['sha256'])
            self.assertTrue(result['processgroups_closed'],result)
            self.assertTrue(result['job_handle_closed'],result)
            self.assertEqual(result['surviving_pids'],[],result)
            self.assertEqual(result['observation_status'],'OBSERVED',result)
            self.assertEqual(result['cleanup_errors'],[],result)
            self.assertFalse(result['windows_job_used'])
            self.assertEqual(result['oom_killed'],'UNKNOWN')
            return result,stdout,stderr

    def test_normal_exit_output_and_affinity_limits(self):
        source='import os,resource,json; print(json.dumps([len(os.sched_getaffinity(0)),resource.getrlimit(resource.RLIMIT_AS)[0]]))'
        result,out,err=self.launch(source)
        cpus,memory=json.loads(out)
        self.assertGreaterEqual(cpus,1);self.assertLessEqual(cpus,2)
        self.assertEqual(memory,256*1024**2)
        self.assertIsNone(result['failure']);self.assertEqual(result['exit_code'],0)
        self.assertEqual(err,b'')

    def test_nonzero_exit_does_not_become_supervisor_error(self):
        result,out,err=self.launch('import sys;sys.stderr.write("neutral failure");sys.exit(7)')
        self.assertIsNone(result['failure']);self.assertEqual(result['exit_code'],7)
        self.assertEqual(err,b'neutral failure')

    def test_timeout_closes_processes(self):
        result,_,_=self.launch('import time;time.sleep(30)',seconds=1)
        self.assertEqual(result['failure'],'TIMEOUT')
        self.assertTrue(result['go_sent'])

    def test_timeout_before_launch_does_not_claim_workload_ran(self):
        result,_,_=self.launch('import time;time.sleep(30)',seconds=.001)
        self.assertEqual(result['failure'],'TIMEOUT')
        self.assertFalse(result['go_sent'])
        self.assertEqual(result['closure_scope'],'bootstrap_only_prelaunch')

    def test_stdout_and_stderr_caps(self):
        for stream in ('stdout','stderr'):
            result,out,err=self.launch('import sys;sys.'+stream+'.write("x"*1000000)',stdout_cap=10,stderr_cap=10)
            self.assertEqual(result['failure'],'OUTPUT_LIMIT_OR_IO')
            self.assertEqual(len(out if stream=='stdout' else err),10)

    def test_parent_exit_reaps_orphan_and_detached_session(self):
        source='import subprocess,sys; p=subprocess.Popen([sys.executable,"-c","import os,time;os.setsid();time.sleep(30)"]); print(p.pid,flush=True)'
        result,out,err=self.launch(source)
        self.assertEqual(result['failure'],'SURVIVING_CHILDREN')
        child=int(out)
        self.assertIn(child,result['observed_pids'])
        self.assertFalse(Path('/proc',str(child)).exists())

    def test_interrupt_closes_own_children(self):
        timer=threading.Timer(.4,lambda:os.kill(os.getpid(),signal.SIGINT))
        timer.start()
        try:result,_,_=self.launch('import time;time.sleep(30)')
        finally:timer.cancel()
        self.assertEqual(result['failure'],'CANCELLED')
        self.assertTrue(result['cancelled'])

    def test_rlimit_is_address_space_per_process_not_cgroup_claim(self):
        result,_,_=self.launch('import sys\ntry:a=bytearray(128*1024**2)\nexcept MemoryError:sys.exit(17)',rss_cap=64*1024**2)
        self.assertEqual(result['exit_code'],17)
        self.assertIsNone(result['hard_cgroup_memory_bytes'])
        self.assertEqual(result['hard_address_space_per_process_bytes'],64*1024**2)

    def test_overwrite_and_overlapping_paths_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);out=root/'out';out.write_text('owned existing')
            with self.assertRaises(ValueError):run(['true'],out,root/'err',root/'receipt',1,1,1)
            self.assertEqual(out.read_text(),'owned existing')
            with self.assertRaises(ValueError):run(['true'],root/'x',root/'x',root/'receipt',1,1,1)

    def test_controller_death_triggers_subreaper_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);pidfile=root/'pids.json'
            workload='import json,os,pathlib,time;pathlib.Path('+repr(str(pidfile))+').write_text(json.dumps([os.getpid(),os.getppid()]));time.sleep(30)'
            controller='import sys;sys.path.insert(0,'+repr(str(PACKAGE))+');from onecdb2src.control.bounded_process import run;run('+repr([sys.executable,'-B','-c',workload])+','+repr(str(root/'out'))+','+repr(str(root/'err'))+','+repr(str(root/'receipt'))+',30,10000,10000)'
            proc=subprocess.Popen([sys.executable,'-B','-c',controller],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                deadline=time.monotonic()+5
                while not pidfile.exists() and time.monotonic()<deadline:time.sleep(.02)
                self.assertTrue(pidfile.exists())
                target,bootstrap=json.loads(pidfile.read_text())
                proc.kill();proc.wait(3)
                deadline=time.monotonic()+5
                def active(pid):
                    try:
                        text=Path('/proc',str(pid),'stat').read_text();return text[text.rfind(')')+2:].split()[0]!='Z'
                    except FileNotFoundError:return False
                while (active(target) or active(bootstrap)) and time.monotonic()<deadline:time.sleep(.02)
                self.assertFalse(active(target));self.assertFalse(active(bootstrap))
            finally:
                if proc.poll() is None:proc.kill();proc.wait(3)

    def test_clean_target_env_does_not_break_private_python_bootstrap_or_leak(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            env={'PATH':'/usr/bin:/bin','LANG':'C','ONLY_WORKLOAD':'neutral'}
            result=run(['/usr/bin/env'],root/'out',root/'err',root/'receipt',5,10000,10000,256*1024**2,env=env)
            self.assertIsNone(result['failure'],result)
            self.assertTrue(result['processgroups_closed'],result)
            actual=dict(line.split('=',1) for line in (root/'out').read_text().splitlines())
            self.assertEqual(actual,env)
            self.assertNotIn('LD_LIBRARY_PATH',actual)
            self.assertNotIn('PYTHONHOME',actual)
            self.assertNotIn('ONLY_WORKLOAD',json.dumps(result))

    def test_outer_timeout_closes_nested_supervisor_and_detached_engine_child(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);pidfile=root/'engine-child.pid'
            grandchild='import os,time;os.setsid();time.sleep(30)'
            engine='import subprocess,sys,pathlib,time;p=subprocess.Popen([sys.executable,"-c",'+repr(grandchild)+']);pathlib.Path('+repr(str(pidfile))+').write_text(str(p.pid));time.sleep(30)'
            inner='import sys;sys.path.insert(0,'+repr(str(PACKAGE))+');from onecdb2src.control.bounded_process import run;run('+repr([sys.executable,'-B','-c',engine])+','+repr(str(root/'inner-out'))+','+repr(str(root/'inner-err'))+','+repr(str(root/'inner-receipt'))+',30,10000,10000)'
            # Three interpreter startups over the host-mounted private Python
            # need fixture startup room; this is not a product timeout change.
            result=run([sys.executable,'-B','-c',inner],root/'out',root/'err',root/'receipt',4,10000,10000,256*1024**2)
            self.assertTrue(pidfile.exists(),result)
            self.assertEqual(result['failure'],'TIMEOUT')
            self.assertTrue(result['processgroups_closed'],result)
            self.assertEqual(result['surviving_pids'],[],result)
            self.assertEqual(result['cleanup_errors'],[],result)
            self.assertFalse(Path('/proc',pidfile.read_text()).exists())

    def test_more_than_64_sleeping_children_are_all_closed(self):
        source='import os,time\nfor i in range(70):\n p=os.fork()\n if p==0:time.sleep(30);os._exit(0)\ntime.sleep(.1)'
        result,_,_=self.launch(source,rss_cap=2*1024**3)
        self.assertEqual(result['failure'],'SURVIVING_CHILDREN')
        self.assertGreaterEqual(len(result['observed_pids']),70)
        for pid in result['observed_pids']:self.assertFalse(Path('/proc',str(pid)).exists())

    def test_enumeration_quota_fault_does_not_bypass_known_or_adopted_cleanup(self):
        # Test-only lowered observation quota; real package files remain intact.
        # Stop only our bootstrap while creating the neutral70-child fixture,
        # guaranteeing the next real /proc traversal enters the failure branch.
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);control=root/'fault-control'
            shutil.copytree(PACKAGE/'onecdb2src/control',control)
            support=control/'posix_support.py'
            support.write_text(support.read_text().replace('len(result)>4096','len(result)>64'))
            pkg=types.ModuleType('fault_control');pkg.__path__=[str(control)]
            sys.modules['fault_control']=pkg
            spec=importlib.util.spec_from_file_location('fault_control.bounded_posix',control/'bounded_posix.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            pidfile=root/'all-pids.json'
            source=('import os,time,json,pathlib\nparent=os.getppid();pids=[];os.kill(parent,19)\ntry:\n'
                    ' for i in range(70):\n  p=os.fork()\n  if p==0:time.sleep(30);os._exit(0)\n  pids.append(p)\n'
                    ' pathlib.Path('+repr(str(pidfile))+').write_text(json.dumps(pids))\nfinally:os.kill(parent,18)\ntime.sleep(30)')
            result=module.run([sys.executable,'-B','-c',source],root/'out',root/'err',root/'receipt',8,10000,10000,2*1024**3)
            self.assertTrue(pidfile.exists(),result)
            pids=json.loads(pidfile.read_text());self.assertEqual(len(pids),70)
            self.assertIsNotNone(result['failure'])
            self.assertEqual(result['observation_status'],'UNKNOWN')
            self.assertFalse(result['processgroups_closed'])
            self.assertEqual(result['known_surviving_pids'],[])
            for pid in pids:self.assertFalse(Path('/proc',str(pid)).exists(),pid)

if __name__=='__main__':unittest.main()
