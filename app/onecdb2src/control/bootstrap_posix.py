"""Dedicated Linux subreaper. Survives target exit to close owned descendants."""
import ctypes
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from posix_support import descendants,live,process,same_process,signal_process,write_status

def main():
    argv=json.loads(sys.argv[1]);cap=int(sys.argv[2]);path=Path(sys.argv[3]);parent=int(sys.argv[4])
    libc=ctypes.CDLL(None,use_errno=True)
    def prctl(option,value):
        if libc.prctl(option,value,0,0,0)!=0:raise OSError(ctypes.get_errno(),'Process isolation setup failed')
    stop=[False]
    def cancel(signum,frame):stop[0]=True
    signal.signal(signal.SIGTERM,cancel);signal.signal(signal.SIGINT,cancel)
    prctl(36,1);prctl(1,signal.SIGTERM)
    if os.getppid()!=parent:return 126
    # Require safe signaling support before accepting GO or launching a child.
    test_fd=os.pidfd_open(os.getpid(),0);os.close(test_fd)
    if not hasattr(signal,'pidfd_send_signal'):raise RuntimeError('Linux pidfd signaling required')
    cpus=sorted(os.sched_getaffinity(0))[:2]
    if not cpus:raise RuntimeError('No usable CPU affinity')
    seen={};peak=0;target=None;failure=None;observation_errors=[];cleanup_errors=[];samples=[]
    def remember(item):
        pid=item['pid']
        # A new descendant can legitimately reuse a reaped former child's PID.
        # Fresh ancestry plus start_ticks supplies its new owned identity.
        seen[pid]=item
    def sample():
        nonlocal peak
        try:owned=descendants(os.getpid(),on_process=remember)
        except Exception as error:
            observation_errors.append(type(error).__name__);raise
        running=[token for token in seen.values() if live(token)]
        peak=max(peak,sum((same_process(t) or {}).get('rss_bytes',0) for t in running))
        return running
    def publish(closed=False):
        write_status(path,dict(schema=1,bootstrap_pid=os.getpid(),bootstrap_start_ticks=process(os.getpid())['start_ticks'],
            target_exit=target.returncode if target else None,failure=failure,known_processes=list(seen.values()),
            peak_sampled_tree_rss_bytes=peak,cpu_affinity=cpus,processgroups_closed=closed,
            observation_errors=observation_errors,cleanup_errors=cleanup_errors,post_exit_samples=samples,
            subreaper=True,parent_death_signal='SIGTERM',closed=closed))
    def reap():
        for pid in list(seen):
            if target and pid==target.pid:continue
            try:os.waitpid(pid,os.WNOHANG)
            except ChildProcessError:pass
    def signal_owned(sig):
        for token in list(seen.values()):
            if live(token):
                signal_process(token,sig)
    try:
        publish()
        if sys.stdin.buffer.readline()!=b'GO\n' or stop[0]:raise RuntimeError('Launch handshake cancelled')
        raw_env=sys.stdin.buffer.readline(1048577)
        if len(raw_env)>1048576 or not raw_env.endswith(b'\n'):raise RuntimeError('Workload environment pipe quota exceeded')
        payload=json.loads(raw_env)
        if not isinstance(payload,dict) or set(payload)!={'env'}:raise RuntimeError('Invalid environment handshake')
        target_env=payload['env']
        if target_env is not None and (not isinstance(target_env,dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in target_env.items())):
            raise RuntimeError('Invalid workload environment')
        if stop[0]:raise RuntimeError('Launch handshake cancelled')
        supervisor_pid=os.getpid()
        def limits():
            prctl(1,signal.SIGKILL)
            if os.getppid()!=supervisor_pid:os._exit(126)
            resource.setrlimit(resource.RLIMIT_AS,(cap,cap))
            os.sched_setaffinity(0,set(cpus))
            if resource.getrlimit(resource.RLIMIT_AS)!=(cap,cap) or os.sched_getaffinity(0)!=set(cpus):
                raise RuntimeError('Workload process limits could not be verified')
        target=subprocess.Popen(argv,stdin=subprocess.DEVNULL,preexec_fn=limits,env=target_env)
        while target.poll() is None:
            running=sample();publish()
            if stop[0]:failure='CANCELLED';break
            if sum((same_process(t) or {}).get('rss_bytes',0) for t in running)>cap:
                failure='RSS_LIMIT';break
            reap();time.sleep(.02)
        deadline=time.monotonic()+.25
        while failure is None:
            running=sample();reap()
            samples.append(dict(pids=[t['pid'] for t in running],rss_bytes=sum((same_process(t) or {}).get('rss_bytes',0) for t in running)))
            if len(samples)>16:samples=samples[-16:]
            if not running:break
            if stop[0]:failure='CANCELLED';break
            if time.monotonic()>=deadline:failure='SURVIVING_CHILDREN';break
            publish();time.sleep(.02)
    except BaseException as error:
        failure=failure or type(error).__name__
    finally:
        def cleanup_sample():
            nonlocal failure
            try:return sample()
            except BaseException as error:
                failure=failure or 'PROCESS_OBSERVATION_UNKNOWN'
                if type(error).__name__ not in observation_errors:observation_errors.append(type(error).__name__)
                return None
        try:
            # Enumeration failure MUST NOT skip termination of the identities
            # already streamed into seen. Unknown membership remains UNKNOWN.
            cleanup_sample();signal_owned(signal.SIGTERM)
            deadline=time.monotonic()+.25
            while time.monotonic()<deadline:
                if target:target.poll()
                reap()
                if cleanup_sample()==[]:break
                time.sleep(.02)
            cleanup_sample();signal_owned(signal.SIGKILL)
            deadline=time.monotonic()+2
            while time.monotonic()<deadline:
                if target:target.poll()
                reap()
                if cleanup_sample()==[]:break
                # Newly adopted children can appear while killed parents exit.
                signal_owned(signal.SIGKILL)
                time.sleep(.02)
            remaining=cleanup_sample();reap()
            if remaining:failure=failure or 'SURVIVING_PROCESSES'
            publish(closed=remaining==[] and not observation_errors)
        except BaseException as error:
            cleanup_errors.append(type(error).__name__)
            failure=failure or 'CLEANUP_FAILURE'
            try:publish(False)
            except Exception:pass
    return 0 if not failure else 125

if __name__=='__main__':raise SystemExit(main())
