"""Linux process-tree supervisor; RLIMIT_AS is NOT an aggregate cgroup cap."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from .posix_support import live,process,read_status,signal_process

def require(condition,message):
    if not condition:raise ValueError(message)

def run(argv,stdout_path,stderr_path,receipt_path,seconds,stdout_cap,stderr_cap,rss_cap=1073741824,env=None):
    require(sys.platform.startswith('linux'),'Linux /proc and prctl are required')
    require(seconds>0 and stdout_cap>=0 and stderr_cap>=0 and rss_cap>0,'Invalid process bounds')
    require(isinstance(argv,(list,tuple)) and argv and all(isinstance(a,str) for a in argv),'Invalid process argv')
    target_env=None if env is None else dict(env)
    require(target_env is None or all(isinstance(k,str) and isinstance(v,str) for k,v in target_env.items()),'Invalid workload environment')
    bootstrap_env=None if target_env is None else dict(target_env)
    if bootstrap_env is not None:
        # Retain the caller's capture/later-stage secret boundary in our
        # trusted bootstrap too. Its private Python loader may additionally
        # require ONLY the trusted parent's library path; never alter GO env.
        bootstrap_env.pop('LD_LIBRARY_PATH',None)
        if 'LD_LIBRARY_PATH' in os.environ:
            bootstrap_env['LD_LIBRARY_PATH']=os.environ['LD_LIBRARY_PATH']
    env_payload=json.dumps({'env':target_env},separators=(',',':')).encode('utf-8')+b'\n'
    require(len(env_payload)<=1048576,'Workload environment pipe quota exceeded')
    paths=[Path(p).resolve() for p in (stdout_path,stderr_path,receipt_path)]
    require(len(set(paths))==3 and not any(p.exists() for p in paths),'Process output already exists or overlaps')
    started=time.monotonic();proc=None;bootstrap_token=None;threads=[];failure=None;status=None;interrupted=False;go_sent=False
    overflow=threading.Event();counts=[0,0];hashes=[hashlib.sha256(),hashlib.sha256()]
    io_errors=[];cleanup_errors=[];observation_errors=[];actions=[];pipes_closed={};known={};peak=0;out=None;err=None
    result=dict(argv=list(argv),backend='linux-posix',timeout_seconds=seconds,rss_limit_bytes=rss_cap,
        stdout_cap=stdout_cap,stderr_cap=stderr_cap,exit_code=None,failure=None,
        hard_address_space_per_process_bytes=rss_cap,hard_cgroup_memory_bytes=None,hard_job_memory_bytes=None,
        memory_scope='sampled_workload_descendants_excludes_bootstrap',rss_sampling_interval_seconds=.02,
        oom_killed='UNKNOWN',windows_job_used=False,job_handle_kind='posix_process_tree_cleanup_no_windows_job',
        job_limits_verified=False,processgroups_closed=False,job_handle_closed=False,
        rlimit_as_scope='each workload process; inherited by descendants; not aggregate RSS hard limit')
    def update_status(path):
        nonlocal status,peak
        current=read_status(path)
        if current is None:return
        require(current.get('schema')==1 and current.get('bootstrap_pid')==proc.pid,'Invalid owned bootstrap status')
        if bootstrap_token:
            require(current.get('bootstrap_start_ticks')==bootstrap_token['start_ticks'],'Bootstrap identity changed')
        require(isinstance(current.get('known_processes'),list) and len(current['known_processes'])<=4097,'Invalid owned process list')
        for token in current['known_processes']:
            pid=token['pid']
            known[pid]=token
        peak=max(peak,current.get('peak_sampled_tree_rss_bytes',0));status=current
    def signal_bootstrap(sig):
        if bootstrap_token and live(bootstrap_token):
            try:signal_process(bootstrap_token,sig);actions.append('signal_owned_bootstrap_'+str(sig))
            except ProcessLookupError:pass
    with tempfile.TemporaryDirectory(prefix='onecdb2src-posix-') as temporary:
        state_path=Path(temporary)/'status.json'
        try:
            out=paths[0].open('xb');err=paths[1].open('xb')
            command=[sys.executable,'-I','-S','-B',str(Path(__file__).with_name('bootstrap_posix.py')),
                     json.dumps(list(argv)),str(rss_cap),str(state_path),str(os.getpid())]
            proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                  start_new_session=True,env=bootstrap_env)
            bootstrap_token=process(proc.pid)
            require(bootstrap_token is not None,'Bootstrap exited before observation')
            def drain(stream,target,index,cap):
                try:
                    while True:
                        data=stream.read(65536)
                        if not data:return
                        keep=data[:max(0,cap-counts[index])]
                        target.write(keep);hashes[index].update(keep);counts[index]+=len(keep)
                        if len(keep)!=len(data):overflow.set();return
                except BaseException as error:
                    io_errors.append(type(error).__name__);overflow.set()
            threads=[threading.Thread(target=drain,args=(s,t,i,c),daemon=True)
                for i,(s,t,c) in enumerate(((proc.stdout,out,stdout_cap),(proc.stderr,err,stderr_cap)))]
            for thread in threads:thread.start()
            # No workload can launch until the dedicated bootstrap has
            # installed its signal/subreaper guards and published identity.
            while status is None and proc.poll() is None:
                update_status(state_path)
                if time.monotonic()-started>seconds:
                    failure='TIMEOUT';break
                if status is None:time.sleep(.02)
            if not failure and status is None:failure='BOOTSTRAP_START_FAILED'
            if not failure:
                go_sent=True
                # Bootstrap receives the cleaned loader environment. The exact
                # workload environment travels only through the private pipe,
                # never through argv, status, output, or the receipt.
                proc.stdin.write(b'GO\n'+env_payload);proc.stdin.flush();proc.stdin.close()
            while failure is None and proc.poll() is None:
                update_status(state_path)
                if overflow.is_set():failure='OUTPUT_LIMIT_OR_IO'
                if time.monotonic()-started>seconds:failure='TIMEOUT'
                if failure:break
                time.sleep(.02)
        except KeyboardInterrupt:
            failure='CANCELLED';interrupted=True
        except BaseException as error:
            failure=failure or type(error).__name__
            observation_errors.append(type(error).__name__)
        finally:
            if proc:
                if proc.stdin is not None and not proc.stdin.closed:
                    try:proc.stdin.close()
                    except Exception as error:cleanup_errors.append(type(error).__name__)
                if proc.poll() is None:
                    try:
                        signal_bootstrap(signal.SIGTERM);proc.wait(timeout=4)
                    except BaseException as error:
                        cleanup_errors.append('BootstrapGrace:'+type(error).__name__)
                        # Known-identity fallback. Unknown unobserved escapees
                        # mean closure remains UNKNOWN, never synthetic PASS.
                        for token in known.values():
                            try:
                                if live(token):signal_process(token,signal.SIGKILL)
                            except ProcessLookupError:pass
                            except Exception as error:cleanup_errors.append(type(error).__name__)
                        try:signal_bootstrap(signal.SIGKILL);proc.wait(timeout=2)
                        except BaseException as error:cleanup_errors.append(type(error).__name__)
                try:update_status(state_path)
                except Exception as error:observation_errors.append(type(error).__name__)
            for thread in threads:thread.join(timeout=2)
            if any(t.is_alive() for t in threads):failure=failure or 'PIPE_NOT_CLOSED'
            for stream in (out,err):
                if stream is not None:
                    try:stream.close()
                    except Exception as error:io_errors.append(type(error).__name__)
            if overflow.is_set():failure=failure or 'OUTPUT_LIMIT_OR_IO'
            if status:
                failure=failure or status.get('failure')
                observation_errors+=status.get('observation_errors',[])
                cleanup_errors+=status.get('cleanup_errors',[])
            survivors=[]
            try:
                survivors=[t['pid'] for t in known.values() if live(t)]
                if proc and proc.poll() is None:survivors.append(proc.pid)
            except Exception as error:
                observation_errors.append(type(error).__name__);survivors=None
            prelaunch_closed=bool(proc and not go_sent and proc.poll() is not None and survivors==[]
                                  and not cleanup_errors and not observation_errors)
            closed=prelaunch_closed or bool(status and status.get('closed') and status.get('processgroups_closed')
                        and survivors==[] and not cleanup_errors and not observation_errors and proc.poll() is not None)
            if not closed:failure=failure or 'PROCESS_OBSERVATION_UNKNOWN'
            for name in ('stdin','stdout','stderr'):
                stream=getattr(proc,name,None) if proc else None
                if stream is None:pipes_closed[name]=True;continue
                try:
                    if not stream.closed:stream.close()
                    pipes_closed[name]=stream.closed
                except Exception as error:
                    pipes_closed[name]=False;cleanup_errors.append(type(error).__name__)
            if not all(pipes_closed.values()) or cleanup_errors:
                closed=False;failure=failure or 'CLEANUP_FAILURE'
            result.update(exit_code=status.get('target_exit') if status else None,failure=failure,seconds=time.monotonic()-started,
                supervisor_exit=proc.returncode if proc else None,peak_job_rss_bytes=peak,peak_sampled_tree_rss_bytes=peak,
                memory_peak_status='SAMPLED' if known else 'NOT_OBSERVED',observed_pids=sorted(known),
                surviving_pids=survivors if closed or survivors else None,known_surviving_pids=survivors,
                observation_status='OBSERVED' if closed else 'UNKNOWN',observation_errors=observation_errors,
                cleanup_errors=cleanup_errors,job_handle_closed=closed,processgroups_closed=closed,
                pipes_closed=pipes_closed,cleanup_actions=actions,bootstrap_pid=proc.pid if proc else None,
                bootstrap_survived=proc.poll() is None if proc else False,subreaper=bool(status and status.get('subreaper')),
                cpu_affinity=status.get('cpu_affinity') if status else None,cpu_count=len(status.get('cpu_affinity',[])) if status else None,
                post_exit_grace_limit_seconds=.25,post_exit_samples=status.get('post_exit_samples',[]) if status else [],
                stdout=dict(bytes=counts[0],sha256=hashes[0].hexdigest()),stderr=dict(bytes=counts[1],sha256=hashes[1].hexdigest()),
                io_errors=io_errors,cancelled=interrupted)
            result.update(go_sent=go_sent,launch_handshake_completed=go_sent,
                          closure_scope='bootstrap_only_prelaunch' if prelaunch_closed else 'owned_workload_tree')
            with paths[2].open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    return result
