"""Windows Job supervisor: binary files, hard byte caps, RSS/deadline, child cleanup."""
def require(condition,message):
 if not condition:raise ValueError(message)

import ctypes,ctypes.wintypes as wt,hashlib,json,os,pathlib,subprocess,sys,threading,time
K=ctypes.WinDLL('kernel32',use_last_error=True);P=ctypes.WinDLL('psapi',use_last_error=True)
K.CreateJobObjectW.argtypes=[ctypes.c_void_p,wt.LPCWSTR];K.CreateJobObjectW.restype=wt.HANDLE
K.AssignProcessToJobObject.argtypes=[wt.HANDLE,wt.HANDLE];K.AssignProcessToJobObject.restype=wt.BOOL
K.QueryInformationJobObject.argtypes=[wt.HANDLE,ctypes.c_int,ctypes.c_void_p,wt.DWORD,ctypes.c_void_p];K.QueryInformationJobObject.restype=wt.BOOL
K.SetInformationJobObject.argtypes=[wt.HANDLE,ctypes.c_int,ctypes.c_void_p,wt.DWORD];K.SetInformationJobObject.restype=wt.BOOL
K.TerminateJobObject.argtypes=[wt.HANDLE,wt.UINT];K.CloseHandle.argtypes=[wt.HANDLE]
K.WaitForSingleObject.argtypes=[wt.HANDLE,wt.DWORD];K.WaitForSingleObject.restype=wt.DWORD
K.GetCurrentProcess.restype=wt.HANDLE
K.GetProcessAffinityMask.argtypes=[wt.HANDLE,ctypes.POINTER(ctypes.c_size_t),ctypes.POINTER(ctypes.c_size_t)];K.GetProcessAffinityMask.restype=wt.BOOL
K.OpenProcess.argtypes=[wt.DWORD,wt.BOOL,wt.DWORD];K.OpenProcess.restype=wt.HANDLE
class BASIC(ctypes.Structure):_fields_=[('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),('flags',wt.DWORD),('min_working',ctypes.c_size_t),('max_working',ctypes.c_size_t),('active_limit',wt.DWORD),('affinity',ctypes.c_size_t),('priority',wt.DWORD),('scheduling',wt.DWORD)]
class IO(ctypes.Structure):_fields_=[(n,ctypes.c_ulonglong) for n in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
class EXTENDED(ctypes.Structure):_fields_=[('basic',BASIC),('io',IO),('process_memory',ctypes.c_size_t),('job_memory',ctypes.c_size_t),('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]
class PIDS(ctypes.Structure):_fields_=[('assigned',wt.DWORD),('listed',wt.DWORD),('ids',ctypes.c_size_t*64)]
class PMC(ctypes.Structure):_fields_=[('cb',wt.DWORD),('faults',wt.DWORD),('peak_rss',ctypes.c_size_t),('rss',ctypes.c_size_t),('peak_paged',ctypes.c_size_t),('paged',ctypes.c_size_t),('peak_nonpaged',ctypes.c_size_t),('nonpaged',ctypes.c_size_t),('pagefile',ctypes.c_size_t),('peak_pagefile',ctypes.c_size_t)]
P.GetProcessMemoryInfo.argtypes=[wt.HANDLE,ctypes.POINTER(PMC),wt.DWORD];P.GetProcessMemoryInfo.restype=wt.BOOL
def members(job):
 x=PIDS();require(K.QueryInformationJobObject(job,3,ctypes.byref(x),ctypes.sizeof(x),None),ctypes.get_last_error());require(x.assigned<=64,'Bounded process invariant failed')
 alive=[]
 for pid in list(x.ids)[:x.listed]:
  handle=K.OpenProcess(0x100000,False,pid) # SYNCHRONIZE only
  if not handle:
   error=ctypes.get_last_error()
   if error==87:continue # already exited/no such PID
   raise OSError(error,'Cannot observe owned Job member')
  try:
   state=K.WaitForSingleObject(handle,0)
   if state==258:alive.append(pid) # WAIT_TIMEOUT: still running
   elif state!=0:raise OSError('Unexpected owned process wait state '+str(state))
  finally:K.CloseHandle(handle)
 return alive
def rss(pid):
 handle=K.OpenProcess(0x410,False,pid)
 if not handle:return 0
 try:
  x=PMC();x.cb=ctypes.sizeof(x)
  return x.rss if P.GetProcessMemoryInfo(handle,ctypes.byref(x),x.cb) else 0
 finally:K.CloseHandle(handle)
def run(argv,stdout_path,stderr_path,receipt_path,seconds,stdout_cap,stderr_cap,rss_cap=1073741824,env=None):
 require(seconds>0 and stdout_cap>=0 and stderr_cap>=0 and (rss_cap is None or type(rss_cap) is int and rss_cap>0),'Bounded process invariant failed')
 paths=[pathlib.Path(x) for x in (stdout_path,stderr_path,receipt_path)];require(len(set(paths))==3 and not any(p.exists() for p in paths),'Bounded process invariant failed')
 memory_enabled=rss_cap is not None
 start=time.monotonic();job=None;assigned=False;go_sent=False;cleanup_actions=[]
 out=None;err=None
 proc=None;threads=[];failure=None;overflow=threading.Event();io_errors=[];counts=[0,0];hashes=[hashlib.sha256(),hashlib.sha256()];peak=0 if memory_enabled else None;seen=set()
 observation_errors=[];cleanup_errors=[];observation_unknown=False;post_exit_samples=[]
 def observe(label):
  nonlocal observation_unknown
  try:return members(job) if job else []
  except BaseException as e:
   observation_unknown=True;observation_errors.append(dict(stage=label,error=type(e).__name__+': '+str(e)));raise
 result=dict(argv=argv,timeout_seconds=seconds,rss_limit_bytes=rss_cap,memory_controls=memory_enabled,rss_monitoring=memory_enabled,stdout_cap=stdout_cap,stderr_cap=stderr_cap,exit_code=None,failure=None,surviving_pids=[])
 try:
  job=K.CreateJobObjectW(None,None);require(job,'Bounded process invariant failed')
  allowed=ctypes.c_size_t();system=ctypes.c_size_t()
  require(K.GetProcessAffinityMask(K.GetCurrentProcess(),ctypes.byref(allowed),ctypes.byref(system)),'Bounded process invariant failed')
  selected=[1<<i for i in range(ctypes.sizeof(ctypes.c_size_t)*8) if allowed.value & (1<<i)][:2];require(len(selected)==2,'Bounded process invariant failed')
  limits=EXTENDED();limits.basic.flags=0x2000|0x10 # kill-on-close and CPU affinity always
  if memory_enabled:limits.basic.flags|=0x100|0x200 # explicit-cap contract only
  limits.process_memory=rss_cap if memory_enabled else 0;limits.job_memory=rss_cap if memory_enabled else 0;limits.basic.affinity=sum(selected)
  result.update(cpu_affinity_mask=limits.basic.affinity,cpu_count=2,hard_job_memory_bytes=rss_cap)
  require(K.SetInformationJobObject(job,9,ctypes.byref(limits),ctypes.sizeof(limits)),ctypes.get_last_error())
  verified=EXTENDED();require(K.QueryInformationJobObject(job,9,ctypes.byref(verified),ctypes.sizeof(verified),None),'Bounded process invariant failed')
  require(verified.basic.flags==limits.basic.flags and verified.basic.affinity==limits.basic.affinity and verified.job_memory==limits.job_memory and verified.process_memory==limits.process_memory,'Bounded process invariant failed')
  result['job_limits_verified']=True
  out=paths[0].open('xb');err=paths[1].open('xb')
  proc=subprocess.Popen([sys.executable,'-I','-B',str(pathlib.Path(__file__).with_name('bootstrap.py')),json.dumps(argv)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
  seen.add(proc.pid);assigned=bool(K.AssignProcessToJobObject(job,wt.HANDLE(int(proc._handle))))
  require(assigned,ctypes.get_last_error())
  def drain(stream,target,index,cap):
   try:
    while True:
     data=stream.read(65536)
     if not data:return
     keep=data[:max(0,cap-counts[index])];target.write(keep);hashes[index].update(keep);counts[index]+=len(keep)
     if len(keep)!=len(data):overflow.set();return
   except BaseException as e:io_errors.append(repr(e));overflow.set()
  threads=[threading.Thread(target=drain,args=(s,t,i,c),daemon=True) for i,(s,t,c) in enumerate(((proc.stdout,out,stdout_cap),(proc.stderr,err,stderr_cap)))]
  for t in threads:t.start()
  proc.stdin.write(b'GO\n');proc.stdin.flush();go_sent=True;proc.stdin.close()
  while proc.poll() is None:
   pids=observe('running');seen.update(pids)
   if memory_enabled:
    used=sum(rss(p) for p in pids);peak=max(peak,used)
    if used>rss_cap:failure='RSS_LIMIT'
   if overflow.is_set():failure='OUTPUT_LIMIT_OR_IO'
   if time.monotonic()-start>seconds:failure='TIMEOUT'
   if failure:K.TerminateJobObject(job,124);proc.wait(5);break
   time.sleep(.02)
  grace_started=time.monotonic();grace_deadline=min(start+seconds,grace_started+.25)
  while True:
   post_exit_pids=observe('post_exit_grace');seen.update(post_exit_pids)
   used=None
   if memory_enabled:
    used=sum(rss(p) for p in post_exit_pids);peak=max(peak,used)
    if used>rss_cap:failure=failure or 'RSS_LIMIT'
   post_exit_samples.append(dict(seconds=time.monotonic()-grace_started,pids=post_exit_pids,rss_bytes=used))
   if overflow.is_set():failure=failure or 'OUTPUT_LIMIT_OR_IO'
   if not post_exit_pids:break
   if failure or time.monotonic()>=grace_deadline:
    failure=failure or 'SURVIVING_CHILDREN';K.TerminateJobObject(job,125);break
   time.sleep(min(.02,max(0,grace_deadline-time.monotonic())))
  for t in threads:t.join(5)
  if any(t.is_alive() for t in threads):failure=failure or 'PIPE_NOT_CLOSED'
  if overflow.is_set():failure=failure or 'OUTPUT_LIMIT_OR_IO'
 except BaseException as e:
  failure=failure or type(e).__name__+': '+str(e)
 finally:
  remaining=None;bootstrap_alive=None;job_closed=None;pipes_closed={}
  def cleanup_call(label,fn,default=None):
   nonlocal failure
   try:return fn()
   except BaseException as e:
    cleanup_errors.append(dict(action=label,error=type(e).__name__+': '+str(e)))
    failure=failure or 'CLEANUP_FAILURE';return default
  def terminate_job():
   require(K.TerminateJobObject(job,126),ctypes.get_last_error())
   cleanup_actions.append('terminate_owned_job');return True
  def close_job():
   require(K.CloseHandle(job),ctypes.get_last_error())
   cleanup_actions.append('close_owned_job');return True
  def direct_terminate():
   proc.terminate();cleanup_actions.append('terminate_unassigned_bootstrap' if not assigned else 'terminate_owned_bootstrap');return True
  def kill_bootstrap():
   proc.kill();cleanup_actions.append('kill_owned_bootstrap_fallback');return True
  try:
   # No observation result is allowed to bypass termination or outer closure.
   if proc is not None:
    if proc.stdin is not None and not proc.stdin.closed:
     cleanup_call('close_go_pipe',proc.stdin.close);cleanup_actions.append('close_go_pipe')
    bootstrap_alive=cleanup_call('poll_bootstrap',lambda:proc.poll() is None)
    if bootstrap_alive is not False:
     terminated=cleanup_call('terminate_job',terminate_job,False) if assigned and job else False
     if not terminated:cleanup_call('terminate_bootstrap',direct_terminate)
     waited=cleanup_call('wait_bootstrap',lambda:(proc.wait(5),True)[1],False)
     if not waited:
      cleanup_call('kill_bootstrap',kill_bootstrap)
      cleanup_call('wait_bootstrap_after_kill',lambda:proc.wait(5))
   remaining=cleanup_call('observe_cleanup',lambda:observe('cleanup_before_close'))
   if job and (remaining is None or remaining):cleanup_call('terminate_remaining_job',terminate_job)
   for t in threads:cleanup_call('join_drain',lambda t=t:t.join(1))
   remaining=cleanup_call('observe_cleanup_final',lambda:observe('cleanup_final'))
   bootstrap_alive=cleanup_call('poll_bootstrap_final',lambda:proc.poll() is None) if proc is not None else False
   if bootstrap_alive:failure=failure or 'SURVIVING_PROCESSES'
   if remaining:failure=failure or 'SURVIVING_PROCESSES'
  except BaseException as e:
   cleanup_errors.append(dict(action='cleanup_unexpected',error=type(e).__name__+': '+str(e)));failure=failure or 'CLEANUP_FAILURE';observation_unknown=True
  finally:
   # Closing the Job enables KILL_ON_JOB_CLOSE even if all queries failed.
   try:
    if job:job_closed=cleanup_call('close_job',close_job,False)
   finally:
    if proc is not None:
     for name in ('stdin','stdout','stderr'):
      pipe=getattr(proc,name,None)
      if pipe is None:pipes_closed[name]=True;continue
      try:
       if not pipe.closed:cleanup_call('close_'+name,pipe.close)
       pipes_closed[name]=pipe.closed
      except BaseException as e:
       pipes_closed[name]=None;cleanup_errors.append(dict(action='close_'+name,error=repr(e)));failure=failure or 'CLEANUP_FAILURE'
   # Drain targets must outlive the consumer threads, including cancellation.
   # Job termination and source-pipe closure above unblock normal drains first.
   for t in threads:cleanup_call('join_drain_after_pipe_close',lambda t=t:t.join(1))
   drains_joined=not any(t.is_alive() for t in threads)
   if not drains_joined:
    failure=failure or 'PIPE_NOT_CLOSED'
    cleanup_errors.append(dict(action='drain_target_lifetime',error='DRAIN_NOT_JOINED_TARGET_RETAINED_OPEN'))
   target_streams_closed={}
   for label,target in (('stdout',out),('stderr',err)):
    if target is None:target_streams_closed[label]=True;continue
    # Never close a target under a live writer. Unknown closure stays explicit.
    if drains_joined and not target.closed:cleanup_call('close_'+label+'_target',target.close)
    target_streams_closed[label]=target.closed
   if not all(target_streams_closed.values()):failure=failure or 'PIPE_NOT_CLOSED'
   if observation_unknown or bootstrap_alive is None:
    failure=failure or 'PROCESS_OBSERVATION_UNKNOWN';survivors=None
   else:survivors=sorted(set(remaining or [])|({proc.pid} if bootstrap_alive else set()))
   result.update(exit_code=proc.returncode if proc else None,failure=failure,seconds=time.monotonic()-start,peak_job_rss_bytes=peak,observed_pids=sorted(seen),surviving_pids=survivors,known_surviving_pids=sorted(set(remaining or [])|({proc.pid} if bootstrap_alive else set())),observation_status='UNKNOWN' if observation_unknown or bootstrap_alive is None else 'OBSERVED',observation_errors=observation_errors,post_exit_grace_limit_seconds=.25,post_exit_samples=post_exit_samples,cleanup_errors=cleanup_errors,job_handle_closed=job_closed,pipes_closed=pipes_closed,target_streams_closed=target_streams_closed,drains_joined=drains_joined,stdout=dict(bytes=counts[0],sha256=hashes[0].hexdigest()),stderr=dict(bytes=counts[1],sha256=hashes[1].hexdigest()),io_errors=io_errors,job_assigned_before_child_launch=assigned,go_sent=go_sent,bootstrap_pid=proc.pid if proc else None,bootstrap_survived=bootstrap_alive,cleanup_actions=cleanup_actions)
   with paths[2].open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')

 return result
