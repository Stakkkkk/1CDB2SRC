"""Two final side supervisors; common acceptance remains in worker.integrity."""
import os,sys,threading,time
from pathlib import Path
from .util import fact,read,require,save,utc

SIDE_STATUS='SIDE_VERIFIED_REQUIRES_CLOSED_PAIR_AND_COMMON_FINALIZATION'
PAIR_STATUS='CLOSED_FINAL_PAIR_REQUIRES_COMMON_FINALIZATION'


def side_workers(config,side):
    require(config.get('final_verification')=='parallel' and config.get('docker_mode')=='fast'
            and config.get('runtime_backend')=='docker' and config.get('assembly_mode')=='adopt'
            and config.get('memory_controls') is False,'Invalid parallel final verification policy')
    workers=config.get('readback_workers',4)
    require(type(workers) is int and workers==8,'Parallel final verification requires 8 workers')
    require(side in ('main','vendor'),'Invalid final verification side')
    split=config.get('final_worker_split','vendor-heavy')
    require(split in ('balanced','vendor-heavy'),'Unknown final worker split')
    # Balanced is a research control, not a faster-mode claim.
    return {'main':2,'vendor':6}[side] if split=='vendor-heavy' else 4


def coordinate(run_side,deadline,emit=lambda event:None):
    stop=threading.Event();threads={};done={};results={};errors={}
    def launch(side):
        done[side]=threading.Event()
        def target():
            try:results[side]=run_side(side,stop)
            except BaseException as error:errors[side]=error;stop.set()
            finally:done[side].set()
        thread=threading.Thread(target=target,name='final-'+side,daemon=False)
        emit({'event':'side-started','side':side,'utc':utc(),'monotonic':time.monotonic()})
        threads[side]=thread;thread.start()
    try:
        for side in ('main','vendor'):launch(side)
        while True:
            for side,event in done.items():
                if event.is_set() and side in errors:
                    raise ValueError('Final side failed: '+side+' ('+type(errors[side]).__name__+')') from errors[side]
            require(time.monotonic()<deadline,'Final pair deadline expired')
            if all(event.is_set() for event in done.values()):return results
            time.sleep(.02)
    finally:
        stop.set()
        while any(thread.is_alive() for thread in threads.values()):
            for thread in threads.values():
                try:thread.join(.05)
                except KeyboardInterrupt:stop.set()
        emit({'event':'all-supervisors-joined','utc':utc()})


def collect(config,completed):
    """Rebind actual closed jobs and their freshly sealed side receipts."""
    from .xml.early_lineage import closed_stage
    root=Path(config['root']);require(set(completed)=={'main','vendor'},'Incomplete final pair')
    results={};limitations=[]
    for side in ('main','vendor'):
        job,_=closed_stage(config,'integrity-'+side)
        row=completed[side];path=root/'_work/final-pair'/(side+'.json')
        require(row['job']==job and fact(path)==row['candidate'],'Final side job or receipt changed')
        value=read(path)
        require(value.get('status')==SIDE_STATUS and value.get('side')==side and value.get('oracle_inputs')==[],
                'Final side receipt incomplete')
        result=value['result'];verified=result['fast_verification']
        require(verified['status']=='PASS_FAST_SIDE_REQUIRES_COMMON_CF_FINALIZATION' and verified['side']==side
                and verified['workers']==side_workers(config,side),'Final side verification policy differs')
        require(result['cf']==verified['cf'] and result['profile']==verified['profile'],'Final side CF/profile differs')
        require(fact(path)==row['candidate'],'Final side receipt changed during collection')
        results[side]=result;limitations.extend(value['limitations'])
    return results,limitations


def verify_pair(config):
    from . import cli
    from .control.bounded_process import run
    workers={side:side_workers(config,side) for side in ('main','vendor')};root=Path(config['root']);out=root/'_work/final-pair';out.mkdir()
    started=time.monotonic();deadline=min(config.get('total_deadline_monotonic') or float('inf'),
                                        started+2*config['python_seconds']+120)
    bindings={str(path):fact(path) for path in (root/'_work/config.json',root/'_work/cf/manifest.json')}
    journal={'status':'RUNNING','started_utc':utc(),'events':[],'workers_per_side':workers,
             'aggregate_workers':sum(workers.values()),'requested_workers':config.get('readback_workers',4),
             'cpu_policy':'both children inherit the same outer two-CPU affinity','memory_controls':False}
    save(out/'result.json',journal)
    def emit(event):journal['events'].append(event);save(out/'result.json',journal)
    env={k:v for k,v in os.environ.items() if k not in ('PGPASSWORD','ONECDB2SRC_AUTH_PASSWORD','PYTHONOPTIMIZE')}
    env.update(PYTHONUTF8='1',PYTHONDONTWRITEBYTECODE='1')
    def run_side(side,stop):
        seconds=min(config['python_seconds']+45,deadline-time.monotonic())
        require(seconds>0,'No final side time remains')
        stage='integrity-'+side;path=root/'_work/jobs'/stage
        job=run([sys.executable,'-B',str(cli.PACKAGE/'export_1c.py'),'--_worker',stage,str(root/'_work/config.json')],
            path.with_suffix('.stdout'),path.with_suffix('.stderr'),path.with_suffix('.json'),seconds,
            8*1024**2,8*1024**2,rss_cap=None,env=env,cancel_event=stop)
        cli.require_stage_closure(job,stage,True)
        require(job['exit_code']==0,'Final side process exit failed: '+side)
        candidate=out/(side+'.json');require(read(candidate).get('status')==SIDE_STATUS,'Final side incomplete')
        return {'job':job,'candidate':fact(candidate)}
    try:
        journal['sides']=coordinate(run_side,deadline,emit)
        result=collect(config,journal['sides'])
        require(all(fact(path)==value for path,value in bindings.items()),'Final shared config/CF manifest changed')
        journal['status']=PAIR_STATUS
        return result
    except BaseException as error:
        journal.update(status='FAILED',error_type=type(error).__name__,reason=str(error)[:512] if isinstance(error,ValueError) else None)
        raise
    finally:
        journal.update(seconds=time.monotonic()-started,finished_utc=utc());save(out/'result.json',journal)
