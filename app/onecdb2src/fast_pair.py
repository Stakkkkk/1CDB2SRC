"""One transfer-overlap coordinator; never accepts XML or performs Docker cleanup."""
import json,math,os,re,sys,threading,time
from pathlib import Path
from .util import require,save,utc

READY_SCHEMA='1CDB2SRC_TRANSFER_READY_V1'
PAIR_STATUS='PAIR_CANDIDATES_GENERATED_REQUIRES_FINAL_VERIFICATION'


def coordinate(run_side,ready,admit,deadline,emit=lambda event:None,verify_main=None):
    """Only main thread writes events. Every launched supervisor is joined."""
    stop=threading.Event();threads={};done={};results={};errors={}
    def check_errors():
        for side,event in done.items():
            if event.is_set() and side in errors:
                raise ValueError('Pair side failed: '+side+' ('+type(errors[side]).__name__+')') from errors[side]
    def launch(side):
        done[side]=threading.Event()
        def target():
            try:results[side]=(verify_main if side=='preverify-main' else run_side)(side,stop)
            except BaseException as error:
                errors[side]=error;stop.set()
            finally:done[side].set()
        emit({'event':'verification-started' if side=='preverify-main' else 'side-started','side':side,'monotonic':time.monotonic(),'utc':utc()})
        thread=threading.Thread(target=target,name='xml-'+side,daemon=False)
        threads[side]=thread;thread.start()
    try:
        launch('main')
        while True:
            check_errors()
            require(time.monotonic()<deadline,'Pair total deadline expired')
            if 'vendor' not in threads:
                proof=ready()
                if proof is not None:
                    emit({'event':'main-transfer-ready','proof':proof,'monotonic':time.monotonic(),'utc':utc()})
                    admission=admit()
                    require(not stop.is_set(),'Pair cancelled during vendor admission')
                    emit({'event':'vendor-admission','admission':admission,'utc':utc()})
                    launch('vendor')
                elif done['main'].is_set():
                    raise ValueError('Main exited without a bound transfer-ready marker')
            if verify_main is not None and done['main'].is_set() and 'preverify-main' not in threads:
                check_errors();launch('preverify-main')
            if len(done)==(3 if verify_main is not None else 2) and all(event.is_set() for event in done.values()):
                check_errors()
                return results
            time.sleep(.02)
    finally:
        stop.set()
        # Never recover/remove either side's Docker resources while any side
        # supervisor is alive. Outer bounded worker remains the last deadline.
        while any(thread.is_alive() for thread in threads.values()):
            for thread in threads.values():
                try:thread.join(.05)
                except KeyboardInterrupt:stop.set()
        emit({'event':'all-supervisors-joined','utc':utc()})


def transfer_ready(config):
    """Coordination evidence only; partial JSON never opens the vendor gate."""
    from .xml._fast_contract import fact,read
    root=Path(config['root']);directory=root/'_work/fast-main';path=directory/'transfer-ready.json'
    if not path.exists():return None
    require(path.stat().st_size<=16384,'Transfer-ready marker exceeds quota')
    try:
        before=fact(path);marker=read(path)
    except (json.JSONDecodeError,UnicodeDecodeError):return None
    if fact(path)!=before:return None
    require(marker.get('schema')==READY_SCHEMA and marker.get('side')=='main'
            and marker.get('status')=='LINUX_HELPERS_CLOSED_READY_FOR_HOST_TRANSFER', 'Invalid transfer-ready schema')
    contract=read(directory/'contract.json');helper=config['fast_helper']
    helper_path=Path(helper['manifest_path']).resolve(strict=True);helper_fact=fact(helper_path)
    require(helper_fact['sha256']==helper['manifest_sha256'],'Transfer-ready helper manifest changed')
    expected_helper={'path':str(helper_path),'bytes':helper_fact['bytes'],'sha256':helper['manifest_sha256'],
                     'selected_image_id':helper['selected_image_id']}
    expected_cf=read(root/'_work/cf/manifest.json')['main_cf']
    expected_cf={key:expected_cf[key] for key in ('bytes','sha256')}
    require(re.fullmatch('[a-f0-9]{32}',contract['nonce']) is not None
            and marker['nonce']==contract['nonce'] and contract['side']=='main'
            and marker['cf']==contract['cf']==expected_cf,'Transfer-ready source/nonce differs')
    require(marker['contract']==fact(directory/'contract.json')
            and marker['helper']==contract['helper_manifest_binding']==expected_helper,'Transfer-ready closure differs')
    after_path=directory/'helpers-container-after.json'
    require(marker['helpers_after']==fact(after_path),'Transfer-ready closed-helper proof differs')
    state=read(after_path)['State']
    require(state['Running'] is False and state['ExitCode']==0 and state['Pid']==0
            and state.get('OOMKilled',False) is False,'Linux helper is not successfully closed')
    return before


def docker_admission(config,deadline=None):
    """Host workers share outer two CPUs; only one Docker compute may start."""
    from .cli import docker
    def remaining():
        left=60 if deadline is None else min(60,deadline-time.monotonic())
        require(left>0,'Pair admission deadline expired');return left
    info=docker(['info','--format','{{json .}}'],timeout=remaining())
    stats=docker(['stats','--no-stream','--format','{{.CPUPerc}}'],timeout=remaining())
    require(info.returncode==stats.returncode==0,'Cannot observe pair Docker CPU headroom')
    used=0.
    for line in stats.stdout.splitlines():
        value=float(line.strip().removesuffix('%'))/100
        require(math.isfinite(value) and value>=0,'Invalid pair Docker CPU sample');used+=value
    count=json.loads(info.stdout)['NCPU'];require(count-used>=2,'Insufficient pair Docker CPU headroom')
    return {'observed_utc':utc(),'docker_cpu_count':count,'docker_used_cores_estimate':used,
            'host_workers':'shared outer two-CPU affinity','docker_compute_quota':2,'memory_controls':False}


def produce_fast_pair(config):
    from . import cli
    from .control.bounded_process import run
    from .xml import export_native
    from .xml._fast_contract import fact,read
    require(config.get('side_scheduling') in ('transfer-overlap','verify-overlap') and cli.is_fast(config)
            and config.get('runtime_backend')=='docker' and config.get('docker_transfer')=='stream'
            and config.get('assembly_mode')=='adopt' and config.get('memory_controls') is False,'Invalid pair policy')
    root=Path(config['root']);out=root/'_work/fast-pair';out.mkdir()
    started=time.monotonic();deadline=min(config.get('total_deadline_monotonic') or float('inf'),
                                        started+2*config['fast_side_seconds']+90+(config['python_seconds']+45 if config['side_scheduling']=='verify-overlap' else 0))
    export_native.configure(config.get('docker_context'),config.get('docker_socket'))
    journal={'schema':'1CDB2SRC_TRANSFER_OVERLAP_PAIR_V1','status':'RUNNING','started_utc':utc(),
             'memory_controls':False,'side_scheduling':config['side_scheduling'],'events':[],'cleanup_owner':'outer CLI after all side supervisors close'}
    save(out/'result.json',journal)
    def emit(event):
        journal['events'].append(event);save(out/'result.json',journal)
    env={key:value for key,value in os.environ.items() if key not in ('PGPASSWORD','ONECDB2SRC_AUTH_PASSWORD','PYTHONOPTIMIZE')}
    env.update(PYTHONUTF8='1',PYTHONDONTWRITEBYTECODE='1')
    def run_side(side,stop):
        early=side=='preverify-main'
        seconds=min((config['python_seconds'] if early else config['fast_side_seconds'])+45,deadline-time.monotonic())
        require(seconds>0,'No pair side time remains')
        stage=side if early else 'fast-'+side;path=root/'_work/jobs'/stage
        job=run([sys.executable,'-B',str(cli.PACKAGE/'export_1c.py'),'--_worker',stage,str(root/'_work/config.json')],
            path.with_suffix('.stdout'),path.with_suffix('.stderr'),path.with_suffix('.json'),seconds,
            8*1024**2,8*1024**2,rss_cap=None,env=env,cancel_event=stop)
        cli.require_stage_closure(job,stage,True)
        require(job['exit_code']==0,'Pair side process exit failed: '+side)
        candidate=root/'_work/fast-main/early-verification.json' if early else root/'_work'/stage/'result.json'
        expected='PASS_FAST_SIDE_REQUIRES_COMMON_CF_FINALIZATION' if early else 'CANDIDATE_GENERATED_REQUIRES_HOST_VERIFICATION'
        require(read(candidate).get('status')==expected,'Pair side candidate incomplete')
        return {'job':job,'candidate':fact(candidate)}
    try:
        journal['sides']=coordinate(run_side,lambda:transfer_ready(config),lambda:docker_admission(config,deadline),deadline,emit,
            verify_main=run_side if config['side_scheduling']=='verify-overlap' else None)
        if 'preverify-main' in journal['sides']:journal['early_main']=journal['sides'].pop('preverify-main')
        journal['status']=PAIR_STATUS
    except BaseException as error:
        journal.update(status='FAILED',error_type=type(error).__name__,
                       reason=str(error)[:512] if isinstance(error,ValueError) else None);raise
    finally:
        journal.update(finished_utc=utc(),seconds=time.monotonic()-started)
        save(out/'result.json',journal)
