"""Closed classification of the exact engine's complete/sole-opaque outcomes."""
import re
from collections import Counter
from .util import require


def process_outcome(receipt):
    """Backend evidence stays distinct; native processes never impersonate containers."""
    require(not receipt.get('cleanup_error'),'Native cleanup failed')
    process=receipt['process']
    if receipt.get('runtime_backend','docker')=='native':
        cleanup=receipt.get('cleanup',{})
        job=process.get('job',{})
        require(cleanup.get('confirmed') is True and cleanup.get('surviving_pids')==[],'Local process cleanup unconfirmed')
        require(job.get('failure') is None and job.get('surviving_pids')==[] and not job.get('cleanup_errors') and job.get('observation_status')=='OBSERVED','Local process supervision failed')
        require(job.get('processgroups_closed') is True,'Local engine process groups not closed')
        require(receipt.get('memory_oom_status')=='NOT_OBSERVED','Unexpected local memory evidence')
        raw=process.get('exit_code')
        require(type(raw) is int and raw==job.get('exit_code'),'Local engine exit receipt mismatch')
        return raw,raw
    require(receipt.get('runtime_backend','docker')=='docker','Unknown runtime backend')
    require(receipt.get('container_removed') is True,'Native container cleanup unconfirmed')
    state=process['container_state']
    require(not state.get('Running') and state.get('OOMKilled') is False and not state.get('Error'),'Native infrastructure failure')
    return state.get('ExitCode'),process.get('docker_start_exit')

def classify(receipt,report,stored_sizes,job_exit,profile):
    raw,attach=process_outcome(receipt)
    require(receipt.get('profile')==profile and receipt['engine'].get('profile_id')==profile['profile_id'],'Native selected profile mismatch')
    require(receipt['engine'].get('platform_profile')==profile['platform_profile'] and receipt['engine'].get('xml_version')==profile['xml_version'],'Native profile receipt mismatch')
    require(report.get('command')=='export' and report.get('source_version')==profile['xml_version'] and report.get('export',{}).get('source_version')==profile['xml_version'],'Native reported edition mismatch')
    storage=report['export']['storage'];rows=storage['entries']
    require(isinstance(rows,list),'Native entries missing')
    for key in ('supported','opaque','failed','logical_entries','physical_entries'):
        require(type(storage.get(key)) is int and storage[key]>=0,'Invalid native count')
    require(storage['logical_entries']>0 and storage['physical_entries']>=storage['logical_entries'],'Invalid native inventory counts')
    require(all(isinstance(row,dict) and row.get('disposition') in ('supported','opaque','failed') for row in rows),'Unknown native disposition')
    counts=Counter(row['disposition'] for row in rows)
    require(all(counts[k]==storage[k] for k in ('supported','opaque','failed')),'Native storage counts inconsistent')
    names=[row.get('logical_name') for row in rows]
    require(all(isinstance(n,str) for n in names) and len(set(names))==len(rows)==storage['logical_entries'],'Duplicate/incomplete native report')
    require(set(names)==set(stored_sizes),'Native/CF membership mismatch')
    require(all(type(row.get('packed_bytes')) is int and row['packed_bytes']==stored_sizes[row['logical_name']] for row in rows),'Native/CF stored length mismatch')
    require(all(type(row.get('part_count')) is int and row['part_count']>0 for row in rows),'Invalid native part count')
    require(sum(row['part_count'] for row in rows)==storage['physical_entries'],'Native physical part count mismatch')
    require(storage['failed']==0,'Native failed records')
    errors=report.get('errors');require(isinstance(errors,list),'Native errors list missing')
    if raw==0:
        require(attach==0 and job_exit==0 and report.get('ok') is True and storage['opaque']==0 and errors==[],'Inconsistent native success')
        return {'status':'NATIVE_COMPLETE','raw_exit':0,'opaque':0,'profile_id':profile['profile_id'],'raw_errors':errors}
    require(raw==attach==2 and job_exit==1 and report.get('ok') is False and storage['opaque']>0 and receipt.get('status')=='FAILED','Not the sole opaque-refusal process mode')
    require(len(errors)==1 and isinstance(errors[0],dict) and set(errors[0])=={'code','message'},'Unexpected/mixed native errors')
    error=errors[0]
    require(error['code']=='opaque_export_refused' and isinstance(error['message'],str),'Unknown native error')
    expected=f"--fail-on-opaque refused {storage['opaque']} opaque CF storage entries; see export.storage.entries for names and reasons; no index was published"
    require(error['message']==expected,'Opaque refusal diagnostic/count mismatch')
    return {'status':'NATIVE_OPAQUE_ONLY','raw_exit':2,'opaque':storage['opaque'],'raw_status':receipt['status'],'profile_id':profile['profile_id'],'raw_errors':errors}
