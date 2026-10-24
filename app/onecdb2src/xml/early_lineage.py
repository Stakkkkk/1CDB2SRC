"""Authenticate one closed early main XML validation before late hash readback."""
from pathlib import Path
from ._fast_contract import fact,read,require

EARLY='EARLY_FULL_XML_VALIDATION'


def closed_stage(config,stage):
    from ..cli import require_stage_closure
    root=Path(config['root']).resolve(strict=True);path=root/'_work/jobs'/(stage+'.json');job=read(path)
    require_stage_closure(job,stage,True)
    argv=job.get('argv',[])
    require(job['exit_code']==0 and type(argv) is list and len(argv)>=3
            and argv[-3:-1]==['--_worker',stage] and type(argv[-1]) is str
            and Path(argv[-1])==root/'_work/config.json',
            'Early/main supervisor invocation or exit differs')
    return job,path


def early_main_for_final(config,bound):
    root=bound['root'];directory=bound['proof_root'];pair_path=root/'_work/fast-pair/result.json';pair=read(pair_path)
    require(config.get('side_scheduling')=='verify-overlap' and pair.get('side_scheduling')=='verify-overlap'
            and pair.get('status')=='PAIR_CANDIDATES_GENERATED_REQUIRES_FINAL_VERIFICATION',
            'Completed verification-overlap pair required')
    main,main_job=closed_stage(config,'fast-main');early,early_job=closed_stage(config,'preverify-main')
    require(pair['sides']['main']['job']==main and pair['early_main']['job']==early,
            'Pair/early supervisor evidence differs')
    require(pair['sides']['main']['candidate']==bound['metadata'][str(directory/'result.json')],
            'Main candidate changed since pair generation')
    receipt=directory/'early-verification.json';files=directory/'early-file-verification.json';namespace=directory/'early-namespace-map.json'
    require(pair['early_main']['candidate']==fact(receipt),'Early completion receipt changed')
    value=read(receipt);prior=read(files);mapping=read(namespace)
    require(value.get('status')=='PASS_FAST_SIDE_REQUIRES_COMMON_CF_FINALIZATION' and value.get('readback_phase')==EARLY
            and value['side']=='main' and value['cf']==bound['cf'] and value['profile']==bound['host_profile']
            and value['linux_profile']==bound['linux_profile'] and value['native_policy']==bound['classification']
            and value.get('oracle_inputs')==[] and type(value.get('workers')) is int and value['workers'] in (1,4,8),
            'Earlier full XML identity/policy differs')
    require(value['lineage_snapshot']==bound['metadata'],'Earlier CF/profile/raw/producer lineage changed')
    require(value['files_proof']==fact(files) and value['namespace_map']==fact(namespace)
            and mapping['schema']=='1CDB2SRC_FAST_NAMESPACE_MAP_V1' and mapping['status']=='VERIFIED_FAST_SIDE'
            and mapping['side']=='main' and mapping['cf']==bound['cf']
            and mapping['host_profile']==bound['host_profile'] and mapping['linux_profile']==bound['linux_profile']
            and mapping['native_policy']==bound['classification']
            and mapping['helper_manifest_binding']==bound['helper_binding']
            and mapping['file_facts_sha256']==prior['facts_sha256'],'Earlier file/namespace proof changed')
    require(value['xml_files']==prior['files'] and value['xml_bytes']==prior['bytes'] and value['bsl_files']==prior['bsl_files'],
            'Earlier result/file counts differ')
    paths=(pair_path,main_job,early_job,receipt,files,namespace)
    metadata={str(path):fact(path) for path in paths};bound['metadata'].update(metadata)
    return prior,{'kind':'CLOSED_EARLY_FULL_XML_WITH_FINAL_FRESH_PAYLOAD_HASHES','bindings':metadata}
