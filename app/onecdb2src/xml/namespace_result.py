"""Bind immutable Linux receipts to host CF, then perform exactly one V readback."""
import hashlib
from pathlib import Path
import re

from .. import profiles
from ..nativecf.cf_source import CFSource
from ..native_policy import classify
from . import export_native
from ._fast_contract import (CONTRACT_SCHEMA, NAMESPACE_SCHEMA, PROOF_SCHEMA,
    require, fact, read, save_new, load_helper_manifest)


def _caps(values):
    require(type(values) is list and all(type(value) is str for value in values), 'Invalid raw capabilities')
    return [value[4:] if value.startswith('CAP_') else value for value in values]


def _container(value, row, result, side, exited):
    require(value['Id'] == row['cid'] and value['Name'] == '/' + row['name'], 'Raw container CID/name mismatch')
    require(row['name'] == 'onecdb2src-fast-' + result['nonce'] + '-' + row['role'], 'Unexpected side role name')
    config, host = value['Config'], value['HostConfig']
    require(config['Image'] == row['image'] and config['Labels'].get('onecdb2src.fast.nonce') == result['nonce'],
            'Raw container image/owner mismatch')
    root_role = row['role'] == 'owner-init'
    require(config['User'] == ('0:0' if root_role else '65532:65532')
            and host['Memory'] == 0 and host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True
            and host['NanoCpus'] == 2 * 10**9 and _caps(host['CapDrop']) == ['ALL']
            and _caps(host.get('CapAdd') or []) == (['CHOWN'] if root_role else [])
            and any(item in ('no-new-privileges', 'no-new-privileges:true') for item in host['SecurityOpt']),
            'Raw process resource/isolation contract differs')
    jobs = [mount for mount in value['Mounts'] if mount['Destination'] == '/job']
    staged=result['cf_transport']=='STAGED_OWN_READONLY_VOLUME'
    if row['role']=='cf-stage':
        cfs=[mount for mount in value['Mounts'] if mount['Destination']=='/cf']
        require(len(cfs)==len(value['Mounts'])==1 and cfs[0]['Type']=='volume'
                and cfs[0]['Name']==result['cf_volume'] and cfs[0]['RW'] is True,'Raw CF staging mount differs')
    else:
        require(len(jobs) == 1 and jobs[0]['Type'] == 'volume' and jobs[0]['Name'] == result['volume']
                and jobs[0]['RW'] is True, 'Raw job volume differs')
    if root_role:
        require(len(value['Mounts']) == 1, 'Owner initialization had unexpected bind')
    elif row['role']!='cf-stage':
        cfs=[mount for mount in value['Mounts'] if mount['Destination']==('/job/_work/cf/'+side if staged
                else '/job/_work/cf/'+side+'/source.cf')]
        require(len(cfs)==1 and cfs[0]['RW'] is False
                and cfs[0]['Type']==('volume' if staged else 'bind')
                and (not staged or cfs[0]['Name']==result['cf_volume']),'Raw readonly CF mount differs')
    if row['role'] in ('prepare','helpers'):
        contracts=[mount for mount in value['Mounts'] if mount['Destination']=='/contract.json']
        require(len(value['Mounts'])==3 and len(contracts)==1 and contracts[0]['Type']=='bind'
                and contracts[0]['RW'] is False,'Raw readonly contract differs')
    elif row['role']=='engine':
        require(len(value['Mounts'])==2,'Raw engine has unexpected mounts')
    state = value['State']
    require(state['Running'] is False and state['OOMKilled'] is False and not state['Error'], 'Writer closure unknown')
    if exited:
        require(state.get('Status') == 'exited' and state.get('Pid') == 0
                and not state.get('Paused') and not state.get('Restarting') and not state.get('Dead')
                and state.get('StartedAt') and state.get('FinishedAt')
                and not state['StartedAt'].startswith('0001') and not state['FinishedAt'].startswith('0001'),
                'Actual writer lifecycle incomplete')
        require(state['ExitCode'] in ((0, 2) if row['role'] == 'engine' else (0,)), 'Actual writer exit failed')


def bind_fast_side(config, side):
    require(side in ('main', 'vendor'), 'Unknown fast side')
    helper, helper_binding = load_helper_manifest(config)
    root = Path(config['root']).resolve(strict=True)
    proof_root = root / '_work' / ('fast-' + side)
    output = root / side
    cf = root / '_work/cf' / side / 'source.cf'
    host_profile_path = root / '_work/profiles' / (side + '.json')
    host_profile = profiles.load(host_profile_path, cf)
    cf_fact = {'bytes': host_profile['cf_bytes'], 'sha256': host_profile['cf_sha256']}
    required = ['result.json', 'contract.json', 'host-profile-binding.json', 'linux-profile.json', 'namespace.json',
        'native-receipt.json', 'native-classification.json', 'native.stdout', 'native.stderr',
        'owner-init.stdout', 'owner-init-container-before.json', 'owner-init-container-after.json',
        'prepare-container-before.json', 'prepare-container-after.json',
        'native-container-before.json', 'native-container-after.json',
        'helpers-container-before.json', 'helpers-container-after.json', 'linux-proof.json',
        'docker-context.json', 'docker-daemon.json', 'image-engine.json', 'image-helper.json']
    metadata = {str(proof_root / name): fact(proof_root / name) for name in required}
    for path in (output / 'receipt.json', output / 'files.jsonl', host_profile_path, Path(helper_binding['path'])):
        metadata[str(path)] = fact(path)
    result = read(proof_root / 'result.json')
    require(result['status'] == 'CANDIDATE_GENERATED_REQUIRES_HOST_VERIFICATION'
            and result['cleanup_errors'] == [] and result['volume_removed'] is True
            and result['memory_controls'] is False and result['oracle_inputs'] == [], 'Generation/cleanup not complete')
    require(re.fullmatch('[a-f0-9]{32}', result['nonce']) and result['volume'] == 'onecdb2src-fast-' + result['nonce'],
            'Unknown fast side owner')
    require(result['source_cf'] == {'host_path': str(cf), **cf_fact}, 'Host CF/result binding differs')
    staged=result['cf_transport']=='STAGED_OWN_READONLY_VOLUME'
    require(result['cf_transport'] in ('STAGED_OWN_READONLY_VOLUME','HOST_READONLY_BIND')
            and staged==(config.get('fast_cf_transport','volume')=='volume'),'CF transport changed')
    if staged:
        require(result['cf_volume']==result['volume']+'-cf' and result['cf_copy_source']==cf_fact
                and result['cf_volume_removed'] is True,'Own staged CF cleanup/source incomplete')
        cf_absence=result['cf_volume_absence_confirmation']
        require(cf_absence['kind']=='EXACT_NAMED_DOCKER_MISSING_DIAGNOSTIC'
                and cf_absence['reference']==result['cf_volume']
                and cf_absence['operation']==['volume','inspect',result['cf_volume']]
                and re.fullmatch('[a-f0-9]{64}',cf_absence['stderr_sha256']),'CF volume absence proof missing')
        for filename in ('cf-stage-container-before.json','cf-stage-container-after.json'):
            metadata[str(proof_root/filename)]=fact(proof_root/filename)
    absence = result['volume_absence_confirmation']
    require(absence['kind'] == 'EXACT_NAMED_DOCKER_MISSING_DIAGNOSTIC'
            and absence['reference'] == result['volume']
            and absence['operation'] == ['volume', 'inspect', result['volume']]
            and re.fullmatch('[a-f0-9]{64}', absence['stderr_sha256']), 'Volume absence proof missing')
    contract = read(proof_root / 'contract.json')
    require(contract == {'schema': CONTRACT_SCHEMA, 'namespace': '/job', 'side': side,
        'nonce': result['nonce'], 'requested_platform': host_profile['requested_platform'], 'cf': cf_fact,
        'provider': config['db']['provider'], 'oracle_inputs': [], 'memory_controls': False,
        'engine_image': config['runtime']['image_id'], 'helper_manifest_binding': helper_binding,
        'source_files': helper['source_files'], 'runtime_files': helper['runtime_files']}, 'Original contract differs')
    require(read(proof_root / 'host-profile-binding.json') == {'path': str(host_profile_path),
        'fact': fact(host_profile_path), 'profile': host_profile}, 'Original host profile binding changed')
    linux_profile = read(proof_root / 'linux-profile.json')
    linux_cf = '/job/_work/cf/' + side + '/source.cf'
    linux_profile_path = '/job/_work/profiles/' + side + '.json'
    require(set(linux_profile) == profiles.KEYS and profiles._id(linux_profile) == linux_profile['profile_id']
            and linux_profile['cf_path'] == linux_cf, 'Canonical Linux profile invalid')
    semantics = lambda profile: {key: value for key, value in profile.items() if key not in ('cf_path', 'profile_id')}
    require(semantics(host_profile) == semantics(linux_profile), 'Host/Linux profile semantics differ')
    namespace = read(proof_root / 'namespace.json')
    require(namespace == {'schema': NAMESPACE_SCHEMA, 'contract_sha256': fact(proof_root / 'contract.json')['sha256'],
        'cf_path': linux_cf, 'profile_path': linux_profile_path, 'profile_fact': fact(proof_root / 'linux-profile.json'),
        'profile': linux_profile, 'originals_rewritten': False}, 'Original Linux namespace differs')
    native = read(proof_root / 'native-receipt.json')
    expected_profile_ref = {'path': linux_profile_path, 'sha256': fact(proof_root / 'linux-profile.json')['sha256']}
    require(native['source'] == {'path': linux_cf, **cf_fact, 'sha256_after': cf_fact['sha256']}
            and native['native_xml'] == '/job/_work/native-' + side + '/tree/xml'
            and native['profile'] == linux_profile and native['profile_receipt'] == expected_profile_ref
            and native['engine']['image_id'] == config['runtime']['image_id']
            and native['engine']['binary'] == config['runtime']['binary']['path']
            and native['producer_sha256'] == helper['source_files']['onecdb2src/xml/fast_docker.py']['sha256'],
            'Native source/runtime/profile bindings differ')
    rows = result['containers']
    expected_roles={'init','owner-init','prepare','engine','helpers'}|({'cf-stage'} if staged else set())
    require(len(rows) == len(expected_roles) and {row['role'] for row in rows} == expected_roles
            and all(row['created'] is True and row['removed'] is True for row in rows), 'Owned roles cleanup incomplete')
    roles = {row['role']: row for row in rows}
    if staged:
        row=roles['cf-stage']
        require(row['image']==config['runtime']['image_id'] and 'seconds' not in row,'CF staging unexpectedly ran a payload')
        for filename in ('cf-stage-container-before.json','cf-stage-container-after.json'):
            value=read(proof_root/filename);_container(value,row,result,side,False)
            require(value['State']['Status']=='created' and value['State']['Pid']==0
                    and value['State']['StartedAt'].startswith('0001'),'CF staging view was started')
    for role, stem in (('owner-init', 'owner-init'), ('prepare', 'prepare'), ('engine', 'native'), ('helpers', 'helpers')):
        row = roles[role]
        require(row['image'] == (config['runtime']['image_id'] if role == 'engine' else helper_binding['selected_image_id']),
                'Role image changed')
        _container(read(proof_root / (stem + '-container-before.json')), row, result, side, False)
        _container(read(proof_root / (stem + '-container-after.json')), row, result, side, True)
    actual_engine = read(proof_root / 'native-container-after.json')
    require(actual_engine['Id'] == native['container_id'] and native['container_removed'] is True
            and actual_engine['State'] == native['process']['container_state'], 'Native actual State differs')
    for field, filename in (('container_before', 'native-container-before.json'), ('container_after', 'native-container-after.json'),
                            ('raw_stdout', 'native.stdout'), ('raw_stderr', 'native.stderr')):
        require(native['host_evidence'][field] == fact(proof_root / filename), 'Native raw evidence changed')
    projection = native['native_wrapper_exit_projection']
    require(projection['kind'] == 'ADAPTER_POLICY_PROJECTION_NOT_PROCESS_EXIT'
            and projection['input_raw_engine_exit'] == actual_engine['State']['ExitCode']
            and projection['value'] == (0 if projection['input_raw_engine_exit'] == 0 else 1)
            and projection['producer_sha256'] == native['producer_sha256'], 'Native projection differs')
    require(native['provider'] == config['db']['provider'] and native['side'] == side
            and native['runtime_backend'] == 'docker' and native['schema_version'] == 1
            and native['status'] == ('ENGINE_EXPORT_OK_VERIFICATION_PENDING'
                if projection['input_raw_engine_exit'] == 0 else 'FAILED'), 'Native receipt identity differs')
    report = export_native.read_engine_report(proof_root / 'native.stdout', proof_root / 'native.stderr')
    archive = CFSource(cf)
    try:
        sizes = {name: archive.catalog.entries[name].stored_size for name in archive.names()}
    finally:
        archive.close()
    classification = classify(native, report, sizes, projection['value'], linux_profile)
    require(classification == read(proof_root / 'native-classification.json'), 'Native policy changed')
    proof = read(proof_root / 'linux-proof.json')
    assembly = read(output / 'receipt.json')
    require(assembly['status'] == 'CANDIDATE_POSTGEN_VERIFICATION_REQUIRED'
            and assembly['cf_sha256'] == cf_fact['sha256'] and assembly['profile'] == linux_profile
            and assembly['profile_receipt'] == expected_profile_ref, 'Assembly original profile differs')
    require(proof['schema'] == PROOF_SCHEMA and proof['status'] == 'CANDIDATE_HOST_READBACK_REQUIRED'
            and proof['side'] == side and proof['native_policy'] == classification
            and proof['cf'] == cf_fact and proof['source_files'] == helper['source_files']
            and proof['runtime_files'] == helper['runtime_files'] and proof['oracle_inputs'] == []
            and proof['memory_controls'] is False and proof['host_transfer'] == proof['host_readback'] == 'NOT_RUN',
            'Linux helper proof boundary differs')
    require(proof['contract_sha256'] == fact(proof_root / 'contract.json')['sha256']
            and proof['native_receipt_fact'] == fact(proof_root / 'native-receipt.json')
            and proof['assembly_receipt_fact'] == fact(output / 'receipt.json')
            and proof['files_manifest_fact'] == fact(output / 'files.jsonl')
            and proof['files_manifest_fact']['sha256'] == assembly['manifest_sha256']
            and proof['namespace_fact'] == fact(proof_root / 'namespace.json'), 'Linux proof hash chain differs')
    from .fast_docker import OWNER_INIT_CODE
    owner_proof = read(proof_root / 'owner-init.stdout')
    require(result['owner_init_code_sha256'] == hashlib.sha256(OWNER_INIT_CODE.encode()).hexdigest()
            and result['owner_init_proof'] == owner_proof and owner_proof['schema'] == '1CDB2SRC_FAST_ROOT_OWNER_V1'
            and owner_proof['nonce'] == result['nonce'] and owner_proof['target'] == '/job'
            and owner_proof['recursive'] is False
            and owner_proof['after'] == {'uid': 65532, 'gid': 65532, 'mode': '0o755'}, 'Explicit owner init proof differs')
    export_native.daemon_policy(read(proof_root / 'docker-context.json'), read(proof_root / 'docker-daemon.json'))
    for filename, image in (('image-engine.json', config['runtime']['image_id']), ('image-helper.json', helper_binding['selected_image_id'])):
        image_info = read(proof_root / filename)
        export_native.image_policy(image, image_info, config['runtime']['binary']['path'] if filename == 'image-engine.json' else helper['entrypoint'][-1])
        if filename=='image-helper.json':
            require(image_info['RootFS']['Layers']==helper['image_identity']['rootfs_diff_ids']
                    and image_info['Config'].get('Entrypoint')==helper['entrypoint'], 'Helper sealed image identity differs')
    if config.get('docker_transfer','copy')=='stream':
        from .fast_stream import verify_transfer_receipts
        metadata.update(verify_transfer_receipts(config,side,result,helper=helper,helper_binding=helper_binding))
    else:
        require(config.get('docker_transfer','copy')=='copy' and 'xml_transfer' not in result,
                'Unexpected transport evidence in ordinary copy mode')
    return {'side': side, 'root': root, 'proof_root': proof_root, 'output': output, 'cf_path': cf, 'cf': cf_fact,
            'helper_binding': helper_binding, 'metadata': metadata, 'host_profile': host_profile,
            'linux_profile': linux_profile, 'assembly': assembly, 'classification': classification}


def verify_fast_side(config, side, workers=4):
    from .readback import verify_xml_tree
    bound = bind_fast_side(config, side)
    proof_root = bound['proof_root']
    require(not (proof_root / 'verification.json').exists() and not (proof_root / 'namespace-map.json').exists(),
            'Fresh fast verification receipt required')
    files = verify_xml_tree(bound['output'] / 'xml', bound['output'] / 'files.jsonl',
        manifest_sha256=bound['assembly']['manifest_sha256'], xml_version=bound['linux_profile']['xml_version'], workers=workers)
    require(files['status'] == 'FILES_VERIFIED_REQUIRES_CALLER_LINEAGE'
            and files['files'] == bound['assembly']['files'], 'Independent verifier incomplete')
    require(fact(bound['cf_path']) == bound['cf'], 'Host CF changed during independent verification')
    for path, expected in bound['metadata'].items():
        require(fact(path) == expected, 'Namespace/raw proof changed during file verification')
    current_helper, current_binding = load_helper_manifest(config)
    require(current_binding == bound['helper_binding'], 'Sealed helper manifest changed')
    namespace_map = {'schema': '1CDB2SRC_FAST_NAMESPACE_MAP_V1', 'status': 'VERIFIED_FAST_SIDE', 'side': side,
        'linux_profile': bound['linux_profile'], 'host_profile': bound['host_profile'], 'cf': bound['cf'],
        'differences': [key for key in ('cf_path', 'profile_id') if bound['linux_profile'][key] != bound['host_profile'][key]],
        'originals_rewritten': False, 'native_policy': bound['classification'],
        'file_facts_sha256': files['facts_sha256'], 'helper_manifest_binding': bound['helper_binding']}
    save_new(proof_root / 'namespace-map.json', namespace_map)
    save_new(proof_root / 'file-verification.json', files)
    result = {'status': 'PASS_FAST_SIDE_REQUIRES_COMMON_CF_FINALIZATION', 'side': side, 'cf': bound['cf'],
        'profile': bound['host_profile'], 'linux_profile': bound['linux_profile'],
        'xml_files': files['files'], 'xml_bytes': files['bytes'], 'bsl_files': files['bsl_files'],
        'opaque_unaccepted': len(bound['assembly']['unaccepted_opaque_entries']), 'workers': workers,
        'files_proof': fact(proof_root / 'file-verification.json'), 'namespace_map': fact(proof_root / 'namespace-map.json'),
        'native_policy': bound['classification'], 'oracle_inputs': [],
        'limitations': list(bound['assembly'].get('limitations', []))}
    if result['opaque_unaccepted']:
        result['limitations'].append({'kind': 'UNACCEPTED_OPAQUE_ENTRIES',
            'count': result['opaque_unaccepted'],
            'entries': bound['assembly']['unaccepted_opaque_entries']})
    parents=bound['assembly'].get('parent_assets')
    if parents:
        result['limitations'].append({'kind':'OPAQUE_PARENT_CF_PRESERVED_NOT_DECODED',
            'operation':parents['operation'],'raw_asset_status':parents['raw_asset_status'],
            'internal_metadata_decode':parents['internal_metadata_decode'],
            'all_declared_parent_assets':parents['all_declared_parent_assets']})
    save_new(proof_root / 'verification.json', result)
    return result
