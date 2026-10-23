"""Owned local Docker cp client -> frozen strict reader (experimental source).

Only the client created here may be terminated. Container/volume cleanup stays
with their producer owner. Return is transfer-only, not an XML acceptance.
"""
import datetime as dt
from dataclasses import dataclass, asdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import time

from .stream_tar import extract_xml_tar, long_path, regular_directory, normalized_name
from ._fast_contract import read, save_new, CONTRACT_SCHEMA, PROOF_SCHEMA

READER_SHA256 = '84367146ad2ecc49e43135dadd00f97c00bb86724f5778a5e199394e56253fc1'


class TransferFailure(RuntimeError):
    def __init__(self, receipt):
        self.receipt = receipt
        super().__init__('Docker XML transfer: '+receipt['status'])


def require(value, reason):
    if not value:
        raise ValueError(reason)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


@dataclass(frozen=True)
class FastStreamOwner:
    nonce: str
    cid: str
    name: str
    image: str
    volume: str
    side: str
    role: str
    cf_sha256: str
    helper_sha256: str
    contract_sha256: str
    profile_sha256: str
    helper_manifest_sha256: str
    cf_bytes: int
    cf_transport: str = 'HOST_READONLY_BIND'
    cf_volume: str | None = None
    schema: str = '1CDB2SRC_FAST_STREAM_OWNER_V1'

    def validate(self):
        require(self.schema == '1CDB2SRC_FAST_STREAM_OWNER_V1', 'Product stream owner schema required')
        require(re.fullmatch('[a-f0-9]{32}', self.nonce or ''), 'Fast job nonce required')
        require(re.fullmatch('[a-f0-9]{64}', self.cid or ''), 'Fast exact CID required')
        require(self.side in ('main', 'vendor') and self.role == 'helpers', 'Only closed Fast helper role allowed')
        require(self.name == 'onecdb2src-fast-' + self.nonce + '-helpers', 'Fast helper name mismatch')
        require(self.volume == 'onecdb2src-fast-' + self.nonce, 'Fast owned job volume mismatch')
        require(re.fullmatch('sha256:[a-f0-9]{64}', self.image or ''), 'Pinned Fast helper image required')
        if self.cf_transport == 'HOST_READONLY_BIND':
            require(self.cf_volume is None, 'Bind owner must not claim a CFast volume')
        elif self.cf_transport == 'STAGED_OWN_READONLY_VOLUME':
            require(self.cf_volume == self.volume + '-cf', 'Exact separately owned CFast volume required')
        else:
            raise ValueError('Unknown explicit CFast transport variant')
        require(type(self.cf_bytes) is int and self.cf_bytes >= 0, 'Product CF size required')
        for value in (self.cf_sha256, self.helper_sha256, self.contract_sha256, self.profile_sha256, self.helper_manifest_sha256):
            require(re.fullmatch('[a-f0-9]{64}', value or ''), 'Fast proof digest required')

    @property
    def xml_source(self):
        self.validate()
        return '/job/' + self.side + '/xml'


def owner_digest(owner):
    owner.validate()
    return hashlib.sha256(json.dumps(asdict(owner), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def route(native, source):
    context = native.context_record()
    native.endpoint_policy(context)
    environment = dict(native.docker_environment())
    command = list(native.docker_argv('cp', source, '-'))
    require(command[-3:] == ['cp', source, '-'], 'Unexpected Fast Docker argv')
    prefix = command[:-3]
    if '--context' in prefix:
        require(prefix == ['docker', '--context', context['Name']], 'Docker context changed')
    elif '--host' in prefix:
        require(prefix == ['docker', '--host', context['Endpoints']['docker']['Host']], 'Docker endpoint changed')
    else:
        require(prefix == ['docker'], 'Unexpected Docker prefix')
        require(re.fullmatch('[A-Za-z0-9_.-]+', context.get('Name', '')), 'Invalid local context')
        prefix += ['--context', context['Name']]
    return prefix, environment, context


def inspect_job(owner, prefix, environment, remaining, control_run):
    owner.validate()
    result = control_run(prefix + ['inspect', owner.cid], env=environment, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=min(10, remaining()), check=False)
    require(result.returncode == 0 and len(result.stdout) <= 1024 * 1024, 'Fast inspect unknown/over quota')
    records = json.loads(result.stdout)
    require(type(records) is list and len(records) == 1, 'Fast inspect ambiguous')
    value = records[0]
    require(value.get('Id') == owner.cid and value.get('Name') == '/' + owner.name, 'Fast exact name/CID mismatch')
    config, host = value.get('Config', {}), value.get('HostConfig', {})
    require(config.get('Labels', {}).get('onecdb2src.fast.nonce') == owner.nonce
            and config.get('Image') == owner.image and config.get('User') == '65532:65532', 'Fast owner/image/user mismatch')
    caps = host.get('CapDrop')
    require(type(caps) is list and all(type(cap) is str for cap in caps), 'Invalid product helper capabilities')
    require(host.get('Memory') == 0 and host.get('NetworkMode') == 'none' and host.get('ReadonlyRootfs') is True
            and host.get('NanoCpus') == 2 * 10**9 and [cap.removeprefix('CAP_') for cap in caps] == ['ALL']
            and not host.get('CapAdd') and not host.get('Privileged',False)
            and any(item in ('no-new-privileges', 'no-new-privileges:true') for item in host.get('SecurityOpt', [])),
            'Fast process configuration changed')
    mounts = value.get('Mounts', [])
    jobs = [item for item in mounts if item.get('Destination') == '/job']
    require(len(jobs) == 1 and jobs[0].get('Type') == 'volume'
            and jobs[0].get('Name') == owner.volume and jobs[0].get('RW') is True, 'Fast job mount mismatch')
    cf_volume_record = None
    if owner.cf_transport == 'HOST_READONLY_BIND':
        cf_destination = '/job/_work/cf/' + owner.side + '/source.cf'
        cfs = [item for item in mounts if item.get('Destination') == cf_destination]
        require(len(cfs) == 1 and cfs[0].get('Type') == 'bind' and cfs[0].get('RW') is False,
                'Fast explicit readonly CFast bind mismatch')
    elif owner.cf_transport == 'STAGED_OWN_READONLY_VOLUME':
        cf_destination = '/job/_work/cf/' + owner.side
        cfs = [item for item in mounts if item.get('Destination') == cf_destination]
        require(len(cfs) == 1 and cfs[0].get('Type') == 'volume' and cfs[0].get('Name') == owner.cf_volume
                and cfs[0].get('RW') is False, 'Fast explicit readonly CFast volume mismatch')
        volume_result = control_run(prefix + ['volume', 'inspect', owner.cf_volume], env=environment,
            stdin=subprocess.DEVNULL, capture_output=True, timeout=min(10, remaining()), check=False)
        require(volume_result.returncode == 0 and len(volume_result.stdout) <= 1024*1024, 'CFast volume identity unknown')
        volumes = json.loads(volume_result.stdout)
        require(type(volumes) is list and len(volumes) == 1, 'CFast volume identity ambiguous')
        volume = volumes[0]
        require(volume.get('Name') == owner.cf_volume and volume.get('Labels', {}).get('onecdb2src.fast.nonce') == owner.nonce
                and volume.get('Labels', {}).get('onecdb2src.fast.volume_role') == 'cf', 'CFast volume nonce/role mismatch')
        cf_volume_record = {key:volume.get(key) for key in ('Name','Driver','Scope','Labels','Options','CreatedAt','Mountpoint')}
    else:
        raise ValueError('Unknown CFast transport variant')
    # Reject nested mounts shadowing the fixed XML source or another CFast view.
    destinations = [item.get('Destination') for item in mounts]
    require(len(set(destinations)) == len(destinations), 'Duplicate helper mount destinations')
    require(all(path in ('/job', cf_destination, '/contract.json') for path in destinations), 'Unexpected helper mount/source view')
    require(len(destinations) == 3 and '/contract.json' in destinations, 'Product helper requires exact three mounts')
    for item in mounts:
        if item.get('Destination') == '/contract.json':
            require(item.get('Type') == 'bind' and item.get('RW') is False, 'Contract mount must be readonly bind')
    state = value.get('State', {})
    require(state.get('Running') is False and state.get('Paused') is False and state.get('Restarting') is False
            and state.get('Dead') is False and state.get('Pid') == 0 and state.get('Status') == 'exited'
            and state.get('OOMKilled') is False and state.get('ExitCode') == 0 and not state.get('Error'),
            'Fast helper producer not successfully closed')
    require(state.get('StartedAt') and state.get('FinishedAt')
            and not state['StartedAt'].startswith('0001') and not state['FinishedAt'].startswith('0001'),
            'Fast helper lifecycle missing')
    return {'state': state, 'restart_count': value.get('RestartCount'), 'owner_sha256': owner_digest(owner),
            'cf_transport': owner.cf_transport, 'cf_volume': cf_volume_record}


def _extract_job_xml(container_id, target, *, owner, frozen_route,
        expected_files, timeout=600, cancel_event=None, native=None,
        popen=subprocess.Popen, control_run=subprocess.run, stop_grace=2, proof_root=None):
    """Private pipe operation for one successfully closed product helper.

    native is the existing export_native module, never a new Docker endpoint.
    popen/control_run are explicit process seams for small fake-client tests.
    No shell, memory limits, native ownership emulation or foreign cleanup.
    """
    require(re.fullmatch(r'[0-9a-f]{64}', container_id or '') is not None, 'exact owned CID required')
    require(type(timeout) in (int, float) and math.isfinite(timeout) and timeout > 0, 'finite positive timeout required')
    require(type(stop_grace) in (int, float) and math.isfinite(stop_grace) and stop_grace > 0, 'finite positive stop grace required')
    if native is None:
        from onecdb2src.xml import export_native as native
    target = Path(os.path.abspath(target))
    for parent in reversed(target.parents):
        regular_directory(long_path(parent))
    paths = {name: long_path(target.with_name(target.name+suffix)) for name, suffix in (
        ('receipt', '.transfer-process.json'), ('stderr', '.docker-cp.stderr'),
        ('manifest', '.transfer.jsonl'))}
    paths['receipt'] = long_path(Path(proof_root) / 'stream-process.json')
    paths['stderr'] = long_path(Path(proof_root) / 'stream-cp.stderr')
    require(not os.path.lexists(long_path(target)) and
            all(not os.path.lexists(path) for path in paths.values()), 'new transfer paths required')
    begun = time.monotonic()
    deadline = begun+timeout
    receipt = {'schema': 1, 'status': 'RUNNING', 'started_utc': utc(),
        'container_id': container_id, 'target': str(target), 'reader_sha256':
        hashlib.sha256(Path(extract_xml_tar.__code__.co_filename).read_bytes()).hexdigest(),
        'container_cleanup': 'CALLER_OWNED_NOT_PERFORMED',
        'client_cleanup': {'confirmed': False}, 'independent_readback': 'NOT_RUN'}
    receipt['transport_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    require(receipt['reader_sha256'] == READER_SHA256, 'frozen G reader source mismatch')
    process = None
    stderr = None
    watcher = None
    finished = threading.Event()
    stop_lock = threading.Lock()
    stop = {'reason': None, 'errors': []}

    def cancelled():
        return cancel_event is not None and cancel_event.is_set()

    def remaining():
        if cancelled():
            raise InterruptedError('cancelled')
        value = deadline-time.monotonic()
        if value <= 0:
            raise TimeoutError('transfer deadline')
        return value

    def stop_own_client(reason):
        with stop_lock:
            if stop['reason'] is None:
                stop['reason'] = reason
            if process is None or process.poll() is not None:
                return
            try:
                process.terminate()
                try:
                    process.wait(timeout=stop_grace)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=stop_grace)
            except BaseException as error:
                stop['errors'].append(type(error).__name__)

    def watch():
        while not finished.wait(0.02):
            if cancelled():
                stop_own_client('CANCELLED')
                return
            if time.monotonic() >= deadline:
                stop_own_client('TIMED_OUT')
                return

    def cleanup_client():
        if process is not None:
            if process.poll() is None:
                stop_own_client(stop['reason'] or 'FAILED')
            try:
                process.wait(timeout=stop_grace)
            except BaseException as error:
                stop['errors'].append(type(error).__name__)
            if process.stdout is not None:
                try:
                    process.stdout.close()
                except BaseException as error:
                    stop['errors'].append(type(error).__name__)
        finished.set()
        if watcher is not None:
            watcher.join(timeout=2*stop_grace+1)
        if stderr is not None:
            try:
                stderr.close()
            except BaseException as error:
                stop['errors'].append(type(error).__name__)
        closed = process is None or (process.poll() is not None and
            (process.stdout is None or process.stdout.closed))
        joined = watcher is None or not watcher.is_alive()
        receipt['client_cleanup'] = {'confirmed': closed and joined and
            (stderr is None or stderr.closed) and not stop['errors'],
            'returncode': None if process is None else process.poll(),
            'stdout_closed': process is None or process.stdout is None or process.stdout.closed,
            'stderr_closed': stderr is None or stderr.closed,
            'watcher_joined': joined, 'errors': list(stop['errors'])}

    with paths['receipt'].open('xb') as durable:
        try:
            remaining()
            owner.validate()
            require(container_id == owner.cid, 'Fast owner CID contradiction')
            own_sha = owner_digest(owner)
            prefix, environment, context = frozen_route
            require(route(native, container_id + ':' + owner.xml_source) == frozen_route, 'Fast local route changed')
            command = prefix + ['cp', container_id + ':' + owner.xml_source, '-']
            receipt['docker_argv'] = command
            receipt['docker_context'] = {'name': context['Name'],
                'endpoint': context['Endpoints']['docker']['Host']}
            receipt['ownership_sha256'] = own_sha
            receipt['ownership_protocol'] = 'PRODUCT_FAST_HELPER_NOT_NATIVE_OWNERSHIP'

            def inspect_closed():
                return inspect_job(owner, prefix, environment, remaining, control_run)

            before = inspect_closed()
            receipt['producer_before'] = before
            remaining()
            stderr = paths['stderr'].open('xb')
            process = popen(command, env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=stderr, shell=False, bufsize=0)
            receipt['client_pid'] = process.pid
            require(process.stdout is not None, 'cp stdout pipe missing')
            watcher = threading.Thread(target=watch, name='owned-docker-cp-timeout', daemon=True)
            watcher.start()
            reader = extract_xml_tar(process.stdout, target, expected_files=expected_files)
            process.wait(timeout=remaining())
            require(process.returncode == 0, 'docker cp exited nonzero')
            require(stop['reason'] is None, 'client timed out or cancelled')
            receipt['reader'] = reader
            # Finish cp client/pipe/thread before postflight daemon queries.
            cleanup_client()
            require(receipt['client_cleanup']['confirmed'], 'cp client cleanup unknown')
            remaining()
            after = inspect_closed()
            receipt['producer_after'] = after
            require(after == before, 'producer changed/restarted during transfer')
            require(owner_digest(owner) == own_sha, 'Fast owner contract changed')
            require(route(native, container_id + ':' + owner.xml_source) == frozen_route, 'Fast local endpoint changed')
            require(hashlib.sha256(Path(extract_xml_tar.__code__.co_filename).read_bytes()).hexdigest()
                    == receipt['reader_sha256'], 'reader source changed')
            require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == receipt['transport_sha256'], 'transport source changed')
            remaining()
            receipt['status'] = 'TRANSFERRED_REQUIRES_INDEPENDENT_READBACK'
        except BaseException as error:
            receipt['status'] = stop['reason'] or ('CANCELLED' if isinstance(error, (InterruptedError, KeyboardInterrupt))
                else 'TIMED_OUT' if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else 'FAILED')
            receipt['error_type'] = type(error).__name__
            receipt['reason'] = str(error)[:2048]
            # Do not serialize environment, Docker stderr or exception repr.
        finally:
            cleanup_client()
            if not receipt['client_cleanup']['confirmed']:
                receipt['status'] = 'FAILED_CLEANUP_UNKNOWN'
            receipt['finished_utc'] = utc()
            receipt['elapsed_seconds'] = round(time.monotonic()-begun, 6)
            raw = (json.dumps(receipt, ensure_ascii=False, indent=2)+'\n').encode('utf-8')
            require(durable.write(raw) == len(raw), 'short durable transfer receipt write')
    if receipt['status'] != 'TRANSFERRED_REQUIRES_INDEPENDENT_READBACK':
        raise TransferFailure(receipt)
    return receipt


def file_fact(path, quota=None):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and not getattr(before, 'st_file_attributes', 0) & 0x400, 'Fast metadata must be regular')
    require(quota is None or before.st_size <= quota, 'Fast metadata quota exceeded')
    with path.open('rb') as stream:
        sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'Fast metadata changed while reading')
    return {'bytes': before.st_size, 'sha256': sha}


def _transfer_fast_side(config, side, *, owner, proof_root, output_side, timeout=600, cancel_event=None,
        native=None, popen=subprocess.Popen, control_run=subprocess.run, stop_grace=2):
    """Product-owned narrow API, not native ownership emulation or a drop-in Fast change.

    Copies immutable assembly receipt/manifest/helper proof first, then streams
    strictly /job/<main|vendor>/xml. Caller Fast still performs its independent
    final file readback AND owns helper/volume cleanup. No producer is stopped.
    """
    require(type(owner) is FastStreamOwner, 'Explicit Fast FastStreamOwner required; native ownership is incompatible')
    owner.validate()
    require(type(timeout) in (int, float) and math.isfinite(timeout) and timeout > 0, 'Finite job transfer budget required')
    if native is None:
        from onecdb2src.xml import export_native as native
    target_side = Path(os.path.abspath(output_side))
    proof_root = Path(os.path.abspath(proof_root))
    root = Path(config['root']).resolve(strict=True)
    require(side == owner.side and target_side == root / side and proof_root == root / '_work' / ('fast-' + side), 'Canonical product transfer paths required')
    require(config.get('docker_mode')=='fast' and config.get('runtime_backend')=='docker'
            and config.get('assembly_mode')=='adopt' and config.get('memory_controls') is False,
            'Explicit product fast stream policy required')
    contract = read(proof_root/'contract.json')
    require(contract['schema']==CONTRACT_SCHEMA and contract['side']==side and contract['nonce']==owner.nonce
            and file_fact(proof_root/'contract.json')['sha256']==owner.contract_sha256
            and contract['cf']=={'bytes':owner.cf_bytes,'sha256':owner.cf_sha256}
            and contract['helper_manifest_binding']['sha256']==owner.helper_manifest_sha256,
            'Product stream contract/CF/helper binding differs')
    require(contract['source_files']['onecdb2src/xml/fast_stream.py']==file_fact(__file__)
            and contract['source_files']['onecdb2src/xml/stream_tar.py']==file_fact(Path(__file__).with_name('stream_tar.py')),
            'Sealed product stream source differs')
    for parent in reversed(target_side.parents):
        regular_directory(long_path(parent))
    outer_path = long_path(proof_root / 'stream-transfer.json')
    require(not os.path.lexists(long_path(target_side)) and not os.path.lexists(outer_path), 'New Fast transfer destination required')
    begun = time.monotonic()
    deadline = begun + timeout
    outer = {'schema': '1CDB2SRC_FAST_STREAM_V1', 'status': 'RUNNING', 'started_utc': utc(),
             'owner': asdict(owner), 'owner_sha256': owner_digest(owner),
             'sourcepath': owner.xml_source, 'metadata_rewritten': False,
             'container_cleanup': 'CALLER_PRODUCT_OWNED_NOT_PERFORMED', 'independent_readback': 'NOT_RUN'}
    outer['transport_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def remaining():
        require(cancel_event is None or not cancel_event.is_set(), 'Fast transfer cancelled')
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('Fast overall transfer deadline')
        return left

    with outer_path.open('xb') as durable:
        try:
            remaining()
            frozen_route = route(native, owner.cid + ':' + owner.xml_source)
            prefix, environment, _ = frozen_route
            before = inspect_job(owner, prefix, environment, remaining, control_run)
            outer['producer_before'] = before
            actual_target = long_path(target_side)
            actual_target.mkdir()  # exclusive; partial metadata remains on any refusal
            copies = (
                ('/job/' + owner.side + '/receipt.json', actual_target/'receipt.json', 'receipt.json', 1024 * 1024),
                ('/job/' + owner.side + '/files.jsonl', actual_target/'files.jsonl', 'files.jsonl', 256 * 1024 * 1024),
                ('/job/linux-proof-' + owner.side + '.json', long_path(proof_root/'linux-proof.json'), 'linux-proof.json', 16 * 1024 * 1024),
            )
            facts = {}
            outer['metadata'] = facts
            for sourcepath, target, name, quota in copies:
                require(inspect_job(owner, prefix, environment, remaining, control_run) == before, 'Fast helper changed before metadata cp')
                require(not os.path.lexists(target), 'Metadata target already exists')
                done = control_run(prefix + ['cp', owner.cid + ':' + sourcepath, str(target)], env=environment,
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=min(60, remaining()), check=False)
                require(done.returncode == 0, 'Fast metadata cp failed; no XML fallback')
                facts[name] = file_fact(target, quota)
            require(inspect_job(owner, prefix, environment, remaining, control_run) == before, 'Fast helper changed after metadata cp')
            assembly = read(actual_target/'receipt.json')
            proof = read(proof_root/'linux-proof.json')
            require(assembly['status'] == 'CANDIDATE_POSTGEN_VERIFICATION_REQUIRED'
                    and proof['status'] == 'CANDIDATE_HOST_READBACK_REQUIRED'
                    and proof['schema'] == PROOF_SCHEMA and proof['side']==side, 'Fast closed assembly/proof not complete')
            require(proof['assembly_receipt_fact'] == facts['receipt.json']
                    and proof['files_manifest_fact'] == facts['files.jsonl']
                    and assembly['manifest_sha256'] == facts['files.jsonl']['sha256'],
                    'Fast closed assembly/manifest binding mismatch')
            require(proof['cf'] == contract['cf'] and assembly['cf_sha256'] == owner.cf_sha256
                    and proof['source_files'] == contract['source_files'] and proof['runtime_files'] == contract['runtime_files']
                    and contract['source_files']['onecdb2src/xml/linux_helpers.py']['sha256']==owner.helper_sha256
                    and proof['contract_sha256'] == owner.contract_sha256
                    and proof['namespace_fact']==file_fact(proof_root/'namespace.json')
                    and proof['native_receipt_fact']==file_fact(proof_root/'native-receipt.json')
                    and proof['native_policy']==read(proof_root/'native-classification.json')
                    and proof['oracle_inputs'] == [] and proof['memory_controls'] is False
                    and proof['host_transfer']==proof['host_readback']=='NOT_RUN',
                    'Fast helper CF/source/contract mismatch')
            require(assembly['profile']==read(proof_root/'linux-profile.json')
                    and file_fact(proof_root/'linux-profile.json')['sha256']==owner.profile_sha256,
                    'Original Linux profile bytes differ')
            require(assembly['profile_receipt'] == {'path': '/job/_work/profiles/' + owner.side + '.json',
                    'sha256': owner.profile_sha256}, 'Fast original Linux profile receipt mismatch')
            expected = []
            with (actual_target / 'files.jsonl').open(encoding='utf-8') as stream:
                for line in stream:
                    remaining()
                    def unique(pairs):
                        row={}
                        for key,value in pairs:
                            require(key not in row,'Duplicate manifest JSON key');row[key]=value
                        return row
                    row = json.loads(line,object_pairs_hook=unique)
                    parts = normalized_name('xml/' + row['path'], False)
                    require('/'.join(parts) == row['path'] and type(row['bytes']) is int and row['bytes'] >= 0
                            and re.fullmatch('[a-f0-9]{64}', row['sha256']), 'Fast invalid closed manifest row')
                    expected.append(row['path'])
            require(len(set(expected)) == len(expected) == assembly['files'] and expected,
                    'Fast incomplete/duplicate closed assembly manifest')
            outer['expected_files'] = len(expected)
            stream_receipt = _extract_job_xml(owner.cid, target_side / 'xml', owner=owner,
                frozen_route=frozen_route, expected_files=expected, timeout=remaining(), cancel_event=cancel_event,
                native=native, popen=popen, control_run=control_run, stop_grace=stop_grace, proof_root=proof_root)
            outer['stream'] = stream_receipt
            after=inspect_job(owner, prefix, environment, remaining, control_run)
            outer['producer_after']=after
            require(after == before,'Fast helper changed after XML transfer')
            require(route(native, owner.cid + ':' + owner.xml_source) == frozen_route, 'Fast local endpoint changed')
            for sourcepath, path, name, quota in copies:
                require(file_fact(path) == facts[name], 'Fast copied metadata changed')
            require(owner_digest(owner) == outer['owner_sha256'], 'Fast owner contract changed')
            require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == outer['transport_sha256'], 'Fast transport source changed')
            remaining()
            outer['status'] = 'TRANSFERRED_REQUIRES_INDEPENDENT_READBACK'
        except BaseException as error:
            outer['status'] = 'FAILED_JOB_TRANSFER'
            outer['error_type'] = type(error).__name__
            outer['reason'] = str(error)[:2048]
            if isinstance(error, TransferFailure):
                outer['stream'] = error.receipt
                outer['reason'] = error.receipt.get('reason',str(error))[:2048]
        finally:
            outer['finished_utc'] = utc()
            outer['elapsed_seconds'] = round(time.monotonic() - begun, 6)
            durable.write((json.dumps(outer, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    if outer['status'] != 'TRANSFERRED_REQUIRES_INDEPENDENT_READBACK':
        raise TransferFailure(outer)
    return outer


def make_stream_owner(config, side, generation, helper, helper_binding):
    root=Path(config['root']).resolve(strict=True);proof=root/'_work'/('fast-'+side)
    rows=[row for row in generation['containers'] if row['role']=='helpers']
    require(len(rows)==1,'Exact product helper role required')
    row=rows[0];cf=generation['source_cf']
    return FastStreamOwner(nonce=generation['nonce'],cid=row['cid'],name=row['name'],image=helper_binding['selected_image_id'],
        volume=generation['volume'],side=side,role='helpers',cf_sha256=cf['sha256'],cf_bytes=cf['bytes'],
        helper_sha256=helper['source_files']['onecdb2src/xml/linux_helpers.py']['sha256'],
        contract_sha256=file_fact(proof/'contract.json')['sha256'],profile_sha256=file_fact(proof/'linux-profile.json')['sha256'],
        helper_manifest_sha256=helper_binding['sha256'],cf_transport=generation['cf_transport'],
        cf_volume=generation.get('cf_volume'))


def transfer_fast_side(config, side, *, owner, proof_root, output_side, timeout=600, cancel_event=None,
        native=None,popen=subprocess.Popen,control_run=subprocess.run,stop_grace=2):
    """Product-only entry; early source guard failures retain a bounded reason."""
    require(side in ('main','vendor'),'Unknown product side')
    canonical=Path(config['root']).resolve(strict=True)/'_work'/('fast-'+side)
    require(Path(proof_root).resolve(strict=True)==canonical,'Canonical existing product proof root required')
    save_new(canonical/'stream-start.json',{'schema':'1CDB2SRC_FAST_STREAM_START_V1','status':'INITIALIZED_NOT_ACCEPTED',
        'side':side,'started_utc':utc(),'independent_readback':'NOT_RUN'})
    try:
        return _transfer_fast_side(config,side,owner=owner,proof_root=proof_root,output_side=output_side,timeout=timeout,
            cancel_event=cancel_event,native=native,popen=popen,control_run=control_run,stop_grace=stop_grace)
    except BaseException as error:
        reason=error.receipt.get('reason',str(error)) if isinstance(error,TransferFailure) else str(error)
        save_new(canonical/'stream-error.json',{'schema':'1CDB2SRC_FAST_STREAM_ERROR_V1','status':'FAILED',
            'error_type':type(error).__name__,'reason':reason[:2048],'finished_utc':utc()})
        raise


def verify_transfer_receipts(config,side,generation,*,helper,helper_binding):
    """Bind transfer evidence only. The caller still owns the one V readback."""
    root=Path(config['root']).resolve(strict=True);proof=root/'_work'/('fast-'+side);output=root/side
    require(not (proof/'stream-error.json').exists(),'Stream error proof forbids acceptance')
    names=[proof/'stream-start.json',proof/'stream-transfer.json',proof/'stream-process.json',proof/'stream-cp.stderr',output/'xml.transfer.jsonl']
    facts={str(path):file_fact(path) for path in names}
    outer=read(proof/'stream-transfer.json');process=read(proof/'stream-process.json')
    require(generation['xml_transfer']=='stream' and generation['stream_transfer']==file_fact(proof/'stream-transfer.json'),
            'Generation stream receipt binding differs')
    start=read(proof/'stream-start.json')
    require(start['schema']=='1CDB2SRC_FAST_STREAM_START_V1' and start['side']==side
            and start['status']=='INITIALIZED_NOT_ACCEPTED' and start['independent_readback']=='NOT_RUN','Unknown stream start proof')
    owner=make_stream_owner(config,side,generation,helper,helper_binding);owner.validate()
    require(outer['schema']=='1CDB2SRC_FAST_STREAM_V1' and outer['status']=='TRANSFERRED_REQUIRES_INDEPENDENT_READBACK'
            and outer['owner']==asdict(owner) and outer['owner_sha256']==owner_digest(owner)
            and outer['sourcepath']==owner.xml_source and outer['metadata_rewritten'] is False
            and outer['container_cleanup']=='CALLER_PRODUCT_OWNED_NOT_PERFORMED'
            and outer['independent_readback']=='NOT_RUN','Product stream owner/status differs')
    require(outer['stream']==process and outer['producer_before']==outer['producer_after']
            and process['producer_before']==process['producer_after']==outer['producer_before'],'Closed producer changed during stream')
    raw=read(proof/'helpers-container-after.json')
    require(outer['producer_before']['state']==raw['State'] and outer['producer_before']['restart_count']==raw.get('RestartCount')
            and outer['producer_before']['owner_sha256']==owner_digest(owner)
            and outer['producer_before']['cf_transport']==owner.cf_transport,'Transport closed producer differs from original Y proof')
    volume=outer['producer_before']['cf_volume']
    if owner.cf_transport=='STAGED_OWN_READONLY_VOLUME':
        require(volume['Name']==owner.cf_volume and volume['Labels'].get('onecdb2src.fast.nonce')==owner.nonce
                and volume['Labels'].get('onecdb2src.fast.volume_role')=='cf','Historical CF volume owner differs')
    else:require(volume is None,'Bind transport has unexpected CF volume proof')
    require(process['status']=='TRANSFERRED_REQUIRES_INDEPENDENT_READBACK' and process['container_id']==owner.cid
            and process['ownership_sha256']==owner_digest(owner) and process['reader_sha256']==READER_SHA256
            and process['ownership_protocol']=='PRODUCT_FAST_HELPER_NOT_NATIVE_OWNERSHIP'
            and process['transport_sha256']==outer['transport_sha256']==file_fact(__file__)['sha256'],
            'Stream process/source status differs')
    require(process['docker_argv'][-3:]==['cp',owner.cid+':'+owner.xml_source,'-'],'Stream source command differs')
    context=read(proof/'docker-context.json')
    require(process['docker_context']=={'name':context['Name'],'endpoint':context['Endpoints']['docker']['Host']},
            'Stream context differs from original local Y route')
    if config.get('docker_socket'):
        require(process['docker_argv'][:-3]==['docker','--host',context['Endpoints']['docker']['Host']], 'Stream socket route differs')
    else:
        require(process['docker_argv'][:-3]==['docker','--context',context['Name']], 'Stream context prefix differs')
    cleanup=process['client_cleanup']
    require(cleanup['confirmed'] is True and cleanup['returncode']==0 and cleanup['stdout_closed'] is True
            and cleanup['stderr_closed'] is True and cleanup['watcher_joined'] is True and cleanup['errors']==[],
            'Stream client closure incomplete')
    assembly=read(output/'receipt.json')
    require(process['reader']['status']=='TRANSFERRED_REQUIRES_INDEPENDENT_READBACK'
            and process['reader']['target']==str(long_path(output/'xml'))
            and process['reader']['manifest']==str(long_path(output/'xml.transfer.jsonl'))
            and process['reader']['files']==outer['expected_files']==assembly['files']
            and process['reader']['archive_metadata_applied'] is False
            and process['reader']['manifest_sha256']==file_fact(output/'xml.transfer.jsonl')['sha256'],
            'Stream writer manifest binding differs')
    for name,path in (('receipt.json',output/'receipt.json'),('files.jsonl',output/'files.jsonl'),('linux-proof.json',proof/'linux-proof.json')):
        require(outer['metadata'][name]==file_fact(path),'Copied original metadata changed after stream')
    return facts


