"""Export a SQL-derived CF using the pinned independent engine, without oracle inputs.

The engine receipt is evidence, not proof of native XML equivalence. Run the
independent full-tree verifier AFTER this command has finished.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import stat
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path
from .. import profiles

DOCKER_CONTEXT = 'desktop-linux' if os.name == 'nt' else None
DOCKER_SOCKET = None


def configure(context=None, socket=None):
    global DOCKER_CONTEXT, DOCKER_SOCKET
    require(not (context and socket), 'Choose Docker context or local socket')
    if os.name == 'nt':
        require(socket is None and context in (None, 'desktop-linux'), 'Windows requires local Docker Desktop context')
        DOCKER_CONTEXT = 'desktop-linux'
    else:
        require(sys.platform == 'linux', 'Only Windows and Linux Docker hosts are supported')
        DOCKER_CONTEXT = context
    if context is not None:
        require(re.fullmatch(r'[A-Za-z0-9_.-]+', context) is not None, 'Invalid Docker context')
    if socket is not None:
        socket = str(Path(socket).resolve(strict=True))
        require(stat.S_ISSOCK(Path(socket).stat().st_mode), 'Docker endpoint must be a local Unix socket')
    DOCKER_SOCKET = socket


def context_record():
    if DOCKER_SOCKET:
        return {'Name': 'explicit-local-unix-socket', 'Endpoints': {'docker': {'Host': 'unix://' + DOCKER_SOCKET}}}
    selected = DOCKER_CONTEXT or docker('context', 'show').strip()
    require(re.fullmatch(r'[A-Za-z0-9_.-]+', selected) is not None, 'Invalid current Docker context')
    return json.loads(docker('context', 'inspect', selected))[0]


def docker_environment():
    # No ambient remote daemon or alternate Docker configuration may redirect binds.
    return {key: value for key, value in os.environ.items()
            if key.upper() not in {'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'}}


def docker_argv(*args):
    target = ['--host', 'unix://' + DOCKER_SOCKET] if DOCKER_SOCKET else ['--context', DOCKER_CONTEXT] if DOCKER_CONTEXT else []
    return ['docker', *target, *args]


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def docker(*args):
    result = subprocess.run(docker_argv(*args), env=docker_environment(), capture_output=True, encoding='utf-8', errors='replace', timeout=60)
    require(result.returncode == 0, 'Docker command failed: ' + result.stderr.strip())
    return result.stdout


def image_policy(image, metadata, binary):
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', image) is not None, 'Use an immutable Docker image ID')
    require(metadata['Id'] == image, 'Image ID mismatch')
    config = metadata['Config']
    require(not config.get('Volumes'), 'Image declares unexpected volumes')
    require(not config.get('OnBuild'), 'Image declares OnBuild instructions')
    require(binary.startswith('/') and '..' not in binary.split('/'), 'Use an absolute engine path')
    for item in config.get('Env') or []:
        require(not item.split('=', 1)[0].upper().startswith('IBC'), 'Image contains IBC environment hooks')


def endpoint_policy(context):
    endpoint = context['Endpoints']['docker']['Host']
    if os.name == 'nt':
        require(endpoint == 'npipe:////./pipe/dockerDesktopLinuxEngine', 'Only the local Docker Desktop Linux named pipe is supported')
    else:
        require(sys.platform == 'linux' and endpoint.startswith('unix:///'), 'Linux requires a local Unix Docker socket; remote daemons are unsupported')
        require(stat.S_ISSOCK(Path(endpoint[7:]).stat().st_mode), 'Docker endpoint is not a local Unix socket')


def daemon_policy(context, info):
    endpoint_policy(context)
    if os.name == 'nt':require(info['Name'] == 'docker-desktop', 'Unexpected Windows Docker daemon')
    require(info['OSType'] == 'linux' and info.get('Architecture') in ('x86_64', 'amd64'), 'Linux amd64 Docker engine required')


def verify_bind_visibility(image, root):
    """Verify a fresh unique child directory through the actual daemon's bind mount."""
    directory = Path(root) / '_work' / ('bind-probe-' + uuid.uuid4().hex)
    directory.mkdir()
    nonce = uuid.uuid4().hex
    (directory / 'marker').write_text(nonce, encoding='ascii')
    (directory / ('marker-' + nonce)).mkdir()
    name = '1cdb2src-' + nonce
    directory = directory.resolve()
    ownership = {'schema': 1, 'nonce': nonce, 'name': name, 'cidfile': str(directory / 'container.cid'),
                 'source': str(directory / 'marker'), 'destination': str(directory),
                 'labels': {'onecdb2src.export.nonce': nonce,
                            'onecdb2src.export.destination': hashlib.sha256(str(directory).encode()).hexdigest(),
                            'onecdb2src.export.source': hashlib.sha256(str(directory / 'marker').encode()).hexdigest()}}
    save(directory / 'ownership.json', ownership)
    cid = None
    result = {'status': 'RUNNING', 'name': name, 'context': context_record(), 'container_started': False,
              'scope': 'unique directory chdir and pinned engine version through actual bind; not a claim of arbitrary remote file-byte equivalence'}
    try:
        labels = []
        for key, value in ownership['labels'].items():
            labels += ['--label', key + '=' + value]
        cid = docker('create', '--name', name, '--cidfile', ownership['cidfile'], *labels,
                     '--network', 'none', '--read-only', '--memory', '512m', '--memory-swap', '512m', '--cpus', '2', '--pids-limit', '64',
                     '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--mount',
                     'type=bind,source=' + str(directory.resolve()) + ',target=/onecdb2src-bind,readonly',
                     '--entrypoint', '/usr/bin/env', image, '-C', '/onecdb2src-bind/marker-' + nonce, '-i', '/engine/ibcmd-rs', '--version').strip()
        require(re.fullmatch('[0-9a-f]{64}', cid) is not None, 'Invalid bind probe CID')
        before=inspect_owned(directory)
        require(before is not None,'Bind probe inspection missing')
        save(directory/'container-before.json',before)
        result['resource_limits']={key:before['HostConfig'][key] for key in ('Memory','MemorySwap','NanoCpus','PidsLimit')}
        info=json.loads(docker('info','--format','{{json .}}'))
        result['swap_limit_supported']=info.get('SwapLimit') is True
        require(before['HostConfig']['Memory']==512*1024**2 and before['HostConfig']['NanoCpus']==2*10**9 and before['HostConfig']['PidsLimit']==64, 'Docker bind probe resource caps mismatch')
        require(before['HostConfig']['MemorySwap']==512*1024**2 or info.get('SwapLimit') is False,'Docker bind probe swap cap mismatch')
        result['container_started'] = True
        output = docker('start', '--attach', cid)
        state = inspect_owned(directory)
        require(state is not None and not state['State']['Running'] and state['State']['OOMKilled'] is False and state['State']['ExitCode'] == 0, 'Docker bind probe process failed')
        require(output == 'ibcmd-rs 0.4.1\n', 'Docker bind probe version mismatch')
        result['state'] = state['State']
        result['version_stdout'] = output
        result['status'] = 'PASS_UNIQUE_BIND_DIRECTORY'
    finally:
        # Name is unique and labelled before create, including a lost create response.
        try:
            result['cleanup'] = cleanup_owned(directory)
            result['removed'] = result['cleanup']['confirmed']
        except Exception:
            result['cleanup_status'] = 'NOT_CONFIRMED'
            save(directory / 'receipt.json', result)
            raise
        save(directory / 'receipt.json', result)
    return result


def create_command(image, binary, source, tree, name, memory_mib, workers, ownership=None, platform='8.3.27'):
    require(platform in ('8.3.27','8.5.1'),'Unsupported selected native platform')
    require(memory_mib >= 512 and 1 <= workers <= 8, 'Invalid explicit runtime budget')
    for path in (source, tree):
        require(',' not in str(path) and '\n' not in str(path), 'Unsupported Docker mount path')
    owned=[]
    if ownership:
        owned=['--cidfile',ownership['cidfile']]
        for key,value in ownership['labels'].items():owned+=['--label',key+'='+value]
    user = ['--user', str(os.getuid()) + ':' + str(os.getgid())] if sys.platform == 'linux' else []
    return ['create', '--name', name, *owned, *user, '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--pids-limit', '256', '--memory', str(memory_mib) + 'm',
            '--memory-swap', str(memory_mib) + 'm', '--cpus', str(workers),
            '--workdir', '/tmp', '--tmpfs', '/tmp:rw,noexec,nosuid,size=256m',
            '--mount', f'type=bind,source={source},target=/input/source.cf,readonly',
            '--mount', f'type=bind,source={tree},target=/output',
            '--entrypoint', '/usr/bin/env', image,
            '-i', 'PATH=/engine', 'RAYON_NUM_THREADS=' + str(workers), binary,
            'cf', 'export', '/input/source.cf', '/output/xml',
            '--platform', platform, '--compression', 'raw-deflate', '--fail-on-opaque']


def read_engine_report(stdout, stderr):
    candidates = []
    for path in (stdout, stderr):
        try:
            value = json.loads(path.read_text(encoding='utf-8-sig'))
            if isinstance(value, dict) and 'ok' in value:
                candidates.append(value)
        except (ValueError, OSError):
            pass
    require(len(candidates) == 1, 'Expected one complete engine JSON receipt')
    report = candidates[0]
    require(report.get('command') == 'export', 'Unexpected engine report command')
    return report


def report_summary(report):
    export = report.get('export') or {}
    storage = export.get('storage') or {}
    counts = {key: storage.get(key) for key in ('physical_entries', 'logical_entries', 'supported', 'opaque', 'failed')}
    return {'engine_ok': report.get('ok'), 'files_written': export.get('files_written'),
            'storage': counts, 'errors': report.get('errors', [])}


def inspect_owned(directory):
    """Resolve only this invocation, including a lost docker-create response.

    Daemon errors remain errors. Only Docker's explicit missing-object response
    is absence evidence; callers cannot convert an unreachable daemon to clean.
    """
    directory=Path(directory).resolve(strict=True)
    ownership=load_ownership(directory)
    cidfile=Path(ownership['cidfile'])
    reference=ownership['name']
    cid_reference=None
    if cidfile.exists():
        require(cidfile.is_file() and cidfile.stat().st_size<=128,'Invalid own CID file')
        candidate=cidfile.read_text(encoding='ascii').strip()
        # Docker may create the file before it can persist the daemon's reply.
        # An empty interrupted file has no CID; the unique labelled name remains.
        if candidate:
            require(re.fullmatch('[0-9a-f]{64}',candidate) is not None,'Invalid own CID')
            reference=cid_reference=candidate
    try:
        records=json.loads(docker('inspect',reference))
    except ValueError as error:
        message=str(error)
        # Match the entire known Docker diagnostic, including the exact
        # requested reference. Additional/mixed errors remain UNKNOWN.
        missing = (r'(?i:Docker command failed: (?:error: |Error response from daemon: )?'
                   r'no such (?:object|container): )' + re.escape(reference))
        if re.fullmatch(missing,message) is not None:return None
        raise
    require(isinstance(records,list) and len(records)==1,'Ambiguous owned container inspection')
    state=records[0]
    require(re.fullmatch('[0-9a-f]{64}',state.get('Id','')) is not None,'Invalid inspected CID')
    require(state.get('Name')=='/'+ownership['name'],'Owned container name mismatch')
    labels=state.get('Config',{}).get('Labels') or {}
    require(all(labels.get(k)==v for k,v in ownership['labels'].items()),'Owned container labels mismatch')
    if cid_reference:require(state['Id']==cid_reference,'Owned CID inspection mismatch')
    return state


def load_ownership(directory):
    directory=Path(directory).resolve(strict=True)
    ownership=json.loads((directory/'ownership.json').read_text(encoding='utf-8'))
    require(ownership.get('schema')==1,'Unknown native ownership schema')
    nonce=ownership.get('nonce','')
    require(re.fullmatch('[0-9a-f]{32}',nonce) is not None,'Invalid native ownership nonce')
    require(ownership.get('name')=='1cdb2src-'+nonce,'Invalid native ownership name')
    require(Path(ownership['destination']).resolve()==directory,'Ownership destination mismatch')
    require(Path(ownership['cidfile']).resolve()==directory/'container.cid','Ownership CID path mismatch')
    expected={'onecdb2src.export.nonce':nonce,'onecdb2src.export.destination':hashlib.sha256(str(directory).encode()).hexdigest(),
              'onecdb2src.export.source':hashlib.sha256(str(Path(ownership['source']).resolve()).encode()).hexdigest()}
    require(ownership.get('labels')==expected,'Ownership labels malformed')
    return ownership


def cleanup_owned(directory):
    """Return confirmed absence/removal or raise; never hide UNKNOWN daemon state."""
    state=inspect_owned(directory)
    if state is None:return {'status':'ABSENT','confirmed':True}
    cid=state['Id']
    docker('rm','--force',cid)
    require(inspect_owned(directory) is None,'Owned native container survives removal')
    return {'status':'REMOVED','confirmed':True,'container_id':cid}


def export(args):
    require(args.timeout > 0, 'Native timeout must be positive')
    source = Path(args.cf).resolve(strict=True)
    destination = Path(args.output).resolve()
    require(source.is_file(), 'CF input is not a file')
    profile_path=getattr(args,'profile_receipt',None)
    profile=profiles.load(profile_path,source) if profile_path else profiles.select(source,getattr(args,'platform','auto'))
    require(getattr(args,'platform','auto') in ('auto',profile['platform_profile']),'Native platform contradicts immutable profile')
    require(not destination.exists(), 'Output must be new; existing results are never overwritten')
    require(source != destination and source not in destination.parents, 'Invalid output path')
    context = context_record()
    info = json.loads(docker('info', '--format', '{{json .}}'))
    daemon_policy(context, info)
    metadata = json.loads(docker('image', 'inspect', args.image))[0]
    image_policy(args.image, metadata, args.binary)
    destination.mkdir(parents=True)
    if not profile_path:
        profile_path=destination/'profile.json'
        profiles.save_new(profile_path,profile)
    profile_path=Path(profile_path).resolve(strict=True)
    tree = destination / 'tree'
    tree.mkdir()
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    nonce=uuid.uuid4().hex
    name='1cdb2src-'+nonce
    ownership={'schema':1,'nonce':nonce,'name':name,'cidfile':str(destination/'container.cid'),
               'source':str(source),'destination':str(destination),
               'labels':{'onecdb2src.export.nonce':nonce,'onecdb2src.export.destination':hashlib.sha256(str(destination).encode()).hexdigest(),
                         'onecdb2src.export.source':hashlib.sha256(str(source).encode()).hexdigest()}}
    # Written before Docker create: an outer Job kill can still recover by name
    # and unique labels, even before create returns or a CID receipt is saved.
    save(destination/'ownership.json',ownership)
    receipt = {'schema_version': 1, 'status': 'RUNNING', 'provider': args.provider,
               'side': args.side, 'started_utc': started,
               'source': {'path': str(source), 'bytes': source.stat().st_size},
               'engine': {'image_id': args.image, 'binary': args.binary,
                          'platform_profile': profile['platform_profile'], 'xml_version': profile['xml_version'],
                          'profile_id':profile['profile_id']},
               'profile':profile,'profile_receipt':{'path':str(profile_path),'sha256':sha256(profile_path)},
               'native_xml': str(tree / 'xml'), 'verification': 'NOT_RUN',
               'producer_sha256': sha256(__file__)}
    save(destination / 'image-inspect.json', metadata)
    save(destination / 'docker-context.json', context)
    save(destination / 'docker-daemon.json', {key: info[key] for key in ('ID', 'Name', 'OSType', 'Architecture', 'MemTotal', 'ServerVersion')})
    if args.engine_receipt:
        evidence = Path(args.engine_receipt).resolve(strict=True)
        receipt['engine']['build_receipt'] = {'path': str(evidence), 'sha256': sha256(evidence)}
    created = False
    try:
        print(json.dumps({'stage': 'hash-input', 'provider': args.provider, 'side': args.side}), flush=True)
        receipt['source']['sha256'] = sha256(source)
        require(not args.expected_sha256 or receipt['source']['sha256'] == args.expected_sha256.lower(), 'CF SHA256 mismatch')
        command = create_command(args.image, args.binary, source, tree, name, args.memory_mib, args.workers, ownership,profile['platform_profile'])
        receipt['docker_create_argv'] = command
        save(destination / 'receipt.json', receipt)
        container_id = docker(*command).strip()
        require(re.fullmatch('[0-9a-f]{64}',container_id) is not None,'Invalid Docker create CID')
        created = True
        receipt['container_id'] = container_id
        save(destination/'receipt.json',receipt)
        state=inspect_owned(destination)
        require(state is not None and state['Id']==container_id,'Created container ownership mismatch')
        save(destination / 'container-before.json', state)
        print(json.dumps({'stage': 'export', 'container_id': container_id, 'output': str(tree / 'xml')}), flush=True)
        ticks = time.monotonic()
        with (destination / 'engine.stdout.json').open('wb') as out, (destination / 'engine.stderr.json').open('wb') as err:
            completed = subprocess.run(docker_argv('start', '--attach', container_id), env=docker_environment(), stdout=out, stderr=err, timeout=args.timeout)
        receipt['elapsed_seconds'] = round(time.monotonic() - ticks, 3)
        state = json.loads(docker('inspect', container_id))[0]
        save(destination / 'container-after.json', state)
        receipt['process'] = {'docker_start_exit': completed.returncode, 'container_state': state['State']}
        require(not state['State'].get('Running'), 'Container still running')
        receipt['source']['sha256_after'] = sha256(source)
        require(receipt['source']['sha256_after'] == receipt['source']['sha256'], 'CF changed during export')
        report = read_engine_report(destination / 'engine.stdout.json', destination / 'engine.stderr.json')
        require(report.get('source_version')==profile['xml_version'] and report.get('export',{}).get('source_version')==profile['xml_version'],
                'Engine report XML profile mismatch')
        require(profiles.load(profile_path,source)==profile,'Immutable native profile changed')
        require(sha256(profile_path)==receipt['profile_receipt']['sha256'],'Native profile receipt bytes changed')
        summary = report_summary(report)
        receipt['summary'] = summary
        require(state['State']['ExitCode'] == 0 and completed.returncode == 0 and report['ok'] is True,
                'Engine refused full export; retained partial tree and complete diagnostics')
        require(summary['storage']['opaque'] == 0 and summary['storage']['failed'] == 0, 'Engine contains opaque/failed records')
        require((tree / 'xml').is_dir(), 'Native XML tree absent')
        receipt['status'] = 'ENGINE_EXPORT_OK_VERIFICATION_PENDING'
    except BaseException as error:
        receipt['status'] = 'CANCELLED' if isinstance(error, KeyboardInterrupt) else 'FAILED'
        receipt['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        receipt['finished_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        if (destination/'ownership.json').exists():
            # Force-remove only the ID returned by this invocation. A timed-out
            # docker attach client does not stop the engine container itself.
            try:
                receipt['cleanup']=cleanup_owned(destination)
                receipt['container_removed'] = receipt['cleanup']['confirmed']
            except Exception as error:
                receipt['cleanup_error'] = str(error)
        save(destination / 'receipt.json', receipt)
    print(json.dumps({'status': receipt['status'], 'summary': receipt['summary']}, ensure_ascii=False), flush=True)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--cf', required=True)
    result.add_argument('--output', required=True)
    result.add_argument('--provider', choices=['mssql', 'postgresql'], required=True)
    result.add_argument('--side', choices=['main', 'vendor'], required=True)
    result.add_argument('--image', required=True, help='Immutable sha256 Docker image ID')
    result.add_argument('--binary', required=True, help='Absolute binary path inside audited image')
    result.add_argument('--engine-receipt')
    result.add_argument('--expected-sha256')
    result.add_argument('--memory-mib', type=int, required=True)
    result.add_argument('--workers', type=int, default=2)
    result.add_argument('--platform',choices=['auto','8.3.27','8.5.1'],default='auto')
    result.add_argument('--profile-receipt',help='Immutable selected per-CF profile receipt')
    result.add_argument('--timeout', type=float, default=2400, help='Native engine wall-clock limit in seconds')
    return result


if __name__ == '__main__':
    try:
        export(parser().parse_args())
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)
