"""SOURCE-ONLY until explicit GO. Offline proof image ASSEMBLY, no build/run/pull.

Creates one stopped container from an already cached immutable base with
--pull=never, copies only pinned regular files, commits one local image layer.
Neither the container nor Rust/Python payload is executed by this script.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import time
import uuid

HERE = Path(__file__).resolve().parent
BASE = 'sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641'


def fact(path):
    with Path(path).open('rb') as stream:
        sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'bytes': Path(path).stat().st_size, 'sha256': sha}


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='NEW journal/image-ID directory')
    parser.add_argument('--seconds', type=float, default=180)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--expected-context-sha256', required=True)
    args = parser.parse_args()
    require(args.seconds > 0, 'Invalid assembly deadline')
    output = args.output.absolute()
    require(not output.exists(), 'Output must be new')
    output.mkdir(parents=True)
    manifest_path = args.manifest.resolve(strict=True)
    manifest = read(manifest_path)
    manifest_fact = fact(manifest_path)
    require(re.fullmatch('[a-f0-9]{64}', args.expected_context_sha256) and manifest_fact['sha256'] == args.expected_context_sha256, 'Authorised frozen context manifest pin mismatch')
    require(manifest['status'] == 'PREPARED_FROZEN_CONTEXT_ONLY' and manifest['base_image'] == BASE,
            'Unexpected frozen context')
    context = Path(manifest['context'])
    require(context.resolve().parent == manifest_path.parent and context.name == 'context', 'Unexpected context path')
    require(context not in output.parents and output not in context.parents, 'Context/output overlap')
    nonce = uuid.uuid4().hex
    name = '1cdb2src-fast-build-' + nonce
    label = '1cdb2src.fast.build.nonce'
    journal = {'schema': 1, 'status': 'ASSEMBLING', 'name': name, 'nonce': nonce, 'base_image': BASE,
               'context_manifest': manifest_fact, 'assembly_only': True, 'container_starts': 0,
               'build': 'NOT_RUN', 'pull': 'FORBIDDEN', 'memory_controls': False,
               'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'actions': []}
    save(output / 'result.json', journal)
    env = {key: value for key, value in os.environ.items()
           if key.upper() not in {'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY',
                                  'DOCKER_CERT_PATH', 'PGPASSWORD', 'ONECDB2SRC_AUTH_PASSWORD'}}
    started = time.monotonic()
    cleanup = False
    cleanup_until = None
    attempted = False
    base = None

    def snapshot():
        save(output / 'result.json', journal)

    def docker(*parts, stdin=None):
        left = cleanup_until - time.monotonic() if cleanup else args.seconds - (time.monotonic() - started)
        require(left > 0, 'Assembly/cleanup deadline expired')
        argv = ['docker', '--context', 'desktop-linux', *map(str, parts)]
        require(not any(part in ('start', 'run', 'build', 'pull') for part in parts), 'Execution/network command forbidden')
        row = {'argv': argv, 'started_seconds': time.monotonic() - started}
        journal['actions'].append(row)
        snapshot()
        tick = time.monotonic()
        result = subprocess.run(argv, stdin=stdin, capture_output=True, timeout=min(left, 120), env=env)
        row.update(seconds=time.monotonic() - tick, exit=result.returncode)
        snapshot()
        require(result.returncode == 0, 'Docker command failed: ' + result.stderr.decode('utf-8', errors='replace').strip())
        return result.stdout

    def own():
        records = json.loads(docker('inspect', name))
        require(len(records) == 1, 'Ambiguous prep container')
        value = records[0]
        require(value['Name'] == '/' + name and value['Config']['Labels'].get(label) == nonce,
                'Prep ownership mismatch')
        if journal.get('container_id'):
            require(value['Id'] == journal['container_id'], 'Recorded prep CID differs from owned name')
        require(value['Config']['Image'] == BASE and value['State']['Running'] is False
                and value['State']['Status'] == 'created' and value['State'].get('Pid') == 0,
                'Prep was executed or base changed')
        require(not value.get('Mounts') and value['HostConfig']['NetworkMode'] == 'none',
                'Unexpected prep mounts/network')
        return value

    def validate_image(metadata, expected_id=None):
        require(re.fullmatch('sha256:[a-f0-9]{64}', metadata['Id'])
                and (expected_id is None or metadata['Id'] == expected_id)
                and metadata['Architecture'] == 'amd64'
                and metadata['Config']['Labels'].get(label) == nonce
                and metadata['Config']['Labels'].get('1cdb2src.fast.build.context_sha256') == manifest_fact['sha256'],
                'Committed image identity/pins mismatch')
        require(metadata['Config']['User'] == '65532:65532'
                and metadata['Config']['Entrypoint'] == ['python', '-I', '-S', '-B', '/opt/app/onecdb2src/xml/linux_helpers.py']
                and metadata['Config'].get('Cmd') in (None, [])
                and not metadata['Config'].get('Volumes') and not metadata['Config'].get('OnBuild'),
                'Committed runtime configuration mismatch')
        env_values = dict(value.split('=', 1) for value in metadata['Config'].get('Env', []))
        require(env_values.get('PYTHONDONTWRITEBYTECODE') == '1' and env_values.get('PYTHONUTF8') == '1',
                'Committed helper ENV differs from requested changes')
        base_layers = base['RootFS']['Layers']
        image_layers = metadata['RootFS']['Layers']
        require(image_layers[:len(base_layers)] == base_layers and len(image_layers) == len(base_layers) + 1,
                'Expected exact cached base plus one owned payload layer')

    def recover_commit():
        """Target only this durable intent; no image deletion/prune or false absence."""
        recovery = {'status': 'UNKNOWN_PENDING', 'action': 'NO_IMAGES_REMOVED',
                    'intent': journal['commit_intent'], 'accepted_for_execution': False}
        journal['commit_recovery'] = recovery
        snapshot()
        ids = sorted(set(docker('images', '--no-trunc', '--quiet', '--filter', 'label=' + label + '=' + nonce,
            '--filter', 'label=1cdb2src.fast.build.context_sha256=' + manifest_fact['sha256']).decode().split()))
        recovery['observed_candidate_ids'] = ids
        if len(ids) != 1:
            recovery['reason'] = 'No single observable owned image; commit may still finish after response loss'
            snapshot()
            return
        require(fact(manifest_path) == manifest_fact, 'Frozen context manifest changed during commit recovery')
        for row in manifest['files']:
            require(fact(context / row['context_path']) == {key: row[key] for key in ('bytes', 'sha256')},
                    'Frozen source pin changed during commit recovery')
        metadata = json.loads(docker('image', 'inspect', ids[0]))[0]
        validate_image(metadata, journal.get('image_id'))
        save(output / 'recovered-image-inspect.json', metadata)
        recovery.update(status='RECOVERED_OWNED_IMAGE_UNACCEPTED', image_id=metadata['Id'],
                        metadata_receipt=fact(output / 'recovered-image-inspect.json'),
                        reason='Retained for explicit handoff; failed operation remains FAILED')
        snapshot()

    try:
        local = json.loads(docker('context', 'inspect', 'desktop-linux'))[0]
        require(local['Endpoints']['docker']['Host'] == 'npipe:////./pipe/dockerDesktopLinuxEngine',
                'Only local Desktop Linux endpoint allowed')
        base = json.loads(docker('image', 'inspect', BASE))[0]
        require(base['Id'] == BASE and base['Architecture'] == 'amd64'
                and 'python@' + BASE in base['RepoDigests'] and base['Descriptor']['digest'] == BASE,
                'Cached base pin mismatch: STOP without pull')
        require(not base['Config'].get('Volumes') and not base['Config'].get('OnBuild'), 'Unexpected base hooks/volumes')
        save(output / 'base-inspect.json', base)
        payload = []
        for row in manifest['files']:
            relative = PurePosixPath(row['context_path'])
            require(not relative.is_absolute() and '..' not in relative.parts and '\\' not in row['context_path'],
                    'Unsafe context path')
            file = context / relative
            info = file.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and not getattr(info, 'st_file_attributes', 0) & 0x400, 'Nonregular context file')
            require(fact(file) == {key: row[key] for key in ('bytes', 'sha256')}, 'Frozen context pin mismatch')
            if relative.parts[:2] in (('app', 'onecdb2src'), ('app', 'runtime')):
                target = PurePosixPath('opt') / relative
            elif relative.as_posix() == 'linux_helpers.py':
                target = PurePosixPath('opt/bd029/linux_helpers.py')
            else:
                continue  # Dockerfile/.dockerignore are recipes, not payload.
            payload.append((file, target, row))
        require(payload and len({target for _, target, _ in payload}) == len(payload), 'Duplicate/empty payload')
        archive_path = output / 'source-payload.tar'
        with tarfile.open(archive_path, mode='w') as archive:
            directories = set()
            for _, target, _ in payload:
                directories.update(parent for parent in target.parents if parent.as_posix() != '.')
            for directory in sorted(directories, key=lambda value: (len(value.parts), value.as_posix())):
                entry = tarfile.TarInfo(directory.as_posix())
                entry.type = tarfile.DIRTYPE
                entry.uid = entry.gid = 0
                entry.mode = 0o755 if directory.as_posix() == 'opt' else 0o555
                archive.addfile(entry)
            for file, target, row in payload:
                require(time.monotonic() - started < args.seconds, 'Deadline during source TAR')
                entry = tarfile.TarInfo(target.as_posix())
                entry.size = row['bytes']
                entry.uid = entry.gid = 0
                entry.mode = 0o555 if target.name in ('ibcmd-rs', 'ld-linux-x86-64.so.2') else 0o444
                with file.open('rb') as stream:
                    archive.addfile(entry, stream)
                require(fact(file) == {key: row[key] for key in ('bytes', 'sha256')}, 'Context changed during TAR')
        journal['payload_tar'] = fact(archive_path)
        journal['payload_files'] = len(payload)
        attempted = True
        journal['container_create_attempted'] = True
        snapshot()
        cid = docker('create', '--pull=never', '--name', name, '--label', label + '=' + nonce,
                     '--network', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                     '--cpus', '1', BASE).decode('ascii').strip()
        require(re.fullmatch('[a-f0-9]{64}', cid), 'Invalid prep CID')
        journal['create_response_cid'] = cid
        snapshot()
        require(own()['Id'] == cid, 'Returned create CID differs from exact owned name')
        journal['container_id'] = cid
        save(output / 'prep-before.json', own())
        with archive_path.open('rb') as stream:
            docker('cp', '-a', '-', cid + ':/', stdin=stream)
        save(output / 'prep-after-copy.json', own())
        require(fact(manifest_path) == manifest_fact, 'Frozen manifest changed')
        journal['commit_attempted'] = True
        journal['commit_intent'] = {'nonce': nonce, 'labels': {label: nonce,
                 '1cdb2src.fast.build.context_sha256': manifest_fact['sha256']}, 'container_id': cid,
                 'base_image': BASE, 'context_manifest': manifest_fact, 'state': 'REQUESTED'}
        snapshot()
        image = docker('commit', '--change', 'USER 65532:65532',
                       '--change', 'ENTRYPOINT ["python","-I","-S","-B","/opt/app/onecdb2src/xml/linux_helpers.py"]',
                       '--change', 'CMD []', '--change', 'ENV PYTHONDONTWRITEBYTECODE=1',
                       '--change', 'ENV PYTHONUTF8=1', '--change', 'LABEL ' + label + '=' + nonce,
                       '--change', 'LABEL 1cdb2src.fast.build.context_sha256=' + manifest_fact['sha256'], cid).decode('ascii').strip()
        require(re.fullmatch('sha256:[a-f0-9]{64}', image), 'Invalid committed image ID')
        journal['image_id'] = image
        metadata = json.loads(docker('image', 'inspect', image))[0]
        validate_image(metadata, image)
        save(output / 'proof-image-inspect.json', metadata)
        (output / 'proof-image.id').write_text(image + '\n', encoding='ascii')
        save(output / 'prep-after-commit.json', own())
        journal['status'] = 'ASSEMBLED_STOPPED_CONTAINER_IMAGE_SMALL_EXECUTION_NOT_RUN'
        journal['commit_intent']['state'] = 'METADATA_VERIFIED_EXECUTION_NOT_RUN'
        journal['base_layers_verified'] = True
        journal['rust_build'] = 'NOT_RUN'
        journal['payload_readback_in_container'] = 'REQUIRED_ON_FIRST_SMALL_RUN'
    except BaseException as error:
        journal.update(status='FAILED', error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        cleanup = True
        cleanup_until = time.monotonic() + 15
        if journal.get('commit_attempted') and journal['status'] != 'ASSEMBLED_STOPPED_CONTAINER_IMAGE_SMALL_EXECUTION_NOT_RUN':
            try:
                recover_commit()
            except BaseException as error:
                recovery = journal.setdefault('commit_recovery', {})
                recovery.update(status='UNKNOWN_PENDING', accepted_for_execution=False,
                     action='NO_IMAGES_REMOVED', error=type(error).__name__ + ': ' + str(error))
        # Image uncertainty must not consume the prep-container cleanup reserve.
        cleanup_until = time.monotonic() + 30
        try:
            if attempted:
                names = docker('ps', '-a', '--format', '{{.Names}}', '--filter', 'name=^/' + name + '$').decode().split()
                if names:
                    require(names == [name], 'Ambiguous own prep name')
                    value = own()
                    docker('rm', value['Id'])  # Never started; no force needed.
                    require(not docker('ps', '-a', '-q', '--filter', 'name=^/' + name + '$').strip(), 'Prep survives remove')
                journal['prep_container_absent_confirmed'] = True
        except BaseException as error:
            journal['cleanup_error'] = type(error).__name__ + ': ' + str(error)
            journal['status'] = 'FAILED_CLEANUP_UNCONFIRMED'
        journal.update(seconds=time.monotonic() - started,
                       finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        snapshot()
        if journal.get('cleanup_error'):
            raise RuntimeError('Own stopped-container cleanup unconfirmed')


if __name__ == '__main__':
    main()
