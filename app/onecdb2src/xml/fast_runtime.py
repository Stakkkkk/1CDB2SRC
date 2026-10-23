"""Validate and load the bundled offline fast helper; never pull/build/run it.

PACKAGE is the application root (<installation>/app), as in cli.PACKAGE.
Only the documented Docker-save/OCI layouts below are accepted. This module
does not change the independent engine's runtime_identity contract.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import time

SCHEMA = '1CDB2SRC_FAST_HELPER_V1'
ENTRYPOINT = ['python', '-I', '-S', '-B', '/opt/app/onecdb2src/xml/linux_helpers.py']
OCI_INDEX = {'application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'}
OCI_MANIFEST = {'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'}
RAW_LAYERS = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.docker.image.rootfs.diff.tar'}
GZIP_LAYERS = {'application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar.gzip'}


def require(ok, message):
    if not ok:
        raise ValueError('Fast helper: ' + message)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_unique)


def _safe(value):
    require(type(value) is str and value and not any(c in value for c in ('\\', ':', '\0')), 'unsafe bundle path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and '..' not in path.parts and path.as_posix() == value, 'noncanonical bundle path')
    return path


def _regular(path, directory=False):
    info = path.lstat()
    require(not getattr(info, 'st_file_attributes', 0) & 0x400 and not stat.S_ISLNK(info.st_mode), 'link/reparse input forbidden')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'unexpected input kind')
    require(directory or info.st_nlink == 1, 'hardlinked bundle input forbidden')
    return info


def _token(info):
    # Windows path-stat and handle-stat can expose different ctime semantics;
    # compare ctime only between observations of the SAME open handle.
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _fact(path, check=lambda: None):
    before = _regular(path)
    digest = hashlib.sha256()
    count = 0
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        require(_token(opened) == _token(before), 'input changed before open')
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
            count += len(chunk)
            check()
        after_open = os.fstat(stream.fileno())
        require(_token(after_open) == _token(before) and after_open.st_ctime_ns == opened.st_ctime_ns, 'open input changed')
    require(_token(_regular(path)) == _token(before) and count == before.st_size, 'input changed while reading')
    return {'bytes': count, 'sha256': digest.hexdigest()}


def _expected_fact(value):
    require(type(value) is dict and set(value) == {'bytes', 'sha256'}, 'invalid file fact')
    require(type(value['bytes']) is int and value['bytes'] >= 0 and type(value['sha256']) is str
            and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'invalid file fact values')


def _path(root, relative):
    parts = _safe(relative).parts
    target = root.joinpath(*parts)
    for parent in reversed(target.parents):
        if parent == root or root in parent.parents:
            _regular(parent, True)
    _regular(target)
    return target


def _closure(root, relative, predicate):
    directory = root / relative
    _regular(directory, True)
    names = set()
    def failed(error):
        raise error
    for base, dirs, files in os.walk(directory, followlinks=False, onerror=failed):
        base = Path(base)
        _regular(base, True)
        for name in dirs:
            _regular(base / name, True)
        for name in files:
            path = base / name
            key = path.relative_to(root).as_posix()
            if predicate(key):
                _regular(path)
                names.add(key)
    return names


def _bundle_files(root, manifest, check):
    sources, runtimes = manifest['source_files'], manifest['runtime_files']
    require(type(sources) is dict and sources and type(runtimes) is dict and runtimes, 'empty source/runtime closure')
    actual_sources = _closure(root, 'onecdb2src', lambda p: p.endswith('.py') or p == 'onecdb2src/xml/data/assets.rs')
    actual_runtime = _closure(root, 'runtime/local', lambda p: True)
    require(set(sources) == actual_sources and set(runtimes) == actual_runtime, 'source/runtime pathset mismatch')
    require('onecdb2src/xml/data/assets.rs' in sources, 'assets.rs missing from source closure')
    facts = {}
    for mapping in (sources, runtimes):
        for name, expected in mapping.items():
            require(name.startswith('onecdb2src/') if mapping is sources else name.startswith('runtime/local/'), 'wrong closure namespace')
            _expected_fact(expected)
            facts[name] = _fact(_path(root, name), check)
            require(facts[name] == expected, 'source/runtime hash mismatch: ' + name)
    return facts


def _digest_id(value):
    require(type(value) is str and re.fullmatch('sha256:[0-9a-f]{64}', value), 'invalid image/blob digest')
    return value


def archive_identity(archive, check=lambda: None):
    """Return proven identity/config from one Docker-save TAR (optionally gzip).

    Supports OCI index->single Linux/amd64 manifest, OCI direct manifest, and
    classic Docker manifest.json with one config/layer chain. No extraction,
    layer execution or network is involved; every selected layer is hashed.
    """
    before = _token(_regular(archive))
    with tarfile.open(archive, 'r:*') as tar:
        members = {}
        for member in tar:
            check()
            name = member.name.rstrip('/') if member.isdir() else member.name
            if name in ('', '.') and member.isdir():
                continue
            _safe(name)
            require(name not in members, 'duplicate archive member')
            require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                    and member.sparse is None, 'archive links/special/sparse entries unsupported')
            members[name] = member

        def stream(name):
            _safe(name)
            require(name in members and members[name].isfile(), 'missing regular archive member')
            return tar.extractfile(members[name])

        def document(name):
            require(name in members and members[name].size <= 4 * 1024 * 1024, 'identity JSON absent/oversized')
            with stream(name) as source:
                return _json(source.read())

        def digest_stream(source):
            digest = hashlib.sha256()
            count = 0
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(chunk)
                count += len(chunk)
                check()
            return 'sha256:' + digest.hexdigest(), count

        def descriptor(row, parse=False):
            require(type(row) is dict, 'invalid OCI descriptor')
            digest = _digest_id(row.get('digest'))
            require(type(row.get('size')) is int and row['size'] >= 0, 'invalid OCI blob size')
            name = 'blobs/sha256/' + digest[7:]
            require(name in members and members[name].size == row['size'], 'OCI descriptor size mismatch')
            with stream(name) as source:
                actual, size = digest_stream(source)
            require(actual == digest and size == row['size'], 'OCI descriptor digest mismatch')
            return document(name) if parse else name

        if 'index.json' in members:
            require(document('oci-layout') == {'imageLayoutVersion': '1.0.0'}, 'unsupported OCI layout')
            index = document('index.json')
            require(index.get('schemaVersion') == 2 and type(index.get('manifests')) is list
                    and len(index['manifests']) == 1, 'unsupported OCI root index shape')
            root = index['manifests'][0]
            provenance = _digest_id(root.get('digest'))
            node = descriptor(root, True)
            if root.get('mediaType') in OCI_INDEX:
                require(node.get('schemaVersion') == 2 and type(node.get('manifests')) is list, 'invalid nested OCI index')
                candidates = [row for row in node['manifests'] if row.get('platform') == {'architecture': 'amd64', 'os': 'linux'}]
                require(len(candidates) == 1, 'expected one Linux amd64 OCI image')
                image_row = candidates[0]
                require(image_row.get('mediaType') in OCI_MANIFEST, 'unsupported selected OCI image media type')
                image = descriptor(image_row, True)
                platform_id = image_row['digest']
                format_name = 'OCI_INDEX'
            else:
                require(root.get('mediaType') in OCI_MANIFEST, 'unsupported OCI root media type')
                image, platform_id, format_name = node, provenance, 'OCI_DIRECT_MANIFEST'
            require(image.get('schemaVersion') == 2 and type(image.get('layers')) is list, 'invalid OCI image manifest')
            require(image['config'].get('mediaType') in {'application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'}, 'unsupported OCI config media type')
            config = descriptor(image['config'], True)
            config_id = image['config']['digest']
            layers = image['layers']
            diff_ids = config.get('rootfs', {}).get('diff_ids')
            require(config.get('rootfs', {}).get('type') == 'layers' and type(diff_ids) is list
                    and len(diff_ids) == len(layers), 'invalid OCI rootfs chain')
            for layer, expected_diff in zip(layers, diff_ids):
                _digest_id(expected_diff)
                media = layer.get('mediaType')
                require(media in RAW_LAYERS | GZIP_LAYERS, 'unsupported OCI layer compression/media type')
                name = descriptor(layer)
                with stream(name) as raw:
                    if media in GZIP_LAYERS:
                        with gzip.GzipFile(fileobj=raw) as decoded:
                            actual_diff, ignored = digest_stream(decoded)
                    else:
                        actual_diff, ignored = digest_stream(raw)
                require(actual_diff == expected_diff, 'OCI layer diff-id mismatch')
            # Docker-save can carry a classic compatibility manifest beside
            # OCI metadata. Bind that alternate loader view to the SAME image;
            # never let docker load interpret an unchecked second payload.
            if 'manifest.json' in members:
                compatibility = document('manifest.json')
                require(type(compatibility) is list and len(compatibility) == 1, 'ambiguous OCI compatibility manifest')
                row = compatibility[0]
                require(type(row) is dict and row.get('Config') == 'blobs/sha256/' + config_id[7:]
                        and row.get('Layers') == ['blobs/sha256/' + layer['digest'][7:] for layer in layers],
                        'OCI/classic compatibility views disagree')
        elif 'manifest.json' in members:
            rows = document('manifest.json')
            require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, 'unsupported classic Docker archive shape')
            row = rows[0]
            require(type(row.get('Config')) is str and re.fullmatch('[0-9a-f]{64}\\.json', row['Config']), 'unsupported classic Docker config name')
            config = document(row['Config'])
            with stream(row['Config']) as source:
                config_id, ignored = digest_stream(source)
            require(config_id[7:] + '.json' == row['Config'], 'classic config digest mismatch')
            diff_ids = config.get('rootfs', {}).get('diff_ids')
            layers = row.get('Layers')
            require(config.get('rootfs', {}).get('type') == 'layers' and type(diff_ids) is list
                    and type(layers) is list and len(diff_ids) == len(layers), 'invalid classic rootfs chain')
            for name, expected_diff in zip(layers, diff_ids):
                _digest_id(expected_diff)
                with stream(name) as source:
                    actual_diff, ignored = digest_stream(source)
                require(actual_diff == expected_diff, 'classic layer diff-id mismatch')
            provenance = platform_id = config_id
            format_name = 'DOCKER_CLASSIC'
        else:
            raise ValueError('Fast helper: unsupported archive layout (expected structured OCI or classic Docker-save)')
        require(config.get('os') == 'linux' and config.get('architecture') == 'amd64', 'helper config must be Linux amd64')
        require(type(config.get('config')) is dict, 'helper execution config missing')
    require(_token(_regular(archive)) == before, 'archive changed during identity verification')
    return {'archive_format': format_name, 'provenance_image_id': provenance,
            'platform_manifest_id': platform_id, 'classic_config_image_id': config_id,
            'allowed_image_ids': list(dict.fromkeys([provenance, config_id])),
            'rootfs_diff_ids': diff_ids}, config['config']


def derive_archive_identity(archive):
    """Pure root-builder API: (identity, execution_config), no Docker calls."""
    return archive_identity(Path(archive))


def prepare_helper(config, PACKAGE):
    from . import export_native as native
    deadline = config.get('total_deadline_monotonic')
    require(deadline is None or (type(deadline) in (int, float) and math.isfinite(deadline)), 'invalid overall deadline')
    def remaining(limit=60):
        value = limit if deadline is None else min(limit, deadline - time.monotonic())
        require(value > 0, 'overall deadline expired')
        return value
    def check():
        remaining()
    def docker(*args, timeout=60):
        return subprocess.run(native.docker_argv(*map(str, args)), env=native.docker_environment(),
                              capture_output=True, encoding='utf-8', errors='replace', timeout=remaining(timeout))
    def success(*args):
        done = docker(*args)
        require(done.returncode == 0, 'local Docker command failed: ' + done.stderr[:1000])
        return done.stdout

    root = Path(PACKAGE).absolute()
    _regular(root, True)
    manifest_path = _path(root, 'runtime/fast-helper/manifest.json')
    manifest_fact = _fact(manifest_path, check)
    require(manifest_fact['bytes'] <= 4 * 1024 * 1024, 'manifest format oversized')
    manifest = _json(manifest_path.read_bytes())
    require(manifest.get('schema') == SCHEMA and manifest.get('entrypoint') == ENTRYPOINT, 'unsupported helper manifest/entrypoint')
    archive_fact = manifest['archive']
    require(type(archive_fact) is dict and set(archive_fact) == {'file', 'bytes', 'sha256'}
            and archive_fact['file'] in ('helper-image.tar', 'helper-image.tar.gz'), 'unsupported helper archive declaration')
    expected_archive = {key: archive_fact[key] for key in ('bytes', 'sha256')}
    _expected_fact(expected_archive)
    source_before = _bundle_files(root, manifest, check)
    archive = _path(root, 'runtime/fast-helper/' + archive_fact['file'])
    archive_before = _token(_regular(archive))
    require(_fact(archive, check) == expected_archive, 'bundled helper archive hash mismatch')
    identity, execution = archive_identity(archive, check)
    expected_identity = manifest['image_identity']
    require(type(expected_identity) is dict, 'image identity missing')
    for key in ('allowed_image_ids', 'rootfs_diff_ids', 'provenance_image_id', 'classic_config_image_id'):
        require(expected_identity.get(key) == identity[key], 'archive/manifest identity mismatch: ' + key)
    for key in ('archive_format', 'platform_manifest_id'):
        require(key not in expected_identity or expected_identity[key] == identity[key], 'archive/manifest identity mismatch: ' + key)
    require(manifest['image_id'] == identity['provenance_image_id'], 'primary image is not archive provenance')
    require(execution.get('User') == '65532:65532' and execution.get('Entrypoint') == ENTRYPOINT,
            'archive helper user/entrypoint mismatch')
    require(not execution.get('Volumes') and not execution.get('OnBuild'), 'archive helper declares Volumes/OnBuild')
    require(type(execution.get('Env')) is list and all(type(item) is str and '=' in item
            and not item.split('=', 1)[0].upper().startswith('IBC') for item in execution['Env']),
            'archive helper has malformed/unsafe environment')
    require('env' not in manifest or manifest['env'] == execution.get('Env'), 'manifest/archive ENV mismatch')

    # Reuse the established local endpoint/environment contract, with every
    # subprocess timeout bounded by the existing caller's overall deadline.
    if native.DOCKER_SOCKET:
        context = {'Name': 'explicit-local-unix-socket', 'Endpoints': {'docker': {'Host': 'unix://' + native.DOCKER_SOCKET}}}
    else:
        selected = native.DOCKER_CONTEXT or success('context', 'show').strip()
        require(re.fullmatch('[A-Za-z0-9_.-]+', selected), 'invalid selected Docker context')
        context = json.loads(success('context', 'inspect', selected))[0]
        native.configure(context=selected)
    native.endpoint_policy(context)
    info = json.loads(success('info', '--format', '{{json .}}'))
    native.daemon_policy(context, info)

    def inspect():
        for requested in identity['allowed_image_ids']:
            done = docker('image', 'inspect', requested)
            if done.returncode:
                missing = r'(?:Error response from daemon: |Error: )?(?:No such image: |No such object: )' + re.escape(requested) + r'\s*'
                require(re.fullmatch(missing, done.stderr, flags=re.IGNORECASE), 'image inspection failed; absence not established: ' + done.stderr[:1000])
                continue
            rows = json.loads(done.stdout)
            require(type(rows) is list and len(rows) == 1, 'ambiguous helper image inspection')
            item = rows[0]
            selected = item['Id']
            require(selected in identity['allowed_image_ids'] and item.get('RootFS', {}).get('Type') == 'layers'
                    and item['RootFS'].get('Layers') == identity['rootfs_diff_ids'], 'loaded helper identity/rootfs mismatch')
            require(item.get('Os') == 'linux' and item.get('Architecture') == 'amd64', 'loaded helper platform mismatch')
            current = item['Config']
            for key in ('User', 'Entrypoint', 'Env', 'Cmd', 'WorkingDir'):
                require(current.get(key) == execution.get(key), 'loaded helper execution config mismatch: ' + key)
            native.image_policy(selected, item, '/opt/app/onecdb2src/xml/linux_helpers.py')
            return selected, item
        return None, None

    selected, metadata = inspect()
    loaded = False
    if selected is None:
        done = docker('load', '--input', archive, timeout=120)
        require(done.returncode == 0, 'offline helper load failed: ' + done.stderr[:1000])
        loaded = True
        selected, metadata = inspect()
    require(selected is not None, 'bundled helper unavailable after offline load')
    require(_token(_regular(archive)) == archive_before, 'archive changed during preflight/load')
    require(_bundle_files(root, manifest, check) == source_before and _fact(manifest_path, check) == manifest_fact,
            'bundle source/manifest changed during helper preflight')
    check()
    return {'manifest_path': str(manifest_path), 'manifest_sha256': manifest_fact['sha256'], 'selected_image_id': selected,
            'proof': {'status': 'VERIFIED_BUNDLED_OFFLINE_HELPER', 'archive': expected_archive,
                      'image_identity': identity, 'loaded_from_archive': loaded,
                      'source_files': len(manifest['source_files']), 'runtime_files': len(manifest['runtime_files']),
                      'source_closure_before_after': True, 'archive_stable': True,
                      'context': context, 'memory_controls': False, 'helper_executed': False}}
