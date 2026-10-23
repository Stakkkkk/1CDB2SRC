"""Tiny genuine archive/filesystem fixtures, fake Docker only; no real image IO."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from onecdb2src.xml import export_native as native
from onecdb2src.xml import fast_runtime as module


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def tiny_layer():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as tar:
        info = tarfile.TarInfo('neutral.txt')
        raw = b'neutral fixture bytes\n'
        info.size = len(raw)
        tar.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def archive(path, layout='direct', defect=None):
    raw_layer = tiny_layer()
    encoded_layer = gzip.compress(raw_layer, mtime=0) if layout == 'index' else raw_layer
    execution = {'User': '65532:65532', 'Entrypoint': module.ENTRYPOINT,
                 'Env': ['PATH=/usr/bin', 'PYTHONDONTWRITEBYTECODE=1'], 'Cmd': None, 'WorkingDir': ''}
    if defect == 'user': execution['User'] = '0:0'
    if defect == 'entrypoint': execution['Entrypoint'] = ['sh']
    if defect == 'env': execution['Env'].append('IBC_UNTRUSTED=1')
    config = {'architecture': 'amd64', 'os': 'linux', 'config': execution,
              'rootfs': {'type': 'layers', 'diff_ids': [digest(raw_layer) if defect != 'diff-id' else 'sha256:'+'0'*64]}}
    config_bytes = packed(config)
    config_id = digest(config_bytes)
    members = {}
    def blob(raw, media):
        value = {'mediaType': media, 'digest': digest(raw), 'size': len(raw)}
        members['blobs/sha256/' + value['digest'][7:]] = raw
        return value
    if layout == 'classic':
        config_name = config_id[7:] + '.json'
        members[config_name] = config_bytes
        members['layer/layer.tar'] = raw_layer
        members['manifest.json'] = packed([{'Config': config_name, 'RepoTags': [], 'Layers': ['layer/layer.tar']}])
    else:
        config_row = blob(config_bytes, 'application/vnd.oci.image.config.v1+json')
        layer_row = blob(encoded_layer, 'application/vnd.oci.image.layer.v1.tar+gzip' if layout == 'index' else 'application/vnd.oci.image.layer.v1.tar')
        image = {'schemaVersion': 2, 'config': config_row, 'layers': [layer_row]}
        image_row = blob(packed(image), 'application/vnd.oci.image.manifest.v1+json')
        if layout == 'index':
            image_row['platform'] = {'architecture': 'amd64', 'os': 'linux'}
            root = blob(packed({'schemaVersion': 2, 'manifests': [image_row]}), 'application/vnd.oci.image.index.v1+json')
        else:
            root = image_row
        members['index.json'] = packed({'schemaVersion': 2, 'manifests': [root]})
        members['oci-layout'] = packed({'imageLayoutVersion': '1.0.0'})
        if layout == 'compat' or defect == 'mixed':
            members['manifest.json'] = packed([{'Config': 'blobs/sha256/' + config_id[7:],
                'Layers': ['blobs/sha256/' + layer_row['digest'][7:]] if defect != 'mixed' else ['foreign/layer.tar']}])
        if defect == 'layer':
            members['blobs/sha256/' + layer_row['digest'][7:]] = b'X' + encoded_layer[1:]
        if defect == 'config':
            members['blobs/sha256/' + config_id[7:]] = b'X' + config_bytes[1:]
    if defect == 'path': members['../escape'] = b'bad'
    with tarfile.open(path, 'w') as tar:
        for name, raw in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    return execution


def fixture(root, layout='direct', defect=None):
    app = root/'app'
    files = {'onecdb2src/__init__.py': b'# fixture\n', 'onecdb2src/xml/linux_helpers.py': b'# helper fixture\n',
             'onecdb2src/xml/data/assets.rs': b'// assets\n', 'runtime/local/linux-amd64/ibcmd-rs': b'fixture-not-executable\n'}
    for name, raw in files.items():
        path = app/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    directory = app/'runtime/fast-helper'
    directory.mkdir(parents=True)
    tar = directory/'helper-image.tar'
    execution = archive(tar, layout, defect)
    if defect in ('layer', 'config', 'diff-id', 'path', 'mixed'):
        return app, tar, None, execution
    identity, decoded = module.archive_identity(tar)
    manifest = {'schema': module.SCHEMA, 'archive': {'file': 'helper-image.tar', **module._fact(tar)},
                'image_id': identity['provenance_image_id'], 'image_identity': identity,
                'entrypoint': module.ENTRYPOINT, 'env': execution['Env'],
                'source_files': {name: module._fact(app/name) for name in files if name.startswith('onecdb2src/')},
                'runtime_files': {name: module._fact(app/name) for name in files if name.startswith('runtime/local/')}}
    (directory/'manifest.json').write_bytes(packed(manifest))
    return app, tar, manifest, execution


class Docker:
    def __init__(self, manifest, execution, *, missing=False, fault=None, mutate=None):
        self.manifest, self.execution, self.missing, self.fault, self.mutate = manifest, execution, missing, fault, mutate
        self.calls = []
    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        self.assert_local(argv, kwargs)
        parts = argv[3:]  # docker --context desktop-linux ...
        output, error, code = '', '', 0
        if parts[:2] == ['context', 'inspect']:
            endpoint = self.endpoint
            if self.fault == 'remote': endpoint = 'tcp://foreign:2375'
            output = json.dumps([{'Name': 'desktop-linux', 'Endpoints': {'docker': {'Host': endpoint}}}])
        elif parts[0] == 'info':
            output = json.dumps({'Name': 'docker-desktop', 'OSType': 'linux', 'Architecture': 'amd64'})
        elif parts[:2] == ['image', 'inspect']:
            if self.fault == 'daemon': code, error = 1, 'daemon unavailable'
            elif self.missing: code, error = 1, 'Error response from daemon: No such image: ' + parts[2] + '\n'
            else:
                item = {'Id': parts[2], 'Os': 'linux', 'Architecture': 'amd64',
                        'RootFS': {'Type': 'layers', 'Layers': self.manifest['image_identity']['rootfs_diff_ids']}, 'Config': copy.deepcopy(self.execution)}
                if self.fault == 'found-rootfs': item['RootFS']['Layers'] = ['sha256:'+'f'*64]
                if self.fault == 'found-env': item['Config']['Env'] = ['PATH=foreign']
                if self.fault == 'classic-alias': item['Id'] = self.manifest['image_identity']['classic_config_image_id']
                if self.fault == 'found-volume': item['Config']['Volumes'] = {'/foreign': {}}
                output = json.dumps([item])
                if self.mutate:
                    mutation, self.mutate = self.mutate, None
                    mutation()
        elif parts[0] == 'load':
            self.missing = False
            output = 'Loaded image ID: ' + self.manifest['image_id'] + '\n'
            if self.fault == 'load-fails': code, error = 1, 'offline fixture load refused'
        else: raise AssertionError('Unexpected Docker command: '+repr(parts))
        return subprocess.CompletedProcess(argv, code, output, error)
    @staticmethod
    def assert_local(argv, kwargs):
        assert argv[:3] == ['docker', '--context', 'desktop-linux']
        assert not any(key.upper() in {'DOCKER_HOST','DOCKER_CONTEXT','DOCKER_CONFIG','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'} for key in kwargs['env'])
        assert kwargs['timeout'] > 0
        assert not any(item in argv for item in ('pull', 'build', 'run', 'create'))


class FastRuntimeTests(unittest.TestCase):
    def trial(self, app, fake, config=None):
        # A fake daemon must advertise a real local endpoint of the correct kind.
        # The socket is owned by this fixture; no Docker daemon is contacted.
        with tempfile.TemporaryDirectory(prefix='ab-sock-') as temporary:
            owned_socket = None
            try:
                if os.name == 'nt':
                    fake.endpoint = 'npipe:////./pipe/dockerDesktopLinuxEngine'
                else:
                    endpoint = Path(temporary)/'docker.sock'
                    owned_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    owned_socket.bind(str(endpoint))
                    fake.endpoint = 'unix://' + str(endpoint)
                with patch.object(module.subprocess, 'run', fake), patch.object(native, 'DOCKER_CONTEXT', 'desktop-linux'), \
                     patch.object(native, 'DOCKER_SOCKET', None), patch.dict(os.environ, {'DOCKER_HOST':'tcp://foreign:2375','DOCKER_CONTEXT':'foreign','DOCKER_CONFIG':'foreign'}):
                    return module.prepare_helper(config or {}, app)
            finally:
                if owned_socket is not None:
                    owned_socket.close()

    def test_genuine_three_archive_layouts_and_compat_have_bound_identities(self):
        for layout in ('direct','index','classic','compat'):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as temp:
                app, tar, manifest, execution = fixture(Path(temp), layout)
                identity, decoded = module.archive_identity(tar)
                self.assertEqual(decoded, execution)
                self.assertEqual(identity, manifest['image_identity'])
                self.assertIn(identity['classic_config_image_id'], identity['allowed_image_ids'])
                self.assertIn(identity['provenance_image_id'], identity['allowed_image_ids'])

    def test_existing_and_missing_image_use_only_local_inspect_or_offline_load(self):
        for missing in (False,True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temp:
                app, tar, manifest, execution = fixture(Path(temp), 'index')
                fake = Docker(manifest, execution, missing=missing)
                result = self.trial(app, fake, {'total_deadline_monotonic': time.monotonic()+30})
                self.assertEqual(result['selected_image_id'], manifest['image_id'])
                self.assertEqual(result['manifest_sha256'], module._fact(app/'runtime/fast-helper/manifest.json')['sha256'])
                self.assertEqual(result['proof']['loaded_from_archive'], missing)
                self.assertEqual(sum('load' in argv for argv, kwargs in fake.calls), int(missing))

    def test_actual_archive_layer_config_path_and_diffid_corruption_refuse(self):
        for defect in ('layer','config','diff-id','path','mixed'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temp:
                app, tar, manifest, execution = fixture(Path(temp), 'direct', defect)
                with self.assertRaises(ValueError): module.archive_identity(tar)

    def test_archive_execution_user_entrypoint_and_unsafe_env_refuse_before_docker(self):
        for defect in ('user','entrypoint','env'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temp:
                app, tar, manifest, execution = fixture(Path(temp), 'direct', defect)
                fake = Docker(manifest, execution)
                with self.assertRaises(ValueError): self.trial(app, fake)
                self.assertEqual(fake.calls, [])

    def test_wrong_archive_and_source_and_runtime_bytes_refuse(self):
        for name in ('runtime/fast-helper/helper-image.tar','onecdb2src/__init__.py','runtime/local/linux-amd64/ibcmd-rs'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                app, tar, manifest, execution = fixture(Path(temp))
                with (app/name).open('ab') as stream: stream.write(b'changed')
                fake = Docker(manifest, execution)
                with self.assertRaises(ValueError): self.trial(app, fake)
                self.assertEqual(fake.calls, [])

    def test_unlisted_source_and_runtime_and_manifest_path_refuse(self):
        for name in ('onecdb2src/extra.py','runtime/local/extra.bin','../escape'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                app, tar, manifest, execution = fixture(Path(temp))
                if name.startswith('../'):
                    manifest['source_files'][name] = next(iter(manifest['source_files'].values()))
                    (app/'runtime/fast-helper/manifest.json').write_bytes(packed(manifest))
                else: (app/name).write_bytes(b'extra')
                fake = Docker(manifest, execution)
                with self.assertRaises(ValueError): self.trial(app, fake)
                self.assertEqual(fake.calls, [])

    def test_bad_found_image_or_daemon_failure_never_falls_back_to_load(self):
        for fault in ('found-rootfs','found-env','found-volume','daemon','remote'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                app, tar, manifest, execution = fixture(Path(temp))
                fake = Docker(manifest, execution, fault=fault)
                with self.assertRaises(ValueError): self.trial(app, fake)
                self.assertFalse(any('load' in argv for argv, kwargs in fake.calls))

    def test_source_changes_during_docker_phase_fail_afterward(self):
        with tempfile.TemporaryDirectory() as temp:
            app, tar, manifest, execution = fixture(Path(temp))
            fake = Docker(manifest, execution, mutate=lambda:(app/'onecdb2src/__init__.py').write_bytes(b'mutated'))
            with self.assertRaises(ValueError): self.trial(app, fake)

    def test_classic_alias_is_selected_only_from_proven_archive_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            app, tar, manifest, execution = fixture(Path(temp), 'index')
            fake = Docker(manifest, execution, fault='classic-alias')
            result = self.trial(app, fake)
            self.assertNotEqual(manifest['image_id'], manifest['image_identity']['classic_config_image_id'])
            self.assertEqual(result['selected_image_id'], manifest['image_identity']['classic_config_image_id'])
            self.assertEqual(result['proof']['image_identity']['allowed_image_ids'], manifest['image_identity']['allowed_image_ids'])

    def test_load_failure_never_publishes_prepared_helper(self):
        with tempfile.TemporaryDirectory() as temp:
            app, tar, manifest, execution = fixture(Path(temp))
            fake = Docker(manifest, execution, missing=True, fault='load-fails')
            with self.assertRaisesRegex(ValueError,'offline helper load failed'): self.trial(app, fake)
            self.assertEqual(sum('load' in argv for argv, kwargs in fake.calls), 1)

    def test_archive_manifest_and_runtime_pathset_mutations_during_inspect_refuse(self):
        for kind in ('archive', 'manifest', 'runtime-pathset'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                app, tar, manifest, execution = fixture(Path(temp))
                def mutate():
                    if kind == 'archive':
                        with tar.open('ab') as output: output.write(b'changed')
                    elif kind == 'manifest':
                        (app/'runtime/fast-helper/manifest.json').write_bytes(packed({**manifest, 'changed':True}))
                    else:
                        (app/'runtime/local/extra.bin').write_bytes(b'extra')
                fake = Docker(manifest, execution, mutate=mutate)
                with self.assertRaises(ValueError): self.trial(app, fake)

    def test_real_hardlinked_source_refused_before_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            app, tar, manifest, execution = fixture(Path(temp))
            os.link(app/'onecdb2src/__init__.py', Path(temp)/'outside-hardlink')
            fake = Docker(manifest, execution)
            with self.assertRaisesRegex(ValueError,'hardlinked'): self.trial(app, fake)
            self.assertEqual(fake.calls, [])

    def test_duplicate_and_symlink_outer_archive_members_are_not_accepted(self):
        for kind in ('duplicate', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                app, tar, manifest, execution = fixture(Path(temp))
                with tarfile.open(tar, 'a') as output:
                    info = tarfile.TarInfo('index.json' if kind == 'duplicate' else 'linked')
                    if kind == 'symlink': info.type, info.linkname = tarfile.SYMTYPE, '/foreign'
                    output.addfile(info)
                with self.assertRaises(ValueError): module.archive_identity(tar)

    def test_wrong_manifest_identity_does_not_degrade_to_one_image_id(self):
        with tempfile.TemporaryDirectory() as temp:
            app, tar, manifest, execution = fixture(Path(temp), 'index')
            manifest['image_identity']['allowed_image_ids'] = [manifest['image_id']]
            (app/'runtime/fast-helper/manifest.json').write_bytes(packed(manifest))
            fake = Docker(manifest, execution)
            with self.assertRaises(ValueError): self.trial(app, fake)
            self.assertEqual(fake.calls, [])

    def test_expired_deadline_refuses_without_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            app, tar, manifest, execution = fixture(Path(temp))
            fake = Docker(manifest, execution)
            with self.assertRaises(ValueError): self.trial(app, fake, {'total_deadline_monotonic':time.monotonic()-1})
            self.assertEqual(fake.calls, [])

    def test_unknown_archive_refuses_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'unknown.tar'
            with tarfile.open(path,'w'): pass
            with self.assertRaisesRegex(ValueError,'unsupported archive layout'):module.archive_identity(path)

    def test_outer_gzip_archive_has_same_pure_identity_and_preflight_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            app, tar, manifest, execution = fixture(Path(temp), 'index')
            compressed = tar.with_suffix('.tar.gz')
            compressed.write_bytes(gzip.compress(tar.read_bytes(), mtime=0))
            self.assertEqual(module.derive_archive_identity(compressed), module.derive_archive_identity(tar))
            manifest['archive'] = {'file': compressed.name, **module._fact(compressed)}
            (app/'runtime/fast-helper/manifest.json').write_bytes(packed(manifest))
            fake = Docker(manifest, execution, missing=True)
            self.trial(app, fake)
            load = next(argv for argv, kwargs in fake.calls if 'load' in argv)
            self.assertEqual(load[-1], str(compressed))


if __name__ == '__main__': unittest.main(verbosity=2)
