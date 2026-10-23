"""Closed fast-helper manifest and source contract; no Docker/archive loading."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

APP_ROOT = Path(__file__).resolve().parents[2]
HELPER_SCHEMA = '1CDB2SRC_FAST_HELPER_V1'
CONTRACT_SCHEMA = '1CDB2SRC_FAST_CONTRACT_V1'
NAMESPACE_SCHEMA = '1CDB2SRC_FAST_NAMESPACE_V1'
PROOF_SCHEMA = '1CDB2SRC_FAST_LINUX_PROOF_V1'


def require(ok, message):
    if not ok:
        raise ValueError('Fast Docker: ' + message)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def fact(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not getattr(info, 'st_file_attributes', 0) & 0x400, 'Regular immutable proof/source required')
    with path.open('rb') as stream:
        sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = path.lstat()
    require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'Source/proof changed during read')
    return {'bytes': info.st_size, 'sha256': sha}


def read(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate JSON key')
            value[key] = item
        return value
    return json.loads(Path(path).read_text(encoding='utf-8-sig'), object_pairs_hook=unique)


def save_new(path, value):
    with Path(path).open('xb') as stream:
        stream.write(canonical(value) + b'\n')


def source_path(relative, app_root):
    parts = PurePosixPath(relative)
    require(parts.parts and not parts.is_absolute() and '..' not in parts.parts
            and '\\' not in relative and ':' not in relative and parts.as_posix() == relative,
            'Unsafe packaged source path')
    root = Path(app_root).resolve(strict=True)
    target = root / parts
    require(target.resolve(strict=True).is_relative_to(root), 'Packaged source escapes app root')
    for parent in (target, *target.parents):
        require(not parent.is_symlink() and not getattr(parent.lstat(), 'st_file_attributes', 0) & 0x400,
                'Packaged source has linked/reparse ancestor')
        if parent == root:
            break
    return target


def verify_source_closure(source_files, runtime_files, app_root=APP_ROOT):
    app_root = Path(app_root)
    require(type(source_files) is dict and type(runtime_files) is dict and source_files and runtime_files,
            'Sealed source/runtime closures required')
    actual_python = {path.relative_to(app_root).as_posix()
                    for path in (app_root / 'onecdb2src').rglob('*')
                    if path.is_file() and (path.suffix == '.py' or path.name == 'assets.rs')}
    actual_runtime = {path.relative_to(app_root).as_posix()
                      for path in (app_root / 'runtime/local').rglob('*') if path.is_file()}
    require(set(source_files) == actual_python and set(runtime_files) == actual_runtime,
            'Incomplete packaged source/runtime closure')
    for mapping, prefix in ((source_files, 'onecdb2src/'), (runtime_files, 'runtime/local/')):
        for relative, expected in mapping.items():
            require(relative.startswith(prefix) and type(expected) is dict and set(expected) == {'bytes', 'sha256'},
                    'Unexpected sealed source/runtime record')
            require(type(expected['bytes']) is int and expected['bytes'] >= 0
                    and re.fullmatch('[a-f0-9]{64}', expected['sha256']), 'Invalid packaged fact')
            require(fact(source_path(relative, app_root)) == expected, 'Packaged source/runtime pin changed: ' + relative)


def load_helper_manifest(config, app_root=APP_ROOT):
    supplied = config['fast_helper']
    required = {'manifest_path', 'manifest_sha256', 'selected_image_id'}
    require(type(supplied) is dict and required <= set(supplied) <= required | {'proof'},
            'Sealed fast_helper manifest binding required')
    manifest_path = Path(supplied['manifest_path']).resolve(strict=True)
    observed = fact(manifest_path)
    require(observed['sha256'] == supplied['manifest_sha256'], 'Helper manifest pin mismatch')
    value = read(manifest_path)
    require(value['schema'] == HELPER_SCHEMA and re.fullmatch('sha256:[a-f0-9]{64}', value['image_id']),
            'Unsupported helper manifest/image identity')
    identity=value['image_identity']
    allowed=identity['allowed_image_ids'];layers=identity['rootfs_diff_ids']
    require(type(allowed) is list and len(set(allowed))==len(allowed) and value['image_id'] in allowed
            and all(re.fullmatch('sha256:[a-f0-9]{64}', item) for item in allowed)
            and supplied['selected_image_id'] in allowed, 'Unapproved helper image alias')
    require(type(layers) is list and layers and all(re.fullmatch('sha256:[a-f0-9]{64}', item) for item in layers),
            'Sealed helper RootFS identity required')
    require(value['entrypoint'] == ['python', '-I', '-S', '-B', '/opt/app/onecdb2src/xml/linux_helpers.py'],
            'Unexpected packaged helper entrypoint')
    verify_source_closure(value['source_files'], value['runtime_files'], app_root)
    return value, {'path': str(manifest_path), **observed, 'selected_image_id':supplied['selected_image_id']}
