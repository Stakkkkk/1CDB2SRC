"""Independent actual-file readback, serial or bounded parallel.

No CF extraction, profile selection, reference exports or cached assembly facts.
Caller must separately bind the unchanged CF/profile/receipt/producer lineage.
"""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from onecdb2src.xml.materialize import inspect_file
from onecdb2src.xml.dump_info import long_path

MD = '{http://v8.1c.ru/8.3/MDClasses}'
DI = '{http://v8.1c.ru/8.3/xcf/dumpinfo}'


class ReadbackFailure(ValueError):
    def __init__(self, proof):
        self.proof = proof
        super().__init__('Independent XML readback: '+proof['phase'])


def require(value, reason):
    if not value:
        raise ValueError(reason)


def file_token(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def ordinary(value, directory=False):
    require(not getattr(value, 'st_file_attributes', 0) & 0x400,
            'reparse path forbidden')
    require(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode),
            'unexpected path kind')
    if not directory:
        require(value.st_nlink == 1, 'hardlink forbidden')


def safe_path(value):
    require(type(value) is str and value and '\\' not in value and ':' not in value and '\0' not in value,
            'invalid manifest path')
    relative = PurePosixPath(value)
    require(not relative.is_absolute() and relative.parts and '..' not in relative.parts
            and relative.as_posix() == value and not value.endswith('/'), 'noncanonical manifest path')
    return relative


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def load_manifest(path, expected_sha256):
    before = path.lstat()
    ordinary(before)
    rows, digest, count = {}, hashlib.sha256(), 0
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        require(file_token(opened) == file_token(before), 'manifest handle/path changed')
        while True:
            raw = stream.readline(2*1024**2+1)
            if not raw:
                break
            require(len(raw) <= 2*1024**2, 'manifest row format quota exceeded')
            digest.update(raw)
            count += len(raw)
            row = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
            require(type(row) is dict, 'manifest row is not an object')
            require({'path', 'bytes', 'sha256'} <= set(row), 'incomplete manifest row')
            safe_path(row['path'])
            require(row['path'] not in rows, 'duplicate manifest file')
            require(type(row['bytes']) is int and row['bytes'] >= 0, 'invalid manifest byte count')
            require(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
                    'invalid manifest SHA256')
            require(row.get('kind', 'file') == 'file', 'manifest must list files only')
            rows[row['path']] = {'bytes': row['bytes'], 'sha256': row['sha256']}
        after_open = os.fstat(stream.fileno())
    after = path.lstat()
    ordinary(after)
    require(file_token(before) == file_token(opened) == file_token(after_open) == file_token(after)
            and opened.st_ctime_ns == after_open.st_ctime_ns, 'manifest changed while reading')
    require(count == before.st_size and digest.hexdigest() == expected_sha256,
            'manifest receipt digest mismatch')
    require({'Configuration.xml', 'ConfigDumpInfo.xml'} <= set(rows), 'required files absent from manifest')
    return rows, {'bytes': count, 'sha256': digest.hexdigest()}


def actual_paths(tree):
    ordinary(tree.lstat(), True)
    names = set()
    def walk_error(error):
        raise error
    for base, directories, files in os.walk(tree, followlinks=False, onerror=walk_error):
        directory = Path(base)
        ordinary(directory.lstat(), True)
        for name in directories:
            ordinary((directory/name).lstat(), True)
        for name in files:
            key = (directory/name).relative_to(tree).as_posix()
            safe_path(key)
            require(key not in names, 'duplicate actual filesystem path')
            names.add(key)
    return names


def verify_file(tree, path, expected, xml_version):
    relative = safe_path(path)
    file = tree.joinpath(*relative.parts)
    fact, node = inspect_file(file, parse_xml=file.suffix.lower() == '.xml')
    require(fact == expected, 'actual file bytes/hash mismatch')
    metadata = node is not None and node.tag in (MD+'MetaDataObject', DI+'ConfigDumpInfo')
    if metadata:
        require(node.get('version') == xml_version, 'actual metadata XML edition mismatch')
    if path == 'Configuration.xml':
        require(node is not None and node.tag == MD+'MetaDataObject'
                and len(node.findall(MD+'Configuration')) == 1, 'Configuration envelope missing')
    if path == 'ConfigDumpInfo.xml':
        require(node is not None and node.tag == DI+'ConfigDumpInfo', 'DumpInfo envelope missing')
    return {'path': path, 'kind': 'file', **fact,
            'bsl': file.suffix.lower() == '.bsl', 'metadata_envelope': bool(metadata)}


def verify_xml_tree(tree, manifest, *, manifest_sha256, xml_version, workers=4):
    """Read each actual payload afresh exactly once, regardless of thread count.

    Return is file verification only; caller must perform CF/profile/receipt
    lineage checks before accepting a configuration or reporting overall PASS.
    No success receipt is written here. Any failed file/path/manifest raises
    ReadbackFailure with structured error proof and cannot return a success.
    """
    phase, facts, errors = 'preflight', {}, []
    proof = {'status': 'FAILED_FILE_READBACK', 'caller_lineage': 'NOT_CHECKED',
             'oracle_inputs': [], 'workers': workers}
    try:
        require(type(workers) is int and workers in (1, 4, 8), 'workers must be 1, 4 or 8')
        require(xml_version in ('2.20', '2.21'), 'unsupported XML edition')
        require(type(manifest_sha256) is str and re.fullmatch('[0-9a-f]{64}', manifest_sha256),
                'expected manifest SHA256 required')
        tree, manifest = long_path(Path(tree).absolute()), long_path(Path(manifest).absolute())
        require(tree != manifest and tree not in manifest.parents, 'manifest overlaps output XML')
        for parent in set(tree.parents) | set(manifest.parents):
            ordinary(parent.lstat(), True)
        ordinary(tree.lstat(), True)
        phase = 'manifest'
        rows, manifest_fact = load_manifest(manifest, manifest_sha256)
        expected_paths = set(rows)
        phase = 'pathset_before'
        actual = actual_paths(tree)
        require(actual == expected_paths, 'missing/extra files before readback')
        phase = 'payload'

        def collect(path, result=None, error=None):
            if error is None:
                facts[path] = result
            else:
                errors.append({'path': path, 'error_type': type(error).__name__, 'reason': str(error)[:1024]})

        if workers == 1:
            for path, expected in rows.items():
                try:
                    collect(path, verify_file(tree, path, expected, xml_version))
                except Exception as error:
                    collect(path, error=error)
                    break
        else:
            # Only 2*workers queued futures; no one-future-per-140k-file fanout.
            iterator = iter(rows.items())
            exhausted = False
            pending = {}
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='actual-xml-readback') as executor:
                while pending or not exhausted:
                    while not exhausted and not errors and len(pending) < 2*workers:
                        try:
                            path, expected = next(iterator)
                        except StopIteration:
                            exhausted = True
                            break
                        future = executor.submit(verify_file, tree, path, expected, xml_version)
                        pending[future] = path
                    if not pending:
                        break
                    done, ignored = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        path = pending.pop(future)
                        if future.cancelled():
                            continue
                        try:
                            collect(path, future.result())
                        except Exception as error:
                            collect(path, error=error)
                    if errors:
                        exhausted = True
                        for future in pending:
                            future.cancel()
        require(not errors, 'one or more actual files failed verification')
        require(set(facts) == expected_paths, 'incomplete actual payload verification')
        phase = 'pathset_after'
        actual = actual_paths(tree)
        require(actual == expected_paths, 'missing/extra files after readback')
        phase = 'manifest_after'
        current_manifest, ignored = inspect_file(manifest)
        require(current_manifest == manifest_fact, 'manifest changed during payload verification')
        ordered = [facts[path] for path in sorted(facts)]
        digest = hashlib.sha256()
        for row in ordered:
            digest.update((json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(',', ':'))+'\n').encode('utf-8'))
        return {'status': 'FILES_VERIFIED_REQUIRES_CALLER_LINEAGE', 'caller_lineage': 'NOT_CHECKED',
            'workers': workers, 'files': len(ordered), 'bytes': sum(row['bytes'] for row in ordered),
            'bsl_files': sum(row['bsl'] for row in ordered),
            'metadata_envelopes': sum(row['metadata_envelope'] for row in ordered),
            'manifest': manifest_fact, 'facts_sha256': digest.hexdigest(), 'facts': ordered,
            'missing': 0, 'extra': 0, 'errors': [], 'oracle_inputs': []}
    except Exception as error:
        proof.update(phase=phase, error_type=type(error).__name__, reason=str(error)[:1024],
            verified_files=len(facts), file_errors=sorted(errors, key=lambda row: row['path']))
        if 'actual' in locals() and 'expected_paths' in locals():
            proof.update(missing_count=len(expected_paths-actual), extra_count=len(actual-expected_paths),
                missing_examples=sorted(expected_paths-actual)[:20], extra_examples=sorted(actual-expected_paths)[:20])
        raise ReadbackFailure(proof) from error
