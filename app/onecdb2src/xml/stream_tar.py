"""Strict host-side reader for an owned container's uncompressed xml tar.

No extract()/extractall(), no archive permissions/ownership/times, no cached
acceptance. A later independent whole-output readback remains mandatory.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile

BLOCK = 512
CHUNK = 1024 * 1024
DEVICES = re.compile(r'^(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])$', re.I)
PAX_KEYS = frozenset(('path', 'size', 'mtime', 'atime', 'ctime', 'uid', 'gid', 'uname', 'gname'))


def require(condition, reason):
    if not condition:
        raise ValueError('XML tar: ' + reason)


def read_exact(stream, size):
    pieces = []
    while size:
        block = stream.read(min(CHUNK, size))
        require(isinstance(block, bytes) and 0 < len(block) <= size, 'truncated stream')
        pieces.append(block)
        size -= len(block)
    return b''.join(pieces)


def regular_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
            'parent is not a regular directory')


def long_path(path):
    path = Path(path)
    if os.name == 'nt' and not str(path).startswith('\\\\?\\'):
        require(path.is_absolute() and not str(path).startswith('\\\\'), 'local absolute target required')
        return Path('\\\\?\\' + str(path))
    return path


def normalized_name(name, directory):
    require(isinstance(name, str) and name and '\\' not in name and '\0' not in name,
            'invalid archive path')
    if directory and name.endswith('/'):
        name = name[:-1]
    parts = name.split('/')
    require(parts[0] == 'xml', 'archive root must be xml')
    require(all(part and part not in ('.', '..') for part in parts), 'empty or relative path component')
    for part in parts:
        require(not any(ord(char) < 32 or ord(char) == 127 or char in ':*?"<>|' for char in part),
                'unsafe or drive path component')
        require(part[-1] not in '. ', 'trailing-dot/space alias')
        require(not DEVICES.fullmatch(part.split('.')[0]), 'reserved device name')
        require(not any(0xD800 <= ord(char) <= 0xDFFF for char in part), 'invalid Unicode path')
    require(directory or len(parts) > 1, 'xml root cannot be a file')
    return tuple(parts[1:])


def parse_pax(raw):
    result = {}
    offset = 0
    while offset < len(raw):
        space = raw.find(b' ', offset)
        require(space > offset, 'malformed PAX length')
        number = raw[offset:space]
        require(number.isdigit() and not number.startswith(b'0'), 'noncanonical PAX length')
        size = int(number)
        require(size >= 5 and offset + size <= len(raw), 'truncated PAX record')
        record = raw[space+1:offset+size]
        require(record.endswith(b'\n') and b'=' in record, 'malformed PAX record')
        key, value = record[:-1].split(b'=', 1)
        key = key.decode('utf-8', 'strict')
        value = value.decode('utf-8', 'strict')
        require(key in PAX_KEYS and key not in result, 'unsupported/duplicate PAX key')
        result[key] = value
        offset += size
    return result


def extract_xml_tar(stream, target, *, expected_files=None, max_entries=1000000,
                    max_file_bytes=64*1024**3, max_metadata_bytes=65536):
    """Create a fresh target and target.transfer.jsonl; leave failures unaccepted.

    target is the resulting XML directory itself, not its parent. Expected files
    are optional exact CF/engine-derived relative output paths, never an oracle.
    The caller owns stream timeout/cancellation and must check docker cp exit 0.
    This function never starts/kills Docker or publishes an acceptance receipt.
    """
    require(type(max_entries) is int and max_entries > 0, 'invalid entry quota')
    expected = None
    if expected_files is not None:
        expected = set()
        for name in expected_files:
            parts = normalized_name('xml/'+name, False)
            require('/'.join(parts) == name and name not in expected, 'duplicate/noncanonical expected file')
            expected.add(name)
    target = Path(os.path.abspath(target))
    for parent in reversed(target.parents):
        regular_directory(long_path(parent))
    manifest_path = target.with_name(target.name+'.transfer.jsonl')
    require(not os.path.lexists(long_path(target)) and not os.path.lexists(long_path(manifest_path)),
            'target or sidecar already exists')
    target = long_path(target)
    manifest_path = long_path(manifest_path)
    target.mkdir()  # exclusive; archive metadata does not change this directory
    declared, aliases, directories, files = set(), {}, {()}, set()
    total = 0
    headers = 0
    pending = None
    root_seen = False
    manifest_hash = hashlib.sha256()

    with manifest_path.open('xb') as manifest:
        def record(parts, kind, size=0, digest=None):
            raw = (json.dumps({'path': '/'.join(parts), 'kind': kind,
                    'bytes': size, 'sha256': digest}, ensure_ascii=False,
                    separators=(',', ':'))+'\n').encode('utf-8')
            require(manifest.write(raw) == len(raw), 'short manifest write')
            manifest_hash.update(raw)

        def bind(parts, kind):
            # Literal declared identities are tracked here. Actual filesystem
            # case/composition aliases are rejected by exclusive mkdir/open,
            # not by an invented Unicode normalization or casefold policy.
            previous = aliases.get(parts)
            require(previous is None or previous == kind, 'file/directory kind collision')
            aliases[parts] = kind

        def ensure_parents(parts):
            for index in range(1, len(parts)):
                parent = parts[:index]
                bind(parent, 'dir')
                path = target.joinpath(*parent)
                if parent not in directories:
                    path.mkdir()
                    directories.add(parent)
                    record(parent, 'dir')
                regular_directory(path)
            regular_directory(target)

        record((), 'dir')
        bind((), 'dir')
        while True:
            header = read_exact(stream, BLOCK)
            if header == b'\0'*BLOCK:
                require(pending is None and root_seen, 'dangling metadata or missing xml root')
                require(read_exact(stream, BLOCK) == b'\0'*BLOCK, 'missing second tar end block')
                # No hidden second archive/nonzero garbage accepted. Docker tar
                # can pad its final physical record with additional zero blocks.
                trailing = 0
                while True:
                    block = stream.read(CHUNK)
                    require(isinstance(block, bytes), 'invalid stream bytes')
                    if not block:
                        break
                    require(not any(block), 'nonzero bytes after tar terminator')
                    trailing += len(block)
                require(trailing % BLOCK == 0, 'partial trailing tar block')
                break
            headers += 1
            require(headers <= max_entries, 'entry quota exceeded')
            # Parse only the header/checksum. Do not invoke tarfile extension or
            # extraction processors, which can normalize paths or expand sparse
            # records before a caller has validated their effective path/type.
            info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            require(info.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE,
                                 tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME), 'nonregular tar entry')
            require(type(info.size) is int and 0 <= info.size <= max_file_bytes, 'invalid file size')
            raw_name = header[:100].split(b'\0', 1)[0]
            if info.type in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
                require(pending is None and 0 < info.size <= max_metadata_bytes, 'excessive/chained metadata')
                raw = read_exact(stream, info.size)
                padding = (-info.size) % BLOCK
                require(read_exact(stream, padding) == b'\0'*padding, 'nonzero metadata padding')
                if info.type == tarfile.XHDTYPE:
                    pending = parse_pax(raw)
                else:
                    require(raw.endswith(b'\0') and b'\0' not in raw[:-1], 'malformed GNU long name')
                    pending = {'path': raw[:-1].decode('utf-8', 'strict')}
                continue
            attributes = pending or {}
            pending = None
            # A PAX/GNU path is the effective filesystem name; Docker's ASCII
            # fallback can contain // after removing non-ASCII characters.
            # Without an override keep the raw guard (TarInfo strips trailing
            # directory slashes). The effective name is always checked below.
            if 'path' not in attributes:
                require(b'//' not in raw_name, 'path separator alias')
            name = attributes.get('path', info.name)
            size = info.size
            if 'size' in attributes:
                require(re.fullmatch(r'0|[1-9][0-9]*', attributes['size']) is not None, 'invalid PAX size')
                size = int(attributes['size'])
                require(size <= max_file_bytes, 'PAX file size quota exceeded')
            directory = info.type == tarfile.DIRTYPE
            require(not directory or size == 0, 'directory has payload')
            parts = normalized_name(name, directory)
            require(parts not in declared, 'duplicate archive member')
            declared.add(parts)
            require(root_seen or directory and not parts, 'xml root must be first')
            if not parts:
                root_seen = True
                continue
            ensure_parents(parts)
            bind(parts, 'dir' if directory else 'file')
            path = target.joinpath(*parts)
            if directory:
                if parts not in directories:
                    path.mkdir()
                    directories.add(parts)
                    record(parts, 'dir')
                regular_directory(path)
                continue
            relative = '/'.join(parts)
            require(expected is None or relative in expected, 'unexpected engine output path')
            digest = hashlib.sha256()
            remaining = size
            with path.open('xb') as output:
                while remaining:
                    block = read_exact(stream, min(CHUNK, remaining))
                    written = output.write(block)
                    require(written == len(block), 'short target write')
                    digest.update(block)
                    remaining -= len(block)
            state = path.lstat()
            require(stat.S_ISREG(state.st_mode) and state.st_nlink == 1 and
                    not getattr(state, 'st_file_attributes', 0) & 0x400 and state.st_size == size,
                    'nonregular or changed extracted file')
            padding = (-size) % BLOCK
            require(read_exact(stream, padding) == b'\0'*padding, 'nonzero file padding')
            record(parts, 'file', size, digest.hexdigest())
            total += size
            files.add(relative)
        require(expected is None or files == expected, 'missing engine output path')
    return {'status': 'TRANSFERRED_REQUIRES_INDEPENDENT_READBACK',
            'target': str(target), 'manifest': str(manifest_path),
            'manifest_sha256': manifest_hash.hexdigest(), 'files': len(files),
            'directories': len(directories), 'bytes': total, 'headers': headers,
            'archive_metadata_applied': False}
