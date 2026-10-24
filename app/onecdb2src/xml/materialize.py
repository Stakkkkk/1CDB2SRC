"""Single-read inspection and exclusive publication of owned native output."""
import ctypes
import hashlib
import os
from pathlib import Path
import stat
import sys
import xml.etree.ElementTree as ET


def token(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def inspect_file(path, parse_xml=False, *, _xml_parser_factory=None):
    """Hash and optionally parse the same bytes; caller still verifies final output."""
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or getattr(before, 'st_file_attributes', 0) & 0x400 or before.st_nlink != 1:
        raise ValueError('Adoption requires a regular unlinked native file')
    parser = (_xml_parser_factory or ET.XMLParser)() if parse_xml else None
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        if token(os.fstat(stream.fileno())) != token(before):
            raise ValueError('Native file identity changed before read')
        while block := stream.read(1024 * 1024):
            digest.update(block)
            if parser is not None:
                parser.feed(block)
        opened_after = os.fstat(stream.fileno())
    after = path.lstat()
    if token(before) != token(opened_after) or token(before) != token(after) or after.st_nlink != 1:
        raise ValueError('Native file changed during inspection')
    node = parser.close() if parser is not None else None
    return {'bytes': before.st_size, 'sha256': digest.hexdigest()}, node


def producer_closed(receipt):
    process = receipt.get('process', {})
    if 'container_state' in process:
        return process['container_state'].get('Running') is False
    job = process.get('job', {})
    return job.get('job_handle_closed') is True and job.get('surviving_pids') == []


def adopt_tree(source, target):
    """Rename only to a missing sibling result on the same filesystem, never merge."""
    source, target = Path(source), Path(target)
    if source.is_symlink() or source.resolve(strict=True) != source.absolute():
        raise ValueError('Adoption source alias is forbidden')
    for parent in (source, target.parent):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Adoption directory is not regular')
    if source == target or source in target.parents or target in source.parents:
        raise ValueError('Adoption paths overlap')
    if os.path.lexists(target):
        raise ValueError('Adoption target already exists')
    if source.stat().st_dev != target.parent.stat().st_dev:
        raise ValueError('Adoption requires the same filesystem')
    if os.name == 'nt':
        # Windows rename fails if the target already exists.
        os.rename(source, target)
    elif sys.platform.startswith('linux'):
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, 'renameat2', None)
        if rename is None:
            raise ValueError('Exclusive renameat2 required for adoption')
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(source), -100, os.fsencode(target), 1):
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number))
    else:
        raise ValueError('Adoption supports Windows and Linux only')
