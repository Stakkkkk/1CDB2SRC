"""Explicit readable-file CF staging. No Docker, DB or source permission changes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def regular(info):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not getattr(info, 'st_file_attributes', 0) & 0x400,
            'CF staging source/target must be one regular non-link file')


def copy_file(source, target, expected, *, write=os.write):
    """Real portable copy core; Linux main alone normalizes owned target modes."""
    source, target = Path(source), Path(target)
    before = source.lstat()
    regular(before)
    parent = target.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and not target.parent.is_symlink(), 'Unsafe CF volume root')
    require(not any(target.parent.iterdir()), 'CF volume is not empty')
    flags = getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    src = dst = directory = None
    try:
        src = os.open(source, os.O_RDONLY | flags)
        opened = os.fstat(src)
        regular(opened)
        require(identity(before)[:4] == identity(opened)[:4], 'CF source changed before open')
        if os.open in os.supports_dir_fd:
            directory = os.open(target.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | flags)
            require((os.fstat(directory).st_dev, os.fstat(directory).st_ino) == (parent.st_dev, parent.st_ino), 'CF directory changed')
            dst = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | flags, 0o600, dir_fd=directory)
        else:
            dst = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
        target_before = os.fstat(dst)
        digest = hashlib.sha256()
        count = 0
        while block := os.read(src, 1024 * 1024):
            view = memoryview(block)
            while view:
                written = write(dst, view)
                require(type(written) is int and 0 < written <= len(view), 'CF target short/nonprogressing write')
                digest.update(view[:written])
                count += written
                view = view[written:]
        value = {'bytes': count, 'sha256': digest.hexdigest()}
        require(value == expected and opened.st_size == count, 'CF copy bytes/hash mismatch')
        require(identity(opened) == identity(os.fstat(src)) and identity(before) == identity(source.lstat()), 'CF source changed during copy')
        os.close(dst)
        dst = None
        # Fresh closed-target readback, independent of the writing digest.
        check = os.open(target, os.O_RDONLY | flags)
        try:
            current = os.fstat(check)
            regular(current)
            require((current.st_dev, current.st_ino) == (target_before.st_dev, target_before.st_ino), 'CF target replaced')
            with os.fdopen(os.dup(check), 'rb') as reader:
                readback = {'bytes': current.st_size, 'sha256': hashlib.file_digest(reader, 'sha256').hexdigest()}
            require(readback == expected and identity(current) == identity(os.fstat(check)) and identity(current)[:4] == identity(target.lstat())[:4], 'CF target readback mismatch/changed')
        finally:
            os.close(check)
        require((parent.st_dev, parent.st_ino) == (target.parent.lstat().st_dev, target.parent.lstat().st_ino), 'CF directory changed after copy')
        require(identity(before) == identity(source.lstat()) and identity(opened) == identity(os.fstat(src)), 'CF source changed after readback')
        return {'source_identity': list(identity(opened)), 'target_identity': list(identity(target.lstat())),
                'target_directory_identity': [parent.st_dev, parent.st_ino],
                'copied': value, 'fresh_target_readback': readback,
                'source_identity_stable': True, 'exclusive_target': True}
    finally:
        for fd in (dst, src, directory):
            if fd is not None:
                os.close(fd)


def normalize_target(target, target_identity, directory_identity):
    """Only the fixed fresh own-volume file and root; never source."""
    target = Path(target)
    for path, mode in ((target, 0o444), (target.parent, 0o755)):
        flags = os.O_RDONLY | os.O_NOFOLLOW
        if path == target.parent:
            flags |= os.O_DIRECTORY
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if path == target:
                regular(opened)
                require(list(identity(opened)) == target_identity, 'CF target changed before normalization')
            else:
                require(stat.S_ISDIR(opened.st_mode) and [opened.st_dev, opened.st_ino] == directory_identity,
                        'CF volume root changed before normalization')
            require(identity(opened) == identity(path.lstat()), 'CF normalization path replaced')
            os.fchmod(fd, mode)  # Must precede chown without CAP_FOWNER.
            os.fchown(fd, 65532, 65532)
            value = os.fstat(fd)
            require(value.st_uid == value.st_gid == 65532 and stat.S_IMODE(value.st_mode) == mode,
                    'Owned CF target normalization failed')
            require((opened.st_dev, opened.st_ino) == (value.st_dev, value.st_ino)
                    and identity(value) == identity(path.lstat()), 'CF normalization identity changed')
        finally:
            os.close(fd)
    return {'uid': 65532, 'gid': 65532, 'file_mode': '0o444', 'directory_mode': '0o755'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nonce', required=True)
    parser.add_argument('--side', choices=('main', 'vendor'), required=True)
    parser.add_argument('--bytes', type=int, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.getuid() == os.getgid() == 0, 'Linux root CF copier required')
    require(len(args.nonce) == 32 and all(c in '0123456789abcdef' for c in args.nonce), 'Invalid nonce')
    require(args.bytes > 0 and len(args.sha256) == 64 and all(c in '0123456789abcdef' for c in args.sha256), 'Invalid expected CF fact')
    expected = {'bytes': args.bytes, 'sha256': args.sha256}
    result = copy_file('/source.cf', '/cf/source.cf', expected)
    normalization = normalize_target('/cf/source.cf', result['target_identity'], result['target_directory_identity'])
    # Metadata normalization cannot change the content proof.
    with Path('/cf/source.cf').open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == expected['sha256'], 'CF changed during normalization')
    print(json.dumps({'schema': '1CDB2SRC_CF_BIND_COPY_V1', 'status': 'CF_COPY_COMPLETE',
        'nonce': args.nonce, 'side': args.side, 'source': '/source.cf', 'target': '/cf/source.cf',
        'expected': expected, **result, 'normalization': normalization,
        'source_permissions_changed': False, 'memory_controls': False}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except PermissionError as error:
        raise PermissionError('bind-copy requires a readable exact CF source under Docker UID mapping; use --docker-cf-transfer copy with a fresh output; original permissions were not changed') from error
