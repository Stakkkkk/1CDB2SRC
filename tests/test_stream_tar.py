"""Real small uncompressed tar fixtures. No Docker or reflection mocks."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

from onecdb2src.xml.stream_tar import extract_xml_tar


def archive(entries, format=tarfile.PAX_FORMAT):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=format) as output:
        root = tarfile.TarInfo('xml')
        root.type = tarfile.DIRTYPE
        output.addfile(root)
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = 'elsewhere'
            if kind in (tarfile.REGTYPE, tarfile.AREGTYPE):
                info.size = len(data)
            output.addfile(info, io.BytesIO(data) if info.size else None)
    return stream.getvalue()


def pax_record(key, value):
    body = (key+'='+value+'\n').encode('utf-8')
    size = len(body)+2
    while True:
        record = str(size).encode()+b' '+body
        if len(record) == size:
            return record
        size = len(record)


class SplitStream:
    """A real byte stream which returns short chunks, like a process pipe."""
    def __init__(self, raw, limit=7):
        self.source = io.BytesIO(raw)
        self.limit = limit
    def read(self, size):
        return self.source.read(min(size, self.limit))


class StreamTarTests(unittest.TestCase):
    def test_neutral_pax_effective_directory_overrides_ascii_fallback_only(self):
        root=tarfile.TarInfo('xml');root.type=tarfile.DIRTYPE
        fallback=tarfile.TarInfo('xml//');fallback.type=tarfile.DIRTYPE
        for effective,accept in (('xml/Папка/',True),('xml/a//b',False)):
            with self.subTest(effective=effective),tempfile.TemporaryDirectory() as temporary:
                payload=pax_record('path',effective);control=tarfile.TarInfo('meta//PaxHeaders.0');control.type=tarfile.XHDTYPE;control.size=len(payload)
                raw=root.tobuf()+control.tobuf()+payload+b'\0'*((-len(payload))%512)+fallback.tobuf()+b'\0'*1024
                if accept:
                    result=extract_xml_tar(io.BytesIO(raw),Path(temporary)/'xml',expected_files=[])
                    self.assertEqual(result['files'],0);self.assertTrue((Path(temporary)/'xml/Папка').is_dir())
                else:
                    with self.assertRaises(ValueError):extract_xml_tar(io.BytesIO(raw),Path(temporary)/'xml')
    def rejected(self, raw, expected=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(Exception):
                extract_xml_tar(io.BytesIO(raw), root/'new', expected_files=expected)
            self.assertFalse((root/'escaped.txt').exists())

    def test_unicode_long_paths_chunking_and_same_written_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = '/'.join(['Каталоги', 'Справочник'*8, 'Формы', 'Форма'*15, 'Модуль.bsl'])
            data = ('// Привет\n'*300).encode()
            raw = archive([('xml/'+path, data, tarfile.REGTYPE),
                           ('xml/Empty', b'', tarfile.DIRTYPE),
                           ('xml/Configuration.xml', b'<Metadata/>', tarfile.REGTYPE)])
            result = extract_xml_tar(SplitStream(raw), Path(directory)/'new',
                expected_files=[path, 'Configuration.xml'])
            self.assertEqual(result['status'], 'TRANSFERRED_REQUIRES_INDEPENDENT_READBACK')
            self.assertEqual(result['files'], 2)
            self.assertFalse(result['archive_metadata_applied'])
            manifest = Path(result['manifest']).read_bytes()
            self.assertEqual(hashlib.sha256(manifest).hexdigest(), result['manifest_sha256'])
            rows = [json.loads(line) for line in manifest.splitlines()]
            actual = {row['path']: row for row in rows if row['kind'] == 'file'}
            self.assertEqual(actual[path]['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(actual[path]['bytes'], len(data))
            target = Path(result['target'])
            self.assertEqual((target/path).read_bytes(), data)
            self.assertEqual((target/'Configuration.xml').read_bytes(), b'<Metadata/>')
            self.assertEqual(len({row['path'] for row in rows}), len(rows))

    def test_gnu_long_name_real_fixture(self):
        # Exercise GNU long-name metadata with a long total UTF-8 path while
        # every component remains a valid ordinary Linux filename.
        path = 'xml/'+('ДлиннаяПапка'*4)+'/'+('ВложеннаяПапка'*4)+'/'+('ДлинноеИмя'*4)+'.bsl'
        self.assertGreater(len(path.encode('utf-8')), 255)
        self.assertTrue(all(len(part.encode('utf-8')) <= 255 for part in path.split('/')))
        with tempfile.TemporaryDirectory() as directory:
            result = extract_xml_tar(io.BytesIO(archive([(path, b'code', tarfile.REGTYPE)], tarfile.GNU_FORMAT)),
                                     Path(directory)/'new')
            self.assertEqual(result['files'], 1)
            self.assertEqual((Path(directory)/'new'/path.removeprefix('xml/')).read_bytes(), b'code')

    def test_existing_target_and_manifest_are_not_overwritten(self):
        raw = archive([('xml/A', b'changed', tarfile.REGTYPE)])
        for existing in ('target-file', 'target-dir', 'manifest'):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root/'new'
                if existing == 'target-file':
                    target.write_bytes(b'keep')
                elif existing == 'target-dir':
                    target.mkdir()
                    (target/'kept').write_bytes(b'keep')
                else:
                    (root/'new.transfer.jsonl').write_bytes(b'keep')
                with self.assertRaises(ValueError):
                    extract_xml_tar(io.BytesIO(raw), target)
                if existing == 'target-file':
                    self.assertEqual(target.read_bytes(), b'keep')
                elif existing == 'target-dir':
                    self.assertEqual((target/'kept').read_bytes(), b'keep')
                else:
                    self.assertEqual((root/'new.transfer.jsonl').read_bytes(), b'keep')

    def test_traversal_absolute_drive_windows_aliases_and_wrong_root_refuse(self):
        names = ('xml/../escaped.txt', '/xml/A', 'C:/xml/A', 'xml/C:/A',
                 'xml/./A', 'xml//A', 'xml\\A', 'xml/A.', 'xml/A ',
                 'xml/CON.txt', 'xml/LPT¹', 'xml/CONOUT$', 'xml/CLOCK$',
                 'other/A', 'xml/A:stream', 'xml/A\x01')
        for name in names:
            with self.subTest(name=name):
                self.rejected(archive([(name, b'bad', tarfile.REGTYPE)]))

    def test_links_devices_fifo_sparse_and_duplicate_members_refuse(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.GNUTYPE_SPARSE):
            with self.subTest(kind=kind):
                self.rejected(archive([('xml/A', b'', kind)]))
        self.rejected(archive([('xml/A', b'a', tarfile.REGTYPE), ('xml/A', b'b', tarfile.REGTYPE)]))
        self.rejected(archive([('xml/D', b'', tarfile.DIRTYPE), ('xml/D', b'', tarfile.DIRTYPE)]))

    def test_actual_filesystem_alias_rules_and_kind_collision(self):
        for first, second in (('A', 'a'), ('é', 'e\u0301'), ('I', 'ı'), ('Folder/X', 'folder/Y')):
            with self.subTest(first=first, second=second), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                probe = root/'probe'
                probe.mkdir()
                declared_dirs = set()
                def create_literal(name, data):
                    parts = name.split('/')
                    for index in range(1, len(parts)):
                        literal = tuple(parts[:index])
                        if literal not in declared_dirs:
                            probe.joinpath(*literal).mkdir()
                            declared_dirs.add(literal)
                    with (probe/name).open('xb') as stream:
                        stream.write(data)
                create_literal(first, b'a')
                try:
                    create_literal(second, b'b')
                    distinct = True
                except FileExistsError:
                    distinct = False
                raw = archive([('xml/'+first, b'a', tarfile.REGTYPE),
                               ('xml/'+second, b'b', tarfile.REGTYPE)])
                if distinct:
                    result = extract_xml_tar(io.BytesIO(raw), root/'new')
                    self.assertEqual(result['files'], 2)
                else:
                    with self.assertRaises((ValueError, FileExistsError)):
                        extract_xml_tar(io.BytesIO(raw), root/'new')
        self.rejected(archive([('xml/A/X', b'a', tarfile.REGTYPE), ('xml/A', b'b', tarfile.REGTYPE)]))

    def test_corrupt_checksum_and_bad_header_after_valid_member_refuse(self):
        raw = bytearray(archive([('xml/A', b'a', tarfile.REGTYPE)]))
        raw[512] ^= 1
        self.rejected(bytes(raw))
        raw = archive([('xml/A', b'a', tarfile.REGTYPE)])
        # Root header512 + file header512 + padded body512; corrupt a following
        # ordinary header, after valid payload, rather than only the first one.
        malformed = bytearray(tarfile.TarInfo('xml/B').tobuf())
        malformed[0] ^= 1
        self.rejected(raw[:1536]+bytes(malformed)+b'\0'*1024)

    def test_truncation_missing_terminators_nonzero_tail_and_padding_refuse(self):
        raw = archive([('xml/A', b'abc', tarfile.REGTYPE)])
        cases = [raw[:1100], raw[:1026], raw[:1536], raw[:2048], raw[:1600], raw+b'X', raw+b'\0']
        damaged_padding = bytearray(raw)
        damaged_padding[1027] = 1
        cases.append(bytes(damaged_padding))
        for index, value in enumerate(cases):
            with self.subTest(case=index):
                self.rejected(value)

    def test_expected_engine_inventory_missing_extra_and_duplicates_refuse(self):
        raw = archive([('xml/A', b'a', tarfile.REGTYPE)])
        for expected in (['A', 'Missing'], ['Other'], ['A', 'A'], ['../A']):
            with self.subTest(expected=expected):
                self.rejected(raw, expected)

    def test_directory_payload_and_no_xml_root_refuse(self):
        header = tarfile.TarInfo('xml')
        header.type = tarfile.DIRTYPE
        header.size = 1
        self.rejected(header.tobuf()+b'x'+b'\0'*1535)
        file = tarfile.TarInfo('xml/A')
        self.rejected(file.tobuf()+b'\0'*1024)

    def test_pax_unsupported_malformed_traversal_and_global_headers_refuse(self):
        root = tarfile.TarInfo('xml')
        root.type = tarfile.DIRTYPE
        file = tarfile.TarInfo('xml/A')
        for value, kind in ((b'bad framing', tarfile.XHDTYPE),
                            (pax_record('GNU.sparse.map', '0'), tarfile.XHDTYPE),
                            (pax_record('path', 'xml/../escaped.txt'), tarfile.XHDTYPE),
                            (b'0', tarfile.XGLTYPE)):
            with self.subTest(value=value, kind=kind):
                metadata = tarfile.TarInfo('PaxHeaders/ignored')
                metadata.type = kind
                metadata.size = len(value)
                raw = root.tobuf()+metadata.tobuf()+value+b'\0'*((-len(value)) % 512)+file.tobuf()+b'\0'*1024
                self.rejected(raw)


if __name__ == '__main__':
    unittest.main()
