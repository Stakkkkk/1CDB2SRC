"""Small genuine files/manifest/XML; no CF, Docker, oracle or reflection mocks."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'app'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from onecdb2src.xml.dump_info import long_path
from onecdb2src.xml.readback import verify_xml_tree, ReadbackFailure


def fixture(root, edition='2.20', defect=None):
    tree = root/'xml'
    tree.mkdir()
    files = {
        'Configuration.xml': ('<MetaDataObject xmlns="http://v8.1c.ru/8.3/MDClasses" version="'+edition+'"><Configuration/></MetaDataObject>').encode(),
        'ConfigDumpInfo.xml': ('<ConfigDumpInfo xmlns="http://v8.1c.ru/8.3/xcf/dumpinfo" version="'+edition+'"/>').encode(),
        'CommonModules/Нейтральный/Ext/Module.bsl': '// Привет\n'.encode(),
        'Catalogs/A/Ext/Form.xml': b'<Form><Item>Neutral</Item></Form>',
        'Pictures/Empty.bin': b'',
        '/'.join(['Documents', 'Long'+('X'*80), 'Forms', 'Long'+('Y'*80), 'Ext', 'Module.bsl']): b'// long path\n',
    }
    if defect == 'malformed':
        files['Catalogs/A/Ext/Form.xml'] = b'<broken>'
    if defect == 'edition':
        files['ConfigDumpInfo.xml'] = b'<ConfigDumpInfo xmlns="http://v8.1c.ru/8.3/xcf/dumpinfo" version="2.21"/>'
    if defect == 'envelope':
        files['Configuration.xml'] = b'<Wrong version="2.20"/>'
    rows = []
    for name, data in files.items():
        path = long_path(tree/name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        rows.append({'path': name, 'source': 'base', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    manifest = root/'files.jsonl'
    if defect == 'duplicate': rows.append(dict(rows[0]))
    if defect == 'path': rows[0]['path'] = '../escaped.xml'
    raw = ''.join(json.dumps(row, ensure_ascii=False)+'\n' for row in rows).encode()
    if defect == 'duplicate-key':
        raw = raw.replace(b'"path": "Configuration.xml"', b'"path": "Configuration.xml", "path": "Other.xml"', 1)
    manifest.write_bytes(raw)
    if defect == 'changed':
        (tree/'ConfigDumpInfo.xml').write_bytes(b'<Changed/>')
    if defect == 'extra': (tree/'Unexpected.bin').write_bytes(b'x')
    if defect == 'missing': (tree/'ConfigDumpInfo.xml').unlink()
    if defect == 'hardlink': os.link(tree/'ConfigDumpInfo.xml', root/'external-hardlink')
    if defect == 'manifest-hardlink': os.link(manifest, root/'manifest-hardlink')
    return tree, manifest, hashlib.sha256(raw).hexdigest(), files


class ParallelReadbackTests(unittest.TestCase):
    def test_serial_four_eight_actual_facts_and_counts_identical_both_editions(self):
        for edition in ('2.20', '2.21'):
            with self.subTest(edition=edition), tempfile.TemporaryDirectory() as directory:
                tree, manifest, digest, expected = fixture(Path(directory), edition)
                results = [verify_xml_tree(tree, manifest, manifest_sha256=digest,
                    xml_version=edition, workers=workers) for workers in (1, 4, 8)]
                for result in results:
                    self.assertEqual(result['status'], 'FILES_VERIFIED_REQUIRES_CALLER_LINEAGE')
                    self.assertEqual(result['caller_lineage'], 'NOT_CHECKED')
                    self.assertEqual(result['files'], len(expected))
                    self.assertEqual(result['bytes'], sum(len(data) for data in expected.values()))
                    self.assertEqual(result['bsl_files'], 2)
                    self.assertEqual(result['metadata_envelopes'], 2)
                    actual = {row['path']: (row['bytes'], row['sha256']) for row in result['facts']}
                    self.assertEqual(actual, {name: (len(data), hashlib.sha256(data).hexdigest())
                                             for name, data in expected.items()})
                self.assertEqual(results[0]['facts'], results[1]['facts'])
                self.assertEqual(results[0]['facts'], results[2]['facts'])
                self.assertEqual(len({row['facts_sha256'] for row in results}), 1)

    def test_all_serial_and_parallel_negatives_have_error_proof_never_success(self):
        defects = ('malformed', 'edition', 'envelope', 'changed', 'extra', 'missing',
                   'hardlink', 'manifest-hardlink', 'duplicate', 'duplicate-key', 'path')
        for workers in (1, 4, 8):
            for defect in defects:
                with self.subTest(workers=workers, defect=defect), tempfile.TemporaryDirectory() as directory:
                    tree, manifest, digest, ignored = fixture(Path(directory), defect=defect)
                    with self.assertRaises(ReadbackFailure) as caught:
                        verify_xml_tree(tree, manifest, manifest_sha256=digest,
                                        xml_version='2.20', workers=workers)
                    proof = caught.exception.proof
                    self.assertEqual(proof['status'], 'FAILED_FILE_READBACK')
                    self.assertEqual(proof['caller_lineage'], 'NOT_CHECKED')
                    self.assertIn('phase', proof)
                    if defect in ('malformed', 'edition', 'envelope', 'changed', 'hardlink'):
                        self.assertEqual(proof['phase'], 'payload')
                        self.assertTrue(proof['file_errors'])

    def test_symlink_file_or_directory_refuses_when_platform_allows_creation(self):
        for directory_link in (False, True):
            with self.subTest(directory=directory_link), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tree, manifest, digest, ignored = fixture(root)
                try:
                    if directory_link:
                        outside = root/'outside'
                        outside.mkdir()
                        os.symlink(outside, tree/'Linked', target_is_directory=True)
                    else:
                        target = tree/'ConfigDumpInfo.xml'
                        outside = root/'outside.xml'
                        target.replace(outside)
                        os.symlink(outside, target)
                except OSError as error:
                    self.skipTest('Host does not permit creating a real symlink: '+str(error))
                with self.assertRaises(ReadbackFailure):
                    verify_xml_tree(tree, manifest, manifest_sha256=digest, xml_version='2.20', workers=4)

    def test_invalid_workers_and_wrong_manifest_digest_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            tree, manifest, digest, ignored = fixture(Path(directory))
            for workers in (0, 2, 16, True):
                with self.subTest(workers=workers), self.assertRaises(ReadbackFailure):
                    verify_xml_tree(tree, manifest, manifest_sha256=digest, xml_version='2.20', workers=workers)
            with self.assertRaises(ReadbackFailure):
                verify_xml_tree(tree, manifest, manifest_sha256='0'*64, xml_version='2.20', workers=4)


if __name__ == '__main__':
    unittest.main()
