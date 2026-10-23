"""Tiny actual verifier tests; only unchanged CF identity decoder is stubbed.

This isolates final XML readback and does not establish generic CF extraction.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'app'))
sys.path.insert(0, str(ROOT/'tests'))
from test_profiles import fixture_cf
from onecdb2src import worker as old, profiles
from onecdb2src.util import fact, save, read

new = old

IDENTITY = {'uuid': '00000000-0000-0000-0000-000000000001',
            'name': 'Neutral', 'vendor': 'Neutral', 'version': '1'}


def fixture(root, defect=None):
    cf_manifest = {'main_identity': IDENTITY, 'supplier_identity': IDENTITY}
    for side, key in [('main', 'main_cf'), ('vendor', 'supplier_cf')]:
        cf = root/'_work/cf'/side/'source.cf'
        cf.parent.mkdir(parents=True)
        fixture_cf(cf)
        cf_manifest[key] = fact(cf)
        profile = profiles.select(cf)
        path = root/'_work/profiles'/(side+'.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        profiles.save_new(path, profile)
        final = root/side
        tree = final/'xml'
        tree.mkdir(parents=True)
        files = {
            'Configuration.xml': b'<MetaDataObject xmlns="http://v8.1c.ru/8.3/MDClasses" version="2.21"><Configuration/></MetaDataObject>',
            'ConfigDumpInfo.xml': b'<ConfigDumpInfo xmlns="http://v8.1c.ru/8.3/xcf/dumpinfo" version="2.21"/>',
            'Module.bsl': b'// Neutral\n',
        }
        if defect == 'malformed':
            files['Configuration.xml'] = b'<broken>'
        rows = []
        for name, data in files.items():
            (tree/name).write_bytes(data)
            rows.append({'path': name, **fact(tree/name)})
        (final/'files.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows), 'utf-8')
        save(final/'receipt.json', {'profile': profile,
            'profile_receipt': {'path': str(path.resolve()), 'sha256': fact(path)['sha256']},
            'status': 'CANDIDATE_POSTGEN_VERIFICATION_REQUIRED',
            'cf_sha256': fact(cf)['sha256'], 'manifest_sha256': fact(final/'files.jsonl')['sha256'],
            'files': len(rows), 'unaccepted_opaque_entries': []})
        if defect == 'corrupt':
            (tree/'Module.bsl').write_bytes(b'// changed\n')
        if defect == 'extra':
            (tree/'Unexpected.bin').write_bytes(b'x')
        if defect == 'missing':
            (tree/'Module.bsl').unlink()
        if defect == 'manifest':
            with (final/'files.jsonl').open('a', encoding='utf-8') as stream:
                stream.write('\n')
        if defect == 'profile':
            receipt = read(final/'receipt.json')
            receipt['profile']['xml_version'] = '2.20'
            save(final/'receipt.json', receipt)
        if defect == 'profile-path':
            changed = read(path)
            changed['cf_path'] = str(root/'not-the-same.cf')
            save(path, changed)
        if defect == 'hardlink':
            os.link(tree/'Module.bsl', root/(side+'-module-hardlink'))
    save(root/'_work/cf/manifest.json', cf_manifest)
    return {'root': str(root)}


class WorkerSingleReadTests(unittest.TestCase):
    def test_independent_verifier_accepts_tiny_files_and_checks_final_cf_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            config = fixture(target)
            with patch('onecdb2src.sqlcf.export_cf.config_identity', return_value=IDENTITY):
                new.integrity(config)
            result = read(target/'_work/integrity.json')
            self.assertEqual(result['status'], 'PASS_OWN_RESULT_INTEGRITY')
            for side in ('main', 'vendor'):
                self.assertEqual(result['sides'][side]['xml_files'], 3)
                self.assertEqual(result['sides'][side]['bsl_files'], 1)
                self.assertEqual(result['sides'][side]['cf'], fact(target/(side+'.cf')))

    def test_changes_after_assembly_and_extra_paths_still_refuse(self):
        for defect in ('corrupt', 'extra', 'missing', 'manifest', 'malformed',
                       'profile', 'profile-path', 'hardlink'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = fixture(root, defect)
                with patch('onecdb2src.sqlcf.export_cf.config_identity', return_value=IDENTITY):
                    with self.assertRaises(Exception):
                        new.integrity(config)
                self.assertFalse((root/'_work/integrity.json').exists())

    def test_reparse_attribute_refuses_without_an_integrity_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = fixture(root)
            original = Path.lstat
            def marked(path, *args, **kwargs):
                state = original(path, *args, **kwargs)
                if path.name == 'Configuration.xml':
                    return SimpleNamespace(st_file_attributes=0x400, st_mode=state.st_mode,
                                           st_nlink=state.st_nlink)
                return state
            # Portable representation of the Windows reparse attribute. No
            # privilege/global developer-mode change or real junction needed.
            with patch('onecdb2src.sqlcf.export_cf.config_identity', return_value=IDENTITY), patch.object(Path, 'lstat', marked):
                with self.assertRaisesRegex(ValueError, 'Reparse/symlink'):
                    new.integrity(config)
            self.assertFalse((root/'_work/integrity.json').exists())

    def test_candidate_reads_each_final_xml_payload_once_and_not_assembler_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = fixture(root)
            original = Path.open
            counts = {}
            def counted(path, *args, **kwargs):
                if path.suffix == '.xml':
                    normalized = Path(str(path)[4:]) if str(path).startswith('\\\\?\\') else path
                    relative = normalized.relative_to(root).as_posix()
                    counts[relative] = counts.get(relative, 0) + 1
                return original(path, *args, **kwargs)
            with patch('onecdb2src.sqlcf.export_cf.config_identity', return_value=IDENTITY), patch.object(Path, 'open', counted):
                new.integrity(config)
            self.assertEqual(counts, {f'{side}/xml/{name}': 1
                for side in ('main', 'vendor')
                for name in ('Configuration.xml', 'ConfigDumpInfo.xml')})


if __name__ == '__main__':
    unittest.main()
