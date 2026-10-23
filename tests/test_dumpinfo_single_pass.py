"""Small synthetic regression tests for BD-029A (actual permitted by parent).

Run manually after review with the repository's normal Python environment.
No DB, Docker, platform, control exports or real ERP inputs are used.
"""
import collections
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
sys.path.insert(0, str(ROOT / 'tests'))
from onecdb2src.xml import dump_info_modern_r3 as old
from onecdb2src import profiles
from test_profiles import fixture_cf

# Compare retained legacy API with explicit fused API of the packaged module.
new = old

MD = old.MD[1:-1]
ROOT_ID = str(uuid.UUID(int=100))
CAT_ID = str(uuid.UUID(int=101))
CHILD_ID = str(uuid.UUID(int=102))


def envelope(family, identity, name, child='', edition='2.20'):
    return (f'<MetaDataObject xmlns="{MD}" version="{edition}">'
            f'<{family} uuid="{identity}"><Properties><Name>{name}</Name></Properties>'
            f'{child}</{family}></MetaDataObject>').encode()


def tree_fixture(root):
    paths = {
        'Configuration.xml': envelope('Configuration', ROOT_ID, 'Neutral'),
        'Catalogs/A.xml': envelope('Catalog', CAT_ID, 'A',
            f'<Attributes><Attribute uuid="{CHILD_ID}"><Properties><Name>X</Name>'
            '</Properties></Attribute></Attributes>'),
        'Catalogs/A/Ext/Form.xml': b'<Form xmlns="urn:form"><Item>neutral</Item></Form>',
        'Ext/Other.xml': b'<Other/>',
    }
    for relative, data in paths.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return paths


class SinglePassTests(unittest.TestCase):
    def test_original_return_api_stays_three_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree_fixture(root)
            self.assertEqual(len(new.metadata_index(root, {ROOT_ID: 'r', CAT_ID: 'c'}, ROOT_ID,
                {'name': 'Neutral', 'uuid': ROOT_ID})), 3)

    def test_indexes_and_evidence_equal_legacy_two_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = tree_fixture(root)
            stamps = {ROOT_ID: 'r', CAT_ID: 'c'}
            identity = {'name': 'Neutral', 'uuid': ROOT_ID}
            expected = old.metadata_index(root, stamps, ROOT_ID, identity)
            expected_count = old.validate_metadata_envelopes(root, '2.20')
            counts = collections.Counter()
            original = Path.read_bytes
            def counted(path):
                counts[path.relative_to(root).as_posix()] += 1
                return original(path)
            with patch.object(Path, 'read_bytes', counted):
                result = new.metadata_index(root, stamps, ROOT_ID, identity, '2.20')
            self.assertEqual(result[:3], expected)
            self.assertEqual(result[3], expected_count)
            self.assertEqual(counts, collections.Counter({name: 1 for name in paths}))

    def test_nested_depth_path_order_and_owners_equal_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree_fixture(root)
            form = root/'Catalogs/A/Forms/F.xml'
            form.parent.mkdir(parents=True)
            form_id = str(uuid.UUID(int=103))
            form.write_bytes(envelope('Form', form_id, 'F'))
            stamps = {ROOT_ID: 'r', CAT_ID: 'c', form_id: 'f'}
            identity = {'name': 'Neutral', 'uuid': ROOT_ID}
            self.assertEqual(new.metadata_index(root, stamps, ROOT_ID, identity, '2.20')[:3],
                             old.metadata_index(root, stamps, ROOT_ID, identity))

    def test_wrong_metadata_edition_outside_ext_still_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree_fixture(root)
            (root/'Catalogs/A.xml').write_bytes(envelope('Catalog', CAT_ID, 'A', edition='2.21'))
            with self.assertRaisesRegex(ValueError, 'envelope profile mismatch'):
                new.metadata_index(root, {ROOT_ID: 'r', CAT_ID: 'c'}, ROOT_ID,
                                   {'name': 'Neutral', 'uuid': ROOT_ID}, '2.20')

    def test_malformed_xml_in_ext_still_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree_fixture(root)
            (root/'Ext/Other.xml').write_bytes(b'<bad>')
            with self.assertRaises(Exception):
                new.metadata_index(root, {ROOT_ID: 'r', CAT_ID: 'c'}, ROOT_ID,
                                   {'name': 'Neutral', 'uuid': ROOT_ID}, '2.20')

    def test_wrong_envelope_edition_in_ext_still_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree_fixture(root)
            (root/'Ext/Other.xml').write_bytes(envelope('Catalog', str(uuid.uuid4()), 'Ignored', edition='2.21'))
            with self.assertRaisesRegex(ValueError, 'envelope profile mismatch'):
                new.metadata_index(root, {ROOT_ID: 'r', CAT_ID: 'c'}, ROOT_ID,
                                   {'name': 'Neutral', 'uuid': ROOT_ID}, '2.20')

    def test_ext_metadata_is_validated_but_not_indexed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree_fixture(root)
            (root/'Ext/Other.xml').write_bytes(envelope('Catalog', str(uuid.uuid4()), 'Ignored'))
            result = new.metadata_index(root, {ROOT_ID: 'r', CAT_ID: 'c'}, ROOT_ID,
                                        {'name': 'Neutral', 'uuid': ROOT_ID}, '2.20')
            self.assertEqual(result[3], 3)
            self.assertEqual(set(result[0]), {ROOT_ID, CAT_ID, CHILD_ID})

    def test_no_metadata_envelope_still_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'Other.xml').write_text('<Other/>')
            with self.assertRaisesRegex(ValueError, 'No generated MDClasses'):
                new.metadata_index(root, {}, ROOT_ID, {'name': 'Neutral', 'uuid': ROOT_ID}, '2.20')

    def test_fresh_full_profile_load_detects_same_size_same_mtime_cf_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cf = fixture_cf(root/'source.cf')
            profile = profiles.select(cf)
            receipt = root/'profile.json'
            profiles.save_new(receipt, profile)
            loaded = profiles.load(receipt, cf)
            self.assertEqual(loaded['cf_sha256'], hashlib.sha256(cf.read_bytes()).hexdigest())
            original = cf.stat()
            # A payload-bit mutation keeps size and restored mtime. No stat-only
            # cache can establish immutability; the unchanged full load refuses.
            raw = bytearray(cf.read_bytes())
            raw[-1] ^= 1
            cf.write_bytes(raw)
            os.utime(cf, ns=(original.st_atime_ns, original.st_mtime_ns))
            with self.assertRaises(Exception):
                profiles.load(receipt, cf)


if __name__ == '__main__':
    unittest.main()
