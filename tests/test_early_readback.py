"""Actual neutral bytes/XML: early parsing never replaces late payload hashes."""
import copy,hashlib,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'app'),str(Path(__file__).resolve().parent)]
from test_parallel_readback import fixture
from onecdb2src.xml import readback,late_readback as late


class EarlyReadbackTests(unittest.TestCase):
    def test_all_bytes_read_again_without_reparsing_both_editions(self):
        for edition in ('2.20','2.21'):
            for workers in (1,2,4,6,8):
                with self.subTest(edition=edition,workers=workers),tempfile.TemporaryDirectory() as tmp:
                    tree,manifest,digest,expected=fixture(Path(tmp),edition)
                    full=readback.verify_xml_tree(tree,manifest,manifest_sha256=digest,xml_version=edition,workers=workers)
                    calls=[];original=late.inspect_file
                    def inspect(path,parse_xml=False):
                        name=str(path);normalized=Path(name[4:]) if name.startswith('\\\\?\\') else Path(path)
                        calls.append((normalized.relative_to(tree).as_posix(),parse_xml));return original(path,parse_xml)
                    with patch.object(late,'inspect_file',inspect):
                        final=late.verify_unchanged_xml_tree(tree,manifest,manifest_sha256=digest,xml_version=edition,prior=full,workers=workers)
                    self.assertEqual(final['status'],late.STATUS)
                    self.assertEqual(final['facts'],full['facts']);self.assertEqual(final['facts_sha256'],full['facts_sha256'])
                    self.assertEqual(sorted(calls),[(name,False) for name in sorted(expected)])

    def test_same_size_changed_payload_with_restored_mtime_is_rejected(self):
        for workers in (1,2,6,8):
            with self.subTest(workers=workers),tempfile.TemporaryDirectory() as tmp:
                tree,manifest,digest,_=fixture(Path(tmp));full=readback.verify_xml_tree(tree,manifest,manifest_sha256=digest,xml_version='2.20')
                target=tree/'Catalogs/A/Ext/Form.xml';state=target.stat();raw=target.read_bytes();target.write_bytes(raw.replace(b'Neutral',b'Changed'))
                os.utime(target,ns=(state.st_atime_ns,state.st_mtime_ns));self.assertEqual(target.stat().st_size,state.st_size)
                with self.assertRaises(readback.ReadbackFailure):
                    late.verify_unchanged_xml_tree(tree,manifest,manifest_sha256=digest,xml_version='2.20',prior=full,workers=workers)

    def test_missing_extra_hardlink_and_changed_manifest_refuse(self):
        for defect in ('missing','extra','hardlink','manifest'):
            with self.subTest(defect=defect),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);tree,manifest,digest,_=fixture(root);full=readback.verify_xml_tree(tree,manifest,manifest_sha256=digest,xml_version='2.20')
                if defect=='missing':(tree/'ConfigDumpInfo.xml').unlink()
                elif defect=='extra':(tree/'unexpected.bin').write_bytes(b'x')
                elif defect=='hardlink':os.link(tree/'ConfigDumpInfo.xml',root/'outside')
                else:manifest.write_bytes(manifest.read_bytes()+b'\n')
                with self.assertRaises(readback.ReadbackFailure):late.verify_unchanged_xml_tree(tree,manifest,manifest_sha256=digest,xml_version='2.20',prior=full)

    def test_incomplete_or_tampered_prior_facts_refuse(self):
        changes=(lambda x:x.update(status='FAILED'),lambda x:x.update(files=x['files']+1),
            lambda x:x['facts'].append(copy.deepcopy(x['facts'][0])),lambda x:x.update(facts_sha256='0'*64),
            lambda x:x['facts'][0].update(kind='directory'),lambda x:x.update(bytes=x['bytes']+1),
            lambda x:x.update(bsl_files=x['bsl_files']+1),lambda x:x.update(metadata_envelopes=0),
            lambda x:x.update(errors=['bad']),lambda x:x.update(manifest={'sha256':'0'*64}),
            lambda x:x.update(xml_parse='REUSED'),lambda x:x.update(bsl_files=False))
        with tempfile.TemporaryDirectory() as tmp:
            tree,manifest,digest,_=fixture(Path(tmp));full=readback.verify_xml_tree(tree,manifest,manifest_sha256=digest,xml_version='2.20')
            for change in changes:
                prior=copy.deepcopy(full);change(prior)
                with self.subTest(change=change),self.assertRaises(ValueError):late.verify_unchanged_xml_tree(tree,manifest,manifest_sha256=digest,xml_version='2.20',prior=prior)

    def test_changed_self_consistent_manifest_cannot_reuse_old_xml_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree,manifest,digest,_=fixture(Path(tmp));full=readback.verify_xml_tree(tree,manifest,manifest_sha256=digest,xml_version='2.20')
            path=tree/'Catalogs/A/Ext/Form.xml';path.write_bytes(b'<broken>')
            rows=[json.loads(line) for line in manifest.read_text('utf-8').splitlines()]
            for row in rows:
                if row['path']=='Catalogs/A/Ext/Form.xml':row.update(bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            manifest.write_text(''.join(json.dumps(row)+'\n' for row in rows),'utf-8');changed=hashlib.sha256(manifest.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):late.verify_unchanged_xml_tree(tree,manifest,manifest_sha256=changed,xml_version='2.20',prior=full)


if __name__=='__main__':unittest.main()
