"""Real-filesystem adoption tests: exclusive move, bytes, XML and refusals."""
import hashlib,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from onecdb2src.xml.materialize import inspect_file,adopt_tree,producer_closed
from onecdb2src.cli import parser

class MaterializeTests(unittest.TestCase):
    def test_hash_xml_from_same_read(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'form.xml';raw=b'<Form><Title>example</Title></Form>';p.write_bytes(raw)
            fact,node=inspect_file(p,True)
            self.assertEqual(fact,{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()});self.assertEqual(node.findtext('Title'),'example')

    def test_unchanged_payload_and_atomic_publication(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);src=r/'stage';src.mkdir();(src/'x').write_bytes(b'original');dest=r/'final'
            inode=(src/'x').stat().st_ino;adopt_tree(src,dest)
            self.assertFalse(src.exists());self.assertEqual((dest/'x').read_bytes(),b'original');self.assertEqual((dest/'x').stat().st_ino,inode)

    def test_existing_empty_directory_and_file_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);src=r/'stage';src.mkdir();(src/'x').write_bytes(b'original');dst=r/'final';dst.mkdir()
            with self.assertRaises(ValueError):adopt_tree(src,dst)
            self.assertTrue(src.exists());dst.rmdir();dst.write_bytes(b'keep')
            with self.assertRaises(ValueError):adopt_tree(src,dst)
            self.assertEqual(dst.read_bytes(),b'keep');self.assertTrue(src.exists())

    def test_overlap_refused(self):
        with tempfile.TemporaryDirectory() as d:
            src=Path(d)/'stage';src.mkdir()
            with self.assertRaises(ValueError):adopt_tree(src,src/'nested')

    def test_link_and_malformed_xml_refused(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);p=r/'x';p.write_bytes(b'<broken>')
            with self.assertRaises(ET.ParseError):inspect_file(p,True)
            os.link(p,r/'alias')
            with self.assertRaises(ValueError):inspect_file(p)

    def test_concurrent_target_creation_cannot_replace_empty_directory(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'source';src.mkdir();(src/'x').write_bytes(b'keep');dst=root/'target';dst.mkdir()
            # Simulate a target appearing after the precheck; the actual OS
            # operation must still refuse to replace even an empty directory.
            with patch('onecdb2src.xml.materialize.os.path.lexists',return_value=False):
                with self.assertRaises(OSError):adopt_tree(src,dst)
            self.assertEqual((src/'x').read_bytes(),b'keep');self.assertEqual(list(dst.iterdir()),[])

    def test_source_changed_between_stat_and_open_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source';p.write_bytes(b'original');original=Path.open
            def opening(path,*args,**kwargs):
                if path==p:
                    with original(p,'wb') as writer:writer.write(b'changed length')
                return original(path,*args,**kwargs)
            with patch.object(Path,'open',opening):
                with self.assertRaisesRegex(ValueError,'identity changed'):inspect_file(p)

    def test_live_or_unproven_producer_refused(self):
        self.assertFalse(producer_closed({}));self.assertFalse(producer_closed({'process':{'container_state':{'Running':True}}}))
        self.assertTrue(producer_closed({'process':{'container_state':{'Running':False}}}))
        self.assertFalse(producer_closed({'process':{'job':{'job_handle_closed':True,'surviving_pids':[1]}}}))
        self.assertTrue(producer_closed({'process':{'job':{'job_handle_closed':True,'surviving_pids':[]}}}))

    def test_copy_default_and_explicit_adopt(self):
        args=['--provider','mssql','--host','localhost','--database','Neutral','--supplier','Neutral','--output','new']
        self.assertEqual(parser().parse_args(args).assembly_mode,'copy')
        self.assertEqual(parser().parse_args(args+['--assembly-mode','adopt']).assembly_mode,'adopt')
