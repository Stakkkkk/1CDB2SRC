"""Real filesystem readback of a long generated path; no DB or platform."""
import contextlib,hashlib,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from onecdb2src import profiles,worker
from onecdb2src.nativecf.cf_source import CFSource
from onecdb2src.sqlcf.export_cf import cf_tree,config_identity
from onecdb2src.util import fact,save
from onecdb2src.xml.dump_info import long_path
from test_profiles import fixture_cf,a,q

@contextlib.contextmanager
def own_directory():
    workspace=Path(__file__).resolve().parents[1]/'.test-scratch'
    workspace.mkdir(exist_ok=True)
    root=Path(tempfile.mkdtemp(prefix='integrity-',dir=workspace))
    try:yield str(root)
    finally:
        assert root.resolve().parent==workspace.resolve() and root.name.startswith('integrity-')
        shutil.rmtree(long_path(root))

class IntegrityLongPathTests(unittest.TestCase):
    def test_full_integrity_real_long_path_and_changed_payload_refusal(self):
        with own_directory() as td:
            root=Path(td);(root/'_work/cf').mkdir(parents=True);(root/'_work/profiles').mkdir();manifest={}
            for side,key,ident in [('main','main_cf','main_identity'),('vendor','supplier_cf','supplier_identity')]:
                source=root/'_work/cf'/side/'source.cf';source.parent.mkdir()
                def vendor_fields(r,v):v[3][1][1][14]=q('NeutralVendor');v[3][1][1][15]=q('1.0')
                fixture_cf(source,'68',mutator=vendor_fields);manifest[key]=fact(source)
                cf=CFSource(source)
                try:manifest[ident]=config_identity(cf_tree(cf.catalog,str(cf_tree(cf.catalog,'root')[1])))
                finally:cf.close()
                profile=profiles.select(source);profile_path=root/'_work/profiles'/(side+'.json');profiles.save_new(profile_path,profile)
                final=root/side;tree=long_path(final/'xml');tree.mkdir(parents=True)
                bodies={'Configuration.xml':b'<MetaDataObject xmlns="http://v8.1c.ru/8.3/MDClasses" version="2.20"><Configuration/></MetaDataObject>',
                        'ConfigDumpInfo.xml':b'<ConfigDumpInfo xmlns="http://v8.1c.ru/8.3/xcf/dumpinfo" version="2.20"/>',
                        '/'.join(['CommonModules']+['nested_'+str(n)+'_'+'x'*50 for n in range(5)]+['Module.bsl']):b'Procedure Example()\nEndProcedure\n'}
                rows=[]
                for rel,data in bodies.items():
                    p=tree/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);rows.append({'path':rel,**fact(p)})
                with (final/'files.jsonl').open('w',encoding='utf-8') as stream:
                    for row in rows:stream.write(json.dumps(row)+'\n')
                save(final/'receipt.json',{'profile':profile,'profile_receipt':{'path':str(profile_path.resolve()),'sha256':fact(profile_path)['sha256']},'status':'CANDIDATE_POSTGEN_VERIFICATION_REQUIRED','cf_sha256':manifest[key]['sha256'],'manifest_sha256':fact(final/'files.jsonl')['sha256'],'files':len(rows),'unaccepted_opaque_entries':[]})
            save(root/'_work/cf/manifest.json',manifest)
            worker.integrity({'root':str(root)})
            result=json.loads((root/'_work/integrity.json').read_text('utf-8'));self.assertEqual(result['status'],'PASS_OWN_RESULT_INTEGRITY');self.assertEqual(result['sides']['main']['bsl_files'],1)
            long=next(p for p in long_path(root/'main/xml').rglob('Module.bsl'));self.assertGreater(len(str(long)),300);long.write_bytes(b'changed')
            # Final CF is exclusive; remove only this test's two explicit copies
            # so a second call reaches readback, rather than the exclusive gate.
            for name in ('main.cf','vendor.cf'):(root/name).unlink()
            with self.assertRaisesRegex(ValueError,'Final XML readback mismatch'):worker.integrity({'root':str(root)})

if __name__=='__main__':unittest.main()
