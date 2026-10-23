"""Fast Docker protocol tests, fully synthetic and portable.

Real CF/profile/classifier/independent readback run against small generated data.
Docker daemon, engine and Linux helper payloads are simulated; no external files,
credentials, project exports, image cache or Docker installation are required.
"""
import copy, hashlib, importlib.util, json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
# Standard source checkout layout; an installed package/PYTHONPATH also works.
APP=Path(__file__).resolve().parents[1]/'app'
if APP.is_dir():sys.path.insert(0,str(APP))
from onecdb2src import profiles
from onecdb2src.xml import fast_docker as fast, namespace_result as ns, _fast_contract as fc
from onecdb2src.xml import readback as v
import fast_protocol_support as af
CF=af.CF;ENGINE=af.ENGINE;HELPER=af.HELPER
HELPER_VALUE={'source_files':{'onecdb2src/xml/fast_docker.py':fc.fact(fast.__file__)},
    'runtime_files':{'runtime/local/test-elf':{'bytes':1,'sha256':'1'*64}},
    'entrypoint':['python','-I','-S','-B','/opt/app/onecdb2src/xml/linux_helpers.py'],
    'image_identity':{'allowed_image_ids':[HELPER],'rootfs_diff_ids':['sha256:'+'d'*64]}}

class ProductDocker(af.FakeDocker):
    side='main'
    def profile(self):
        value=profiles.select(CF,'auto');value['cf_path']='/job/_work/cf/'+self.side+'/source.cf'
        value['profile_id']=profiles._id(value);return value
    def prepare(self):
        profile=self.profile();fast.save(self.job/('_work/profiles/'+self.side+'.json'),profile)
        if any(name.endswith('-cf') for name in self.volumes):
            fc.require(fc.fact(self.cf_store/'source.cf')==self.contract()['cf'],'Staged CF fixture mismatch')
        fc.save_new(self.job/('namespace-'+self.side+'.json'),{'schema':fc.NAMESPACE_SCHEMA,
            'contract_sha256':fc.fact(self.output/'contract.json')['sha256'],
            'cf_path':profile['cf_path'],'profile_path':'/job/_work/profiles/'+self.side+'.json',
            'profile_fact':fc.fact(self.job/('_work/profiles/'+self.side+'.json')),'profile':profile,'originals_rewritten':False})
    def helpers(self):
        output=self.job/self.side;tree=output/'xml';tree.mkdir(parents=True)
        version=self.profile()['xml_version']
        values={'Configuration.xml':'<MetaDataObject xmlns="http://v8.1c.ru/8.3/MDClasses" version="'+version+'"><Configuration/></MetaDataObject>',
                'ConfigDumpInfo.xml':'<ConfigDumpInfo xmlns="http://v8.1c.ru/8.3/xcf/dumpinfo" version="'+version+'"/>',
                'Module.bsl':'// synthetic test fixture\n'}
        records=[]
        for name,text in values.items():
            (tree/name).write_text(text,encoding='utf-8');records.append({'path':name,**fc.fact(tree/name)})
        (output/'files.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in records),encoding='utf-8')
        native=fc.read(self.job/('_work/native-'+self.side+'/receipt.json'))
        fc.save_new(output/'receipt.json',{'status':'CANDIDATE_POSTGEN_VERIFICATION_REQUIRED',
            'files':3,'manifest_sha256':fc.fact(output/'files.jsonl')['sha256'],
            'profile':self.profile(),'profile_receipt':native['profile_receipt'],
            'cf_sha256':self.contract()['cf']['sha256'],'unaccepted_opaque_entries':[]})
        fc.save_new(self.job/('linux-proof-'+self.side+'.json'),{'schema':fc.PROOF_SCHEMA,'status':'CANDIDATE_HOST_READBACK_REQUIRED',
            'side':self.side,'native_policy':fc.read(self.output/'native-classification.json'),
            'contract_sha256':fc.fact(self.output/'contract.json')['sha256'],
            'native_receipt_fact':fc.fact(self.job/('_work/native-'+self.side+'/receipt.json')),
            'assembly_receipt_fact':fc.fact(output/'receipt.json'),'files_manifest_fact':fc.fact(output/'files.jsonl'),
            'namespace_fact':fc.fact(self.job/('namespace-'+self.side+'.json')),'cf':self.contract()['cf'],
            'source_files':HELPER_VALUE['source_files'],'runtime_files':HELPER_VALUE['runtime_files'],
            'oracle_inputs':[],'memory_controls':False,'host_transfer':'NOT_RUN','host_readback':'NOT_RUN'})
    def __call__(self,argv,**kwargs):
        command=list(map(str,argv))[1:]
        if command[:1] in (['--context'],['--host']):command=command[2:]
        fault=self.fault
        special=fault in ('cf-mount-foreign','cf-mount-writable','cf-mount-bind') and command[:1]==['inspect']
        if special:self.fault=None
        try:result=super().__call__(argv,**kwargs)
        finally:self.fault=fault
        if special:
            values=json.loads(result.stdout);row=values[0]
            if row['Name'].endswith('-prepare'):
                mount=next(item for item in row['Mounts'] if item['Destination']=='/job/_work/cf/'+self.side)
                if fault=='cf-mount-foreign':mount['Name']='foreign-cf'
                if fault=='cf-mount-writable':mount['RW']=True
                if fault=='cf-mount-bind':mount['Type']='bind'
            result=subprocess.CompletedProcess(argv,0,json.dumps(values).encode(),b'')
        if command[:2]==['image','inspect']:
            data=json.loads(result.stdout)[0]
            data['RootFS']={'Layers':HELPER_VALUE['image_identity']['rootfs_diff_ids']}
            if command[2]==HELPER:data['Config']['Entrypoint']=HELPER_VALUE['entrypoint']
            result=subprocess.CompletedProcess(argv,0,json.dumps([data]).encode(),b'')
        if command[:1]==['create']:
            row=self.lookup(result.stdout.decode())
            mounts=[]
            for index,item in enumerate(command):
                if item!='--mount':continue
                fields=dict((part.split('=',1) if '=' in part else (part,True)) for part in command[index+1].split(','))
                mount={'Destination':fields['target'],'Type':fields['type'],'RW':not fields.get('readonly',False)}
                if fields['type']=='volume':mount['Name']=fields['source']
                else:mount['Source']=fields['source']
                mounts.append(mount)
            row['Mounts']=mounts
            row['State'].update(Status='created',Pid=0,Paused=False,Restarting=False,Dead=False,
                StartedAt='0001-01-01T00:00:00Z',FinishedAt='0001-01-01T00:00:00Z')
        if command[:1]==['start']:
            row=self.lookup(command[-1]);row['State'].update(Status='exited',Pid=0,
                StartedAt='2026-01-01T00:00:01Z',FinishedAt='2026-01-01T00:00:02Z')
            if row['Name'].endswith('-owner-init'):
                kwargs['stdout'].flush();data=fc.read(self.output/'owner-init.stdout')
                data['schema']='1CDB2SRC_FAST_ROOT_OWNER_V1'
                kwargs['stdout'].seek(0);kwargs['stdout'].truncate();kwargs['stdout'].write(json.dumps(data).encode())
        return result

class ProductTests(unittest.TestCase):
    def run_case(self,fault=None,provider='mssql',side='main',transport='volume',budget=100):
        temp=tempfile.TemporaryDirectory(prefix='fast-product-');self.addCleanup(temp.cleanup)
        base=Path(temp.name);root=base/'output';(root/'_work/cf'/side).mkdir(parents=True)
        (root/'_work/profiles').mkdir();shutil.copyfile(CF,root/'_work/cf'/side/'source.cf')
        profiles.save_new(root/'_work/profiles'/(side+'.json'),profiles.select(root/'_work/cf'/side/'source.cf','auto'))
        (root/'helper.json').write_text('{}')
        binding={'path':str(root/'helper.json'),**fc.fact(root/'helper.json'),'selected_image_id':HELPER}
        config={'root':str(root),'assembly_mode':'adopt','runtime_backend':'docker','db':{'provider':provider},
            'runtime':{'image_id':ENGINE,'binary':{'path':'/engine/ibcmd-rs'}},
            'native_seconds':10,'python_seconds':10,'fast_transport_seconds':10,'fast_side_seconds':budget,
            'fast_cf_transport':transport,'docker_context':'desktop-linux',
            'fast_helper':{'manifest_path':binding['path'],'manifest_sha256':binding['sha256'],'selected_image_id':HELPER}}
        fake=ProductDocker(base,root/'_work'/('fast-'+side),fault);fake.side=side
        binding_fn=lambda config:(copy.deepcopy(HELPER_VALUE),copy.deepcopy(binding))
        patches=[patch.object(fast,'load_helper_manifest',binding_fn),patch.object(ns,'load_helper_manifest',binding_fn),
            patch.object(fast.subprocess,'run',fake),patch.object(fast.time,'monotonic',lambda:fake.clock)]
        from contextlib import ExitStack
        stack=ExitStack();self.addCleanup(stack.close)
        for item in patches:stack.enter_context(item)
        error=None
        try:fast.produce_fast_side(config,side)
        except BaseException as caught:error=caught
        return fake,config,error,root
    def test_produce_then_independent_v_readback_and_both_provider_metadata(self):
        for provider,side,transport in (('mssql','main','volume'),('postgresql','main','volume'),
                                        ('mssql','vendor','volume'),('postgresql','vendor','bind')):
            with self.subTest(provider=provider,side=side,transport=transport):
                fake,config,error,root=self.run_case(provider=provider,side=side,transport=transport)
                self.assertIsNone(error)
                self.assertFalse((root/'_work'/('fast-'+side)/'verification.json').exists())
                result=ns.verify_fast_side(config,side,workers=4)
                self.assertEqual((result['xml_files'],result['bsl_files']),(3,1))
                self.assertEqual(result['limitations'],[])
                self.assertEqual(fc.read(root/'_work'/('fast-'+side)/'native-receipt.json')['provider'],provider)
                self.assertEqual(set(fake.containers),{fake.foreign})
                self.assertEqual(fake.volumes,{})
                self.assertEqual(fc.read(root/side/'receipt.json')['profile']['cf_path'],'/job/_work/cf/'+side+'/source.cf')
                self.assertNotEqual(result['profile']['profile_id'],result['linux_profile']['profile_id'])
    def test_actual_file_corruption_rejected_without_verified_map(self):
        fake,config,error,root=self.run_case();self.assertIsNone(error)
        (root/'main/xml/Module.bsl').write_text('// corrupted')
        with self.assertRaises(ValueError):ns.verify_fast_side(config,'main')
        self.assertFalse((root/'_work/fast-main/namespace-map.json').exists())
    def test_namespace_profile_source_raw_state_reject_before_acceptance(self):
        for filename,mutate in (
            ('linux-profile.json',lambda x:x.update(cf_path='/job/foreign.cf')),
            ('namespace.json',lambda x:x.update(originals_rewritten=True)),
            ('native-container-after.json',lambda x:x['State'].update(Running=True)),
            ('linux-proof.json',lambda x:x.update(source_files={})),
            ('native-receipt.json',lambda x:x['source'].update(sha256='0'*64))):
            with self.subTest(filename=filename):
                fake,config,error,root=self.run_case();self.assertIsNone(error)
                path=root/'_work/fast-main'/filename;value=fc.read(path);mutate(value);fast.save(path,value)
                with self.assertRaises(ValueError):ns.verify_fast_side(config,'main')
                self.assertFalse((root/'_work/fast-main/namespace-map.json').exists())
    def test_failed_native_cleanup_and_outer_recovery_keep_foreign(self):
        fake,config,error,root=self.run_case('native-timeout')
        self.assertIsInstance(error,subprocess.TimeoutExpired)
        self.assertTrue(fake.volumes)
        result=fast.cleanup_fast_owned(config)
        self.assertTrue(result['confirmed']);self.assertFalse(fake.volumes)
        self.assertEqual(set(fake.containers),{fake.foreign})
    def test_outer_foreign_label_and_unknown_daemon_are_not_clean(self):
        for fault in ('foreign-volume','ownership-swapped'):
            with self.subTest(fault=fault):
                fake,config,error,root=self.run_case(fault);self.assertIsNotNone(error)
                with self.assertRaises(RuntimeError):fast.cleanup_fast_owned(config)
                self.assertEqual(set(fake.containers)&{fake.foreign},{fake.foreign})
    def test_canceled_prepare_never_starts_native_then_outer_cleans(self):
        fake,config,error,root=self.run_case('cancel');self.assertIsInstance(error,KeyboardInterrupt)
        self.assertEqual(fake.native_started,0)
        self.assertTrue(fast.cleanup_fast_owned(config)['confirmed'])
    def test_shared_work_deadline_refuses_native_and_keeps_cleanup_possible(self):
        fake,config,error,root=self.run_case('budget',budget=10)
        self.assertIsNotNone(error);self.assertEqual(fake.native_started,0)
        self.assertTrue(fast.cleanup_fast_owned(config)['confirmed'])
    def test_cf_copy_and_cf_mount_failures_never_reach_native(self):
        for fault in ('cf-create-uncertain','cf-volume-foreign','cf-volume-role','cf-copy-failure','cf-content-corrupt','cf-mount-foreign',
                      'cf-mount-writable','cf-mount-bind','cf-absence-unknown'):
            with self.subTest(fault=fault):
                fake,config,error,root=self.run_case(fault)
                self.assertIsNotNone(error)
                self.assertFalse((root/'_work/fast-main/verification.json').exists())
                if fault!='cf-absence-unknown':self.assertEqual(fake.native_started,0)
    def test_v_is_called_once_and_metadata_change_during_readback_refuses_map(self):
        fake,config,error,root=self.run_case();self.assertIsNone(error)
        calls=[];original=v.verify_xml_tree
        def changed(*args,**kwargs):
            calls.append(True);result=original(*args,**kwargs)
            path=root/'_work/fast-main/linux-proof.json';value=fc.read(path);value['cf']['bytes']+=1;fast.save(path,value)
            return result
        with patch.object(v,'verify_xml_tree',changed):
            with self.assertRaises(ValueError):ns.verify_fast_side(config,'main')
        self.assertEqual(len(calls),1)
        self.assertFalse((root/'_work/fast-main/namespace-map.json').exists())
    def test_outer_cleanup_moved_journal_changed_cid_and_live_attachment_refused(self):
        for fault in ('moved-journal','changed-cid','live-attachment','daemon-unknown'):
            with self.subTest(fault=fault):
                fake,config,error,root=self.run_case('native-timeout')
                self.assertIsNotNone(error)
                if fault=='moved-journal':
                    path=root/'_work/fast-main/result.json';value=fc.read(path)
                    value['source_cf']['host_path']='C:/other/output/source.cf';fast.save(path,value)
                elif fault=='changed-cid':
                    # Recreate an OWN-named row whose daemon CID differs from the durable created CID.
                    path=root/'_work/fast-main/result.json';value=fc.read(path)
                    row=next(item for item in value['containers'] if item['role']=='engine')
                    fake.containers[row['name']]={'Id':'e'*64,'Name':'/'+row['name'],
                        'Config':{'Labels':{'onecdb2src.fast.nonce':value['nonce']},'Image':ENGINE},
                        'Mounts':[{'Destination':'/job','Type':'volume','Name':value['volume'],'RW':True}]}
                original=fake.__call__
                def altered(argv,**kwargs):
                    words=list(map(str,argv))
                    if fault=='live-attachment' and any(item.startswith('volume=') for item in words):
                        return subprocess.CompletedProcess(argv,0,b'foreign-attached',b'')
                    if fault=='daemon-unknown' and 'inspect' in words and 'volume' in words:
                        return subprocess.CompletedProcess(argv,1,b'',b'daemon unavailable')
                    return original(argv,**kwargs)
                with patch.object(fast.subprocess,'run',altered):
                    with self.assertRaises(RuntimeError):fast.cleanup_fast_owned(config)
                self.assertTrue(fake.volumes,'UNKNOWN cleanup must not erase ownership evidence')
                self.assertIn(fake.foreign,fake.containers)
    def test_unsupported_backend_stream_and_side_refuse_before_candidate(self):
        for side,config in (('invalid',{}),('main',{'runtime_backend':'local','assembly_mode':'adopt'}),
                            ('main',{'runtime_backend':'docker','assembly_mode':'adopt','docker_transfer':'stream'})):
            with self.subTest(side=side,config=config):
                with self.assertRaises(ValueError):fast.produce_fast_side(config,side)

class ClosureTests(unittest.TestCase):
    def test_sealed_manifest_alias_pins_and_optional_preflight_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            app=Path(temp);(app/'onecdb2src').mkdir();(app/'runtime/local').mkdir(parents=True)
            source=app/'onecdb2src/a.py';source.write_bytes(b'source')
            runtime=app/'runtime/local/elf';runtime.write_bytes(b'ELF')
            manifest=app/'helper.json';primary='sha256:'+'a'*64;alias='sha256:'+'b'*64
            value={'schema':fc.HELPER_SCHEMA,'image_id':primary,'entrypoint':HELPER_VALUE['entrypoint'],
                'image_identity':{'allowed_image_ids':[primary,alias],'rootfs_diff_ids':['sha256:'+'c'*64],
                    'provenance_image_id':primary,'classic_config_image_id':alias},
                'source_files':{'onecdb2src/a.py':fc.fact(source)},'runtime_files':{'runtime/local/elf':fc.fact(runtime)}}
            fast.save(manifest,value)
            supplied={'manifest_path':str(manifest),'manifest_sha256':fc.fact(manifest)['sha256'],
                'selected_image_id':alias,'proof':{'diagnostic':'not authoritative'}}
            _,binding=fc.load_helper_manifest({'fast_helper':supplied},app)
            self.assertEqual(binding['selected_image_id'],alias)
            for field,replacement in (('manifest_sha256','0'*64),('selected_image_id','sha256:'+'f'*64)):
                bad=dict(supplied);bad[field]=replacement
                with self.assertRaises(ValueError):fc.load_helper_manifest({'fast_helper':bad},app)
            runtime.write_bytes(b'changed')
            with self.assertRaises(ValueError):fc.load_helper_manifest({'fast_helper':supplied},app)
    def test_real_closure_rejects_extra_source_tamper_unsafe_and_hardlink(self):
        with tempfile.TemporaryDirectory() as temp:
            app=Path(temp);(app/'onecdb2src').mkdir();(app/'runtime/local').mkdir(parents=True)
            source=app/'onecdb2src/a.py';runtime=app/'runtime/local/elf'
            source.write_bytes(b'hello');runtime.write_bytes(b'ELF')
            sources={'onecdb2src/a.py':fc.fact(source)};runtimes={'runtime/local/elf':fc.fact(runtime)}
            fc.verify_source_closure(sources,runtimes,app)
            source.write_bytes(b'changed')
            with self.assertRaises(ValueError):fc.verify_source_closure(sources,runtimes,app)
            source.write_bytes(b'hello');(app/'onecdb2src/extra.py').write_bytes(b'new')
            with self.assertRaises(ValueError):fc.verify_source_closure(sources,runtimes,app)
            with self.assertRaises(ValueError):fc.source_path('../escape',app)
            os.link(runtime,app/'linked')
            with self.assertRaises(ValueError):fc.fact(runtime)
    def test_missing_volume_only_two_exact_named_errors(self):
        for message in ('no such volume: own','get own: no such volume'):
            self.assertTrue(fast.missing_volume(fast.DockerFailure(('volume','inspect','own'),1,message),'own'))
        for operation,message in ((('volume','inspect','own'),'daemon unavailable'),
                                  (('volume','inspect','own'),'get foreign: no such volume'),
                                  (('inspect','own'),'no such volume: own')):
            self.assertFalse(fast.missing_volume(fast.DockerFailure(operation,1,message),'own'))

if __name__=='__main__':unittest.main(verbosity=2)
