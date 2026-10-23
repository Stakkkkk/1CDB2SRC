"""Portable product stream protocol: fake Docker, real TAR/CF/profile/V files."""
import copy,io,json,os,shutil,subprocess,sys,tarfile,tempfile,threading,unittest
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from onecdb2src import cli,profiles
from onecdb2src.xml import fast_stream as stream,fast_docker as fast,namespace_result as ns,stream_tar,readback as v
from onecdb2src.xml import _fast_contract as fc,linux_helpers
import test_fast_docker as y

def pax_record(key,value):
    body=(key+'='+value+'\n').encode();size=len(body)+2
    while True:
        value=str(size).encode()+b' '+body
        if len(value)==size:return value
        size=len(value)

class Client:
    def __init__(self,raw,code=0,hook=None):
        self.stdout=io.BytesIO(raw);self.returncode=None;self.code=code;self.hook=hook;self.pid=10002
    def poll(self):return self.returncode
    def wait(self,timeout=None):
        if self.hook:
            hook,self.hook=self.hook,None;hook()
        if self.returncode is None:self.returncode=self.code
        return self.returncode
    def terminate(self):
        self.returncode=-15
        if hasattr(self.stdout,'signal'):self.stdout.signal.set()
    def kill(self):
        self.returncode=-9
        if hasattr(self.stdout,'signal'):self.stdout.signal.set()

class BlockedPipe:
    def __init__(self,on_read):self.closed=False;self.signal=threading.Event();self.on_read=on_read
    def read(self,size):self.on_read();self.signal.wait(2);return b''
    def close(self):self.closed=True

class StreamDocker(y.ProductDocker):
    def helpers(self):
        super().helpers();output=self.job/self.side;path=output/'xml/Папка/A.bsl';path.parent.mkdir();path.write_bytes(b'// nested\n')
        with (output/'files.jsonl').open('a',encoding='utf-8') as target:target.write(json.dumps({'path':'Папка/A.bsl',**fc.fact(path)})+'\n')
        receipt=fc.read(output/'receipt.json');receipt.update(files=4,manifest_sha256=fc.fact(output/'files.jsonl')['sha256']);fast.save(output/'receipt.json',receipt)
        proof_path=self.job/('linux-proof-'+self.side+'.json');proof=fc.read(proof_path);proof.update(assembly_receipt_fact=fc.fact(output/'receipt.json'),files_manifest_fact=fc.fact(output/'files.jsonl'));fast.save(proof_path,proof)
        if self.fault=='bad-proof':
            proof['namespace_fact']['sha256']='0'*64;fast.save(proof_path,proof)
        self.helpers_closed=True
    def __call__(self,argv,**kwargs):
        result=super().__call__(argv,**kwargs);words=list(map(str,argv))
        if getattr(self,'helpers_closed',False) and 'inspect' in words and 'volume' in words and self.fault=='foreign-cf-role' and words[-1].endswith('-cf'):
            data=json.loads(result.stdout);data[0]['Labels']['onecdb2src.fast.volume_role']='job';result.stdout=json.dumps(data).encode()
        if kwargs.get('encoding'):
            result.stdout=result.stdout.decode(kwargs['encoding']);result.stderr=result.stderr.decode(kwargs['encoding'])
        return result
    def spawn(self,command,**kwargs):
        assert command[-3:]==['cp',self.lookup(command[-2].split(':',1)[0])['Id']+':/job/'+self.side+'/xml','-']
        raw=io.BytesIO();root=tarfile.TarInfo('xml');root.type=tarfile.DIRTYPE;raw.write(root.tobuf())
        # Docker-like PAX/GNU fallback semantics, fully synthetic safe path.
        payload=pax_record('path','xml/Папка/')
        control=tarfile.TarInfo('xml//PaxHeaders.0');control.type=tarfile.XHDTYPE;control.size=len(payload)
        fallback=tarfile.TarInfo('xml//');fallback.type=tarfile.DIRTYPE
        raw.write(control.tobuf()+payload+b'\0'*((-len(payload))%512)+fallback.tobuf())
        for file in sorted((self.job/self.side/'xml').rglob('*')):
            if file.is_dir():continue
            data=file.read_bytes();member=tarfile.TarInfo('xml/'+file.relative_to(self.job/self.side/'xml').as_posix());member.size=len(data)
            raw.write(member.tobuf()+data+b'\0'*((-len(data))%512))
        raw.write(b'\0'*1024);data=raw.getvalue()
        if self.fault=='partial-stream':data=data[:700]
        hook=None
        if self.fault=='changed-cf-volume':
            def hook():next(value for key,value in self.volumes.items() if key.endswith('-cf'))['CreatedAt']='changed'
        self.client=Client(data,code=9 if self.fault=='cp-exit9' else 0,hook=hook)
        if self.fault in ('blocked-cancel','blocked-timeout'):
            def on_read():
                if self.fault=='blocked-cancel':self.cancel_event.set()
                else:self.clock+=20
            self.client.stdout=BlockedPipe(on_read)
        return self.client

class FastStreamTests(unittest.TestCase):
    def run_case(self,side='main',provider='mssql',cf_transport='volume',fault=None):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);base=Path(temporary.name);root=base/'output'
        (root/'_work/cf'/side).mkdir(parents=True);(root/'_work/profiles').mkdir()
        shutil.copyfile(y.CF,root/'_work/cf'/side/'source.cf');profiles.save_new(root/'_work/profiles'/(side+'.json'),profiles.select(root/'_work/cf'/side/'source.cf'))
        (root/'helper.json').write_bytes(b'{}');binding={'path':str(root/'helper.json'),**fc.fact(root/'helper.json'),'selected_image_id':y.HELPER}
        config=dict(root=str(root),assembly_mode='adopt',runtime_backend='docker',docker_mode='fast',docker_transfer='stream',memory_controls=False,
            db={'provider':provider},runtime={'image_id':y.ENGINE,'binary':{'path':'/engine/ibcmd-rs'}},native_seconds=10,python_seconds=10,
            fast_transport_seconds=10,fast_side_seconds=100,fast_cf_transport=cf_transport,docker_context='desktop-linux',fast_helper={'manifest_path':binding['path'],'manifest_sha256':binding['sha256'],'selected_image_id':y.HELPER})
        fake=StreamDocker(base,root/'_work'/('fast-'+side),fault);fake.side=side
        fake.cancel_event=threading.Event()
        sources={'onecdb2src/xml/fast_docker.py':fc.fact(fast.__file__),'onecdb2src/xml/linux_helpers.py':fc.fact(linux_helpers.__file__),
                 'onecdb2src/xml/fast_stream.py':fc.fact(stream.__file__),'onecdb2src/xml/stream_tar.py':fc.fact(stream_tar.__file__)}
        if fault=='bad-stream-source':sources['onecdb2src/xml/fast_stream.py']['sha256']='0'*64
        stack=ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch.dict(y.HELPER_VALUE['source_files'],sources))
        binding_fn=lambda config:(copy.deepcopy(y.HELPER_VALUE),copy.deepcopy(binding))
        for item in (patch.object(fast,'load_helper_manifest',binding_fn),patch.object(ns,'load_helper_manifest',binding_fn),
                     patch.object(fast.subprocess,'run',fake),patch.object(fast.subprocess,'Popen',fake.spawn),patch.object(fast.time,'monotonic',lambda:fake.clock)):
            stack.enter_context(item)
        if fault=='blocked-cancel':
            original_transfer=stream.transfer_fast_side
            def with_cancel(*args,**kwargs):return original_transfer(*args,**kwargs,cancel_event=fake.cancel_event)
            stack.enter_context(patch.object(stream,'transfer_fast_side',with_cancel))
        error=None
        try:fast.produce_fast_side(config,side)
        except BaseException as caught:error=caught
        self.assertIn(fake.foreign,fake.containers)
        return fake,config,root,error
    def test_main_vendor_volume_and_bind_original_proofs_and_one_v(self):
        for side,provider,cf_transport in (('main','mssql','volume'),('vendor','postgresql','volume'),('main','postgresql','bind')):
            with self.subTest(side=side,cf_transport=cf_transport):
                fake,config,root,error=self.run_case(side,provider,cf_transport);self.assertIsNone(error)
                calls=[];original=v.verify_xml_tree
                def checked(*args,**kwargs):calls.append(True);return original(*args,**kwargs)
                proof=root/'_work'/('fast-'+side);before=fc.fact(proof/'linux-proof.json')
                with patch.object(v,'verify_xml_tree',checked):result=ns.verify_fast_side(config,side,workers=4)
                self.assertEqual(len(calls),1);self.assertEqual((result['xml_files'],result['bsl_files']),(4,2))
                self.assertEqual(fc.fact(proof/'linux-proof.json'),before);self.assertEqual(fake.volumes,{})
                self.assertEqual(set(fake.containers),{fake.foreign});self.assertTrue(fake.client.stdout.closed)
                self.assertEqual(fc.read(root/side/'receipt.json')['profile']['cf_path'],'/job/_work/cf/'+side+'/source.cf')
    def test_transport_failures_retain_reasons_and_never_reach_final_acceptance(self):
        for fault in ('partial-stream','cp-exit9','changed-cf-volume','foreign-cf-role','bad-proof','bad-stream-source'):
            with self.subTest(fault=fault):
                fake,config,root,error=self.run_case(fault=fault);self.assertIsNotNone(error)
                proof=root/'_work/fast-main';self.assertFalse((proof/'verification.json').exists());self.assertFalse((proof/'namespace-map.json').exists())
                reason=fc.read(proof/'stream-error.json');self.assertTrue(reason['reason']);self.assertTrue(reason['error_type'])
                if fault=='partial-stream':self.assertIn('truncated',reason['reason'])
                if fault=='bad-stream-source':
                    self.assertIn('Sealed product stream source differs',reason['reason']);self.assertFalse((root/'main/xml').exists())
                if hasattr(fake,'client'):self.assertTrue(fake.client.stdout.closed)
    def test_mutated_transport_receipt_fails_before_v(self):
        fake,config,root,error=self.run_case();self.assertIsNone(error);proof=root/'_work/fast-main'
        value=fc.read(proof/'stream-process.json');value['client_cleanup']['confirmed']=False;fast.save(proof/'stream-process.json',value)
        calls=[]
        with patch.object(v,'verify_xml_tree',side_effect=lambda *args,**kwargs:calls.append(True)):
            with self.assertRaises(ValueError):ns.verify_fast_side(config,'main')
        self.assertEqual(calls,[])
    def test_owned_blocked_cp_cancel_and_timeout_close_client_without_acceptance(self):
        for fault,status in (('blocked-cancel','CANCELLED'),('blocked-timeout','TIMED_OUT')):
            with self.subTest(fault=fault):
                fake,config,root,error=self.run_case(fault=fault);self.assertIsNotNone(error)
                process=fc.read(root/'_work/fast-main/stream-process.json')
                self.assertEqual(process['status'],status);self.assertTrue(process['client_cleanup']['confirmed'])
                self.assertTrue(fake.client.stdout.closed);self.assertEqual(fake.client.returncode,-15)
                self.assertFalse((root/'_work/fast-main/verification.json').exists())
            # Each fake cancellation patch is per case, not inherited by the
            # next timeout case through unittest's method-level addCleanup.
            self.doCleanups()
    def test_owner_path_role_variant_and_schema_reject_without_source_command(self):
        owner=stream.FastStreamOwner(nonce='a'*32,cid='b'*64,name='onecdb2src-fast-'+'a'*32+'-helpers',image='sha256:'+'c'*64,
            volume='onecdb2src-fast-'+'a'*32,side='main',role='helpers',cf_sha256='d'*64,helper_sha256='e'*64,
            contract_sha256='f'*64,profile_sha256='1'*64,helper_manifest_sha256='2'*64,cf_bytes=1)
        self.assertEqual(owner.xml_source,'/job/main/xml')
        for changed in (replace(owner,side='main/../vendor'),replace(owner,role='engine'),replace(owner,schema='native'),
                        replace(owner,cf_transport='STAGED_OWN_READONLY_VOLUME',cf_volume='foreign'),replace(owner,name='foreign')):
            with self.subTest(owner=changed),self.assertRaises(ValueError):changed.validate()
    def test_early_source_guard_reason_durable_and_mode_parser(self):
        fake,config,root,error=self.run_case();self.assertIsNone(error)
        args=cli.parser().parse_args(['--provider','mssql','--host','localhost','--database','sample','--user','user','--supplier','Generic','--output','unused','--docker-mode','fast','--assembly-mode','adopt','--docker-transfer','stream'])
        cli.validate_modes(args)
        for runtime,mode in (('native','fast'),('docker','host')):
            args.runtime=runtime;args.docker_mode=mode
            with self.assertRaises(ValueError):cli.validate_modes(args)

if __name__=='__main__':unittest.main()
