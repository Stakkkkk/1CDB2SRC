import copy,io,json,os,tempfile,types,unittest
from contextlib import redirect_stdout,redirect_stderr
from pathlib import Path
from unittest.mock import patch
import onecdb2src
from onecdb2src import cli,worker
from onecdb2src.util import fact,save,read

BASE=['--provider','postgresql','--host','localhost','--database','sample','--user','user','--supplier','Generic','--output','unused']

def good_job(backend='windows-job'):
    result=dict(failure=None,job_handle_closed=True,surviving_pids=[],cleanup_errors=[],observation_status='OBSERVED',io_errors=[],pipes_closed={'stdin':True,'stdout':True,'stderr':True},memory_controls=False,rss_limit_bytes=None,exit_code=0,seconds=.01,peak_job_rss_bytes=None)
    if backend=='linux-posix':result.update(backend=backend,processgroups_closed=True)
    else:result.update(drains_joined=True,target_streams_closed={'stdout':True,'stderr':True})
    return result

class FastCLI(unittest.TestCase):
    def test_parser_defaults_and_invalid_modes(self):
        a=cli.parser().parse_args(BASE);cli.validate_modes(a)
        self.assertEqual((a.docker_mode,a.docker_transfer,a.readback_workers),('host','copy',None))
        for flags in [['--docker-mode','fast'],['--docker-mode','fast','--assembly-mode','adopt','--runtime','native'],['--docker-transfer','stream'],['--readback-workers','8'],['--docker-mode','fast','--assembly-mode','adopt','--native-memory-mib','512']]:
            with self.subTest(flags=flags),self.assertRaises(ValueError):cli.validate_modes(cli.parser().parse_args(BASE+flags))
        a=cli.parser().parse_args(BASE+['--docker-mode','fast','--assembly-mode','adopt','--readback-workers','8']);cli.validate_modes(a)

    def test_stage_plan_budget_and_memory(self):
        fast=dict(docker_mode='fast',runtime_backend='docker',native_seconds=300,python_seconds=600,fast_side_seconds=2880)
        args=cli.parser().parse_args(BASE+['--profile','small'])
        self.assertEqual(cli.stage_plan(fast),['capture','cf','profiles','fast-main','fast-vendor','integrity'])
        for stage in cli.stage_plan(fast):self.assertIsNone(cli.stage_memory_budget(fast,stage))
        self.assertEqual(cli.stage_seconds(fast,args,'fast-main'),2925)
        self.assertEqual(cli.stage_seconds(fast,args,'integrity'),1380)
        legacy=dict(runtime_backend='docker',native_seconds=300,native_memory_mib=3072)
        self.assertEqual(len(cli.stage_plan(legacy)),12)
        self.assertEqual(cli.stage_seconds(legacy,args,'assembly-main'),600)
        self.assertEqual(cli.stage_memory_budget(legacy,'capture'),3*1024**3)

    def test_receipt_backend_semantics_and_negatives(self):
        for backend in ('windows-job','linux-posix'):
            clean=good_job(backend);cli.require_stage_closure(clean,'capture',True)
            for key,value in [('io_errors',['write closed']),('pipes_closed',{'stdout':True,'stderr':False}),('surviving_pids',[999]),('memory_controls',True),('rss_limit_bytes',1),('cleanup_errors',['unknown'])]:
                row=copy.deepcopy(clean);row[key]=value
                with self.subTest(backend=backend,key=key),self.assertRaises(ValueError):cli.require_stage_closure(row,'capture',True)
        row=good_job();row.pop('drains_joined')
        with self.assertRaises(ValueError):cli.require_stage_closure(row,'capture')
        row=good_job('linux-posix');row['processgroups_closed']=False
        with self.assertRaises(ValueError):cli.require_stage_closure(row,'capture')

    def test_cpu_only_admission_never_queries_memory(self):
        import psutil
        def docker(args,timeout=60):
            self.assertNotIn('MemUsage',str(args))
            return types.SimpleNamespace(returncode=0,stdout=json.dumps({'NCPU':8}) if args[0]=='info' else '2.50%\n')
        with patch.object(cli,'docker',docker),patch.object(psutil,'virtual_memory',side_effect=AssertionError('memory called')),patch.object(psutil,'cpu_percent',return_value=2),patch.object(psutil,'Process',return_value=types.SimpleNamespace(cpu_affinity=lambda:list(range(8)))):
            self.assertFalse(cli.fresh_fast_cpu_admission({})['memory_controls'])

    def test_fast_cleanup_requires_positive_proof(self):
        module=types.ModuleType('onecdb2src.xml.fast_docker');module.cleanup_fast_owned=lambda config:{'confirmed':True,'status':'CONFIRMED_OWN_FAST_RESOURCES_ABSENT'}
        with patch.dict('sys.modules',{'onecdb2src.xml.fast_docker':module}):
            self.assertTrue(cli.cleanup_native(Path('.'),{'docker_mode':'fast'})['confirmed'])
            module.cleanup_fast_owned=lambda config:{'confirmed':False,'status':'UNKNOWN'}
            with self.assertRaises(ValueError):cli.cleanup_native(Path('.'),{'docker_mode':'fast'})

    def test_preflight_preserves_offline_engine_guards_without_memory_or_bind_caps(self):
        import psutil
        from onecdb2src.xml import export_native,runtime_identity
        helper=types.ModuleType('onecdb2src.xml.fast_runtime')
        helper.prepare_helper=lambda config,package:{'manifest_path':'sealed.json','manifest_sha256':'a'*64,'selected_image_id':'sha256:'+'b'*64}
        image='sha256:'+'c'*64;layers=['sha256:'+'d'*64]
        context={'Endpoints':{'docker':{'Host':'unix:///local-fixture'}}}
        def docker(args,timeout=60):
            if args[:2]==['image','inspect']:
                return types.SimpleNamespace(returncode=0,stdout=json.dumps([{'Id':image,'RootFS':{'Layers':layers},'Config':{}}]))
            self.assertEqual(args[0],'info')
            return types.SimpleNamespace(returncode=0,stdout=json.dumps({'MemoryLimit':False,'CpuCfsQuota':True,'PidsLimit':True}))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);archive=root/'runtime/runtime-image.tar';archive.parent.mkdir();archive.write_bytes(b'sealed-fixture')
            config=dict(root=str(root),runtime={'archive':fact(archive)},docker_mode='fast',runtime_backend='docker',memory_controls=False)
            with patch.dict('sys.modules',{'onecdb2src.xml.fast_runtime':helper}),patch.object(cli,'PACKAGE',root),patch.object(cli,'docker',docker),patch.object(cli,'fresh_fast_cpu_admission',return_value={'memory_controls':False}),patch.object(cli.shutil,'disk_usage',return_value=types.SimpleNamespace(free=9*1024**3)),patch.object(psutil,'virtual_memory',side_effect=AssertionError('memory queried')),patch.object(export_native,'configure'),patch.object(export_native,'context_record',return_value=context),patch.object(export_native,'endpoint_policy') as endpoint,patch.object(export_native,'daemon_policy') as daemon,patch.object(export_native,'image_policy') as policy,patch.object(export_native,'verify_bind_visibility',side_effect=AssertionError('capped bind probe called')),patch.object(runtime_identity,'identities',return_value={'allowed_image_ids':[image],'rootfs_diff_ids':layers,'provenance_image_id':image}):
                result=cli.preflight(config);self.assertFalse(result['memory_controls']);endpoint.assert_called();daemon.assert_called_once();policy.assert_called_once()
                self.assertEqual(config['runtime']['image_id'],image);self.assertIn('fast_helper',config)
                archive.write_bytes(b'corrupt')
                with self.assertRaisesRegex(ValueError,'Bundled runtime archive mismatch'):cli.preflight(config)

    def test_fake_main_pipeline_password_and_single_final_dispatch(self):
        from onecdb2src.control import bounded_process
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'result';events=[]
            def fake_run(argv,out,err,receipt,seconds,*caps,**kw):
                stage=argv[-2];config=read(argv[-1]);events.append((stage,kw['rss_cap'],kw['env'],seconds))
                out.write_bytes(b'');err.write_bytes(b'')
                if stage.startswith('fast-'):
                    path=output/'_work'/stage;path.mkdir();save(path/'result.json',{'status':'CANDIDATE_GENERATED_REQUIRES_HOST_VERIFICATION'})
                if stage=='integrity':save(output/'_work/integrity.json',{'status':'PASS_OWN_RESULT_INTEGRITY','sides':{},'limitations':[{'parents_inventory':'UNKNOWN'}]})
                return good_job()
            def preflight(config):config['fast_helper']={'manifest_path':'sealed','manifest_sha256':'0'*64,'selected_image_id':'sha256:'+'1'*64};return {'memory_controls':False}
            argv=BASE+['--output',str(output),'--docker-mode','fast','--assembly-mode','adopt','--password-env','AA_FAKE_PASSWORD','--total-seconds','60']
            with patch.dict(os.environ,{'AA_FAKE_PASSWORD':'fixture-only','PGPASSWORD':'other-fixture'}),patch.object(cli,'PACKAGE',Path(onecdb2src.__file__).resolve().parents[1]),patch.object(cli,'preflight',preflight),patch.object(cli,'fresh_fast_cpu_admission',return_value={'memory_controls':False}),patch.object(cli,'cleanup_native',return_value={'confirmed':True}),patch.object(bounded_process,'run',fake_run),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(argv),2)
            self.assertEqual([x[0] for x in events],['capture','cf','profiles','fast-main','fast-vendor','integrity'])
            for stage,cap,env,seconds in events:
                self.assertIsNone(cap);self.assertLessEqual(seconds,60)
                self.assertNotIn('AA_FAKE_PASSWORD',env);self.assertNotIn('PGPASSWORD',env)
                self.assertEqual(env.get('ONECDB2SRC_AUTH_PASSWORD'),'fixture-only' if stage=='capture' else None)
            config=read(output/'_work/config.json');self.assertFalse(config['memory_controls']);self.assertIn('fast_helper',config)
            self.assertEqual(read(output/'report.json')['status'],'COMPLETE_WITH_LIMITATIONS')

    def test_worker_dispatch_rejects_invalid_config(self):
        module=types.ModuleType('onecdb2src.xml.fast_docker');calls=[];module.produce_fast_side=lambda config,side:calls.append(side)
        config=dict(root='.',runtime_backend='docker',docker_mode='fast',assembly_mode='adopt',memory_controls=False)
        with patch.dict('sys.modules',{'onecdb2src.xml.fast_docker':module}):
            worker.run('fast-main',config);worker.run('fast-vendor',config)
            self.assertEqual(calls,['main','vendor'])
            for change in ({'memory_controls':True},{'assembly_mode':'copy'},{'runtime_backend':'native'}):
                with self.assertRaises(ValueError):worker.run('fast-main',{**config,**change})
            with self.assertRaises(ValueError):worker.run('fast-other',config)

    def test_final_common_cf_lineage_and_exactly_one_readback_per_side(self):
        from test_worker_single_read import fixture,IDENTITY
        from onecdb2src import profiles
        from onecdb2src.xml.readback import verify_xml_tree
        for defect in (None,'corrupt','malformed','cf-mutation','wrong-host-profile','candidate-missing'):
            with self.subTest(defect=defect),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);config=fixture(root,defect if defect in ('corrupt','malformed') else None)
                config.update(docker_mode='fast',runtime_backend='docker',assembly_mode='adopt',memory_controls=False,readback_workers=4)
                calls=[]
                for side in ('main','vendor'):
                    p=root/'_work'/('fast-'+side);p.mkdir();save(p/'result.json',{'status':'CANDIDATE_GENERATED_REQUIRES_HOST_VERIFICATION' if not(defect=='candidate-missing' and side=='vendor') else 'FAILED'})
                module=types.ModuleType('onecdb2src.xml.namespace_result')
                def verify(config,side,workers):
                    calls.append(side);source=root/'_work/cf'/side/'source.cf';profile=profiles.load(root/'_work/profiles'/(side+'.json'),source)
                    proof=verify_xml_tree(root/side/'xml',root/side/'files.jsonl',manifest_sha256=fact(root/side/'files.jsonl')['sha256'],xml_version=profile['xml_version'],workers=workers)
                    result=dict(status='PASS_FAST_SIDE_REQUIRES_COMMON_CF_FINALIZATION',cf=fact(source),profile=profile,xml_files=proof['files'],xml_bytes=proof['bytes'],bsl_files=proof['bsl_files'],opaque_unaccepted=0,native_policy={'opaque':[]},files_proof=proof,limitations=[{'parents_inventory':'UNKNOWN'}])
                    if defect=='cf-mutation':source.write_bytes(b'changed during verification')
                    if defect=='wrong-host-profile':result['profile']={**profile,'xml_version':'2.20'}
                    return result
                module.verify_fast_side=verify
                with patch.dict('sys.modules',{'onecdb2src.xml.namespace_result':module}),patch('onecdb2src.sqlcf.export_cf.config_identity',return_value=IDENTITY):
                    if defect:
                        with self.assertRaises(Exception):worker.integrity(config)
                        self.assertFalse((root/'_work/integrity.json').exists())
                        if defect=='candidate-missing':self.assertEqual(calls,[])
                    else:
                        worker.integrity(config);self.assertEqual(calls,['main','vendor'])
                        result=read(root/'_work/integrity.json');self.assertEqual(result['sides']['main']['xml_files'],3)
                        self.assertEqual(result['limitations'],[{'parents_inventory':'UNKNOWN'},{'parents_inventory':'UNKNOWN'}])

if __name__=='__main__':unittest.main()
