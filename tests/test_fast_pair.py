"""Real tiny thread/process lifecycle tests; neutral files only, no Docker/CF."""
import copy,json,sys,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from onecdb2src import cli,fast_pair as pair
from onecdb2src.xml._fast_contract import fact,save_new
from onecdb2src.util import save


class CoordinateTests(unittest.TestCase):
    def test_vendor_overlaps_main_transfer_only_after_ready(self):
        ready=threading.Event();vendor=threading.Event();main_closed=threading.Event();events=[]
        def run(side,stop):
            if side=='main':
                ready.set();self.assertTrue(vendor.wait(1));self.assertFalse(stop.is_set());main_closed.set()
            else:self.assertTrue(ready.is_set());self.assertFalse(main_closed.is_set());vendor.set()
            return side
        result=pair.coordinate(run,lambda:{} if ready.is_set() else None,lambda:{'cpu':2},time.monotonic()+2,events.append)
        self.assertEqual(result,{'main':'main','vendor':'vendor'})
        self.assertEqual(events[-1]['event'],'all-supervisors-joined')
        names=[x['event'] for x in events];self.assertLess(names.index('main-transfer-ready'),names.index('vendor-admission'))

    def test_main_failure_before_gate_never_launches_vendor(self):
        calls=[]
        def run(side,stop):calls.append(side);raise ValueError('neutral')
        with self.assertRaisesRegex(ValueError,'Pair side failed: main'):
            pair.coordinate(run,lambda:None,lambda:None,time.monotonic()+1)
        self.assertEqual(calls,['main'])

    def test_vendor_failure_cancels_and_joins_main(self):
        ready=threading.Event();closed=threading.Event();events=[]
        def run(side,stop):
            if side=='main':ready.set();stop.wait(2);closed.set();return 'closed'
            raise ValueError('vendor neutral failure')
        with self.assertRaisesRegex(ValueError,'vendor'):
            pair.coordinate(run,lambda:{} if ready.is_set() else None,lambda:None,time.monotonic()+1,events.append)
        self.assertTrue(closed.is_set());self.assertEqual(events[-1]['event'],'all-supervisors-joined')

    def test_main_failure_after_gate_cancels_vendor(self):
        ready=threading.Event();started=threading.Event();closed=threading.Event()
        def run(side,stop):
            if side=='main':ready.set();started.wait(1);raise ValueError('late main')
            started.set();stop.wait(2);closed.set();return 'closed'
        with self.assertRaisesRegex(ValueError,'main'):
            pair.coordinate(run,lambda:{} if ready.is_set() else None,lambda:None,time.monotonic()+1)
        self.assertTrue(closed.is_set())

    def test_deadline_cancels_gate_wait_without_vendor(self):
        calls=[];closed=threading.Event()
        def run(side,stop):calls.append(side);stop.wait(2);closed.set()
        with self.assertRaisesRegex(ValueError,'deadline'):
            pair.coordinate(run,lambda:None,lambda:None,time.monotonic()+.06)
        self.assertEqual(calls,['main']);self.assertTrue(closed.is_set())

    def test_admission_failure_never_launches_vendor_and_joins_main(self):
        ready=threading.Event();closed=threading.Event();calls=[]
        def run(side,stop):calls.append(side);ready.set();stop.wait(2);closed.set()
        def admit():raise ValueError('No Docker CPU')
        with self.assertRaisesRegex(ValueError,'No Docker CPU'):
            pair.coordinate(run,lambda:{} if ready.is_set() else None,admit,time.monotonic()+1)
        self.assertEqual(calls,['main']);self.assertTrue(closed.is_set())

    def test_success_without_marker_is_a_protocol_failure(self):
        with self.assertRaisesRegex(ValueError,'without a bound'):
            pair.coordinate(lambda side,stop:None,lambda:None,lambda:None,time.monotonic()+1)


class MarkerTests(unittest.TestCase):
    def fixture(self,root):
        directory=root/'_work/fast-main';directory.mkdir(parents=True)
        manifest=root/'helper.json';save(manifest,{'neutral':True});mf=fact(manifest)
        helper={'path':str(manifest.resolve()),**mf,'selected_image_id':'sha256:'+'a'*64}
        cf={'bytes':123,'sha256':'b'*64};nonce='c'*32
        (root/'_work/cf').mkdir();save(root/'_work/cf/manifest.json',{'main_cf':cf})
        contract={'nonce':nonce,'side':'main','cf':cf,'helper_manifest_binding':helper}
        save(directory/'contract.json',contract)
        save(directory/'helpers-container-after.json',{'State':{'Running':False,'ExitCode':0,'Pid':0,'OOMKilled':False}})
        marker={'schema':pair.READY_SCHEMA,'side':'main','nonce':nonce,'cf':cf,'helper':helper,
                'status':'LINUX_HELPERS_CLOSED_READY_FOR_HOST_TRANSFER','contract':fact(directory/'contract.json'),
                'helpers_after':fact(directory/'helpers-container-after.json')}
        config={'root':str(root),'fast_helper':{'manifest_path':str(manifest),'manifest_sha256':mf['sha256'],'selected_image_id':helper['selected_image_id']}}
        return config,directory,marker

    def test_valid_and_partial_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            config,directory,marker=self.fixture(Path(tmp));self.assertIsNone(pair.transfer_ready(config))
            path=directory/'transfer-ready.json';path.write_text('{"schema":','utf-8');self.assertIsNone(pair.transfer_ready(config))
            save(path,marker);self.assertEqual(pair.transfer_ready(config),fact(path))

    def test_wrong_source_nonce_contract_and_helper_never_open_gate(self):
        for key in ('nonce','cf','contract','helper','schema'):
            with self.subTest(key=key),tempfile.TemporaryDirectory() as tmp:
                config,directory,marker=self.fixture(Path(tmp));marker[key]='wrong';save(directory/'transfer-ready.json',marker)
                with self.assertRaises(ValueError):pair.transfer_ready(config)

    def test_running_or_failed_helper_never_opens_gate_even_with_matching_hash(self):
        for change in ({'Running':True},{'Pid':123},{'ExitCode':1},{'OOMKilled':True}):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as tmp:
                config,directory,marker=self.fixture(Path(tmp))
                state={'Running':False,'ExitCode':0,'Pid':0,'OOMKilled':False};state.update(change)
                save(directory/'helpers-container-after.json',{'State':state});marker['helpers_after']=fact(directory/'helpers-container-after.json')
                save(directory/'transfer-ready.json',marker)
                with self.assertRaises(ValueError):pair.transfer_ready(config)


class PairCLITests(unittest.TestCase):
    def test_public_cli_dispatches_one_pair_then_one_integrity(self):
        from test_fast_cli import BASE,good_job
        from onecdb2src.control import bounded_process
        import contextlib,io,os
        from onecdb2src.util import read
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'result';stages=[]
            def run(argv,out,err,receipt,seconds,*caps,**kwargs):
                stage=argv[-2];config=read(argv[-1]);stages.append(stage)
                self.assertEqual(config['side_scheduling'],'transfer-overlap');self.assertIsNone(kwargs['rss_cap'])
                out.write_bytes(b'');err.write_bytes(b'')
                if stage=='fast-pair':
                    p=root/'_work/fast-pair';p.mkdir();save(p/'result.json',{'status':pair.PAIR_STATUS})
                if stage=='integrity':save(root/'_work/integrity.json',{'sides':{},'limitations':[{'parents_inventory':'UNKNOWN'}]})
                return good_job()
            flags=['--output',str(root),'--docker-mode','fast','--assembly-mode','adopt','--docker-transfer','stream','--side-scheduling','transfer-overlap']
            with patch.object(cli,'preflight',return_value={}),patch.object(cli,'fresh_fast_cpu_admission',return_value={}),patch.object(cli,'cleanup_native',return_value={'confirmed':True}),patch.object(bounded_process,'run',run),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(BASE+flags),2)
            self.assertEqual(stages,['capture','cf','profiles','fast-pair','integrity'])
            self.assertEqual(read(root/'report.json')['stages'][3]['status'],'COMPLETED')

    def test_overlap_requires_four_host_cpu_headroom_default_still_two(self):
        import types,psutil
        def docker(argv,**kwargs):return types.SimpleNamespace(returncode=0,stdout='{"NCPU":4}' if argv[0]=='info' else '')
        with patch.object(cli,'docker',docker),patch.object(psutil,'cpu_percent',return_value=10),patch.object(psutil,'Process',return_value=types.SimpleNamespace(cpu_affinity=lambda:[0,1,2,3])):
            self.assertEqual(cli.fresh_fast_cpu_admission({})['host_headroom_required'],2)
            with self.assertRaisesRegex(ValueError,'CPU headroom'):cli.fresh_fast_cpu_admission({'side_scheduling':'transfer-overlap'})

    def test_explicit_mode_and_budget_default_preserved(self):
        from test_fast_cli import BASE
        for flags in (['--side-scheduling','transfer-overlap'],['--side-scheduling','transfer-overlap','--docker-mode','fast','--assembly-mode','adopt']):
            with self.assertRaises(ValueError):cli.validate_modes(cli.parser().parse_args(BASE+flags))
        args=cli.parser().parse_args(BASE+['--side-scheduling','transfer-overlap','--docker-mode','fast','--assembly-mode','adopt','--docker-transfer','stream'])
        cli.validate_modes(args)
        config={'side_scheduling':'transfer-overlap','docker_mode':'fast','fast_side_seconds':123}
        self.assertEqual(cli.stage_plan(config),['capture','cf','profiles','fast-pair','integrity'])
        self.assertEqual(cli.stage_seconds(config,args,'fast-pair'),336)
        self.assertEqual(cli.parser().parse_args(BASE).side_scheduling,'sequential')

    def test_pair_admission_does_not_query_memory(self):
        import types
        calls=[]
        def docker(argv,**kwargs):calls.append(argv);return types.SimpleNamespace(returncode=0,stdout='{"NCPU":4}' if argv[0]=='info' else '12.5%\n')
        with patch.object(cli,'docker',docker):self.assertFalse(pair.docker_admission({})['memory_controls'])
        self.assertEqual(len(calls),2)


class CancellationTests(unittest.TestCase):
    def test_nested_supervisor_cancels_under_outer_job(self):
        from onecdb2src.control.bounded_process import run
        app=str(Path(cli.__file__).parents[1])
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);marker=root/'nested-started'
            child='import time;from pathlib import Path;Path('+repr(str(marker))+').write_text("started");time.sleep(20)'
            source='''import sys,threading,time,json
from pathlib import Path
sys.path.insert(0,APP)
from onecdb2src.control.bounded_process import run
root=Path(ROOT);event=threading.Event()
def cancel():
    end=time.monotonic()+3
    while not Path(MARKER).exists() and time.monotonic()<end:time.sleep(.01)
    event.set()
t=threading.Thread(target=cancel);t.start()
job=run([sys.executable,'-B','-c',CHILD],root/'nested.out',root/'nested.err',root/'nested.json',4,10000,10000,rss_cap=None,cancel_event=event)
t.join();assert job['failure']=='CANCELLED' and job['job_handle_closed'] and job['surviving_pids']==[]
'''
            source='APP='+repr(app)+'\nROOT='+repr(str(root))+'\nMARKER='+repr(str(marker))+'\nCHILD='+repr(child)+'\n'+source
            outer=run([sys.executable,'-B','-c',source],root/'outer.out',root/'outer.err',root/'outer.json',6,100000,100000,rss_cap=None)
            cli.require_stage_closure(outer,'neutral-nested',True);self.assertEqual(outer['exit_code'],0)
            self.assertTrue(marker.exists());self.closure(json.loads((root/'nested.json').read_text('utf-8')))

    def launch(self,root,source,event):
        from onecdb2src.control.bounded_process import run
        return run([sys.executable,'-B','-c',source],root/'out',root/'err',root/'job.json',5,100000,100000,rss_cap=None,cancel_event=event)

    def closure(self,job):
        self.assertEqual(job['failure'],'CANCELLED');self.assertEqual(job['surviving_pids'],[])
        self.assertTrue(job['job_handle_closed']);self.assertEqual(job['cleanup_errors'],[])
        self.assertEqual(job['pipes_closed'],{'stdin':True,'stdout':True,'stderr':True})
        self.assertFalse(job['memory_controls']);self.assertIsNone(job['rss_limit_bytes'])

    def test_pre_cancel_never_launches_workload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);event=threading.Event();event.set();marker=root/'should-not-exist'
            job=self.launch(root,'from pathlib import Path;Path('+repr(str(marker))+').write_text("bad")',event)
            self.closure(job);self.assertFalse(marker.exists());self.assertFalse(job['go_sent'])

    def test_cancel_closes_workload_and_grandchild(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);event=threading.Event();marker=root/'started'
            source='import subprocess,sys,time;from pathlib import Path;p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(20)"]);Path('+repr(str(marker))+').write_text(str(p.pid));time.sleep(20)'
            def cancel():
                end=time.monotonic()+3
                while not marker.exists() and time.monotonic()<end:time.sleep(.01)
                event.set()
            thread=threading.Thread(target=cancel);thread.start()
            try:job=self.launch(root,source,event)
            finally:thread.join()
            self.assertTrue(marker.exists());self.closure(job);self.assertTrue(job['go_sent'])


class CleanupBarrierTests(unittest.TestCase):
    def closed(self):
        return dict(job_handle_closed=True,observation_status='OBSERVED',surviving_pids=[],cleanup_errors=[],
            io_errors=[],pipes_closed={'stdin':True,'stdout':True,'stderr':True},drains_joined=True,
            bootstrap_survived=False,target_streams_closed={'stdout':True,'stderr':True},failure='TIMEOUT',exit_code=124)

    def test_failed_but_closed_producer_allows_recovery(self):
        from onecdb2src.xml.fast_docker import require_pair_shutdown
        for failure in ('TIMEOUT','CANCELLED',None):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'_work/jobs').mkdir(parents=True);value=self.closed();value['failure']=failure
                save(root/'_work/jobs/fast-pair.json',value)
                self.assertEqual(require_pair_shutdown({'side_scheduling':'transfer-overlap'},root)['receipt'],fact(root/'_work/jobs/fast-pair.json'))

    def test_unknown_closure_refuses_before_any_docker_or_runtime_read(self):
        from onecdb2src.xml import fast_docker
        changes=({'job_handle_closed':False},{'surviving_pids':[123]},{'observation_status':'UNKNOWN'},
            {'cleanup_errors':['bad']},{'io_errors':['bad']},{'pipes_closed':{}},{'drains_joined':False},
            {'bootstrap_survived':True},{'target_streams_closed':{}},
            {'backend':'linux-posix','processgroups_closed':False})
        for change in changes:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'_work/jobs').mkdir(parents=True);value=self.closed();value.update(change)
                save(root/'_work/jobs/fast-pair.json',value)
                with patch.object(fast_docker,'load_helper_manifest') as load,patch.object(fast_docker.subprocess,'run') as docker:
                    with self.assertRaisesRegex(ValueError,'closure UNKNOWN'):
                        fast_docker.cleanup_fast_owned({'root':tmp,'side_scheduling':'transfer-overlap'})
                    load.assert_not_called();docker.assert_not_called()

    def test_missing_and_partial_receipt_refuse_when_pair_started(self):
        from onecdb2src.xml.fast_docker import cleanup_fast_owned
        for payload in (None,'{'):
            with self.subTest(payload=payload),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'_work/jobs').mkdir(parents=True)
                (root/'_work/jobs/fast-pair.stdout').write_text('')
                if payload is not None:(root/'_work/jobs/fast-pair.json').write_text(payload)
                with self.assertRaises((ValueError,json.JSONDecodeError)):
                    cleanup_fast_owned({'root':tmp,'side_scheduling':'transfer-overlap'})

    def test_no_pair_activity_and_sequential_are_unaffected(self):
        from onecdb2src.xml.fast_docker import cleanup_fast_owned,require_pair_shutdown
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(cleanup_fast_owned({'root':tmp,'side_scheduling':'transfer-overlap'})['confirmed'])
            (Path(tmp)/'_work/jobs').mkdir(parents=True);(Path(tmp)/'_work/jobs/fast-pair.json').write_text('{}')
            self.assertIsNone(require_pair_shutdown({'side_scheduling':'sequential'},Path(tmp)))

    def test_linux_closed_groups_allow_failed_export_recovery(self):
        from onecdb2src.xml.fast_docker import require_pair_shutdown
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'_work/jobs').mkdir(parents=True)
            value=self.closed();value.update(backend='linux-posix',processgroups_closed=True)
            for key in ('drains_joined','bootstrap_survived','target_streams_closed'):value.pop(key)
            save(root/'_work/jobs/fast-pair.json',value)
            self.assertIsNotNone(require_pair_shutdown({'side_scheduling':'transfer-overlap'},root))


if __name__=='__main__':unittest.main()
