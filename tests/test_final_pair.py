"""Parallel final acceptance: lifetime, worker budgets and forged closure tests."""
import copy,sys,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'app'),str(Path(__file__).resolve().parent)]
from onecdb2src import cli,worker,final_pair as pair
from onecdb2src.util import read,save,fact
from test_fast_cli import BASE,good_job


class FinalPairTests(unittest.TestCase):
    def config(self,root):
        return dict(root=str(root),docker_mode='fast',runtime_backend='docker',assembly_mode='adopt',memory_controls=False,
                    final_verification='parallel',readback_workers=8,python_seconds=5)

    def test_policy_preserves_defaults_and_total_worker_budget(self):
        args=cli.parser().parse_args(BASE);cli.validate_modes(args);self.assertEqual(args.final_verification,'sequential')
        config=self.config(Path('.'))
        self.assertEqual([pair.side_workers(config,s) for s in ('main','vendor')],[2,6])
        self.assertEqual(sum(pair.side_workers(config,s) for s in ('main','vendor')),8)
        balanced={**config,'final_worker_split':'balanced'}
        self.assertEqual([pair.side_workers(balanced,s) for s in ('main','vendor')],[4,4])
        for changes in ({'readback_workers':4},{'final_worker_split':'unknown'}):
            with self.assertRaises(ValueError):pair.side_workers({**config,**changes},'main')
        with self.assertRaises(ValueError):pair.side_workers(config,'wrong')
        for changes in ({'memory_controls':True},{'docker_mode':'host'},{'runtime_backend':'native'},
                        {'assembly_mode':'copy'},{'readback_workers':1},{'readback_workers':True}):
            config=self.config(Path('.'));config.update(changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):pair.side_workers(config,'main')
        for flags in (['--final-verification','parallel'],['--docker-mode','fast','--assembly-mode','adopt','--final-verification','parallel','--readback-workers','1']):
            with self.assertRaises(ValueError):cli.validate_modes(cli.parser().parse_args(BASE+flags))

    def test_two_sides_really_overlap_and_join_before_return(self):
        entered={side:threading.Event() for side in ('main','vendor')};closed=[];events=[]
        def run(side,stop):
            entered[side].set();self.assertTrue(entered['vendor' if side=='main' else 'main'].wait(1));closed.append(side);return side
        result=pair.coordinate(run,time.monotonic()+2,events.append)
        self.assertEqual(result,dict(main='main',vendor='vendor'));self.assertCountEqual(closed,['main','vendor'])
        self.assertEqual(events[-1]['event'],'all-supervisors-joined')

    def test_failure_cancels_and_joins_other_side(self):
        for failing in ('main','vendor'):
            entered=threading.Barrier(2);closed=threading.Event()
            def run(side,stop):
                entered.wait(1)
                if side==failing:raise ValueError('neutral failure')
                self.assertTrue(stop.wait(1));closed.set()
            with self.subTest(side=failing),self.assertRaisesRegex(ValueError,failing):pair.coordinate(run,time.monotonic()+2)
            self.assertTrue(closed.is_set())

    def test_deadline_cancels_and_joins_both(self):
        closed=[]
        def run(side,stop):stop.wait(1);closed.append(side)
        with self.assertRaisesRegex(ValueError,'deadline'):pair.coordinate(run,time.monotonic()+.05)
        self.assertCountEqual(closed,['main','vendor'])

    def fixture(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name).resolve();cfg=self.config(root)
        (root/'_work/jobs').mkdir(parents=True);(root/'_work/final-pair').mkdir()
        result={}
        for side in ('main','vendor'):
            stage='integrity-'+side;job=good_job()
            job['argv']=['python','--_worker',stage,str(root/'_work/config.json')];save(root/'_work/jobs'/(stage+'.json'),job)
            verified=dict(status='PASS_FAST_SIDE_REQUIRES_COMMON_CF_FINALIZATION',side=side,cf={'sha256':side},profile={},workers=pair.side_workers(cfg,side))
            value=dict(status=pair.SIDE_STATUS,side=side,oracle_inputs=[],result=dict(cf=verified['cf'],profile={},fast_verification=verified),limitations=[{'side':side}])
            path=root/'_work/final-pair'/(side+'.json');save(path,value);result[side]=dict(job=job,candidate=fact(path))
        return cfg,root,result

    def test_collect_requires_two_closed_exact_side_receipts(self):
        cfg,root,completed=self.fixture();result,limits=pair.collect(cfg,completed)
        self.assertEqual(set(result),{'main','vendor'});self.assertEqual(len(limits),2)
        self.assertFalse((root/'_work/integrity.json').exists())

    def test_collect_refuses_missing_changed_wrong_side_and_worker_policy(self):
        for change in ('missing','bytes','side','workers','status','oracle','cf'):
            with self.subTest(change=change):
                cfg,root,completed=self.fixture();path=root/'_work/final-pair/main.json';value=read(path)
                if change=='missing':completed.pop('vendor')
                else:
                    if change=='bytes':value['limitations']=[]
                    elif change=='side':value['side']='vendor'
                    elif change=='workers':value['result']['fast_verification']['workers']=8
                    elif change=='status':value['status']='PASS'
                    elif change=='oracle':value['oracle_inputs']=['forbidden']
                    elif change=='cf':value['result']['cf']={}
                    save(path,value)
                    if change!='bytes':completed['main']['candidate']=fact(path)
                with self.assertRaises((ValueError,KeyError)):pair.collect(cfg,completed)

    def test_collect_refuses_failed_unclosed_or_wrong_job(self):
        for changes in ({'exit_code':1},{'failure':'TIMEOUT'},{'job_handle_closed':False},
                        {'surviving_pids':[999]},{'pipes_closed':{}},{'memory_controls':True},
                        {'argv':['python','--_worker','integrity-vendor','other']}):
            with self.subTest(changes=changes):
                cfg,root,completed=self.fixture();job=read(root/'_work/jobs/integrity-main.json');job.update(changes)
                save(root/'_work/jobs/integrity-main.json',job);completed['main']['job']=job
                with self.assertRaises(ValueError):pair.collect(cfg,completed)

    def test_common_success_only_after_pair_returns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'_work/cf').mkdir(parents=True);save(root/'_work/cf/manifest.json',{});cfg=self.config(root)
            def run(config):
                self.assertFalse((root/'_work/integrity.json').exists());return {'main':{},'vendor':{}},[]
            with patch.object(worker,'validate_fast_candidates'),patch.object(pair,'verify_pair',run):worker.integrity(cfg)
            self.assertEqual(set(read(root/'_work/integrity.json')['sides']),{'main','vendor'})

    def test_failure_never_publishes_common_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'_work/cf').mkdir(parents=True);save(root/'_work/cf/manifest.json',{});cfg=self.config(root)
            with patch.object(worker,'validate_fast_candidates'),patch.object(pair,'verify_pair',side_effect=ValueError('neutral')):
                with self.assertRaises(ValueError):worker.integrity(cfg)
            self.assertFalse((root/'_work/integrity.json').exists())

    def test_existing_sequential_order_and_full_worker_budget_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'_work/cf').mkdir(parents=True);save(root/'_work/cf/manifest.json',{});calls=[];cfg=self.config(root);cfg.pop('final_verification')
            def side(config,name,workers=None,*,manifest=None):calls.append((name,workers));return {},[]
            with patch.object(worker,'validate_fast_candidates'),patch.object(worker,'integrity_side',side):worker.integrity(cfg)
            self.assertEqual(calls,[('main',None),('vendor',None)])

    def test_common_manifest_change_rejects_sequential_and_parallel_without_success(self):
        for mode in ('sequential','parallel'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'_work/cf').mkdir(parents=True);path=root/'_work/cf/manifest.json';save(path,{})
                cfg=self.config(root);cfg['final_verification']=mode
                def side(config,name,workers=None,*,manifest=None):
                    self.assertEqual(manifest,{});save(path,{'changed':True});return {},[]
                def together(config):save(path,{'changed':True});return {'main':{},'vendor':{}},[]
                with patch.object(worker,'validate_fast_candidates'),patch.object(worker,'integrity_side',side),patch.object(pair,'verify_pair',together):
                    with self.assertRaisesRegex(ValueError,'Common CF manifest'):worker.integrity(cfg)
                self.assertFalse((root/'_work/integrity.json').exists())

    def test_actual_bounded_children_cancel_and_close_without_memory_caps(self):
        from onecdb2src.control.bounded_process import run
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);ready=threading.Barrier(2);jobs={}
            def child(side,stop):
                ready.wait(2)
                job=run([sys.executable,'-B','-c','import time;time.sleep(30)'],root/(side+'.out'),root/(side+'.err'),root/(side+'.job.json'),5,65536,65536,rss_cap=None,cancel_event=stop)
                jobs[side]=job
            with self.assertRaisesRegex(ValueError,'deadline'):pair.coordinate(child,time.monotonic()+.4)
            self.assertEqual(set(jobs),{'main','vendor'})
            for job in jobs.values():
                self.assertEqual(job['failure'],'CANCELLED');self.assertTrue(job['job_handle_closed'])
                self.assertEqual(job['surviving_pids'],[]);self.assertFalse(job['memory_controls'])
                self.assertEqual(job['cleanup_errors'],[]);self.assertEqual(job['io_errors'],[])


if __name__=='__main__':unittest.main()
