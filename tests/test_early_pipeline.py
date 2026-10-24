"""Synthetic Docker metadata + real neutral XML; no daemon/CF project inputs."""
import copy,sys,tempfile,threading,time,unittest
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'app'),str(Path(__file__).resolve().parent)]
import test_fast_docker as protocol
import test_fast_stream as stream_protocol
from test_fast_cli import good_job,BASE
from onecdb2src import cli,fast_pair
from onecdb2src.xml import namespace_result as ns,_fast_contract as fc
from onecdb2src.util import save


class EarlyLineageTests(unittest.TestCase):
    def run_case(self):
        fake,cfg,root,error=stream_protocol.FastStreamTests.run_case(self)
        return fake,cfg,error,root
    def fixture(self):
        fake,cfg,error,root=self.run_case();self.assertIsNone(error)
        cfg.update(side_scheduling='verify-overlap',memory_controls=False)
        (root/'_work/jobs').mkdir()
        def job(stage):
            value=good_job();value['argv']=[sys.executable,'-B',str(cli.PACKAGE/'export_1c.py'),'--_worker',stage,str(root/'_work/config.json')]
            save(root/'_work/jobs'/(stage+'.json'),value);return value
        main=job('fast-main');result=ns.verify_fast_side(cfg,'main',workers=4,early=True)
        early=job('preverify-main');directory=root/'_work/fast-main'
        pair={'status':fast_pair.PAIR_STATUS,'side_scheduling':'verify-overlap',
              'sides':{'main':{'job':main,'candidate':fc.fact(directory/'result.json')}},
              'early_main':{'job':early,'candidate':fc.fact(directory/'early-verification.json')}}
        (root/'_work/fast-pair').mkdir();save(root/'_work/fast-pair/result.json',pair)
        return cfg,root,result

    def test_closed_full_early_then_fresh_final_hashes_and_both_receipts(self):
        cfg,root,early=self.fixture();directory=root/'_work/fast-main'
        before=fc.fact(directory/'early-file-verification.json')
        final=ns.verify_fast_side(cfg,'main',workers=4)
        self.assertEqual(final['readback_phase'],'FINAL_FRESH_HASH_AFTER_EARLY_XML')
        self.assertEqual((final['xml_files'],final['bsl_files']),(4,2))
        self.assertEqual(fc.read(directory/'file-verification.json')['facts'],fc.read(directory/'early-file-verification.json')['facts'])
        self.assertEqual(fc.fact(directory/'early-file-verification.json'),before)
        self.assertEqual(early['readback_phase'],'EARLY_FULL_XML_VALIDATION')

    def test_actual_payload_change_after_early_is_rejected(self):
        cfg,root,_=self.fixture();(root/'main/xml/Module.bsl').write_text('// changed after early')
        with self.assertRaises(ValueError):ns.verify_fast_side(cfg,'main')
        self.assertFalse((root/'_work/fast-main/verification.json').exists())

    def test_early_phase_namespace_counts_and_lineage_tampering_reject(self):
        changes=(lambda x:x.update(readback_phase='FINAL'),lambda x:x.update(lineage_snapshot={}),
                 lambda x:x.update(files_proof={'bytes':0,'sha256':'0'*64}),lambda x:x.update(xml_files=999),
                 lambda x:x.update(profile={}),lambda x:x.update(native_policy={}))
        for change in changes:
            with self.subTest(change=change):
                cfg,root,_=self.fixture();path=root/'_work/fast-main/early-verification.json';value=fc.read(path);change(value);save(path,value)
                pair_path=root/'_work/fast-pair/result.json';pair=fc.read(pair_path);pair['early_main']['candidate']=fc.fact(path);save(pair_path,pair)
                with self.assertRaises(ValueError):ns.verify_fast_side(cfg,'main')
                self.assertFalse((root/'_work/fast-main/verification.json').exists())

    def test_unclosed_wrong_invocation_and_failed_early_job_reject(self):
        for change in ({'failure':'TIMEOUT'},{'job_handle_closed':False},{'surviving_pids':[123]},
                       {'exit_code':1},{'argv':['python','--_worker','wrong','elsewhere']}):
            with self.subTest(change=change):
                cfg,root,_=self.fixture();path=root/'_work/jobs/preverify-main.json';value=fc.read(path);value.update(change);save(path,value)
                with self.assertRaises(ValueError):ns.verify_fast_side(cfg,'main')

    def test_running_pair_or_stale_candidate_binding_reject(self):
        for change in ('running','candidate','mode'):
            with self.subTest(change=change):
                cfg,root,_=self.fixture();path=root/'_work/fast-pair/result.json';pair=fc.read(path)
                if change=='running':pair['status']='RUNNING'
                elif change=='candidate':pair['sides']['main']['candidate']['sha256']='0'*64
                else:pair['side_scheduling']='transfer-overlap'
                save(path,pair)
                with self.assertRaises(ValueError):ns.verify_fast_side(cfg,'main')

    def test_closed_stage_uses_platform_path_case_rules(self):
        from onecdb2src.xml.early_lineage import closed_stage
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();(root/'_work/jobs').mkdir(parents=True)
            job=good_job();job['argv']=['python','--_worker','fast-main',str(root/'_work/config.json').swapcase()]
            save(root/'_work/jobs/fast-main.json',job)
            if os.name=='nt':self.assertEqual(closed_stage({'root':str(root)},'fast-main')[0],job)
            else:
                with self.assertRaises(ValueError):closed_stage({'root':str(root)},'fast-main')

    def test_main_producer_must_be_closed_before_early(self):
        fake,cfg,error,root=self.run_case();self.assertIsNone(error);cfg['side_scheduling']='verify-overlap'
        with self.assertRaises((ValueError,FileNotFoundError)):ns.verify_fast_side(cfg,'main',early=True)
        self.assertFalse((root/'_work/fast-main/early-verification.json').exists())


class EarlyCoordinateTests(unittest.TestCase):
    def test_early_starts_after_main_closed_while_vendor_running(self):
        ready=threading.Event();vendor=threading.Event();main_closed=threading.Event();verifying=threading.Event();vendor_closed=threading.Event()
        def produce(side,stop):
            if side=='main':ready.set();self.assertTrue(vendor.wait(1));main_closed.set()
            else:vendor.set();self.assertTrue(verifying.wait(1));vendor_closed.set()
            return side
        def verify(side,stop):self.assertTrue(main_closed.is_set());self.assertFalse(vendor_closed.is_set());verifying.set();return 'verified'
        result=fast_pair.coordinate(produce,lambda:{} if ready.is_set() else None,lambda:None,time.monotonic()+2,verify_main=verify)
        self.assertEqual(set(result),{'main','vendor','preverify-main'})

    def test_early_failure_cancels_and_joins_vendor(self):
        ready=threading.Event();closed=threading.Event()
        def produce(side,stop):
            if side=='main':ready.set();return
            stop.wait(1);closed.set()
        def verify(side,stop):raise ValueError('neutral early failure')
        with self.assertRaisesRegex(ValueError,'preverify-main'):
            fast_pair.coordinate(produce,lambda:{} if ready.is_set() else None,lambda:None,time.monotonic()+2,verify_main=verify)
        self.assertTrue(closed.is_set())

    def test_vendor_failure_cancels_and_joins_early(self):
        ready=threading.Event();verifying=threading.Event();closed=threading.Event()
        def produce(side,stop):
            if side=='main':ready.set();return
            self.assertTrue(verifying.wait(1));raise ValueError('neutral vendor failure')
        def verify(side,stop):verifying.set();stop.wait(1);closed.set()
        with self.assertRaisesRegex(ValueError,'vendor'):
            fast_pair.coordinate(produce,lambda:{} if ready.is_set() else None,lambda:None,time.monotonic()+2,verify_main=verify)
        self.assertTrue(closed.is_set())

    def test_deadline_during_early_joins_all(self):
        ready=threading.Event();closed=threading.Event()
        def produce(side,stop):
            if side=='main':ready.set();return
            stop.wait(1)
        def verify(side,stop):stop.wait(1);closed.set()
        with self.assertRaisesRegex(ValueError,'deadline'):
            fast_pair.coordinate(produce,lambda:{} if ready.is_set() else None,lambda:None,time.monotonic()+.08,verify_main=verify)
        self.assertTrue(closed.is_set())

    def test_new_mode_preserves_defaults_and_has_explicit_budget(self):
        args=cli.parser().parse_args(BASE+['--docker-mode','fast','--assembly-mode','adopt','--docker-transfer','stream','--side-scheduling','verify-overlap'])
        cli.validate_modes(args);cfg=dict(side_scheduling='verify-overlap',docker_mode='fast',fast_side_seconds=123,python_seconds=20)
        self.assertEqual(cli.stage_plan(cfg),['capture','cf','profiles','fast-pair','integrity'])
        self.assertEqual(cli.stage_seconds(cfg,args,'fast-pair'),401)
        self.assertEqual(cli.parser().parse_args(BASE).side_scheduling,'sequential')


if __name__=='__main__':unittest.main()
