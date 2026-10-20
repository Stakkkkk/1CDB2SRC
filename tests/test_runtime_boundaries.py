"""Closed process/opaque contracts using generated neutral records; no engine/DB."""
import copy,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from onecdb2src import native_policy,cli

class RuntimeBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        profile={'profile_id':'synthetic','platform_profile':'8.5.1','xml_version':'2.21'}
        cls.receipt={'status':'FAILED','runtime_backend':'docker','profile':profile,
            'engine':profile.copy(),'container_removed':True,
            'process':{'docker_start_exit':2,'container_state':{'ExitCode':2,'Running':False,'OOMKilled':False,'Error':''}}}
        cls.sizes={'root':3,'version':2,'versions':1,'neutral':4}
        entries=[{'logical_name':name,'disposition':'opaque' if name!='neutral' else 'supported','packed_bytes':size,'part_count':1} for name,size in cls.sizes.items()]
        cls.report={'command':'export','source_version':'2.21','ok':False,
            'export':{'source_version':'2.21','storage':{'entries':entries,'supported':1,'opaque':3,'failed':0,'logical_entries':4,'physical_entries':4}},
            'errors':[{'code':'opaque_export_refused','message':'--fail-on-opaque refused 3 opaque CF storage entries; see export.storage.entries for names and reasons; no index was published'}]}
    def local(self):
        receipt=copy.deepcopy(self.receipt)
        receipt.pop('container_removed',None)
        receipt.update(runtime_backend='native',memory_oom_status='NOT_OBSERVED',cleanup={'confirmed':True,'surviving_pids':[]})
        receipt['process']={'exit_code':2,'job':{'exit_code':2,'failure':None,'surviving_pids':[],'cleanup_errors':[],'observation_status':'OBSERVED','processgroups_closed':True}}
        return receipt
    def classify(self,receipt=None,report=None):
        receipt=receipt or self.local()
        return native_policy.classify(receipt,report or self.report,self.sizes,1,receipt['profile'])
    def test_saved_windows_contract_unchanged(self):self.assertEqual(self.classify(self.receipt)['status'],'NATIVE_OPAQUE_ONLY')
    def test_local_opaque_closed_contract(self):self.assertEqual(self.classify()['raw_exit'],2)
    def test_native_cannot_use_fake_container_fields(self):
        rec=self.local();rec['process']=copy.deepcopy(self.receipt['process'])
        with self.assertRaises(ValueError):self.classify(rec)
    def test_native_memory_evidence_cannot_claim_oom_false(self):
        rec=self.local();rec['memory_oom_status']=False
        with self.assertRaises(ValueError):self.classify(rec)
    def test_native_live_child_refused(self):
        rec=self.local();rec['process']['job']['surviving_pids']=[999]
        with self.assertRaises(ValueError):self.classify(rec)
    def test_native_unknown_observation_refused(self):
        rec=self.local();rec['process']['job']['observation_status']='UNKNOWN'
        with self.assertRaises(ValueError):self.classify(rec)
    def test_native_timeout_refused_even_with_exit2(self):
        rec=self.local();rec['process']['job']['failure']='TIMEOUT'
        with self.assertRaises(ValueError):self.classify(rec)
    def test_mixed_engine_errors_refused(self):
        report=copy.deepcopy(self.report);report['errors'].append({'code':'other','message':'other'})
        with self.assertRaises(ValueError):self.classify(report=report)
    def test_native_exit_receipt_conflict_refused(self):
        rec=self.local();rec['process']['exit_code']=0
        with self.assertRaises(ValueError):self.classify(rec)
    def test_default_cli_docker_preserved(self):
        args=cli.parser().parse_args(['--provider','postgresql','--host','localhost','--database','db','--user','reader','--supplier','x','--output','out'])
        self.assertEqual(args.runtime,'docker');self.assertIsNone(args.docker_context);self.assertIsNone(args.docker_socket)
    def test_native_default_memory_budget_does_not_inherit_smaller_python_hard_limit(self):
        config={'runtime_backend':'native','native_memory_mib':8192}
        self.assertEqual(cli.stage_memory_budget(config,'native-main'),8704*1024**2)
        self.assertEqual(cli.stage_memory_budget(config,'cf'),3*1024**3)
    def test_docker_and_windows_python_memory_budget_preserved(self):
        self.assertEqual(cli.stage_memory_budget({'runtime_backend':'docker','native_memory_mib':8192},'native-main'),3*1024**3)
    def test_context_and_socket_mutually_exclusive(self):
        with self.assertRaises(SystemExit):cli.parser().parse_args(['--provider','postgresql','--host','localhost','--database','db','--user','reader','--supplier','x','--output','out','--docker-context','default','--docker-socket','/tmp/docker.sock'])

if __name__=='__main__':unittest.main(verbosity=2)
