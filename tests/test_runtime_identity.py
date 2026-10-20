import copy,hashlib,io,json,sys,tarfile,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from onecdb2src import cli
from onecdb2src.util import fact
from onecdb2src.xml import export_native as docker
from onecdb2src.xml.runtime_identity import identities

def fixture(base,corrupt_blob=False):
    blobs={}
    def blob(value):
        raw=json.dumps(value).encode();digest='sha256:'+hashlib.sha256(raw).hexdigest();blobs[digest[7:]]=raw
        return {'digest':digest,'size':len(raw)}
    config=blob({'architecture':'amd64','os':'linux','rootfs':{'diff_ids':['sha256:'+'1'*64]}})
    image=blob({'config':config})
    row=dict(image,platform={'architecture':'amd64','os':'linux'})
    root=blob({'manifests':[row]})
    index={'schemaVersion':2,'manifests':[root]}
    archive=base/'runtime/runtime-image.tar';archive.parent.mkdir()
    with tarfile.open(archive,'w') as tar:
        for name,raw in [('index.json',json.dumps(index).encode()),*[(f'blobs/sha256/{name}',raw) for name,raw in blobs.items()]]:
            if corrupt_blob and name.endswith(config['digest'][7:]):raw=raw.replace(b'amd64',b'amd65')
            member=tarfile.TarInfo(name);member.size=len(raw);tar.addfile(member,io.BytesIO(raw))
    return archive,{'image_id':root['digest'],'archive':fact(archive)},config['digest']

class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name)
        self.archive,self.runtime,self.config_id=fixture(self.base)
    def tearDown(self):self.temp.cleanup()
    def test_root_and_classic_ids_bound(self):
        result=identities(self.archive,self.runtime)
        self.assertEqual(result['allowed_image_ids'],[self.runtime['image_id'],self.config_id])
    def test_archive_hash_mismatch_refused(self):
        runtime=copy.deepcopy(self.runtime);runtime['archive']['sha256']='0'*64
        with self.assertRaises(ValueError):identities(self.archive,runtime)
    def test_pinned_root_mismatch_refused(self):
        runtime=copy.deepcopy(self.runtime);runtime['image_id']='sha256:'+'0'*64
        with self.assertRaises(ValueError):identities(self.archive,runtime)
    def test_identity_blob_digest_mismatch_refused(self):
        other=self.base/'other';other.mkdir();archive,runtime,_=fixture(other,True)
        with self.assertRaises(ValueError):identities(archive,runtime)
    def preflight(self,available,wrong_layers=False):
        runtime=copy.deepcopy(self.runtime)
        info={'OSType':'linux','Name':'docker-desktop','Architecture':'x86_64','MemTotal':32*1024**3,'MemoryLimit':True,'SwapLimit':True,'CpuCfsQuota':True,'PidsLimit':True}
        def call(args,timeout=60):
            if args[:2]==['image','inspect']:
                image=args[2];exists=image in available
                value=[{'Id':image,'Config':{},'RootFS':{'Layers':['sha256:'+('2' if wrong_layers else '1')*64]}}]
                return types.SimpleNamespace(returncode=0 if exists else 1,stdout=json.dumps(value),stderr='')
            if args[0]=='info':return types.SimpleNamespace(returncode=0,stdout=json.dumps(info))
            raise AssertionError('Unexpected Docker operation '+str(args))
        context={'Endpoints':{'docker':{'Host':'npipe:////./pipe/dockerDesktopLinuxEngine'}}}
        config={'runtime_backend':'docker','runtime':runtime,'root':str(self.base),'native_memory_mib':3072}
        with patch.object(cli,'PACKAGE',self.base),patch.object(cli,'docker',call),patch.object(docker,'context_record',return_value=context),patch.object(docker,'endpoint_policy'),patch.object(docker,'verify_bind_visibility',return_value={'status':'SYNTHETIC_BIND'}),patch('psutil.virtual_memory',return_value=types.SimpleNamespace(available=16*1024**3)),patch.object(cli.shutil,'disk_usage',return_value=types.SimpleNamespace(free=4*1024**3)):
            result=cli.preflight(config)
        return config,result
    def test_desktop_root_id_selected_first(self):
        config,_=self.preflight([self.runtime['image_id'],self.config_id]);self.assertEqual(config['runtime']['image_id'],self.runtime['image_id'])
    def test_classic_config_id_selected(self):
        config,result=self.preflight([self.config_id]);self.assertEqual(config['runtime']['image_id'],self.config_id)
        self.assertEqual(result['oci_identity']['provenance_image_id'],self.runtime['image_id'])
    def test_rootfs_diffid_mismatch_refused(self):
        with self.assertRaises(ValueError):self.preflight([self.config_id],True)
    def test_linux_remote_endpoints_refused(self):
        for host in ('ssh://server','tcp://127.0.0.1:2375','npipe:////./pipe/dockerDesktopLinuxEngine'):
            with self.subTest(host=host),patch.object(docker,'os',types.SimpleNamespace(name='posix')),patch.object(docker,'sys',types.SimpleNamespace(platform='linux')):
                with self.assertRaises(ValueError):docker.endpoint_policy({'Endpoints':{'docker':{'Host':host}}})

if __name__=='__main__':unittest.main(verbosity=2)
