"""Pinned Linux local engine; Docker is neither located nor invoked here."""
import datetime,hashlib,json,os,platform,tempfile,time
from pathlib import Path
from .. import profiles

RUNTIME_ROOT=Path(__file__).resolve().parents[2]/'runtime/local'
IMAGE='sha256:40e04a9a6ef3d30217c30ead631e2cdd3c53fe4767ef7ae070d046df3ef72b83'
EXPECTED={
 'ibcmd-rs':(65435328,'e4823a015f093e3e805da57f874793cf767d35675314baf58a13424f3f67a0df'),
 'ld-linux-x86-64.so.2':(215000,'02bcda52c1a5dfc236f94d9e5255b4a0e26347d8a372a5223b650e31f291ce3c'),
 'lib/libc.so.6':(1926232,'6b4a45352fd0c540a9c7c718f35ce8c8e46a4e482f9d3885a910c32d1a0e1421'),
 'lib/libgcc_s.so.1':(125312,'2bd1552c47799ef67e701e81d4383061fd76059868e446e63560f0dd0d5ec14e'),
 'licenses/GPL-3.txt':(35149,'3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986'),
 'licenses/ibcmd-rs-MIT.txt':(1099,'866a167ccd074fe0b81754c777f0587d7fb3fd27c605fb06c1f50a50dd061b92'),
 'licenses/LGPL-2.1.txt':(26530,'dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551'),
}

def require(ok,message):
    if not ok:raise ValueError(message)

def fact(path):
    path=Path(path)
    require(path.is_file() and not path.is_symlink(),'Expected regular local runtime/input file')
    with path.open('rb') as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'bytes':path.stat().st_size,'sha256':sha}

def save(path,value):Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def environment(workers):return {'PATH':str(RUNTIME_ROOT),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','RAYON_NUM_THREADS':str(workers)}
def prefix():return [str(RUNTIME_ROOT/'ld-linux-x86-64.so.2'),'--library-path',str(RUNTIME_ROOT/'lib'),str(RUNTIME_ROOT/'ibcmd-rs')]

def engine_command(source,tree,platform_profile):
    require(platform_profile in ('8.3.27','8.5.1'),'Unsupported local engine platform')
    return prefix()+['cf','export',str(Path(source).resolve()),str(Path(tree).resolve()/'xml'),
                     '--platform',platform_profile,'--compression','raw-deflate','--fail-on-opaque']

def closed(job):
    return (job.get('backend')=='linux-posix' and job.get('processgroups_closed') is True
            and job.get('surviving_pids')==[] and job.get('cleanup_errors')==[]
            and job.get('observation_status')=='OBSERVED')

class LocalPreflightError(ValueError):
    def __init__(self,message,job):super().__init__(message);self.job=job

class LocalPreflightCancelled(KeyboardInterrupt):
    def __init__(self,job):super().__init__('Local version check cancelled');self.job=job

def preflight(config=None,*,verify_version=True):
    config=config or {};ticks=time.monotonic()
    require(platform.system()=='Linux' and platform.machine().lower() in ('x86_64','amd64'),'Native runtime requires Linux x86-64')
    manifest_path=RUNTIME_ROOT/'manifest.json';manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    require(manifest['schema']==1 and manifest['image_id']==IMAGE and set(manifest['files'])==set(EXPECTED),'Local runtime manifest differs from pinned closure')
    files={}
    for relative,(size,sha) in EXPECTED.items():
        files[relative]=fact(RUNTIME_ROOT/relative)
        require(files[relative]=={'bytes':size,'sha256':sha},'Pinned local runtime hash mismatch: '+relative)
        require(all(manifest['files'][relative][key]==files[relative][key] for key in ('bytes','sha256')),'Local manifest/file mismatch')
    require(manifest['binary']=='ibcmd-rs' and manifest['loader']=='ld-linux-x86-64.so.2' and manifest['library_path']=='lib','Local runtime layout mismatch')
    require(manifest['version_stdout']=='ibcmd-rs 0.4.1\n','Pinned local version contract changed')
    require(os.access(RUNTIME_ROOT/'ld-linux-x86-64.so.2',os.X_OK),'Bundled loader is not executable; restore supplied executable modes')
    result={'runtime_backend':'native','files':files,'manifest':fact(manifest_path),'image_provenance':IMAGE,
            'execution':'bundled glibc loader with explicit bundled library path','host_libc':platform.libc_ver(),
            'version_verified':False,'memory_scope':'POSIX supervisor per-process address-space limit and sampled process-tree RSS; no hard cgroup claim'}
    if verify_version:
        from ..control.bounded_process import run
        parent=Path(config['root']) if config.get('root') else None
        directory=Path(tempfile.mkdtemp(prefix='native-version-',dir=parent))
        job=run(prefix()+['--version'],directory/'stdout',directory/'stderr',directory/'process.json',15,65536,65536,
                rss_cap=max(512,int(config.get('native_memory_mib',512)))*1024**2,env=environment(1))
        result['version_supervision']={'directory':str(directory),'job':job,'receipt':fact(directory/'process.json')}
        if job.get('cancelled') is True or job.get('failure')=='CANCELLED':raise LocalPreflightCancelled(job)
        if not closed(job) or job.get('failure') is not None or job.get('exit_code')!=0:
            raise LocalPreflightError('Local engine version process failed or cleanup unconfirmed',job)
        if (directory/'stdout').read_text(encoding='utf-8')!=manifest['version_stdout'] or (directory/'stderr').read_bytes():
            raise LocalPreflightError('Local engine version output mismatch',job)
        result['version_verified']=True
    result['seconds']=time.monotonic()-ticks
    return result

def read_report(stdout,stderr):
    reports=[]
    for path in (stdout,stderr):
        try:value=json.loads(path.read_text(encoding='utf-8-sig'))
        except (ValueError,OSError):continue
        if isinstance(value,dict) and 'ok' in value:reports.append(value)
    require(len(reports)==1 and reports[0].get('command')=='export','Expected one complete engine export JSON receipt')
    return reports[0]

def export(args):
    from ..control.bounded_process import run
    source=Path(args.cf).resolve(strict=True);destination=Path(args.output).resolve()
    require(not destination.exists() and source not in destination.parents,'Native output must be new and separate')
    require(args.timeout>0 and args.memory_mib>=512 and 1<=args.workers<=8,'Invalid local engine budget')
    before=fact(source);profile_path=getattr(args,'profile_receipt',None)
    profile=profiles.load(profile_path,source) if profile_path else profiles.select(source,getattr(args,'platform','auto'))
    require(getattr(args,'platform','auto') in ('auto',profile['platform_profile']),'Native platform contradicts immutable profile')
    destination.mkdir(parents=True);tree=destination/'tree';tree.mkdir()
    if not profile_path:profile_path=destination/'profile.json';profiles.save_new(profile_path,profile)
    profile_path=Path(profile_path).resolve(strict=True)
    receipt={'schema_version':1,'runtime_backend':'native','status':'RUNNING','provider':args.provider,'side':args.side,
             'started_utc':utc(),'source':{'path':str(source),**before},'native_xml':str(tree/'xml'),
             'profile':profile,'profile_receipt':{'path':str(profile_path),'sha256':fact(profile_path)['sha256']},
             'engine':{'binary':str(RUNTIME_ROOT/'ibcmd-rs'),'binary_sha256':EXPECTED['ibcmd-rs'][1],
                       **{key:profile[key] for key in ('platform_profile','xml_version','profile_id')}},
             'producer_sha256':fact(__file__)['sha256'],'memory_oom_status':'NOT_OBSERVED','verification':'NOT_RUN'}
    job=None;engine_attempted=False
    save(destination/'receipt.json',receipt)
    try:
        receipt['preflight']=preflight({'root':str(destination),'native_memory_mib':args.memory_mib})
        command=engine_command(source,tree,profile['platform_profile']);receipt['engine_argv']=command
        save(destination/'receipt.json',receipt)
        engine_attempted=True
        receipt['engine_attempted']=True
        save(destination/'receipt.json',receipt)
        job=run(command,destination/'engine.stdout.json',destination/'engine.stderr.json',destination/'process-receipt.json',
                args.timeout,64*1024**2,256*1024**2,rss_cap=args.memory_mib*1024**2,env=environment(args.workers))
        receipt['process']={'exit_code':job.get('exit_code'),'job':job,
                            'supervision_receipt':{'path':str(destination/'process-receipt.json'),**fact(destination/'process-receipt.json')}}
        receipt['elapsed_seconds']=job['seconds'];receipt['source']['sha256_after']=fact(source)['sha256']
        require(receipt['source']['sha256_after']==before['sha256'],'CF changed during local export')
        if job.get('cancelled') is True or job.get('failure')=='CANCELLED' or (job.get('failure') or '').startswith('KeyboardInterrupt'):raise KeyboardInterrupt
        require(closed(job) and job.get('failure') is None,'Local engine supervision failed or cleanup unconfirmed')
        report=read_report(destination/'engine.stdout.json',destination/'engine.stderr.json')
        require(report.get('source_version')==profile['xml_version'] and report.get('export',{}).get('source_version')==profile['xml_version'],'Local engine XML profile mismatch')
        storage=report['export']['storage']
        receipt['summary']={'engine_ok':report['ok'],'files_written':report['export']['files_written'],
                            'storage':{k:storage.get(k) for k in ('physical_entries','logical_entries','supported','opaque','failed')},'errors':report.get('errors',[])}
        require(profiles.load(profile_path,source)==profile and fact(profile_path)['sha256']==receipt['profile_receipt']['sha256'],'Immutable local profile changed')
        require(job['exit_code']==0 and report['ok'] is True and storage['opaque']==storage['failed']==0,
                'Engine refused full export; raw report and partial native tree retained')
        require((tree/'xml').is_dir(),'Local native XML tree absent')
        receipt['status']='ENGINE_EXPORT_OK_VERIFICATION_PENDING'
    except BaseException as error:
        receipt['status']='CANCELLED' if isinstance(error,KeyboardInterrupt) else 'FAILED'
        receipt['error']=type(error).__name__+': '+str(error)
        if isinstance(error,(LocalPreflightError,LocalPreflightCancelled)):receipt['preflight_failed_job']=error.job
        raise
    finally:
        observed=job if engine_attempted else receipt.get('preflight_failed_job') or receipt.get('preflight',{}).get('version_supervision',{}).get('job')
        receipt['cleanup']={'confirmed':closed(observed) if observed is not None else False,
                            'processgroups_closed':observed.get('processgroups_closed') if observed is not None else None,
                            'surviving_pids':observed.get('surviving_pids') if observed is not None else None,
                            'engine_attempted':engine_attempted,'engine_process_started':True if job is not None else None if engine_attempted else False}
        receipt['finished_utc']=utc();save(destination/'receipt.json',receipt)
