"""Seal one accepted local helper image into an offline candidate APP bundle.

No image build, pull, run, load, remote Docker endpoint, container creation or
image deletion. Docker save is a read-only operation on the exact accepted ID.
The sealed archive requires subsequent product actual acceptance by the caller.
"""
import argparse,datetime,gzip,hashlib,importlib,json,math,os,re,subprocess,sys,time
from pathlib import Path,PurePosixPath
import stat

SCHEMA='1CDB2SRC_FAST_HELPER_V1'
ENTRYPOINT=['python','-I','-S','-B','/opt/app/onecdb2src/xml/linux_helpers.py']

def require(ok,message):
    if not ok:raise ValueError('Helper seal: '+message)

def regular(path,directory=False):
    info=Path(path).lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'linked/reparse file')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),'wrong file kind')
    require(directory or info.st_nlink==1,'hardlinked file')
    return info

def token(info):return info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns

def safe(value):
    require(type(value) is str and value and not any(c in value for c in ('\\',':','\0','\r','\n')),'unsafe path')
    p=PurePosixPath(value)
    require(p.parts and not p.is_absolute() and '..' not in p.parts and p.as_posix()==value,'noncanonical path')
    return p

def child(root,name):
    path=root.joinpath(*safe(name).parts)
    for parent in reversed(path.parents):
        if parent==root or root in parent.parents:regular(parent,True)
    regular(path);return path

def fact(path,check=lambda:None):
    before=regular(path);digest=hashlib.sha256();count=0
    with Path(path).open('rb') as stream:
        opened=os.fstat(stream.fileno());require(token(opened)==token(before),'file changed before open')
        for block in iter(lambda:stream.read(1024*1024),b''):
            digest.update(block);count+=len(block);check()
        after=os.fstat(stream.fileno())
        require(token(after)==token(opened) and after.st_ctime_ns==opened.st_ctime_ns,'open file changed')
    require(token(regular(path))==token(before) and count==before.st_size,'file changed after read')
    return {'bytes':count,'sha256':digest.hexdigest()}

def read(path):
    def unique(pairs):
        obj={}
        for key,value in pairs:
            require(key not in obj,'duplicate JSON key');obj[key]=value
        return obj
    regular(path);return json.loads(Path(path).read_text(encoding='utf-8-sig'),object_pairs_hook=unique)

def save_new(path,value):
    with Path(path).open('x',encoding='utf-8') as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2);stream.write('\n')

def inventory(root,start,predicate):
    directory=root/start;regular(directory,True);names=set()
    def fail(error):raise error
    for base,dirs,files in os.walk(directory,followlinks=False,onerror=fail):
        regular(base,True)
        for name in dirs:regular(Path(base)/name,True)
        for name in files:
            key=(Path(base)/name).relative_to(root).as_posix()
            if predicate(key):child(root,key);names.add(key)
    require(len({name.casefold() for name in names})==len(names),'case-colliding closure')
    return names

def validate_context(app,context,check):
    sources=context['source_files'];runtimes=context['runtime_files']
    require(type(sources) is dict and sources and type(runtimes) is dict and runtimes,'empty source/runtime closure')
    actual_sources=inventory(app,'onecdb2src',lambda p:p.endswith('.py') or p=='onecdb2src/xml/data/assets.rs')
    actual_runtime=inventory(app,'runtime/local',lambda p:True)
    require(set(sources)==actual_sources and set(runtimes)==actual_runtime,'candidate source/runtime pathset differs')
    require({'onecdb2src/xml/linux_helpers.py','onecdb2src/xml/fast_runtime.py',
             'onecdb2src/xml/data/assets.rs'}<=set(sources),'required helper source missing')
    expected={**sources,**runtimes};observed={}
    for name,row in expected.items():
        require(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and row['bytes']>=0
                and re.fullmatch('[a-f0-9]{64}',row['sha256']),'invalid sealed file fact')
        observed[name]=fact(child(app,name),check);require(observed[name]==row,'candidate source/runtime pin changed: '+name)
    rows=context['files']
    require(type(rows) is list and len(rows)==len(expected),'context payload count differs')
    mapped={}
    for row in rows:
        name=str(safe(row['context_path']));require(name.startswith('app/'),'unexpected context payload namespace')
        key=name[4:];require(key in expected and key not in mapped,'extra/duplicate context payload')
        mapped[key]={key2:row[key2] for key2 in ('bytes','sha256')}
    require(mapped==expected,'context rows and closure maps differ')
    return observed

def load_tools(app):
    sys.path.insert(0,str(app))
    native=importlib.import_module('onecdb2src.xml.export_native')
    runtime=importlib.import_module('onecdb2src.xml.fast_runtime')
    for module in (native,runtime):
        require(Path(module.__file__).resolve().is_relative_to(app),'helper tool imported from another installation')
    return native,runtime

def _execution(value):
    require(value.get('User')=='65532:65532' and value.get('Entrypoint')==ENTRYPOINT
            and value.get('Cmd') in (None,[]) and not value.get('Volumes') and not value.get('OnBuild'),
            'image execution config differs')
    env=value.get('Env')
    require(type(env) is list and all(type(item) is str and '=' in item for item in env),'invalid image environment')
    keys=[item.split('=',1)[0] for item in env]
    require(len(keys)==len(set(keys)) and not any(key.upper().startswith('IBC') for key in keys),'duplicate/IBC image environment')
    values=dict(item.split('=',1) for item in env)
    require(values.get('PYTHONDONTWRITEBYTECODE')=='1' and values.get('PYTHONUTF8')=='1','helper deterministic environment missing')

def seal_helper(app,assembly_path,assembly_sha256,context_path,context_sha256,*,output=None,
                seconds=300,compression='gzip',max_archive_bytes=100_000_000,context_name=None,socket=None,
                base_source='python:3.13-slim-bookworm',_tools=None,_runner=subprocess.run):
    started=time.monotonic()
    require(type(seconds) in (int,float) and math.isfinite(seconds) and seconds>0,'positive seal deadline required')
    deadline=started+seconds
    def check():require(time.monotonic()<deadline,'seal deadline expired')
    app=Path(app).absolute();regular(app,True);app=app.resolve(strict=True)
    assembly_path=Path(assembly_path).resolve(strict=True);context_path=Path(context_path).resolve(strict=True)
    assembly_fact=fact(assembly_path,check);context_fact=fact(context_path,check)
    require(assembly_fact['sha256']==assembly_sha256 and context_fact['sha256']==context_sha256,'authorised input receipt pin differs')
    assembly=read(assembly_path);context=read(context_path)
    require(context['status']=='PREPARED_FROZEN_CONTEXT_ONLY' and context['entrypoint']==ENTRYPOINT,'unsupported AI context')
    require(assembly['status']=='ASSEMBLED_STOPPED_CONTAINER_IMAGE_SMALL_EXECUTION_NOT_RUN'
            and assembly['context_manifest']==context_fact and assembly['base_image']==context['base_image']
            and assembly['prep_container_absent_confirmed'] is True and not assembly.get('cleanup_error')
            and assembly['assembly_only'] is True and assembly['container_starts']==0
            and assembly['build']=='NOT_RUN' and assembly['pull']=='FORBIDDEN'
            and assembly['base_layers_verified'] is True,'assembly result is not accepted stopped-only proof')
    image=assembly['image_id'];require(re.fullmatch('sha256:[a-f0-9]{64}',image),'immutable accepted image required')
    require(re.fullmatch('[a-f0-9]{32}',assembly['nonce']),'assembly nonce missing')
    before=validate_context(app,context,check)
    native,runtime=load_tools(app) if _tools is None else _tools
    output=Path(output).absolute() if output is not None else app/'runtime/fast-helper'
    require(not output.exists() and not output.is_symlink(),'fresh fast-helper output required')
    output=output.resolve(strict=False)
    require(output==app/'runtime/fast-helper','bundle output must be APP/runtime/fast-helper')
    require(compression in ('gzip','none') and type(max_archive_bytes) is int and max_archive_bytes>0,'invalid archive options')
    native.configure(context_name,socket)
    output.mkdir(parents=True)
    journal={'schema':1,'status':'SAVING_EXACT_ACCEPTED_IMAGE','image_id':image,'assembly':assembly_fact,
        'context':context_fact,'source_app':str(app),'memory_controls':False,'docker_actions':[],
        'build':'NOT_RUN','pull':'FORBIDDEN','load':'NOT_RUN','run':'NOT_RUN','container_creates':0,
        'source_closure_before_after':False,'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    def snapshot():
        (output/'seal-result.json').write_text(json.dumps(journal,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    snapshot()
    env={key:value for key,value in native.docker_environment().items()
         if key.upper() not in ('PGPASSWORD','ONECDB2SRC_AUTH_PASSWORD')}
    def docker(*parts):
        check();require(parts and parts[0] in ('context','info','image','save'),'forbidden Docker operation')
        argv=native.docker_argv(*map(str,parts));journal['docker_actions'].append(list(argv));snapshot()
        done=_runner(argv,capture_output=True,env=env,timeout=min(120,deadline-time.monotonic()))
        require(done.returncode==0,'local Docker command failed: '+done.stderr.decode('utf-8',errors='replace')[:1000])
        return done.stdout
    try:
        if native.DOCKER_SOCKET:record=native.context_record()
        else:
            selected=native.DOCKER_CONTEXT or docker('context','show').decode().strip()
            require(re.fullmatch('[A-Za-z0-9_.-]+',selected),'invalid local Docker context')
            record=json.loads(docker('context','inspect',selected))[0];native.configure(context=selected)
        native.daemon_policy(record,json.loads(docker('info','--format','{{json .}}')))
        journal['context_record']=record
        def inspect():
            rows=json.loads(docker('image','inspect',image));require(type(rows) is list and len(rows)==1,'ambiguous accepted image')
            value=rows[0]
            require(value['Id']==image and value.get('Os')=='linux' and value['Architecture']=='amd64','accepted image identity differs')
            labels=value['Config'].get('Labels') or {}
            require(labels.get('1cdb2src.fast.build.nonce')==assembly['nonce']
                    and labels.get('1cdb2src.fast.build.context_sha256')==context_sha256,'accepted image context owner differs')
            _execution(value['Config']);native.image_policy(image,value,ENTRYPOINT[-1]);return value
        image_before=inspect();save_new(output/'image-before.json',image_before)
        raw=output/'helper-image.tar';docker('save','--output',str(raw),image)
        raw_fact=fact(raw,check)
        identity,execution=runtime.derive_archive_identity(raw)
        # derive_archive_identity is the public pure API; its parser has no Docker calls.
        check();_execution(execution)
        require(image in identity['allowed_image_ids'] and image_before['RootFS']['Layers']==identity['rootfs_diff_ids'],
                'saved archive does not represent exact accepted image/rootfs')
        for key in ('User','Entrypoint','Env','Cmd','WorkingDir','Labels'):
            require(image_before['Config'].get(key)==execution.get(key),'archive/config mismatch: '+key)
        require(fact(raw,check)==raw_fact,'saved archive changed during identity check')
        archive=raw
        if compression=='gzip':
            archive=output/'helper-image.tar.gz'
            with raw.open('rb') as source,archive.open('xb') as target:
                with gzip.GzipFile(filename='',mode='wb',fileobj=target,compresslevel=6,mtime=0) as zipped:
                    for block in iter(lambda:source.read(1024*1024),b''):zipped.write(block);check()
            require(fact(raw,check)==raw_fact,'raw archive changed during gzip')
            zipped_identity,zipped_execution=runtime.derive_archive_identity(archive)
            check();require((zipped_identity,zipped_execution)==(identity,execution),'gzip changed archive semantics')
            raw.unlink()  # Only the exact fresh owned file created above; never an image/container/global path.
        archive_fact=fact(archive,check);require(archive_fact['bytes']<max_archive_bytes,'archive exceeds requested package size')
        image_after=inspect();require(image_after==image_before,'accepted image metadata changed during save')
        save_new(output/'image-after.json',image_after)
        require(validate_context(app,context,check)==before and fact(assembly_path,check)==assembly_fact
                and fact(context_path,check)==context_fact,'candidate/context/assembly changed during seal')
        manifest={'schema':SCHEMA,'status':'SEALED_OFFLINE_HELPER_REQUIRES_PRODUCT_ACTUAL',
            'image_id':identity['provenance_image_id'],'image_identity':identity,'entrypoint':ENTRYPOINT,
            'env':execution['Env'],'archive':{'file':archive.name,**archive_fact},
            'source_files':context['source_files'],'runtime_files':context['runtime_files'],
            'provenance':{'base_source':base_source,'base_image':context['base_image'],'assembly':assembly_fact,
                'context_manifest':context_fact,'accepted_image_id':image,'seal_producer':fact(__file__),
                'no_remote_resolution':True,'docker_save_only':True},
            'source_closure_before_after':True,'product_actual':'NOT_RUN_THIS_TOOL'}
        save_new(output/'manifest.json',manifest)
        notice=('This helper inherits the unmodified filesystem layers of '+base_source+' ('+context['base_image']+').\n'
            'This name records build provenance; no tag lookup/pull was performed.\n'
            'CPython, Debian packages and other base-image components keep their respective licenses and notices; '
            'this file does not replace or relicense them. Inherited layers are preserved in the offline image archive.\n'
            'The bundled independent converter/runtime licenses are in /opt/app/runtime/local/licenses in the image, '
            'and app/runtime/local/licenses in this distribution.\n'
            'Application source is governed by its repository license notices. No blanket license is claimed for this image.\n')
        (output/'THIRD-PARTY-NOTICES.txt').write_text(notice,encoding='utf-8')
        journal.update(status='SEALED_OFFLINE_HELPER_REQUIRES_PRODUCT_ACTUAL',archive=manifest['archive'],
            manifest=fact(output/'manifest.json'),image_identity=identity,source_closure_before_after=True,
            seconds=time.monotonic()-started,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        snapshot();return manifest
    except BaseException as error:
        journal.update(status='FAILED_UNACCEPTED_PARTIAL_RETAINED',error=type(error).__name__+': '+str(error),
            seconds=time.monotonic()-started);snapshot();raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app',type=Path,required=True);parser.add_argument('--assembly',type=Path,required=True)
    parser.add_argument('--assembly-sha256',required=True);parser.add_argument('--context-manifest',type=Path,required=True)
    parser.add_argument('--context-sha256',required=True);parser.add_argument('--seconds',type=float,default=300)
    parser.add_argument('--compression',choices=('gzip','none'),default='gzip')
    parser.add_argument('--max-archive-bytes',type=int,default=100_000_000)
    parser.add_argument('--docker-context');parser.add_argument('--docker-socket')
    args=parser.parse_args()
    value=seal_helper(args.app,args.assembly,args.assembly_sha256,args.context_manifest,args.context_sha256,
        seconds=args.seconds,compression=args.compression,max_archive_bytes=args.max_archive_bytes,
        context_name=args.docker_context,socket=args.docker_socket)
    print(json.dumps({'status':value['status'],'manifest':str(args.app/'runtime/fast-helper/manifest.json'),
                      'archive':value['archive'],'image_identity':value['image_identity']},indent=2))

if __name__=='__main__':main()
