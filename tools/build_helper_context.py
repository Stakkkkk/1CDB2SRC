"""Freeze an APP source/runtime closure for the offline stopped-image assembler.

No Docker, image resolver, interpreter payload or network calls. Output contains
only context/app/<selected source/runtime files> and a sealed context manifest.
The final runnable helper identity is produced AFTER image assembly/save; it is
deliberately absent here, avoiding a manifest/image source cycle.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

BASE='sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641'
ENTRYPOINT=['python','-I','-S','-B','/opt/app/onecdb2src/xml/linux_helpers.py']

def require(ok,message):
    if not ok:raise ValueError('Helper context: '+message)

def safe(value):
    require(type(value) is str and value and not any(c in value for c in ('\\',':','\0','\r','\n')),
            'unsafe relative path')
    path=PurePosixPath(value)
    require(path.parts and not path.is_absolute() and '..' not in path.parts and path.as_posix()==value,
            'noncanonical relative path')
    require(not any(part.endswith((' ','.')) for part in path.parts),'ambiguous path suffix')
    return path

def regular(path,directory=False):
    info=Path(path).lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,
            'linked/reparse input')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),'unexpected input kind')
    require(directory or info.st_nlink==1,'hardlinked input')
    return info

def token(info):return info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns

def location(root,name):
    path=root.joinpath(*safe(name).parts)
    for parent in reversed(path.parents):
        if parent==root or root in parent.parents:regular(parent,True)
    regular(path)
    return path

def fact(path):
    before=regular(path);digest=hashlib.sha256();count=0
    with Path(path).open('rb') as stream:
        opened=os.fstat(stream.fileno())
        require(token(opened)==token(before),'input changed before open')
        for block in iter(lambda:stream.read(1024*1024),b''):
            digest.update(block);count+=len(block)
        after=os.fstat(stream.fileno())
        require(token(after)==token(opened) and after.st_ctime_ns==opened.st_ctime_ns,'open input changed')
    require(token(regular(path))==token(before) and count==before.st_size,'input changed during read')
    return {'bytes':count,'sha256':digest.hexdigest()}

def read_json(path):
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'duplicate JSON key');value[key]=item
        return value
    return json.loads(Path(path).read_text(encoding='utf-8-sig'),object_pairs_hook=unique)

def walk(root,start,predicate):
    directory=root/start;regular(directory,True);result=set()
    def fail(error):raise error
    for base,dirs,files in os.walk(directory,followlinks=False,onerror=fail):
        regular(base,True)
        for name in dirs:
            regular(Path(base)/name,True)
            require(name not in ('.venv','venv','.git','node_modules'),'foreign dependency tree inside package')
        for name in files:
            path=Path(base)/name;key=path.relative_to(root).as_posix()
            if predicate(key):safe(key);regular(path);result.add(key)
    require(len({name.casefold() for name in result})==len(result),'case-colliding package paths')
    return result

def inventory(app):
    sources=walk(app,'onecdb2src',lambda p:p.endswith('.py') or p=='onecdb2src/xml/data/assets.rs')
    require({'onecdb2src/xml/data/assets.rs','onecdb2src/xml/linux_helpers.py'}<=sources,
            'helper entry/assets source missing')
    runtimes=walk(app,'runtime/local',lambda p:True)
    runtime=read_json(location(app,'runtime/local/manifest.json'))
    require(runtime.get('schema')==1 and type(runtime.get('files')) is dict and runtime['files'],
            'sealed local runtime manifest required')
    expected={'runtime/local/manifest.json'}
    for name,row in runtime['files'].items():
        safe(name);require(name!='manifest.json','runtime manifest self-reference forbidden')
        require(type(row) is dict and type(row.get('bytes')) is int and row['bytes']>=0
                and type(row.get('sha256')) is str and re.fullmatch('[a-f0-9]{64}',row['sha256']),
                'invalid local runtime pin')
        expected.add('runtime/local/'+name)
    require(runtimes==expected,'extra or missing local runtime file')
    return sources,runtimes,runtime

def copy_pinned(source,target,expected):
    before=regular(source)
    target.parent.mkdir(parents=True,exist_ok=True)
    digest=hashlib.sha256();count=0
    with source.open('rb') as stream,target.open('xb') as output:
        opened=os.fstat(stream.fileno());require(token(opened)==token(before),'copy source changed before open')
        for block in iter(lambda:stream.read(1024*1024),b''):
            output.write(block);digest.update(block);count+=len(block)
        after=os.fstat(stream.fileno())
        require(token(after)==token(opened) and after.st_ctime_ns==opened.st_ctime_ns,'copy source changed in handle')
    require(token(regular(source))==token(before),'copy source changed after read')
    require({'bytes':count,'sha256':digest.hexdigest()}==expected and fact(target)==expected,
            'copied bytes differ from pinned source')

def build_context(app,output,base_image=BASE):
    started=time.monotonic();app=Path(app).absolute();regular(app,True);app=app.resolve(strict=True)
    output=Path(output).absolute()
    require(not output.exists() and not output.is_symlink(),'fresh output required')
    output=output.resolve(strict=False)
    require(app not in output.parents and output not in app.parents and output!=app,
            'fresh context outside source APP required')
    require(type(base_image) is str and re.fullmatch('sha256:[a-f0-9]{64}',base_image),'immutable base ID required')
    sources,runtimes,runtime=inventory(app)
    pinned={name:fact(location(app,name)) for name in sorted(sources|runtimes)}
    for name,row in runtime['files'].items():
        require(pinned['runtime/local/'+name]=={key:row[key] for key in ('bytes','sha256')},
                'local runtime differs from its declared pin')
    output.mkdir(parents=True);context=output/'context';context.mkdir()
    rows=[]
    for name,expected in pinned.items():
        context_path='app/'+name
        copy_pinned(location(app,name),context.joinpath(*safe(context_path).parts),expected)
        rows.append({'source_path':str(app.joinpath(*safe(name).parts)),
                     'context_path':context_path,**expected})
    after_sources,after_runtimes,_=inventory(app)
    require((after_sources,after_runtimes)==(sources,runtimes),'source closure changed during copy')
    require({name:fact(location(app,name)) for name in pinned}==pinned,'source content changed during copy')
    copied={p.relative_to(context).as_posix() for p in context.rglob('*') if p.is_file()}
    require(copied=={row['context_path'] for row in rows},'context closure differs')
    value={'schema':1,'status':'PREPARED_FROZEN_CONTEXT_ONLY','base_image':base_image,
        'base_repo_digest':'python@'+base_image,'base_inspection':'NOT_RUN_THIS_SOURCE_BUILDER',
        'context':str(context),'source_app':str(app),'files':rows,'context_files':len(rows),
        'context_bytes':sum(row['bytes'] for row in rows),
        'source_files':{name:pinned[name] for name in sorted(sources)},
        'runtime_files':{name:pinned[name] for name in sorted(runtimes)},'entrypoint':ENTRYPOINT,
        'actual_build':'NOT_RUN','containers':0,'remote_requests_in_this_preparation':0,
        'source_before_after':'EXACT_PATHSET_AND_FILE_FACTS','context_copy_readback':'ALL_REGULAR_FILES_EXACT',
        'helper_image_identity':'NOT_YET_ASSEMBLED_NO_SOURCE_CYCLE',
        'seconds':time.monotonic()-started,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    with (output/'context-manifest.json').open('x',encoding='utf-8') as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2);stream.write('\n')
    return value

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--base-image',default=BASE)
    args=parser.parse_args();value=build_context(args.app,args.output,args.base_image)
    print(json.dumps({'status':value['status'],'manifest':str(args.output/'context-manifest.json'),
        'manifest_fact':fact(args.output/'context-manifest.json'),'files':value['context_files'],
        'bytes':value['context_bytes'],'seconds':value['seconds']},indent=2))

if __name__=='__main__':main()
