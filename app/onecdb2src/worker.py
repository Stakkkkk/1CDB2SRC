"""Fixed pipeline stages, each launched inside the existing bounded Windows Job."""
import argparse,hashlib,json,os,shutil,sys
from pathlib import Path,PurePosixPath
from .util import read,save,fact,require,regular

def invoke(module,argv):
    previous=sys.argv
    try:sys.argv=[module.__file__,*map(str,argv)];module.main()
    finally:sys.argv=previous

def signature_options(cf,profile):
    from .nativecf.cf_source import CFSource,identity
    from .xml.dump_info_modern_r3 import validate_current_signature_model,signature_profile_guard
    source=CFSource(cf)
    try:
        root=str(source.tree('root')[1]);uid=identity(source.tree(root))['uuid'];legacy=uid+'.d';modern=uid+'.10'
        if profile['xml_version']=='2.21' and modern in source.names() and legacy not in source.names():
            signature_profile_guard(source,uid,profile,modern_passthrough=True)
            return ['--modern-signature-passthrough']
        signature_profile_guard(source,uid,profile)
        if legacy not in source.names():return []
        if source.inflated(legacy)!=b'\xef\xbb\xbf{0,"",""}':return []
        if modern in source.names():
            validate_current_signature_model(source.tree(modern))
            return ['--omit-empty-legacy-signature-profile']
        return ['--legacy-empty-signature-profile']
    finally:source.close()

def parents(config,side):
    from .nativecf.cf_source import CFSource,identity
    from .xml import extract_parent_assets_r8 as producer
    cf=Path(config['root'])/'_work/cf'/side/'source.cf'
    output=Path(config['root'])/'_work'/('parents-'+side)
    source=CFSource(cf)
    try:
        uid=identity(source.tree(str(source.tree('root')[1])))['uuid'];name=uid+'.4'
        require(name in source.names(),'Support descriptor missing')
        tree=source.tree(name)
        if not (isinstance(tree,list) and tree[:2]==['6','0']):
            # Unsupported descriptor stays exactly as CF-derived native raw asset.
            native=Path(config['root'])/'_work'/('native-'+side)
            report=read(native/'engine.stderr.json')
            rows=[r for r in report['export']['storage']['entries'] if r['logical_name']==name]
            require(len(rows)==1 and 'Ext/ParentConfigurations.bin' in rows[0]['outputs'],'Unsupported support descriptor not preserved')
            raw=source.inflated(name)
            require(fact(native/'tree/xml/Ext/ParentConfigurations.bin')['sha256']==hashlib.sha256(raw).hexdigest(),'Support descriptor raw mismatch')
            output.mkdir()
            save(output/'unsupported.json',{'status':'UNSUPPORTED_DESCRIPTOR_PRESERVED','logical_name':name,'sha256':hashlib.sha256(raw).hexdigest(),'parents_inventory':'UNKNOWN'})
            return
    finally:source.close()
    invoke(producer,['--cf',cf,'--expected-sha256',fact(cf)['sha256'],'--output',output])

def integrity(config):
    from .nativecf.cf_source import CFSource
    from .sqlcf.export_cf import config_identity,cf_tree
    from . import profiles
    import xml.etree.ElementTree as ET
    from .xml.dump_info import long_path
    root=Path(config['root']);manifest=read(root/'_work/cf/manifest.json');result={}
    for side,key in [('main','main_cf'),('vendor','supplier_cf')]:
        source=root/'_work/cf'/side/'source.cf';target=root/(side+'.cf')
        regular(source);require(not target.exists(),'Final CF already exists')
        shutil.copyfile(source,target)
        expected={k:manifest[key][k] for k in ('bytes','sha256')}
        require(fact(source)==fact(target)==expected,'Final CF lineage mismatch')
        archive=CFSource(target)
        try:
            root_id=str(cf_tree(archive.catalog,'root')[1])
            identity=config_identity(cf_tree(archive.catalog,root_id))
            expected_identity=manifest['main_identity' if side=='main' else 'supplier_identity']
            require(all(identity[k]==expected_identity[k] for k in ('uuid','name','vendor','version')),'Final CF identity mismatch')
            entry_count=len(archive.catalog.entries)
        finally:archive.close()
        final=long_path(root/side);receipt=read(final/'receipt.json')
        profile_path=root/'_work/profiles'/(side+'.json');profile=profiles.load(profile_path,source)
        require(receipt.get('profile')==profile and receipt.get('profile_receipt')=={'path':str(profile_path.resolve()),'sha256':fact(profile_path)['sha256']},'Final profile lineage mismatch')
        require(receipt['status']=='CANDIDATE_POSTGEN_VERIFICATION_REQUIRED','Assembly incomplete')
        require(receipt['cf_sha256']==expected['sha256'],'Assembly/CF binding mismatch')
        require(fact(final/'files.jsonl')['sha256']==receipt['manifest_sha256'],'Assembly manifest changed')
        require((final/'xml/Configuration.xml').is_file(),'Complete XML configuration missing')
        seen=set();total=0;bsl=0
        with (final/'files.jsonl').open(encoding='utf-8') as f:
            for line in f:
                row=json.loads(line);rel=PurePosixPath(row['path'])
                require(not rel.is_absolute() and '..' not in rel.parts and '\\' not in row['path'],'Unsafe output path')
                require(row['path'] not in seen,'Duplicate assembly output')
                seen.add(row['path']);p=final/'xml'/rel
                regular(p);require(fact(p)=={k:row[k] for k in ('bytes','sha256')},'Final XML readback mismatch')
                if p.suffix=='.xml':
                    node=ET.parse(p).getroot()
                    if rel.as_posix()=='Configuration.xml':
                        require(node.tag=='{http://v8.1c.ru/8.3/MDClasses}MetaDataObject' and len(node.findall('{http://v8.1c.ru/8.3/MDClasses}Configuration'))==1,'Configuration metadata envelope missing')
                    if rel.as_posix()=='ConfigDumpInfo.xml':
                        require(node.tag=='{http://v8.1c.ru/8.3/xcf/dumpinfo}ConfigDumpInfo','DumpInfo envelope missing')
                    if node.tag in ('{http://v8.1c.ru/8.3/MDClasses}MetaDataObject','{http://v8.1c.ru/8.3/xcf/dumpinfo}ConfigDumpInfo'):
                        require(node.attrib.get('version')==profile['xml_version'],'Final metadata edition mismatch')
                total+=p.stat().st_size;bsl+=p.suffix.lower()=='.bsl'
        actual=set()
        for base,dirs,files in os.walk(final/'xml',followlinks=False):
            for name in dirs:regular(Path(base)/name,True)
            for name in files:actual.add((Path(base)/name).relative_to(final/'xml').as_posix())
        require(actual==seen and len(seen)==receipt['files'] and {'Configuration.xml','ConfigDumpInfo.xml'}<=seen,'Final XML path set mismatch')
        result[side]={'cf':expected,'identity':identity,'profile':profile,'profile_receipt_sha256':fact(profile_path)['sha256'],'cf_entries':entry_count,'xml_files':len(seen),'xml_bytes':total,'bsl_files':bsl,'opaque_unaccepted':len(receipt['unaccepted_opaque_entries'])}
    save(root/'_work/integrity.json',{'status':'PASS_OWN_RESULT_INTEGRITY','sides':result,'oracle_inputs':[]})

def run(stage,config):
    root=Path(config['root']);work=root/'_work'
    if stage=='capture':
        from .db import capture
        db=dict(config['db']);db['password']=os.environ.get('ONECDB2SRC_AUTH_PASSWORD','')
        result=capture(db,work/'capture');save(work/'capture-result.json',result)
    elif stage=='cf':
        from .sqlcf.export_cf import export
        result=read(work/'capture-result.json')
        export(result['path'],work/'cf',config['supplier'],result['inventory'])
    elif stage=='profiles':
        from . import profiles
        directory=work/'profiles';directory.mkdir()
        for side in ('main','vendor'):
            profile=profiles.select(work/'cf'/side/'source.cf',config['platform'])
            profiles.save_new(directory/(side+'.json'),profile)
    elif stage.startswith('native-'):
        if config.get('runtime_backend','docker')=='native':
            from .xml.export_local import export
        else:
            from .xml.export_native import export,configure
            configure(config.get('docker_context'),config.get('docker_socket'))
        side=stage[7:]
        export(argparse.Namespace(cf=str(work/'cf'/side/'source.cf'),output=str(work/stage),provider=config['db']['provider'],side=side,image=config['runtime']['image_id'],binary='/engine/ibcmd-rs',engine_receipt=None,expected_sha256=None,memory_mib=config['native_memory_mib'],workers=2,timeout=config['native_seconds'],platform=config['platform'],profile_receipt=str(work/'profiles'/(side+'.json'))))
    elif stage.startswith('dumpinfo-'):
        from .xml import dump_info_modern_r3 as module
        side=stage[9:];native=work/('native-'+side);cf=work/'cf'/side/'source.cf'
        from . import profiles
        profile_path=work/'profiles'/(side+'.json');profile=profiles.load(profile_path,cf)
        options=signature_options(cf,profile)
        require(profile['xml_version']!='2.21' or options in ([],['--modern-signature-passthrough']),'Unsupported legacy signature projection for XML2.21')
        invoke(module,['--cf',cf,'--generated',native/'tree/xml','--engine-report',native/'engine.stderr.json','--run-receipt',native/'receipt.json','--profile-receipt',profile_path,'--output',work/stage,*options])
    elif stage.startswith('parents-'):parents(config,stage[8:])
    elif stage.startswith('assembly-'):
        from .xml import complete_native_with_parents_r9 as module
        side=stage[9:];args=['--base-run',work/('native-'+side),'--dumpinfo',work/('dumpinfo-'+side),'--profile-receipt',work/'profiles'/(side+'.json'),'--output',root/side]
        if (work/('parents-'+side)/'receipt.json').exists():args+=['--parent-assets',work/('parents-'+side)]
        invoke(module,args)
    elif stage=='integrity':integrity(config)
    else:raise ValueError('Unknown fixed pipeline stage')

def main(argv):
    require(len(argv)==2,'Invalid internal invocation')
    stage,path=argv
    try:
        run(stage,read(path));print(json.dumps({'stage':stage,'status':'STAGE_COMPLETED'}),flush=True);return 0
    except KeyboardInterrupt:return 130
    except Exception as error:
        # DB driver messages/connection repr must never reach logs or traceback.
        from .db.common import CaptureError
        diagnostic={'stage':stage,'status':'FAILED','error_type':type(error).__name__}
        profile_stage=stage=='profiles' or stage.startswith(('native-','dumpinfo-','assembly-'))
        profile_reason=isinstance(error,ValueError) and profile_stage and (
            str(error).startswith('CF profile: ') or str(error) in (
                'Unsupported XML2.21 configuration signature form',
                'Legacy signature projection has no XML2.21 proof',
                'Unsupported legacy signature projection for XML2.21'))
        assembly_reason=False
        if stage.startswith('assembly-'):
            try:
                from .xml.complete_native_with_parents_r9 import AssemblyValidationError
            except Exception:
                # An import failure must not break the diagnostic boundary.
                pass
            else:
                assembly_reason=isinstance(error,AssemblyValidationError)
        if isinstance(error,CaptureError) or isinstance(error,ValueError) and stage in ('cf','integrity') or profile_reason or assembly_reason:
            diagnostic['reason']=str(error)[:512]
        print(json.dumps(diagnostic,ensure_ascii=False),file=sys.stderr,flush=True)
        return 1
