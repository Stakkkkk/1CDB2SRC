import argparse,getpass,json,os,shutil,subprocess,sys,time
from pathlib import Path
from .util import fact,read,regular,require,safe_output,save,utc

PACKAGE=Path(__file__).resolve().parents[1]


def stage_memory_budget(config,stage):
    # Native children inherit RLIMIT_AS. Leave room for its supervisor and never
    # impose the ordinary Python 3GiB hard limit below an 8GiB native budget.
    if config.get('runtime_backend','docker')=='native' and stage.startswith('native-'):
        return max(3*1024**3,(config['native_memory_mib']+512)*1024**2)
    return 3*1024**3

def parser():
    p=argparse.ArgumentParser(description='MS SQL/PostgreSQL → main.cf/vendor.cf + XML, без платформы 1С')
    p.add_argument('--provider',choices=['mssql','postgresql'],required=True)
    p.add_argument('--host',required=True);p.add_argument('--port',type=int)
    p.add_argument('--database',required=True);p.add_argument('--schema')
    p.add_argument('--auth',choices=['integrated','sql'],default='sql');p.add_argument('--user')
    p.add_argument('--password-env');p.add_argument('--prompt-password',action='store_true')
    p.add_argument('--supplier',required=True);p.add_argument('--output',required=True)
    p.add_argument('--mssql-consistency',choices=['snapshot','serializable'],default='snapshot')
    p.add_argument('--mssql-driver',choices=['pytds','pyodbc'],default='pytds')
    p.add_argument('--transport',choices=['tcp','lpc'],default='tcp')
    p.add_argument('--odbc-driver',default='ODBC Driver 17 for SQL Server')
    p.add_argument('--platform',choices=['auto','8.3.27','8.5.1'],default='auto',help='Проверенный профиль каждой CF; неизвестная/противоречивая структура отклоняется')
    p.add_argument('--assembly-mode',choices=['copy','adopt'],default='copy',help='copy: прежняя сборка; adopt: передать собственное дерево native без повторного копирования, с конечной проверкой')
    p.add_argument('--runtime',choices=['docker','native'],default='docker',help='Docker (Windows/Linux) либо закреплённый локальный конвертер (Linux x86-64)')
    connection=p.add_mutually_exclusive_group()
    connection.add_argument('--docker-context',help='Локальный Docker context; Windows: desktop-linux')
    connection.add_argument('--docker-socket',help='Явный локальный Unix socket Docker на Linux; удалённые daemon не поддержаны')
    p.add_argument('--profile',choices=['default','small'],default='default')
    p.add_argument('--capture-seconds',type=int,default=600);p.add_argument('--python-seconds',type=int)
    p.add_argument('--native-seconds',type=int);p.add_argument('--native-memory-mib',type=int)
    p.add_argument('--total-seconds',type=int,help='Дополнительный общий предел, не делит бюджеты этапов по умолчанию')
    return p

def docker(args,timeout=60):
    from .xml.export_native import docker_environment,docker_argv
    return subprocess.run(docker_argv(*args),env=docker_environment(),capture_output=True,timeout=timeout,encoding='utf-8',errors='replace')

def preflight(config):
    import psutil
    require(os.name=='nt' or sys.platform=='linux','Supported hosts: Windows x64 or Linux x86-64/glibc')
    if config.get('runtime_backend','docker')=='native':
        from .xml.export_local import preflight as local_preflight
        result=local_preflight(config)
        require(shutil.disk_usage(config['root']).free>=2*1024**3,'Insufficient output disk space')
        return result
    from .xml.export_native import daemon_policy,image_policy,context_record,configure,verify_bind_visibility,endpoint_policy
    configure(config.get('docker_context'),config.get('docker_socket'))
    context=context_record();endpoint_policy(context)
    runtime=config['runtime'];archive=PACKAGE/'runtime/runtime-image.tar'
    regular(archive);require(fact(archive)==runtime['archive'],'Bundled runtime archive mismatch')
    from .xml.runtime_identity import identities
    identity=identities(archive,runtime)
    def inspect_exact():
        for image in identity['allowed_image_ids']:
            found=docker(['image','inspect',image])
            if found.returncode==0:
                item=json.loads(found.stdout)[0]
                require(item['Id']==image and item['RootFS']['Layers']==identity['rootfs_diff_ids'],'Docker image differs from OCI config/rootfs binding')
                return image,found
        return None,None
    selected,metadata=inspect_exact()
    if selected is None:
        loaded=docker(['load','--input',str(archive)],120)
        require(loaded.returncode==0,'Cannot load bundled runtime')
        selected,metadata=inspect_exact()
    require(selected is not None,'Exact bundled image unavailable')
    runtime['provenance_image_id']=identity['provenance_image_id'];runtime['image_id']=selected
    info_result=docker(['info','--format','{{json .}}'])
    require(info_result.returncode==0,'Local Docker engine unavailable')
    info=json.loads(info_result.stdout);context=context_record()
    daemon_policy(context,info);image_policy(runtime['image_id'],json.loads(metadata.stdout)[0],'/engine/ibcmd-rs')
    reserve=(config['native_memory_mib']/1024+2)*1024**3
    memory=psutil.virtual_memory()
    require(memory.available>=reserve and info['MemTotal']>=config['native_memory_mib']*1024**2,'Insufficient fresh host/Docker memory reserve')
    disk=shutil.disk_usage(config['root'])
    require(disk.free>=2*1024**3,'Insufficient output disk space')
    require(info.get('MemoryLimit') is True and info.get('CpuCfsQuota') is True and info.get('PidsLimit') is True,'Docker kernel memory/CPU/PID limits unavailable')
    result={'host_available_bytes':memory.available,'docker_memory_bytes':info['MemTotal'],'disk_free_bytes':disk.free,'image_id':runtime['image_id'],'archive':fact(archive),'context':context,'oci_identity':identity,'kernel_limits':{key:info.get(key) for key in ('MemoryLimit','SwapLimit','CpuCfsQuota','PidsLimit')}}
    if sys.platform=='linux':result['bind_visibility']=verify_bind_visibility(runtime['image_id'],config['root'])
    return result

def fresh_native_admission(config):
    """Fresh numeric resource observation, with explicit Docker headroom estimate."""
    import psutil,re,math
    if config.get('runtime_backend','docker')=='native':
        memory=psutil.virtual_memory();host_cpu=psutil.cpu_percent(interval=.1);host_count=len(psutil.Process().cpu_affinity())
        reserve=(config['native_memory_mib']+2048)*1024**2
        require(memory.available>=reserve,'Insufficient fresh native host memory reserve')
        require(math.isfinite(host_cpu) and 0<=host_cpu<=100 and host_count*(1-host_cpu/100)>=2,'Insufficient fresh native CPU headroom')
        return {'observed_utc':utc(),'host_available_bytes':memory.available,'host_cpu_percent':host_cpu,'host_cpu_count':host_count,'reserve_bytes':reserve,'runtime_backend':'native','memory_enforcement':'per-process RLIMIT_AS; sampled aggregate RSS; no hard cgroup claim'}
    info_result=docker(['info','--format','{{json .}}']);stats_result=docker(['stats','--no-stream','--format','{{json .}}'])
    require(info_result.returncode==stats_result.returncode==0,'Cannot observe current Docker resources')
    info=json.loads(info_result.stdout);used=0;cpu=0.
    units={'B':1,'KB':1000,'MB':1000**2,'GB':1000**3,'KiB':1024,'MiB':1024**2,'GiB':1024**3,'TiB':1024**4}
    for line in stats_result.stdout.splitlines():
        row=json.loads(line);usage=row['MemUsage'].split('/')[0].strip();match=re.fullmatch(r'([0-9.]+)\s*([A-Za-z]+)',usage)
        require(match is not None and match[2] in units,'Cannot parse Docker memory observation')
        amount=float(match[1]);load=float(row['CPUPerc'].rstrip('%'))/100
        require(math.isfinite(amount) and amount>=0 and math.isfinite(load) and load>=0,'Invalid Docker resource value')
        used+=amount*units[match[2]];cpu+=load
    memory=psutil.virtual_memory();host_cpu=psutil.cpu_percent(interval=.1);host_count=psutil.cpu_count() or 0
    reserve=(config['native_memory_mib']+2048)*1024**2;headroom=info['MemTotal']-used
    require(memory.available>=reserve and headroom>=reserve,'Insufficient fresh host/Docker headroom')
    require(math.isfinite(host_cpu) and 0<=host_cpu<=100,'Invalid host CPU observation')
    require(host_count*(1-host_cpu/100)>=2 and info['NCPU']-cpu>=2,'Insufficient fresh CPU headroom')
    return {'observed_utc':utc(),'host_available_bytes':memory.available,'host_cpu_percent':host_cpu,'host_cpu_count':host_count,'docker_capacity_bytes':info['MemTotal'],'docker_current_container_bytes':int(used),'docker_headroom_estimate_bytes':int(headroom),'docker_cpu_count':info['NCPU'],'docker_used_cores_estimate':cpu,'reserve_bytes':reserve,'headroom_scope':'capacity minus current containers; host available measured separately'}

def native_outcome(root,stage,job):
    """A raw exit2 is allowed only when the engine's complete report proves opaque-only."""
    from . import profiles
    from .native_policy import classify
    from .nativecf.cf_source import CFSource
    directory=root/'_work'/stage
    receipt=read(directory/'receipt.json')
    report=read(directory/'engine.stderr.json')
    side=stage[7:];profile_path=root/'_work/profiles'/(side+'.json');profile=profiles.load(profile_path,receipt['source']['path'])
    require(receipt.get('profile_receipt')=={'path':str(profile_path.resolve()),'sha256':fact(profile_path)['sha256']},'Native profile artifact binding mismatch')
    archive=CFSource(receipt['source']['path'])
    try:stored_sizes={name:archive.catalog.entries[name].stored_size for name in archive.names()}
    finally:archive.close()
    require(receipt['source']['sha256']==receipt['source']['sha256_after']==fact(receipt['source']['path'])['sha256'],'Native source changed')
    return classify(receipt,report,stored_sizes,job['exit_code'],profile)

def cleanup_native(root,config=None):
    if (config or {}).get('runtime_backend','docker')=='native':
        results=[]
        for path in (root/'_work').glob('native-*'):
            if not path.is_dir():continue
            receipt=read(path/'receipt.json')
            require(receipt.get('runtime_backend')=='native' and receipt.get('cleanup',{}).get('confirmed') is True,'Local engine process cleanup unconfirmed')
            results.append(receipt['cleanup'])
        return results
    from .xml.export_native import cleanup_owned
    return [cleanup_owned(path) for path in (root/'_work').iterdir() if path.is_dir() and path.name.startswith(('native-','bind-probe-')) and (path/'ownership.json').exists()]

def readable_report(root,report):
    lines=[report['status'],f"Время: {report['total_seconds']:.3f} с"]
    verified=report.get('integrity',{}).get('sides',{})
    for side,label in [('main','Основная'),('vendor','Поставщик')]:
        if side in verified:
            lines.append(f"{label}: {side}.cf и {side}/xml проверены; XML-файлов {verified[side]['xml_files']}, BSL {verified[side]['bsl_files']}.")
        else:
            paths=[name for name in (side+'.cf',side+'/xml') if (root/name).exists()]
            lines.append(f"{label}: проверенный результат не получен."+(' Частичные данные: '+', '.join(paths)+'.' if paths else ''))
    if report.get('error'):lines.append('Причина: '+report['error'])
    for limit in report.get('limitations',[]):lines.append('Ограничение: '+json.dumps(limit,ensure_ascii=False))
    lines.append('Этапы, время, исходные статусы и ограничения: report.json; частичные данные: _work/.')
    return '\n'.join(lines)+'\n'

def main(argv=None):
    args=parser().parse_args(argv);root=None;report=None;config=None;exitcode=1;clock=time.monotonic()
    try:
        require(not(args.prompt_password and args.password_env),'Choose password prompt or env')
        require(args.provider=='mssql' or args.auth!='integrated','Integrated auth is MS SQL only')
        require(args.transport!='lpc' or args.provider=='mssql' and args.mssql_driver=='pyodbc','LPC requires explicit MS SQL pyodbc backend')
        require(args.auth=='integrated' or bool(args.user),'Specify --user for SQL/PG authentication')
        require(args.port is None or 1<=args.port<=65535,'Invalid port')
        require(args.runtime!='native' or sys.platform=='linux','Native runtime requires Linux x86-64/glibc')
        require(args.runtime=='docker' or not(args.docker_context or args.docker_socket),'Docker connection options are invalid for native runtime')
        require(os.name=='nt' or args.transport=='tcp','LPC is only supported on Windows')
        require(os.name=='nt' or args.auth!='integrated','Linux MS SQL path requires explicit SQL authentication')
        root=safe_output(args.output)
        require(root!=PACKAGE and PACKAGE not in root.parents and root not in PACKAGE.parents,'Output/package paths overlap')
        require(all(n is None or n>0 for n in [args.capture_seconds,args.python_seconds,args.native_seconds,args.total_seconds]),'Timeouts must be positive')
        password=getpass.getpass('Пароль СУБД: ') if args.prompt_password else os.environ.get(args.password_env,'') if args.password_env else ''
        if args.password_env:require(args.password_env in os.environ,'Password environment variable absent')
        root.mkdir(parents=True);(root/'_work').mkdir();(root/'_work/jobs').mkdir()
        config={'root':str(root),'supplier':args.supplier,'profile':args.profile,'platform':args.platform,'assembly_mode':args.assembly_mode,'runtime_backend':args.runtime,'docker_context':args.docker_context,'docker_socket':args.docker_socket,
                'db':{'provider':args.provider,'host':args.host,'port':args.port or (1433 if args.provider=='mssql' else 5432),'database':args.database,'schema':args.schema or ('dbo' if args.provider=='mssql' else 'public'),'auth':args.auth,'user':args.user,'consistency':args.mssql_consistency,'statement_timeout':min(args.capture_seconds,600),'lock_timeout':3000,'driver':args.mssql_driver,'transport':args.transport,'odbc_driver':args.odbc_driver},
                'runtime':read(PACKAGE/'runtime/manifest.json'),'native_seconds':args.native_seconds or (300 if args.profile=='small' else 2400),'native_memory_mib':args.native_memory_mib or (3072 if args.profile=='small' else 8192)}
        require(config['native_memory_mib']>=512,'Native memory must be at least512MiB')
        save(root/'_work/config.json',config)
        report={'status':'RUNNING','started_utc':utc(),'provider':args.provider,'database':args.database,'supplier':args.supplier,'stages':[],'limitations':[],'oracle_inputs':[]}
        save(root/'report.json',report)
        print('Проверка ресурсов и закреплённого runtime…',flush=True)
        tick=time.monotonic();report['preflight']=preflight(config);report['preflight_seconds']=time.monotonic()-tick
        save(root/'_work/config.json',config)
        if config['runtime_backend']=='docker' and report['preflight']['kernel_limits']['SwapLimit'] is not True:
            report['limitations'].append({'scope':'docker_swap_limit','enforcement':'NOT_AVAILABLE_ON_KERNEL','configured_memory_swap_is_not_proof_of_swap_enforcement':True})
        from .control.bounded_process import run
        env=dict(os.environ)
        for name in ('ONECDB2SRC_AUTH_PASSWORD','PGPASSWORD',args.password_env):
            if name:env.pop(name,None)
        env['PYTHONDONTWRITEBYTECODE']='1';env['PYTHONUTF8']='1'
        stages=['capture','cf','profiles']
        for side in ('main','vendor'):stages += [kind+'-'+side for kind in ('native','dumpinfo','parents','assembly')]
        stages+=['integrity']
        titles={'capture':'Согласованный снимок из СУБД','cf':'Восстановление двух CF','profiles':'Проверка структуры и выбор XML-профиля каждой CF','native':'XML независимым конвертером','dumpinfo':'Служебные версии XML','parents':'Вложенные поставки и их происхождение','assembly':'Сборка итогового XML','integrity':'Проверка CF и всех сформированных файлов'}
        for stage in stages:
            if args.total_seconds:require(time.monotonic()-clock<args.total_seconds,'Total E2E time cap exceeded')
            seconds=args.capture_seconds if stage=='capture' else config['native_seconds']+90 if stage.startswith('native-') else args.python_seconds or (600 if args.profile=='small' or not stage.startswith('assembly-') else 2400)
            if args.total_seconds:seconds=min(seconds,max(.1,args.total_seconds-(time.monotonic()-clock)))
            ledger={'stage':stage,'started_utc':utc(),'limit_seconds':seconds};report['stages'].append(ledger);save(root/'report.json',report)
            title=titles[stage.split('-')[0]]+(' — основная конфигурация' if stage.endswith('-main') else ' — поставщик' if stage.endswith('-vendor') else '')
            print(f'{title} ({stage}); предел {seconds:.0f} с.',flush=True)
            if stage.startswith('native-'):ledger['resource_admission']=fresh_native_admission(config)
            childenv=dict(env)
            if stage=='capture':childenv['ONECDB2SRC_AUTH_PASSWORD']=password
            ledger['python_supervision_memory_bytes']=stage_memory_budget(config,stage)
            job=run([sys.executable,'-B',str(PACKAGE/'export_1c.py'),'--_worker',stage,str(root/'_work/config.json')],root/'_work/jobs'/(stage+'.stdout'),root/'_work/jobs'/(stage+'.stderr'),root/'_work/jobs'/(stage+'.json'),seconds,8*1024**2,8*1024**2,rss_cap=ledger['python_supervision_memory_bytes'],env=childenv)
            ledger.update(finished_utc=utc(),seconds=job['seconds'],peak_rss_bytes=job['peak_job_rss_bytes'],exit_code=job['exit_code'],failure=job['failure'],supervisor_backend=job.get('backend','windows-job'),resource_semantics=job.get('rlimit_as_scope','Windows hard Job memory/CPU affinity'))
            if job.get('cancelled') or job.get('failure')=='CANCELLED' or (job['failure'] or '').startswith('KeyboardInterrupt'):raise KeyboardInterrupt
            require(job['failure'] is None and job['job_handle_closed'] and job['surviving_pids']==[] and not job['cleanup_errors'] and job['observation_status']=='OBSERVED','Stage timeout/resource/process closure failure: '+stage)
            if stage.startswith('native-'):
                ledger['native']=native_outcome(root,stage,job)
                if ledger['native']['opaque']:report['limitations'].append({'stage':stage,'opaque':ledger['native']['opaque'],'raw_exit':2})
            else:
                if job['exit_code']!=0:
                    diagnostic=None
                    for line in (root/'_work/jobs'/(stage+'.stderr')).read_text('utf-8',errors='replace').splitlines():
                        try:value=json.loads(line)
                        except ValueError:continue
                        if isinstance(value,dict) and value.get('stage')==stage and value.get('status')=='FAILED':diagnostic=value
                    if diagnostic:ledger['diagnostic']=diagnostic
                    reason=(diagnostic or {}).get('reason','')
                    raise ValueError('Stage refused input or failed: '+stage+('; '+reason if reason else ''))
            if stage.startswith('parents-') and (root/'_work'/stage/'unsupported.json').exists():report['limitations'].append(read(root/'_work'/stage/'unsupported.json'))
            ledger['status']='COMPLETED';save(root/'report.json',report)
            print(f'{title}: завершено за {job["seconds"]:.2f} с.',flush=True)
        report['integrity']=read(root/'_work/integrity.json')
        report['limitations'].append({'scope':'experimental_native_serialization','platform_loading':'NOT_TESTED','arbitrary_configuration_semantic_equivalence':'NOT_ESTABLISHED'})
        report['status']='COMPLETE_WITH_LIMITATIONS' if any('opaque' in x or 'parents_inventory' in x for x in report['limitations']) else 'COMPLETE'
        exitcode=2 if report['status']=='COMPLETE_WITH_LIMITATIONS' else 0
    except KeyboardInterrupt:
        exitcode=130
        if report:report['status']='CANCELLED'
    except Exception as error:
        # Only our validation messages are emitted; driver subprocess diagnostics are sanitized.
        if report:report.update(status='FAILED',error_type=type(error).__name__,error=str(error))
        print('Выгрузка не завершена: '+type(error).__name__+': '+str(error),file=sys.stderr,flush=True)
    finally:
        if report:
            postclock=time.monotonic()
            try:report['cleanup']=cleanup_native(root,config)
            except Exception as error:report.update(status='FAILED',cleanup_error=type(error).__name__);exitcode=1
            report.update(finished_utc=utc(),total_seconds=time.monotonic()-clock,postflight_seconds=time.monotonic()-postclock,exit_code=exitcode)
            save(root/'report.json',report)
            (root/'report.txt').write_text(readable_report(root,report),encoding='utf-8');print(report['status'],flush=True)
    return exitcode
