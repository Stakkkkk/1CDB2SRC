"""Opt-in Docker-volume candidate generation, no CLI/DB/archive operations.

The caller owns its output root, sealed helper preflight and common final CF
publication. A side is not accepted until namespace_result + independent V.
"""
import datetime,hashlib,io,json,os,re,subprocess,tarfile,time,uuid
from pathlib import Path
from types import SimpleNamespace
from .. import profiles
from ..nativecf.cf_source import CFSource
from ..native_policy import classify
from . import export_native
from .export_native import read_engine_report, report_summary
from ._fast_contract import (APP_ROOT, CONTRACT_SCHEMA, require, fact, read,
    load_helper_manifest, verify_source_closure, save_new)

def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(path,value):Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def capabilities(values):
    require(type(values) is list and all(type(value) is str for value in values), 'Invalid capability list')
    return [value[4:] if value.startswith('CAP_') else value for value in values]

class DockerFailure(RuntimeError):
    def __init__(self, operation, returncode, stderr):
        self.operation=tuple(map(str,operation));self.returncode=returncode;self.stderr=stderr
        super().__init__('Docker command failed: '+stderr[:1000])

def missing_volume(error,name):
    if not isinstance(error,DockerFailure) or error.operation!=('volume','inspect',name):return False
    escaped=re.escape(name)
    pattern=r'(?:Error response from daemon: )?(?:no such volume: '+escaped+r'|get '+escaped+r': no such volume)\s*'
    return re.fullmatch(pattern,error.stderr,flags=re.IGNORECASE) is not None

def absence_evidence(error,name):
    require(missing_volume(error,name),'Volume absence is not established')
    return {'kind':'EXACT_NAMED_DOCKER_MISSING_DIAGNOSTIC','operation':list(error.operation),
        'reference':name,'stderr_sha256':hashlib.sha256(error.stderr.encode('utf-8')).hexdigest()}

OWNER_INIT_CODE = "\nimport json,os,stat,sys\nfrom pathlib import Path\nnonce,side=sys.argv[1:]\nassert len(nonce)==32 and all(c in '0123456789abcdef' for c in nonce) and side in ('main','vendor')\nassert os.getuid()==0 and os.getgid()==0\nroot=Path('/job');info=root.lstat()\nassert stat.S_ISDIR(info.st_mode) and not root.is_symlink() and stat.S_IMODE(info.st_mode)==0o755\nassert (info.st_uid,info.st_gid) in ((0,0),(65532,65532))\npaths=['_work','_work/cf','_work/cf/'+side,'_work/profiles','_work/native-'+side,'_work/native-'+side+'/tree']\nexpected=set(paths+['.ownership']);actual=set()\nfor base,dirs,files in os.walk(root,followlinks=False):\n for name in dirs+files:\n  node=Path(base)/name;rel=node.relative_to(root).as_posix();actual.add(rel);s=node.lstat()\n  assert not node.is_symlink() and s.st_uid==s.st_gid==65532\n  if rel=='.ownership':\n   assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o444 and s.st_size==32\n  else:\n   assert rel in paths and stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o755\nassert actual==expected and (root/'.ownership').read_text(encoding='ascii')==nonce\nbefore=dict(uid=info.st_uid,gid=info.st_gid,mode=oct(stat.S_IMODE(info.st_mode)))\nfd=os.open('/job',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\ntry:\n opened=os.fstat(fd);assert (opened.st_dev,opened.st_ino)==(info.st_dev,info.st_ino)\n os.fchown(fd,65532,65532)\n after=os.fstat(fd);current=root.lstat()\n assert (after.st_dev,after.st_ino)==(current.st_dev,current.st_ino)==(info.st_dev,info.st_ino)\n assert after.st_uid==after.st_gid==65532 and stat.S_IMODE(after.st_mode)==0o755\nfinally:\n os.close(fd)\nprint(json.dumps(dict(schema='1CDB2SRC_FAST_ROOT_OWNER_V1',nonce=nonce,target='/job',recursive=False,\n before=before,after=dict(uid=after.st_uid,gid=after.st_gid,mode=oct(stat.S_IMODE(after.st_mode))),\n children_verified=sorted(actual))))\n"

def produce_fast_side(config, side):
    require(side in ('main','vendor'), 'Unknown fast side')
    require(config.get('runtime_backend','docker')=='docker' and config.get('assembly_mode')=='adopt',
            'Fast requires Docker and explicit adopt assembly')
    require(config.get('docker_transfer','copy') in ('copy','stream'), 'Unknown product transfer strategy')
    if config.get('docker_transfer','copy')=='stream':
        require(config.get('docker_mode')=='fast' and config.get('memory_controls') is False,
                'Explicit no-memory fast policy required for stream')
    helper, helper_binding = load_helper_manifest(config)
    product_root=Path(config['root']).resolve(strict=True)
    require(product_root.is_dir() and not product_root.is_symlink(), 'Owned output root required')
    cf=product_root/'_work/cf'/side/'source.cf'
    host_profile_path=product_root/'_work/profiles'/(side+'.json')
    host_profile=profiles.load(host_profile_path,cf)
    before={'bytes':host_profile['cf_bytes'],'sha256':host_profile['cf_sha256']}
    root=product_root/'_work'/('fast-'+side)
    require(not root.exists() and not (product_root/side).exists(), 'Fresh fast proof/result paths required')
    root.mkdir()
    args=SimpleNamespace(side=side, platform=host_profile['requested_platform'],
        helper_image=helper_binding['selected_image_id'],engine_image=config['runtime']['image_id'],
        seconds=float(config.get('native_seconds',2400)),
        budget_seconds=float(config.get('fast_side_seconds',5400)))
    require(args.seconds>0 and args.budget_seconds>0, 'Positive fast time budgets required')
    require(type(config.get('native_workers',2)) is int and 1<=config.get('native_workers',2)<=8,
            'Invalid native worker count')
    for image in (args.helper_image,args.engine_image):
        require(re.fullmatch('sha256:[a-f0-9]{64}',image), 'Pinned runtime image required')
    for path in (cf,root,Path(config['fast_helper']['manifest_path'])):
        require(not any(character in str(path) for character in (',','\0','\n','\r')), 'Unsupported bind path character')
    binary=config['runtime']['binary']['path']
    require(binary.startswith('/') and '..' not in binary.split('/'), 'Absolute pinned engine path required')
    nonce = uuid.uuid4().hex
    label = 'onecdb2src.fast.nonce'
    volume = 'onecdb2src-fast-' + nonce
    cf_volume=volume+'-cf'
    cf_transport=config.get('fast_cf_transport','volume')
    cf_method=config.get('docker_cf_transfer','copy')
    require(cf_method in ('copy','bind-copy') and (cf_method!='bind-copy' or cf_transport=='volume' and config.get('docker_mode')=='fast'),'Invalid CF staging method')
    require(cf_transport in ('volume','bind'),'Unknown fast CF transport')
    journal = {'schema': 1, 'status': 'RUNNING', 'started_utc': utc(), 'volume': volume,
               'nonce': nonce, 'containers': [], 'stages': [], 'memory_controls': False,
               'source_cf': {'host_path': str(cf), **before}, 'oracle_inputs': []}
    journal['cf_stage_method']=cf_method
    journal['cf_transport']='STAGED_OWN_READONLY_VOLUME' if cf_transport=='volume' else 'HOST_READONLY_BIND'
    if cf_transport=='volume':journal['cf_volume']=cf_volume
    save(root / 'result.json', journal)
    contract = {'schema': CONTRACT_SCHEMA, 'namespace': '/job', 'side': side,
        'nonce': nonce, 'requested_platform': args.platform, 'cf': before,
        'provider': config['db']['provider'], 'oracle_inputs': [], 'memory_controls': False,
        'engine_image': args.engine_image, 'helper_manifest_binding': helper_binding,
        'source_files': helper['source_files'], 'runtime_files': helper['runtime_files']}
    save_new(root/'contract.json',contract)
    save_new(root/'host-profile-binding.json',{'path':str(host_profile_path.resolve()),
        'fact':fact(host_profile_path),'profile':host_profile})
    containers = []
    volume_created = False
    volume_create_attempted = False
    cf_volume_create_attempted = False
    successful = False
    overall = time.monotonic()
    cleanup_phase = False
    cleanup_deadline = None
    journal['budget_seconds'] = args.budget_seconds
    export_native.configure(config.get('docker_context'),config.get('docker_socket'))
    env = {key: value for key, value in export_native.docker_environment().items()
           if key.upper() not in ('PGPASSWORD', 'ONECDB2SRC_AUTH_PASSWORD')}

    def docker(*parts, stdin=None, timeout=60):
        remaining = (cleanup_deadline - time.monotonic()) if cleanup_phase else args.budget_seconds - (time.monotonic() - overall)
        require(remaining > 0, 'Overall work/cleanup budget expired')
        done = subprocess.run(export_native.docker_argv(*map(str, parts)), input=stdin, capture_output=True,
                              timeout=min(timeout, remaining), env=env)
        if done.returncode:
            raise DockerFailure(parts,done.returncode,done.stderr.decode('utf-8', errors='replace'))
        return done.stdout

    def snapshot():
        save(root / 'result.json', journal)

    def stage(name, function):
        require(time.monotonic() - overall < args.budget_seconds, 'Overall work budget expired before ' + name)
        row = {'stage': name, 'started_utc': utc()}
        journal['stages'].append(row)
        snapshot()
        tick = time.monotonic()
        try:
            value = function()
            require(time.monotonic() - overall < args.budget_seconds, 'Overall work budget expired after ' + name)
            row['status'] = 'PASS'
            return value
        except BaseException:
            row['status'] = 'FAILED'
            raise
        finally:
            row['seconds'] = time.monotonic() - tick
            row['finished_utc'] = utc()
            snapshot()

    def create(role, image, command, *, source_bind=False):
        name = 'onecdb2src-fast-' + nonce + '-' + role
        row = {'role': role, 'name': name, 'image': image, 'created': False, 'removed': False}
        containers.append(row)
        journal['containers'] = containers
        snapshot()  # Recoverable unique name exists BEFORE Docker request.
        argv = ['create', '--name', name, '--label', label + '=' + nonce, '--network', 'none',
                '--read-only', '--user', '0:0' if role in ('owner-init','cf-copy') else '65532:65532', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--cpus', '2',
                '--mount', ('type=volume,source='+cf_volume+',target=/cf,volume-nocopy') if role in ('cf-stage','cf-copy')
                            else ('type=volume,source=' + volume + ',target=/job,volume-nocopy')]
        if role in ('owner-init','cf-copy'):
            argv += ['--cap-add', 'CHOWN']
        if role=='cf-copy':
            argv += ['--mount','type=bind,source='+str(cf)+',target=/source.cf,readonly']
        if source_bind:
            if cf_transport=='volume':
                argv += ['--mount','type=volume,source='+cf_volume+',target=/job/_work/cf/'+args.side+',readonly,volume-nocopy']
            else:
                argv += ['--mount', 'type=bind,source=' + str(cf) + ',target=/job/_work/cf/' + args.side + '/source.cf,readonly']
        if role in ('prepare', 'helpers'):
            argv += ['--mount', 'type=bind,source=' + str(root / 'contract.json') + ',target=/contract.json,readonly']
        elif role in ('owner-init','cf-copy'):
            argv += ['--entrypoint', 'python']
        else:
            argv += ['--entrypoint', '/usr/bin/env']
        argv += [image, *command]
        row['argv']=argv
        if role=='cf-copy':row['source_bind_request']=str(cf)
        snapshot()
        cid = docker(*argv).decode('ascii').strip()
        require(re.fullmatch('[a-f0-9]{64}', cid), 'Invalid created CID')
        row.update(cid=cid, created=True, argv=argv)
        snapshot()
        return row

    def inspect(row):
        data = json.loads(docker('inspect', row['name']))
        require(len(data) == 1, 'Ambiguous container')
        data = data[0]
        require(data['Name'] == '/' + row['name'] and data['Config']['Labels'].get(label) == nonce,
                'Owned container label/name mismatch')
        if row.get('cid'):
            require(row['cid'] == data['Id'], 'Owned CID mismatch')
        require(data['Config']['Image'] == row['image'], 'Owned image reference mismatch')
        require(data['HostConfig']['Memory'] == 0, 'Unexpected memory cap')
        require(data['HostConfig']['NetworkMode'] == 'none' and data['HostConfig']['ReadonlyRootfs'] is True,
                'Container isolation changed')
        require(data['Config']['User'] == ('0:0' if row['role'] in ('owner-init','cf-copy') else '65532:65532')
                and data['HostConfig']['NanoCpus'] == 2 * 10**9
                and capabilities(data['HostConfig']['CapDrop']) == ['ALL']
                and any(option == 'no-new-privileges' or option == 'no-new-privileges:true'
                        for option in data['HostConfig']['SecurityOpt']), 'Container user/CPU/capabilities changed')
        require(capabilities(data['HostConfig'].get('CapAdd') or []) == (['CHOWN'] if row['role'] in ('owner-init','cf-copy') else []),
                'Unexpected additional capabilities')
        jobs = [mount for mount in data['Mounts'] if mount['Destination'] == '/job']
        if row['role'] in ('cf-stage','cf-copy'):
            cfs=[mount for mount in data['Mounts'] if mount['Destination']=='/cf']
            require(len(cfs)==1 and len(data['Mounts'])==(2 if row['role']=='cf-copy' else 1) and cfs[0]['Type']=='volume'
                    and cfs[0]['Name']==cf_volume and cfs[0]['RW'] is True,'Own CF staging mount differs')
            if row['role']=='cf-copy':
                sources=[m for m in data['Mounts'] if m['Destination']=='/source.cf']
                require(len(sources)==1 and sources[0]['Type']=='bind' and sources[0]['RW'] is False,'CF copy source must be one readonly file bind')
                require(row.get('source_bind_source',sources[0]['Source'])==sources[0]['Source'],'CF copy source bind changed')
                row['source_bind_source']=sources[0]['Source']
        else:
            require(len(jobs) == 1 and jobs[0]['Type'] == 'volume' and jobs[0]['Name'] == volume
                    and jobs[0]['RW'] is True, 'Owned job volume mount changed')
        if row['role'] not in ('init', 'owner-init','cf-stage','cf-copy'):
            if cf_transport=='volume':
                cfs=[mount for mount in data['Mounts'] if mount['Destination']=='/job/_work/cf/'+args.side]
                require(len(cfs)==1 and cfs[0]['Type']=='volume' and cfs[0]['Name']==cf_volume
                        and cfs[0]['RW'] is False,'Own readonly CF volume changed')
            else:
                binds = [mount for mount in data['Mounts'] if mount['Destination'] == '/job/_work/cf/' + args.side + '/source.cf']
                require(len(binds) == 1 and binds[0]['RW'] is False and binds[0]['Type'] == 'bind', 'CF readonly mount changed')
        if row['role'] == 'owner-init':
            require(len(data['Mounts']) == 1, 'Owner initializer must mount only its exact own /job volume')
        if row['role'] in ('prepare','helpers'):
            contracts=[mount for mount in data['Mounts'] if mount['Destination']=='/contract.json']
            require(len(data['Mounts'])==3 and len(contracts)==1 and contracts[0]['Type']=='bind'
                    and contracts[0]['RW'] is False,'Readonly contract mount changed')
        elif row['role']=='engine':
            require(len(data['Mounts'])==2,'Engine has unexpected mounts')
        elif row['role']=='init':
            require(len(data['Mounts'])==1,'Init has unexpected mounts')
        return data

    def remove(row):
        state = inspect(row)
        docker('rm', '--force', state['Id'])
        leftovers = docker('ps', '-a', '-q', '--no-trunc', '--filter', 'name=^/' + row['name'] + '$').decode().split()
        require(not leftovers, 'Owned container survives remove')
        row['removed'] = True
        snapshot()

    def start(row, stem, allowed, phase_seconds=None):
        save(root / (stem + '-container-before.json'), inspect(row))
        tick = time.monotonic()
        remaining = args.budget_seconds - (time.monotonic() - overall)
        require(remaining > 0, 'Overall work budget expired before start')
        with (root / (stem + '.stdout')).open('xb') as stdout, (root / (stem + '.stderr')).open('xb') as stderr:
            done = subprocess.run(export_native.docker_argv('start', '--attach', row['cid']), stdout=stdout, stderr=stderr,
                                  timeout=min(args.seconds if phase_seconds is None else phase_seconds, remaining), env=env)
        after = inspect(row)
        save(root / (stem + '-container-after.json'), after)
        require(after['State']['Running'] is False and after['State']['OOMKilled'] is False
                and not after['State']['Error'], 'Container exit/cleanup unknown')
        require(done.returncode == after['State']['ExitCode'] and done.returncode in allowed,
                'Container failed/attach mismatch')
        row['seconds'] = time.monotonic() - tick
        snapshot()
        return after, done.returncode

    def cp_out(row, container_path, host_path, seconds=None):
        inspect(row)
        docker('cp', row['cid'] + ':' + container_path, host_path, timeout=args.seconds if seconds is None else seconds)

    try:
        if export_native.DOCKER_SOCKET:
            context=export_native.context_record()
            selected=None
        else:
            selected = export_native.DOCKER_CONTEXT or docker('context', 'show').decode().strip()
            context = json.loads(docker('context', 'inspect', selected))[0]
        info = json.loads(docker('info', '--format', '{{json .}}'))
        export_native.daemon_policy(context, info)
        if not export_native.DOCKER_SOCKET:
            export_native.configure(context=selected)  # Never replace an explicit local Unix socket.
        save(root / 'docker-context.json', context)
        save(root / 'docker-daemon.json', {key: info[key] for key in ('ID', 'Name', 'OSType', 'Architecture', 'ServerVersion')})
        for image in (args.engine_image, args.helper_image):
            metadata = json.loads(docker('image', 'inspect', image))[0]
            require(metadata['Id'] == image and metadata['Architecture'] == 'amd64', 'Image identity/architecture mismatch')
            export_native.image_policy(image, metadata, binary if image == args.engine_image else helper['entrypoint'][-1])
            if image==args.helper_image:
                require(metadata['Config'].get('Entrypoint')==helper['entrypoint']
                    and metadata['RootFS']['Layers']==helper['image_identity']['rootfs_diff_ids'],
                    'Helper image entrypoint/RootFS differs from sealed manifest')
            save_new(root/('image-helper.json' if image==args.helper_image else 'image-engine.json'),metadata)
        volume_create_attempted = True
        journal['volume_create_attempted'] = True
        snapshot()
        docker('volume', 'create', '--label', label + '=' + nonce, volume)
        volume_created = True
        volume_metadata = json.loads(docker('volume', 'inspect', volume))[0]
        require(volume_metadata['Name'] == volume and volume_metadata['Labels'].get(label) == nonce,
                'Created volume ownership mismatch')

        def init_volume():
            init = create('init', args.engine_image, ['-i', binary, '--version'])
            tar_bytes = io.BytesIO()
            with tarfile.open(fileobj=tar_bytes, mode='w') as archive:
                for name in ('.', '_work', '_work/cf', '_work/cf/' + args.side,
                             '_work/profiles', '_work/native-' + args.side,
                             '_work/native-' + args.side + '/tree'):
                    info = tarfile.TarInfo(name)
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    info.uid = info.gid = 65532
                    archive.addfile(info)
                marker = nonce.encode('ascii')
                info = tarfile.TarInfo('.ownership')
                info.size = len(marker)
                info.mode = 0o444
                info.uid = info.gid = 65532
                archive.addfile(info, io.BytesIO(marker))
            docker('cp', '-a', '-', init['cid'] + ':/job', stdin=tar_bytes.getvalue())
            remove(init)  # Stopped container used only as a view of its own volume.
        stage('tiny-tar-volume-init', init_volume)
        journal['owner_init_code_sha256'] = hashlib.sha256(OWNER_INIT_CODE.encode('utf-8')).hexdigest()
        snapshot()
        owner_init = create('owner-init', args.helper_image,
             ['-I', '-S', '-B', '-c', OWNER_INIT_CODE, nonce, args.side])
        stage('explicit-job-root-owner-init', lambda: start(owner_init, 'owner-init', {0},float(config.get('python_seconds',600))))
        ownership_proof = read(root / 'owner-init.stdout')
        require(ownership_proof['schema'] == '1CDB2SRC_FAST_ROOT_OWNER_V1'
                and ownership_proof['nonce'] == nonce and ownership_proof['target'] == '/job'
                and ownership_proof['recursive'] is False
                and ownership_proof['after'] == {'uid': 65532, 'gid': 65532, 'mode': '0o755'},
                'Explicit own-volume root ownership not established')
        journal['owner_init_proof'] = ownership_proof
        remove(owner_init)
        if cf_transport=='volume':
            def stage_cf_volume():
                nonlocal cf_volume_create_attempted
                cf_volume_create_attempted=True
                journal['cf_volume_create_attempted']=True;snapshot()
                docker('volume','create','--label',label+'='+nonce,
                       '--label','onecdb2src.fast.volume_role=cf',cf_volume)
                info=json.loads(docker('volume','inspect',cf_volume))[0]
                require(info['Name']==cf_volume and info['Labels'].get(label)==nonce
                        and info['Labels'].get('onecdb2src.fast.volume_role')=='cf','CF volume owner/role mismatch')
                if cf_method=='copy':
                    view=create('cf-stage',args.engine_image,['-i',binary,'--version'])
                    save_new(root/'cf-stage-container-before.json',inspect(view))
                    docker('cp',str(cf),view['cid']+':/cf/source.cf',timeout=float(config.get('fast_transport_seconds',2400)))
                    require(fact(cf)==before,'Host CF changed during one-time CF staging')
                    save_new(root/'cf-stage-container-after.json',inspect(view))
                    remove(view)
                else:
                    copier=create('cf-copy',args.helper_image,['-I','-S','-B','/opt/app/onecdb2src/xml/cf_copy.py',
                        '--nonce',nonce,'--side',side,'--bytes',str(before['bytes']),'--sha256',before['sha256']])
                    stage('cf-bind-copy',lambda:start(copier,'cf-copy',{0},float(config.get('fast_transport_seconds',2400))))
                    proof=read(root/'cf-copy.stdout')
                    require(proof['schema']=='1CDB2SRC_CF_BIND_COPY_V1' and proof['status']=='CF_COPY_COMPLETE'
                        and proof['nonce']==nonce and proof['side']==side and proof['expected']==before
                        and proof['copied']==before and proof['fresh_target_readback']==before
                        and proof['source_identity_stable'] is True and proof['exclusive_target'] is True
                        and proof['source_permissions_changed'] is False and proof['memory_controls'] is False
                        and proof['normalization']=={'uid':65532,'gid':65532,'file_mode':'0o444','directory_mode':'0o755'},'CF bind-copy proof differs')
                    require(fact(cf)==before,'Host CF changed during bind-copy staging')
                    journal['cf_bind_copy_proof']=fact(root/'cf-copy.stdout')
                    remove(copier)
                journal['cf_copy_source']=before
            stage('cf-volume-staging',stage_cf_volume)
        prepare = create('prepare', args.helper_image, ['prepare', '--side', args.side, '--contract', '/contract.json'], source_bind=True)
        stage('linux-namespace-prepare', lambda: start(prepare, 'prepare', {0},float(config.get('python_seconds',600))))
        cp_out(prepare, '/job/_work/profiles/' + args.side + '.json', root / 'linux-profile.json')
        cp_out(prepare, '/job/namespace-' + args.side + '.json', root / 'namespace.json')
        profile = read(root / 'linux-profile.json')
        require(profile['cf_sha256'] == before['sha256'] and profile['cf_bytes'] == before['bytes'], 'Prepare CF mismatch')
        remove(prepare)
        binary = config['runtime']['binary']['path']
        linux_cf = '/job/_work/cf/' + args.side + '/source.cf'
        linux_native = '/job/_work/native-' + args.side
        engine = create('engine', args.engine_image,
                        ['-i', 'PATH='+binary.rsplit('/',1)[0], 'RAYON_NUM_THREADS='+str(config.get('native_workers',2)), binary, 'cf', 'export', linux_cf,
                         linux_native + '/tree/xml', '--platform', profile['platform_profile'],
                         '--compression', 'raw-deflate', '--fail-on-opaque'], source_bind=True)
        after, raw = stage('linux-native', lambda: start(engine, 'native', {0, 2}))
        report = read_engine_report(root / 'native.stdout', root / 'native.stderr')
        require(fact(cf) == before, 'Host CF changed during native')
        remove(engine)
        # Fresh Linux namespace receipt authored from this actual engine evidence.
        # No old receipt is translated and the engine container is not the helper.
        native_receipt = {'schema_version': 1, 'runtime_backend': 'docker',
            'status': 'ENGINE_EXPORT_OK_VERIFICATION_PENDING' if raw == 0 else 'FAILED',
            'provider': config['db']['provider'], 'side': args.side,
            'source': {'path': linux_cf, **before, 'sha256_after': before['sha256']},
            'engine': {'image_id': args.engine_image, 'binary': binary,
                       **{key: profile[key] for key in ('platform_profile', 'xml_version', 'profile_id')}},
            'profile': profile, 'profile_receipt': {'path': '/job/_work/profiles/' + args.side + '.json',
                                                    'sha256': fact(root / 'linux-profile.json')['sha256']},
            'native_xml': linux_native + '/tree/xml',
            'process': {'docker_start_exit': raw, 'container_state': after['State']},
            'container_id': engine['cid'], 'container_removed': engine['removed'],
            'native_wrapper_exit_projection': {'value': 0 if raw == 0 else 1,
                 'kind': 'ADAPTER_POLICY_PROJECTION_NOT_PROCESS_EXIT',
                 'input_raw_engine_exit': raw, 'producer_sha256': fact(__file__)['sha256']},
            'summary': report_summary(report),
            'producer_sha256': fact(__file__)['sha256'],
            'host_evidence': {'container_after': fact(root / 'native-container-after.json'),
                              'container_before': fact(root / 'native-container-before.json'),
                              'raw_stdout': fact(root / 'native.stdout'),
                              'raw_stderr': fact(root / 'native.stderr')},
            'verification': 'NOT_RUN'}
        save(root / 'native-receipt.json', native_receipt)
        source = CFSource(cf)
        try:
            sizes = {name: source.catalog.entries[name].stored_size for name in source.names()}
        finally:
            source.close()
        save(root / 'native-classification.json', classify(native_receipt, report, sizes, native_receipt['native_wrapper_exit_projection']['value'], profile))
        helpers = create('helpers', args.helper_image, ['run', '--side', args.side, '--contract', '/contract.json'], source_bind=True)
        for host, target in ((root / 'native-receipt.json', 'receipt.json'),
                             (root / 'native.stdout', 'engine.stdout.json'),
                             (root / 'native.stderr', 'engine.stderr.json')):
            docker('cp', host, helpers['cid'] + ':' + linux_native + '/' + target)
        stage('linux-helpers', lambda: start(helpers, 'helpers', {0},float(config.get('python_seconds',2400))))

        def transfer():
            if side=='main' and config.get('side_scheduling') in ('transfer-overlap','verify-overlap'):
                from ..fast_pair import READY_SCHEMA
                # start() already observed helper exit0/Pid0. Marker opens
                # scheduling only; final XML/profile/CF verification is unchanged.
                closed=read(root/'helpers-container-after.json')['State']
                require(closed['Running'] is False and closed['ExitCode']==0 and closed['Pid']==0,
                        'Transfer readiness requires a closed successful helper')
                save_new(root/'transfer-ready.json',{'schema':READY_SCHEMA,'side':'main','nonce':nonce,
                    'status':'LINUX_HELPERS_CLOSED_READY_FOR_HOST_TRANSFER','cf':before,
                    'contract':fact(root/'contract.json'),'helper':helper_binding,
                    'helpers_after':fact(root/'helpers-container-after.json'),'ready_utc':utc()})
            end=time.monotonic()+float(config.get('fast_transport_seconds',2400))
            if config.get('docker_transfer','copy')=='stream':
                from .fast_stream import make_stream_owner,transfer_fast_side
                owner=make_stream_owner(config,side,journal,helper,helper_binding)
                remaining=min(end-time.monotonic(),args.budget_seconds-(time.monotonic()-overall))
                require(remaining>0,'Final stream phase deadline expired')
                transfer_fast_side(config,side,owner=owner,proof_root=root,output_side=product_root/side,
                    timeout=remaining,native=export_native,popen=subprocess.Popen,control_run=subprocess.run)
                journal['xml_transfer']='stream';journal['stream_transfer']=fact(root/'stream-transfer.json')
                return
            cp_out(helpers, '/job/' + args.side, product_root / args.side,seconds=end-time.monotonic())
            remaining_transfer=end-time.monotonic()
            require(remaining_transfer>0,'Final host transfer phase deadline expired')
            cp_out(helpers, '/job/linux-proof-' + args.side + '.json', root / 'linux-proof.json',seconds=remaining_transfer)
        stage('ready-tree-windows-transfer', transfer)
        remove(helpers)

        successful=True
        journal['status']='CANDIDATE_GENERATED_REQUIRES_HOST_VERIFICATION'
    except BaseException as error:
        journal['status'] = 'FAILED'
        journal['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        cleanup_phase = True
        cleanup_deadline = time.monotonic() + 45
        cleanup_errors = []
        for row in reversed(containers):
            if row['removed']:
                continue
            try:
                # Even a failed create response is resolved by this invocation's
                # persisted unique name/nonce; absence is not inferred from errors.
                names = docker('ps', '-a', '--format', '{{.Names}}', '--filter', 'name=^/' + row['name'] + '$').decode().split()
                if not names:
                    row['removed'] = True
                    continue
                require(names == [row['name']], 'Ambiguous cleanup name')
                remove(row)
            except BaseException as error:
                cleanup_errors.append(type(error).__name__ + ': ' + str(error))
        if cf_volume_create_attempted:
            try:
                info=json.loads(docker('volume','inspect',cf_volume))[0]
                require(info['Name']==cf_volume and info['Labels'].get(label)==nonce
                        and info['Labels'].get('onecdb2src.fast.volume_role')=='cf','CF cleanup owner/role mismatch')
                journal['cf_volume_existence']='OWNED_CONFIRMED'
                if successful and not cleanup_errors:
                    require(not docker('ps','-a','-q','--filter','volume='+cf_volume).strip(),'CF volume still attached')
                    docker('volume','rm',cf_volume)
                    try:docker('volume','inspect',cf_volume)
                    except DockerFailure as error:
                        require(missing_volume(error,cf_volume),'CF removal absence UNKNOWN')
                        journal['cf_volume_absence_confirmation']=absence_evidence(error,cf_volume)
                    else:raise ValueError('Own CF volume survives removal')
                    journal['cf_volume_removed']=True
                else:journal['cf_volume_retained_for_diagnosis']=True
            except BaseException as error:
                if missing_volume(error,cf_volume):
                    journal['cf_volume_existence']='ABSENT_CONFIRMED'
                    journal['cf_volume_absence_confirmation']=absence_evidence(error,cf_volume)
                else:
                    journal['cf_volume_existence']='UNKNOWN'
                    cleanup_errors.append(type(error).__name__+': '+str(error))
        volume_observed = None
        if volume_create_attempted:
            try:
                volume_observed = json.loads(docker('volume', 'inspect', volume))[0]
                require(volume_observed['Name'] == volume and volume_observed['Labels'].get(label) == nonce,
                        'Cleanup volume ownership mismatch')
                journal['volume_existence'] = 'OWNED_CONFIRMED'
            except BaseException as error:
                # Only the complete Docker missing-volume diagnostic is absence;
                # daemon/permission errors and foreign labels remain UNKNOWN.
                message = str(error)
                if missing_volume(error,volume):
                    journal['volume_existence'] = 'ABSENT_CONFIRMED'
                    journal['volume_absence_confirmation']=absence_evidence(error,volume)
                else:
                    journal['volume_existence'] = 'UNKNOWN'
                    cleanup_errors.append(type(error).__name__ + ': ' + message)
                    volume_observed = None
        if volume_observed is not None and successful and not cleanup_errors:
            try:
                metadata = json.loads(docker('volume', 'inspect', volume))[0]
                require(metadata['Name'] == volume and metadata['Labels'].get(label) == nonce, 'Owned volume mismatch')
                require(not docker('ps', '-a', '-q', '--filter', 'volume=' + volume).strip(), 'Volume still attached')
                docker('volume', 'rm', volume)
                try:
                    docker('volume', 'inspect', volume)
                except RuntimeError as error:
                    require(missing_volume(error,volume),
                            'Volume removal absence UNKNOWN: ' + str(error))
                    journal['volume_absence_confirmation']=absence_evidence(error,volume)
                else:
                    raise ValueError('Owned volume survives removal')
                journal['volume_removed'] = True
            except BaseException as error:
                cleanup_errors.append(type(error).__name__ + ': ' + str(error))
        else:
            journal['volume_retained_for_diagnosis'] = volume_observed is not None
        journal.update(finished_utc=utc(), seconds=time.monotonic() - overall, cleanup_errors=cleanup_errors)
        if cleanup_errors:
            journal['status'] = 'FAILED_CLEANUP_UNCONFIRMED'
        snapshot()
        if cleanup_errors:
            raise RuntimeError('Own cleanup unconfirmed; see durable result.json')

    return journal


def verify_fast_side(config,side,workers=4):
    from .namespace_result import verify_fast_side as verify
    return verify(config,side,workers=workers)


def require_pair_shutdown(config,product_root):
    """A failed export may be cleaned only after the outer producer is closed.

    Export success is deliberately not required: timeout/cancellation must also
    recover owned containers, but unknown process closure must never do so.
    """
    if config.get('side_scheduling','sequential') not in ('transfer-overlap','verify-overlap'):return None
    job=product_root/'_work/jobs/fast-pair.json'
    activity=[job,job.with_suffix('.stdout'),job.with_suffix('.stderr'),
              product_root/'_work/fast-pair/result.json']
    activity.extend(product_root/'_work'/('fast-'+side)/'contract.json' for side in ('main','vendor'))
    if not any(path.exists() for path in activity):return None
    require(job.is_file() and job.stat().st_size<=2*1024*1024,'Pair shutdown receipt missing/oversized; cleanup refused')
    value=read(job)
    require(value.get('job_handle_closed') is True and value.get('observation_status')=='OBSERVED'
            and value.get('surviving_pids')==[] and value.get('cleanup_errors')==[]
            and value.get('io_errors')==[]
            and value.get('pipes_closed')=={'stdin':True,'stdout':True,'stderr':True},
            'Pair producer closure UNKNOWN; cleanup refused')
    if value.get('backend')=='linux-posix':
        require(value.get('processgroups_closed') is True,'Pair process groups closure UNKNOWN; cleanup refused')
    else:
        require(value.get('drains_joined') is True and value.get('bootstrap_survived') is False
                and value.get('target_streams_closed')=={'stdout':True,'stderr':True},
                'Pair process/stream closure UNKNOWN; cleanup refused')
    return {'status':'OUTER_PAIR_PRODUCER_CLOSED','receipt':fact(job)}


def cleanup_fast_owned(config):
    """Recover only this output's journaled resources after outer worker failure.

    No global enumeration/prune; each name is nonce-bound before inspect/remove.
    A daemon error is UNKNOWN, never confirmation of absence. Inner failed trial
    volumes retained for diagnosis can be removed here by the owning CLI finally.
    """
    product_root=Path(config['root']).resolve(strict=True)
    shutdown=require_pair_shutdown(config,product_root)
    if not any((product_root/'_work'/('fast-'+side)).exists() for side in ('main','vendor')):
        return {'status':'CONFIRMED_OWN_FAST_RESOURCES_ABSENT','confirmed':True,'sides':{},'errors':[]}
    _,binding=load_helper_manifest(config)
    engine=config['runtime']['image_id'];helper=binding['selected_image_id']
    export_native.configure(config.get('docker_context'),config.get('docker_socket'))
    env=export_native.docker_environment()
    deadline=time.monotonic()+float(config.get('fast_cleanup_seconds',45))
    proof={'status':'RECOVERING','confirmed':False,'sides':{},'errors':[],'pair_shutdown':shutdown}
    def docker(*parts):
        remaining=deadline-time.monotonic()
        require(remaining>0,'Outer fast cleanup deadline expired')
        done=subprocess.run(export_native.docker_argv(*parts),capture_output=True,env=env,timeout=remaining)
        if done.returncode:raise DockerFailure(parts,done.returncode,done.stderr.decode('utf-8',errors='replace'))
        return done.stdout
    if export_native.DOCKER_SOCKET:
        context=export_native.context_record();selected=None
    else:
        selected=export_native.DOCKER_CONTEXT or docker('context','show').decode().strip()
        context=json.loads(docker('context','inspect',selected))[0]
    export_native.daemon_policy(context,json.loads(docker('info','--format','{{json .}}')))
    if selected:export_native.configure(context=selected)
    # Recompute sanitized environment after locking the selected local endpoint.
    env=export_native.docker_environment()
    for side in ('main','vendor'):
        directory=product_root/'_work'/('fast-'+side)
        if not directory.exists():continue
        record={'status':'UNKNOWN','containers':[],'volumes':[]}
        proof['sides'][side]=record
        try:
            result=read(directory/'result.json');contract=read(directory/'contract.json')
            nonce=result['nonce'];volume='onecdb2src-fast-'+nonce
            require(re.fullmatch('[a-f0-9]{32}',nonce) and result['volume']==volume
                    and contract['nonce']==nonce and contract['side']==side
                    and contract['schema']==CONTRACT_SCHEMA and contract['engine_image']==engine
                    and contract['helper_manifest_binding']==binding,'Outer cleanup owner/runtime binding changed')
            source=result['source_cf']
            require(source['host_path']==str(product_root/'_work/cf'/side/'source.cf')
                    and type(source['bytes']) is int and source['bytes']>0
                    and re.fullmatch('[a-f0-9]{64}',source['sha256'])
                    and contract['cf']=={key:source[key] for key in ('bytes','sha256')}
                    and contract['provider']==config['db']['provider'], 'Outer cleanup output/CF/provider binding changed')
            method=result.get('cf_stage_method','copy')
            require(method in ('copy','bind-copy') and method==config.get('docker_cf_transfer','copy'),'Outer CF staging method changed')
            rows=result['containers']
            require(type(rows) is list and len(rows)<=6 and len({row['role'] for row in rows})==len(rows),
                    'Ambiguous owned cleanup roles')
            for row in reversed(rows):
                role=row['role'];name=volume+'-'+role
                require(role not in (('cf-stage',) if method=='bind-copy' else ('cf-copy',)),'Unexpected CF staging cleanup role')
                require(role in ('init','owner-init','prepare','engine','helpers','cf-stage','cf-copy')
                        and row['name']==name and row['image']==(engine if role in ('init','engine','cf-stage') else helper),
                        'Unexpected cleanup role/name/image')
                names=docker('ps','-a','--format','{{.Names}}','--filter','name=^/'+name+'$').decode().split()
                if not names:
                    record['containers'].append({'name':name,'status':'ABSENT_CONFIRMED'})
                    continue
                require(names==[name],'Ambiguous targeted cleanup name')
                values=json.loads(docker('inspect',name));require(len(values)==1,'Ambiguous targeted inspect')
                value=values[0]
                require(value['Name']=='/'+name and value['Config']['Labels'].get('onecdb2src.fast.nonce')==nonce
                        and value['Config']['Image']==row['image']
                        and (not row.get('cid') or row['cid']==value['Id']), 'Foreign container cleanup refused')
                mounts=value['Mounts']
                own_mounts=[mount for mount in mounts if mount['Type']=='volume']
                require(own_mounts and all(mount['Name'] in (volume,volume+'-cf') for mount in own_mounts),
                        'Foreign volume cleanup refused')
                if role in ('cf-stage','cf-copy'):
                    require(len(mounts)==(2 if role=='cf-copy' else 1) and own_mounts[0]['Name']==volume+'-cf'
                            and own_mounts[0]['Destination']=='/cf' and own_mounts[0]['RW'] is True,
                            'CF staging cleanup mount differs')
                    if role=='cf-copy':
                        sources=[m for m in mounts if m['Destination']=='/source.cf']
                        require(len(sources)==1 and sources[0]['Type']=='bind' and sources[0]['RW'] is False
                            and row.get('source_bind_request')==source['host_path']
                            and row.get('source_bind_source',sources[0]['Source'])==sources[0]['Source'],'CF copy cleanup source differs')
                else:
                    jobs=[mount for mount in mounts if mount['Destination']=='/job']
                    require(len(jobs)==1 and jobs[0]['Name']==volume and jobs[0]['RW'] is True,
                            'Owned cleanup job mount differs')
                docker('rm','--force',value['Id'])
                require(not docker('ps','-a','-q','--no-trunc','--filter','name=^/'+name+'$').strip(),
                        'Owned container removal not confirmed')
                record['containers'].append({'name':name,'cid':value['Id'],'status':'REMOVED_ABSENCE_CONFIRMED'})
            for name,attempted,role in ((volume+'-cf',result.get('cf_volume_create_attempted'), 'cf'),
                                         (volume,result.get('volume_create_attempted'),'job')):
                if not attempted:continue
                try:
                    values=json.loads(docker('volume','inspect',name));require(len(values)==1,'Ambiguous volume inspect')
                except DockerFailure as error:
                    require(missing_volume(error,name),'Outer volume absence UNKNOWN')
                    record['volumes'].append(absence_evidence(error,name));continue
                value=values[0]
                require(value['Name']==name and value['Labels'].get('onecdb2src.fast.nonce')==nonce,
                        'Foreign volume owner cleanup refused')
                if role=='cf':
                    require(value['Labels'].get('onecdb2src.fast.volume_role')=='cf','CF volume role cleanup refused')
                require(not docker('ps','-a','-q','--filter','volume='+name).strip(),'Own volume still attached')
                docker('volume','rm',name)
                try:docker('volume','inspect',name)
                except DockerFailure as error:
                    require(missing_volume(error,name),'Removed outer volume absence UNKNOWN')
                    record['volumes'].append(absence_evidence(error,name))
                else:raise ValueError('Owned volume survives outer cleanup')
            record['status']='CONFIRMED_OWN_FAST_RESOURCES_ABSENT'
        except BaseException as error:
            record['error']=type(error).__name__+': '+str(error)
            proof['errors'].append({'side':side,'error':record['error']})
    proof['confirmed']=not proof['errors']
    proof['status']='CONFIRMED_OWN_FAST_RESOURCES_ABSENT' if proof['confirmed'] else 'UNKNOWN_OWN_FAST_CLEANUP'
    save(product_root/'_work/fast-cleanup-recovery.json',proof)
    if proof['errors']:raise RuntimeError('Own fast cleanup UNKNOWN; see _work/fast-cleanup-recovery.json')
    return proof
