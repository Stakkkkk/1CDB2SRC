"""Portable synthetic Docker protocol. No Docker process or real engine is run."""
import atexit,copy,hashlib,io,json,os,shutil,socket,subprocess,tarfile,tempfile
from pathlib import Path
from onecdb2src import profiles
from onecdb2src.nativecf.cf_source import CFSource
from onecdb2src.xml import fast_docker as trial
from fast_cf_fixture import fixture_cf

_TEMP=tempfile.TemporaryDirectory(prefix='1cdb2src-fast-fixture-')
atexit.register(_TEMP.cleanup)
CF=fixture_cf(Path(_TEMP.name)/'synthetic.cf')
ENGINE='sha256:'+'a'*64
HELPER='sha256:'+'b'*64
UNIX_SOCKET=str(Path(_TEMP.name)/'fake-docker.sock')
if os.name!='nt':
    _SOCKET=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    _SOCKET.bind(UNIX_SOCKET)
    atexit.register(_SOCKET.close)

class FakeDocker:
    def __init__(self, directory, output, fault=None):
        self.directory, self.output, self.fault = directory, output, fault
        self.containers, self.volumes, self.calls = {}, {}, []
        self.job = directory / 'fake-volume'
        self.job.mkdir()
        self.cf_store = directory / 'fake-cf-volume'
        self.cf_store.mkdir()
        self.tar_members = []
        self.clock = 0.0
        self.native_started = 0
        self.foreign = 'foreign-untouched'
        self.containers[self.foreign] = {'Id': 'f' * 64, 'Name': '/' + self.foreign,
            'Config': {'Labels': {'foreign': 'yes'}, 'Image': HELPER},
            'State': {'Running': True}, 'HostConfig': {'Memory': 0}}

    def profile(self):
        value = profiles.select(CF, 'auto')
        value['cf_path'] = '/job/_work/cf/main/source.cf'
        value['profile_id'] = profiles._id(value)
        return value

    def contract(self):
        return trial.read(self.output / 'contract.json')

    def prepare(self):
        profile = self.profile()
        trial.save(self.job / '_work/profiles/main.json', profile)
        namespace = {'schema': 'BD029B_LINUX_NAMESPACE_V1',
            'contract_sha256': trial.fact(self.output / 'contract.json')['sha256'],
            'cf_path': '/job/_work/cf/main/source.cf', 'profile_path': '/job/_work/profiles/main.json',
            'profile_sha256': trial.fact(self.job / '_work/profiles/main.json')['sha256'],
            'profile': profile, 'historical_receipts_modified': False}
        if self.fault == 'namespace':
            namespace['cf_path'] = '/foreign/source.cf'
        if self.fault == 'namespace-schema':
            namespace['schema'] = 'UNKNOWN'
        if self.fault == 'namespace-profile-hash':
            namespace['profile_sha256'] = '0' * 64
        trial.save(self.job / 'namespace-main.json', namespace)

    def report(self):
        source = CFSource(CF)
        try:
            rows = [{'logical_name': name, 'disposition': 'supported',
                     'packed_bytes': source.catalog.entries[name].stored_size, 'part_count': 1,
                     'outputs': []} for name in source.names()]
        finally:
            source.close()
        version = self.profile()['xml_version']
        return {'ok': True, 'command': 'export', 'source_version': version, 'errors': [],
            'export': {'source_version': version, 'files_written': 3, 'storage': {
                'entries': rows, 'supported': len(rows), 'opaque': 0, 'failed': 0,
                'logical_entries': len(rows), 'physical_entries': len(rows)}}}

    def helpers(self):
        output = self.job / 'main'
        xml = output / 'xml'
        xml.mkdir(parents=True)
        version = self.profile()['xml_version']
        fixture = {'Configuration.xml': '<MetaDataObject xmlns="http://v8.1c.ru/8.3/MDClasses" version="' + version + '"><Configuration/></MetaDataObject>',
                   'ConfigDumpInfo.xml': '<ConfigDumpInfo xmlns="http://v8.1c.ru/8.3/xcf/dumpinfo" version="' + version + '"/>',
                   'Module.bsl': '// Synthetic protocol test fixture only\n'}
        manifest = []
        for name, text in fixture.items():
            file = xml / name
            file.write_text(text, encoding='utf-8')
            manifest.append({'path': name, **trial.fact(file)})
        (output / 'files.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in manifest), encoding='utf-8')
        native = trial.read(self.job / '_work/native-main/receipt.json')
        assembly = {'status': 'CANDIDATE_POSTGEN_VERIFICATION_REQUIRED', 'files': 3,
            'manifest_sha256': trial.fact(output / 'files.jsonl')['sha256'], 'profile': self.profile(),
            'profile_receipt': native['profile_receipt'], 'cf_sha256': self.contract()['cf']['sha256'],
            'unaccepted_opaque_entries': []}
        if self.fault == 'mapped-profile':
            assembly['profile']['cf_path'] = str(CF)
            assembly['profile']['profile_id'] = profiles._id(assembly['profile'])
        trial.save(output / 'receipt.json', assembly)
        proof = {'schema': 'BD029B_LINUX_HELPERS_V1', 'status': 'CANDIDATE_WINDOWS_READBACK_REQUIRED',
            'oracle_inputs': [], 'memory_controls': False, 'transfer': 'NOT_RUN', 'windows_readback': 'NOT_RUN',
            'contract_sha256': trial.fact(self.output / 'contract.json')['sha256'],
            'native_receipt_sha256': trial.fact(self.job / '_work/native-main/receipt.json')['sha256'],
            'assembly_receipt_sha256': trial.fact(output / 'receipt.json')['sha256'],
            'files_manifest_sha256': trial.fact(output / 'files.jsonl')['sha256'],
            'helper_sha256': self.contract()['helper_sha256'], 'cf_sha256': self.contract()['cf']['sha256'],
            'native_policy': trial.read(self.output / 'native-classification.json')}
        if self.fault == 'helper-pin':
            proof['helper_sha256'] = '0' * 64
        if self.fault == 'native-outcome':
            proof['native_policy']['status'] = 'invented'
        if self.fault == 'native-raw-evidence':
            (self.output / 'native.stderr').write_text('{}', encoding='utf-8')
        if self.fault == 'native-state-evidence':
            state = trial.read(self.output / 'native-container-after.json')
            state['State']['Running'] = True
            trial.save(self.output / 'native-container-after.json', state)
        trial.save(self.job / 'linux-helpers-main.json', proof)

    def lookup(self, value):
        return self.containers[value] if value in self.containers else next(x for x in self.containers.values() if x['Id'] == value)

    def __call__(self, argv, **kwargs):
        self.clock += .01
        argv = list(map(str, argv))
        self.calls.append((argv, kwargs))
        require_clean = {'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'}
        assert not require_clean.intersection(key.upper() for key in kwargs.get('env', {}))
        assert kwargs['timeout'] > 0
        command = argv[1:]
        if command[:1] in (['--context'], ['--host']):
            command = command[2:]
        result, code, diagnostic = b'', 0, b''
        if command[:2] == ['context', 'inspect']:
            endpoint = 'tcp://foreign:2375' if self.fault == 'remote-daemon' else ('npipe:////./pipe/dockerDesktopLinuxEngine' if os.name=='nt' else 'unix://'+UNIX_SOCKET)
            result = json.dumps([{'Name': 'desktop-linux', 'Endpoints': {'docker': {'Host': endpoint}}}]).encode()
        elif command[:1] == ['info']:
            result = json.dumps({'ID': 'fake-local', 'Name': 'docker-desktop', 'OSType': 'linux',
                                 'Architecture': 'amd64', 'ServerVersion': 'fake'}).encode()
        elif command[:2] == ['image', 'inspect']:
            result = json.dumps([{'Id': command[2], 'Architecture': 'amd64', 'Config': {}}]).encode()
        elif command[:2] == ['volume', 'create']:
            name = command[-1]
            labels = dict(command[index+1].split('=',1) for index,value in enumerate(command) if value=='--label')
            label = command[command.index('--label') + 1].split('=', 1)
            self.volumes[name] = {'Name': name, 'Labels': labels}
            if name.endswith('-cf') and self.fault == 'cf-create-uncertain':
                raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
            if name.endswith('-cf') and self.fault == 'cf-volume-foreign':
                self.volumes[name]['Labels'][label[0]] = 'foreign'
            if name.endswith('-cf') and self.fault == 'cf-volume-role':
                self.volumes[name]['Labels']['onecdb2src.fast.volume_role'] = 'job'
            if self.fault == 'uncertain-volume-create':
                raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
            if self.fault == 'foreign-volume':
                self.volumes[name]['Labels'][label[0]] = 'foreign'
            result = name.encode()
        elif command[:2] == ['volume', 'inspect']:
            if command[2] not in self.volumes:
                code = 1
                diagnostic = ('daemon unavailable' if command[2].endswith('-cf') and self.fault=='cf-absence-unknown'
                              else 'Error response from daemon: no such volume: ' + command[2]).encode()
            else:
                result = json.dumps([self.volumes[command[2]]]).encode()
        elif command[:2] == ['volume', 'rm']:
            del self.volumes[command[2]]
        elif command[:1] == ['create']:
            name = command[command.index('--name') + 1]
            label = command[command.index('--label') + 1].split('=', 1)
            image = HELPER if HELPER in command else ENGINE
            cid = hashlib.sha256(name.encode()).hexdigest()
            self.containers[name] = {'Id': cid, 'Name': '/' + name,
                'Config': {'Labels': {label[0]: label[1]}, 'Image': image, 'User': command[command.index('--user') + 1]},
                'HostConfig': {'Memory': 0, 'ReadonlyRootfs': True, 'NetworkMode': 'none', 'NanoCpus': 2 * 10**9,
                               'CapDrop': ['ALL'], 'CapAdd': ['CHOWN'] if '--cap-add' in command else [],
                               'SecurityOpt': ['no-new-privileges']},
                'Mounts': [{'Destination': '/job', 'RW': True, 'Type': 'volume', 'Name': next(iter(self.volumes))}],
                'State': {'Running': False, 'ExitCode': 0, 'OOMKilled': False, 'Error': ''}}
            if any('target=/job/_work/cf/main/source.cf,readonly' in item for item in command):
                self.containers[name]['Mounts'].append({'Destination': '/job/_work/cf/main/source.cf', 'RW': False, 'Type': 'bind'})
            if name.endswith('-cf-stage'):
                self.containers[name]['Mounts']=[{'Destination':'/cf','RW':True,'Type':'volume',
                    'Name':next(item for item in self.volumes if item.endswith('-cf'))}]
            if any('target=/job/_work/cf/main,readonly,volume-nocopy' in item for item in command):
                self.containers[name]['Mounts'].append({'Destination':'/job/_work/cf/main','RW':False,'Type':'volume',
                    'Name':next(item for item in self.volumes if item.endswith('-cf'))})
            result = cid.encode()
        elif command[:1] == ['inspect']:
            value = copy.deepcopy(self.lookup(command[1]))
            if self.fault == 'ownership-swapped' and value['Name'].endswith('-prepare'):
                value['Config']['Labels'] = {'foreign': 'yes'}
            if self.fault == 'foreign-mount' and value['Name'].endswith('-prepare'):
                value['Mounts'][0]['Name'] = 'foreign-volume'
            if self.fault == 'root-user' and value['Name'].endswith('-prepare'):
                value['Config']['User'] = '0:0'
            if self.fault == 'init-extra-caps' and value['Name'].endswith('-owner-init'):
                value['HostConfig']['CapAdd'] = ['CHOWN', 'DAC_OVERRIDE']
            if self.fault == 'init-cf-mount' and value['Name'].endswith('-owner-init'):
                value['Mounts'].append({'Destination': '/foreign', 'Type': 'bind', 'RW': False})
            if self.fault in ('cf-mount-foreign','cf-mount-writable','cf-mount-bind') and value['Name'].endswith('-prepare'):
                value['Mounts'][-1]['Name']='foreign-cf' if self.fault=='cf-mount-foreign' else value['Mounts'][-1]['Name']
                value['Mounts'][-1]['RW']=self.fault=='cf-mount-writable'
                if self.fault=='cf-mount-bind':value['Mounts'][-1]['Type']='bind'
            result = json.dumps([value]).encode()
        elif command[:1] == ['start']:
            row = self.lookup(command[-1])
            role = 'owner-init' if row['Name'].endswith('-owner-init') else row['Name'].rsplit('-', 1)[1]
            if role == 'owner-init':
                nonce = row['Config']['Labels']['onecdb2src.bd027.nonce'] if 'onecdb2src.bd027.nonce' in row['Config']['Labels'] else next(iter(row['Config']['Labels'].values()))
                if self.fault == 'init-marker-mismatch':
                    row['State']['ExitCode'] = 1
                    return subprocess.CompletedProcess(argv, 1, b'', b'ownership marker mismatch')
                proof = {'schema': 'BD029W2_JOB_ROOT_OWNER_V1', 'nonce': nonce, 'target': '/job', 'recursive': False,
                    'before': {'uid': 0, 'gid': 0, 'mode': '0o755'},
                    'after': {'uid': 65532, 'gid': 65532, 'mode': '0o755'}, 'children_verified': ['.ownership', '_work']}
                if self.fault == 'init-bad-proof':
                    proof['after']['uid'] = 0
                kwargs['stdout'].write(json.dumps(proof).encode())
            elif role == 'prepare':
                if self.fault == 'cancel':
                    raise KeyboardInterrupt()
                if self.fault == 'budget':
                    self.clock = 20
                if any(mount['Destination']=='/job/_work/cf/main' for mount in row['Mounts']):
                    if trial.fact(self.cf_store/'source.cf') != self.contract()['cf']:
                        row['State']['ExitCode']=1
                        return subprocess.CompletedProcess(argv,1,b'',b'actual staged CF hash mismatch')
                self.prepare()
            elif role == 'engine':
                self.native_started += 1
                if self.fault == 'native-timeout':
                    row['State']['Running'] = True
                    raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
                kwargs['stderr'].write(json.dumps(self.report()).encode())
                if self.fault == 'writer-running':
                    row['State']['Running'] = True
            elif role == 'helpers':
                self.helpers()
        elif command[:1] == ['cp']:
            if '-a' in command:
                # Simulate the actual daemon boundary observed by BD029U:
                # readonly container rootfs refuses destination /; own /job is RW.
                if command[-1].endswith(':/'):
                    return subprocess.CompletedProcess(argv, 1, b'', b'Error response from daemon: container rootfs is marked read-only')
                assert command[-1].endswith(':/job'), 'Tiny TAR must target only the owned volume root'
                with tarfile.open(fileobj=io.BytesIO(kwargs['input'])) as archive:
                    self.tar_members = archive.getmembers()
                    assert self.tar_members[0].name == '.' and self.tar_members[0].isdir()
                    for member in self.tar_members:
                        assert member.uid == member.gid == 65532 and not member.issym() and not member.islnk()
                        assert member.name == '.' or (not Path(member.name).is_absolute()
                            and '..' not in Path(member.name).parts and 'job' not in Path(member.name).parts)
                        path = self.job / member.name
                        if member.isdir():
                            path.mkdir(parents=True, exist_ok=True)
                        else:
                            path.write_bytes(archive.extractfile(member).read())
            elif ':' in command[1] and not Path(command[1]).exists():
                _, source = command[1].split(':', 1)
                source = self.job / Path(source).relative_to('/job')
                target = Path(command[2])
                shutil.copytree(source, target) if source.is_dir() else shutil.copyfile(source, target)
                if self.fault == 'readback-corrupt' and target.name == 'main':
                    (target / 'xml/Module.bsl').write_text('// changed', encoding='utf-8')
            else:
                _, target = command[2].split(':', 1)
                if target=='/cf/source.cf':
                    data=Path(command[1]).read_bytes()
                    if self.fault=='cf-copy-failure':
                        (self.cf_store/'source.cf').write_bytes(data[:20])
                        return subprocess.CompletedProcess(argv,1,b'',b'CF copy failed')
                    (self.cf_store/'source.cf').write_bytes(data if self.fault!='cf-content-corrupt' else data+b'changed')
                else:
                    shutil.copyfile(command[1], self.job / Path(target).relative_to('/job'))
        elif command[:1] == ['rm']:
            row = self.lookup(command[-1])
            del self.containers[row['Name'][1:]]
        elif command[:1] == ['ps']:
            filt = command[command.index('--filter') + 1]
            if filt.startswith('name=^/'):
                name = filt[len('name=^/'):-1]
                if name in self.containers:
                    result = (name if '--format' in command else self.containers[name]['Id']).encode()
            elif filt.startswith('volume='):
                result = b''
        else:
            raise AssertionError('Unexpected fake Docker call ' + str(command))
        return subprocess.CompletedProcess(argv, code, result, diagnostic)


