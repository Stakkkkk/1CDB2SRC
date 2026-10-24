"""Readable-source opt-in staging; real neutral file bytes and fake Docker only."""
import hashlib
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack
from types import SimpleNamespace
import stat

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from onecdb2src.xml import cf_copy as copy
from onecdb2src import cli
import test_fast_docker as protocol


class CopyDocker(protocol.ProductDocker):
    def __call__(self, argv, **kwargs):
        words = list(map(str, argv))[1:]
        if words[:1] in (['--context'], ['--host']):
            words = words[2:]
        value = super().__call__(argv, **kwargs)
        if words[:1] == ['create'] and words[words.index('--name') + 1].endswith('-cf-copy') and self.fault == 'copy-create-uncertain':
            raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
        if words[:1] == ['inspect']:
            rows = json.loads(value.stdout)
            if rows[0]['Name'].endswith('-cf-copy'):
                if self.fault == 'copy-caps':
                    rows[0]['HostConfig']['CapAdd'].append('DAC_READ_SEARCH')
                if self.fault == 'copy-source-rw':
                    rows[0]['Mounts'][1]['RW'] = True
            value = subprocess.CompletedProcess(argv, 0, json.dumps(rows).encode(), b'')
        if words[:1] == ['start'] and self.lookup(words[-1])['Name'].endswith('-cf-copy'):
            if self.fault == 'copy-timeout':
                raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
            if self.fault == 'copy-unreadable':
                return subprocess.CompletedProcess(argv, 1, b'', b'exact source not readable; choose copy')
            source = next(m['Source'] for m in self.lookup(words[-1])['Mounts'] if m['Destination'] == '/source.cf')
            expected = self.contract()['cf']
            proof = copy.copy_file(source, self.cf_store / 'source.cf', expected)
            proof.update(schema='1CDB2SRC_CF_BIND_COPY_V1', status='CF_COPY_COMPLETE',
                nonce=self.contract()['nonce'], side=self.side, expected=expected,
                source='/source.cf', target='/cf/source.cf', source_permissions_changed=False,
                memory_controls=False,
                normalization={'uid':65532,'gid':65532,'file_mode':'0o444','directory_mode':'0o755'})
            if self.fault == 'copy-hash':
                proof['fresh_target_readback'] = expected | {'sha256': '0' * 64}
            kwargs['stdout'].write(json.dumps(proof).encode())
        return value


class CopyCoreTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = root / 'input.cf'
        source.write_bytes(bytes(range(256)) * 51)
        output = root / 'own-volume'
        output.mkdir()
        expected = {'bytes': source.stat().st_size, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
        return source, output / 'source.cf', expected

    def test_real_bytes_closed_readback_and_partial_write_progress(self):
        source, target, expected = self.fixture()
        before = copy.identity(source.stat())
        proof = copy.copy_file(source, target, expected, write=lambda fd, data: os.write(fd, data[:19]))
        self.assertEqual(proof['copied'], expected)
        self.assertEqual(proof['fresh_target_readback'], expected)
        self.assertEqual(source.read_bytes(), target.read_bytes())
        self.assertEqual(before, copy.identity(source.stat()))

    def test_existing_target_wrong_hash_and_nonprogress_refuse(self):
        for fault in ('existing', 'hash', 'write-zero'):
            with self.subTest(fault=fault):
                source, target, expected = self.fixture()
                if fault == 'existing':
                    target.write_bytes(b'preserve')
                if fault == 'hash':
                    expected['sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    copy.copy_file(source, target, expected,
                        **({'write': lambda fd, data: 0} if fault == 'write-zero' else {}))
                if fault == 'existing':
                    self.assertEqual(target.read_bytes(), b'preserve')

    def test_source_unreadable_and_source_mutation_refuse(self):
        source, target, expected = self.fixture()
        original = os.open
        def deny(path, *args, **kwargs):
            if Path(path) == source:
                raise PermissionError('neutral source access denied')
            return original(path, *args, **kwargs)
        with patch.object(copy.os, 'open', deny), self.assertRaises(PermissionError):
            copy.copy_file(source, target, expected)
        self.assertFalse(target.exists())
        changed = []
        def mutate(fd, data):
            result = os.write(fd, data)
            if not changed:
                source.write_bytes(source.read_bytes() + b'changed')
                changed.append(True)
            return result
        with self.assertRaises(ValueError):
            copy.copy_file(source, target, expected, write=mutate)

    def test_unchanged_unicode_help_report_and_password_literals(self):
        source = Path(cli.__file__).read_text(encoding='utf8')
        values = sorted(node.value for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and any(ord(c) > 127 for c in node.value))
        # Frozen original UTF-8 literal inventory, including progress/report/password.
        added='Перекрыть передачу основной XML обработкой поставщика; только fast Docker stream'
        self.assertEqual(cli.parser()._option_string_actions['--side-scheduling'].help,added)
        self.assertEqual(values.count(added),1);values.remove(added)
        final_help='Проверять две готовые конфигурации одновременно; только fast, общий бюджет 8 потоков (2+6)'
        self.assertEqual(cli.parser()._option_string_actions['--final-verification'].help,final_help)
        self.assertEqual(values.count(final_help),1);values.remove(final_help)
        self.assertEqual(len(values), 39)
        self.assertEqual(hashlib.sha256(json.dumps(values, ensure_ascii=True).encode()).hexdigest(),
            '7af231c2ab1b1137851a1c19c252e12d3c0d9cca264d8188ce5ab24de5a0f5d3')
        self.assertEqual(cli.parser().description,
            'MS SQL/PostgreSQL \u2192 main.cf/vendor.cf + XML, \u0431\u0435\u0437 \u043f\u043b\u0430\u0442\u0444\u043e\u0440\u043c\u044b 1\u0421')
        self.assertIn('\u041f\u0430\u0440\u043e\u043b\u044c \u0421\u0423\u0411\u0414: ', values)
        self.assertIn(cli.parser().description, cli.parser().format_help())

    def test_cli_copy_default_and_bind_copy_scope(self):
        base = ['--provider','mssql','--host','localhost','--database','Neutral',
                '--supplier','Neutral','--output','neutral-output']
        args = cli.parser().parse_args(base)
        self.assertEqual(args.docker_cf_transfer, 'copy')
        cli.validate_modes(args)
        for extra in [[], ['--runtime','native']]:
            with self.assertRaises(ValueError):
                cli.validate_modes(cli.parser().parse_args(base + extra + ['--docker-cf-transfer','bind-copy']))
        cli.validate_modes(cli.parser().parse_args(base + ['--docker-mode','fast','--assembly-mode','adopt','--docker-cf-transfer','bind-copy']))

    def test_hardlinked_source_refused_without_target(self):
        source, target, expected = self.fixture()
        try:
            os.link(source, source.with_suffix('.alias'))
        except OSError as error:
            self.skipTest('Host filesystem cannot create neutral hardlink: ' + type(error).__name__)
        with self.assertRaisesRegex(ValueError, 'regular non-link'):
            copy.copy_file(source, target, expected)
        self.assertFalse(target.exists())

    def test_linux_normalization_contract_chmod_precedes_chown(self):
        calls = []
        with ExitStack() as stack:
            stack.enter_context(patch.object(copy.os, 'O_NOFOLLOW', 0, create=True))
            stack.enter_context(patch.object(copy.os, 'O_DIRECTORY', 0, create=True))
            stack.enter_context(patch.object(copy.os, 'open', side_effect=[11, 12]))
            stack.enter_context(patch.object(copy.os, 'close', lambda fd: None))
            stack.enter_context(patch.object(copy.os, 'fchmod',
                lambda fd, mode: calls.append(('chmod', fd, mode)), create=True))
            stack.enter_context(patch.object(copy.os, 'fchown',
                lambda fd, uid, gid: calls.append(('chown', fd, uid, gid)), create=True))
            file = SimpleNamespace(st_dev=1, st_ino=11, st_size=13, st_mtime_ns=1,
                st_ctime_ns=1, st_nlink=1, st_uid=65532, st_gid=65532, st_mode=stat.S_IFREG | 0o444)
            directory = SimpleNamespace(st_dev=1, st_ino=12, st_size=0, st_mtime_ns=1,
                st_ctime_ns=1, st_uid=65532, st_gid=65532, st_mode=stat.S_IFDIR | 0o755)
            stack.enter_context(patch.object(copy.os, 'fstat', side_effect=[file,file,directory,directory]))
            stack.enter_context(patch.object(Path, 'lstat', lambda path: file if path.name=='source.cf' else directory))
            copy.normalize_target(Path('/cf/source.cf'), list(copy.identity(file)), [1,12])
        self.assertEqual(calls, [('chmod',11,0o444),('chown',11,65532,65532),
                                 ('chmod',12,0o755),('chown',12,65532,65532)])


class CopyProtocolTests(unittest.TestCase):
    def run_case(self, fault=None):
        original = protocol.fast.produce_fast_side
        def invoke(config, side):
            config.update(docker_mode='fast', docker_cf_transfer='bind-copy')
            return original(config, side)
        with patch.object(protocol, 'ProductDocker', CopyDocker), patch.object(protocol.fast, 'produce_fast_side', invoke):
            return protocol.ProductTests.run_case(self, fault=fault)

    def test_typed_bind_copy_then_independent_verifier(self):
        fake, config, error, root = self.run_case()
        self.assertIsNone(error)
        proof = protocol.ns.verify_fast_side(config, 'main')
        self.assertEqual(proof['xml_files'], 3)
        self.assertEqual(fake.volumes, {})
        self.assertEqual(set(fake.containers), {fake.foreign})

    def test_bad_caps_mount_hash_unreadable_and_timeout_never_accept(self):
        for fault in ('copy-caps','copy-source-rw','copy-hash','copy-unreadable','copy-timeout'):
            with self.subTest(fault=fault):
                fake, config, error, root = self.run_case(fault)
                self.assertIsNotNone(error)
                self.assertFalse((root / '_work/fast-main/verification.json').exists())
                self.assertIn(fake.foreign, fake.containers)

    def test_uncertain_create_is_recoverable_only_for_owned_resources(self):
        fake, config, error, root = self.run_case('copy-create-uncertain')
        self.assertIsNotNone(error)
        proof = protocol.fast.cleanup_fast_owned(config)
        self.assertTrue(proof['confirmed'])
        self.assertEqual(set(fake.containers), {fake.foreign})
        self.assertEqual(fake.volumes, {})


if __name__ == '__main__':
    unittest.main()
