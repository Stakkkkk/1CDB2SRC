"""No real workload/OS cap: fake process/API paths plus extracted branch units."""
import ast
import copy
import ctypes
import importlib
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'app'))


class Pipe(io.BytesIO):
    def close(self):
        self.saved = self.getvalue() if not self.closed else getattr(self, 'saved', b'')
        super().close()


class FakeProcess:
    def __init__(self):
        self.pid = 990001
        self._handle = 5
        self.stdin, self.stdout, self.stderr = Pipe(), Pipe(b'neutral\n'), Pipe()
        self.returncode = None
        self.polls = 0
    def poll(self):
        self.polls += 1
        if self.polls >= 2: self.returncode = 0
        return self.returncode
    def wait(self, timeout=None):
        self.returncode = 0 if self.returncode is None else self.returncode
        return self.returncode
    def terminate(self): self.returncode = 126
    def kill(self): self.returncode = 127


class FakeKernel:
    def __init__(self):
        self.limits = None
        self.terminated = []
        self.closed = []
    def CreateJobObjectW(self, *args): return 1
    def GetCurrentProcess(self): return 2
    def GetProcessAffinityMask(self, handle, allowed, system):
        allowed._obj.value = 3
        system._obj.value = 3
        return 1
    def SetInformationJobObject(self, job, kind, pointer, size):
        self.limits = type(pointer._obj).from_buffer_copy(bytes(pointer._obj))
        return 1
    def QueryInformationJobObject(self, job, kind, pointer, size, ignored):
        ctypes.memmove(pointer, ctypes.byref(self.limits), size)
        return 1
    def AssignProcessToJobObject(self, *args): return 1
    def TerminateJobObject(self, job, code):
        self.terminated.append((job, code))
        return 1
    def CloseHandle(self, handle):
        self.closed.append(handle)
        return 1


@unittest.skipUnless(sys.platform == 'win32', 'Windows module/API definitions required; APIs are faked')
class WindowsFakeTests(unittest.TestCase):
    def trial(self, cap, observation_error=False):
        module = importlib.import_module('onecdb2src.control.bounded_windows')
        kernel, process = FakeKernel(), FakeProcess()
        calls = []
        member_calls = [0]
        def members(job):
            member_calls[0] += 1
            if observation_error: raise OSError('fake enumeration failure')
            return [process.pid] if member_calls[0] == 1 else []
        def rss(pid):
            calls.append(pid)
            if cap is None: raise AssertionError('None must never inspect RSS')
            return 10
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(module, 'K', kernel), patch.object(module, 'members', members), \
                    patch.object(module, 'rss', rss), patch.object(module.subprocess, 'Popen', return_value=process):
                result = module.run(['fake-worker'], root/'out', root/'err', root/'receipt',
                                    2, 10000, 10000, rss_cap=cap)
            self.assertEqual(json.loads((root/'receipt').read_text()), result)
        return result, kernel, process, calls

    def test_none_keeps_job_cpu_handshake_cleanup_without_memory_flags_or_rss(self):
        result, kernel, process, calls = self.trial(None)
        self.assertEqual(kernel.limits.basic.flags, 0x2000 | 0x10)
        self.assertEqual(kernel.limits.process_memory, 0)
        self.assertEqual(kernel.limits.job_memory, 0)
        self.assertEqual(kernel.limits.basic.affinity, 3)
        self.assertEqual(calls, [])
        self.assertFalse(result['memory_controls'])
        self.assertFalse(result['rss_monitoring'])
        self.assertIsNone(result['peak_job_rss_bytes'])
        self.assertIsNone(result['hard_job_memory_bytes'])
        self.assertEqual(process.stdin.saved, b'GO\n')
        self.assertTrue(result['job_assigned_before_child_launch'])
        self.assertTrue(result['job_handle_closed'])
        self.assertEqual(result['surviving_pids'], [])
        self.assertIsNone(result['failure'])

    def test_explicit_cap_contract_is_preserved_with_fake_memory_api_only(self):
        result, kernel, process, calls = self.trial(123456)
        self.assertEqual(kernel.limits.basic.flags, 0x2000 | 0x100 | 0x200 | 0x10)
        self.assertEqual(kernel.limits.process_memory, 123456)
        self.assertEqual(kernel.limits.job_memory, 123456)
        self.assertTrue(calls)
        self.assertTrue(result['memory_controls'])
        self.assertEqual(result['peak_job_rss_bytes'], 10)
        self.assertIsNone(result['failure'])

    def test_none_observation_failure_still_terminates_and_closes_owned_job(self):
        result, kernel, process, calls = self.trial(None, True)
        self.assertEqual(calls, [])
        self.assertTrue(kernel.terminated)
        self.assertIn(1, kernel.closed)
        self.assertTrue(result['job_handle_closed'])
        self.assertEqual(result['observation_status'], 'UNKNOWN')
        self.assertIsNone(result['surviving_pids'])
        self.assertIsNotNone(result['failure'])


class PosixSourceFakeTests(unittest.TestCase):
    def trial(self, cap, mismatch=False):
        module = importlib.import_module('onecdb2src.control.bounded_posix')
        process = FakeProcess()
        command = []
        observed = []
        def spawn(argv, **kwargs):
            command.extend(argv)
            return process
        def identity(pid, *, include_rss=True):
            observed.append(include_rss)
            return {'pid': pid, 'start_ticks': 42}
        def status(path):
            return {'schema': 1, 'bootstrap_pid': process.pid, 'bootstrap_start_ticks': 42,
                'known_processes': [], 'memory_controls': (True if mismatch else cap is not None), 'rss_limit_bytes': cap,
                'peak_sampled_tree_rss_bytes': 10 if cap is not None else None,
                'closed': True, 'processgroups_closed': True, 'observation_errors': [],
                'cleanup_errors': [], 'failure': None, 'target_exit': 0, 'subreaper': True,
                'cpu_affinity': [0, 1]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(module.sys, 'platform', 'linux'), patch.object(module, 'process', identity), \
                    patch.object(module, 'read_status', status), patch.object(module, 'live', return_value=False), \
                    patch.object(module.subprocess, 'Popen', spawn):
                result = module.run(['fake-worker'], root/'out', root/'err', root/'receipt',
                                    2, 10000, 10000, rss_cap=cap)
        return result, command, observed

    def test_none_parent_passes_none_to_existing_bootstrap_and_has_no_memory_claim(self):
        result, command, observed = self.trial(None)
        self.assertIn('None', command)
        self.assertEqual(observed, [False])
        self.assertFalse(result['memory_controls'])
        self.assertIsNone(result['peak_sampled_tree_rss_bytes'])
        self.assertEqual(result['memory_peak_status'], 'DISABLED')
        self.assertIsNone(result['hard_address_space_per_process_bytes'])
        self.assertEqual(result['rlimit_as_scope'], 'DISABLED')
        self.assertTrue(result['processgroups_closed'])
        self.assertEqual(result['surviving_pids'], [])

    def test_explicit_cap_parent_contract_is_unchanged(self):
        result, command, observed = self.trial(123456)
        self.assertIn('123456', command)
        self.assertEqual(observed, [True])
        self.assertEqual(result['hard_address_space_per_process_bytes'], 123456)
        self.assertTrue(result['memory_controls'])

    def test_none_bootstrap_policy_mismatch_cannot_publish_closed_success(self):
        result, command, observed = self.trial(None, mismatch=True)
        self.assertIsNotNone(result['failure'])
        self.assertFalse(result['processgroups_closed'])
        self.assertEqual(result['observation_status'], 'UNKNOWN')

    def test_bootstrap_none_skips_rlimit_but_keeps_pdeath_and_affinity(self):
        source = ast.parse((ROOT/'app/onecdb2src/control/bootstrap_posix.py').read_text())
        main = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        limits = next(node for node in ast.walk(main) if isinstance(node, ast.FunctionDef) and node.name == 'limits')
        standalone = ast.Module(body=[copy.deepcopy(limits)], type_ignores=[])
        ast.fix_missing_locations(standalone)
        for cap in (None, 123456):
            with self.subTest(cap=cap):
                calls = []
                resource = types.SimpleNamespace(RLIMIT_AS=9,
                    setrlimit=lambda which, value: calls.append(('setrlimit', which, value)),
                    getrlimit=lambda which: (cap, cap))
                fake_os = types.SimpleNamespace(getppid=lambda: 42,
                    sched_setaffinity=lambda pid, cpus: calls.append(('affinity', pid, cpus)),
                    sched_getaffinity=lambda pid: {0, 1}, _exit=lambda code: self.fail('unexpected parent mismatch'))
                namespace = {'memory_enabled': cap is not None, 'cap': cap, 'resource': resource,
                    'os': fake_os, 'supervisor_pid': 42, 'cpus': [0, 1],
                    'signal': types.SimpleNamespace(SIGKILL=9),
                    'prctl': lambda which, value: calls.append(('prctl', which, value))}
                exec(compile(standalone, '<actual-bootstrap-limits-subtree>', 'exec'), namespace)
                namespace['limits']()
                self.assertIn(('prctl', 1, 9), calls)
                self.assertIn(('affinity', 0, {0, 1}), calls)
                self.assertEqual(any(row[0] == 'setrlimit' for row in calls), cap is not None)

    def test_all_candidate_files_parse_without_launching_anything(self):
        for file in (ROOT/'app/onecdb2src/control').glob('*.py'):
            ast.parse(file.read_text('utf-8'), filename=str(file))


if __name__ == '__main__':
    unittest.main()
