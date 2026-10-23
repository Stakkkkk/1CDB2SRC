"""Deterministic fake cancel/drain race; no OS process or memory cap."""
import importlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'app'))
from test_no_memory_fake import FakeKernel, FakeProcess


class DelayedPipe:
    def __init__(self, reading, terminated):
        self.reading = reading
        self.terminated = terminated
        self.closed = False
        self.emitted = False
    def read(self, size):
        if self.emitted: return b''
        self.reading.set()
        if not self.terminated.wait(2):
            raise RuntimeError('fake Job never terminated')
        self.emitted = True
        return b'late neutral output\n'
    def close(self): self.closed = True


@unittest.skipUnless(sys.platform == 'win32', 'Windows supervisor definitions; OS calls remain fake')
class CancelDrainTests(unittest.TestCase):
    def trial(self, module):
        reading, terminated = threading.Event(), threading.Event()
        process = FakeProcess()
        process.stdout = DelayedPipe(reading, terminated)
        interrupted = [False]
        def poll():
            if not interrupted[0]:
                if not reading.wait(2): raise RuntimeError('fake reader never started')
                interrupted[0] = True
                raise KeyboardInterrupt
            return process.returncode
        process.poll = poll
        class Kernel(FakeKernel):
            def TerminateJobObject(self, job, code):
                process.returncode = code
                terminated.set()
                return super().TerminateJobObject(job, code)
        kernel = Kernel()
        def members(job): return [] if process.returncode is not None else [process.pid]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(module, 'K', kernel), patch.object(module, 'members', members), \
                    patch.object(module, 'rss', side_effect=AssertionError('no RSS in None branch')), \
                    patch.object(module.subprocess, 'Popen', return_value=process):
                result = module.run(['fake-worker'], root/'out', root/'err', root/'receipt',
                    2, 10000, 10000, rss_cap=None)
            return result, (root/'out').read_bytes()

    def test_cancel_keeps_targets_open_until_drained(self):
        candidate = importlib.import_module('onecdb2src.control.bounded_windows')
        after, new_bytes = self.trial(candidate)
        self.assertTrue(str(after['failure']).startswith('KeyboardInterrupt'))
        self.assertEqual(after['io_errors'], [])
        self.assertEqual(after['cleanup_errors'], [])
        self.assertEqual(after['surviving_pids'], [])
        self.assertTrue(after['job_handle_closed'])
        self.assertTrue(after['drains_joined'])
        self.assertTrue(all(after['pipes_closed'].values()))
        self.assertTrue(all(after['target_streams_closed'].values()))
        self.assertEqual(new_bytes, b'late neutral output\n')
        self.assertEqual(after['stdout']['bytes'], len(new_bytes))



if __name__ == '__main__':
    unittest.main()
