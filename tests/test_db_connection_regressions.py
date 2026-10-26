"""Regressions from real remote SQL captures, independent of configuration data."""
import hashlib,io,tempfile,unittest
from contextlib import redirect_stdout,redirect_stderr
from pathlib import Path
from unittest.mock import patch
from onecdb2src import cli
from onecdb2src.db.mssql import Spool
from onecdb2src.util import read

class DriverBinaryChunks(unittest.TestCase):
    def test_real_pinned_tds_reader_bytearray_is_preserved_exactly(self):
        from pytds.tds_reader import _TdsReader
        payload=b'\x00\xff\x10\x80binary\x00'
        reader=_TdsReader(None,None,bufsize=len(payload))
        reader._buf[:]=payload;reader._pos=0;reader._size=len(payload)
        chunk=reader.recv(len(payload))
        self.assertIsInstance(chunk,bytearray)
        spool=Spool(100)
        try:
            self.assertEqual(spool.write(chunk),len(payload))
            chunk[:]=b'X'*len(chunk)
            self.assertEqual(b''.join(spool.chunks()),payload)
            self.assertEqual(spool.sha.hexdigest(),hashlib.sha256(payload).hexdigest())
        finally:spool.close()

    def test_nonbinary_and_overquota_chunks_still_fail(self):
        spool=Spool(3)
        try:
            for value in ('abc',None,1,[1,2,3]):
                with self.subTest(value=value),self.assertRaises(ValueError):spool.write(value)
            spool.write(b'AB')
            with self.assertRaises(ValueError):spool.write(bytearray(b'CD'))
            self.assertEqual(b''.join(spool.chunks()),b'AB')
        finally:spool.close()

class PublicCaptureBudget(unittest.TestCase):
    def test_explicit_capture_budget_reaches_sql_statement_without_hidden_ceiling(self):
        from onecdb2src.control import bounded_process
        for provider in ('postgresql','mssql'):
            for seconds in (600,1800):
                with self.subTest(provider=provider,seconds=seconds),tempfile.TemporaryDirectory() as tmp:
                    output=Path(tmp)/'result';observed=[]
                    def capture_only(argv,out,err,receipt,timeout,*caps,**kw):
                        self.assertEqual(argv[-2],'capture')
                        observed.append((read(argv[-1])['db']['statement_timeout'],timeout))
                        out.write_bytes(b'');err.write_bytes(b'')
                        return dict(job_handle_closed=True,surviving_pids=[],known_surviving_pids=[],cleanup_errors=[],io_errors=[],
                            observation_status='OBSERVED',pipes_closed={'stdin':True,'stdout':True,'stderr':True},
                            drains_joined=True,target_streams_closed={'stdout':True,'stderr':True},memory_controls=False,
                            rss_limit_bytes=None,exit_code=1,seconds=.01,peak_job_rss_bytes=None,failure=None)
                    args=['--provider',provider,'--host','127.0.0.1','--database','neutral','--user','neutral',
                          '--supplier','Neutral','--output',str(output),'--docker-mode','fast','--assembly-mode','adopt',
                          '--capture-seconds',str(seconds)]
                    with patch.object(cli,'preflight',return_value={}),patch.object(cli,'cleanup_native',return_value={'confirmed':True}),\
                         patch.object(bounded_process,'run',capture_only),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                        self.assertEqual(cli.main(args),1)
                    self.assertEqual(observed,[(seconds,seconds)])
                    self.assertEqual(read(output/'report.json')['status'],'FAILED')

    def test_nonpositive_budget_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'never-created'
            args=['--provider','postgresql','--host','127.0.0.1','--database','neutral','--user','neutral',
                  '--supplier','Neutral','--output',str(output),'--capture-seconds','0']
            with redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):self.assertEqual(cli.main(args),1)
            self.assertFalse(output.exists())

if __name__=='__main__':unittest.main()
