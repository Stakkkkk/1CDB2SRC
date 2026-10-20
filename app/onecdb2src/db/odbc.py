"""Optional installed ODBC driver; bounded keyed SQL slices, no huge fetch BLOB.

Autocommit only prevents driver-created transactions. Explicit BEGIN/COMMIT
surround the entire capture just as in pytds. No server setting is changed.
"""
from contextlib import contextmanager
from importlib.metadata import version
import re
from .common import CHUNK, CaptureError, metadata, require
from .mssql import Transaction as MSSQLTransaction

def quoted(value):
    require(isinstance(value,str) and '\x00' not in value and '\r' not in value and '\n' not in value, 'Invalid ODBC option')
    return '{'+value.replace('}','}}')+'}'

def connection_string(config):
    driver = config.get('odbc_driver')
    require(isinstance(driver,str) and bool(driver), 'Explicit installed ODBC driver name required')
    host = config['host']
    require(isinstance(host,str) and bool(re.fullmatch(r'[A-Za-z0-9_.:\-]+',host)), 'Unsupported MSSQL host syntax')
    transport = config.get('transport','tcp')
    if transport == 'lpc':
        require(host.lower() in ('localhost','.','(local)'), 'LPC requires a local SQL Server host')
        server = 'lpc:'+host
    elif transport == 'tcp':
        port = int(config.get('port') or 1433)
        require(0 < port <= 65535, 'Invalid MSSQL TCP port')
        server = 'tcp:'+host+','+str(port)
    else:
        raise CaptureError('Unsupported MSSQL transport')
    fields = [('DRIVER',driver),('SERVER',server),('DATABASE',config['database']),('APP','1cdb2src-readonly'),
              ('ApplicationIntent','ReadOnly')]
    auth = config.get('auth','sql')
    if auth == 'integrated':
        fields.append(('Trusted_Connection','Yes'))
    elif auth == 'sql':
        require(bool(config.get('user')) and config.get('password') is not None, 'MSSQL SQL authentication requires user and password')
        fields.extend((('UID',config['user']),('PWD',config['password'])))
    else:
        raise CaptureError('Unsupported MSSQL authentication')
    return ';'.join(k+'='+quoted(v) for k,v in fields)+';'

class Cursor:
    """pyodbc cursor context doesn't close it: always close explicitly here."""
    def __init__(self, cursor):
        self.raw = cursor
    def __enter__(self):
        return self
    def __exit__(self,*exc):
        self.raw.close()
    def execute(self,query,params=None):
        if params is None:
            self.raw.execute(query)
        else:
            self.raw.execute(query,params)
        return self
    def fetchone(self):
        return self.raw.fetchone()

class Connection:
    def __init__(self,connection):
        self.raw=connection
    def cursor(self):
        return Cursor(self.raw.cursor())
    def close(self):
        self.raw.close()

class Transaction(MSSQLTransaction):
    def __init__(self,connection,config):
        super().__init__(connection,config)
        self.driver = 'pyodbc/'+version('pyodbc')+'; '+config['odbc_driver']+'; '+config.get('transport','tcp')

    def query_rows(self,query,params=None):
        yield from super().query_rows(query.replace('%s','?'),params)

    def export(self,writer):
        # Only bounded metadata is materialized. Its cursor closes before blobs.
        records = self.inventory()['config']
        seen = set()
        total = 0
        for record in records:
            key = (record['file_name'],record['part_no'])
            require(key not in seen, 'Duplicate Config key before ODBC payload read')
            seen.add(key)
            total += record['stored_bytes']
            require(total <= writer.max_bytes, 'ODBC capture payload quota exceeded')
        for record in records:
            length = record['stored_bytes']
            meta = metadata({k:v for k,v in record.items() if k != 'stored_bytes'})
            def chunks():
                offset = 0
                # Even empty BLOB is read once, distinguishing NULL/missing row.
                while True:
                    wanted = min(CHUNK,length-offset)
                    query = ('SELECT DATALENGTH(BinaryData),SUBSTRING(BinaryData,?,?) FROM '+self.prefix+'[Config] '
                             'WHERE FileName=? AND PartNo=?')
                    rows = self.query_rows(query,(offset+1,wanted,meta['file_name'],meta['part_no']))
                    try:
                        row = next(rows,None)
                        require(row is not None and next(rows,None) is None, 'Missing or duplicate ODBC Config key')
                    finally:
                        rows.close()
                    require(type(row[0]) is int and row[0] == length and isinstance(row[1],(bytes,bytearray,memoryview)), 'ODBC Config length changed or NULL BLOB')
                    require(len(row[1]) == wanted, 'Incomplete or oversized ODBC Config slice')
                    if wanted:
                        yield row[1]
                    offset += wanted
                    if offset == length:
                        break
            writer.row(meta,length,chunks())

@contextmanager
def transaction(config):
    import pyodbc
    require(version('pyodbc') == '5.3.0', 'Unsupported pyodbc version; install pinned optional requirements')
    require(config.get('odbc_driver') in pyodbc.drivers(), 'Requested ODBC driver is not installed')
    raw = pyodbc.connect(connection_string(config),autocommit=True,timeout=10)
    conn = Connection(raw)
    try:
        timeout = int(config.get('statement_timeout',600))
        require(0 < timeout <= 86400, 'Invalid ODBC statement timeout')
        raw.timeout = timeout
        txn = Transaction(conn,config)
        txn.begin()
        yield txn
        with conn.cursor() as cur:
            cur.execute('COMMIT TRANSACTION')
    except BaseException:
        try:
            with conn.cursor() as cur:
                cur.execute('IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION')
        except Exception:
            pass
        raise
    finally:
        conn.close()
