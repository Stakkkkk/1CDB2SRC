"""python-tds 1.17.1: explicit transaction, bounded one-row disk spool."""
from contextlib import contextmanager
from importlib.metadata import version
import hashlib
import tempfile
from .common import CHUNK, TABLES, CaptureError, identifier, metadata, require

class Spool:
    def __init__(self, quota):
        self.file = tempfile.TemporaryFile(mode='w+b')
        self.quota = quota
        self.reset()

    def reset(self):
        self.file.seek(0)
        self.file.truncate()
        self.size = 0
        self.sha = hashlib.sha256()

    def write(self, data):
        # The pinned TDS reader slices its bytearray receive buffer. Both
        # binary representations must preserve the same bytes and spool quota.
        require(isinstance(data, (bytes, bytearray)), 'Nonbinary driver stream')
        require(self.size+len(data) <= self.quota, 'Driver BLOB spool quota exceeded')
        self.file.write(data)
        self.size += len(data)
        self.sha.update(data)
        return len(data)

    def chunks(self):
        self.file.seek(0)
        while data := self.file.read(CHUNK):
            yield data

    def close(self):
        self.file.close()

class Transaction:
    def __init__(self, connection, config):
        self.connection, self.config = connection, config
        self.schema = identifier(config.get('schema') or 'dbo')
        self.consistency = config.get('consistency', 'snapshot').lower()
        require(self.consistency in ('snapshot','serializable'), 'Unsupported MSSQL consistency')
        self.driver = 'python-tds/'+version('python-tds')
        self.prefix = '['+self.schema+'].'
        self.tables = {}

    def query_rows(self, query, params=None):
        with self.connection.cursor() as cur:
            cur.execute(query, params)
            total = 0
            while (row := cur.fetchone()) is not None:
                total += 1
                require(total <= self.config.get('max_rows',500000), 'SQL metadata row quota exceeded')
                yield row

    def begin(self):
        lock = int(self.config.get('lock_timeout',3000))
        require(0 < lock <= 60000, 'Invalid lock timeout')
        with self.connection.cursor() as cur:
            cur.execute('SET LOCK_TIMEOUT '+str(lock))
            if self.consistency == 'snapshot':
                cur.execute('SELECT snapshot_isolation_state FROM sys.databases WHERE name=DB_NAME()')
                row = cur.fetchone()
                require(row is not None and row[0] == 1, 'MSSQL SNAPSHOT is not enabled; choose serializable explicitly if acceptable')
            cur.execute('SET TRANSACTION ISOLATION LEVEL '+self.consistency.upper())
            cur.execute('BEGIN TRANSACTION')
        columns = list(self.query_rows('SELECT COLUMN_NAME,DATA_TYPE,IS_NULLABLE,CHARACTER_MAXIMUM_LENGTH FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s', (self.schema,'Config')))
        by_name = {r[0].lower(): (r[1].lower(),r[2],r[3]) for r in columns}
        types = {'filename':{'varchar','nvarchar','char','nchar'},'partno':{'int'},'datasize':{'bigint','int'},'attributes':{'smallint','int'},'creation':{'datetime','datetime2'},'modified':{'datetime','datetime2'},'binarydata':{'varbinary','image'}}
        require(set(by_name) == set(types), 'Unexpected MSSQL Config column layout')
        require(all(by_name[k][0] in allowed and by_name[k][1] == 'NO' for k,allowed in types.items()), 'Unsupported MSSQL Config types/nullability')
        require(by_name['binarydata'][0] == 'image' or by_name['binarydata'][2] == -1, 'MSSQL BinaryData must be IMAGE or VARBINARY(MAX) for streaming')
        for table in TABLES:
            rows = list(self.query_rows('SELECT TABLE_NAME,TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=%s AND LOWER(TABLE_NAME)=%s', (self.schema,table)))
            require(len(rows)==1 and rows[0][1]=='BASE TABLE', 'Missing or unsupported Config storage table')
            self.tables[table] = identifier(rows[0][0])

    def metadata_sql(self, payload=False):
        columns = 'FileName,PartNo,DataSize,Attributes,CONVERT(varchar(33),Creation,126),CONVERT(varchar(33),Modified,126),DATALENGTH(BinaryData)'
        if payload:
            columns += ',BinaryData'
        return 'SELECT '+columns+' FROM '+self.prefix+'[Config] ORDER BY FileName,PartNo'

    def inventory(self):
        result = {}
        for table in TABLES[1:]:
            rows = list(self.query_rows('SELECT TOP (1) 1 FROM '+self.prefix+'['+self.tables[table]+']'))
            require(not rows, 'Nonempty '+table+'; overlays unsupported')
            result[table] = []
        result['config'] = []
        used = 0
        from .common import encoded
        for row in self.query_rows(self.metadata_sql()):
            meta = row_meta(row)
            require(type(row[6]) is int and row[6] >= 0, 'NULL or invalid Config binarydata')
            record = meta | {'stored_bytes':row[6]}
            used += len(encoded(record))
            require(used <= self.config.get('max_metadata_bytes',128*1024**2), 'SQL metadata quota exceeded')
            result['config'].append(record)
        return result

    def export(self, writer):
        spool = Spool(writer.max_bytes)
        try:
            with self.connection.cursor() as cur:
                cur.execute(self.metadata_sql(True))
                cur.set_stream(7, spool)
                while True:
                    spool.reset()
                    row = cur.fetchone()
                    if row is None:
                        break
                    meta = row_meta(row)
                    require(row[7] is not None and type(row[6]) is int and spool.size == row[6], 'NULL or incomplete MSSQL streamed BLOB')
                    writer.row(meta, row[6], spool.chunks())
        finally:
            spool.close()

def row_meta(row):
    return metadata(dict(zip(('file_name','part_no','data_size','attributes','creation','modified'),row[:6])))

@contextmanager
def transaction(config):
    import pytds
    require(version('python-tds') == '1.17.1', 'Unsupported python-tds version; install pinned requirements')
    kwargs = {'server':config['host'], 'port':int(config.get('port') or 1433), 'database':config['database'],
              'autocommit':True, 'timeout':int(config.get('statement_timeout',600)), 'login_timeout':10,
              'appname':'1cdb2src-readonly', 'readonly':True, 'disable_connect_retry':True}
    auth = config.get('auth','sql')
    if auth == 'integrated':
        kwargs['auth'] = pytds.SspiAuth(server_name=config['host'],port=kwargs['port'])
    elif auth == 'sql':
        kwargs.update(user=config.get('user'),password=config.get('password'))
        require(bool(kwargs['user']) and kwargs['password'] is not None, 'MSSQL SQL authentication requires user and password')
    else:
        raise CaptureError('Unsupported MSSQL authentication')
    conn = pytds.connect(**kwargs)
    try:
        txn = Transaction(conn, config)
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
