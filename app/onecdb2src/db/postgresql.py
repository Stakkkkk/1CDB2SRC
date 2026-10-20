"""psycopg 3 binary COPY streaming, REPEATABLE READ READ ONLY transaction."""
from contextlib import contextmanager
from importlib.metadata import version
import json
import struct
from .common import CHUNK, TABLES, encoded, identifier, metadata, require

# Catalog-only query: bounded domain chain and extension-owned scalar contract.
# Ordinary ::text is an automatic I/O cast and need not have a pg_cast entry.
FILENAME_TYPE_SQL = """WITH RECURSIVE target AS (
 SELECT a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attndims,a.attgenerated,a.attidentity,
        c.relname,n.nspname FROM pg_catalog.pg_attribute a
 JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=%s AND c.relname=%s AND a.attname=%s AND a.attnum>0 AND NOT a.attisdropped
), chain AS (
 SELECT t.oid,t.typbasetype,0 AS depth FROM pg_catalog.pg_type t JOIN target a ON a.atttypid=t.oid
 UNION ALL SELECT t.oid,t.typbasetype,c.depth+1 FROM chain c
 JOIN pg_catalog.pg_type t ON t.oid=c.typbasetype WHERE c.typbasetype<>0 AND c.depth<8
), facts AS (
 SELECT c.depth,t.oid::text AS oid,t.typname,n.nspname AS type_schema,t.typtype,t.typcategory,
 t.typbasetype::text AS typbasetype,t.typelem::text AS typelem,t.typlen,t.typtypmod,t.typnotnull,
 pi.proname AS input_function,p.proname AS output_function,p.prosrc AS output_symbol,
 p.probin AS output_library,p.prorettype::pg_catalog.regtype::text AS output_return_type,
 pn.nspname AS output_schema,l.lanname AS output_language,
 (SELECT json_agg(json_build_object('name',e.extname,'version',e.extversion,'dependency',d.deptype))
  FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_extension e ON e.oid=d.refobjid
  WHERE d.classid='pg_catalog.pg_type'::pg_catalog.regclass AND d.objid=t.oid
   AND d.refclassid='pg_catalog.pg_extension'::pg_catalog.regclass) AS extensions,
 (SELECT count(*) FROM pg_catalog.pg_cast k WHERE k.castsource=t.oid
   AND k.casttarget IN ('pg_catalog.text'::pg_catalog.regtype,'pg_catalog.varchar'::pg_catalog.regtype,
                       'pg_catalog.bpchar'::pg_catalog.regtype)) AS explicit_string_casts
 FROM chain c JOIN pg_catalog.pg_type t ON t.oid=c.oid
 JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
 JOIN pg_catalog.pg_proc pi ON pi.oid=t.typinput
 JOIN pg_catalog.pg_proc p ON p.oid=t.typoutput
 JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace
 JOIN pg_catalog.pg_language l ON l.oid=p.prolang
)
SELECT json_build_object('attribute',(SELECT row_to_json(a) FROM target a),
 'chain',(SELECT json_agg(f ORDER BY f.depth) FROM facts f))"""

def filename_type_contract(facts, schema):
    """Admit exact catalog facts; no arbitrary USER-DEFINED or binary decoding."""
    require(type(facts) is dict and set(facts)=={'attribute','chain'}, 'Invalid filename type metadata')
    attr,chain = facts['attribute'],facts['chain']
    require(type(attr) is dict and attr.get('attname')=='filename' and attr.get('relname')=='config'
            and attr.get('nspname')==schema, 'Filename attribute binding mismatch')
    require(type(attr.get('attnotnull')) is bool and type(attr.get('atttypmod')) is int
            and type(attr.get('attndims')) is int and attr['attndims']==0
            and attr.get('attgenerated')==attr.get('attidentity')=='', 'Unsupported filename attribute layout')
    require(type(chain) is list and 1<=len(chain)<=9, 'Filename domain depth quota exceeded')
    seen=set()
    expected_oid=str(attr.get('atttypid'))
    effective_notnull=attr['attnotnull']
    for depth,node in enumerate(chain):
        require(type(node) is dict, 'Malformed filename type node')
        oid=str(node.get('oid'));base=str(node.get('typbasetype'))
        require(oid.isdecimal() and oid!='0' and oid==expected_oid and oid not in seen,
                'Filename type chain is cyclic or disconnected')
        seen.add(oid)
        require(type(node.get('depth')) is int and node['depth']==depth
                and str(node.get('typelem'))=='0' and type(node.get('typnotnull')) is bool
                and type(node.get('typtypmod')) is int, 'Unsupported filename type shape')
        effective_notnull = effective_notnull or node['typnotnull']
        if depth<len(chain)-1:
            require(node.get('typtype')=='d' and node.get('typcategory')=='S' and base.isdecimal() and base!='0',
                    'Unsupported filename domain wrapper')
            expected_oid=base
        else:
            require(node.get('typtype')=='b' and base=='0', 'Unresolved filename domain or non-base type')
    require(effective_notnull, 'Nullable filename is unsupported')
    terminal=chain[-1]
    if terminal.get('type_schema')=='pg_catalog' and terminal.get('typname') in ('text','varchar','bpchar'):
        require(terminal.get('typcategory')=='S', 'Builtin filename category mismatch')
        # A domain's stored typmod can constrain its base. A declared bound
        # still passes the existing per-value safe_name/length guards later.
        require(attr['atttypmod']>=-1 and all(n['typtypmod']>=-1 for n in chain), 'Invalid filename type modifier')
        return {'kind':'domain-string' if len(chain)>1 else 'builtin-string',
                'base_type':terminal['typname'],'domain_depth':len(chain)-1}
    require(len(chain)==1, 'Custom filename domain has no accepted contract')
    require(terminal.get('type_schema')=='public' and terminal.get('typname')=='mvarchar'
            and terminal.get('typcategory')=='U' and terminal.get('typlen')==-1
            and terminal['typtypmod']==-1 and 0<attr['atttypmod']<=255,
            'Unknown custom filename type')
    require(terminal.get('extensions')==[{'name':'mchar','version':'2.2.1','dependency':'e'}],
            'Unverified filename extension identity/version')
    expected={'input_function':'mvarchar_in','output_function':'mvarchar_out','output_symbol':'mvarchar_out',
              'output_library':'$libdir/mchar','output_return_type':'cstring','output_schema':'public','output_language':'c'}
    require(all(terminal.get(k)==v for k,v in expected.items()), 'Unverified filename output function contract')
    require(type(terminal.get('explicit_string_casts')) is int and terminal['explicit_string_casts']==0,
            'Custom filename cast overrides automatic output conversion')
    return {'kind':'extension-string','type':'public.mvarchar','extension':'mchar','extension_version':'2.2.1',
            'conversion':'automatic IO cast via mvarchar_out to text','domain_depth':0}

class CopyReader:
    def __init__(self, blocks):
        self.blocks = iter(blocks)
        self.current = memoryview(b'')

    def exact(self, count):
        require(0 <= count <= CHUNK, 'COPY read quota exceeded')
        result = bytearray()
        while len(result) < count:
            if not self.current:
                try:
                    self.current = memoryview(next(self.blocks))
                except StopIteration:
                    require(False, 'Truncated binary COPY stream')
                require(0 < len(self.current) <= 16*CHUNK, 'COPY driver block quota exceeded')
            n = min(count-len(result),len(self.current))
            result.extend(self.current[:n])
            self.current = self.current[n:]
        return bytes(result)

    def eof(self):
        if self.current:
            return False
        for block in self.blocks:
            if block:
                return False
        return True

def parse_copy(blocks, writer):
    reader = CopyReader(blocks)
    require(reader.exact(11) == b'PGCOPY\n\xff\r\n\0', 'Invalid binary COPY signature')
    require(reader.exact(8) == b'\0'*8, 'Unsupported binary COPY flags/extensions')
    while True:
        count = struct.unpack('!h',reader.exact(2))[0]
        if count == -1:
            break
        require(count == 2, 'Unexpected COPY column count')
        n = struct.unpack('!i',reader.exact(4))[0]
        require(0 < n < 65536, 'COPY metadata quota exceeded')
        meta = metadata(json.loads(reader.exact(n)))
        length = struct.unpack('!i',reader.exact(4))[0]
        require(length >= 0, 'NULL/invalid COPY BLOB length')
        def chunks():
            left = length
            while left:
                chunk = reader.exact(min(CHUNK,left))
                left -= len(chunk)
                yield chunk
        writer.row(meta,length,chunks())
    require(reader.eof(), 'Trailing binary COPY bytes')

def parse_sliced_copy(blocks, writer):
    """SQL bounds each wire row. Libpq must never receive an unsliced huge bytea."""
    reader = CopyReader(blocks)
    require(reader.exact(11) == b'PGCOPY\n\xff\r\n\0' and reader.exact(8) == b'\0'*8, 'Unsupported binary COPY header')
    def header():
        count = struct.unpack('!h',reader.exact(2))[0]
        if count == -1:
            return None
        require(count == 4, 'Unexpected sliced COPY column count')
        n = struct.unpack('!i',reader.exact(4))[0]
        require(0 < n < 65536, 'COPY metadata quota exceeded')
        meta = metadata(json.loads(reader.exact(n)))
        require(struct.unpack('!i',reader.exact(4))[0] == 8, 'Invalid COPY total length field')
        total = struct.unpack('!q',reader.exact(8))[0]
        require(struct.unpack('!i',reader.exact(4))[0] == 8, 'Invalid COPY offset field')
        offset = struct.unpack('!q',reader.exact(8))[0]
        length = struct.unpack('!i',reader.exact(4))[0]
        require(total >= 0 and 0 <= offset <= total and 0 <= length <= CHUNK and offset+length <= total, 'Invalid COPY slice bounds')
        return meta,total,offset,length
    while (first := header()) is not None:
        meta,total,offset,length = first
        require(offset == 0, 'Missing first COPY slice')
        def chunks():
            current = first
            consumed = 0
            while True:
                m,t,o,n = current
                require(m == meta and t == total and o == consumed, 'Missing, duplicate or crossed COPY slices')
                require(n == min(CHUNK,total-consumed), 'Unexpected COPY slice length')
                if n:
                    yield reader.exact(n)
                consumed += n
                if consumed == total:
                    break
                current = header()
                require(current is not None, 'Truncated COPY part slices')
        writer.row(meta,total,chunks())
    require(reader.eof(), 'Trailing binary COPY bytes')

class Transaction:
    consistency = 'REPEATABLE READ READ ONLY'
    def __init__(self, connection, config):
        self.connection, self.config = connection, config
        self.schema = identifier(config.get('schema') or 'public')
        self.prefix = '"'+self.schema+'".'
        self.driver = 'psycopg/'+version('psycopg')

    def rows(self, query, params=None):
        # Server cursor bounds metadata transport as well as Python-side iteration.
        with self.connection.cursor(name='onecdb2src_metadata') as cur:
            cur.execute(query, params)
            count = 0
            for row in cur:
                count += 1
                require(count <= self.config.get('max_rows',500000), 'SQL metadata row quota exceeded')
                yield row

    def begin(self):
        columns = list(self.rows('SELECT column_name,data_type,is_nullable FROM information_schema.columns WHERE table_schema=%s AND table_name=%s',(self.schema,'config')))
        by_name = {r[0]:(r[1],r[2]) for r in columns}
        types = {'filename':{'character varying','character','text'}, 'partno':{'integer'}, 'datasize':{'bigint','integer'}, 'attributes':{'smallint','integer'}, 'creation':{'timestamp without time zone'}, 'modified':{'timestamp without time zone'}, 'binarydata':{'bytea'}}
        require(len(columns)==len(by_name)==len(types) and set(by_name) == set(types), 'Unexpected PostgreSQL Config column layout')
        require(all((k=='filename' or by_name[k][0] in allowed) and by_name[k][1]=='NO' for k,allowed in types.items()), 'Unsupported PostgreSQL Config types/nullability')
        filename_rows=list(self.rows(FILENAME_TYPE_SQL,(self.schema,'config','filename')))
        require(len(filename_rows)==1 and len(filename_rows[0])==1, 'Missing or ambiguous filename type metadata')
        facts=filename_rows[0][0]
        require(isinstance(facts,(dict,str)), 'Malformed filename type metadata value')
        if isinstance(facts,str):
            require(len(facts.encode('utf-8'))<=65536, 'Filename type metadata quota exceeded')
            facts=json.loads(facts)
        else:
            require(len(encoded(facts))<=65536, 'Filename type metadata quota exceeded')
        self.filename_type=filename_type_contract(facts,self.schema)
        display_type='USER-DEFINED' if self.filename_type['kind']=='extension-string' else {
            'text':'text','varchar':'character varying','bpchar':'character'}[self.filename_type['base_type']]
        require(by_name['filename'][0]==display_type, 'Filename catalog/information_schema contradiction')
        for table in TABLES:
            rows = list(self.rows('SELECT table_type FROM information_schema.tables WHERE table_schema=%s AND table_name=%s',(self.schema,table)))
            require(len(rows)==1 and rows[0][0]=='BASE TABLE', 'Missing or unsupported Config storage table')

    def select(self, payload=False):
        meta = "json_build_object('file_name',filename::text,'part_no',partno,'data_size',datasize,'attributes',attributes,'creation',creation::text,'modified',modified::text)::text"
        return 'SELECT '+meta+(',binarydata' if payload else ',octet_length(binarydata)')+' FROM '+self.prefix+'"config" ORDER BY filename,partno'

    def inventory(self):
        result = {}
        for table in TABLES[1:]:
            require(not list(self.rows('SELECT 1 FROM '+self.prefix+'"'+table+'" LIMIT 1')), 'Nonempty '+table+'; overlays unsupported')
            result[table] = []
        result['config'] = []
        used = 0
        for text, length in self.rows(self.select()):
            meta = metadata(json.loads(text))
            require(type(length) is int and length >= 0, 'NULL or invalid Config binarydata')
            record = meta | {'stored_bytes':length}
            used += len(encoded(record))
            require(used <= self.config.get('max_metadata_bytes',128*1024**2), 'SQL metadata quota exceeded')
            result['config'].append(record)
        return result

    def export(self, writer):
        meta = "json_build_object('file_name',filename::text,'part_no',partno,'data_size',datasize,'attributes',attributes,'creation',creation::text,'modified',modified::text)::text"
        # PQgetCopyData materializes one CopyData message: keep server messages small.
        query = ('SELECT '+meta+',octet_length(binarydata)::bigint,s.off::bigint,'
                 'substring(binarydata FROM (s.off+1)::integer FOR '+str(CHUNK)+') FROM '+self.prefix+'"config" '
                 'CROSS JOIN LATERAL generate_series(0::bigint,greatest(octet_length(binarydata)-1,0)::bigint,'+str(CHUNK)+'::bigint) AS s(off) '
                 'ORDER BY filename,partno,s.off')
        with self.connection.cursor() as cur:
            with cur.copy('COPY ('+query+') TO STDOUT WITH (FORMAT binary)') as copy:
                parse_sliced_copy(copy,writer)

@contextmanager
def transaction(config):
    import psycopg
    require(version('psycopg') == '3.3.6', 'Unsupported psycopg version; install pinned requirements')
    conn = psycopg.connect(host=config['host'],port=int(config.get('port') or 5432),dbname=config['database'],
                           user=config.get('user'),password=config.get('password'),connect_timeout=10,autocommit=True,
                           application_name='1cdb2src-readonly')
    try:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
                cur.execute("SELECT set_config('statement_timeout', %s, true)", (str(int(config.get('statement_timeout',600))*1000),))
                cur.execute("SELECT set_config('lock_timeout', %s, true)", (str(int(config.get('lock_timeout',3000))),))
            txn = Transaction(conn,config)
            txn.begin()
            yield txn
    finally:
        conn.close()
