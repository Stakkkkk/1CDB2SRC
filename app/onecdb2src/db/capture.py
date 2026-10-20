"""BDCF1 local capture with bounded frames, source transaction and local readback."""
import hashlib
import json
import struct
import time
from pathlib import Path
from .common import CaptureError, CHUNK, TABLES, digest, encoded, metadata, require, utc

class Writer:
    def __init__(self, directory, header, *, max_bytes=64*1024**3, max_rows=500000, max_metadata_bytes=128*1024**2):
        self.directory = Path(directory)
        self.path = self.directory/'source.bdcf'
        self.stream = self.path.open('xb')
        self.index = self.path.with_suffix('.parts.jsonl').open('x', encoding='utf-8')
        self.hash = hashlib.sha256()
        self.size = self.blobs = self.rows = self.metadata_bytes = 0
        self.max_bytes, self.max_rows, self.max_metadata_bytes = max_bytes, max_rows, max_metadata_bytes
        self.header = header
        self.records = []
        self.groups = {}
        self.last_name = None
        self.emit(b'BDCF1\r\n\x1a')
        self.jblock(header)

    def emit(self, data):
        require(self.size + len(data) <= self.max_bytes, 'Capture disk quota exceeded')
        self.stream.write(data)
        self.hash.update(data)
        self.size += len(data)

    def jblock(self, obj):
        data = encoded(obj)
        require(0 < len(data) < 1000000, 'Capture JSON quota exceeded')
        self.emit(struct.pack('<I', len(data)))
        self.emit(data)

    def row(self, meta, length, chunks):
        meta = metadata(meta)
        require(type(length) is int and 0 <= length <= self.max_bytes, 'Invalid Config BLOB length')
        require(self.rows < self.max_rows, 'Capture row quota exceeded')
        data = encoded(meta)
        self.metadata_bytes += len(data)
        require(len(data) < 65536 and self.metadata_bytes <= self.max_metadata_bytes, 'Metadata quota exceeded')
        name = meta['file_name']
        group = self.groups.get(name)
        if group is None:
            require(meta['part_no'] == 0, 'Config first PartNo must be zero')
            group = self.groups[name] = {'next': 0, 'bytes': 0, 'data_size': meta['data_size'], 'attributes': meta['attributes']}
        else:
            require(name == self.last_name, 'Noncontiguous Config file parts')
        require(meta['part_no'] == group['next'], 'Missing or duplicate Config part')
        require(meta['data_size'] == group['data_size'] and meta['attributes'] == group['attributes'], 'Inconsistent Config parts')
        self.emit(struct.pack('<IQ', len(data), length))
        self.emit(data)
        offset = self.size
        sha, written = hashlib.sha256(), 0
        for chunk in chunks:
            require(isinstance(chunk, (bytes, bytearray, memoryview)) and 0 < len(chunk) <= CHUNK, 'Invalid payload chunk')
            require(written + len(chunk) <= length, 'Config BLOB longer than declared')
            self.emit(chunk)
            sha.update(chunk)
            written += len(chunk)
        require(written == length, 'Config BLOB shorter than declared')
        self.emit(sha.digest())
        row = meta | {'offset': offset, 'length': length, 'sha256': sha.hexdigest()}
        self.index.write(encoded(row).decode('utf-8')+'\n')
        self.records.append(meta | {'stored_bytes': length})
        group['next'] += 1
        group['bytes'] += length
        self.last_name = name
        self.rows += 1
        self.blobs += length

    def validate(self):
        require(self.rows > 0, 'Empty Config is not supported')
        require(all(g['bytes'] == g['data_size'] for g in self.groups.values()), 'Config DataSize mismatch')

    def finish(self):
        self.validate()
        self.trailer = {'rows': self.rows, 'blob_bytes': self.blobs, 'ended_utc': utc()}
        self.emit(b'\0'*12)
        self.jblock(self.trailer)
        self.close()
        require(digest(self.path) == self.hash.hexdigest(), 'Local capture readback hash mismatch')
        # Re-read every framed byte, including individual part hashes, before closure.
        with self.path.open('rb') as src, self.path.with_suffix('.parts.jsonl').open(encoding='utf-8') as idx:
            require(src.read(8) == b'BDCF1\r\n\x1a', 'Local capture magic changed')
            n = struct.unpack('<I', src.read(4))[0]
            require(json.loads(src.read(n)) == self.header, 'Local capture header changed')
            for line in idx:
                row = json.loads(line)
                ml, length = struct.unpack('<IQ', src.read(12))
                require(length == row['length'] and json.loads(src.read(ml)) == {k:v for k,v in row.items() if k not in ('offset','length','sha256')}, 'Local capture framing changed')
                require(src.tell() == row['offset'], 'Local capture offset changed')
                sha = hashlib.sha256()
                left = length
                while left:
                    chunk = src.read(min(CHUNK, left))
                    require(chunk, 'Local capture truncated')
                    sha.update(chunk)
                    left -= len(chunk)
                require(src.read(32).hex() == sha.hexdigest() == row['sha256'], 'Local part hash mismatch')
            require(src.read(12) == b'\0'*12, 'Local capture terminator changed')
            n = struct.unpack('<I', src.read(4))[0]
            require(json.loads(src.read(n)) == self.trailer and not src.read(1), 'Local capture trailer changed')
        verification = {'status': 'PASS', 'provenance': 'direct-db-local-v1', 'local_readback_hash_match': True,
                        'header': self.header, 'trailer': self.trailer, 'rows': self.rows, 'stream_bytes': self.size,
                        'sha256': self.hash.hexdigest(), 'stream_sha256':self.hash.hexdigest(), 'parts_sha256': digest(self.path.with_suffix('.parts.jsonl')),
                        'transaction_closed': True}
        return verification

    def close(self):
        self.stream.close()
        self.index.close()

def capture(config, output):
    started = time.monotonic()
    directory = Path(output)
    require(not directory.exists(), 'Capture output already exists')
    directory.mkdir(parents=True)
    writer = None
    try:
        provider = config.get('provider')
        require(provider in ('mssql', 'postgresql'), 'Unsupported database provider')
        if provider == 'mssql':
            driver = config.get('driver','pytds')
            require(driver in ('pytds','pyodbc'), 'Unsupported MSSQL driver')
            if driver == 'pyodbc':
                from . import odbc as adapter
            else:
                require(config.get('transport','tcp') == 'tcp', 'pytds supports TCP transport only')
                from . import mssql as adapter
        else:
            from . import postgresql as adapter
        with adapter.transaction(config) as txn:
            before = txn.inventory()
            header = {'format': 'BDCF1', 'provider': provider, 'database': config['database'], 'schema': txn.schema,
                      'started_utc': utc(), 'consistency': txn.consistency, 'driver': txn.driver,
                      'provenance': 'direct-db-local-v1', 'source_dates': 'SQL text, no timezone conversion'}
            writer = Writer(directory, header, max_bytes=config.get('max_capture_bytes',64*1024**3),
                            max_rows=config.get('max_rows',500000), max_metadata_bytes=config.get('max_metadata_bytes',128*1024**2))
            txn.export(writer)
            writer.validate()
            after = txn.inventory()
            require(before == after, 'Config inventory changed within transaction')
            require(before['config'] == writer.records, 'Captured Config metadata differs from transactional inventory')
        # Context exits only after successful commit. PASS is never written earlier.
        verification = writer.finish()
        inventory = {'provenance': 'direct-db-local-v1', 'consistency': header['consistency'], 'same_transaction': True,
                     'databases': [{'provider': provider, 'database': config['database'], 'captured_utc': header['started_utc'],
                                    'file_tables': [{'table': t, 'rows': before[t]} for t in TABLES]}]}
        ip = writer.path.with_suffix('.inventory.json')
        ip.write_bytes(encoded(inventory))
        verification['inventory_sha256'] = digest(ip)
        verification['elapsed_seconds'] = time.monotonic()-started
        with writer.path.with_suffix('.files.jsonl').open('x', encoding='utf-8') as f:
            for name, group in writer.groups.items():
                f.write(encoded({'file_name':name, 'parts':group['next'], 'stored_bytes':group['bytes'], 'data_size':group['data_size'], 'attributes':group['attributes']}).decode()+'\n')
        writer.path.with_suffix('.verification.json').write_bytes(encoded(verification))
        return {'path':str(writer.path.resolve()), 'snapshot':str(writer.path.resolve()), 'inventory':str(ip.resolve()), 'verification':verification,
                'receipt':str(writer.path.with_suffix('.verification.json').resolve())}
    except (CaptureError, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise CaptureError('Database capture failed ('+type(exc).__name__+'); connection details suppressed') from None
    finally:
        if writer is not None:
            writer.close()
