"""Random access to verified, multipart BDCF1 captures; no network or oracle.

Index offsets alone are not trusted: every consumed part is SHA256 checked.
"""
import hashlib,io,json,struct
from pathlib import Path
from .brace import Reader,walk
from .v8container import CHUNK,inflate_to,safe_name

def require(ok,message):
    if not ok: raise ValueError(message)

class Snapshot:
    def __init__(self,path):
        self.path=Path(path); self.files={}
        verification=json.loads(self.path.with_suffix('.verification.json').read_text('utf-8-sig'))
        require(verification['status']=='PASS' and verification.get('provenance')=='direct-db-local-v1'
                and verification.get('local_readback_hash_match') is True
                and verification.get('transaction_closed') is True,'Unverified direct DB capture')
        self.verification=verification; self.provider=verification['header']['provider']
        size=self.path.stat().st_size
        require(size==verification['stream_bytes'],'Changed snapshot size')
        with self.path.open('rb') as stream:
            actual_sha=hashlib.file_digest(stream,'sha256').hexdigest()
        require(actual_sha==verification['stream_sha256']==verification['sha256'],'Changed snapshot SHA256')
        with self.path.with_suffix('.parts.jsonl').open('rb') as stream:
            require(hashlib.file_digest(stream,'sha256').hexdigest()==verification['parts_sha256'],'Changed parts index SHA256')
        with self.path.with_suffix('.parts.jsonl').open(encoding='utf-8') as f:
            for line in f:
                r=json.loads(line); safe_name(r['file_name'])
                require(0<=r['offset']<=size and 0<=r['length']<=size-r['offset'],'Invalid capture offset/size')
                self.files.setdefault(r['file_name'],[]).append(r)
        require(sum(map(len,self.files.values()))==verification['rows'],'Index count mismatch')
        for name,rows in self.files.items():
            require([r['part_no'] for r in rows]==list(range(len(rows))),'PartNo sequence: '+name)
            n=sum(r['length'] for r in rows)
            require(all(r['data_size']==n for r in rows),'DataSize mismatch: '+name)
            require(len({r['attributes'] for r in rows})==1,'Mixed part attributes: '+name)
        self._check_index_binding()

    def _check_index_binding(self):
        """Bind names, offsets, lengths and hashes to actual BDCF1 framing.

        Payload SHA is checked lazily while consumed; this pass skips payloads.
        It prevents a renamed/reordered JSONL index from reassigning SQL bytes.
        """
        def exact(stream,n):
            result=stream.read(n); require(len(result)==n,'Truncated BDCF framing'); return result
        def jblock(stream):
            n=struct.unpack('<I',exact(stream,4))[0]
            require(0<n<1000000,'BDCF JSON block quota')
            return json.loads(exact(stream,n))
        with self.path.open('rb') as stream:
            require(exact(stream,8)==b'BDCF1\r\n\x1a','Invalid BDCF magic')
            require(jblock(stream)==self.verification['header'],'BDCF header mismatch')
            for rows in self.files.values():
                for row in rows:
                    meta_size,length=struct.unpack('<IQ',exact(stream,12))
                    require(0<meta_size<65536 and length==row['length'],'BDCF frame size mismatch')
                    metadata=json.loads(exact(stream,meta_size))
                    require(metadata=={k:v for k,v in row.items() if k not in {'offset','length','sha256'}},'Index metadata does not match capture')
                    require(stream.tell()==row['offset'],'Index offset does not match capture')
                    stream.seek(length,1)
                    require(exact(stream,32).hex()==row['sha256'],'Index hash does not match capture')
            require(exact(stream,12)==b'\0'*12,'BDCF row count/terminator mismatch')
            require(jblock(stream)==self.verification['trailer'],'BDCF trailer mismatch')
            require(not stream.read(1),'Trailing BDCF bytes')

    def names(self): return self.files.keys()
    def size(self,name): return sum(r['length'] for r in self.files[name])
    def attributes(self,name): return self.files[name][0]['attributes']

    def chunks(self,name):
        with self.path.open('rb') as f:
            for row in self.files[name]:
                f.seek(row['offset']); remaining=row['length']; digest=hashlib.sha256()
                while remaining:
                    data=f.read(min(remaining,CHUNK)); require(data,'Truncated snapshot part')
                    digest.update(data); remaining-=len(data); yield data
                require(digest.hexdigest()==row['sha256'],'Snapshot part integrity: '+name)

    def read(self,name,*,max_bytes=64*1024**2):
        require(self.size(name)<=max_bytes,'Stored read quota: '+name)
        return b''.join(self.chunks(name))

    def inflated(self,name,*,max_output=128*1024**2):
        out=io.BytesIO(); inflate_to(self.chunks(name),out,max_output=max_output); return out.getvalue()

    def tree(self,name): return Reader(self.inflated(name)).read()

    def export_cf_entries(self):
        for name in sorted(self.files):
            # SQL Attributes are retained separately in the source manifest;
            # they are not asserted to have native CF header flag semantics.
            yield {'name':name,'size':self.size(name),'chunks':lambda n=name:self.chunks(n)}

def identity(tree,expected=None):
    import re
    guid=re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',re.I)
    found=[]
    for path,node in walk(tree):
        if not isinstance(node,list) or len(node)<3 or not isinstance(node[1],list): continue
        key=node[1]
        if len(key)==3 and key[:2]==['1','0'] and isinstance(key[2],str) and guid.fullmatch(key[2]) and isinstance(node[2],str):
            if expected is None or key[2]==expected:
                found.append({'uuid':str(key[2]),'name':safe_name(str(node[2])),'path':list(path)})
    require(len(found)==1,'Missing/ambiguous object identity')
    return found[0]
