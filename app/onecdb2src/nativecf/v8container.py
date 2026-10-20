"""Streaming readers/writer for packed 1C paged 32/64-bit catalogs.

Format basis: independently inspected saby-integration/v8unpack 1.2.13
container.py/container_doc.py; no platform or XML oracle dependency.
"""
from dataclasses import dataclass
import hashlib
import io
import math
from pathlib import Path
import re
import struct
import zlib

CHUNK=1024*1024

def require(ok,message):
    if not ok: raise ValueError(message)

def safe_name(name):
    require(isinstance(name,str) and name and name not in {'.','..'},'Empty/relative container name')
    require(not any(c in name for c in '/\\:*?"<>|\x00\r\n'),'Unsafe container name')
    require(not name.endswith(('.',' ')),'Ambiguous container name')
    return name

@dataclass(frozen=True)
class Entry:
    name:str
    header_offset:int
    data_offset:int
    stored_size:int
    created:int
    modified:int
    attributes:int

class Catalog:
    def __init__(self,stream,origin=0,*,max_entries=1000000,max_entry_bytes=16*1024**3,max_pages=2000000):
        self.stream=stream; self.origin=origin
        self.max_entries=max_entries; self.max_entry_bytes=max_entry_bytes; self.max_pages=max_pages
        stream.seek(0,2); self.file_size=stream.tell(); stream.seek(origin)
        head=stream.read(20)
        if head[:4]==b'\xff\xff\xff\x7f':
            self.bits=32; self.width=8; self.header_size=16; self.page_header=31; self.end=0x7fffffff; self.record='<III'
            _,block,declared,reserved=struct.unpack('<IIII',head[:16])
        elif head[:8]==b'\xff'*8:
            self.bits=64; self.width=16; self.header_size=20; self.page_header=55; self.end=0xffffffffffffffff; self.record='<QQQ'
            _,block,declared,reserved=struct.unpack('<QIII',head)
        else: raise ValueError('Unsupported catalog header at '+str(origin))
        require(block>0 and reserved==0,'Unsupported catalog header fields')
        self.default_block=block; self.declared_count=declared
        self.pattern=re.compile(rb'\r\n'+(rb'[0-9a-fA-F]{%d} '%self.width)*3+rb'\r\n')
        self.extent=origin+self.header_size; self.entries={}
        toc=self.read_chain(self.header_size,max_bytes=max_entries*struct.calcsize(self.record))
        stride=struct.calcsize(self.record)
        require(len(toc)%stride==0 and len(toc)//stride<=max_entries,'Invalid catalog index length')
        for at in range(0,len(toc),stride):
            hp,dp,end=struct.unpack_from(self.record,toc,at)
            require(end==self.end,'Invalid catalog index record')
            header=self.read_chain(hp,max_bytes=65536)
            require(len(header)>=22,'Truncated entry header')
            created,modified,attributes=struct.unpack_from('<QQI',header)
            text=header[20:].decode('utf-16le')
            require('\0' in text,'Unterminated container filename')
            name=safe_name(text.partition('\0')[0])
            require(name not in self.entries,'Duplicate container filename')
            size,_=self.chain_layout(dp)
            self.entries[name]=Entry(name,hp,dp,size,created,modified,attributes)
        # Retain the header value without assigning unverified semantics to
        # observed header/TOC count differences. The checked TOC is authoritative.

    def chain_layout(self,offset):
        seen=set(); total=None; written=0; spans=[]
        while offset!=self.end:
            require(isinstance(offset,int) and offset not in seen and len(seen)<self.max_pages,'Cyclic/excessive page chain')
            seen.add(offset); pos=self.origin+offset
            require(self.origin+self.header_size<=pos<=self.file_size-self.page_header,'Page pointer outside file')
            self.stream.seek(pos); h=self.stream.read(self.page_header)
            require(self.pattern.fullmatch(h) is not None,'Malformed page header')
            size,capacity,following=(int(x,16) for x in h.strip().split())
            if total is None:
                total=size; require(total<=self.max_entry_bytes,'Entry size quota exceeded')
            require(pos+self.page_header+capacity<=self.file_size,'Truncated page capacity')
            require(written<=total,'Excess chain content')
            length=min(capacity,total-written)
            require(capacity>0 or total==0,'Nonprogressing data page')
            spans.append((pos+self.page_header,length)); written+=length
            self.extent=max(self.extent,pos+self.page_header+capacity)
            offset=following
        require(total is not None and written==total,'Incomplete chain')
        return total,spans

    def chunks(self,offset):
        _,spans=self.chain_layout(offset)
        for start,length in spans:
            self.stream.seek(start)
            while length:
                data=self.stream.read(min(CHUNK,length)); require(data,'Unexpected end of page')
                length-=len(data); yield data

    def read_chain(self,offset,*,max_bytes=64*1024*1024):
        size,_=self.chain_layout(offset)
        require(size<=max_bytes,'Memory read quota exceeded')
        return b''.join(self.chunks(offset))

    def read(self,name,*,max_bytes=64*1024*1024):
        return self.read_chain(self.entries[name].data_offset,max_bytes=max_bytes)

    def copy(self,name,target):
        digest=hashlib.sha256(); count=0
        for chunk in self.chunks(self.entries[name].data_offset):
            target.write(chunk); digest.update(chunk); count+=len(chunk)
        require(count==self.entries[name].stored_size,'Copied size mismatch')
        return count,digest.hexdigest()

def catalogs(stream):
    stream.seek(0,2); size=stream.tell(); origin=0; result=[]
    while origin<size:
        require(len(result)<4,'Too many concatenated catalogs')
        catalog=Catalog(stream,origin); require(catalog.extent>origin,'Empty catalog extent')
        result.append(catalog); origin=catalog.extent
    require(origin==size,'Trailing bytes beyond catalog extent')
    return result

def actual_catalog(stream):
    found=catalogs(stream)
    # Modern dual-format CF contains a legacy compatibility catalog followed by
    # the authoritative 64-bit catalog. Never select the stub by its metadata.
    require(len(found)==1 or (len(found)==2 and found[0].bits==32 and found[1].bits==64),'Unsupported catalog sequence')
    return found[-1],found

def inflate_to(chunks,target,*,max_output=32*1024**3):
    decoder=zlib.decompressobj(-15); digest=hashlib.sha256(); total=0
    for chunk in chunks:
        require(not decoder.eof,'Trailing compressed data')
        pending=chunk
        while pending:
            data=decoder.decompress(pending,CHUNK); pending=decoder.unconsumed_tail
            total+=len(data); require(total<=max_output,'Inflated output quota exceeded')
            target.write(data); digest.update(data)
            require(not decoder.unused_data,'Trailing compressed data')
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'Truncated DEFLATE stream')
    return total,digest.hexdigest()

def file_chunks(path):
    with Path(path).open('rb') as f:
        while chunk:=f.read(CHUNK): yield chunk

def page_header(size,capacity,following,width=16):
    return ('\r\n'+''.join(f'{v:0{width}X} ' for v in (size,capacity,following))+'\r\n').encode('ascii')

def write_cf64(path,files,*,legacy_prefix=b''):
    """files: [{name,size,chunks:callable,created?,modified?,attributes?}].

    Stored compressed bytes are copied without recompression. legacy_prefix,
    if present, must be the complete catalog copied from a SQL-derived CF.
    """
    entries=list(files); require(entries and len(entries)<=1000000,'Invalid export count')
    require(len({safe_name(e['name']) for e in entries})==len(entries),'Duplicate export name')
    for entry in entries:
        require(24+len(entry['name'].encode('utf-16le'))<=65536,'Export header size quota')
        require(0<=entry['size']<=16*1024**3,'Export entry size quota')
    if legacy_prefix:
        parsed=catalogs(io.BytesIO(legacy_prefix))
        require(len(parsed)==1 and parsed[0].bits==32,'Invalid legacy compatibility prefix')
    end=0xffffffffffffffff; toc_bytes=len(entries)*24; cap=65536
    toc_pages=math.ceil(toc_bytes/cap)
    with Path(path).open('xb') as out:
        out.write(legacy_prefix); origin=out.tell(); out.write(struct.pack('<QIII',end,512,len(entries),0))
        toc_start=out.tell()
        # Sparse reservation is filled with actual TOC pages before closing.
        out.seek(toc_start+toc_pages*(55+cap)); toc=[]; receipts=[]
        for entry in entries:
            h=struct.pack('<QQI',entry.get('created',0),entry.get('modified',0),entry.get('attributes',0))+entry['name'].encode('utf-16le')+b'\0'*4
            hp=out.tell()-origin; out.write(page_header(len(h),len(h),end)); out.write(h)
            dp=out.tell()-origin; n=entry['size']
            out.write(page_header(n,n,end)); digest=hashlib.sha256(); copied=0
            for chunk in entry['chunks']():
                copied+=len(chunk); require(copied<=n,'Export source grew')
                out.write(chunk); digest.update(chunk)
            require(copied==n,'Export source truncated')
            toc.append(struct.pack('<QQQ',hp,dp,end)); receipts.append({'name':entry['name'],'bytes':n,'sha256':digest.hexdigest()})
        end_position=out.tell(); data=b''.join(toc)
        for i in range(toc_pages):
            at=toc_start+i*(55+cap); following=(at-origin+55+cap) if i+1<toc_pages else end
            part=data[i*cap:(i+1)*cap]; out.seek(at)
            out.write(page_header(toc_bytes if i==0 else 0,cap,following)); out.write(part); out.write(b'\0'*(cap-len(part)))
        out.seek(end_position)
    return receipts
