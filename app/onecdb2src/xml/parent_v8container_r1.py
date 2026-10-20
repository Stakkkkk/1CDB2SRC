"""Parent-asset catalog reader with bounded live/free page geometry.

The first header field is a free-list pointer, not a format magic. Width is
selected only by unique header fields plus the exact root page grammar.
Full contiguous allocation coverage is required; this is not a metadata
schema decoder. Frozen BD-007/main CFSource remains unchanged.
"""
import re
import struct
from ..sqlcf import v8container as base

require=base.require


def widths(stream,origin):
    stream.seek(origin);head=stream.read(20);found=[]
    for bits,hs,ph,fmt in [(32,16,31,'<IIII'),(64,20,55,'<QIII')]:
        if len(head)<hs:continue
        free,block,declared,reserved=struct.unpack(fmt,head[:hs])
        if block<=0 or reserved!=0:continue
        stream.seek(origin+hs);page=stream.read(ph)
        pattern=rb'\r\n'+(rb'[0-9a-fA-F]{%d} '%(bits//4))*3+rb'\r\n'
        if re.fullmatch(pattern,page):found.append(bits)
    return found


class Catalog(base.Catalog):
    def __init__(self,stream,origin=0,*,max_entries=1000000,max_entry_bytes=16*1024**3,max_pages=2000000):
        self.stream=stream;self.origin=origin
        self.max_entries=max_entries;self.max_entry_bytes=max_entry_bytes;self.max_pages=max_pages
        stream.seek(0,2);self.file_size=stream.tell()
        require(isinstance(origin,int) and 0<=origin<self.file_size,'Invalid catalog origin')
        candidates=widths(stream,origin)
        require(len(candidates)==1,'Missing/ambiguous catalog width at '+str(origin))
        self.bits=candidates[0];self.width=self.bits//4
        self.header_size=16 if self.bits==32 else 20
        self.page_header=31 if self.bits==32 else 55
        self.end=0x7fffffff if self.bits==32 else 0xffffffffffffffff
        self.record='<III' if self.bits==32 else '<QQQ'
        stream.seek(origin)
        self.first_free,self.default_block,self.declared_count,_=struct.unpack('<IIII' if self.bits==32 else '<QIII',stream.read(self.header_size))
        self.pattern=re.compile(rb'\r\n'+(rb'[0-9a-fA-F]{%d} '%self.width)*3+rb'\r\n')
        self.extent=origin+self.header_size;self.entries={};self.pages={};self.chains={}
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
            name=base.safe_name(text.partition('\0')[0])
            require(name not in self.entries,'Duplicate container filename')
            size,_=self.chain_layout(dp)
            self.entries[name]=base.Entry(name,hp,dp,size,created,modified,attributes)
        offset=self.first_free;seen=set();self.free_pages=0
        while offset!=self.end:
            require(offset not in seen,'Cyclic free page chain');seen.add(offset)
            size,capacity,following,_=self._page(offset,'free')
            require(size==self.end and capacity>0,'Invalid free page marker/capacity')
            self.free_pages+=1;offset=following
        intervals=[(origin,origin+self.header_size)]+[(self.origin+off,self.origin+off+self.page_header+v[1]) for off,v in self.pages.items()]
        intervals.sort();cursor=origin
        for start,stop in intervals:
            require(start==cursor,'Overlapping pages or unexplained allocation gap')
            cursor=stop
        require(cursor==self.extent,'Catalog extent mismatch')

    def _page(self,offset,kind):
        require(isinstance(offset,int) and self.header_size<=offset<=self.file_size-self.origin-self.page_header,'Page pointer outside file')
        require(offset not in self.pages,'Shared interior/free page pointer')
        require(len(self.pages)<self.max_pages,'Catalog page quota exceeded')
        pos=self.origin+offset;self.stream.seek(pos);h=self.stream.read(self.page_header)
        require(self.pattern.fullmatch(h) is not None,'Malformed page header')
        size,capacity,following=(int(x,16) for x in h.strip().split())
        require(pos+self.page_header+capacity<=self.file_size,'Truncated page capacity')
        self.pages[offset]=(size,capacity,following,kind)
        self.extent=max(self.extent,pos+self.page_header+capacity)
        return size,capacity,following,pos+self.page_header

    def chain_layout(self,offset):
        # Re-reading an identical chain start is expected by inherited read/copy.
        # Exact live aliases are admitted; shared suffix/interior chains refuse.
        if offset in self.chains:return self.chains[offset]
        first=offset;seen=set();total=None;written=0;spans=[]
        while offset!=self.end:
            require(offset not in seen,'Cyclic data page chain');seen.add(offset)
            size,capacity,following,payload=self._page(offset,'live')
            if total is None:
                total=size;require(total<=self.max_entry_bytes,'Entry size quota exceeded')
            require(written<=total,'Excess chain content')
            require(capacity>0 or total==0,'Nonprogressing data page')
            length=min(capacity,total-written);spans.append((payload,length));written+=length
            offset=following
        require(total is not None and written==total,'Incomplete chain')
        self.chains[first]=(total,spans)
        return total,spans


def actual_catalog(stream):
    stream.seek(0,2);size=stream.tell();origin=0;found=[]
    while origin<size:
        require(len(found)<2,'Too many concatenated parent catalogs')
        cat=Catalog(stream,origin);require(cat.extent>origin,'Empty catalog extent')
        found.append(cat);origin=cat.extent
    require(origin==size,'Trailing bytes beyond catalog extent')
    require(len(found)==1 or (len(found)==2 and found[0].bits==32 and found[1].bits==64),'Unsupported catalog sequence')
    return found[-1],found


def unpack_supplier(chunks,directory):
    layers=[]
    for number in (1,2):
        path=directory/('envelope-layer'+str(number)+'.bin')
        with path.open('xb') as out:size,digest=base.inflate_to(chunks,out)
        layers.append({'layer':number,'bytes':size,'sha256':digest,'path':path.name})
        with path.open('rb') as stream:
            packed=bool(widths(stream,0))
            if packed:actual_catalog(stream)
        if packed:
            destination=directory/'source.cf';require(not destination.exists(),'Supplier destination exists')
            path.rename(destination);layers[-1]['path']='source.cf'
            return destination,size,digest,layers
        chunks=base.file_chunks(path)
    raise ValueError('Unsupported supplier envelope after two explicit layers')
