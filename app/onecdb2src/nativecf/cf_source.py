"""Streaming SQL-derived CF source, independent of reference XML directories."""
import io,re
from collections import OrderedDict
from .brace import Reader,walk
from .v8container import actual_catalog,inflate_to,safe_name

GUID=re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',re.I)

def require(ok,message):
    if not ok: raise ValueError(message)

class CFSource:
    def __init__(self,path):
        self.path=path; self.stream=open(path,'rb'); self.catalog,self.catalogs=actual_catalog(self.stream)
        self.cache=OrderedDict(); self.cache_limit=8
    def close(self): self.stream.close()
    def names(self): return self.catalog.entries.keys()
    def inflated(self,name,*,max_output=128*1024**2):
        out=io.BytesIO(); inflate_to(self.catalog.chunks(self.catalog.entries[name].data_offset),out,max_output=max_output); return out.getvalue()
    def tree(self,name):
        if name in self.cache: self.cache.move_to_end(name); return self.cache[name]
        value=Reader(self.inflated(name)).read(); self.cache[name]=value
        while len(self.cache)>self.cache_limit: self.cache.popitem(last=False)
        return value

def identity(tree,expected=None):
    found=[]
    for path,node in walk(tree):
        if not (isinstance(node,list) and len(node)>=5 and isinstance(node[0],str) and node[0] in {'0','1','2','3'}): continue
        key=node[1]
        if not (isinstance(key,list) and len(key)==3 and key[:2]==['1','0'] and isinstance(key[2],str) and GUID.fullmatch(key[2])): continue
        if expected is not None and key[2].lower()!=expected.lower(): continue
        if not isinstance(node[2],str): continue
        found.append({'uuid':str(key[2]).lower(),'name':safe_name(str(node[2])),'common_path':list(path),'common_version':str(node[0])})
    require(found,'Missing metadata identity')
    if expected is None:
        depth=min(len(r['common_path']) for r in found); found=[r for r in found if len(r['common_path'])==depth]
    require(len(found)==1,'Ambiguous metadata identity')
    return found[0]
