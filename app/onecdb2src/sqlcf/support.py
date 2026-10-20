"""Read multi-supplier support records without merging object identities.

Layout evidence: 1c-syntax/supportconf@7729f2c4 and
Stepa86/v8metadata-reader@b907b2a1 (see independent-sources.json).
The two post-record flags and final trailer are retained without guessed meaning.
"""
import re
from .brace import Reader
GUID=re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',re.I)

def require(ok,message):
    if not ok: raise ValueError(message)

def uint(value):
    require(isinstance(value,str) and value.isascii() and value.isdigit(),'Expected unsigned integer')
    return int(value)

def guid(value):
    require(isinstance(value,str) and GUID.fullmatch(value),'Expected UUID')
    return value.lower()

def integer(value):
    require(isinstance(value,str) and re.fullmatch(r'-?[0-9]+',value),'Expected integer')
    return int(value)

def parse(data,*,max_suppliers=1000,max_objects=2000000):
    tree=Reader(data).read()
    require(isinstance(tree,list) and len(tree)>=3 and tree[:2]==['6','0'],'Unsupported support format')
    count=uint(tree[2]); require(count<=max_suppliers,'Supplier quota')
    start=3; records=[]
    for i in range(count):
        require(start+9<=len(tree),'Truncated supplier header')
        header=tree[start:start+7]
        require(all(isinstance(v,str) for v in header),'Nested supplier header')
        objects=uint(header[6]); require(objects<=max_objects,'Supported object quota')
        end=start+9+4*objects; require(end<=len(tree),'Truncated supplier objects')
        pairs=[]
        for pos in range(start+7,end-2,4):
            mode,delivery,current,vendor=tree[pos:pos+4]
            pairs.append({'support_mode':integer(mode),'delivery_mode':integer(delivery),'current_uuid':guid(current),'supplier_uuid':guid(vendor)})
        records.append({'ordinal':i,'token_offset':start,'support_id':guid(header[0]),'modification_prohibited':uint(header[1]),
                        'header_configuration_uuid':guid(header[2]),'version':str(header[3]),'vendor':str(header[4]),'name':str(header[5]),
                        'object_count':objects,'objects':pairs,'tail_flags':tree[end-2:end]})
        start=end
    return {'format':'6','records':records,'trailer':tree[start:]}

def select(parsed,name,current_root):
    found=[r for r in parsed['records'] if r['name']==name]
    require(len(found)==1,'Missing/ambiguous supplier name: '+name)
    result=dict(found[0]); root_matches=[p for p in result['objects'] if p['current_uuid']==guid(current_root)]
    require(len(root_matches)==1,'Missing/ambiguous supplier root mapping')
    result['mapped_root_uuid']=root_matches[0]['supplier_uuid']
    result['candidate_file']=guid(current_root)+'.'+result['support_id']
    return result
