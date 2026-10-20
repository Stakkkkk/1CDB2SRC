"""Closed top-level CF structural profile authority (not semantic XML validation).

Structural model: metadata_model/root_export.rs read_row; root.rs SECTIONS;
mssql_dump/refs.rs root owner/header/footer; configuration_root.rs V76 pairs.
Only two complete seven-section shapes are admitted. No nested identity search,
configuration names, business versions, data hashes or oracle select a profile.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .nativecf.brace import Atom
from .nativecf.cf_source import CFSource

NIL = '00000000-0000-0000-0000-000000000000'
GUID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}')
# Fixed language/model class identifiers, never identities of a configuration.
SECTIONS = (
    ('9cd510cd-abfc-11d4-9434-004095e12fc7','properties',(
        '09736b02-9cac-4e3f-b4f7-d3e9576ab948','0c89c792-16c3-11d5-b96b-0050bae0a95d',
        '0fe48980-252d-11d6-a3c7-0050bae0a776','0fffc09c-8f4c-47cc-b41c-8d5c5a221d79',
        '102f6202-43fa-40b0-8898-acd3876daacb','11bdaf85-d5ad-4d91-bb24-aa0eee139052',
        '15794563-ccec-41f6-a83c-ec5f7b9a5bc1','24c43748-c938-45d0-8d14-01424a72b11e',
        '30d554db-541e-4f62-8970-a1c6dcfeb2bc','37f2fa9a-b276-11d4-9435-004095e12fc7',
        '39bddf6a-0c3c-452b-921c-d99cfa1c2f1b','3e5404af-6ef8-4c73-ad11-91bd2dfac4c8',
        '3e7bfcc0-067d-11d6-a3c7-0050bae0a776','46b4cd97-fd13-4eaa-aba2-3bddd7699218',
        '4e828da6-0f44-4b5b-b1c0-a2b3cfe7bdcc','58848766-36ea-4076-8800-e91eb49590d7',
        '6e6dc072-b7ac-41e7-8f88-278d25b6da2a','7dcd43d9-aca5-4926-b549-1842e6a4e8cf',
        '857c4a91-e5f4-4fac-86ec-787626f1c108','8657032e-7740-4e1d-a3ba-5dd6e8afb78f',
        '9cd510ce-abfc-11d4-9434-004095e12fc7','a7641777-7813-45c6-96ef-9d51587a6ac6',
        'af547940-3268-434f-a3e7-e47d6d2638c3','c045099e-13b9-4fb6-9d50-fca00202971e',
        'cc9df798-7c94-4616-97d2-7aa0b7bc515e','d26096fb-7a5d-4df9-af63-47d04771fa9b')),
    ('9fcd25a0-4822-11d4-9414-008048da11f9','directory',(
        '0195e80c-b157-11d4-9435-004095e12fc7','061d872a-5787-460e-95ac-ed74ea3a3e84',
        '07ee8426-87f1-11d5-b99c-0050bae0a95d','13134201-f60b-11d5-a3c7-0050bae0a776',
        '1c57eabe-7349-44b3-b1de-ebfeab67b47d','2f1a5187-fb0e-4b05-9489-dc5dd6412348',
        '36a8e346-9aaa-4af9-bdbd-83be3c177977','4612bd75-71b7-4a5c-8cc5-2b0b65f9fa0d',
        '631b75a0-29e2-11d6-a3c7-0050bae0a776','82a1b659-b220-4d94-a9bd-14d757b95a48',
        'b64d9a40-1642-11d6-a3c7-0050bae0a776','bc587f20-35d9-11d6-a3c7-0050bae0a776',
        'bf845118-327b-4682-b5c6-285d2a0eb296','cf4abea6-37b2-11d4-940f-008048da11f9',
        'f6a80749-5ad7-400b-8519-39dc5dff2542')),
    ('e3687481-0a87-462c-a166-9f34594f9bba','zero',('238e7e88-3c5f-48b2-8a3b-81ebbecb20ed','2deed9b8-0056-4ffe-a473-c20a6c32a0bc')),
    ('9de14907-ec23-4a07-96f0-85521cb6b53b','direct',('30b100d6-b29f-47ac-aec7-cb8ca8a54767','f2de87a8-64e5-45eb-a22d-b3aedab050e7')),
    ('51f2d5d8-ea4d-4064-8892-82951750031e','zero',('3e63355c-1378-4953-be9b-1deb5fb6bec5','fcd3404e-1523-48ce-9bc0-ecdb822684a1')),
    ('e68182ea-4237-4383-967f-90c1e3370bc7','direct',('5274d9fc-9c3a-4a71-8f5e-a0db8ab23de5',)),
    ('fb282519-d103-4dd3-bc12-cb271d631dfc','direct',('bf3420b0-f6f9-41a0-b83a-fe9d4ab0b65d',)),
)
KEYS = frozenset(('schema','cf_path','cf_bytes','cf_sha256','root_storage_uuid','configuration_uuid',
    'shape_tag','shape_arity','interface_pair','platform_profile','xml_version','requested_platform',
    'selection_mode','detector_sha256','profile_id'))

def require(condition,message):
    if not condition:
        raise ValueError('CF profile: '+message)

def _list(value, size=None):
    require(type(value) is list and (size is None or len(value)==size),'invalid wrapper/arity')
    return value

def _atom(value, expected=None):
    require(isinstance(value,Atom) and not value.quoted,'unquoted scalar required')
    require(expected is None or value==expected,'unexpected scalar')
    return str(value)

def _string(value):
    require(isinstance(value,Atom) and value.quoted,'quoted string required')
    return str(value)

def _number(value):
    text = _atom(value)
    require(re.fullmatch(r'0|[1-9][0-9]{0,8}',text) is not None,'invalid canonical count')
    return int(text)

def _uuid(value, *, nonzero=True):
    text = _atom(value)
    require(GUID.fullmatch(text) is not None and (not nonzero or text.lower()!=NIL),'invalid UUID')
    return text.lower()

def _identity(node):
    node = _list(node,3)
    _atom(node[0],'1'); _atom(node[1],'0')
    return _uuid(node[2])

def _header(wrapper):
    wrapper = _list(wrapper,2)
    _atom(wrapper[0],'0')
    h = _list(wrapper[1])
    require(len(h)>=8,'truncated property owner header')
    pairs = _number(h[6]); nil_at = 7+2*pairs
    require(len(h) in (nil_at+1,nil_at+2),'owner state pair count mismatch')
    trailing = len(h)==nil_at+2
    _atom(h[0],'3' if trailing else '2')
    owner = _identity(h[1])
    _string(h[2]); _string(h[4]); _atom(h[5],'0')
    synonym = _list(h[3]); require(bool(synonym),'missing synonym count')
    require(len(synonym)==1+2*_number(synonym[0]),'synonym count mismatch')
    for value in synonym[1:]: _string(value)
    states = set()
    for index in range(pairs):
        state_uuid = _uuid(h[7+2*index])
        require(state_uuid not in states,'duplicate owner state UUID')
        states.add(state_uuid)
        require(_atom(h[8+2*index]) in ('2','3'),'unknown owner state')
    _atom(h[nil_at],NIL)
    if trailing: _atom(h[nil_at+1],'0')
    return owner

def _footer(node):
    node = _list(node)
    require(len(node) in (1,2),'unknown root footer')
    marker = _list(node[0],3)
    first,second = _string(marker[1]),_string(marker[2])
    tag = _atom(marker[0])
    if tag=='0' and len(node)==1:
        require((first==second=='') or (bool(first) and bool(second)),'partial signed footer')
        return
    require(tag=='1' and len(node)==2 and first==second=='','unknown root footer variant')
    checksum = _atom(_list(node[1],1)[0])
    require(re.fullmatch(r'-?(?:0|[1-9][0-9]{0,9})',checksum) is not None and -(2**31)<=int(checksum)<2**31,'invalid footer checksum')

def _detect_rows(root,row):
    root = _list(root)
    # Accepted root_export::root_configuration_uuid reads only members 0/1
    # from {2,<uuid>,...}. Remaining parsed members are opaque, not identity
    # or profile authority. Their grammar/cryptographic meaning is UNKNOWN;
    # do not invent Base64/empty-only/arity constraints. CFSource's bounded
    # parser controls size/depth/nodes; the immutable whole-CF hash binds the
    # original unchanged bytes, including every opaque member.
    require(len(root)>=2,'truncated root pointer')
    _atom(root[0],'2')
    storage = _uuid(root[1])
    row = _list(row,11)
    _atom(row[0],'2')
    configuration = _uuid(_list(row[1],1)[0])
    require(configuration==storage,'root pointer and Configuration UUID differ')
    require(_number(row[2])==7,'exactly seven root sections required')
    _footer(row[-1])
    owners = set()
    children = set()
    properties = None
    for section,(class_id,wrapper,known_slots) in zip(row[3:10],SECTIONS):
        section = _list(section,2)
        _atom(section[0],class_id)
        body = _list(section[1])
        require(len(body)>=2,'truncated section body')
        if wrapper=='directory':
            _list(body,2); _atom(body[0],'6')
            body = _list(body[1]); require(len(body)>=3,'truncated directory body')
        else:
            require(len(body)>=3,'truncated section body')
        _atom(body[0],'1')
        if wrapper=='properties':
            properties = _list(body[1]); require(len(properties)>1,'missing properties tuple')
            owner = _header(properties[1])
        elif wrapper=='directory':
            identity = _list(body[1],2); _atom(identity[1],NIL)
            owner = _identity(identity[0])
        elif wrapper=='zero':
            identity = _list(body[1],2); _atom(identity[0],'0')
            owner = _identity(identity[1])
        else:
            owner = _identity(_list(body[1],1)[0])
        require(owner not in owners and owner!=configuration,'duplicate/contradictory section owner')
        owners.add(owner)
        count = _number(body[2])
        require(len(body)==3+count,'section slot count mismatch')
        classes = set()
        for slot in body[3:]:
            slot = _list(slot); require(len(slot)>=2,'truncated slot')
            slot_class = _uuid(slot[0])
            require(slot_class in known_slots and slot_class not in classes,'unknown/duplicate section slot class')
            classes.add(slot_class)
            require(len(slot)==2+_number(slot[1]),'slot object count mismatch')
            for child in slot[2:]:
                child_uuid = _uuid(child)
                require(child_uuid not in children and child_uuid!=configuration,'duplicate/contradictory root child UUID')
                children.add(child_uuid)
    require(not (owners & children),'section owner reused as child UUID')
    tag = _atom(properties[0])
    require((tag,len(properties)) in (('68',61),('76',77)),'unsupported properties shape (legacy67 is not admitted)')
    # Stored shape authority is independent of business version and name.
    # These lexical bounds are not a semantic equality assertion: V76 stored
    # 80327/80501 is evidenced too. Native semantic guards remain authoritative.
    c26,c43 = _number(properties[26]),_number(properties[43])
    maximum = 80327 if tag=='68' else 80501
    require(80000<=c26<=maximum and 80000<=c43<=maximum,'unsupported compatibility coordinates')
    require(c26<=c43,'contradictory compatibility coordinates')
    _atom(properties[60],'1')
    pair = None
    if tag=='76':
        pair = [_atom(properties[38]),_atom(properties[62])]
        require(tuple(pair) in (('3','3'),('3','6'),('2','2')),'unknown V76 interface pair')
        for index in (61,63,66): _atom(properties[index],'0')
        require((_atom(properties[67]),_atom(properties[68])) in (('0','0'),('1','1')),'unknown V76 defaults pair')
        for index in range(69,77): _atom(properties[index],NIL)
    return dict(root_storage_uuid=storage,configuration_uuid=configuration,shape_tag=tag,
                shape_arity=len(properties),interface_pair=pair,
                platform_profile='8.3.27' if tag=='68' else '8.5.1',xml_version='2.20' if tag=='68' else '2.21')

def _canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')

def _id(profile):
    return hashlib.sha256(_canonical({k:v for k,v in profile.items() if k!='profile_id'})).hexdigest()

def _detector_sha():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

def select(cf_path,request='auto'):
    require(request in ('auto','8.3.27','8.5.1'),'unsupported requested platform')
    path = Path(cf_path).resolve(strict=True)
    require(path.is_file(),'CF must be a regular file')
    # The frozen CFSource constructor opens its handle before catalog parsing;
    # retain the object so even constructor/parser refusal closes that handle.
    source = CFSource.__new__(CFSource)
    try:
        CFSource.__init__(source,path)
        before = os.fstat(source.stream.fileno())
        root = source.tree('root')
        require(type(root) is list and len(root)>=2,'missing root pointer')
        storage = _uuid(root[1])
        require(storage in source.names(),'root pointer target missing from CF')
        facts = _detect_rows(root,source.tree(storage))
        require(request=='auto' or request==facts['platform_profile'],'requested platform contradicts stored CF shape')
        source.stream.seek(0)
        digest = hashlib.file_digest(source.stream,'sha256').hexdigest()
        after = os.fstat(source.stream.fileno())
        current = path.stat()
        token = lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
        # On Windows handle ctime and path ctime have different historical
        # meanings. Compare ctime only handle-to-handle; identity/mtime/size
        # also bind the current path to that same open handle.
        require(stat.S_ISREG(before.st_mode) and token(before)==token(after)==token(current)
                and before.st_ctime_ns==after.st_ctime_ns,'CF changed during detection')
        result = dict(schema=1,cf_path=str(path),cf_bytes=before.st_size,cf_sha256=digest,
                      requested_platform=request,selection_mode='auto' if request=='auto' else 'explicit',
                      detector_sha256=_detector_sha()) | facts
        result['profile_id'] = _id(result)
        return result
    finally:
        if hasattr(source,'stream'):
            source.close()

def validate(profile,cf_path):
    require(type(profile) is dict and set(profile)==KEYS,'profile has missing/unknown keys')
    require(type(profile['schema']) is int and profile['schema']==1,'unsupported profile schema')
    require(type(profile['cf_bytes']) is int and profile['cf_bytes']>0,'invalid CF byte count')
    require(type(profile['shape_arity']) is int,'invalid shape arity type')
    for key in ('cf_sha256','detector_sha256','profile_id'):
        require(isinstance(profile[key],str) and re.fullmatch('[0-9a-f]{64}',profile[key]) is not None,'invalid profile digest')
    require(_id(profile)==profile['profile_id'],'profile_id mismatch')
    # Recompute guards/tool/CF binding; a caller cannot override a selection.
    expected = select(cf_path,profile['requested_platform'])
    require(profile==expected,'profile does not match current CF/guards/detector')
    return copy.deepcopy(expected)

def _object(pairs):
    result = {}
    for key,value in pairs:
        require(key not in result,'duplicate JSON key')
        result[key]=value
    return result

def load(path,cf_path):
    with Path(path).open('rb') as stream:
        raw = stream.read(65537)
    require(len(raw)<=65536,'profile receipt quota exceeded')
    return validate(json.loads(raw.decode('utf-8'),object_pairs_hook=_object),cf_path)

def save_new(path,profile):
    require(type(profile) is dict,'profile must be an object')
    profile = copy.deepcopy(profile)
    validate(profile,profile.get('cf_path'))
    with Path(path).open('xb') as stream:
        stream.write(_canonical(profile))
