"""Extract all declared embedded supplier CF files, using only a source CF.

The independent BD-006 reader supplies counted support records and one/two
explicit DEFLATE envelopes. No platform or reference XML is accepted.
"""
import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

sys.dont_write_bytecode=True
from ..nativecf.cf_source import CFSource,require
from ..nativecf.brace import Reader,walk
from ..sqlcf import support
from ..sqlcf import export_cf
from ..sqlcf import v8container
from . import parent_v8container_r1 as parent_container


def config_identity(tree,expected_root=None):
    """Existing68/76 identity decoder plus the evidenced67/60-field shape.

    The unchanged upstream reader refuses67. Its identity/vendor/version slots
    are shared by67,68,76; ibcmd metadata_model/root_export.rs independently
    distinguishes exact (67,60). This is an identity check, not full metadata
    validation or native import acceptance. No tuple marker is rewritten.
    """
    groups=[(path,node) for path,node in walk(tree) if isinstance(node,list) and len(node)==2 and node[0]=='9cd510cd-abfc-11d4-9434-004095e12fc7']
    require(len(groups)==1,'Missing/ambiguous general metadata group')
    path,group=groups[0]
    require(isinstance(group[1],list) and len(group[1])>1,'Malformed general metadata body')
    header=group[1][1]
    require(isinstance(header,list) and header and isinstance(header[0],str),'Missing configuration identity header')
    if header[0]!='67':return export_cf.config_identity(tree)
    def atom(value,expected=None):
        return isinstance(value,str) and not getattr(value,'quoted',False) and (expected is None or value==expected)
    def canonical_uuid(value):
        return atom(value) and bool(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value)) and value!='00000000-0000-0000-0000-000000000000'
    require(isinstance(tree,list) and len(tree)==11 and atom(tree[0],'2') and atom(tree[2],'7'),'Unsupported legacy counted configuration root')
    require(isinstance(tree[1],list) and len(tree[1])==1 and canonical_uuid(tree[1][0])
            and tree[1][0]==expected_root,'Legacy metadata root differs from named root')
    top=tree[3:10]
    require(all(isinstance(node,list) and len(node)==2 and canonical_uuid(node[0]) for node in top)
            and len({node[0] for node in top})==7,'Invalid/duplicate legacy top-level section')
    require(path==(3,) and group is tree[3],'Shifted/nested legacy General anchor')
    body=group[1]
    require(atom(body[0],'1') and len(body)>=3 and atom(body[2]) and bool(re.fullmatch(r'0|[1-9][0-9]*',body[2]))
            and len(body)==3+int(body[2]),'Invalid legacy Properties count/wrapper')
    require(len(header)==60 and not getattr(header[0],'quoted',False),'Unsupported legacy configuration identity shape')
    require(isinstance(header[1],list) and len(header[1])==2 and header[1][0]=='0'
            and not getattr(header[1][0],'quoted',False),'Unsupported legacy identity wrapper')
    require(all(isinstance(header[i],str) and getattr(header[i],'quoted',False) for i in [14,15]),'Legacy vendor/version must be strings')
    common=header[1][1]
    require(isinstance(common,list) and len(common)==9 and atom(common[0],'3'),'Unsupported legacy common identity shape')
    require(isinstance(common[1],list) and len(common[1])==3 and atom(common[1][0],'1') and atom(common[1][1],'0')
            and canonical_uuid(common[1][2]),'Invalid legacy direct identity key')
    require(isinstance(common[2],str) and getattr(common[2],'quoted',False),'Legacy name must be a string')
    result=export_cf.identity(common);require(result['path']==[],'Missing direct legacy configuration identity')
    result['path']=list(path)+[1,1,1,1]
    return result|{'serialization_version':'67','vendor':str(header[14]),'version':str(header[15])}


def opaque64_parent_identity(tree,expected_root=None):
    """Read only the corroborated identity prefix of an opaque64/57 asset.

    Full schema64 remains UNKNOWN. The outer source entry, DEFLATE chain,
    CF catalog/root and saved bytes are checked by the caller. Other fields
    are preserved in the unchanged CF, not interpreted as metadata XML.
    """
    groups=[(path,node) for path,node in walk(tree) if isinstance(node,list) and len(node)==2 and node[0]=='9cd510cd-abfc-11d4-9434-004095e12fc7']
    require(len(groups)==1,'Missing/ambiguous general metadata group')
    path,group=groups[0]
    require(isinstance(group[1],list) and len(group[1])>1,'Malformed general metadata body')
    header=group[1][1]
    require(isinstance(header,list) and header and isinstance(header[0],str),'Missing configuration identity header')
    require(header[0]=='64','Unsupported opaque identity prefix version')
    def atom(value,expected=None):
        return isinstance(value,str) and not getattr(value,'quoted',False) and (expected is None or value==expected)
    def canonical_uuid(value):
        return atom(value) and bool(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value)) and value!='00000000-0000-0000-0000-000000000000'
    require(isinstance(tree,list) and len(tree)==11 and atom(tree[0],'2') and atom(tree[2],'7'),'Unsupported legacy counted configuration root')
    require(isinstance(tree[1],list) and len(tree[1])==1 and canonical_uuid(tree[1][0])
            and tree[1][0]==expected_root,'Legacy metadata root differs from named root')
    top=tree[3:10]
    require(all(isinstance(node,list) and len(node)==2 and canonical_uuid(node[0]) for node in top)
            and len({node[0] for node in top})==7,'Invalid/duplicate legacy top-level section')
    require(path==(3,) and group is tree[3],'Shifted/nested legacy General anchor')
    body=group[1]
    require(atom(body[0],'1') and len(body)>=3 and atom(body[2]) and bool(re.fullmatch(r'0|[1-9][0-9]*',body[2]))
            and len(body)==3+int(body[2]),'Invalid legacy Properties count/wrapper')
    require(len(header)==57 and not getattr(header[0],'quoted',False),'Unsupported legacy configuration identity shape')
    require(isinstance(header[1],list) and len(header[1])==2 and header[1][0]=='0'
            and not getattr(header[1][0],'quoted',False),'Unsupported legacy identity wrapper')
    require(all(isinstance(header[i],str) and getattr(header[i],'quoted',False) for i in [14,15]),'Legacy vendor/version must be strings')
    common=header[1][1]
    require(isinstance(common,list) and len(common)==9 and atom(common[0],'3'),'Unsupported legacy common identity shape')
    require(isinstance(common[1],list) and len(common[1])==3 and atom(common[1][0],'1') and atom(common[1][1],'0')
            and canonical_uuid(common[1][2]),'Invalid legacy direct identity key')
    require(isinstance(common[2],str) and getattr(common[2],'quoted',False),'Legacy name must be a string')
    result=export_cf.identity(common);require(result['path']==[],'Missing direct legacy configuration identity')
    result['path']=list(path)+[1,1,1,1]
    result=result|{'serialization_version':str(header[0]),'vendor':str(header[14]),'version':str(header[15])}
    if header[0]=='64':
        result.update(identity_profile='bounded-64-57-v3-prefix',serialization_arity=57,
                      full_metadata_layout_validation='NOT_PERFORMED_SCHEMA_UNKNOWN')
    return result


def parent_asset_identity(tree,expected_root):
    """Explicit asset-only route; never upgrades the strict metadata decoder."""
    marker=None
    if isinstance(tree,list) and len(tree)>3 and isinstance(tree[3],list) and len(tree[3])==2:
        body=tree[3][1]
        if isinstance(body,list) and len(body)>1 and isinstance(body[1],list) and body[1]:marker=body[1][0]
    if marker=='64':return opaque64_parent_identity(tree,expected_root)
    return config_identity(tree,expected_root)


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def regular_state(path):
    value=Path(path).lstat()
    require(stat.S_ISREG(value.st_mode) and not getattr(value,'st_file_attributes',0)&0x400,'Nonregular/reparse input')
    return [value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns]


def safe_name(name):
    require(isinstance(name,str) and name and name not in {'.','..'},'Empty/relative supplier name')
    require(not any(c in name for c in '<>:"/\\|?*') and all(ord(c)>=32 for c in name),'Unsafe supplier name')
    require(name.rstrip(' .')==name,'Windows trailing dot/space in supplier name')
    require(name.split('.',1)[0].upper() not in {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))},'Reserved Windows supplier name')
    return name


def plan(source):
    root=source.tree('root')
    require(isinstance(root,list) and len(root)>=2,'Invalid root record')
    current=support.guid(root[1])
    identity=config_identity(source.tree(current),current)
    list_name=identity['uuid']+'.4'
    require(list_name in source.names(),'Support descriptor absent')
    payload=source.inflated(list_name,max_output=64*1024**2)
    parsed=support.parse(payload)
    lexical=Reader(payload).read()
    # Reuse the established counted grammar; add lexical and name/identity
    # checks without assigning guessed meanings to post-record/trailer flags.
    require(all(not getattr(lexical[i],'quoted',False) for i in range(3)),'Quoted support header marker/count')
    records=[];seen_ids=set();seen_paths=set();seen_bodies=set()
    physical=set(source.names())
    for record in parsed['records']:
        start=record['token_offset'];header=lexical[start:start+7]
        require([bool(getattr(v,'quoted',False)) for v in header]==[False,False,False,True,True,True,False],'Unsupported support header lexical types')
        end=start+9+4*record['object_count']
        require(all(isinstance(v,str) and not getattr(v,'quoted',False) for v in lexical[start+7:end]),'Quoted/nested object mapping or post-record flag')
        require(all(re.fullmatch(r'-?[0-9]+',str(v)) for v in lexical[end-2:end]),'Non-numeric post-record flags')
        name=safe_name(record['name']);relative='Ext/ParentConfigurations/'+name+'.cf'
        require(record['support_id'] not in seen_ids and relative.casefold() not in seen_paths,'Duplicate support ID/output path')
        seen_ids.add(record['support_id']);seen_paths.add(relative.casefold())
        matches=[item for item in record['objects'] if item['current_uuid']==current]
        require(len(matches)==1,'Missing/ambiguous current-root supplier mapping')
        require(matches[0]['supplier_uuid']!='00000000-0000-0000-0000-000000000000','Nil mapped supplier root')
        body=current+'.'+record['support_id']
        require(body in physical and body not in seen_bodies,'Missing/duplicate embedded supplier storage')
        seen_bodies.add(body)
        records.append({k:record[k] for k in ['ordinal','token_offset','support_id','header_configuration_uuid','name','version','vendor','object_count']}
            |{'logical_name':body,'mapped_root_uuid':matches[0]['supplier_uuid'],'path':relative})
    return {'configuration_root':current,'configuration_identity':identity,'list_name':list_name,
            'list_bytes':len(payload),'list_sha256':hashlib.sha256(payload).hexdigest(),
            'trailer_tokens_retained_in_original_list':len(parsed['trailer']),'records':records}


def extract_one(source,record,directory):
    directory.mkdir()
    entry=source.catalog.entries[record['logical_name']]
    stored=hashlib.sha256();stored_bytes=0
    def chunks():
        nonlocal stored_bytes
        for data in source.catalog.chunks(entry.data_offset):
            stored.update(data);stored_bytes+=len(data);yield data
    path,size,sha,layers=parent_container.unpack_supplier(chunks(),directory)
    require(stored_bytes==entry.stored_size,'Embedded storage length mismatch')
    with path.open('rb') as stream:
        catalog,catalogs=parent_container.actual_catalog(stream)
        root=support.guid(export_cf.cf_tree(catalog,'root')[1])
        identity=parent_asset_identity(export_cf.cf_tree(catalog,root),root)
        require(root==record['mapped_root_uuid'],'Nested CF root mapping mismatch')
        for key in ['name','version','vendor']:
            require(identity[key]==record[key],'Nested CF identity mismatch: '+key)
        inventory=[{'bits':item.bits,'origin':item.origin,'extent':item.extent,'entries':len(item.entries)} for item in catalogs]
    require(path.stat().st_size==size and digest(path)==sha,'Nested CF final bytes changed')
    return record|{'raw_asset_status':'RAW_ASSET_PRESERVED_EXACT','internal_metadata_decode':'UNKNOWN',
                   'file':str(path.resolve()),'bytes':size,'sha256':sha,'stored_bytes':stored_bytes,
                   'stored_sha256':stored.hexdigest(),'envelopes':layers,'identity':identity,'catalogs':inventory}


def dependency_paths():
    return [Path(__file__),Path(sys.modules['onecdb2src.nativecf.cf_source'].__file__),Path(sys.modules['onecdb2src.nativecf.brace'].__file__),Path(support.__file__),Path(export_cf.__file__),Path(v8container.__file__),Path(sys.modules['onecdb2src.sqlcf.snapshot'].__file__),Path(parent_container.__file__)]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cf',required=True);parser.add_argument('--expected-sha256',required=True)
    parser.add_argument('--output',required=True);args=parser.parse_args()
    cf=Path(args.cf).resolve(strict=True);destination=Path(args.output).resolve()
    require(not destination.exists() and cf not in destination.parents,'Output exists or overlaps source')
    state=regular_state(cf);require(digest(cf)==args.expected_sha256,'Source CF SHA mismatch')
    dependencies=dependency_paths()
    pins={str(path.resolve()):digest(path) for path in dependencies}
    destination.mkdir(parents=True);(destination/'records').mkdir()
    receipt={'status':'RUNNING','operation':'OPAQUE_PARENT_CF_PRESERVATION',
             'internal_metadata_decode':'UNKNOWN','producer_sha256':pins[str(Path(__file__).resolve())],
             'source_cf':str(cf),'source_cf_sha256':args.expected_sha256,'source_state_before':state,
             'source_pins':pins,'oracle_inputs':[],'assets':[]}
    source=None
    try:
        source=CFSource(cf);receipt['support']=plan(source)
        for record in receipt['support']['records']:
            asset=extract_one(source,record,destination/'records'/record['support_id']);receipt['assets'].append(asset)
            print(json.dumps({'stage':'parent-cf-extracted','ordinal':record['ordinal'],'name':record['name'],'bytes':asset['bytes'],'sha256':asset['sha256']},ensure_ascii=False),flush=True)
        source.close();source=None
        require(regular_state(cf)==state and digest(cf)==args.expected_sha256,'Source CF changed')
        require(all(digest(path)==sha for path,sha in pins.items()),'Producer dependency changed')
        receipt.update(status='CF_DERIVED_ASSETS_POSTGEN_VERIFICATION_REQUIRED',source_state_after=regular_state(cf))
    except Exception as error:
        receipt.update(status='FAILED',error_type=type(error).__name__,error=str(error));raise
    finally:
        if source:source.close()
        (destination/'receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf8')


if __name__=='__main__':main()
