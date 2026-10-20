"""Offline SQL snapshot -> main CF and one explicitly selected supplier CF.

No 1C runtime; no reference XML input. This stage does not claim native XML.
"""
import argparse,hashlib,io,json
from pathlib import Path
from .brace import Reader,walk
from .snapshot import Snapshot,identity,require
from .support import parse,select,guid
from .v8container import actual_catalog,inflate_to,write_cf64,file_chunks

def cf_tree(catalog,name):
    out=io.BytesIO(); inflate_to(catalog.chunks(catalog.entries[name].data_offset),out,max_output=128*1024**2)
    return Reader(out.getvalue()).read()

def config_identity(tree):
    # v8unpack Configuration.py stores product version at header[15];
    # Tool1CD SupplierConfigBuilder corroborates provider14/version15.
    groups=[(path,node) for path,node in walk(tree) if isinstance(node,list) and len(node)==2 and node[0]=='9cd510cd-abfc-11d4-9434-004095e12fc7']
    require(len(groups)==1,'Missing/ambiguous general metadata group')
    path,group=groups[0]; header=group[1][1]
    require(isinstance(header,list) and header[0] in {'68','76'} and len(header)>15,'Unsupported configuration identity version')
    require(isinstance(header[14],str) and isinstance(header[15],str),'Invalid vendor/version identity')
    require(isinstance(header[1],list) and len(header[1])==2 and header[1][0]=='0','Unsupported general identity wrapper')
    result=identity(header[1][1]); require(result['path']==[],'Missing direct configuration common identity')
    result['path']=list(path)+( [1,1,1,1] )
    return result|{'serialization_version':str(header[0]),'vendor':str(header[14]),'version':str(header[15])}

def check_inventory(source,path):
    path=Path(path); raw=path.read_bytes(); inventory=json.loads(raw.decode('utf-8-sig'))
    require(hashlib.sha256(raw).hexdigest()==source.verification['inventory_sha256'],'Changed capture inventory SHA256')
    require(inventory.get('provenance')=='direct-db-local-v1' and inventory.get('same_transaction') is True,
            'Inventory must share direct capture transaction')
    require(inventory.get('consistency')==source.verification['header']['consistency'],'Inventory consistency mismatch')
    found=[d for d in inventory['databases'] if d['provider']==source.provider and d['database']==source.verification['header']['database']]
    require(len(found)==1,'Inventory provider/database mismatch')
    table_records=found[0]['file_tables']; tables={t['table'].lower():t['rows'] for t in table_records}
    require(len(table_records)==len(tables)==5 and set(tables)=={'config','configsave','configcas','configcassave','depotfiles'},'Duplicate/missing/unknown inventory tables')
    for name in ('configsave','configcas','configcassave','depotfiles'):
        require(name in tables and not tables[name],'Nonempty/missing '+name+' inventory; overlay not supported')
    expected={(r['file_name'],r['part_no']):(r['data_size'],r['stored_bytes'],r['attributes']) for r in tables['config']}
    require(len(expected)==len(tables['config']),'Duplicate Config inventory key')
    actual={(name,r['part_no']):(r['data_size'],r['length'],r['attributes']) for name,rows in source.files.items() for r in rows}
    require(expected==actual,'Captured Config metadata changed since inventory')
    require(all(source.attributes(name)==0 for name in source.names()),'Unsupported SQL Config Attributes')
    return {'path':str(path.resolve()),'sha256':hashlib.sha256(raw).hexdigest(),'captured_utc':found[0]['captured_utc'],
            'empty_file_tables':['ConfigSave','ConfigCAS','ConfigCASSave','DepotFiles'],
            'scope':'same direct DB transaction as Config capture','consistency':inventory['consistency']}

def validate_versions(source):
    versions=source.tree('versions')
    require(isinstance(versions,list) and len(versions)>=2 and versions[0]=='1','Unsupported versions header')
    count=int(versions[1]); require(count>=1 and len(versions)==2+2*count,'Invalid versions count')
    names=versions[2::2]; ids=versions[3::2]
    require(names[0]=='' and len(set(names))==len(names),'Duplicate/invalid version names')
    require(set(names[1:])==set(source.names()),'Versions and source filenames differ')
    for version in ids: guid(version)
    return {'records':count,'source_names':len(names)-1}

def unpack_supplier(chunks,directory):
    """Admit one or two explicit raw-DEFLATE envelopes, then a checked CF.

    SQL-derived BD-004 proves the two-envelope case. Both intermediate layers
    are retained and hashed; no unbounded 'decompress until it works' loop.
    """
    layers=[]
    for number in (1,2):
        path=directory/('envelope-layer'+str(number)+'.bin')
        with path.open('xb') as out: size,digest=inflate_to(chunks,out)
        layers.append({'layer':number,'bytes':size,'sha256':digest,'path':path.name})
        packed=False
        with path.open('rb') as stream:
            marker=stream.read(8)
            if marker[:4]==b'\xff\xff\xff\x7f' or marker==b'\xff'*8:
                actual_catalog(stream); packed=True
        if packed:
            destination=directory/'source.cf'; require(not destination.exists(),'Supplier destination exists'); path.rename(destination)
            layers[-1]['path']='source.cf'
            return destination,size,digest,layers
        chunks=file_chunks(path)
    raise ValueError('Unsupported supplier envelope after two explicit layers')

def export(snapshot,destination,supplier_name,inventory):
    source=Snapshot(snapshot); destination=Path(destination)
    require(not destination.exists(),'Output already exists')
    inventory_check=check_inventory(source,inventory); version_check=validate_versions(source)
    root_tree=source.tree('root'); root=guid(root_tree[1]); main_identity=config_identity(source.tree(root))
    descriptor_name=main_identity['uuid']+'.4'
    parsed=parse(source.inflated(descriptor_name)); supplier=select(parsed,supplier_name,root)
    candidate=supplier['candidate_file']; require(candidate in source.files,'Selected supplier package absent')
    require(source.attributes(candidate)==0,'Unsupported supplier SQL attributes')
    destination.mkdir(parents=True); vendor_dir=destination/'vendor'; vendor_dir.mkdir()
    print(json.dumps({'stage':'inflate-supplier','provider':source.provider,'stored_bytes':source.size(candidate)},ensure_ascii=True),flush=True)
    vendor_file,vendor_bytes,vendor_sha,envelopes=unpack_supplier(source.chunks(candidate),vendor_dir)
    with vendor_file.open('rb') as stream:
        catalog,all_catalogs=actual_catalog(stream)
        vendor_root=guid(cf_tree(catalog,'root')[1]); vendor_identity=config_identity(cf_tree(catalog,vendor_root))
        require(vendor_root==supplier['mapped_root_uuid'],'Supplier CF root differs from support mapping')
        for field in ('name','version','vendor'): require(vendor_identity[field]==supplier[field],'Supplier CF identity mismatch: '+field)
        if len(all_catalogs)==2:
            stream.seek(0); prefix=stream.read(all_catalogs[0].extent)
        else: prefix=b''
        vendor_catalogs=[{'bits':c.bits,'origin':c.origin,'extent':c.extent,'entries':len(c.entries)} for c in all_catalogs]
    main_dir=destination/'main'; main_dir.mkdir(); main_file=main_dir/'source.cf'
    print(json.dumps({'stage':'pack-main','files':len(source.files)},ensure_ascii=True),flush=True)
    receipts=write_cf64(main_file,source.export_cf_entries(),legacy_prefix=prefix)
    # Verify the packed bytes, not just writer bookkeeping. Every stored entry
    # must reproduce its independently hashed SQL parts exactly.
    with main_file.open('rb') as stream:
        actual,catalog_list=actual_catalog(stream)
        require(set(actual.entries)==set(source.names()),'Packed main file set mismatch')
        for r in receipts:
            digest=hashlib.sha256()
            for chunk in actual.chunks(actual.entries[r['name']].data_offset): digest.update(chunk)
            require(actual.entries[r['name']].stored_size==r['bytes'] and digest.hexdigest()==r['sha256'],'Packed main entry mismatch')
    with main_file.open('rb') as stream: main_sha=hashlib.file_digest(stream,'sha256').hexdigest()
    manifest={'status':'CF_BYTES_VERIFIED_XML_PENDING','provider':source.provider,'capture':str(source.path.resolve()),
              'capture_sha256':source.verification['sha256'],'inventory_check':inventory_check,'versions_check':version_check,'root_uuid':root,'main_identity':main_identity,
              'suppliers':[{k:v for k,v in s.items() if k!='objects'} for s in parsed['records']],
              'selected_supplier':{k:v for k,v in supplier.items() if k!='objects'},'supplier_identity':vendor_identity,
              'supplier_cf':{'path':'vendor/source.cf','bytes':vendor_bytes,'sha256':vendor_sha,'catalogs':vendor_catalogs,'compression_layers':envelopes},
              'main_cf':{'path':'main/source.cf','bytes':main_file.stat().st_size,'sha256':main_sha,'files':len(receipts)},
              'limits':['native XML not produced by this stage','CF platform loading not tested','SQL timestamps not translated to CF entry headers; source values remain in capture index','packed CF catalogs only; empty overlays checked in same direct DB transaction']}
    (destination/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    with (destination/'main-stored-files.jsonl').open('x',encoding='utf-8') as out:
        for r in receipts: out.write(json.dumps(r,separators=(',',':'))+'\n')
    print(json.dumps(manifest,ensure_ascii=True),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',required=True); parser.add_argument('--output',required=True); parser.add_argument('--supplier',required=True); parser.add_argument('--inventory',required=True)
    args=parser.parse_args(); export(args.capture,args.output,args.supplier,args.inventory)
