"""Assemble CF-derived native outputs in a new tree; never accepts an oracle.

Engine refusals remain recorded. Assembly is a candidate, not an acceptance:
an independent verifier must compare every output file after generation.
"""
import argparse
import hashlib
import json
import os
import stat
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

from .dump_info import CFSource, digest, long_path
from . import dump_info_modern_r3 as signature_rules
from .. import profiles


class AssemblyValidationError(ValueError):
    """Trusted validation of the assembler's own fixed input contracts."""


def require(condition,message):
    if not condition:
        raise AssemblyValidationError(message)


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def run_inputs(path,profile=None):
    path = Path(path).resolve(strict=True)
    receipt = load(path / 'receipt.json')
    source = Path(receipt['source']['path']).resolve(strict=True)
    require(digest(source) == receipt['source']['sha256'] == receipt['source']['sha256_after'],
            'Run CF digest mismatch')
    tree = Path(receipt['native_xml']).resolve(strict=True)
    require(tree == path / 'tree' / 'xml', 'Unexpected run tree')
    report = load(path / 'engine.stderr.json')
    if profile is not None:
        profiles.validate(profile,source)
        signature_rules.validate_profile_run(profile,receipt,report)
        signature_rules.validate_metadata_envelopes(long_path(tree),profile['xml_version'])
    entries = report['export']['storage']['entries']
    require(len({row['logical_name'] for row in entries}) == len(entries), 'Duplicate report entry')
    archive = CFSource(source)
    try:
        require({row['logical_name'] for row in entries} == set(archive.names()), 'Report/CF inventory mismatch')
        require(all(row['packed_bytes'] == archive.catalog.entries[row['logical_name']].stored_size for row in entries),
                'Report/CF stored length mismatch')
    finally:
        archive.close()
    return path, receipt, source, tree, entries


def regular(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
            'Nonregular/reparse file: ' + str(path))
    return info


def signature(info):
    return info.st_size, info.st_mtime_ns, info.st_ino, info.st_dev


def copy_file(source, target):
    before = regular(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    with source.open('rb') as src, target.open('xb') as dst:
        while data := src.read(1024 * 1024):
            hasher.update(data)
            dst.write(data)
    require(signature(before) == signature(regular(source)), 'Source changed during copy')
    require(digest(target) == hasher.hexdigest(), 'Copied bytes mismatch')
    return {'sha256': hasher.hexdigest(), 'bytes': before.st_size}


def stored_hash(source, name):
    hasher = hashlib.sha256()
    entry = source.catalog.entries[name]
    for block in source.catalog.chunks(entry.data_offset):
        hasher.update(block)
    return entry.stored_size, hasher.hexdigest()


def safe_relative(value):
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and '..' not in path.parts and '\\' not in value
            and ':' not in value, 'Unsafe output path')
    return Path(*path.parts)


def native_parent_exists(tree,relative):
    """Reject case aliases/reparse ancestors before considering native reuse."""
    current=long_path(tree)
    for index,part in enumerate(relative.parts):
        state=current.lstat()
        require(stat.S_ISDIR(state.st_mode) and not getattr(state,'st_file_attributes',0)&0x400,
                'Nonregular/reparse native parent directory')
        matches=[child for child in current.iterdir() if child.name.casefold()==part.casefold()]
        require(len(matches)<=1,'Ambiguous native parent case collision')
        if not matches:return False
        require(matches[0].name==part,'Native parent path case mismatch')
        current=matches[0]
    return True



def validated_parent_assets(component,cf,run,tree,entries):
    from . import extract_parent_assets_r8 as parent_producer
    component=Path(component).resolve(strict=True)
    receipt_path=component/'receipt.json';receipt_sha=digest(receipt_path);data=load(receipt_path)
    require(data['status']=='CF_DERIVED_ASSETS_POSTGEN_VERIFICATION_REQUIRED','Parent assets not complete')
    require(data['operation']=='OPAQUE_PARENT_CF_PRESERVATION' and data['internal_metadata_decode']=='UNKNOWN','Parent receipt must declare opaque preservation')
    require(Path(data['source_cf']).resolve()==cf and data['source_cf_sha256']==run['source']['sha256'],'Parent CF/run mismatch')
    require(digest(cf)==run['source']['sha256'],'Parent validation source CF changed')
    require(data['oracle_inputs']==[],'Parent producer accepted oracle inputs')
    require(data['producer_sha256']==digest(parent_producer.__file__),'Parent producer binding changed')
    require(set(data['source_pins'])=={str(path.resolve()) for path in parent_producer.dependency_paths()},'Parent dependency set mismatch')
    require(all(digest(path)==sha for path,sha in data['source_pins'].items()),'Parent dependency pins changed')
    source=CFSource(cf)
    additions={};expected_by_name={row['logical_name']:row for row in entries};handled=[];expected_files={}
    require(len(expected_by_name)==len(entries),'Duplicate parent report logical entry')
    handled_opaque=[];reused_native={};reused_supported=[]
    try:
        expected=parent_producer.plan(source)
        require(expected==data['support'],'Parent support plan changed')
        require(expected['list_name'] in expected_by_name,'Parent support list missing from native report')
        list_row=expected_by_name[expected['list_name']]
        require('Ext/ParentConfigurations.bin' in list_row['outputs'],'Parent list not emitted by this run')
        require(digest(long_path(tree/'Ext/ParentConfigurations.bin'))==expected['list_sha256'],'Emitted support list differs from CF')
        require(len(data['assets'])==len(expected['records']),'Incomplete parent assets')
        assets={asset['logical_name']:asset for asset in data['assets']}
        require(len(assets)==len(data['assets']),'Duplicate parent logical name')
        for record in expected['records']:
            name=record['logical_name'];require(name in assets,'Missing declared parent')
            require(name in expected_by_name,'Declared parent missing from native report')
            asset=assets[name]
            require(all(asset[key]==value for key,value in record.items()),'Parent record/asset mismatch')
            require(asset['raw_asset_status']=='RAW_ASSET_PRESERVED_EXACT' and asset['internal_metadata_decode']=='UNKNOWN','Parent must remain an opaque raw asset')
            file=Path(asset['file']).resolve(strict=True)
            require(file==component/'records'/record['support_id']/'source.cf','Parent asset outside its record directory')
            require(regular(file).st_size==asset['bytes'] and digest(file)==asset['sha256'],'Parent asset bytes mismatch')
            require(stored_hash(source,name)==(asset['stored_bytes'],asset['stored_sha256']),'Parent stored payload changed')
            layers=asset['envelopes'];require(len(layers) in {1,2},'Unknown parent envelope count')
            require([layer['layer'] for layer in layers]==list(range(1,len(layers)+1)),'Invalid parent layer ordinals')
            for number,layer in enumerate(layers,1):
                expected_name='source.cf' if number==len(layers) else 'envelope-layer1.bin'
                require(layer['path']==expected_name,'Unexpected retained layer path')
                path=file.parent/expected_name
                require(regular(path).st_size==layer['bytes'] and digest(path)==layer['sha256'],'Retained parent layer mismatch')
            require(layers[-1]['bytes']==asset['bytes'] and layers[-1]['sha256']==asset['sha256'],'Final envelope binding mismatch')
            # Independently re-inflate each actual input stream into a hash
            # sink. Hashing retained files and a receipt alone does not prove
            # source→layer1→final provenance.
            class Sink:
                def write(self,data):return len(data)
            chunks=source.catalog.chunks(source.catalog.entries[name].data_offset)
            previous_bytes=asset['stored_bytes'];previous_sha=asset['stored_sha256']
            for number,layer in enumerate(layers):
                require(0<=layer['bytes']<=32*1024**3,'Parent layer quota')
                input_sha=hashlib.sha256();input_bytes=[0]
                def counted(stream):
                    for block in stream:
                        input_sha.update(block);input_bytes[0]+=len(block);yield block
                observed=parent_producer.v8container.inflate_to(counted(chunks),Sink(),max_output=layer['bytes'])
                require((input_bytes[0],input_sha.hexdigest())==(previous_bytes,previous_sha),'Parent compressed-chain input differs')
                require(observed==(layer['bytes'],layer['sha256']),'Parent DEFLATE chain mismatch')
                previous_bytes,previous_sha=observed
                chunks=parent_producer.v8container.file_chunks(file.parent/layer['path'])

            with file.open('rb') as stream:
                catalog,_=parent_producer.parent_container.actual_catalog(stream)
                actual_root=parent_producer.support.guid(parent_producer.export_cf.cf_tree(catalog,'root')[1])
                identity=parent_producer.parent_asset_identity(parent_producer.export_cf.cf_tree(catalog,actual_root),actual_root)
                require(actual_root==record['mapped_root_uuid'],'Parent root differs from source mapping')
                require(identity==asset['identity'],'Parent identity-prefix receipt mismatch')
                require(all(identity[key]==record[key] for key in ['name','version','vendor']),'Parent identity mismatch')
            relative=record['path'];safe=safe_relative(relative)
            require(relative not in expected_files,'Duplicate declared parent output path')
            native_file=long_path(tree/safe)
            output_owners=[row['logical_name'] for row in entries if relative in row['outputs']]
            expected_file={'bytes':asset['bytes'],'sha256':asset['sha256']}
            if native_parent_exists(tree,safe):
                # Source/identity/DEFLATE checks above remain mandatory. Reuse
                # only the engine's one declared, byte-identical raw CF output;
                # never schedule an addition or overwrite for this branch.
                require(expected_by_name[name]['disposition']=='supported'
                        and expected_by_name[name]['outputs']==[relative]
                        and output_owners==[name],'Existing parent report binding mismatch')
                before=regular(native_file)
                require(before.st_nlink==1,'Hardlinked native parent forbidden')
                require(before.st_size==asset['bytes'] and digest(native_file)==asset['sha256'],
                        'Existing native parent bytes differ from validated source asset')
                require(signature(before)==signature(regular(native_file)),'Existing native parent changed during validation')
                reused_native[relative]=expected_file;reused_supported.append(name)
            else:
                require(expected_by_name[name]['disposition']=='opaque'
                        and not expected_by_name[name]['outputs'] and not output_owners,
                        'Unexpected existing parent disposition')
                additions[relative]=file;handled_opaque.append(name)
            handled.append(name);expected_files[relative]=expected_file
        require(set(assets)==set(handled),'Undeclared parent assets')
    finally:source.close()
    require(digest(receipt_path)==receipt_sha,'Parent receipt changed during validation')
    require(digest(cf)==run['source']['sha256'],'Parent validation source CF changed after checks')
    return additions,{'component':str(component),'receipt_sha256':receipt_sha,
        'operation':'OPAQUE_PARENT_CF_PRESERVATION','raw_asset_status':'RAW_ASSET_PRESERVED_EXACT',
        'internal_metadata_decode':'UNKNOWN',
        'identity_profiles':{asset['path']:asset['identity'].get('identity_profile','known-identity-prefix-only') for asset in data['assets']},
        'expected_files':expected_files,'source_pins':data['source_pins'],'actual_deflate_chain_revalidated':True,
        'expected_base_files':{'Ext/ParentConfigurations.bin':{'bytes':expected['list_bytes'],'sha256':expected['list_sha256']},**reused_native},
        'producer_sha256':data['producer_sha256'],'cf_source_sha256':data['source_cf_sha256'],
        'handled_opaque_entries':handled_opaque,'all_declared_parent_assets':len(handled),
        'added_parent_assets':len(additions),'reused_native_parent_assets':reused_native,
        'reused_supported_parent_entries':reused_supported,'expected_native_parent_files':reused_native}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-run', required=True)
    parser.add_argument('--dumpinfo', required=True)
    parser.add_argument('--supplement-run')
    parser.add_argument('--supplement-entry', action='append', default=[])
    parser.add_argument('--parent-assets')
    parser.add_argument('--output', required=True)
    parser.add_argument('--profile-receipt', required=True)
    args = parser.parse_args()
    # No supplement repairs are assigned in this bounded profile revision.
    require(not args.supplement_run and not args.supplement_entry,'Supplement profile not supported in this revision')
    initial=load(Path(args.base_run)/'receipt.json')
    profile=profiles.load(args.profile_receipt,initial['source']['path'])
    profile_receipt={'path':str(Path(args.profile_receipt).resolve()),'sha256':digest(args.profile_receipt)}
    base, run, cf, tree, entries = run_inputs(args.base_run,profile)
    require(run['profile_receipt']==profile_receipt,'Native/assembly profile receipt mismatch')
    component = Path(args.dumpinfo).resolve(strict=True)
    info = load(component / 'receipt.json')
    require(info.get('profile')==profile and info.get('profile_receipt')==profile_receipt,'DumpInfo/assembly profile mismatch')
    dump_node=ET.fromstring((component/'ConfigDumpInfo.xml').read_bytes())
    require(dump_node.tag=='{http://v8.1c.ru/8.3/xcf/dumpinfo}ConfigDumpInfo' and dump_node.get('version')==profile['xml_version'],
            'Actual DumpInfo XML profile mismatch')
    if profile['xml_version']=='2.21':
        require(not info.get('suppressed_empty_legacy_records') and not info.get('experimental_legacy_signature'),
                'Unsupported XML2.21 signature projection')
        archive=CFSource(cf)
        try:signature_rules.signature_profile_guard(archive,profile['configuration_uuid'],profile)
        finally:archive.close()
    require(info['status'] == 'CANDIDATE' and not info['unresolved'] and not info['unowned_children']
            and not info['cf_child_discrepancies'], 'DumpInfo refused or incomplete')
    require(info['cf_sha256'] == run['source']['sha256'] and Path(info['cf']).resolve() == cf,
            'DumpInfo CF mismatch')
    require(info['run_receipt_sha256'] == digest(base / 'receipt.json')
            and info['engine_report_sha256'] == digest(base / 'engine.stderr.json'), 'DumpInfo/run binding mismatch')
    require(digest(component / 'ConfigDumpInfo.xml') == info['output_sha256'], 'DumpInfo changed')
    signature_gate = None
    if info.get('suppressed_empty_legacy_records'):
        signature_rules_sha_before = digest(signature_rules.__file__)
        suppressed = info['suppressed_empty_legacy_records']
        require(len(suppressed) == 1, 'Only one exact empty legacy signature may be suppressed')
        source = CFSource(cf)
        try:
            storage = str(source.tree('root')[1])
            identity = signature_rules.cf_identity(source.tree(storage))
            require(suppressed[0]['record'] == identity['uuid'] + '.d'
                    and suppressed[0]['modern_record'] == identity['uuid'] + '.10', 'Suppressed signature identity mismatch')
            require(source.inflated(suppressed[0]['record']) == b'\xef\xbb\xbf{0,"",""}', 'Legacy signature is not empty')
            signature_rules.validate_current_signature_model(source.tree(suppressed[0]['modern_record']))
            require(hashlib.sha256(source.inflated(suppressed[0]['modern_record'])).hexdigest()
                    == suppressed[0]['modern_payload_sha256'], 'Modern signature binding mismatch')
            signature_gate = {'status': 'SIX_NUMERIC_MARKERS_UNQUOTED',
                              'fixed_profile_sha256': signature_rules_sha_before,
                              'note': 'Additional reject-only input validation; original DumpInfo producer SHA is retained'}
        finally:
            source.close()
    destination = Path(args.output).resolve()
    require(not destination.exists(), 'Output already exists')
    for source in (tree, component):
        require(source != destination and source not in destination.parents and destination not in source.parents,
                'Overlapping output and input')
    dumpinfo_file=component/'ConfigDumpInfo.xml'
    dumpinfo_state=regular(dumpinfo_file)
    require(dumpinfo_state.st_nlink==1,'Hardlinked DumpInfo component forbidden')
    dumpinfo_fact={'bytes':dumpinfo_state.st_size,'sha256':digest(dumpinfo_file)}
    require(dumpinfo_fact['sha256']==info['output_sha256'],'DumpInfo source binding changed')
    native_dumpinfo=long_path(tree/'ConfigDumpInfo.xml')
    reuse_dumpinfo=native_parent_exists(tree,Path('ConfigDumpInfo.xml'))
    if reuse_dumpinfo:
        state=regular(native_dumpinfo)
        require(state.st_nlink==1,'Hardlinked native DumpInfo forbidden')
        require(state.st_size==dumpinfo_fact['bytes'] and digest(native_dumpinfo)==dumpinfo_fact['sha256'],
                'Existing native DumpInfo differs from validated component')
        require(signature(state)==signature(regular(native_dumpinfo)),'Native DumpInfo changed during validation')
        native_dump_node=ET.fromstring(native_dumpinfo.read_bytes())
        require(native_dump_node.tag==dump_node.tag and native_dump_node.get('version')==profile['xml_version'],
                'Existing native DumpInfo profile mismatch')
    additions = {} if reuse_dumpinfo else {'ConfigDumpInfo.xml':dumpinfo_file}
    parent_evidence=None
    if args.parent_assets:
        parent_component=Path(args.parent_assets).resolve(strict=True)
        require(parent_component!=destination and parent_component not in destination.parents and destination not in parent_component.parents,'Overlapping parent/output')
        parent_additions,parent_evidence=validated_parent_assets(parent_component,cf,run,tree,entries)
        require(not set(parent_additions)&set(additions),'Parent/addition path collision')
        additions.update(parent_additions)
    metadata_hashes = {row['path']: row['sha256'] for row in info['metadata_xml']}
    require(len(metadata_hashes) == len(info['metadata_xml']), 'Duplicate DumpInfo metadata path')
    seen_metadata = set()
    repaired, supplement_evidence = set(), None
    by_name = {row['logical_name']: row for row in entries}
    require(bool(args.supplement_run) == bool(args.supplement_entry), 'Supplement run/entries must be paired')
    if args.supplement_run:
        supplement, supplement_receipt, probe_cf, probe_tree, probe_entries = run_inputs(args.supplement_run)
        require(probe_tree != destination and probe_tree not in destination.parents and destination not in probe_tree.parents,
                'Overlapping supplement/output')
        main_source, probe_source = CFSource(cf), CFSource(probe_cf)
        try:
            require(set(probe_source.names()) <= set(main_source.names()), 'Supplement is not a CF subset')
            for name in probe_source.names():
                require(stored_hash(probe_source, name) == stored_hash(main_source, name),
                        'Supplement CF stored payload differs: ' + name)
        finally:
            main_source.close()
            probe_source.close()
        probe_by_name = {row['logical_name']: row for row in probe_entries}
        for name in args.supplement_entry:
            require(name not in repaired and by_name[name]['disposition'] == 'failed', 'Only failed entries may be repaired')
            row = probe_by_name[name]
            require(row['disposition'] == 'supported' and row['outputs'], 'Supplement did not decode entry')
            for relative in row['outputs']:
                safe = safe_relative(relative)
                require(relative not in additions and not (long_path(tree) / safe).exists(), 'Supplement overwrites output')
                additions[relative] = long_path(probe_tree) / safe
            repaired.add(name)
        supplement_evidence = {'run': str(supplement), 'receipt_sha256': digest(supplement / 'receipt.json'),
                               'selected_entries': sorted(repaired), 'all_probe_CF_entries_byte_equal_to_base': True}
    require(all(row['logical_name'] in repaired for row in entries if row['disposition'] == 'failed'),
            'Unrepaired failed CF entries')
    destination.mkdir(parents=True)
    output_tree = long_path(destination / 'xml')
    output_tree.mkdir()
    receipt = {'status': 'CANDIDATE_POSTGEN_VERIFICATION_REQUIRED', 'producer_sha256': digest(__file__),
               'profile':profile,'profile_receipt':profile_receipt,
               'base_run': str(base), 'base_receipt_sha256': digest(base / 'receipt.json'),
               'base_status': run['status'], 'base_summary': run['summary'], 'cf_sha256': run['source']['sha256'],
               'dumpinfo_receipt_sha256': digest(component / 'receipt.json'), 'supplement': supplement_evidence,
               'dumpinfo_output':{'mode':'REUSED_NATIVE_BYTE_EXACT' if reuse_dumpinfo else 'ADDED_VALIDATED_COMPONENT',
                                  'path':'ConfigDumpInfo.xml','expected':dumpinfo_fact},
               'signature_input_validation': signature_gate,
               'parent_assets':parent_evidence,
               'oracle_inputs': [], 'unaccepted_opaque_entries': [row['logical_name'] for row in entries if row['disposition'] == 'opaque' and (not parent_evidence or row['logical_name'] not in parent_evidence['handled_opaque_entries'])]}
    count = 0
    seen_parent_base=set();seen_native_dumpinfo=False
    try:
        with (destination / 'files.jsonl').open('x', encoding='utf-8') as manifest:
            root = long_path(tree)
            for base_dir, dirs, files in os.walk(root):
                directory = Path(base_dir)
                for name in dirs:
                    info_stat = (directory / name).lstat()
                    require(stat.S_ISDIR(info_stat.st_mode) and not getattr(info_stat, 'st_file_attributes', 0) & 0x400,
                            'Nonregular/reparse directory')
                    (output_tree / (directory / name).relative_to(root)).mkdir(parents=True, exist_ok=True)
                for name in files:
                    source = directory / name
                    relative = source.relative_to(root)
                    require(relative.as_posix() not in additions, 'Addition already exists in base')
                    record = copy_file(source, output_tree / relative)
                    key = relative.as_posix()
                    if key=='ConfigDumpInfo.xml':
                        require(reuse_dumpinfo and not seen_native_dumpinfo and record==dumpinfo_fact,
                                'Copied native DumpInfo binding mismatch')
                        seen_native_dumpinfo=True
                    if parent_evidence and key in parent_evidence['expected_base_files']:
                        require(record==parent_evidence['expected_base_files'][key],'Copied parent list differs from source CF')
                        seen_parent_base.add(key)
                    if relative.suffix.lower()=='.xml' or key in metadata_hashes:
                        node=ET.parse(output_tree/relative).getroot()
                        if node.tag==signature_rules.MD+'MetaDataObject':
                            require(key in metadata_hashes and record['sha256']==metadata_hashes[key],
                                    'Copied MDClasses metadata differs from DumpInfo inventory: '+key)
                            require(node.get('version')==profile['xml_version'],'Copied MDClasses edition mismatch')
                            seen_metadata.add(key)
                        else:
                            require(key not in metadata_hashes,'Declared metadata has wrong XML envelope: '+key)
                            if node.tag=='{http://v8.1c.ru/8.3/xcf/dumpinfo}ConfigDumpInfo':
                                require(node.get('version')==profile['xml_version'],'Copied DumpInfo edition mismatch')
                    manifest.write(json.dumps({'path': relative.as_posix(), 'source': 'base', **record}, ensure_ascii=False) + '\n')
                    count += 1
                if count and count % 5000 < len(files):
                    print(json.dumps({'stage': 'copy', 'files': count}), flush=True)
            require(count == run['summary']['files_written'], 'Base file count differs from engine report')
            require(seen_native_dumpinfo==reuse_dumpinfo,'Native DumpInfo reuse inventory mismatch')
            if parent_evidence:
                require(seen_parent_base==set(parent_evidence['expected_base_files']),'Source-bound parent base file absent')
            require(seen_metadata == set(metadata_hashes), 'Incomplete DumpInfo metadata inventory')
            for relative, source in sorted(additions.items()):
                record = copy_file(long_path(source), output_tree / safe_relative(relative))
                if relative=='ConfigDumpInfo.xml':
                    require(not reuse_dumpinfo and record==dumpinfo_fact,'Added DumpInfo binding mismatch')
                if parent_evidence and relative in parent_evidence['expected_files']:
                    require(record==parent_evidence['expected_files'][relative],'Copied parent differs from validated asset')
                manifest.write(json.dumps({'path': relative, 'source': str(source), **record}, ensure_ascii=False) + '\n')
                count += 1
        receipt.update(files=count, manifest_sha256=digest(destination / 'files.jsonl'), native_xml=str(destination / 'xml'))
        receipt['metadata_envelope_count']=signature_rules.validate_metadata_envelopes(output_tree,profile['xml_version'])
        require(profiles.load(args.profile_receipt,cf)==profile,'Immutable assembly profile changed')
        require(digest(args.profile_receipt)==profile_receipt['sha256'],'Assembly profile receipt bytes changed')
        require(digest(cf) == receipt['cf_sha256'], 'Base CF changed')
        require(digest(dumpinfo_file)==dumpinfo_fact['sha256'] and regular(dumpinfo_file).st_size==dumpinfo_fact['bytes'],
                'Validated DumpInfo component changed')
        require(digest(__file__) == receipt['producer_sha256'], 'Assembler changed')
        if parent_evidence:
            require(digest(Path(parent_evidence['component'])/'receipt.json')==parent_evidence['receipt_sha256'],'Parent receipt changed')
            require(all(digest(path)==sha for path,sha in parent_evidence['source_pins'].items()),'Parent dependency changed after validation')
        if signature_gate:
            require(digest(signature_rules.__file__) == signature_gate['fixed_profile_sha256'], 'Signature validator changed')
    except Exception as error:
        receipt.update(status='FAILED', error=str(error))
        raise
    finally:
        (destination / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'status': receipt['status'], 'files': count, 'output': str(destination)}), flush=True)


if __name__ == '__main__':
    main()
