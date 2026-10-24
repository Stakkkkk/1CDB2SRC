"""CF versions + CF-derived native metadata -> candidate ConfigDumpInfo.xml.

No reference XML is accepted. Names/child identities come from the generated
MDClasses projection; storage stamps and membership come from the original CF.
Rules/encoding follow pinned ibcmd-rs config_dump_info.rs and SourceAssetRegistry.
Unresolved versioned records refuse output rather than guessing a role.
"""
import argparse
import collections
import hashlib
import json
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from xml.sax.saxutils import escape

from ..nativecf.cf_source import CFSource, require, identity as cf_identity
from ..nativecf.brace import walk
from .. import profiles

MD = '{http://v8.1c.ru/8.3/MDClasses}'
SERVICES = {'root', 'version', 'versions'}


def validate_profile_run(profile,run,report):
    require(run.get('profile')==profile,'Native immutable profile mismatch')
    require(all(run['engine'].get(key)==profile[key] for key in ('platform_profile','xml_version','profile_id')),
            'Native engine profile mismatch')
    require(report.get('source_version')==profile['xml_version'] and report.get('export',{}).get('source_version')==profile['xml_version'],
            'Engine report XML profile mismatch')


def validate_metadata_envelopes(tree,xml_version):
    require(xml_version in ('2.20','2.21'),'Unsupported metadata XML profile')
    count=0
    for base,dirs,files in os.walk(tree):
        for name in files:
            if not name.endswith('.xml'):continue
            path=Path(base)/name;before=path.stat();raw=path.read_bytes();after=path.stat()
            require((before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns),'Generated XML changed')
            node=ET.fromstring(raw)
            if node.tag==MD+'MetaDataObject':
                require(node.get('version')==xml_version,'Generated MDClasses envelope profile mismatch')
                count+=1
    require(count>0,'No generated MDClasses envelopes')
    return count


def signature_profile_guard(source,configuration_uuid,profile,legacy_flags=False,modern_passthrough=False):
    if profile['xml_version']=='2.21':
        require(not legacy_flags,'Legacy signature projection has no XML2.21 proof')
        names=set(source.names())
        require(configuration_uuid+'.d' not in names,'Unsupported XML2.21 legacy signature form')
        require(configuration_uuid+'.10' not in names or modern_passthrough,
                'XML2.21 modern signature needs explicit byte-preservation validation')
        if modern_passthrough:
            require(configuration_uuid+'.10' in names,'Modern signature record missing')
    else:require(not modern_passthrough,'Modern passthrough profile requires XML2.21')


def validate_modern_signature_passthrough(source,configuration_uuid,profile,entries,generated):
    # Opaque binary route: prove every byte, without interpreting or regenerating
    # the signature. The public registry names .10 MobileClientSignature.
    signature_profile_guard(source,configuration_uuid,profile,modern_passthrough=True)
    require(routes(Path(__file__).resolve().parent/'data/assets.rs').get(('Configuration','10'))=='MobileClientSignature',
            'Modern signature route changed')
    record=configuration_uuid+'.10';rows=[r for r in entries if r['logical_name']==record]
    require(len(rows)==1 and rows[0].get('disposition')=='supported' and
            rows[0]['outputs']==['Ext/MobileClientSignature.bin'],'Modern signature output route missing/ambiguous')
    raw=source.inflated(record);path=long_path(Path(generated)/'Ext/MobileClientSignature.bin')
    import stat
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
            not getattr(before,'st_file_attributes',0)&0x400,'Nonregular signature output')
    require(path.read_bytes()==raw,'Modern signature output differs from CF bytes')
    after=path.lstat()
    require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'Signature changed during validation')
    return {'status':'MODERN_SIGNATURE_CF_BYTES_PRESERVED','record':record,
            'path':'Ext/MobileClientSignature.bin','bytes':len(raw),
            'sha256':hashlib.sha256(raw).hexdigest(),'cryptographic_validation':False,
            'fixed_profile_sha256':digest(__file__)}


def validate_current_signature_model(tree):
    require(tree == ['2', '', '', [['0'], ['0'], ['0'], ['0']], '0']
            and getattr(tree[1], 'quoted', False) and getattr(tree[2], 'quoted', False),
            'Unsupported modern empty converted signature')
    numeric_markers = [tree[0], tree[4], *(group[0] for group in tree[3])]
    require(all(not getattr(marker, 'quoted', False) for marker in numeric_markers),
            'Modern signature numeric markers must be unquoted')


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def long_path(path):
    path = Path(path)
    if os.name == 'nt' and not str(path).startswith('\\\\?\\'):
        require(path.is_absolute() and not str(path).startswith('\\\\'), 'Expected local absolute path')
        return Path('\\\\?\\' + str(path))
    return path


def routes(path):
    text = Path(path).read_text(encoding='utf-8')
    text = text.split('const ROUTES: &[SourceAssetRoute] = &[', 1)[1].split('\n];', 1)[0]
    pattern = r'route!\(\s*"(\w+)"\s*,\s*(\w+)\s*,\s*"(\.[0-9a-f]+)"\s*,\s*"([^"]+)"\s*,\s*(\w+)\s*\)'
    found = re.findall(pattern, text)
    require(len(found) == text.count('route!('), 'Unparsed public source route')
    result = {}
    for family, role, suffix, relative, codec in found:
        key = family, suffix[1:]
        value = PurePosixPath(relative).stem
        require(key not in result or result[key] == value, 'Conflicting source route')
        result[key] = value
    return result


def versions(source):
    tree = source.tree('versions')
    require(isinstance(tree, list) and len(tree) >= 2 and tree[0] == '1'
            and not getattr(tree[0], 'quoted', False) and not getattr(tree[1], 'quoted', False)
            and str(tree[1]).isascii() and str(tree[1]).isdigit()
            and len(tree) == 2 + 2 * int(tree[1]), 'Unsupported CF versions count')
    result = {}
    seen = set()
    generation_seen = False
    for offset, (name, stamp) in enumerate(zip(tree[2::2], tree[3::2])):
        require(getattr(name, 'quoted', False), 'CF version name must be quoted')
        require(name not in seen, 'Duplicate version entry')
        seen.add(name)
        require(not getattr(stamp, 'quoted', False), 'CF version stamp must be an atom')
        stamp = uuid.UUID(stamp)
        if name == '':
            require(offset == 0, 'Misplaced generation record')
            generation_seen = True
        if name and name not in SERVICES:
            if stamp.int == 0 and name not in source.names():
                continue
            result[name] = stamp.bytes_le.hex() + '00000000'
    require(generation_seen, 'CF versions generation record missing')
    expected = set(result) | SERVICES
    actual = {name for name in source.names() if '_dynupdate_' not in name and name not in {'deleted', 'DynamicallyUpdated'}}
    require(expected == actual, 'CF versions/physical inventory mismatch')
    return result


def metadata_index(tree, version_ids, configuration_storage, configuration_identity, xml_version=None):
    paths = []
    for base, dirs, files in os.walk(tree):
        if xml_version is None and 'Ext' in dirs and len(Path(base).relative_to(tree).parts) % 2 == 0:
            dirs.remove('Ext')
        paths.extend(Path(base) / name for name in files if name.endswith('.xml'))
    paths.sort(key=lambda path: (len(path.relative_to(tree).parts), path.relative_to(tree).as_posix()))
    path_names, canonical, children, owners, evidence = {}, {}, collections.defaultdict(dict), {}, []
    envelope_count = 0
    if xml_version is not None:
        require(xml_version in ('2.20','2.21'), 'Unsupported metadata XML profile')

    def register(identity, name):
        require(identity not in canonical or canonical[identity] == name, 'Conflicting XML metadata identity')
        canonical[identity] = name

    def descend(node, parent_name, version_owner):
        for child in node:
            current_name, current_owner = parent_name, version_owner
            identity = child.get('uuid')
            name = None
            if identity is not None and child.tag.startswith(MD):
                name = child.findtext(MD + 'Properties/' + MD + 'Name')
                require(name is not None, 'UUID metadata child has no Properties/Name')
            if identity is not None and name is not None and child.tag.startswith(MD):
                identity = str(uuid.UUID(identity))
                require(name and '.' not in name, 'Invalid native metadata child name')
                current_name = parent_name + '.' + child.tag[len(MD):] + '.' + name
                register(identity, current_name)
                if identity in version_ids:
                    current_owner = identity
                else:
                    require(identity not in owners, 'Duplicate metadata child UUID')
                    owners[identity] = version_owner
                    children[version_owner][identity] = current_name
            descend(child, current_name, current_owner)

    for path in paths:
        before = path.stat()
        raw = path.read_bytes()
        after = path.stat()
        require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), 'Generated metadata changed')
        node = ET.fromstring(raw)
        if node.tag != MD + 'MetaDataObject':
            continue
        if xml_version is not None:
            require(node.get('version') == xml_version, 'Generated MDClasses envelope profile mismatch')
            envelope_count += 1
            # Preserve the original metadata_index Ext pruning. Those XML
            # documents still get the envelope/parse guard in this same pass.
            if any(part == 'Ext' and index % 2 == 0
                   for index, part in enumerate(path.relative_to(tree).parts[:-1])):
                continue
        require(len(node) == 1 and node[0].tag.startswith(MD), 'Unsupported native metadata root')
        item = node[0]
        identity = str(uuid.UUID(item.attrib['uuid']))
        family = item.tag[len(MD):]
        name = item.findtext(MD + 'Properties/' + MD + 'Name')
        require(name and '.' not in name, 'Missing/invalid native metadata name')
        relative = path.relative_to(tree)
        parent_key = relative.parent.parent.as_posix()
        parent_name = path_names.get(parent_key)
        require(len(relative.parts) <= 2 or parent_name is not None,
                'Native metadata owner path unresolved: ' + relative.as_posix() + ' (owner ' + parent_key + ')')
        full_name = (parent_name + '.' if parent_name else '') + family + '.' + name
        path_names[relative.with_suffix('').as_posix()] = full_name
        register(identity, full_name)
        storage_id = configuration_storage if family == 'Configuration' else identity
        register(storage_id, full_name)
        if family == 'Configuration':
            require(configuration_identity['name'] == name, 'CF/native configuration name mismatch')
            register(configuration_identity['uuid'], full_name)
        require(storage_id in version_ids, 'Native metadata root absent from CF versions: ' + storage_id)
        descend(item, full_name, storage_id)
        evidence.append({'path': relative.as_posix(), 'source_cf': storage_id, 'sha256': hashlib.sha256(raw).hexdigest()})
    if xml_version is not None:
        require(envelope_count > 0, 'No generated MDClasses envelopes')
        return canonical, children, evidence, envelope_count
    return canonical, children, evidence


def check_cf_children(source, version_ids, children, metadata, configuration_storage, configuration_identity):
    """Independent expected child IDs from the serialized CF common headers."""
    discrepancies = []
    for record in metadata:
        owner = record['source_cf']
        expected = set()
        for path, node in walk(source.tree(owner)):
            if not (isinstance(node, list) and len(node) >= 3 and isinstance(node[0], str)
                    and isinstance(node[2], str)
                    and getattr(node[2], 'quoted', False)):
                continue
            key = node[1]
            if not (isinstance(key, list) and len(key) == 3 and key[:2] == ['1', '0'] and isinstance(key[2], str)):
                continue
            try:
                child_id = str(uuid.UUID(key[2]))
            except ValueError:
                continue
            require(node[0] in {'0', '1', '2', '3'}, 'Unsupported CF common header version: ' + node[0])
            if child_id in version_ids:
                continue
            if owner == configuration_storage and child_id == configuration_identity['uuid']:
                continue
            if owner == configuration_storage and child_id == '00000000-0000-0000-0000-000000000002' and child_id not in children.get(owner, {}):
                continue  # Independent documented unversioned CommandInterface header.
            require(child_id not in expected, 'Duplicate CF child header UUID: ' + child_id)
            expected.add(child_id)
        actual = set(children.get(owner, {}))
        if expected != actual:
            discrepancies.append({'owner': owner, 'missing': sorted(expected-actual), 'extra': sorted(actual-expected)})
    return discrepancies


def top_name(identity, canonical, route_table, outputs, legacy_empty_signature=None, suppressed_empty_signature=None):
    if identity == suppressed_empty_signature:
        return None
    if identity in canonical:
        return canonical[identity]
    base, dot, suffix = identity.rpartition('.')
    require(dot and base in canonical, 'Unknown versioned owner: ' + identity)
    name = canonical[base]
    family = name.split('.')[-2]
    if family == 'Configuration':
        try:
            uuid.UUID(suffix)
            return None  # Embedded supplier CF is not a DumpInfo metadata record.
        except ValueError:
            pass
    paths = [PurePosixPath(path) for path in outputs.get(identity, [])]
    role = None
    if identity == legacy_empty_signature and family == 'Configuration' and suffix == 'd':
        role = ''  # Independently observed public legacy DumpInfo spelling.
    if family in {'Template', 'CommonTemplate'} and suffix == '0':
        role = 'Template'  # Native template body role; independent of its resource kind.
    if family in {'Form', 'CommonForm'} and suffix == '0' and any(path.name in {'Form.xml', 'Form.bin'} for path in paths):
        role = 'Form'
    if role is None:
        role = route_table.get((family, suffix))
    if role is None and paths:
        candidates = {path.stem for path in paths if 'Ext' in path.parts}
        require(len(candidates) == 1, 'Ambiguous emitted role: ' + identity)
        role = candidates.pop()
    require(role is not None, 'Unknown versioned role: ' + identity + ' (' + family + ')')
    return name + '.' + role


def render(records,xml_version='2.20'):
    require(xml_version in ('2.20','2.21'),'Unsupported DumpInfo XML profile')
    xml = ['\ufeff<?xml version="1.0" encoding="UTF-8"?>\r\n',
           '<ConfigDumpInfo xmlns="http://v8.1c.ru/8.3/xcf/dumpinfo" xmlns:xen="http://v8.1c.ru/8.3/xcf/enums" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" format="Hierarchical" version="'+xml_version+'">\r\n\t<ConfigVersions>\r\n']
    quote = lambda value: escape(value, {'"': '&quot;'})
    for name, identity, stamp, children in sorted(records):
        xml.append('\t\t<Metadata name="' + quote(name) + '" id="' + identity + '" configVersion="' + stamp)
        if not children:
            xml.append('"/>\r\n')
        else:
            xml.append('\">\r\n')
            for child_id, child_name in sorted(children.items()):
                xml.append('\t\t\t<Metadata name="' + quote(child_name) + '" id="' + child_id + '"/>\r\n')
            xml.append('\t\t</Metadata>\r\n')
    xml.append('\t</ConfigVersions>\r\n</ConfigDumpInfo>')
    return ''.join(xml).encode('utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cf', required=True)
    parser.add_argument('--generated', required=True)
    parser.add_argument('--engine-report', required=True)
    parser.add_argument('--run-receipt', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--profile-receipt', required=True)
    parser.add_argument('--legacy-empty-signature-profile', action='store_true',
                        help='Experimental public 2.11 empty Configuration.d spelling; requires exact CF shape')
    parser.add_argument('--omit-empty-legacy-signature-profile', action='store_true',
                        help='Experimental 2.20 projection: empty legacy body beside verified emitted current signature')
    parser.add_argument('--modern-signature-passthrough',action='store_true',help='XML2.21 .10 binary must match CF bytes; no legacy signature allowed')
    args = parser.parse_args()
    output = Path(args.output).resolve()
    require(not output.exists(), 'Output already exists')
    output.mkdir(parents=True)
    cf_path=Path(args.cf).resolve(strict=True)
    profile=profiles.load(args.profile_receipt,cf_path)
    source = CFSource(cf_path)
    route_source = Path(__file__).resolve().parent / 'data' / 'assets.rs'
    # profiles.load immediately above already recomputed this whole-CF
    # digest and closed-shape selection from current bytes. Reuse that fact;
    # the independent end profiles.load below rechecks everything afresh.
    cf_sha = profile['cf_sha256']
    receipt = {'status': 'CANDIDATE', 'cf': str(source.path), 'cf_sha256': cf_sha,
               'profile':profile,'profile_receipt':{'path':str(Path(args.profile_receipt).resolve()),'sha256':digest(args.profile_receipt)},
               'producer_sha256': digest(__file__), 'route_source_sha256': digest(route_source)}
    try:
        run = json.loads(Path(args.run_receipt).read_text(encoding='utf-8'))
        report = json.loads(Path(args.engine_report).read_text(encoding='utf-8'))
        validate_profile_run(profile,run,report)
        require(run['profile_receipt']==receipt['profile_receipt'],'Native/DumpInfo profile receipt mismatch')
        require(run['source']['sha256'] == cf_sha == run['source']['sha256_after'], 'CF/run receipt digest mismatch')
        require(Path(run['source']['path']).resolve() == Path(source.path).resolve(), 'CF/run source path mismatch')
        require(Path(run['native_xml']).resolve() == Path(args.generated).resolve(), 'XML/run path mismatch')
        require(Path(args.engine_report).resolve().parent == Path(args.run_receipt).resolve().parent, 'Unrelated engine report')
        receipt.update(run_receipt_sha256=digest(args.run_receipt), engine_report_sha256=digest(args.engine_report))
        stamps = versions(source)
        print(json.dumps({'stage': 'index-metadata', 'versions': len(stamps)}), flush=True)
        configuration_storage = str(source.tree('root')[1])
        configuration_identity = cf_identity(source.tree(configuration_storage))
        signature_profile_guard(source,configuration_identity['uuid'],profile,args.legacy_empty_signature_profile or args.omit_empty_legacy_signature_profile,args.modern_signature_passthrough)
        legacy_empty_signature = None
        if args.legacy_empty_signature_profile:
            legacy_empty_signature = configuration_identity['uuid'] + '.d'
            raw_signature = source.inflated(legacy_empty_signature)
            require(raw_signature == b'\xef\xbb\xbf{0,"",""}', 'Unsupported legacy signature payload')
            receipt['experimental_legacy_signature'] = {
                'record': legacy_empty_signature,
                'payload_sha256': hashlib.sha256(raw_signature).hexdigest(),
                'public_source_commit': '12587110fdb96613bcb7c8b97d011c721b44a4e6',
                'public_source_repository': 'Fox-trot/Offline-Reader-4-infostart.ru',
                'public_source_format': '2.11',
                'target_format': '2.20',
                'naming': 'Configuration.<CF-name>.',
                'limitation': 'Historical public example; target version requires independent post-generation verification'}
        canonical, children, evidence, envelope_count = metadata_index(long_path(Path(args.generated).resolve(strict=True)), stamps, configuration_storage, configuration_identity, profile['xml_version'])
        receipt['metadata_envelope_count'] = envelope_count
        print(json.dumps({'stage': 'check-cf-children', 'metadata_roots': len(evidence)}), flush=True)
        report = json.loads(Path(args.engine_report).read_text(encoding='utf-8'))
        entries = report['export']['storage']['entries']
        outputs = {entry['logical_name']: entry['outputs'] for entry in entries}
        require(len(outputs) == len(entries) and set(outputs) == set(source.names()), 'CF/report logical inventory mismatch')
        require(all(entry['packed_bytes'] == source.catalog.entries[entry['logical_name']].stored_size for entry in entries), 'CF/report stored lengths mismatch')
        if args.modern_signature_passthrough:
            receipt['modern_signature_passthrough']=validate_modern_signature_passthrough(source,configuration_identity['uuid'],profile,entries,Path(args.generated).resolve(strict=True))
        child_discrepancies = check_cf_children(source, stamps, children, evidence, configuration_storage, configuration_identity)
        receipt['cf_child_discrepancies'] = child_discrepancies
        receipt['metadata_xml'] = evidence
        require(not child_discrepancies, 'CF/XML child inventory mismatch; see receipt')
        print(json.dumps({'stage': 'render-dumpinfo', 'cf_child_discrepancies': 0}), flush=True)
        route_table = routes(route_source)
        suppressed_empty_signature = None
        if args.omit_empty_legacy_signature_profile:
            require(not args.legacy_empty_signature_profile, 'Conflicting signature profiles')
            require(run['engine']['platform_profile'] == '8.3.27' and run['engine']['xml_version'] == '2.20',
                    'Experimental suppression only supports explicit 8.3.27 / XML2.20 profile')
            suppressed_empty_signature = configuration_identity['uuid'] + '.d'
            raw_signature = source.inflated(suppressed_empty_signature)
            require(raw_signature == b'\xef\xbb\xbf{0,"",""}', 'Unsupported legacy signature payload')
            require(('Configuration', 'd') not in route_table
                    and route_table.get(('Configuration', '10')) == 'MobileClientSignature',
                    'Modern public signature route mismatch')
            config_paths = [row['path'] for row in evidence if row['source_cf'] == configuration_storage]
            require(len(config_paths) == 1, 'Configuration projection is ambiguous')
            native_tree = long_path(Path(args.generated).resolve(strict=True))
            config_node = ET.fromstring((native_tree / config_paths[0]).read_bytes())
            require(config_node.get('version') == '2.20', 'Wrong native XML version')
            properties = config_node.find(MD + 'Configuration/' + MD + 'Properties')
            require(properties is not None and all(properties.find(MD + name) is None
                    for name in ('MobileClientSign', 'MobileClientSignature')), 'Signature property is materialized')
            require(not outputs.get(suppressed_empty_signature), 'Legacy signature has emitted outputs')
            require(not (native_tree / 'Ext' / 'MobileClientSign.bin').exists(), 'Legacy signature file is materialized')
            modern_signature = configuration_identity['uuid'] + '.10'
            require(modern_signature in stamps and outputs.get(modern_signature) == ['Ext/MobileClientSignature.bin'],
                    'Modern signature has no unambiguous CF/output route')
            modern_tree = source.tree(modern_signature)
            validate_current_signature_model(modern_tree)
            receipt['modern_signature_numeric_lexical_gate'] = 'PASS'
            modern_raw = source.inflated(modern_signature)
            require((native_tree / 'Ext' / 'MobileClientSignature.bin').read_bytes() == modern_raw,
                    'Modern signature output differs from its CF payload')
            receipt['suppressed_empty_legacy_records'] = [{
                'record': suppressed_empty_signature,
                'config_version': stamps[suppressed_empty_signature],
                'payload_sha256': hashlib.sha256(raw_signature).hexdigest(),
                'reason': 'Explicit experimental XML2.20 projection: empty historical signature beside an emitted current converted signature',
                'modern_record': modern_signature,
                'modern_payload_sha256': hashlib.sha256(modern_raw).hexdigest(),
                'independent_evidence': 'Public historical .d example, modern .10 route and documented modern filename precedence above8.3.19; absent legacy property/file',
                'limitation': 'Native suppression is an algorithmic assumption, not independently established; requires complete post-generation verification',
                'original_data': 'Preserved in original SQL-derived CF'}]
        records, unresolved, names = [], [], set()
        for identity, stamp in stamps.items():
            try:
                name = top_name(identity, canonical, route_table, outputs, legacy_empty_signature, suppressed_empty_signature)
                if name is None:
                    continue
                require(name not in names, 'Duplicate canonical version name: ' + name)
                names.add(name)
                records.append((name, identity, stamp, children.pop(identity, {})))
            except ValueError as error:
                unresolved.append(str(error))
        receipt.update(metadata_xml=evidence, versioned_records=len(records), unresolved=unresolved,
                       unowned_children=list(children))
        require(not unresolved and not children, 'Unresolved versioned metadata; see receipt')
        raw = render(records,profile['xml_version'])
        (output / 'ConfigDumpInfo.xml').write_bytes(raw)
        receipt['output_sha256'] = hashlib.sha256(raw).hexdigest()
        # The next original profiles.load hashes all current CF bytes and
        # redetects every profile guard. Equality to profile implies cf_sha
        # equality; an immediately preceding independent digest duplicates it.
        require(profiles.load(args.profile_receipt,source.path)==profile,'Immutable DumpInfo profile changed')
        require(digest(args.profile_receipt)==receipt['profile_receipt']['sha256'],'DumpInfo profile receipt bytes changed')
        receipt['producer_sha256_after'] = digest(__file__)
        require(receipt['producer_sha256_after'] == receipt['producer_sha256'], 'Producer changed during generation')
    except Exception as error:
        receipt.update(status='FAILED', error=str(error))
        raise
    finally:
        source.close()
        (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key, value in receipt.items() if key != 'metadata_xml'}, ensure_ascii=True))


if __name__ == '__main__':
    main()
