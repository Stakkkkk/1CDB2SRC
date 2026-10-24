"""Fresh byte readback against a separately authenticated earlier full XML proof.

This module does not authenticate that proof or claim fresh XML parsing. Its
caller must bind the early process/CF/profile/producer before accepting XML.
"""
import hashlib,json
from pathlib import PurePosixPath
from . import readback
from .materialize import inspect_file


STATUS='BYTES_REVERIFIED_REQUIRES_EARLY_XML_LINEAGE'


def prior_rows(proof):
    require=readback.require
    require(type(proof) is dict and proof.get('status')=='FILES_VERIFIED_REQUIRES_CALLER_LINEAGE'
            and proof.get('caller_lineage')=='NOT_CHECKED' and proof.get('oracle_inputs')==[]
            and proof.get('errors')==[] and proof.get('missing')==proof.get('extra')==0,
            'Earlier full file proof incomplete')
    require('xml_parse' not in proof and 'prior_facts_sha256' not in proof,'A late byte proof is not an earlier full XML proof')
    require(all(type(proof.get(key)) is int and proof[key]>=0 for key in ('files','bytes','bsl_files','metadata_envelopes')),
            'Earlier count types differ')
    rows=proof.get('facts');require(type(rows) is list and len(rows)==proof.get('files'),'Earlier fact count differs')
    result={};digest=hashlib.sha256()
    for row in rows:
        require(type(row) is dict and set(row)=={'path','kind','bytes','sha256','bsl','metadata_envelope'},'Earlier fact schema differs')
        path=row['path'];readback.safe_path(path)
        require(path not in result and row['kind']=='file' and type(row['bytes']) is int and row['bytes']>=0,
                'Earlier fact duplicate/kind/size differs')
        require(type(row['bsl']) is bool and row['bsl']==(PurePosixPath(path).suffix.lower()=='.bsl')
                and type(row['metadata_envelope']) is bool,'Earlier type flags differ')
        result[path]=row
        digest.update((json.dumps(row,sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode('utf-8'))
    require(list(result)==sorted(result) and digest.hexdigest()==proof.get('facts_sha256'),'Earlier fact digest/order differs')
    require(proof.get('bytes')==sum(r['bytes'] for r in rows)
            and proof.get('bsl_files')==sum(r['bsl'] for r in rows)
            and proof.get('metadata_envelopes')==sum(r['metadata_envelope'] for r in rows),'Earlier counts differ')
    require(all(result.get(name,{}).get('metadata_envelope') is True for name in ('Configuration.xml','ConfigDumpInfo.xml')),
            'Earlier required XML envelopes missing')
    return result


def verify_unchanged_xml_tree(tree,manifest,*,manifest_sha256,xml_version,prior,workers=4):
    """Read every actual payload now; no timestamp/cache-only acceptance."""
    rows=prior_rows(prior)
    readback.require(prior.get('manifest',{}).get('sha256')==manifest_sha256,'Earlier manifest binding differs')
    def fresh_hash(tree,path,expected,edition):
        readback.require(path in rows and {key:rows[path][key] for key in ('bytes','sha256')}==expected,
                         'Earlier payload/manifest differs')
        actual,_=inspect_file(tree.joinpath(*readback.safe_path(path).parts),parse_xml=False)
        readback.require(actual==expected,'Actual payload changed since full XML validation')
        return dict(rows[path],**actual)
    value=readback._verify_xml_tree(tree,manifest,manifest_sha256=manifest_sha256,
        xml_version=xml_version,workers=workers,_read_file=fresh_hash)
    readback.require(value['manifest']==prior['manifest'] and value['facts']==prior['facts']
                     and value['facts_sha256']==prior['facts_sha256'],'Fresh byte proof differs from earlier full proof')
    value.update(status=STATUS,xml_parse='REUSED_ONLY_WITH_IDENTICAL_PAYLOAD_SHA',prior_facts_sha256=prior['facts_sha256'])
    return value
