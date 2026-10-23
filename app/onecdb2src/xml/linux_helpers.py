"""Packaged Linux-only prepare/assembly entry. No DB, Docker socket or oracle.

The image runs this file directly with isolated stdlib Python. Its app source
and sealed runtime bytes are supplied by the readonly host contract.
"""
import argparse
import datetime
import hashlib
import os
from pathlib import Path
import sys
import time

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from onecdb2src.xml._fast_contract import (APP_ROOT, CONTRACT_SCHEMA, NAMESPACE_SCHEMA,
    PROOF_SCHEMA, require, fact, read, save_new, verify_source_closure)


def main(argv=None):
    from onecdb2src import profiles, worker
    from onecdb2src.nativecf.cf_source import CFSource
    from onecdb2src.native_policy import classify
    from onecdb2src.xml.materialize import producer_closed
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('prepare', 'run'))
    parser.add_argument('--side', choices=('main', 'vendor'), required=True)
    parser.add_argument('--contract', required=True)
    args = parser.parse_args(argv)
    require(sys.platform.startswith('linux'), 'Linux helper required')
    root = Path('/job')
    require(root.is_dir() and not root.is_symlink() and root.resolve() == root, 'Stable Linux /job required')
    contract_path = Path(args.contract).resolve(strict=True)
    contract_fact = fact(contract_path)
    contract = read(contract_path)
    require(contract['schema'] == CONTRACT_SCHEMA and contract['side'] == args.side
            and contract['namespace'] == '/job' and contract['oracle_inputs'] == []
            and contract['memory_controls'] is False, 'Contract namespace/boundary mismatch')
    require((root / '.ownership').read_text(encoding='ascii') == contract['nonce'], 'Job owner nonce mismatch')
    require(os.getuid() == os.getgid() == 65532 and root.stat().st_uid == root.stat().st_gid == 65532,
            'Explicit job root ownership missing')
    verify_source_closure(contract['source_files'], contract['runtime_files'], APP_ROOT)
    require(fact(__file__) == contract['source_files']['onecdb2src/xml/linux_helpers.py'], 'Helper source changed')
    cf = root / '_work/cf' / args.side / 'source.cf'
    require(fact(cf) == contract['cf'], 'Actual readonly CF/contract mismatch')
    profile_path = root / '_work/profiles' / (args.side + '.json')
    if args.phase == 'prepare':
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile = profiles.select(cf, contract['requested_platform'])
        profiles.save_new(profile_path, profile)
        save_new(root / ('namespace-' + args.side + '.json'), {
            'schema': NAMESPACE_SCHEMA, 'contract_sha256': contract_fact['sha256'],
            'cf_path': str(cf), 'profile_path': str(profile_path),
            'profile_fact': fact(profile_path), 'profile': profile, 'originals_rewritten': False})
        return
    profile = profiles.load(profile_path, cf)
    namespace = read(root / ('namespace-' + args.side + '.json'))
    require(namespace == {'schema': NAMESPACE_SCHEMA, 'contract_sha256': contract_fact['sha256'],
        'cf_path': str(cf), 'profile_path': str(profile_path), 'profile_fact': fact(profile_path),
        'profile': profile, 'originals_rewritten': False}, 'Prepared namespace/profile changed')
    native = root / '_work' / ('native-' + args.side)
    native_receipt_path = native / 'receipt.json'
    native_fact = fact(native_receipt_path)
    receipt = read(native_receipt_path)
    require(receipt['source'] == {'path': str(cf), **contract['cf'], 'sha256_after': contract['cf']['sha256']},
            'Native CF binding mismatch')
    require(receipt['native_xml'] == str(native / 'tree/xml') and receipt['engine']['image_id'] == contract['engine_image'],
            'Native namespace/image mismatch')
    require(receipt['profile_receipt'] == {'path': str(profile_path), 'sha256': fact(profile_path)['sha256']},
            'Native profile binding mismatch')
    require(receipt['producer_sha256'] == contract['source_files']['onecdb2src/xml/fast_docker.py']['sha256'],
            'Native host producer source mismatch')
    require(producer_closed(receipt), 'Engine writer not closed')
    projection = receipt['native_wrapper_exit_projection']
    require(projection['kind'] == 'ADAPTER_POLICY_PROJECTION_NOT_PROCESS_EXIT'
            and projection['input_raw_engine_exit'] == receipt['process']['container_state']['ExitCode']
            and projection['value'] == (0 if projection['input_raw_engine_exit'] == 0 else 1),
            'Native classifier mapping changed')
    report = read(native / 'engine.stderr.json')
    archive = CFSource(cf)
    try:
        sizes = {name: archive.catalog.entries[name].stored_size for name in archive.names()}
    finally:
        archive.close()
    outcome = classify(receipt, report, sizes, projection['value'], profile)
    config = {'root': str(root), 'assembly_mode': 'adopt'}
    started = time.monotonic()
    steps = []
    for prefix in ('dumpinfo-', 'parents-', 'assembly-'):
        tick = time.monotonic()
        worker.run(prefix + args.side, config)
        steps.append({'stage': prefix + args.side, 'seconds': time.monotonic() - tick})
    require(fact(native_receipt_path) == native_fact and fact(cf) == contract['cf'], 'Native/CF changed during helpers')
    output = root / args.side
    assembly = read(output / 'receipt.json')
    require(assembly['status'] == 'CANDIDATE_POSTGEN_VERIFICATION_REQUIRED'
            and fact(output / 'files.jsonl')['sha256'] == assembly['manifest_sha256'], 'Assembly not complete')
    verify_source_closure(contract['source_files'], contract['runtime_files'], APP_ROOT)
    save_new(root / ('linux-proof-' + args.side + '.json'), {
        'schema': PROOF_SCHEMA, 'status': 'CANDIDATE_HOST_READBACK_REQUIRED', 'side': args.side,
        'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'seconds': time.monotonic() - started, 'steps': steps, 'native_policy': outcome,
        'contract_sha256': contract_fact['sha256'], 'native_receipt_fact': native_fact,
        'assembly_receipt_fact': fact(output / 'receipt.json'),
        'files_manifest_fact': fact(output / 'files.jsonl'), 'cf': contract['cf'],
        'source_files': contract['source_files'], 'runtime_files': contract['runtime_files'],
        'namespace_fact': fact(root / ('namespace-' + args.side + '.json')),
        'oracle_inputs': [], 'memory_controls': False, 'host_transfer': 'NOT_RUN', 'host_readback': 'NOT_RUN'})


if __name__ == '__main__':
    main()
