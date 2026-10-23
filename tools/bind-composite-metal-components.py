#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the composite plug-in/probe to the corrected network/display collection.

Failure inventory: mixed compiler/probe identities, lost network personality,
lost display/copy ABI, altered runtime, stale captured commands, and historical
offscreen evidence mistaken for physical execution of this new candidate.
Host files only; installation requires a fresh stopped-guest SSD snapshot.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
NETWORK = ROOT.parent / 'Snapintosh-adreno-buffer-textures'
PIPELINE = ROOT.parent / 'Snapintosh-adreno-pipeline'
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
inputs = {}


def bind(path, expected=None):
    path = Path(path).resolve()
    actual = sha(path)
    assert expected is None or actual == expected, path
    assert str(path) not in inputs or inputs[str(path)] == actual, path
    inputs[str(path)] = actual
    return actual


def read(path, expected=None, source_root=ROOT):
    path = Path(path)
    bind(path, expected)
    record = json.loads(path.read_text())
    for key, base in [('inputs_sha256', source_root),
                      ('sources_sha256', source_root),
                      ('artifacts_sha256', path.parent)]:
        for name, value in record.get(key, {}).items():
            bind(base / name, value)
    return record


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    network_path = NETWORK / 'build/ca-network-qualification-20260928-v2.json'
    network = read(network_path,
        '0c7936724e05c8ce706ddd9148b72bc060849b1604e8caf2675d8d2e2e7720d3', NETWORK)
    assert network['linked_collection_personalities_verified']
    assert network['personalities_equal_to_accepted']
    assert network['accepted_network_object_sections_unchanged']
    assert 'SnapintoshVirtualEthernet' in network['required_classes']
    image_path = NETWORK / 'build/ca-network-guest-20260928-v1/qualification.json'
    image = read(image_path,
        '2d0342ee4ff3347ed8913befff55f8cf06ae5f475e9074e4fcc94e71fac909b2', NETWORK)
    assert image['status'] == 'CA_NETWORK_FULL_GUEST_IMAGE_BUILT_NOT_BOOTED'
    assert (image['context_fields'], image['context_bytes']) == (217, 5124736)
    assert image['collection_sha256'] == network['collection_sha256']
    assert image['kext_sha256'] == network['kext_sha256']
    monitor = image['monitor']
    bind(monitor['path'], monitor['sha256'])
    collection = Path(network['collection'])
    bind(collection, network['collection_sha256'])
    bind(collection.with_name('adreno.kc.json'))
    kext = Path(network['kext_bundle'])
    bind(kext / 'Contents/MacOS/AdrenoX2', network['kext_sha256'])
    assert b'AdrenoIBCopyABI' in (kext / 'Contents/MacOS/AdrenoX2').read_bytes()
    display_unit = source_files(ROOT / 'gpu/adreno-kext/kext/src/AdrenoDisplay.cpp')   # with its ordered parts
    accepted_unit = source_files(ROOT.parent / 'Snapintosh-adreno-fill/gpu/adreno-kext/kext/src/AdrenoDisplay.cpp')
    assert [bind(p) for p in display_unit] == [bind(p) for p in accepted_unit]

    native_path = ROOT / 'build/qc-pipelines-composite-20260928-v1.json'
    native = read(native_path,
        'e21bc5f0e164a5d230630ccb014ccdd32cb07c41b702ae35bffdba8eda917d58')
    assert native['status'] == 'NATIVE_QC_PIPELINES_COMPILED'
    assert (native['passed'], native['failed']) == (18, 0)
    bind(native['specification'], native['spec_sha256'])
    bind(native['library'], native['metallib_sha256'])
    for row in native['rows']:
        assert row['status'] == 'COMPILED'
        for variant in row['native_variants']:
            bind(variant['air_file'], variant['air_sha256'])
    bundle = Path(native['bundle'])
    bind(bundle / 'Contents/MacOS/AdrenoMetal', native['plugin_sha256'])
    bind(bundle / 'Contents/Frameworks/libAdrenoCompiler.dylib', native['compiler_sha256'])
    compiler = read(PIPELINE / 'build/ca-compiler-vpc-20260928-v1/qualification.json',
        '67e95cc74486121b68ff8a5e6577f589f382277dd1b83366ddbd83bceae1631d', PIPELINE)
    assert compiler['status'] == 'PACKAGED_COMPILER_ARM64E_C_API_VERIFIED'
    assert compiler['artifacts_sha256']['runtime/libAdrenoCompiler.dylib'] == native['compiler_sha256']
    probe_path = ROOT / 'build/ca-composite-guest-probe-20260928-v1/build.json'
    probe = read(probe_path,
        '676f35ab479a93f4e3fb812ffff2e610cc1dcce4aaeeea9c64edaed3c067be08')
    assert probe['status'] == 'GUEST_TRIANGLE_BUILT_HOST_REFERENCE_MATCHED_NOT_EXECUTED_ON_A16'
    assert probe['compiled_identity_matches_current_bundle']
    assert probe['native_compiler_sha256'] == sha(native_path)
    for name in ('plugin_sha256', 'compiler_sha256'):
        assert probe[name] == native[name]
    executable = probe_path.parent / 'metal-triangle-probe'
    bind(executable, probe['binary_sha256'])
    assert executable.read_bytes().count(native['plugin_sha256'].encode()) == 1

    capture_path = ROOT / 'build/ca-composite-private-20260928-v1/capture.json'
    capture = read(capture_path,
        'd77cee4c9f8d907804ce7f95cf12cb3dd246c268c9ff1dd217b9143481a54efd')
    assert capture['native_paths_completed']
    assert capture['plugin_sha256'] == native['plugin_sha256']
    assert capture['compiler_sha256'] == native['compiler_sha256']
    evidence = []
    for scene in ('desktop', 'shadow', 'mask', 'transform'):
        extent_path = ROOT / f'build/ca-composite-extents-{scene}-20260928-v2.json'
        extent = read(extent_path)
        assert extent['status'] == 'NATIVE_CA_COMPOSITE_EXTENTS_VERIFIED'
        assert not extent['physical_rendering_verified']
        bind(extent['capture'], extent['capture_sha256'])
        replay = read(extent['kernel_replay'], extent['kernel_replay_sha256'])
        assert replay['status'] == 'NATIVE_CA_COPY_KERNEL_REPLAY_PASSED'
        assert replay['capture_sha256'] == extent['capture_sha256']
        assert not replay['gpu_execution'] and len(replay['cases']) == 11
        for name, value in replay['production_inputs'].items():
            bind(ROOT / name, value)
        for name, value in extent['reference_sha256'].items():
            bind(name, value)
        evidence.append(dict(scene=scene, path=str(extent_path), sha256=sha(extent_path)))
    for tree in (bundle, kext, ROOT / 'gpu/adreno-kext/plugin', ROOT / 'gpu/adreno-kext/kext'):
        for path in tree.rglob('*'):
            if path.is_file() and (tree in (bundle, kext) or
                    path.suffix in ('.m', '.h', '.cpp', '.c', '.sh', '.plist')):
                bind(path)
    for path in (bundle, executable, kext):
        subprocess.run(['codesign', '--verify', '--strict', str(path)], check=True)
    bind(__file__)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    record = dict(status='SHADER_DISPLAY_COMPONENTS_BOUND_NOT_INSTALLED',
        inputs_sha256=inputs, display_profile=image['guest_profile'],
        runtime_root=image['runtime_root'], monitor=monitor['path'], monitor_sha256=monitor['sha256'],
        deployed_collection=str(collection), deployed_collection_sha256=sha(collection),
        kext_bundle=str(kext), kext_sha256=network['kext_sha256'],
        network_qualification=str(network_path), network_qualification_sha256=sha(network_path),
        plugin_bundle=str(bundle), plugin_sha256=native['plugin_sha256'],
        compiler_sha256=native['compiler_sha256'], guest_probe=str(executable),
        guest_probe_sha256=probe['binary_sha256'], probe_build=str(probe_path),
        probe_build_sha256=sha(probe_path), compiled_probe_plugin_identity_verified=True,
        context_fields=217, context_bytes=5124736, native_compiler_evidence=str(native_path),
        native_compiler_sha256=sha(native_path), composite_host_evidence=evidence,
        a16_access=False, guest_executed=False, screen_presented=False,
        physical_rendering_verified=False,
        boundary='New composite plug-in/probe with corrected network/display kext. Host command capture, packet extents and submission-model replays only; private replay seeds are not physical pixel evidence. This combination is not installed or executed on the A16.')
    (out / 'components.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], bindings=len(inputs),
        output=str(out / 'components.json'), sha256=sha(out / 'components.json'))))


if __name__ == '__main__':
    main()
