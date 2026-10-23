#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the physically verified CA compiler/plugin to the combined guest kext.

Failure inventory: mixed binaries, lost display fix, absent copy ABI, stale probe
identity, collection omitting the kext, altered monitor, or offscreen proof
misrepresented as guest presentation. This command accesses host files only.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT.parent / 'Snapintosh'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output', type=Path, required=True)
args = ap.parse_args()
inputs = {}


def bind(path, expected=None):
    path = Path(path).resolve()
    actual = sha(path)
    assert expected is None or actual == expected, path
    assert str(path) not in inputs or inputs[str(path)] == actual, path
    inputs[str(path)] = actual
    return actual


def read(path, expected=None):
    bind(path, expected)
    return json.loads(Path(path).read_text())


launch = read(ORIGINAL / 'build/installed-metal-qc-pipeline-3600s-20260928-launch.json',
    '834fada225eb1a4809c84f307f41caff0c2387fac058a62045b8d0b90bd704e9')
for name, digest in launch['source_sha256'].items():
    bind(name, digest)
bind(launch['monitor_path'], launch['monitor_sha256'])
assert (launch['context_fields'], launch['context_bytes']) == (217, 5124736)
native_path = ROOT / 'build/qc-pipelines-vpc-20260928-v1.json'
native = read(native_path, '0f7b2ad462e76103da3d52e2b20a534bd1e4d91d15e3a871081f352c8311455a')
assert native['status'] == 'NATIVE_QC_PIPELINES_COMPILED'
assert native['passed'] == 18 and native['failed'] == 0
bind(native['specification'], native['spec_sha256'])
bind(native['library'], native['metallib_sha256'])
for row in native['rows']:
    assert row['status'] == 'COMPILED'
    for variant in row['native_variants']:
        bind(variant['air_file'], variant['air_sha256'])
bundle = Path(native['bundle'])
bind(bundle / 'Contents/MacOS/AdrenoMetal', native['plugin_sha256'])
bind(bundle / 'Contents/Frameworks/libAdrenoCompiler.dylib', native['compiler_sha256'])
runtime_path = ROOT / 'build/ca-compiler-vpc-20260928-v1/qualification.json'
runtime = read(runtime_path, '67e95cc74486121b68ff8a5e6577f589f382277dd1b83366ddbd83bceae1631d')
assert runtime['status'] == 'PACKAGED_COMPILER_ARM64E_C_API_VERIFIED'
for name, digest in runtime['inputs_sha256'].items():
    bind(name, digest)
for name, digest in runtime['artifacts_sha256'].items():
    bind(runtime_path.parent / name, digest)
assert runtime['artifacts_sha256']['runtime/libAdrenoCompiler.dylib'] == native['compiler_sha256']
probe_path = ROOT / 'build/ca-guest-probe-20260928-v1/build.json'
probe = read(probe_path)
assert probe['status'] == 'GUEST_TRIANGLE_BUILT_HOST_REFERENCE_MATCHED_NOT_EXECUTED_ON_A16'
assert probe['compiled_identity_matches_current_bundle']
assert probe['plugin_sha256'] == native['plugin_sha256']
assert probe['compiler_sha256'] == native['compiler_sha256']
for key, root in [('inputs_sha256', ROOT), ('sources_sha256', ROOT), ('artifacts_sha256', probe_path.parent)]:
    for name, digest in probe[key].items():
        bind(root / name, digest)
executable = probe_path.parent / 'metal-triangle-probe'
assert executable.read_bytes().count(native['plugin_sha256'].encode()) == 1
replay_path = ROOT / 'build/ca-vpc-kernel-replay-20260928-v1/qualification.json'
replay = read(replay_path, 'f817cba40382b398064d94e80f744817c52b28bd14fa490bacfab3906541ccb8')
assert replay['status'] == 'NATIVE_CA_TEXTURE_KERNEL_REPLAY_PASSED'
for name, digest in replay['production_inputs'].items():
    bind(ROOT / name, digest)
physical_path = ROOT / 'build/ca-vpc-a16-verified-gen58-20260928-v1/verification.json'
physical = read(physical_path, '8d95a910aedce77fb31710799e0882e0a1c8b0d32b1eacfbf709e0c5d0995c2e')
assert physical['status'] == 'A16_CA_FRAME_EXACT' and not physical['desktop_verified']
assert physical['pixels']['total'] == 40960 and physical['pixels']['max_channel_error'] == 0
for name, digest in physical['artifact_sha256'].items():
    bind(physical_path.parent / name, digest)
kcdir = ROOT / 'build/ca-integrated-auxkc-20260928-v1'
built = read(kcdir / 'raw.kc.build.json', '12983d1ea06b9337d0274ee0b9244372a3fde64fa0cb01b821888b3f83b4d8ca')
assert built['status'] == 'PASSWORDLESS_AUXKC_BUILT' and built['cleanup']['stage_removed']
assert built['caller_uid'] == built['kmutil_uid'] == built['collection_owner'] != 0
for name, digest in built['inputs_sha256'].items():
    bind(name, digest)
for name, digest in built['artifacts_sha256'].items():
    bind(kcdir / name, digest)
packaging = read(kcdir / 'packaging.json')
assert packaging['unchanged_executable_and_fixup_bytes']
collection = kcdir / 'adreno.kc'
bind(collection, '37f93f1500d6425fbeda90d22263053d4161ce87cfe668f65661af651fe9dc3d')
assert packaging['output_sha256'] == sha(collection)
manifest = read(collection.with_name('adreno.kc.json'))
kext = ROOT / 'build/ca-integrated-kext-20260928-v1/AdrenoX2.kext'
bind(kext / 'Contents/MacOS/AdrenoX2', '54d32bb79af174703a17a21286231b6af6d555ca67d57d7662815a9c4717a9d1')
display = ROOT / 'gpu/adreno-kext/kext/src/AdrenoDisplay.cpp'
accepted = ROOT.parent / 'Snapintosh-adreno-fill/gpu/adreno-kext/kext/src/AdrenoDisplay.cpp'
assert [bind(p) for p in source_files(display)] == [bind(p) for p in source_files(accepted)]   # with its parts
assert b'AdrenoIBCopyABI' in (kext / 'Contents/MacOS/AdrenoX2').read_bytes()
for tree in (bundle, ROOT / 'gpu/adreno-kext/kext', ROOT / 'gpu/adreno-kext/plugin'):
    for path in tree.rglob('*'):
        if path.is_file() and (tree == bundle or path.suffix in ('.m', '.h', '.cpp', '.c', '.sh', '.plist')):
            bind(path)
for path in (bundle, executable, kext):
    subprocess.run(['codesign', '--verify', '--strict', str(path)], check=True)
bind(__file__)
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=False)
record = dict(status='SHADER_DISPLAY_COMPONENTS_BOUND_NOT_INSTALLED', inputs_sha256=inputs,
    display_profile=launch['guest_profile'], runtime_root=launch['runtime_root'],
    monitor=launch['monitor_path'], monitor_sha256=launch['monitor_sha256'],
    deployed_collection=str(collection), deployed_collection_sha256=sha(collection),
    kext_bundle=str(kext), kext_sha256=sha(kext / 'Contents/MacOS/AdrenoX2'),
    plugin_bundle=str(bundle), plugin_sha256=native['plugin_sha256'], compiler_sha256=native['compiler_sha256'],
    guest_probe=str(executable), guest_probe_sha256=probe['binary_sha256'],
    probe_build=str(probe_path), probe_build_sha256=sha(probe_path),
    compiled_probe_plugin_identity_verified=True, context_fields=217, context_bytes=5124736,
    native_compiler_evidence=str(native_path), native_compiler_sha256=sha(native_path),
    physical_offscreen_evidence=str(physical_path), physical_offscreen_sha256=sha(physical_path),
    kernel_replay=str(replay_path), kernel_replay_sha256=sha(replay_path),
    a16_access=False, guest_executed=False, screen_presented=False,
    boundary='Combined display/copy kext and physical CA compiler/plugin staged for a new guest boot. Offscreen pixels are proven; guest execution and presentation of this combination are not.')
(out / 'components.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(status=record['status'], bindings=len(inputs), output=str(out / 'components.json'))))
