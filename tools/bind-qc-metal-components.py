#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the actual 18/18 native compiler candidate to the accepted gen56 driver.

Failure inventory: mixed compiler/bundle, stale AIR, accidental monitor/driver
change, stale probe source, and treating host compilation as hardware rendering.
The probe's old transitive compiler inputs remain historical, not current proof.
"""
from pathlib import Path
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT.parent / 'Snapintosh'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output', type=Path, required=True)
args = ap.parse_args()
inputs = {}


def bind(path, expected=None):
    p = Path(path).resolve()
    actual = sha(p)
    assert expected is None or actual == expected, str(p)
    assert str(p) not in inputs or inputs[str(p)] == actual, str(p)
    inputs[str(p)] = actual
    return actual


def read(path, expected):
    bind(path, expected)
    return json.loads(Path(path).read_text())


launch_path = ORIGINAL / 'build/installed-metal-panel-arguments-3600s-20260928-launch.json'
launch = read(launch_path, 'cd076f19519151cf2073e7871153d8beb4a9cd1c0744c25ad915941f3dca4cfe')
for name, digest in launch['source_sha256'].items():
    bind(name, digest)
bind(launch['monitor_path'], launch['monitor_sha256'])
bind(launch['auxkc'], launch['auxkc_sha256'])
assert launch['context_fields'] == 217 and launch['context_bytes'] == 5124736
hardware_proof = ORIGINAL / 'build/installed-metal-panel-arguments-3600s-20260928-capture-completion-v1.json'
bind(hardware_proof, '3ac970b937a6fc3728bb9c17937b58ed8534a42f842aaded0a9204cbe6a16265')
native_path = ROOT / 'build/qc-pipelines-sampler-20260928-v1.json'
native = read(native_path, '7a80cbcc6ec5fa74dab44e65bbf2b822eb14b1190e0b6177c8001f5b940a8154')
assert native['status'] == 'NATIVE_QC_PIPELINES_COMPILED'
assert native['passed'] == 18 and native['failed'] == 0 and len(native['rows']) == 18
assert native['command_buffers_submitted'] == 0 and not native['a16_access']
bind(native['specification'], native['spec_sha256'])
bind(native['library'], native['metallib_sha256'])
for row in native['rows']:
    assert row['status'] == 'COMPILED' and row['pipeline_class'] == 'AdrenoRenderPipelineState'
    assert len(row['native_variants']) == 2
    for variant in row['native_variants']:
        bind(variant['air_file'], variant['air_sha256'])
bundle = Path(native['bundle'])
bind(bundle / 'Contents/MacOS/AdrenoMetal', native['plugin_sha256'])
bind(bundle / 'Contents/Frameworks/libAdrenoCompiler.dylib', native['compiler_sha256'])
for p in bundle.rglob('*'):
    if p.is_file():
        assert not p.is_symlink()
        bind(p)
runtime_path = ROOT / 'build/qc-compiler-sampler-20260928-v1/qualification.json'
runtime = read(runtime_path, 'db1eb1380e90d3a1c39ba4bd7bb6a90e094af24f607ac3ee1bb994c5ebbe3cb8')
assert runtime['status'] == 'PACKAGED_COMPILER_ARM64E_C_API_VERIFIED'
for name, digest in runtime['inputs_sha256'].items():
    bind(name, digest)
for name, digest in runtime['artifacts_sha256'].items():
    bind(runtime_path.parent / name, digest)
assert runtime['artifacts_sha256']['runtime/libAdrenoCompiler.dylib'] == native['compiler_sha256']
probe_path = ROOT / 'build/adreno-frame-wait-probe-20260928-v2/build.json'
probe = read(probe_path, '8dd1fa811526d38d50241a3157c42ee11d1734b0aecb01ffb092c8d466c43c26')
assert probe['status'] == 'GUEST_TRIANGLE_BUILT_HOST_REFERENCE_MATCHED_NOT_EXECUTED_ON_A16'
for name, digest in probe['sources_sha256'].items():
    bind(ROOT / name, digest)
for name, digest in probe['artifacts_sha256'].items():
    bind(probe_path.parent / name, digest)
executable = probe_path.parent / 'metal-triangle-probe'
bind(executable, probe['binary_sha256'])
for p in (ROOT / 'gpu/adreno-kext/plugin').rglob('*'):
    if p.is_file() and p.suffix in ('.m', '.h', '.c', '.sh'):
        bind(p)
bind(__file__)
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=False)
record = dict(status='SHADER_DISPLAY_COMPONENTS_BOUND_NOT_INSTALLED', inputs_sha256=inputs,
    display_profile=launch['guest_profile'], runtime_root=launch['runtime_root'],
    monitor=launch['monitor_path'], monitor_sha256=launch['monitor_sha256'],
    deployed_collection=launch['auxkc'], deployed_collection_sha256=launch['auxkc_sha256'],
    plugin_bundle=str(bundle), plugin_sha256=native['plugin_sha256'], compiler_sha256=native['compiler_sha256'],
    guest_probe=str(executable), guest_probe_sha256=probe['binary_sha256'],
    context_fields=217, context_bytes=5124736,
    native_compiler_evidence=str(native_path), native_compiler_sha256=sha(native_path),
    hardware_display_evidence=str(hardware_proof), hardware_display_sha256=sha(hardware_proof),
    a16_access=False, guest_executed=False, screen_presented=False,
    boundary='New compiler passes 18 native host CoreAnimation pipelines; accepted gen56 monitor/AuxKC retained. Corrected probe has host reference proof; guest pipelines, pixels and desktop remain unproved.')
(out / 'components.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(status=record['status'], bindings=len(inputs), output=str(out / 'components.json'))))
