#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rebuild the wait-options1 probe for the exact current Metal bundle.

Failure inventory: original docs/GEN57-PROBE-IDENTITY-20260928.md. Preserve the
historical draw/golden record; independently bind the current compiler candidate.
No A16 access and no change to any generation57 launch-pinned source.
"""
from pathlib import Path
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
base = ROOT / 'tools/build-adreno-triangle-probe.py'
assert sha(base) == '05024edc2c862bc835fb83b201e06bae3904c3b421e62019535bd3e5f817d903'
components_path = ROOT / 'build/qc-metal-deploy-20260928/components-v1/components.json'
components = json.loads(components_path.read_text())
assert components['status'] == 'SHADER_DISPLAY_COMPONENTS_BOUND_NOT_INSTALLED'
assert components['plugin_sha256'] == '942d8f2c7261880da126838a62412a562fbd1f0f798eaa3f6263faa3743ea014'
assert components['compiler_sha256'] == 'f455464c31b2d403077b1526e2ff30bfe6fb7aeca4211be1c8d3c88c65026abe'
current_inputs = dict(components['inputs_sha256'])
for name, digest in current_inputs.items():
    assert sha(name) == digest, name
native_path = Path(components['native_compiler_evidence'])
assert sha(native_path) == components['native_compiler_sha256']
native = json.loads(native_path.read_text())
assert native['passed'] == 18 and native['failed'] == 0
assert native['plugin_sha256'] == components['plugin_sha256']
assert native['compiler_sha256'] == components['compiler_sha256']
candidate_bundle = Path(components['plugin_bundle'])
old_plugin_sha = '9a1cdb3981377ad9231fd87806c161434df1b99509ec5bea26b87a31fdb48fb4'
new_plugin_sha = components['plugin_sha256']
reference_commit = 'ec9944b1e1d65847bbba10f9427a371353384ccf'
historical_reference_inputs = {}
current_inputs.update({str(p): sha(p) for p in [base, Path(__file__).resolve(), components_path, native_path]})


def bind_reference(path, expected, key, name):
    actual = sha(path)
    if actual != expected:
        assert key == 'sources_sha256' and name == 'gpu/adreno-kext/plugin/AdrenoMetal/AdrenoPipeline.m', name
        assert expected == 'd0cef5d5902335e99a03f251d71e83d54fe625cc483274042ebff891358702be'
        raw = subprocess.check_output(['git', 'show', reference_commit + ':' + name], cwd=ROOT)
        assert hashlib.sha256(raw).hexdigest() == expected
        assert actual == current_inputs[str(path.resolve())]
        historical_reference_inputs[name] = dict(commit=reference_commit,
            historical_sha256=expected, current_sha256=actual,
            boundary='Historical draw reference source; current candidate independently bound')
    return actual


def check_compiled_identity(executable):
    data = executable.read_bytes()
    assert data.count(new_plugin_sha.encode()) == 1, 'new plug-in identity absent or ambiguous'
    assert old_plugin_sha.encode() not in data, 'previous plug-in identity leaked into rebuilt probe'


source = base.read_text()
changes = {
    "            assert sha(path) == digest, name\n            bindings[str(path)] = digest":
        "            bindings[str(path)] = bind_reference(path, digest, key, name)",
    "    capture_path = parent/'plan-v2-clear.json'":
        "    assert sha(qualification) == '769425b251e8fdf3a223e5dd05639181c0bf45836291233997181527cf380211'\n    bindings.update(current_inputs)\n    capture_path = parent/'plan-v2-clear.json'",
    "    assert sha(binary) == draw['bundle_executable_sha256']":
        "    assert sha(binary) == draw['bundle_executable_sha256'] == old_plugin_sha\n    bundle = candidate_bundle\n    binary = bundle/'Contents/MacOS/AdrenoMetal'\n    assert sha(binary) == new_plugin_sha\n    assert sha(bundle/'Contents/Frameworks/libAdrenoCompiler.dylib') == components['compiler_sha256']",
    '        inputs_sha256=bindings,':
        "        inputs_sha256=bindings, historical_reference_inputs=historical_reference_inputs,\n        current_components=str(components_path), current_components_sha256=sha(components_path),\n        expected_plugin_identity=new_plugin_sha, historical_draw_reference=True,",
    "        record.update(status='GUEST_TRIANGLE_BUILT_HOST_REFERENCE_MATCHED_NOT_EXECUTED_ON_A16',":
        "        check_compiled_identity(out/'metal-triangle-probe')\n        assert record['plugin_sha256'] == components['plugin_sha256']\n        record['compiled_identity_matches_current_bundle'] = True\n        record.update(status='GUEST_TRIANGLE_BUILT_HOST_REFERENCE_MATCHED_NOT_EXECUTED_ON_A16',",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__',
    bind_reference=bind_reference, current_inputs=current_inputs, candidate_bundle=candidate_bundle,
    old_plugin_sha=old_plugin_sha, new_plugin_sha=new_plugin_sha, components=components,
    components_path=components_path, historical_reference_inputs=historical_reference_inputs,
    check_compiled_identity=check_compiled_identity))
