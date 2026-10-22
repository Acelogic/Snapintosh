#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the existing guest probe for the physically verified CA Metal bundle.

Failure inventory: stale compiled plug-in identity, mismatched compiler, changed
golden/capture, stale historical source bindings, and host proof mislabeled A16.
The historical triangle supplies scene/reference bytes only. Current driver
sources and the exact new bundle are separately bound; all host pixel and
presentation-layout checks in the original builder remain enabled.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
base = ROOT / 'tools/build-adreno-triangle-probe.py'
assert sha(base) == '05024edc2c862bc835fb83b201e06bae3904c3b421e62019535bd3e5f817d903'
native_path = ROOT / 'build/qc-pipelines-vpc-20260928-v1.json'
assert sha(native_path) == '0f7b2ad462e76103da3d52e2b20a534bd1e4d91d15e3a871081f352c8311455a'
native = json.loads(native_path.read_text())
assert native['status'] == 'NATIVE_QC_PIPELINES_COMPILED'
assert native['passed'] == 18 and native['failed'] == 0
bundle = Path(native['bundle'])
assert sha(bundle / 'Contents/MacOS/AdrenoMetal') == native['plugin_sha256']
assert sha(bundle / 'Contents/Frameworks/libAdrenoCompiler.dylib') == native['compiler_sha256']
current_inputs = {str(p.resolve()): sha(p) for p in (base, Path(__file__), native_path)}
for p in bundle.rglob('*'):
    if p.is_file():
        assert not p.is_symlink()
        current_inputs[str(p.resolve())] = sha(p)
for p in (ROOT / 'gpu/adreno-kext/plugin').rglob('*'):
    if p.is_file() and p.suffix in ('.m', '.h', '.c', '.sh'):
        current_inputs[str(p.resolve())] = sha(p)


def check_identity(executable):
    data = executable.read_bytes()
    assert data.count(native['plugin_sha256'].encode()) == 1
    for stale in ('9a1cdb3981377ad9231fd87806c161434df1b99509ec5bea26b87a31fdb48fb4',
                  '942d8f2c7261880da126838a62412a562fbd1f0f798eaa3f6263faa3743ea014'):
        assert stale.encode() not in data


source = base.read_text()
changes = {
    "[('sources_sha256', ROOT), ('artifacts_sha256', parent),":
        "[('artifacts_sha256', parent),",
    "    capture_path = parent/'plan-v2-clear.json'":
        "    assert sha(qualification) == '769425b251e8fdf3a223e5dd05639181c0bf45836291233997181527cf380211'\n    bindings.update(current_inputs)\n    capture_path = parent/'plan-v2-clear.json'",
    "    assert sha(binary) == draw['bundle_executable_sha256']":
        "    assert sha(binary) == draw['bundle_executable_sha256']\n    bundle = candidate_bundle\n    binary = bundle/'Contents/MacOS/AdrenoMetal'\n    assert sha(binary) == native['plugin_sha256']",
    '        inputs_sha256=bindings,':
        "        inputs_sha256=bindings, historical_reference_sources=draw['sources_sha256'],\n        native_compiler_evidence=str(native_path), native_compiler_sha256=sha(native_path),\n        compiler_sha256=native['compiler_sha256'], historical_draw_reference=True,",
    "        record.update(status='GUEST_TRIANGLE_BUILT_HOST_REFERENCE_MATCHED_NOT_EXECUTED_ON_A16',":
        "        check_identity(out/'metal-triangle-probe')\n        record['compiled_identity_matches_current_bundle'] = True\n        record.update(status='GUEST_TRIANGLE_BUILT_HOST_REFERENCE_MATCHED_NOT_EXECUTED_ON_A16',",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__',
    candidate_bundle=bundle, native=native, native_path=native_path,
    current_inputs=current_inputs, check_identity=check_identity))
