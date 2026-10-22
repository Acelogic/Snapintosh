#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package the shader/display delta with a declared 128 MiB payload ceiling."""
from pathlib import Path
import hashlib

base = Path(__file__).resolve().parents[2] / 'Snapintosh-adreno-resource-map/tools/package-adreno-clear.py'
base_sha = '6af3b64ccd85af6556cd9a2055c730619333dd3340de92b48e9fb28c4b8f04b1'
assert hashlib.sha256(base.read_bytes()).hexdigest() == base_sha
source = base.read_text()
changes = {
    "    stage_source = ROOT / ('tools/restage-adreno-clear-image.py' if stage.get('ownership_preserved')\n                           else 'tools/stage-adreno-clear-image.py')":
        "    assert not stage.get('ownership_preserved')\n    stage_source = ROOT / 'tools/stage-adreno-gui-image.py'",
    "stage_source, isc_source, base)}":
        f"stage_source, isc_source, base, Path({str(base)!r}))}}",
    "    changes = {":
        "    changes = {\n        'MAX_DELTA = 64 << 20': 'MAX_DELTA = 128 << 20',\n        'delta exceeds 64 MiB proposal limit': 'delta exceeds 128 MiB GUI proposal limit',",
    'binding_inputs_sha256=binding_inputs, base_source_sha256=base_source_sha,':
        f'binding_inputs_sha256=binding_inputs, base_source_sha256=base_source_sha, adapter_base_sha256="{base_sha}", max_delta_bytes=MAX_DELTA,',
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
for old, new, count in (
    ('CLEAR_FILES_STAGED_LOCAL_ONLY', 'SHADER_DISPLAY_FILES_STAGED_LOCAL_ONLY', 1),
    ('CLEAR_STAGE_NORMALIZED_LOCAL_ONLY', 'SHADER_DISPLAY_STAGE_NORMALIZED_LOCAL_ONLY', 2),
    ('tools/normalize-adreno-clear-stage.py', 'tools/normalize-adreno-gui-stage.py', 2),
):
    assert source.count(old) == count, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
