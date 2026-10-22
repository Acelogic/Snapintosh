#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve all seed bytes outside the main APFS container after local restaging."""
from pathlib import Path
import hashlib

base = Path(__file__).resolve().parents[2] / 'Snapintosh-adreno-resource-map/tools/normalize-adreno-clear-stage.py'
base_sha = '82d51b2d60714e38b2c8f3665e9a87d6d50c0cab21d6a3b8c0cb307cce881d3f'
assert hashlib.sha256(base.read_bytes()).hexdigest() == base_sha
source = base.read_text()
changes = {
    "    if stage.get('ownership_preserved'):\n        assert stage['source_sha256'] == sha(ROOT / 'tools/restage-adreno-clear-image.py')\n    else:\n        assert stage['source_sha256'] == sha(ROOT / 'tools/stage-adreno-clear-image.py')":
        "    assert stage.get('ownership_preserved')\n    assert stage['source_sha256'] == sha(ROOT / 'tools/restage-qc-metal-image.py')",
    'CLEAR_FILES_STAGED_LOCAL_ONLY': 'SHADER_DISPLAY_FILES_STAGED_LOCAL_ONLY',
    'CLEAR_STAGE_NORMALIZED_LOCAL_ONLY': 'SHADER_DISPLAY_STAGE_NORMALIZED_LOCAL_ONLY',
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
