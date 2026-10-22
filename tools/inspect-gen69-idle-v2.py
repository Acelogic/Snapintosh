#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rehash and inspect generation69's snapshot against the actual gen62 composite install (v2 output).

The v1 run read everything and matched all six files, but its detach returned
"Resource busy" (exit 16), so that record is FAIL and kept. This copy writes
report-inspection-v2 and is otherwise identical.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/inspect-gen57-metal.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '9b7b0bfb6f04bf4672c358ea6f3e1dd4193023d5ef8a2eb60cb7de521b34a704'
source = base.read_text()
changes = {
    "SNAP = ROOT / 'build/metal-pipeline-deploy-20260928/snapshot-v1'": "SNAP = ROOT / 'build/ca-memo-deploy-20260928/snapshot-gen69-v1'",
    "\"BASE = ROOT/'build/metal-pipeline-deploy-20260928'\"": "\"BASE = ROOT/'build/shader-cache-deploy-gen69-20260928'\"",
    "\"SNAP = BASE/'snapshot-v1'\"": "\"SNAP = ROOT/'build/ca-memo-deploy-20260928/snapshot-gen69-v1'\",\n"
        "    \"OUT = BASE/'report-inspection-v1'\": \"OUT = BASE/'report-inspection-v2'\"",
    "record['generation'] == 57": "record['generation'] == 69",
    "snapshot['generation'] == 57": "snapshot['generation'] == 69",
    'Snapintosh-adreno-pipeline/build/adreno-gui-integration-20260927/deployment-v1/deployment.json':
        'Snapintosh-adreno-composite/build/ca-composite-deploy-20260928/stage-v1/deployment.json',
    '53eac4ddc76738a1ea42dc97dda56f0d3515c936bb505458787ce9a91220247a': 'b5d29b80f469558f12bf7652de719d4090ae575d65968f1b730898a6fa243928',
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
