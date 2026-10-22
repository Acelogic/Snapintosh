#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rehash and inspect generation72's snapshot against the actual gen69 shader-cache install."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/inspect-gen57-metal.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '9b7b0bfb6f04bf4672c358ea6f3e1dd4193023d5ef8a2eb60cb7de521b34a704'
source = base.read_text()
changes = {
    "SNAP = ROOT / 'build/metal-pipeline-deploy-20260928/snapshot-v1'":
        "SNAP = ROOT / 'build/installed-metal-integrated-guestes-2400s-20260928-snapshot-v1'",
    "\"BASE = ROOT/'build/metal-pipeline-deploy-20260928'\"": "\"BASE = ROOT/'build/point-size-deploy-gen72-20260928'\"",
    "\"SNAP = BASE/'snapshot-v1'\"": "\"SNAP = ROOT/'build/installed-metal-integrated-guestes-2400s-20260928-snapshot-v1'\"",
    "record['generation'] == 57": "record['generation'] == 72",
    "snapshot['generation'] == 57": "snapshot['generation'] == 72",
    'Snapintosh-adreno-pipeline/build/adreno-gui-integration-20260927/deployment-v1/deployment.json':
        'Snapintosh-shaders/build/shader-cache-deploy-20260928/stage-v1/deployment.json',
    '53eac4ddc76738a1ea42dc97dda56f0d3515c936bb505458787ce9a91220247a': '593d9a528fb270273fdc282feb32cffcb5836c4d278c852c781e3a39d7b3e3ba',
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
