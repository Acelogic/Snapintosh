#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rehash and inspect generation62's snapshot against the actual gen58->59 install."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/inspect-gen57-metal.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '9b7b0bfb6f04bf4672c358ea6f3e1dd4193023d5ef8a2eb60cb7de521b34a704'
source = base.read_text()
changes = {
    "SNAP = ROOT / 'build/metal-pipeline-deploy-20260928/snapshot-v1'": "SNAP = ROOT / 'build/ca-network-deploy-20260928/snapshot-v1'",
    "\"BASE = ROOT/'build/metal-pipeline-deploy-20260928'\"": "\"BASE = ROOT/'build/ca-composite-deploy-gen62-20260928'\"",
    "\"SNAP = BASE/'snapshot-v1'\"": "\"SNAP = ROOT/'build/ca-network-deploy-20260928/snapshot-v1'\"",
    "record['generation'] == 57": "record['generation'] == 62",
    "snapshot['generation'] == 57": "snapshot['generation'] == 62",
    'build/adreno-gui-integration-20260927/deployment-v1/deployment.json': 'build/ca-metal-deploy-20260928/deployment-v1/deployment.json',
    '53eac4ddc76738a1ea42dc97dda56f0d3515c936bb505458787ce9a91220247a': '82919f55ff56e8d63391ab06f143815bc00e9daa9316bb32b2075d0154d7ce2d',
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
