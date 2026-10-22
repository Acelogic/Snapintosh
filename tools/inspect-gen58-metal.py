#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rehash and inspect generation58's snapshot against the actual gen57 install."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/inspect-gen57-metal.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '9b7b0bfb6f04bf4672c358ea6f3e1dd4193023d5ef8a2eb60cb7de521b34a704'
source = base.read_text()
changes = {
    'build/metal-pipeline-deploy-20260928': 'build/ca-metal-deploy-20260928',
    "record['generation'] == 57": "record['generation'] == 58",
    "snapshot['generation'] == 57": "snapshot['generation'] == 58",
    'build/adreno-gui-integration-20260927/deployment-v1/deployment.json': 'build/qc-metal-deploy-20260928/deployment-v1/deployment.json',
    '53eac4ddc76738a1ea42dc97dda56f0d3515c936bb505458787ce9a91220247a': '7469c51e1143ed703ef1256c30e07871b8f6dd5a76436f11f1af720e464a5ff0',
}
for old, new in changes.items():
    assert source.count(old) == (2 if old == 'build/metal-pipeline-deploy-20260928' else 1), old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
