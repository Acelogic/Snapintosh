#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Apply the generation58 CA candidate using the qualified native SSD writer.

Failure inventory: stale baseline, wrong generation, changed package or replay,
missing probe restoration, uncertain native completion, and duplicate owner.
No new write path: retain whole-container before/overlay/after hashes, protected
edges, read-back, rollback data, and normal shutdown. Never interrupt P_CALL.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'build/run-qc-metal-delta-20260928.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '35f2ce9ed897107f5abf0d157e5a46c267cd4d3d79e020983927ff6a492250e0'
source = base.read_text()
changes = {
    "base = Path(__file__).with_name('run-adreno-gui-delta-20260927.py')":
        "base = ROOT / 'build/run-adreno-gui-delta-20260927.py'",
    'build/metal-pipeline-deploy-20260928': 'build/ca-metal-deploy-20260928',
    'build/qc-metal-deploy-20260928': 'build/ca-metal-deploy-20260928',
    '../metal-pipeline-deploy-20260928/': '../ca-metal-deploy-20260928/',
    'capture-qc-metal-isc-20260928.py': 'capture-ca-metal-isc-20260928.py',
    "' == 49': ' == 57'": "' == 49': ' == 58'",
    'Generation57 compiler': 'Generation58 CoreAnimation',
}
for old, new in changes.items():
    assert source.count(old) == (2 if old == '../metal-pipeline-deploy-20260928/' else 1), old
    source = source.replace(old, new)
# The historical GUI adapter resolves its next source beside __file__. Keep
# that build-directory origin while this entry point supplies the current map.
exec(compile(source, str(base), 'exec'), dict(__file__=str(ROOT / 'build/run-ca-metal-delta-20260928.py'),
    __name__='__main__', ROOT=ROOT))
