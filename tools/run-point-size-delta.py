#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Apply the point-size CA candidate at idle generation72 with the qualified native SSD writer.

Derived from run-shader-cache-delta-gen69.py. The package, replay, stage and
normalization live in ../Snapintosh-clip/build/psize-deploy (delta-v1,
delta-replay-v1.json, local-stage-gen72-v1, normalized-gen72-v1); storage
records (inspection, ISC, check/probe/apply) in this checkout's
build/point-size-deploy-gen72-20260928. Every existing writer rule is
unchanged, including the battery rule of the native preflight: AC, or at least
80% charge. Run check, probe and apply with the same q1n1 checkout: apply
requires the check and probe records' native sources to equal the current ones.

Stage binding preflight (every mode except --syntax-only, before any connection):
the writer's NativeHash binds this checkout's own q1n1 stage build first, so the
stage the last retirement chainloaded must be q1n1/build/uefi's binary for the slot.

Failure inventory: stale baseline, wrong generation, changed package or replay,
missing probe restoration, uncertain native completion, duplicate owner, and a
running stage the native hash helper cannot bind. Never interrupt P_CALL.
"""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
if sys.argv[1:] != ['--syntax-only']:
    retirement = ROOT / 'build/installed-metal-integrated-guestes-2400s-20260928-retirement-v1.json'
    assert sha(retirement) == '65741fbfc298cfce469ee2f8c4cef495d984da50688cc6fc0b431610e2b8ebf3'
    retired = json.loads(retirement.read_text())
    assert retired['status'] == 'GENERATION72_IDLE' and retired['after']['image_base'] == 0xb0800000
    local = ROOT.parent / 'q1n1/build/uefi/q1n1-stage-alt.bin'
    if sha(local) != retired['chosen_stage']['sha256']:
        raise SystemExit(json.dumps(dict(status='REFUSED_STAGE_BINDING', hardware_access=False,
            running_stage=retired['chosen_stage'], native_hash_stage=dict(path=str(local), sha256=sha(local)),
            reason='the native writer\'s hash helper cannot bind the running stage')))
base = ROOT / 'build/run-qc-metal-delta-20260928.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '35f2ce9ed897107f5abf0d157e5a46c267cd4d3d79e020983927ff6a492250e0'
source = base.read_text()
changes = {
    "base = Path(__file__).with_name('run-adreno-gui-delta-20260927.py')":
        "base = ROOT / 'build/run-adreno-gui-delta-20260927.py'",
    'build/metal-pipeline-deploy-20260928': 'build/point-size-deploy-gen72-20260928',
    'build/qc-metal-deploy-20260928': 'build/psize-deploy',
    '../metal-pipeline-deploy-20260928/snapshot-v1': '../installed-metal-integrated-guestes-2400s-20260928-snapshot-v1',
    '../metal-pipeline-deploy-20260928/isc-v1': '../point-size-deploy-gen72-20260928/isc-v1',
    'capture-qc-metal-isc-20260928.py': 'capture-point-size-isc-20260928.py',
    "' == 49': ' == 57'": "' == 49': ' == 72'",
    "    'Generation49 GUI': 'Generation57 compiler',":
        "    'Generation49 GUI': 'Generation72 point-size',\n"
        "    \"'Snapintosh-adreno-pipeline'\": \"'Snapintosh-clip'\",",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
# The historical GUI adapter resolves its next source beside __file__. Keep
# that build-directory origin while this entry point supplies the current map.
exec(compile(source, str(base), 'exec'), dict(__file__=str(ROOT / 'build/run-point-size-delta-20260928.py'),
    __name__='__main__', ROOT=ROOT))
