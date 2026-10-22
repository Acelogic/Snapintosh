#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read generation58 ISC after the fresh full-container snapshot; no SSD writes.

Failure inventory: stale generation, changed snapshot/persistence evidence,
incorrect disk identity, partial read, copy/hash mismatch, or SError. Use the
existing bounded reader, native full hash, and normal controller shutdown.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'build/capture-metal-raw-sign-isc-20260927.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == 'b44ef6b0d439a2f2a6124b35fa6c2332e496c4125c04048860a5efd45454e9be'
source = base.read_text()
changes = {
    "base = Path(__file__).with_name('capture-installed-metal-isc-20260926.py')":
        "base = ROOT / 'build/capture-installed-metal-isc-20260926.py'",
    'installed-metal-raw-sign-3600s-20260927': 'installed-metal-qc-pipeline-3600s-20260928',
    '3eb863e803be5b9436156d025b88bfbc3a3d317620d2276fbd123b40a587ac9e': '03723737e485d7fd7c42a7994c796f94db9312546963e1b10aae3ebb06bb5153',
    'raw-sign-report-snapshot-v1': 'snapshot-v1',
    'raw-sign-isc-v1': 'isc-v1',
    '==45': '==58',
    'generation=45': 'generation=58',
    'Generation45 ISC': 'Generation58 ISC',
}
for old, new in changes.items():
    assert source.count(old) > 0, old
    source = source.replace(old, new)
anchor = "code = compile(source, str(base), 'exec')"
assert source.count(anchor) == 1
extra = {
    "BASE=ROOT/'build/installed-metal-20260926'": "BASE=ROOT/'build/ca-metal-deploy-20260928'",
    "manifest=json.loads((BASE/'bootstrap-delta-v2/manifest.json').read_text())":
        "manifest=json.loads((ROOT.parent/'Snapintosh-adreno-pipeline/build/qc-metal-deploy-20260928/delta-v1/manifest.json').read_text())",
    "assert status==0 and 'on AC' in battery['text']": "assert status==0 and battery['plausible'] and (battery['ac'] or battery['percent']>=30)",
}
injected = ''.join(f'assert source.count({old!r}) == 1, {old!r}\nsource = source.replace({old!r}, {new!r})\n' for old, new in extra.items())
source = source.replace(anchor, injected + anchor)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__', ROOT=ROOT))
