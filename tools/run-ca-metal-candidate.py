#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Boot the combined CA graphics candidate after SSD apply and fresh gen59.

Failure inventory: stale source/disk/identity, old AuxKC in actual arguments,
reinitializing the still-live standalone GPU, changed monitor, wrong generation,
duplicate owner, and claiming host rendering as guest presentation. Keep the
existing guarded GPU preparation, runtime policy and3600-second watchdog.
"""
from pathlib import Path
import hashlib
import sys

ROOT = Path(__file__).resolve().parents[1]
adapter = ROOT / 'tools/run-qc-metal-candidate.py'
assert hashlib.sha256(adapter.read_bytes()).hexdigest() == '6ce4392b115e140faec89212ef5484839bbf72abd63229244e74b7aba2c9e7ba'
source = adapter.read_text()
changes = {
    "PREFIX = 'installed-metal-qc-pipeline-3600s-20260928'": "PREFIX = 'installed-metal-ca-3600s-20260928'",
    "PREDECESSOR = 'installed-metal-panel-arguments-3600s-20260928'": "PREDECESSOR = 'installed-metal-qc-pipeline-3600s-20260928'",
    'build/qc-metal-deploy-20260928': 'build/ca-metal-deploy-20260928',
    'build/metal-pipeline-deploy-20260928': 'build/ca-metal-deploy-20260928',
    'fbd902010b506ab4dcc055f23c40e345eb55a6d85c6da61c72175f250c60ffbb': 'd9fb43b433264be82397d373c4de5ca29791c260d793f8b3109e1dda297a6ea6',
    'Generation57: deploy native vertex-fetch and scalar-sampler compiler fixes plus the corrected triangle wait probe. Retain gen56 SKS monitor/display AuxKC. Verify actual WindowServer pipelines and presentation; host18/18 does not prove a desktop.':
        'Generation59: combine physical CA compiler/texture fixes, copy-capable kernel parser and accepted display behavior. Exact-identity probe and new AuxKC; accepted SKS monitor retained. Verify WindowServer presentation or capture its remaining exception.',
    'cd076f19519151cf2073e7871153d8beb4a9cd1c0744c25ad915941f3dca4cfe': '834fada225eb1a4809c84f307f41caff0c2387fac058a62045b8d0b90bd704e9',
    "old['adreno_record']['stage_generation'] == 56": "old['adreno_record']['stage_generation'] == 57",
    "    assert image['auxkc_sha256'] == old['auxkc_sha256'] == sha(old['auxkc'])":
        "    assert image['auxkc_sha256'] == components['deployed_collection_sha256'] == sha(components['deployed_collection'])\n    old = dict(old, auxkc=components['deployed_collection'], auxkc_sha256=components['deployed_collection_sha256'], kext_sha256=components['kext_sha256'])",
    "applied['bootinfo']['stage_generation'] == 57": "applied['bootinfo']['stage_generation'] == 58",
    "    arguments = list(old['arguments'])":
        "    arguments = list(old['arguments'])\n    arguments[arguments.index('--auxkc') + 1] = old['auxkc']",
    'storage_snapshot_generation=57': 'storage_snapshot_generation=58',
    "str(IMAGE): IMAGE_SHA, str(package_path): sha(package_path), str(applied_path): sha(applied_path)":
        "str(IMAGE): IMAGE_SHA, str(package_path): sha(package_path), str(applied_path): sha(applied_path),\n        str(adapter): sha(adapter), str(ROOT/'tools/retire-gen58-ca.py'): sha(ROOT/'tools/retire-gen58-ca.py'),\n        str(STORAGE/'retirement-gen58-v1.json'): sha(STORAGE/'retirement-gen58-v1.json')",
    "    retired = ROOT / 'build' / (PREDECESSOR + '-retirement-v1.json')\n    assert sha(retired) == '9c6a7fb09e344050880ebcf4fe9e0c33d62722b937aa534dba2935f3e6052d09'\n    record = read(retired)\n    assert record['status'] == 'GENERATION57_IDLE' and record['quiesce'] == 'graceful'":
        "    retired = STORAGE / 'retirement-gen58-v1.json'\n    record = read(retired)\n    assert record['status'] == 'GENERATION59_IDLE' and not record['ssd_writes']\n    assert record['source_sha256'] == sha(ROOT/'tools/retire-gen58-ca.py')\n    assert record['apply_sha256'] == sha(STORAGE/'apply-v1.json')\n    assert record['proof_sha256'] == '8d95a910aedce77fb31710799e0882e0a1c8b0d32b1eacfbf709e0c5d0995c2e'\n    assert record['quiesce_sha256'] == sha(STORAGE/'quiesce-gen58-v1.json')",
    "info['stage_generation'] == 57 and info['image_base'] == 0xb0000000":
        "info['stage_generation'] == 59 and info['image_base'] == 0xb0000000",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
code = compile(source, str(adapter), 'exec')
if sys.argv[1:] == ['--syntax-only']:
    print('Combined CA launcher transformation compiles; no hardware access')
else:
    exec(code, dict(__file__=__file__, __name__='__main__', adapter=adapter))
