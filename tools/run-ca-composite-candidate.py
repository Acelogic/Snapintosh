#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Boot the composite CA plug-in after its SSD apply and fresh generation63.

Derived from run-ca-metal-candidate.py over the same run-qc-metal-candidate.py
adapter. Plug-in78b6b161/probe8837a5e8 and their trust payload come from the
composite checkout's qualified image; kext3c10369c, AuxKC1f22aed6 and the SKS
monitor340bae8f stay exactly those booted by generation61. Guest watchdog is
2400 seconds. Source pins also cover .cpp/.m/.sh/.plist as in generation61.

Failure inventory: stale source/disk/identity, a changed kext/AuxKC/monitor,
reinitializing a live GPU, wrong generation, duplicate owner, and claiming host
encoding or offscreen replay as guest presentation. --check-inputs performs no
hardware access; --prepare runs the established GPU sequence; never interrupt
an in-flight P_CALL.
"""
from pathlib import Path
import hashlib
import sys

ROOT = Path(__file__).resolve().parents[1]
adapter = ROOT / 'tools/run-qc-metal-candidate.py'
assert hashlib.sha256(adapter.read_bytes()).hexdigest() == '6ce4392b115e140faec89212ef5484839bbf72abd63229244e74b7aba2c9e7ba'
source = adapter.read_text()
observers = ['collect-ca-composite-20260928.py', 'capture-ca-composite-ring-20260928.py',
             'capture-native-startup-gen63-20260928.py', 'capture-crash-retention-gen63-20260928.py']
changes = {
    "PREFIX = 'installed-metal-qc-pipeline-3600s-20260928'": "PREFIX = 'installed-metal-ca-composite-2400s-20260928'",
    "PREDECESSOR = 'installed-metal-panel-arguments-3600s-20260928'": "PREDECESSOR = 'installed-metal-ca-network-3600s-20260928'",
    "PIPE = ROOT.parent / 'Snapintosh-adreno-pipeline'": "PIPE = ROOT.parent / 'Snapintosh-adreno-composite'",
    'build/qc-metal-deploy-20260928': 'build/ca-composite-deploy-20260928',
    'build/metal-pipeline-deploy-20260928': 'build/ca-composite-deploy-gen62-20260928',
    'fbd902010b506ab4dcc055f23c40e345eb55a6d85c6da61c72175f250c60ffbb': '27db00f9824a75c999be134f19136849c81cb827037c34e31c76b5e4b9b330ea',
    "\"context_fields=old['context_fields']+1\": \"context_fields=old['context_fields']\",":
        "\"context_fields=old['context_fields']+1\": \"context_fields=old['context_fields']\",\n"
        "    \"('.c','.h','.py','.S','.ld')\": \"('.c','.h','.py','.S','.ld','.cpp','.m','.sh','.plist')\",",
    'Generation57: deploy native vertex-fetch and scalar-sampler compiler fixes plus the corrected triangle wait probe. Retain gen56 SKS monitor/display AuxKC. Verify actual WindowServer pipelines and presentation; host18/18 does not prove a desktop.':
        'Generation63: install composite plug-in78b6b161 (constrained render extents) and matching probe8837a5e8. Retain generation61 network/display kext3c10369c, AuxKC1f22aed6 and SKS monitor340bae8f. Verify WindowServer composition and actual presentation; host encoding and model replays do not prove a desktop.',
    'cd076f19519151cf2073e7871153d8beb4a9cd1c0744c25ad915941f3dca4cfe': 'e7ed07891301789eba73bbe99de55d5f61c0fbaa1c6fb663d589b9c403d913ba',
    "old['adreno_record']['stage_generation'] == 56": "old['adreno_record']['stage_generation'] == 61",
    "    assert image['auxkc_sha256'] == old['auxkc_sha256'] == sha(old['auxkc'])":
        "    assert image['auxkc_sha256'] == old['auxkc_sha256'] == components['deployed_collection_sha256'] == sha(components['deployed_collection'])\n"
        "    assert old['kext_sha256'] == components['kext_sha256'] == '3c10369cef3d0c3dd446e1822569df346340c93599147a29d38fe28f4a0a4b62'\n"
        "    old = dict(old, auxkc=components['deployed_collection'], auxkc_sha256=components['deployed_collection_sha256'], kext_sha256=components['kext_sha256'])",
    "applied['bootinfo']['stage_generation'] == 57": "applied['bootinfo']['stage_generation'] == 62",
    "    arguments = list(old['arguments'])":
        "    arguments = list(old['arguments'])\n    arguments[arguments.index('--auxkc') + 1] = old['auxkc']",
    "SNAP_WATCHDOG='3600'": "SNAP_WATCHDOG='2400'",
    'storage_snapshot_generation=57': 'storage_snapshot_generation=62',
    "compiler_sha256=components['compiler_sha256'], guest_probe_sha256=components['guest_probe_sha256'],":
        "compiler_sha256=components['compiler_sha256'], guest_probe_sha256=components['guest_probe_sha256'],\n"
        "        kext_sha256=components['kext_sha256'], collection_sha256=components['deployed_collection_sha256'],\n"
        "        network_qualification_sha256=components['network_qualification_sha256'],",
    "str(IMAGE): IMAGE_SHA, str(package_path): sha(package_path), str(applied_path): sha(applied_path)":
        "str(IMAGE): IMAGE_SHA, str(package_path): sha(package_path), str(applied_path): sha(applied_path),\n"
        "        str(adapter): sha(adapter), str(ROOT/'tools/retire-gen62-composite.py'): sha(ROOT/'tools/retire-gen62-composite.py'),\n"
        "        str(STORAGE/'retirement-gen62-v1.json'): sha(STORAGE/'retirement-gen62-v1.json'),\n"
        "        **{str(ROOT/'build'/name): sha(ROOT/'build'/name) for name in " + repr(observers) + "}",
    "    retired = ROOT / 'build' / (PREDECESSOR + '-retirement-v1.json')\n    assert sha(retired) == '9c6a7fb09e344050880ebcf4fe9e0c33d62722b937aa534dba2935f3e6052d09'\n    record = read(retired)\n    assert record['status'] == 'GENERATION57_IDLE' and record['quiesce'] == 'graceful'":
        "    retired = STORAGE / 'retirement-gen62-v1.json'\n    record = read(retired)\n"
        "    assert record['status'] == 'GENERATION63_IDLE' and not record['ssd_writes'] and not record['gpu_writes']\n"
        "    assert record['source_sha256'] == sha(ROOT/'tools/retire-gen62-composite.py')\n"
        "    assert record['apply_sha256'] == sha(STORAGE/'apply-v1.json')\n"
        "    assert record['prior_retirement_sha256'] == '7da980b761b1e20ca57b37d9368ef38822bee4701becd5e279f7170597394188'\n"
        "    assert record['inherited_quiesce_sha256'] == '95f374121f38f0e6c60b1cbbcdb4d72fed2cb18d9fc646e739d2561c2c94a3ba'\n"
        "    assert record['after']['stage_generation'] == 63 and record['after']['image_base'] == 0xb0000000",
    "info['stage_generation'] == 57 and info['image_base'] == 0xb0000000":
        "info['stage_generation'] == 63 and info['image_base'] == 0xb0000000\n"
        "        guard = proxy.serror_state()\n"
        "        assert not any(guard[k] for k in ['before', 'during', 'unconsumed'])",
}
for old, new in changes.items():
    assert source.count(old) == (2 if old == "SNAP_WATCHDOG='3600'" else 1), old
    source = source.replace(old, new)
code = compile(source, str(adapter), 'exec')
if sys.argv[1:] == ['--syntax-only']:
    print('Composite CA launcher transformation compiles; no hardware access')
else:
    exec(code, dict(__file__=__file__, __name__='__main__', adapter=adapter))
