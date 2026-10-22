#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retire preserved, natively stopped generation56 to idle generation57.

Reuse the tested graceful GPU quiesce/alternating chainload sequence, preserving
the original unavailable host exit. Recheck native stop before GPU writes.
"""
from pathlib import Path
import argparse
import hashlib
import json
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT.parent / 'Snapintosh-adreno-sks'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--preservation-sha256', required=True)
ap.add_argument('--check', action='store_true')
args = ap.parse_args()
preservation = ROOT / 'build/metal-pipeline-gen56-preserved-20260928-v1/preservation.json'
assert sha(preservation) == args.preservation_sha256
saved = json.loads(preservation.read_text())
assert saved['status'] == 'GEN56_STOPPED_EVIDENCE_PRESERVED' and saved['generation'] == 56
assert len(saved['runtime_sources']) == 243
for group in ['runtime_sources', 'artifacts', 'binaries', 'diagnosis']:
    for name, entry in saved[group].items():
        assert sha(name) == sha(entry['copy']) == entry['sha256'], name
recovery_tool = ROOT / 'tools/recover-gen56-stop.py'
assert sha(recovery_tool) == '25b67bcde22f08efdac0c371c3499ffcf56f999c4e0affbb017bccfbf2ac9433'
recovery_api = runpy.run_path(str(recovery_tool))
recovery_api['validate']()


def validate_native_stop(proxy, info):
    sys.path[:0] = [str(RUNTIME / 'probes'), str(RUNTIME / 'tools')]
    import run
    from monitor_layout import MonitorLayout
    assert info['current_el'] == 2
    layout = MonitorLayout()
    assert layout.size('context') == 5124736
    work, size = run.resident_work(proxy, info)
    service_pa = work + layout.offset('context', 'services')
    raw = proxy.readmem(service_pa, 64, live=True)
    words = struct.unpack('<8Q', raw)
    assert words[0] == 0 and words[2] == 0x8000000000000003 and not any(words[3:])
    assert words[1] >> 32 in (1, 2) and 1 <= words[1] & 0xffffffff <= 6
    assert proxy.readmem(service_pa, 64, live=True) == raw
    guard = proxy.serror_state()
    assert not any(guard[k] for k in ['before', 'during', 'unconsumed'])


base = ROOT / 'build/retire-metal-policy-boot-20260926.py'
assert sha(base) == 'ad5d995e87fcbb3d2755f5e7a4576e4dad39fb81b7fefc4b7cabe071808e092d'
source = base.read_text()
changes = {
    'installed-metal-root-policy-1200s-20260926': 'installed-metal-panel-arguments-3600s-20260928',
    '-observer-extension-verification-v1.json': '-pre-reset-verification.json',
    'OBSERVER_EXTENSION_VERIFIED': 'GEN56_STOPPED_EVIDENCE_PRESERVED',
    "verification['generation'] == 40": "verification['generation'] == 56",
    "len(verification['artifacts_sha256']) == 50": f"len(verification['artifacts_sha256']) == {len(saved['artifacts'])}",
    "info['stage_generation'] == 40": "info['stage_generation'] == 56",
    "proxy.bootinfo()['stage_generation'] == 40": "proxy.bootinfo()['stage_generation'] == 56",
    "info['stage_generation'] == 41": "info['stage_generation'] == 57",
    'GENERATION41_IDLE': 'GENERATION57_IDLE',
    "try: os.kill(launch['pid'],0)\nexcept ProcessLookupError: pass\nelse: raise AssertionError('launcher remains live')":
        "recovery_api['host_absent'](launch)",
    "record['before'] = info": "validate_native_stop(proxy, info)\n        record['before'] = info",
    "if '--check' in sys.argv:": "assert record['stage_sha256'] == expected_stages\nassert record['verification_sha256'] == preservation_sha\nif '--check' in sys.argv:",
}
for old, new in changes.items():
    assert source.count(old) == (2 if old == '-observer-extension-verification-v1.json' else 1), old
    source = source.replace(old, new)
stages = {'q1n1-stage.bin': '752b4ab711fcab5f7a4d4fc1b71dc70ae93ff98efd3212c15d918d2c1e279ea4',
          'q1n1-stage-alt.bin': 'e6276e5a032f97ee0f8f087f5f301da25e709f8b8deca2167eb1d4a4ce9c3c03'}
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__',
    recovery_api=recovery_api, validate_native_stop=validate_native_stop,
    expected_stages=stages, preservation_sha=args.preservation_sha256))
