#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retire preserved generation52 using the established graceful transition."""
from pathlib import Path
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
preservation=ROOT/'build/sks-gpu-candidate-20260928-v1/preserved-gen52-v1/preservation.json'
assert sha(preservation)=='2b6b00b420b608b431f8dc690a9a59b33e81cccc1cab68749d4fe73d1b573b39'
saved=json.loads(preservation.read_text())
assert saved['status']=='GEN52_SOURCES_AND_STOPPED_EVIDENCE_PRESERVED'
assert len(saved['runtime_sources'])==198 and len(saved['artifacts'])==75
for name,entry in {**saved['runtime_sources'],**saved['artifacts']}.items():
    assert sha(name)==sha(entry['copy'])==entry['sha256'],name
base=ROOT/'build/retire-metal-policy-boot-20260926.py'
assert sha(base)=='ad5d995e87fcbb3d2755f5e7a4576e4dad39fb81b7fefc4b7cabe071808e092d'
source=base.read_text()
changes={
    'installed-metal-root-policy-1200s-20260926':'installed-metal-virtual-ethernet-2100s-20260927',
    '-observer-extension-verification-v1.json':'-pre-reset-verification.json',
    'OBSERVER_EXTENSION_VERIFIED':'VIRTUAL_ETHERNET_STOPPED_CAPTURES_VERIFIED',
    "verification['generation'] == 40":"verification['generation'] == 52",
    "len(verification['artifacts_sha256']) == 50":"len(verification['artifacts_sha256']) == 41",
    "info['stage_generation'] == 40":"info['stage_generation'] == 52",
    "proxy.bootinfo()['stage_generation'] == 40":"proxy.bootinfo()['stage_generation'] == 52",
    "info['stage_generation'] == 41":"info['stage_generation'] == 53",
    'GENERATION41_IDLE':'GENERATION53_IDLE',
    "if '--check' in sys.argv:":
        "assert record['stage_sha256'] == expected_stages\n"
        "assert record['verification_sha256'] == '94cabcf00b596f9bcfa802c3b74cdebfd13122b9a8287ad1bb88e18862dac81a'\n"
        "record['preservation_sha256'] = preservation_sha256\n"
        "if '--check' in sys.argv:",
}
for old,new in changes.items():
    assert source.count(old)==(2 if old=='-observer-extension-verification-v1.json' else 1),old
    source=source.replace(old,new)
stages={'q1n1-stage.bin':'752b4ab711fcab5f7a4d4fc1b71dc70ae93ff98efd3212c15d918d2c1e279ea4',
    'q1n1-stage-alt.bin':'e6276e5a032f97ee0f8f087f5f301da25e709f8b8deca2167eb1d4a4ce9c3c03'}
exec(compile(source,str(base),'exec'),dict(__file__=__file__,__name__='__main__',
    expected_stages=stages,preservation_sha256=sha(preservation)))
