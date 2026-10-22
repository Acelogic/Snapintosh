#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Gracefully retire preserved generation53 and verify idle generation54."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
preservation = ROOT/'build/sks-gen53-preserved-20260928-v1/preservation.json'
assert sha(preservation) == '14eec4b24dc939a481fc389cc1d9a2bb9e1ea8484076aa9fda217d2df594bce6'
saved = json.loads(preservation.read_text())
assert saved['status'] == 'SKS_GEN53_STOPPED_EVIDENCE_PRESERVED'
assert len(saved['runtime_sources']) == 232 and len(saved['artifacts']) == 46
for group in ['runtime_sources', 'artifacts', 'monitor']:
    for name, entry in saved[group].items():
        assert sha(name) == sha(entry['copy']) == entry['sha256'], name
base = ROOT/'build/retire-metal-policy-boot-20260926.py'
assert sha(base) == 'ad5d995e87fcbb3d2755f5e7a4576e4dad39fb81b7fefc4b7cabe071808e092d'
source = base.read_text()
changes = {
    'installed-metal-root-policy-1200s-20260926': 'installed-metal-sks-2100s-20260928',
    '-observer-extension-verification-v1.json': '-pre-reset-verification.json',
    'OBSERVER_EXTENSION_VERIFIED': 'SKS_GEN53_STOPPED_EVIDENCE_PRESERVED',
    "verification['generation'] == 40": "verification['generation'] == 53",
    "len(verification['artifacts_sha256']) == 50": "len(verification['artifacts_sha256']) == 46",
    "info['stage_generation'] == 40": "info['stage_generation'] == 53",
    "info['image_base'] == 0xb0800000": "info['image_base'] == 0xb0000000",
    "proxy.bootinfo()['stage_generation'] == 40": "proxy.bootinfo()['stage_generation'] == 53",
    'link == 0xb0000000': 'link == 0xb0800000',
    "info['stage_generation'] == 41": "info['stage_generation'] == 54",
    'GENERATION41_IDLE': 'GENERATION54_IDLE',
    "if '--check' in sys.argv:":
        "assert record['stage_sha256'] == expected_stages\n"
        "assert record['verification_sha256'] == preservation_sha256\n"
        "record['preservation_sha256'] = preservation_sha256\n"
        "if '--check' in sys.argv:",
}
for old, new in changes.items():
    assert source.count(old) == (2 if old == '-observer-extension-verification-v1.json' else 1), old
    source = source.replace(old, new)
stages = {'q1n1-stage.bin': '752b4ab711fcab5f7a4d4fc1b71dc70ae93ff98efd3212c15d918d2c1e279ea4',
    'q1n1-stage-alt.bin': 'e6276e5a032f97ee0f8f087f5f301da25e709f8b8deca2167eb1d4a4ce9c3c03'}
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__',
    expected_stages=stages, preservation_sha256=sha(preservation)))
