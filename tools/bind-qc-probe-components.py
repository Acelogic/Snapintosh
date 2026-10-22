#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind compiler/driver/probe components only when the probe identity matches.

The --probe-build option admits the two known build records so the actual
installed mismatch can be reproduced as a rejected package. No A16 access.
Failure inventory: original docs/GEN57-PROBE-IDENTITY-20260928.md.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/bind-qc-metal-components.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '733fa4ba19aeea9fe13f66f507a678a16c90df200756e4ac59bf69af8294a20e'
approved_builds = {
    str(ROOT / 'build/adreno-frame-wait-probe-20260928-v2/build.json'): '8dd1fa811526d38d50241a3157c42ee11d1734b0aecb01ffb092c8d466c43c26',
    str(ROOT / 'build/qc-triangle-probe-20260928-v1/build.json'): 'b3bd5a85d9944acfa393efb0f0e10ec665b0ddf4953608e8497f2cd6e65761d0',
}


def check_identity(probe_path, native):
    probe = json.loads(probe_path.read_text())
    assert probe['plugin_sha256'] == native['plugin_sha256'], (
        'PROBE_PLUGIN_IDENTITY_MISMATCH', probe['plugin_sha256'], native['plugin_sha256'])
    binary = probe_path.parent / 'metal-triangle-probe'
    data = binary.read_bytes()
    assert hashlib.sha256(data).hexdigest() == probe['binary_sha256']
    assert data.count(native['plugin_sha256'].encode()) == 1
    assert b'9a1cdb3981377ad9231fd87806c161434df1b99509ec5bea26b87a31fdb48fb4' not in data
    assert probe['compiled_identity_matches_current_bundle']


source = base.read_text()
changes = {
    "ap.add_argument('--output', type=Path, required=True)":
        "ap.add_argument('--output', type=Path, required=True)\nap.add_argument('--probe-build', type=Path, default=ROOT/'build/qc-triangle-probe-20260928-v1/build.json')",
    "probe_path = ROOT / 'build/adreno-frame-wait-probe-20260928-v2/build.json'":
        "probe_path = args.probe_build.resolve()\nassert str(probe_path) in approved_builds\ncheck_identity(probe_path, native)",
    "probe = read(probe_path, '8dd1fa811526d38d50241a3157c42ee11d1734b0aecb01ffb092c8d466c43c26')":
        'probe = read(probe_path, approved_builds[str(probe_path)])',
    'bind(__file__)': 'bind(__file__)\nbind(base)',
    '    guest_probe=str(executable), guest_probe_sha256=probe[\'binary_sha256\'],':
        "    guest_probe=str(executable), guest_probe_sha256=probe['binary_sha256'],\n    probe_build=str(probe_path), probe_build_sha256=sha(probe_path),\n    compiled_probe_plugin_identity_verified=True,",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__',
    approved_builds=approved_builds, check_identity=check_identity, base=base))
