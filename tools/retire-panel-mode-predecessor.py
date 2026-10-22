#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Gracefully retire preserved generation54 to idle generation55."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
preservation = ROOT / 'build/panel-mode-gen54-preserved-20260928-v1/preservation.json'
preservation_sha = '08f206283f838f704010829e2bb86208e338aaca6ac167752ddf4b2e0f75ded6'
assert sha(preservation) == preservation_sha
saved = json.loads(preservation.read_text())
assert saved['status'] == 'PANEL_MODE_GEN54_STOPPED_EVIDENCE_PRESERVED'
assert len(saved['runtime_sources']) == 233 and len(saved['artifacts']) == 45
for group in ['runtime_sources', 'artifacts', 'binaries', 'diagnosis']:
    for name, entry in saved[group].items():
        assert sha(name) == sha(entry['copy']) == entry['sha256'], name


def validate_terminal_identity(launch):
    assert launch['exit_code'] == 9 and launch['finished']
    observed = subprocess.run(['ps', '-p', str(launch['pid']), '-o', 'lstart='],
        env=dict(os.environ, TZ='UTC', LC_ALL='C'), capture_output=True, text=True)
    if observed.stdout.strip():
        started = datetime.strptime(observed.stdout.strip(), '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc).timestamp()
        assert started > launch['finished'], 'original launcher may still be present'
    else:
        assert observed.returncode == 1 and not observed.stderr.strip(), observed.stderr


base = ROOT / 'build/retire-metal-policy-boot-20260926.py'
assert sha(base) == 'ad5d995e87fcbb3d2755f5e7a4576e4dad39fb81b7fefc4b7cabe071808e092d'
source = base.read_text()
changes = {
    'installed-metal-root-policy-1200s-20260926': 'installed-metal-sks-transport-2100s-20260928',
    '-observer-extension-verification-v1.json': '-pre-reset-verification.json',
    'OBSERVER_EXTENSION_VERIFIED': 'PANEL_MODE_GEN54_STOPPED_EVIDENCE_PRESERVED',
    "verification['generation'] == 40": "verification['generation'] == 54",
    "len(verification['artifacts_sha256']) == 50": "len(verification['artifacts_sha256']) == 45",
    "info['stage_generation'] == 40": "info['stage_generation'] == 54",
    "proxy.bootinfo()['stage_generation'] == 40": "proxy.bootinfo()['stage_generation'] == 54",
    "info['stage_generation'] == 41": "info['stage_generation'] == 55",
    'GENERATION41_IDLE': 'GENERATION55_IDLE',
    "try: os.kill(launch['pid'],0)\nexcept ProcessLookupError: pass\nelse: raise AssertionError('launcher remains live')":
        'validate_terminal_identity(launch)',
    "if '--check' in sys.argv:":
        "assert record['stage_sha256'] == expected_stages\n"
        "assert record['verification_sha256'] == preservation_sha\n"
        "record['preservation_sha256'] = preservation_sha\n"
        "if '--check' in sys.argv:",
}
for old, new in changes.items():
    assert source.count(old) == (2 if old == '-observer-extension-verification-v1.json' else 1), old
    source = source.replace(old, new)
stages = {'q1n1-stage.bin': '752b4ab711fcab5f7a4d4fc1b71dc70ae93ff98efd3212c15d918d2c1e279ea4',
          'q1n1-stage-alt.bin': 'e6276e5a032f97ee0f8f087f5f301da25e709f8b8deca2167eb1d4a4ce9c3c03'}
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__',
    expected_stages=stages, preservation_sha=preservation_sha,
    validate_terminal_identity=validate_terminal_identity))
