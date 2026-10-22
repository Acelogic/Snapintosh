#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve stopped generation55 and its captured argument-order diagnosis."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/preserve-panel-mode-predecessor.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '6c920d15355d7da7bb3e4d3d1df9d10321d3351e568a81b9760aac7b26ebc616'
source = base.read_text()
changes = {
    'installed-metal-sks-transport-2100s-20260928': 'installed-metal-panel-mode-2100s-20260928',
    'panel-mode-gen54-preserved-20260928-v1': 'panel-mode-gen55-preserved-20260928-v1',
    "launch['adreno_record']['stage_generation'] == 54": "launch['adreno_record']['stage_generation'] == 55",
    "'-native-startup-state-v1.json', '-crash-retention-v1.json'":
        "'-native-startup-state-v1.json', '-crash-retention-v1.json', '-panel-mode-dispatch-v1.json', '-windowserver-corpses-v2.json'",
    "'a16-ic20-survey-gen54-20260928-v1.json'": "'a16-input-transaction-survey-gen55-20260928-v1.json'",
    "'metal-probe-gen54-symbols-20260928-v2.json'": "'metal-probe-gen55-symbols-20260928-v1.json'",
    "'panel-mode-installed-replay-20260928-v3.json'": "'panel-mode-observed-rejection-20260928-v1.json'",
    "'panel-mode-candidate-replay-20260928-v2.json'":
        "'panel-mode-observed-correction-20260928-v1.json', 'triangle-history-comparison-20260928-v1.json', "
        "'capture-windowserver-corpses-gen55-20260928.py', 'capture-panel-mode-dispatch-gen55-20260928.py', "
        "'capture-crash-retention-gen55-20260928.py', 'resolve-metal-probe-gen55-20260928.py'",
    "status='PANEL_MODE_GEN54_STOPPED_EVIDENCE_PRESERVED', generation=54":
        "status='PANEL_ARGUMENT_GEN55_STOPPED_EVIDENCE_PRESERVED', generation=55",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
