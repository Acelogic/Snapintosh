#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Gracefully retire preserved generation55 to idle generation56.

--check verifies inputs without connecting. Actual retirement requires the
terminal launch, unchanged preservation, GPU quiescence and zero SError.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/retire-panel-mode-predecessor.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '4e33dd9d9ede4a174124fa9f38375c1dfa22990c6429252bad58cd626a772176'
source = base.read_text()
changes = [
    ("info['stage_generation'] == 55", "info['stage_generation'] == 56"),
    ('GENERATION55_IDLE', 'GENERATION56_IDLE'),
    ('panel-mode-gen54-preserved-20260928-v1', 'panel-mode-gen55-preserved-20260928-v1'),
    ('08f206283f838f704010829e2bb86208e338aaca6ac167752ddf4b2e0f75ded6', '6d51fbbf72cf24fce5fbe7a09696b8c974bfb4e5497aacf7b21233b4a2c490ba'),
    ('PANEL_MODE_GEN54_STOPPED_EVIDENCE_PRESERVED', 'PANEL_ARGUMENT_GEN55_STOPPED_EVIDENCE_PRESERVED'),
    ("len(saved['runtime_sources']) == 233 and len(saved['artifacts']) == 45", "len(saved['runtime_sources']) == 243 and len(saved['artifacts']) == 53"),
    ('installed-metal-sks-transport-2100s-20260928', 'installed-metal-panel-mode-2100s-20260928'),
    ("verification['generation'] == 54", "verification['generation'] == 55"),
    ("len(verification['artifacts_sha256']) == 45", "len(verification['artifacts_sha256']) == 53"),
    ("info['stage_generation'] == 54", "info['stage_generation'] == 55"),
    ("proxy.bootinfo()['stage_generation'] == 54", "proxy.bootinfo()['stage_generation'] == 55"),
]
for old, new in changes:
    expected = 2 if old == 'PANEL_MODE_GEN54_STOPPED_EVIDENCE_PRESERVED' else 1
    assert source.count(old) == expected, old
    source = source.replace(old, new)
anchor = 'for old, new in changes.items():'
assert source.count(anchor) == 1
extra = {"info['image_base'] == 0xb0800000": "info['image_base'] == 0xb0000000",
         'link == 0xb0000000': 'link == 0xb0800000'}
source = source.replace(anchor, 'changes.update(' + repr(extra) + ')\n' + anchor)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
