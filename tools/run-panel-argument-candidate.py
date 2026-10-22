#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the captured color-first mode correction with a3600-second watchdog.

--check-inputs is offline. --prepare/--boot require retired generation55 and
idle generation56. Only the display object and watchdog differ from generation55.
The unchanged SSD image, GPU objects, SKS monitor and existing guards remain.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/run-panel-mode-candidate.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == 'f13083ce59f293831a5edcfdefdb31adf32cf431981e50cad74f98cf6253f48a'
source = base.read_text()
changes = {
    'panel-mode-candidate-20260928-v2/qualification.json': 'panel-mode-argument-candidate-20260928-v1/qualification.json',
    '6e936cabf4197912dbc533939b21a3db439f6bd88a5dd37f9e2b2d7b52dc8b1f': 'b346eaa20d29c4fb3f2263f139c4d95391431c517b5a39841bf18016ef0b1c4c',
    'panel-mode-candidate-replay-20260928-v2.json': 'panel-mode-observed-correction-20260928-v1.json',
    '0e0ce55772875bff52e096522cbe938c9e2af5d21549ea0dce162ed5862c35a4': '2e2a7eccc2202ed21f113be0ecb53fa6d3bb1060b97c0653f25fc44faca60b83',
    '59e6012865e4eacd835d86b139d5c3032e46d35592c9d1af4726d3209390fcf2': '6d56928d12c5f55e831da2178be8c4552b25967e0a69ccd8fca769c74b137241',
    'installed-metal-panel-mode-2100s-20260928': 'installed-metal-panel-arguments-3600s-20260928',
    '"PREDECESSOR=\'installed-metal-sks-transport-2100s-20260928\'"': '"PREDECESSOR=\'installed-metal-panel-mode-2100s-20260928\'"',
    'GENERATION55_IDLE': 'GENERATION56_IDLE',
    "record['after']['stage_generation']==55": "record['after']['stage_generation']==56",
    "info['stage_generation']==55": "info['stage_generation']==56",
    "info['image_base']==0xb0000000": "info['image_base']==0xb0800000",
    '08f206283f838f704010829e2bb86208e338aaca6ac167752ddf4b2e0f75ded6': '6d51fbbf72cf24fce5fbe7a09696b8c974bfb4e5497aacf7b21233b4a2c490ba',
    'Generation55: fix valid panel modes falling through to unsupported Legacy setter. Only AdrenoDisplay.o replaced; unchanged SKS monitor, other GPU objects and installed SSD image. Verify WindowServer survival and real display presentation.':
        'Generation56: use the captured native color-first, timing-second mode request. Only AdrenoDisplay.o replaced; unchanged SKS monitor, other GPU objects and installed SSD image. Allow3600seconds to observe WindowServer, Metal loading and real presentation.',
    "replay['status'] == 'CANDIDATE_PANEL_MODE_NATIVE_PATH_PASSED' and len(replay['cases']) == 12":
        "replay['status'] == 'CAPTURED_PANEL_REQUEST_ACCEPTED' and len(replay['cases']) == 6",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
anchor = 'source = BASE.read_text()'
assert source.count(anchor) == 1
source = source.replace(anchor, anchor + "\nassert source.count(\"SNAP_WATCHDOG='2100'\") == 1\nsource = source.replace(\"SNAP_WATCHDOG='2100'\", \"SNAP_WATCHDOG='3600'\")")
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
