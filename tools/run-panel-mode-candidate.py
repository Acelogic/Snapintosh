#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Boot the qualified panel-mode change with the unchanged SKS monitor/SSD image.

--check-inputs is offline. --prepare and --boot require graceful generation54
retirement. The existing 2100-second watchdog remains; never interrupt P_CALL.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
BASE = ROOT / 'tools/run-sks-transport-candidate.py'
assert sha(BASE) == '52fe215a9a4779ebc50f01ecaafb4a4210d2b506b09e6ee10a5fbb089a5cc6b8'
DISPLAY = ROOT / 'build/panel-mode-candidate-20260928-v2/qualification.json'
DISPLAY_SHA = '6e936cabf4197912dbc533939b21a3db439f6bd88a5dd37f9e2b2d7b52dc8b1f'
REPLAY = ROOT / 'build/panel-mode-candidate-replay-20260928-v2.json'
REPLAY_SHA = '0e0ce55772875bff52e096522cbe938c9e2af5d21549ea0dce162ed5862c35a4'
COLLECTION = DISPLAY.parent / 'AdrenoX2.kc'
COLLECTION_SHA = '59e6012865e4eacd835d86b139d5c3032e46d35592c9d1af4726d3209390fcf2'

source = BASE.read_text()
changes = {
    "PREFIX='installed-metal-sks-transport-2100s-20260928'": "PREFIX='installed-metal-panel-mode-2100s-20260928'",
    "PREDECESSOR='installed-metal-sks-2100s-20260928'": "PREDECESSOR='installed-metal-sks-transport-2100s-20260928'",
    "record['status']=='GENERATION54_IDLE'": "record['status']=='GENERATION55_IDLE'",
    "record['after']['stage_generation']==54": "record['after']['stage_generation']==55",
    "info['stage_generation']==54": "info['stage_generation']==55",
    "info['image_base']==0xb0800000": "info['image_base']==0xb0000000",
    "record['preservation_sha256']=='14eec4b24dc939a481fc389cc1d9a2bb9e1ea8484076aa9fda217d2df594bce6'":
        "record['preservation_sha256']=='08f206283f838f704010829e2bb86208e338aaca6ac167752ddf4b2e0f75ded6'",
    "comparison='Generation54: correct native SKS query command/sequence decoding after the reproduced generation53 startup panic. Same installed image and GPU/clock baseline; verify SKS startup, HID cleanup and WindowServer.'":
        "comparison='Generation55: fix valid panel modes falling through to unsupported Legacy setter. Only AdrenoDisplay.o replaced; unchanged SKS monitor, other GPU objects and installed SSD image. Verify WindowServer survival and real display presentation.'",
    '    def save():path(\'-launch.json\').write_text':
        "    record['display_candidate'] = display_binding\n"
        "    def save():path('-launch.json').write_text",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
scope = dict(__file__=__file__, __name__='panel_mode_launcher')
exec(compile(source, str(BASE), 'exec'), scope)
validate_baseline = scope['validate']


def validate():
    candidate, old, args, settings = validate_baseline()
    assert sha(DISPLAY) == DISPLAY_SHA and sha(REPLAY) == REPLAY_SHA
    display = json.loads(DISPLAY.read_text())
    replay = json.loads(REPLAY.read_text())
    assert display['status'] == 'PANEL_MODE_KEXT_BUILT_NOT_INSTALLED'
    assert display['replaced_objects'] == ['AdrenoDisplay.o']
    assert replay['status'] == 'CANDIDATE_PANEL_MODE_NATIVE_PATH_PASSED' and len(replay['cases']) == 12
    assert not replay['hardware_access']
    for name, digest in {**display['sources_sha256'], **replay['inputs_sha256']}.items():
        assert sha(name) == digest, name
    assert sha(COLLECTION) == COLLECTION_SHA
    import auxkc
    firmware = Path(args[args.index('--firmware-dir') + 1])
    _, admission = auxkc.load(COLLECTION, sha(firmware / 'kernelcache.release.mac17p'))
    assert admission['sha256'] == COLLECTION_SHA and admission['bundles'] == ['org.snapintosh.driver.AdrenoX2']
    old = dict(old, auxkc=str(COLLECTION), auxkc_sha256=COLLECTION_SHA, kext_sha256=display['kext_sha256'])
    args = list(args)
    args[args.index('--auxkc') + 1] = str(COLLECTION)
    candidate = dict(candidate, inputs_sha256={**candidate['inputs_sha256'],
        **display['sources_sha256'], str(BASE): sha(BASE), str(Path(__file__)): sha(Path(__file__))})
    scope['display_binding'] = dict(qualification=str(DISPLAY), qualification_sha256=DISPLAY_SHA,
        replay=str(REPLAY), replay_sha256=REPLAY_SHA, collection_sha256=COLLECTION_SHA,
        replaced_objects=display['replaced_objects'], ssd_image_replaced=False)
    return candidate, old, args, settings


scope['validate'] = validate
if __name__ == '__main__':
    raise SystemExit(scope['main']())
