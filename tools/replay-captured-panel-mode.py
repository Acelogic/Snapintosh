#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the real generation55 WindowServer scalar order through native code.

Failure inventory and qualification boundary:
docs/GEN55-PANEL-ARGUMENT-ORDER-20260928.md. No hardware access.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CORPSES = ROOT / 'build/installed-metal-panel-mode-2100s-20260928-windowserver-corpses-v2.json'
HISTORICAL = ROOT / 'build/panel-mode-candidate-replay-20260928-v2.json'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--qualification', type=Path, required=True)
    parser.add_argument('--expect', choices=['rejected', 'accepted'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    assert sha(CORPSES) == '7a4a4ee70ea95a06d8201308ebbf077bbc97a0a00bc3ba33966cb4ec117f0676'
    assert sha(HISTORICAL) == '0e0ce55772875bff52e096522cbe938c9e2af5d21549ea0dce162ed5862c35a4'
    historical = json.loads(HISTORICAL.read_text())
    replay_path = ROOT / 'tools/replay-panel-mode.py'
    assert sha(replay_path) == historical['inputs_sha256'][str(replay_path)]
    replay = module('panel_native_replay', replay_path)
    cache_api = module('mode_cache', ROOT / 'tools/dyld-cache.py')
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == '26A428'
    records = json.loads(CORPSES.read_text())['user_processes']['retained_processes']
    assert [p['pid'] for p in records] == [164, 220, 225, 227]
    observations = []
    with cache_api.Cache(Path('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld')) as cache:
        import capstone
        cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        call_bytes = cache.read(0x18b396bf0, 20)
        call = [(x.mnemonic, x.op_str) for x in cs.disasm(call_bytes, 0x18b396bf0)]
        assert call == [('ldr', 'x0, [x27]'), ('mov', 'x1, x24'), ('mov', 'x2, x25'),
                        ('bl', '#0x1900810f0'), ('mov', 'x26, x0')], call
        for process in records:
            thread = next(t for t in process['threads'] if t['tid'] == process['crashed_tid'])
            assert process['user_address_space']['admission'] == 'ownership-audit'
            frames = thread['user_frame_chain']['frames']
            for frame in frames[:8]:
                actual = bytes.fromhex(frame['return_site_hex'])
                assert cache.read(int(frame['return_site_va'], 16) - 0xe380000, len(actual)) == actual
            regs = thread['saved_user_state']['registers']
            observed = dict(pid=process['pid'], color=int(regs['24'], 16),
                timing=int(regs['25'], 16), rejected_return=regs['26'], matched_frame_sites=8)
            assert (observed['color'], observed['timing'], observed['rejected_return']) == (100, 1000, '0xe00002f0')
            observations.append(observed)
    qualification = json.loads(args.qualification.read_text())
    folder = args.qualification.parent
    obj = folder / 'obj/AdrenoDisplay.o'
    kext = folder / 'AdrenoX2.kext/Contents/MacOS/AdrenoX2'
    assert sha(obj) == qualification['new_object_sha256']
    assert sha(kext) == qualification['kext_sha256']
    dwarf = subprocess.check_output(['xcrun', 'dwarfdump', '--debug-info', str(obj)], text=True)
    layout = {}
    for name in historical['layout']:
        matches = re.findall(r'DW_AT_name\s+\("' + name + r'"\)[\s\S]*?DW_AT_data_member_location\s+\((0x[0-9a-f]+)\)', dwarf)
        assert len(matches) == 1
        layout[name] = int(matches[0], 16)
    family, driver = replay.Image(replay.FAMILY, 0x10000000), replay.Image(kext, 0x20000000)
    handler = family.read(family.symbols[replay.HANDLER], 68)
    assert replay.KERNEL.read_bytes().count(handler) == 1
    cases = []
    requests = [(100, 1000)] if args.expect == 'rejected' else [(100, 1000), (102, 1000), (103, 1000), (101, 1000), (100, 999), (1000, 100)]
    for color, timing in requests:
        # Legacy helper parameter names were reversed. These values are the
        # physical scalar slots, now bound to the actual native caller above.
        row = replay.replay(family, driver, color, timing, layout)
        row.pop('timing'); row.pop('color')
        row.update(color=color, timing=timing, scalar_inputs=[color, timing])
        valid = timing == 1000 and color in (100, 102, 103)
        accepted = args.expect == 'accepted' and valid
        assert row['result'] == ('0x0' if accepted else '0xe00002f0'), row
        assert row['geometry'] == ((2880, 1800) if accepted else (0, 0))
        assert row['metadata'] == (dict(DisplayWidth=dict(value=2880, bits=32),
            DisplayHeight=dict(value=1800, bits=32), DPTimingModeId=dict(value=1000, bits=64)) if accepted else {})
        cases.append(row)
    inputs = [CORPSES, HISTORICAL, replay_path, ROOT/'tools/dyld-cache.py', replay.FAMILY,
              args.qualification, obj, kext, Path(__file__)]
    result = dict(status='CAPTURED_PANEL_REQUEST_' + args.expect.upper(), hardware_access=False,
        observations=observations, native_call_site_hex=call_bytes.hex(), native_handler_hex=handler.hex(),
        cases=cases, inputs_sha256={str(p): sha(p) for p in inputs},
        boundary=['Actual stopped WindowServer arguments and frame code witnesses',
            'Native selector and compiled driver execute with gate/property fixtures',
            'User-space RPC, PAC and concurrency are not emulated',
            'Not a hardware GUI or presentation qualification'])
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], cases=len(cases), output=str(args.output), sha256=sha(args.output))))


if __name__ == '__main__':
    main()
