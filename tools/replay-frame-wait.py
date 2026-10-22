#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute native wait branches against the retained generation51 display object.

Failure inventory and qualification boundary: docs/FRAME-WAIT-SEMANTICS-20260928.md.
No A16 connection, source change, native wake fabrication or surface release.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import struct
import sys

import capstone
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

ROOT = Path(__file__).resolve().parents[1]
FAMILY = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Extensions/IOMobileGraphicsFamily.kext/Contents/MacOS/IOMobileGraphicsFamily')
CAPTURE = ROOT / 'build/installed-metal-timesync-3600s-20260927-display-swap-registry-v2.json'
CONSOLE = ROOT / 'build/installed-metal-timesync-3600s-20260927-console-tail.bin'
PINS = {
    ROOT / 'tools/replay-panel-mode.py': '7e54b0a321d51f6900413021220d8115710287672cc8d21238db6398876e4227',
    ROOT / 'tools/dyld-cache.py': 'e4c9ae7ad501e8b9ccf8fc7a90e052db7ceaf8c923074cc661f462b837d924a7',
    CAPTURE: 'f5a4dded33282434b8e0d23180126fdf3a822ee562ae53840a1154bfc82800f0',
    CONSOLE: '10fdad627fa7c8576ac82795575eefc8543c79f94f384f4cc7fea8bfcb3638b0',
    FAMILY: 'a154195ea91a82b03bb3d50d82bd219a5e98b676dd0505ff221ed3f3d82276f5',
}
WAIT = '__ZN25IOMobileFramebufferLegacy15swap_wait_gatedEP29IOMobileFramebufferUserClientjjj'
OBJ, GATE, DEBUG, VTABLE = 0x40000000, 0x40005000, 0x40006000, 0x40007000
STACK, RETURN = 0x50000000, 0x60000000


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def replay(family, raw, swap_id, options):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    family.load(uc)
    uc.mem_map(OBJ, 0x10000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(RETURN, 4096)
    uc.mem_write(OBJ, raw)
    q = lambda address, value: uc.mem_write(address, struct.pack('<Q', value))
    # Only these pointer imports differ from the retained object. No queue,
    # completion ID, power-state or timer field is rewritten.
    q(OBJ + 0x1b48, GATE)
    q(GATE, VTABLE)
    q(VTABLE + 0x210, RETURN + 0x100)
    q(0x59d20, DEBUG)  # Native kernel-debug flags import; tracing disabled.
    uc.mem_write(DEBUG, bytes(4))
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0xf000)
    uc.reg_write(UC_ARM64_REG_X30, RETURN)
    for register, value in [(UC_ARM64_REG_X0, OBJ), (UC_ARM64_REG_X1, 0),
                            (UC_ARM64_REG_X2, swap_id), (UC_ARM64_REG_X3, options),
                            (UC_ARM64_REG_X4, 10000)]:
        uc.reg_write(register, value)
    result = dict(swap_id=swap_id, options=options, timeout_ms=10000,
                  instructions=[], deadline_fixtures=[], pac_omissions=[], terminal=None)
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    start = family.symbols[WAIT]
    end = min(v for v in family.symbols.values() if v > start)

    def hook(engine, address, size, _):
        if address == RETURN:
            result.update(terminal='RETURN', return_value=hex(engine.reg_read(UC_ARM64_REG_X0) & 0xffffffff))
            engine.emu_stop()
            return
        if address == 0x2fc20:
            count = engine.reg_read(UC_ARM64_REG_X0)
            scale = engine.reg_read(UC_ARM64_REG_X1)
            output = engine.reg_read(UC_ARM64_REG_X2)
            result['deadline_fixtures'].append(dict(count=count, scale=scale, output=hex(output)))
            assert scale == 1000000 and count in (10000, 5000)
            assert STACK <= output <= STACK + 0xfff8
            q(output, 0x1000000000 + count * scale)
            engine.reg_write(UC_ARM64_REG_PC, engine.reg_read(UC_ARM64_REG_X30))
            return
        assert start <= address < end, f'unexpected native execution {address:#x}'
        instruction = next(decoder.disasm(bytes(engine.mem_read(address, size)), address))
        result['instructions'].append(dict(address=hex(address), mnemonic=instruction.mnemonic, operands=instruction.op_str))
        if address == 0x2208c:
            assert instruction.mnemonic == 'blraa'
            assert engine.reg_read(UC_ARM64_REG_X0) == GATE
            assert engine.reg_read(UC_ARM64_REG_X1) == OBJ + 0x1a48
            result.update(terminal='COMMAND_SLEEP_REQUEST', sleep_event='display+0x1a48', wake_fabricated=False)
            engine.emu_stop()
        elif instruction.mnemonic in ('pacibsp', 'autibsp', 'autda'):
            result['pac_omissions'].append(hex(address))
            engine.reg_write(UC_ARM64_REG_PC, address + size)
        elif instruction.mnemonic == 'xpacd':
            # The only such path uses the deliberately unsigned fixture vtable.
            assert instruction.op_str == 'x17'
            engine.reg_write(UC_ARM64_REG_PC, address + size)
        elif instruction.mnemonic == 'retab':
            result['pac_omissions'].append(hex(address))
            engine.reg_write(UC_ARM64_REG_PC, engine.reg_read(UC_ARM64_REG_X30))

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(start, RETURN + 0x1000, count=10000)
    assert result['terminal'], 'native instruction budget exhausted'
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    assert not args.output.exists(), 'preserve existing evidence'
    for path, digest in PINS.items():
        assert sha(path) == digest, path
    native = module('frame_wait_native_image', ROOT / 'tools/replay-panel-mode.py')
    family = native.Image(FAMILY, 0)
    capture = json.loads(CAPTURE.read_text())
    entries = [x for x in capture['linked_auxkc']['registry_entries'] if 'display_swap_snapshot' in x]
    assert len(entries) == 1 and entries[0]['class_name'] == 'AdrenoDisplay'
    snapshot = entries[0]['display_swap_snapshot']
    raw = bytes.fromhex(snapshot['raw_hex'])
    assert len(raw) == 8168
    assert struct.unpack_from('<Q', raw, 0x1a40)[0] == 0
    assert struct.unpack_from('<Q', raw, 0x1a48)[0] == 0
    assert struct.unpack_from('<I', raw, 0x1bfc)[0] == 1
    assert struct.unpack_from('<I', raw, 0x1c20)[0] == 0
    assert snapshot['presents'] == 1 and not snapshot['frame_timer_armed'] and not snapshot['swap_presented']
    console = CONSOLE.read_bytes().decode('utf-8', 'replace')
    assert 'swapId = 1, options = 0x0' in console
    assert "CommandWake didn't happen even after 5 seconds" in console
    cases = [replay(family, raw, swap, options) for swap, options in [(1, 0), (1, 1), (2, 0), (2, 1)]]
    assert cases[0]['terminal'] == 'COMMAND_SLEEP_REQUEST'
    assert all(x['terminal'] == 'RETURN' and x['return_value'] == '0x0' for x in cases[1:])
    cache_module = module('frame_wait_cache', ROOT / 'tools/dyld-cache.py')
    cache = cache_module.Cache('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld')
    try:
        name = next(x for x in cache.images if x.endswith('/IOMobileFramebuffer'))
        assert cache.image(name)['uuid'] == 'b1c5bb2ddb25332bad82cf1ec6170e8b'
        symbols = cache.symbols(name)
        decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        witnesses = []
        for symbol in ['_IOMobileFramebufferSwapWaitWithTimeout', '_kern_SwapWaitWithTimeout']:
            address = next(a for a, n, _, _ in symbols if n == symbol)
            limit = min(a for a, _, _, _ in symbols if a > address)
            code = cache.read(address, limit - address)
            witnesses.append(dict(symbol=symbol, address=hex(address), bytes_hex=code.hex(),
                sha256=hashlib.sha256(code).hexdigest(), instructions=[dict(address=hex(i.address), mnemonic=i.mnemonic, operands=i.op_str) for i in decoder.disasm(code,address)]))
        timeout_multiplier = struct.unpack('<d', cache.read(0x18ff13bc0, 8))[0]
        assert timeout_multiplier == 1000.0
    finally:
        cache.close()
    result = dict(schema='snapintosh-native-frame-wait/1', status='CAPTURED_STATE_WAIT_BRANCHES_VERIFIED',
        source_sha256=sha(Path(__file__)), inputs_sha256={str(k):v for k,v in PINS.items()},
        retained_state={k:v for k,v in snapshot.items() if k not in ('raw_hex','objects','native_work_loop')},
        cases=cases, native_user_witnesses=witnesses, seconds_to_scalar_multiplier=timeout_multiplier,
        fixtures=['Relocated object address; command gate pointer and unsigned vtable', 'Kernel-debug flags disabled',
                  'Deadline conversion returns deterministic future timestamps; no elapsed time simulated',
                  'PAC omitted; command sleep is intercepted before invocation without a fabricated wake'],
        conclusion='With an empty queue and last displayed ID1, options0 waits on ID1; options1 returns success. A different ID returns success for either option.',
        boundary='Offline native branch evidence for a later retained state. Does not establish the exact earlier wait timing, successful physical retirement, or a functional GUI.')
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status=result['status'], output=str(args.output), cases=[{k:v for k,v in c.items() if k in ('swap_id','options','terminal','return_value')} for c in cases])))


if __name__ == '__main__':
    main()
