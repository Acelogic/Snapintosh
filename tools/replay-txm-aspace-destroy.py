#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay TXM36's destructor, tree removal and allocator returns.

Registry lookup, primitive uncontended locks and PAC return mechanics are
modeled. The shipped destructor, reference decrement, tree removal, object
invalidation and free-list insertion execute. No SPTM hierarchy is mapped.
"""
import hashlib
from collections import deque
import json
from pathlib import Path
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg


def main():
    raw = (ROOT/'downloads/extracted/j700ap/txm.macosx.release').read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == 'b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246'
    segments = runpy.run_path(str(ROOT/'tools/kc-disas.py'))['segments'](raw)
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.ctl_set_cpu_model(reg.UC_CPU_ARM64_MAX)
    u.mem_map(0xfffffff017000000, 0x200000)
    for _, va, _, off, size in segments:
        u.mem_write(va, raw[off:off+size])
    u.mem_map(0x1000000, 0x200000)
    obj, node, parent = 0x1010000, 0x1010080, 0x1020000
    registry, stack, stop = 0x1040000, 0x11e0000, 0x11f0000
    get = lambda n: u.reg_read(getattr(reg, f'UC_ARM64_REG_X{n}'))
    put = lambda n, v: u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), v)
    readq = lambda a: struct.unpack('<Q', u.mem_read(a, 8))[0]
    writeq = lambda a, v: u.mem_write(a, struct.pack('<Q', v))
    modeled = dict(pac=0, registry=0, lock=0, unlock=0)
    history = deque(maxlen=64)

    def hook(uc, address, size, user):
        history.append(hex(address))
        if 0xfffffff01703d600 <= address < 0xfffffff01703da00:
            raise ValueError(f'native diagnostic {address:x}, caller {get(30):x}, x0 {get(0):x}; {list(history)}')
        word, = struct.unpack('<I', uc.mem_read(address, 4))
        if (word in (0xd503237f, 0xd50323ff) and address not in
                (0xfffffff017036078, 0xfffffff01703b03c, 0xfffffff01703b12c)):
            modeled['pac'] += 1
            uc.reg_write(reg.UC_ARM64_REG_PC, address+4)
        elif word == 0xd65f0fff:
            modeled['pac'] += 1
            uc.reg_write(reg.UC_ARM64_REG_PC, get(30))
        elif address == 0xfffffff017036078:
            packed, = struct.unpack('<I', uc.mem_read(get(0), 4))
            assert packed & 0xffff == 12 and packed >> 16 in (0, 1)
            assert get(1) == 0xffff
            modeled['registry'] += 1
            put(0, registry)
            uc.reg_write(reg.UC_ARM64_REG_PC, get(30))
        elif address == 0xfffffff01703b03c:
            assert get(0) in (obj, node, parent)
            assert get(1) in (0, 1) and get(2) == 0
            modeled['lock'] += 1
            uc.mem_write(get(0)+0x10, b'\xff')
            put(0, 0)
            uc.reg_write(reg.UC_ARM64_REG_PC, get(30))
        elif address == 0xfffffff01703b12c:
            assert get(0) == parent and get(1) == 0
            modeled['unlock'] += 1
            uc.mem_write(parent+0x10, b'\0')
            uc.reg_write(reg.UC_ARM64_REG_PC, get(30))
        elif address in (0xfffffff01703d818, 0xfffffff01703d99c):
            raise ValueError(f'native panic {get(0):x} at caller {get(30):x}')

    u.hook_add(UC_HOOK_CODE, hook)
    u.reg_write(reg.UC_ARM64_REG_CPACR_EL1, 3 << 20)
    cases = 0
    # Counts past one byte: the parent's +0x68 is the u32 the destructor
    # decrements with ldaddal w (256 -> 255 borrows from byte 0x69).
    for shared, refs in ([(0, 0), (1, 0)] + [(0, n) for n in range(1, 64)] +
                         [(0, n) for n in (255, 256, 257, 511, 512, 0x10000)]):
        u.mem_write(obj, bytes(0x100))
        u.mem_write(parent, bytes(0x100))
        # Reset only the allocator's mutable globals between invocations.
        u.mem_write(0xfffffff0170903b0, bytes(0x200))
        u.mem_write(obj+0x11, b'\1')
        u.mem_write(node+0x11, b'\1')
        u.mem_write(obj+0x22, struct.pack('<HH', 12, shared))
        writeq(registry+12*8, obj)
        if refs:
            for off in (0x28, 0x48):
                writeq(obj+off, node)
            u.mem_write(node+0x12, b'\1')
            writeq(node+0x18, parent)
            u.mem_write(parent+0x68, struct.pack('<I', refs))
        else:
            writeq(obj+0x38, node)
        u.reg_write(reg.UC_ARM64_REG_SP, stack)
        put(0, obj)
        put(30, stop)
        try:
            u.emu_start(0xfffffff017036370, stop, count=10000)
        except Exception as error:
            raise ValueError(f'replay case {shared}/{refs} at {u.reg_read(reg.UC_ARM64_REG_PC):x}: {error}; {list(history)}') from error
        assert u.reg_read(reg.UC_ARM64_REG_PC) == stop and get(0) == 0
        assert readq(registry+12*8) == (1 << 64)-3
        assert bytes(u.mem_read(obj+0x10, 0x60)) == bytes(0x60)
        assert bytes(u.mem_read(node+0x10, 0x40)) == bytes(0x40)
        remaining, = struct.unpack('<I', u.mem_read(parent+0x68, 4))
        assert remaining == max(0, refs-1)
        cases += 1
    print(json.dumps(dict(txm_sha256=digest, cases=cases, modeled=modeled,
        boundary='shipped destructor/tree/free-list code; primitive locks, registry lookup and PAC modeled; no source page tables mapped')))


if __name__ == '__main__':
    main()
