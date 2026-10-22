#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay pinned disjoint selection and unmap descriptor callbacks.

Executes the shipped filter and descriptor instructions. PAC call/return is
modeled; stops before CAS and reference/TLBI work, covered by other tests.
"""
from pathlib import Path
import hashlib
import json
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg

BASE = 0xfffffff027000000
RAM = 0x1000000
CONTEXT, DATA, TABLE, SCRATCH = (RAM+0x1000, RAM+0x2000, RAM+0x3000, RAM+0x4000)
TARGET = 0x90014000


def main():
    im = runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    sha = hashlib.sha256(im.data).hexdigest()
    assert sha == 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(BASE, 0x200000); u.mem_map(RAM, 0x10000)
    for _, va, _, off, size in im.segs:
        u.mem_write(va, im.data[off:off+size])
    state = {}

    def get(i): return u.reg_read(getattr(reg, 'UC_ARM64_REG_X'+str(i)))
    def put(i, v): u.reg_write(getattr(reg, 'UC_ARM64_REG_X'+str(i)), v)

    def hook(u, a, size, _):
        off = a-BASE
        if off in (0xfd244, 0xfd478):
            u.reg_write(reg.UC_ARM64_REG_PC, a+4)  # PACIBSP
        elif off == 0xfde24:
            assert get(24) == BASE+0xfd244
            put(30, a+4); u.reg_write(reg.UC_ARM64_REG_PC, get(24))
        elif off == 0xfd344:
            u.reg_write(reg.UC_ARM64_REG_PC, get(30))  # RETAB
        elif off in (0xfdd50, 0xfde28, 0xfd4a8, 0xfd348, 0xfd384, 0xfd3e4, 0xfd42c):
            state['stop'] = off; u.emu_stop()

    u.hook_add(UC_HOOK_CODE, hook)
    leaves = [0, 0x80, 1 << 61, 1 << 62, 1 << 63]
    for ro in (0, 0x80):
        for af in (0, 0x400):
            for wired in (0, 1 << 58):
                for history in (0, 1 << 59):
                    pte = TARGET | 0x0060000000000a43 | ro | af | wired | history
                    leaves += [pte, pte+0x4000]
    cases = 0
    for old in leaves:
        for top in range(8):
            requested = (top << 61) | 0x12345678
            state.clear()
            for i in range(31): put(i, 0)
            u.mem_write(CONTEXT, struct.pack('<5Q', DATA, TABLE, SCRATCH+0x800, 0, 0))
            u.mem_write(DATA, struct.pack('<HBB', 2, 11, 0))
            u.mem_write(TABLE, struct.pack('<HBB', 2, 20, 0))
            u.mem_write(SCRATCH, struct.pack('<Q', old))
            u.reg_write(reg.UC_ARM64_REG_SP, RAM+0xf000)
            for i, v in {1: old, 19: 0, 20: TARGET, 21: SCRATCH, 23: 0,
                         24: BASE+0xfd244, 26: requested, 27: CONTEXT}.items():
                put(i, v)
            u.emu_start(BASE+0xfddec, BASE+0xfe000, count=200)
            valid = old & 3 == 3
            matching = valid and old & 0x0000ffffffffc000 == TARGET
            selected = not valid or matching
            assert state.get('stop') == (0xfde28 if selected else 0xfdd50), (hex(old), state)
            if matching:
                transient = struct.unpack('<Q', u.mem_read(CONTEXT+24, 8))[0]
                assert transient == (requested & 0xe000000000000000) | 0x80
                assert get(0) == 1 and u.mem_read(CONTEXT+32, 1) == b'\x03'
                put(0, CONTEXT); put(1, old); put(2, transient)
                u.emu_start(BASE+0xfd478, BASE+0xfe000, count=100)
                assert state.get('stop') == 0xfd4a8
                assert get(3) == requested & 0xe000000000000000
            else:
                if not valid:
                    # The first pass visits invalid descriptors too, but its
                    # callback returns0 and the second pass cannot release a
                    # non-valid mapping. Scratch preserves the original bits.
                    assert get(0) == 0
                    candidate = struct.unpack('<Q', u.mem_read(CONTEXT+24, 8))[0]
                    assert candidate == old & 0xe000000000000000
                assert struct.unpack('<Q', u.mem_read(SCRATCH, 8))[0] == old
            cases += 1
    print(json.dumps(dict(sptm_sha256=sha, cases=cases,
        boundary='pinned selection and descriptor callbacks; CAS, refs and TLBI not executed')))


if __name__ == '__main__': main()
