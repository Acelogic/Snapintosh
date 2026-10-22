#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare pinned SIGN/AUTH_USER_POINTER control flow against C-model vectors.

XPAC, PAC and system registers are modeled; this is not hardware crypto proof.
"""
from pathlib import Path
import hashlib
import json
import runpy
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg

BASE = 0xfffffff027000000
RAM = 0x80000000


def main():
    im = runpy.run_path(str(ROOT / 'tools/sptm-dispatch.py'))['Image'](
        ROOT / 'downloads/extracted/j700ap/sptm.t8140.release')
    sha = hashlib.sha256(im.data).hexdigest()
    assert sha == 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
    vectors = subprocess.check_output([str(ROOT / 'build/test-pauth-pointer'),
                                       '--replay'], text=True).splitlines()
    cases = 0
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(BASE, 0x200000)
    u.mem_map(RAM, 0x10000)
    for _, va, _, off, size in im.segs:
        u.mem_write(va, im.data[off:off+size])
    state = {}

    def get(i):
        return u.reg_read(getattr(reg, 'UC_ARM64_REG_X'+str(i)))

    def put(i, value):
        u.reg_write(getattr(reg, 'UC_ARM64_REG_X'+str(i)), value)

    def advance(a):
        u.reg_write(reg.UC_ARM64_REG_PC, a+4)

    def hook(u, a, size, _):
        off = a-BASE
        if off in (0x101a00, 0x101d64):
            state['rejected'] = True
            u.emu_stop()
        elif off in (0x1019a0, 0x101cf0):
            put(8, state['daif']); advance(a)
        elif off in (0x1019b0, 0x101d00):
            state['daif'] |= 0x1c0; advance(a)
        elif off in (0x1019f8, 0x101d50):
            state['daif'] = get(8); advance(a)
        elif off in (0x1019b4, 0x1019e0, 0x101d04, 0x101d38):
            put(11 if off == 0x101d38 else 9, state['apctl']); advance(a)
        elif off in (0x1019bc, 0x1019e8, 0x101d0c, 0x101d40):
            state['apctl'] = get(11 if off == 0x101d40 else 9); advance(a)
        elif off in (0x101d1c, 0x101d2c):
            raw = get(9) & ((1 << 47)-1)
            if state['tagged']:
                raw |= get(9) & 0xff00000000000000
            put(9, raw); advance(a)
        elif off in (0x1019d0, 0x1019d8, 0x101d24, 0x101d34):
            assert state['apctl'] == 0x13
            target, modreg = (10, 2) if state['auth'] else (17, 16)
            ptr, modifier = get(target), get(modreg)
            key = get(1) & 0xffffffff
            h = ptr ^ (ptr >> 32) ^ modifier ^ (modifier >> 32) ^ (key * 0x9e37)
            signed = ptr | ((h & 255) << 47)
            if not state['tagged']:
                signed |= ((h >> 8) & 255) << 56
            put(target, signed); state['signs'] += 1; advance(a)

    u.hook_add(UC_HOOK_CODE, hook)
    for index, line in enumerate(vectors):
        parts = line.split()
        pointer, key, modifier = (int(v, 16) for v in parts[:3])
        auth, tbi, tbid, result = (int(v) for v in parts[3:7])
        expected = int(parts[7], 16)
        initial_daif = (0, 0x1c0, 0x3c0, 0x80)[index % 4]
        state.clear()
        state.update(auth=auth, tagged=tbi and (key & 0xffffffff == 2 or not tbid),
                     daif=initial_daif, apctl=0x11, signs=0, rejected=False)
        for i in range(31):
            put(i, 0)
        put(0, pointer); put(1, key); put(2, modifier); put(30, RAM)
        u.reg_write(reg.UC_ARM64_REG_SP, RAM+0x8000)
        u.emu_start(BASE+(0x101ce4 if auth else 0x101994), RAM, count=100)
        assert state['rejected'] == bool(result), (index, line, state)
        assert state['apctl'] == 0x11 and state['daif'] == initial_daif
        assert state['signs'] == (0 if result else 1)
        if not result:
            assert get(0) == expected, (index, line, hex(get(0)))
        cases += 1
    print(json.dumps(dict(sptm_sha256=sha, cases=cases,
        boundary='pinned SIGN/AUTH instructions with modeled sysregs and PAC/XPAC')))


if __name__ == '__main__':
    main()
