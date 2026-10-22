#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the shipped UNMAP_REGION descriptor callback and table count for
invalid (compressed) user leaves.

XNU's compressor leaves ARM_PTE_COMPRESSED (bit63, ALT bit62) in a user slot
through UNMAP_DISJOINT. UNMAP_REGION (endpoint 7, 0x270fd50c) tail-calls the
region iterator 0x270fc7e8 with callback 0x270fd244 and commit 0x270fd478:

    fd2c0  options & 0x500 -> panic
    fd2cc  next = template & 0xe000000000000000      ; template is 0 here
    fd2d4  old valid -> next |= 0x80, return 1         ; removal
    fd2fc  x9 = old >> 61; w8 = (x9 != 0) & options.bit0
    fd314  next = old & (w8 ? 0x80 : 0xe000000000000000); return w8

so an invalid leaf is never refused: option0 keeps it (returns 0, no CAS),
option1 clears a software-bit leaf (returns 1). The commit's CAS
(fd4a8) stores next & 0xe000000000000000 and 0x270ecb8c moves the table's
u16 +8 occupancy, which counts a leaf with any of bits63:61 (ecbe8/ecbf4).
XNU passes option1 exactly for PMAP_OPTIONS_REMOVE (kernelcache ba63360,
ubfx w8, w8, #8, #1) and counts removed markers from the prior PTEs (ba634b0).

No SPTM instruction is modified. PAC landing/return is modeled."""
import hashlib
import json
from pathlib import Path
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg
try:
    from unicorn.arm64_const import UC_CPU_ARM64_MAX
except ImportError:  # pragma: no cover
    UC_CPU_ARM64_MAX = None

SPTM_SHA = 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
BASE = 0xfffffff027000000
RAM = 0x1000000
CONTEXT, TABLE, SLOT = RAM+0x1000, RAM+0x2000, RAM+0x3000
PANICS = {0xfd348, 0xfd384, 0xfd3e4, 0xfd42c, 0xecee0, 0xecefc, 0xecea8, 0x102cc8, 0x102d08}


def main():
    im = runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    sha = hashlib.sha256(im.data).hexdigest()
    if sha != SPTM_SHA:
        raise ValueError('wrong SPTM image')
    handlers = runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['read_table'](
        im, 0xFFFFFFF027022350, 8)
    assert handlers[7][1:3] == ('SPTM_FUNCTIONID_UNMAP_REGION', 0xfffffff0270fd50c)
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    if UC_CPU_ARM64_MAX is not None:
        u.ctl_set_cpu_model(UC_CPU_ARM64_MAX)
    u.mem_map(BASE, 0x200000); u.mem_map(RAM, 0x10000)
    for _, va, _, off, size in im.segs:
        u.mem_write(va, im.data[off:off+size])
    # endpoint 7 installs these two callbacks and enters the iterator
    code = struct.unpack_from('<14I', u.mem_read(BASE+0xfd50c, 56))
    assert code[0] == 0xd503245f and code[-1] >> 26 == 0b000101  # bti c ... b iterator
    stop = {}

    def get(i): return u.reg_read(getattr(reg, f'UC_ARM64_REG_X{i}'))
    def put(i, v): u.reg_write(getattr(reg, f'UC_ARM64_REG_X{i}'), v)

    def hook(uc, a, size, _):
        off = a-BASE
        if off in (0xfd244, 0xfd478, 0xecb8c):
            uc.reg_write(reg.UC_ARM64_REG_PC, a+4)          # PACIBSP
        elif off in (0xfd344, 0xfd4c0, 0xece9c):
            stop['pc'] = off; uc.emu_stop()                  # RETAB / tail call / epilogue
        elif off in PANICS:
            stop['pc'] = off; uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, hook)

    def callback(old, options):
        stop.clear()
        for i in range(31): put(i, 0)
        u.mem_write(CONTEXT, struct.pack('<5Q', 0, TABLE, SLOT, 0, 0))   # no data frame
        u.mem_write(TABLE, struct.pack('<HBB', 0, 20, 3))
        u.reg_write(reg.UC_ARM64_REG_SP, RAM+0xf000)
        for i, v in {0: CONTEXT, 1: old, 2: 0, 3: options, 4: CONTEXT+0x18}.items(): put(i, v)
        u.emu_start(BASE+0xfd244, BASE+0x200000, count=200)
        assert stop.get('pc') == 0xfd344, (hex(old), options, stop)
        return get(0) & 0xffffffff, struct.unpack('<Q', u.mem_read(CONTEXT+0x18, 8))[0]

    def commit(old, next_):
        stop.clear()
        u.mem_write(SLOT, struct.pack('<Q', next_))
        for i, v in {0: CONTEXT, 1: old, 2: next_, 3: 0}.items(): put(i, v)
        u.emu_start(BASE+0xfd478, BASE+0x200000, count=100)
        assert stop.get('pc') == 0xfd4c0, stop
        return struct.unpack('<Q', u.mem_read(SLOT, 8))[0], get(2), get(3)

    def occupancy(old, new, count=5):
        stop.clear()
        u.mem_write(TABLE, struct.pack('<HBBHHH', 0, 20, 3, 0, 1, count))
        for i, v in {0: TABLE, 1: 0, 2: old, 3: new}.items(): put(i, v)
        u.reg_write(reg.UC_ARM64_REG_SP, RAM+0xf000)
        u.emu_start(BASE+0xecb8c, BASE+0x200000, count=500)
        assert stop.get('pc') == 0xece9c, (hex(old), hex(new), stop)
        return struct.unpack_from('<H', u.mem_read(TABLE+8, 2))[0]-count

    rows = []
    for old in (1 << 63, (1 << 63) | (1 << 62), 1 << 62, 1 << 61):
        for options in (0, 1):
            changed, next_ = callback(old, options)
            want = (1, 0) if options else (0, old)
            if (changed, next_) != want:
                raise ValueError(f'{old:x}/opt{options}: {(changed, hex(next_))}')
            final = old
            if changed:
                stored, _, _ = commit(old, next_)
                final = stored
            delta = occupancy(old, final)
            if delta != (-1 if final == 0 else 0):
                raise ValueError(f'{old:x}/opt{options}: occupancy delta {delta}')
            rows.append(dict(old=hex(old), options=options, changed=changed,
                             slot_after=hex(final), table_count_delta=delta))
    # UNMAP_DISJOINT's commit moves empty/valid -> marker the same way.
    assert occupancy(0, 1 << 63) == 1 and occupancy(0, 1 << 61) == 1
    print(json.dumps(dict(sptm_sha256=sha, rows=rows,
        boundary='UNMAP_REGION callback+commit CAS and 0x270ecb8c executed; iterator/TLBI not'),
        indent=1))


if __name__ == '__main__':
    main()
