#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay shipped MAP_PAGE on a kernel-root leaf that maps a different page.

tools/replay-map-page-status.py covers user and shared roots (types 18/19)
and stops at the status join. This one covers the kernel root and runs to
the handler's return, so the store, the reference helpers and the per-CPU
output are all observed.

Root type is the byte at root metadata +2 (x23, loaded at 270f90c4).
SPTM_KERNEL_ROOT_TABLE is type 8 (name table 2701e6b8+8*8), and a kernel
root skips both root-specific leaf checks:

    270f90f0  cmp w23,#8 ; b.eq 270f910c
    270f910c  cmp w23,#8 ; b.eq 270f9120     ; straight to the old-leaf load
    270f9124  ldr x26,[x9]                   ; old descriptor
    270f92e8  and x17,x21,#0xfffffffff000    ; old PA (x21 = old)
    270f92ec  cmp x17,x25                    ; x25 = requested PA
    270f92f0  b.ne 270f95dc                  ; different page ...
    270f95dc  mov w0,#6                      ; ... CONFLICT, no CAS
    270f9530  stp x21,x9,[x8]                ; unless options bit0: old PTE, slot ptr

The only root-type test between the load and the conflict branch is
`cmp w23,#0x21` (XNU_STAGE2_ROOT_TABLE), taken after 92f0. So the kernel
root answers 6 without writing, exactly as a user root does.

Started at 270f9120 (after table walk and data-type policy, which a kernel
request reaching the old-leaf load has already passed). The three helpers
after the CAS (TLBI 270dfea4, table unlock 270ebf8c, reference move
270ecb8c) are stubbed and counted; the per-CPU register reads at 270f9518
are replaced by the output-area pointer. No SPTM instruction is modified.
"""
import hashlib
import itertools
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
TLBI, UNLOCK, REFMOVE = 0xdfea4, 0xebf8c, 0xecb8c
BARRIERS = {0xf95cc}
PERCPU_READ, PERCPU_LOAD = 0xf9518, 0xf9528
RETURN_AT = 0xf9534
REJECT_AT = 0xf9374
FLUSH_PENDING = 0xf9384
KERNEL_ROOT, USER_ROOT, SPTM_PAGE_TABLE = 8, 18, 9
WITNESS = ((0xf90f0, 0x710022ff), (0xf90f4, 0x540000c0), (0xf910c, 0x710022ff), (0xf9110, 0x54000080),
           (0xf9124, 0xf940013a), (0xf92e8, 0x92748eb1), (0xf92ec, 0xeb19023f),
           (0xf92f0, 0x54001761), (0xf92f4, 0x710086ff), (0xf95dc, 0x528000c0),
           (0xf9514, 0x3700011a), (0xf9530, 0xa9002515))

ROOTM, TABLEM, DATAM = 0x1010000, 0x1011000, 0x1012000
CELL, PERCPU, OUT = 0x1030000, 0x1040000, 0x1041000
FP, SP = 0x10800c0, 0x1080000


def machine(im):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    if UC_CPU_ARM64_MAX is not None:
        u.ctl_set_cpu_model(UC_CPU_ARM64_MAX)
    u.mem_map(BASE, 0x200000)
    for _, va, _, offset, size in im.segs:
        u.mem_write(va, im.data[offset:offset+size])
    u.mem_map(0x1000000, 0x100000)
    return u


def u64(u, a):
    return int.from_bytes(u.mem_read(a, 8), 'little')


def run_case(u, calls, *, root_type, data_type, old, requested, options):
    u.mem_write(0x1000000, bytes(0x100000))
    for meta, kind in ((ROOTM, root_type), (TABLEM, SPTM_PAGE_TABLE), (DATAM, data_type)):
        u.mem_write(meta, struct.pack('<HB', 2, kind))       # lock count 2, type
    u.mem_write(fp_slot := FP-0x58, CELL.to_bytes(8, 'little'))
    u.mem_write(CELL, old.to_bytes(8, 'little'))
    u.mem_write(SP+0x5c, options.to_bytes(4, 'little'))
    u.mem_write(SP+0x60, DATAM.to_bytes(8, 'little'))
    u.mem_write(PERCPU+0x1680, OUT.to_bytes(8, 'little'))
    u.mem_write(OUT, bytes.fromhex('5a'*16))
    cls = ((requested >> 4) & 12) | ((requested >> 53) & 3)
    regs = {8: data_type, 19: ROOTM, 20: requested, 21: BASE+0x9e230,
            22: 0xfffffe1000000000, 23: root_type, 24: TABLEM,
            25: requested & 0xfffffffff000, 26: options, 27: DATAM, 28: cls, 29: FP}
    for n, value in regs.items():
        u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
    u.reg_write(reg.UC_ARM64_REG_SP, SP)
    calls.clear()
    u.emu_start(BASE+0xf9120, BASE+0x200000-4, count=4000)
    assert u64(u, fp_slot) == CELL
    return (u.reg_read(reg.UC_ARM64_REG_PC)-BASE, u.reg_read(reg.UC_ARM64_REG_X0) & 0xffffffff,
            u64(u, CELL), u64(u, OUT), u64(u, OUT+8), dict(calls))


def replay():
    im = runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    sha = hashlib.sha256(im.data).hexdigest()
    if sha != SPTM_SHA:
        raise ValueError('wrong SPTM image')
    for off, word in WITNESS:
        got = struct.unpack_from('<I', im.data, im.locate(BASE+off)[1])[0]
        if got != word:
            raise ValueError(f'instruction differs at {off:x}: {got:08x}')
    u = machine(im)
    calls = {}

    def hook(uc, address, size, user):
        off = address-BASE
        if off in (TLBI, UNLOCK, REFMOVE):
            calls[off] = calls.get(off, 0)+1
            uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(reg.UC_ARM64_REG_X30))
        elif off in BARRIERS:
            uc.reg_write(reg.UC_ARM64_REG_PC, address+4)
        elif off == PERCPU_READ:
            uc.reg_write(reg.UC_ARM64_REG_X8, PERCPU)
            uc.reg_write(reg.UC_ARM64_REG_PC, BASE+PERCPU_LOAD)
        elif off in (RETURN_AT, REJECT_AT, FLUSH_PENDING):
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, hook)

    def pte(pa, cls, bits):
        return pa | 0xe03 | ((cls & 12) << 4) | ((cls & 3) << 53) | (bits << 58)

    pa, other = 0x947a0c000, 0x947a10000
    counts = dict(cases=0, conflict=0, same_pa=0, empty=0, rejected=0)
    examples = []
    # Kernel data types with a mapping policy and descriptor +0x32 clear
    # (the +0x32 types take the 270b66d8 detour before the old-leaf load).
    kinds = {11: (3, 5, 7, 9, 11, 13, 15), 7: (3,), 13: (3,), 36: (3, 15), 37: (3, 11, 15)}
    for root_type in (KERNEL_ROOT, USER_ROOT):
        for data_type, classes in kinds.items():
            for old_cls, new_cls, bits, options in itertools.product(classes, classes, (0, 1, 2), (0, 1)):
                old = pte(pa, old_cls, bits)
                cases = (('conflict', old, pte(other, new_cls, bits)),
                         ('same_pa', old, pte(pa, new_cls, bits)),
                         ('empty', 0, pte(pa, new_cls, bits)))
                for kind, before, requested in cases:
                    pc, status, stored, out0, out1, seen = run_case(
                        u, calls, root_type=root_type, data_type=data_type,
                        old=before, requested=requested, options=options)
                    counts['cases'] += 1
                    if pc == REJECT_AT:
                        if kind != 'same_pa':
                            raise ValueError(f'{kind} rejected')
                        counts['rejected'] += 1
                        continue
                    if pc != RETURN_AT:
                        raise ValueError(f'stop {pc:x} for {kind} {before:x}->{requested:x}')
                    reported = (out0, out1) != (0x5a5a5a5a5a5a5a5a,)*2
                    if reported != (not options):
                        raise ValueError(f'output bit0 rule broken: options={options}')
                    if kind == 'conflict':
                        ok = (status == 6 and stored == before and not seen and
                              (options or (out0 == before and out1 == CELL)))
                    elif kind == 'same_pa':
                        # identical requests return 1 at 270f9378 with no CAS
                        ok = status == 1 and stored & 0xfffffffff000 == pa and (
                            REFMOVE in seen or (requested == before and not seen))
                    else:
                        ok = status == 0 and stored & 0xfffffffff000 == pa and REFMOVE in seen
                    if not ok:
                        raise ValueError(f'{kind} root={root_type} type={data_type} '
                                         f'{before:x}->{requested:x} opt={options}: status {status} '
                                         f'stored {stored:x} out {out0:x},{out1:x} calls {seen}')
                    counts[kind] += 1
                    if kind == 'conflict' and root_type == KERNEL_ROOT and len(examples) < 4 and not options:
                        examples.append(dict(root_type=root_type, data_type=data_type,
                                             old=hex(before), requested=hex(requested),
                                             status=status, stored=hex(stored),
                                             out=[hex(out0), hex(out1)], helpers_called=len(seen)))
    return dict(sptm_sha256=sha, **counts, instruction_witnesses=len(WITNESS),
                rule='valid leaf of another PA: status 6, no CAS, no TLBI/unlock/reference '
                     'helper, old PTE + slot pointer reported unless options bit0; '
                     'identical for kernel root (8) and user root (18)',
                examples=examples,
                boundary='entered at 270f9120 (old-leaf load), run to return 270f9534')


if __name__ == '__main__':
    print(json.dumps(replay(), indent=1))
