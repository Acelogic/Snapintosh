#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the shipped MAP_PAGE status for an existing user leaf, through the CAS.

tools/replay-user-map-replace.py stops at the descriptor CAS (0x270f92ac) and
treats "reached the CAS" as status 0. The status is chosen after the CAS:

    270f92b4  casl  x26, x27, [x17]      ; install the selected descriptor
    270f92bc  b.eq  270f9490             ; CAS won
    270f9490  cmp   x16, #3              ; x16 = old & 3, computed at 270f92cc
    270f9498  b.ne  270f9554             ; old was not a valid leaf
    270f9574  mov   w0, #0               ;   -> SPTM_SUCCESS: a new mapping
    270f957c  ...TLBI, reference move...  ; old was a valid leaf (same PA)
    270f95d4  mov   w0, #1               ;   -> SPTM_MAP_VALID

XNU's pmap_enter_options_internal (kernelcache 0xfffffe000ba61544) calls
pmap_enter_pv (0xfffffe000ba77af8) only for status 0; status 1 means "had a
valid mapping" and adds no PV entry. So a same-PA permission change must
return 1, or XNU records the same PTE pointer twice in the page's PV list.

The C side of the same rule is pinned by tools/test-xnu-pv-model.c and
tools/test-user-map-replace.c (SPTM_USER_MAP_VALID).

The three helper calls between the CAS and the status (TLBI 270dfea4, table
lock release 270ebf8c, reference move 270ecb8c) are stubbed to return; they
do not write w0. No SPTM instruction is modified.
"""
import hashlib
import itertools
import json
from pathlib import Path
import runpy
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
STUBS = {0xdfea4, 0xebf8c, 0xecb8c}
# `dsb ishnxs` (FEAT_XS) is a barrier unicorn does not decode; step over it.
BARRIERS = {0xf95cc}
STATUS_AT = 0xf9390     # common status join after w0 is chosen (after the 6 path too)
REJECT_AT = 0xf9374     # panic call for a refused permission transition
FLUSH_PENDING = 0xf9384


def machine(im):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    if UC_CPU_ARM64_MAX is not None:
        u.ctl_set_cpu_model(UC_CPU_ARM64_MAX)
    u.mem_map(BASE, 0x200000)
    for _, va, _, offset, size in im.segs:
        u.mem_write(va, im.data[offset:offset+size])
    u.mem_map(0x1000000, 0x100000)
    return u


def run_case(u, *, root_type, data_type, old, requested, new_class):
    fp, sp, data, cell = 0x10800c0, 0x1080000, 0x1012000, 0x1030000
    u.mem_write(data+2, bytes([data_type]))
    u.mem_write(sp+0x60, data.to_bytes(8, 'little'))
    u.mem_write(fp-0x58, cell.to_bytes(8, 'little'))
    u.mem_write(cell, old.to_bytes(8, 'little'))
    regs = {19: data, 20: requested, 21: BASE+0x9e230, 22: 0x1032d8000,
            23: root_type, 25: requested & 0xfffffffff000, 26: old,
            28: new_class, 29: fp}
    for n, value in regs.items():
        u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
    u.reg_write(reg.UC_ARM64_REG_SP, sp)
    u.emu_start(BASE+0xf9230, BASE+0x200000-4, count=4000)
    pc = u.reg_read(reg.UC_ARM64_REG_PC)-BASE
    stored = int.from_bytes(u.mem_read(cell, 8), 'little')
    return pc, u.reg_read(reg.UC_ARM64_REG_X0) & 0xffffffff, stored


def replay():
    im = runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    sha = hashlib.sha256(im.data).hexdigest()
    if sha != SPTM_SHA:
        raise ValueError('wrong SPTM image')
    u = machine(im)

    def hook(uc, address, size, user):
        off = address-BASE
        if off in STUBS:
            uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(reg.UC_ARM64_REG_X30))
        elif off in BARRIERS:
            uc.reg_write(reg.UC_ARM64_REG_PC, address+4)
        elif off in (STATUS_AT, REJECT_AT, FLUSH_PENDING):
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, hook)

    def pte(pa, cls, bits):
        return pa | 0xe03 | ((cls & 12) << 4) | ((cls & 3) << 53) | (bits << 58)

    rows, counts = [], dict(cases=0, rejected=0, status0=0, status1=0, status6=0,
                            flush_pending=0)
    pa, other = 0x947a0c000, 0x947a10000
    for root_type, data_type in ((18, 11), (18, 14), (18, 17), (19, 11), (19, 14)):
        classes = {11: (7, 15), 14: (13, 15), 17: (7, 9, 15)}[data_type]
        olds = []
        for cls, bits in itertools.product(classes, range(4)):
            olds.append(('valid', pte(pa, cls, bits)))
        olds += [('empty', 0), ('compressed', 1 << 62),
                 ('compressed-alt', (1 << 62) | (1 << 63)), ('in-flight', 0x80)]
        for (kind, old), new_class, new_bits in itertools.product(olds, classes, range(4)):
            requested = pte(pa, new_class, new_bits)
            for target, label in ((requested, 'same-pa'), (pte(other, new_class, new_bits), 'other-pa')):
                if kind != 'valid' and label == 'other-pa':
                    continue
                pc, status, stored = run_case(u, root_type=root_type, data_type=data_type,
                                              old=old, requested=target, new_class=new_class)
                counts['cases'] += 1
                if pc == REJECT_AT:
                    counts['rejected'] += 1
                    continue
                if pc == FLUSH_PENDING:
                    counts['flush_pending'] += 1
                    status = 2
                elif pc != STATUS_AT:
                    raise ValueError(f'unexpected stop {pc:x} for {kind} {old:x} -> {target:x}')
                counts[f'status{status}'] = counts.get(f'status{status}', 0)+1
                # The rule this replay pins: status 1 iff the old leaf was a
                # valid same-PA descriptor (identical or changed); status 0
                # iff the slot held no valid leaf; 6 for a valid other PA.
                if kind == 'valid':
                    want = 1 if label == 'same-pa' else 6
                elif kind == 'in-flight':
                    want = 2
                else:
                    want = 0
                if status != want:
                    raise ValueError(f'{kind}/{label} old={old:x} req={target:x}: status {status}, expected {want}')
                if len(rows) < 12 and kind == 'valid' and label == 'same-pa' and old != target:
                    rows.append(dict(root_type=root_type, data_type=data_type, old=hex(old),
                                     requested=hex(target), stored=hex(stored), status=status))
    return dict(sptm_sha256=sha, **counts, examples=rows,
                boundary='CAS executed; TLBI/lock/reference helpers stubbed; status read at 270f9390')


if __name__ == '__main__':
    print(json.dumps(replay(), indent=1))
