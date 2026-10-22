#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay shipped 26A428 MAP_PAGE normalization and reference-delta slices.

No SPTM instructions are patched. The replay stops before source CAS and before
reference atomics. Scratch RAM supplies typed metadata; this is binary contract
evidence, not a complete SPTM execution or physical permission-fault test.
"""
import hashlib
import json
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
import unicorn.arm64_const as reg

BASE = 0xfffffff027000000
HISTORY = 1 << 59
SPTM_SHA = 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'


def replay():
    im = runpy.run_path(str(ROOT / 'tools/sptm-dispatch.py'))['Image'](
        ROOT / 'downloads/extracted/j700ap/sptm.t8140.release')
    if hashlib.sha256(im.data).hexdigest() != SPTM_SHA:
        raise ValueError('SPTM differs from the selected 26A428 image')
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(BASE, 0x200000)
    for _, va, _, offset, size in im.segs:
        u.mem_write(va, im.data[offset:offset + size])
    u.mem_map(0x1000000, 0x100000)
    table, data = 0x1010000, 0x1011000
    u.mem_write(table + 2, bytes([20]))
    u.mem_write(data + 2, bytes([11]))

    def run(start, end):
        u.reg_write(reg.UC_ARM64_REG_SP, 0x1080000)
        u.emu_start(BASE + start, BASE + end, count=1000)
        if u.reg_read(reg.UC_ARM64_REG_PC) != BASE + end:
            raise ValueError('binary slice did not reach its expected end')

    def normalize(pte):
        values = {20: pte, 21: BASE + 0x9e230, 22: 0x16d524000,
                  23: 18, 25: pte & 0xfffffffff000, 26: 0,
                  28: ((pte >> 4) & 12) | ((pte >> 53) & 3)}
        for n, value in values.items():
            u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
        run(0xf9230, 0xf92ac)
        return u.reg_read(reg.UC_ARM64_REG_X27)

    def deltas(old, new):
        for n, value in enumerate((table, data, old, new)):
            u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
        run(0xecb9c, 0xecd00)
        def signed(n):
            value = u.reg_read(getattr(reg, f'UC_ARM64_REG_W{n}'))
            return value if value < (1 << 31) else value - (1 << 32)
        return [signed(15), signed(16)]

    rows = []
    captured = 0x0860000940504ec3
    for label, requested, expected in [
        ('captured_RO_history', captured, captured),
        ('RO_without_history', captured & ~HISTORY, captured & ~HISTORY),
        ('RW_history_normalizes', captured & ~0x80, captured & ~0x80 & ~HISTORY),
    ]:
        pte = normalize(requested)
        assert pte == expected, (label, hex(pte), hex(expected))
        expected_delta = [1, 0] if label == 'RO_without_history' else [0, 1]
        insert, remove, same = deltas(0, pte), deltas(pte, 0), deltas(pte, pte)
        assert insert == expected_delta
        assert remove == [-v for v in expected_delta] and same == [0, 0]
        rows.append(dict(case=label, requested=f'{requested:016x}',
                         normalized=f'{pte:016x}', insert_RO_other=insert,
                         remove_RO_other=remove, identical_RO_other=same))
    # Removing the history flag changes accounting, despite identical AP/NX.
    assert deltas(captured, captured & ~HISTORY) == [1, -1]
    return dict(sptm_sha256=SPTM_SHA, cases=rows,
                slices=[['fffffff0270f9230', 'fffffff0270f92ac'],
                        ['fffffff0270ecb9c', 'fffffff0270ecd00']],
                boundary='before CAS and reference atomics; no physical execution')


if __name__ == '__main__':
    print(json.dumps(replay(), indent=2))
