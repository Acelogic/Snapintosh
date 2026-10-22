#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay which physical-aperture leaf Apple's SPTM re-permissions on RETYPE
after SLIDE_REGION moved the frame, without a device.

The story, in plain words. SPTM keeps one kernel alias for every frame, the
physical aperture ("papt"). SLIDE_REGION (endpoint 20, 0x270bd3c8) moves part
of it: it unmaps the source pages (0x270e206c), maps the same frames at the
next slide VA (0x270e1d40), records the move in its region array (__DATA+0x2f8)
and rebuilds the physical-to-virtual table (__DATA+0xad0, count at +0xac8;
0x270e2638, then qsort by page count). RETYPE (0x270f83ec) then calls the aperture
updater 0x270dfb1c for the frame (call at 0x270f8784). That updater finds the
frame's aperture VA by searching the same table (0x270dfba4..0x270dfc08), walks
to its leaf (0x270df5cc) and rewrites AP/PXN/UXN with the new type's selector.
So after a slide the leaf that becomes read-only (ROZONE) or sealed
(USER_EXEC) is the moved alias -- the same address XNU's phystokv computes --
and the old source leaf no longer exists.

Replayed with the shipped instructions:
  * the permission-table startup slices (as tools/replay-sptm-aperture.py) so
    every type descriptor's aperture selector (+0x79) is Apple's own;
  * the whole SLIDE_REGION handler including its table rebuild and qsort, with
    the page unmap/map helpers stubbed to record their arguments;
  * the aperture updater from its entry to the leaf store (0x270dfd78), with
    the page-table walk stubbed to record the VA and hand back one leaf cell.
No SPTM instruction is modified. This is a bounded replay, not an SPTM boot.
"""
import hashlib
import json
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg
try:
    from unicorn.arm64_const import UC_CPU_ARM64_MAX
except ImportError:  # pragma: no cover
    UC_CPU_ARM64_MAX = None

SPTM_SHA = 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
BASE = 0xfffffff027000000
TYPE_BASE = 0xfffffff02709e230
MODE_BASE = 0xfffffff02709dfe0
MATRIX = 0x2000000
SLIDE = 0xfffffff0270bd3c8          # SPTM_FUNCTIONID_SLIDE_REGION
PAPT_UPDATE = 0xfffffff0270dfb1c    # aperture updater RETYPE calls at 0x270f8784
UNMAP_PAGES, MAP_PAGES = 0xfffffff0270e206c, 0xfffffff0270e1d40
WALK = 0xfffffff0270df5cc
LINEAR = 0xfffffff0270edecc         # fallback when no table entry covers the PA
STORED = 0xfffffff0270dfd7c         # just after `str x8, [x0]`
PANIC = 0xfffffff027102cc8
DONE = 0x1ff0000                    # sentinel return address

STATE = 0xfffffff027112140          # bit 17: locked down; bit 8: required
LOW_VA, PAPT_END = 0xfffffff02709d048, 0xfffffff02709d508
FRAME_TABLE = 0xfffffff02709d520
MANAGED_LOW, MANAGED_HIGH = 0xfffffff02709e1f8, 0xfffffff02709e200
PAPT_ROOT = 0xfffffff02709e228
CURSOR = 0xfffffff02710df80
REGIONS, REGION_COUNT = 0xfffffff02710d2f8, 0xfffffff02710d2f0
PTOV, PTOV_COUNT = 0xfffffff02710dad0, 0xfffffff02710dac8

RAM = 0x800000000                   # managed physical range (16 MiB)
PAGES = 1024
FT = 0x1040000                      # frame table: 16 bytes per 16K frame
CELL = 0x1030000                    # the leaf cell the stubbed walk returns
SOURCE_VA = 0xfffffe000c000000      # a boot segment's aperture VA
DEST_VA = 0xfffffe01fc000000        # the slide window cursor
LINEAR_MARK = 0xfffffe0f00000000


def q(u, va, value=None, size=8):
    if value is None:
        return int.from_bytes(u.mem_read(va, size), 'little')
    u.mem_write(va, value.to_bytes(size, 'little'))


def selector(d):
    return ((d >> 4) & 12) | ((d >> 53) & 3)


def machine():
    im = runpy.run_path(str(ROOT / 'tools/sptm-dispatch.py'))['Image'](
        ROOT / 'downloads/extracted/j700ap/sptm.t8140.release')
    if hashlib.sha256(im.data).hexdigest() != SPTM_SHA:
        raise ValueError('SPTM differs from the selected 26A428 image')
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    if UC_CPU_ARM64_MAX is not None:
        u.ctl_set_cpu_model(UC_CPU_ARM64_MAX)
    u.mem_map(BASE, 0x200000)
    for _, va, _, offset, size in im.segs:
        u.mem_write(va, im.data[offset:offset + size])
    u.mem_map(0x1000000, 0x100000)
    u.mem_map(MATRIX, 0x100000)
    u.mem_map(DONE & ~0xfff, 0x1000)
    # Startup slices: fill descriptor+0x80 and the aperture selectors +0x79.
    u.reg_write(reg.UC_ARM64_REG_SP, 0x1080000)
    u.reg_write(reg.UC_ARM64_REG_X21, MODE_BASE)
    for start, end, regs in ((0xfffffff0270e35fc, 0xfffffff0270e37fc, {}),
                             (0xfffffff0270e3910, 0xfffffff0270e3e40,
                              {0: MATRIX, 19: TYPE_BASE})):
        for n, value in regs.items():
            u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
        u.emu_start(start, end, count=1000000)
        if u.reg_read(reg.UC_ARM64_REG_PC) != end:
            raise ValueError('startup slice did not reach its end')
    return u


def main():
    u = machine()
    calls = []
    walk = {}

    def hook(uc, address, size, user):
        if address in (UNMAP_PAGES, MAP_PAGES):
            calls.append(('unmap' if address == UNMAP_PAGES else 'map',
                          [uc.reg_read(getattr(reg, f'UC_ARM64_REG_X{n}')) for n in range(4)]))
            uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(reg.UC_ARM64_REG_X30))
        elif address == WALK:
            walk['va'] = uc.reg_read(reg.UC_ARM64_REG_X1)
            walk['level'] = uc.reg_read(reg.UC_ARM64_REG_X2)
            uc.reg_write(reg.UC_ARM64_REG_X0, CELL)
            uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(reg.UC_ARM64_REG_X30))
        elif address == LINEAR:
            pa = uc.reg_read(reg.UC_ARM64_REG_X0)
            uc.reg_write(reg.UC_ARM64_REG_X0, LINEAR_MARK + pa - RAM)
            uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(reg.UC_ARM64_REG_X30))
        elif address in (PANIC, STORED):
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, hook)

    q(u, STATE, 0x100)
    q(u, LOW_VA, 0xfffffe0000000000)
    q(u, PAPT_END, 0xfffffe0200000000)
    q(u, CURSOR, DEST_VA)
    q(u, FRAME_TABLE, FT)
    q(u, MANAGED_LOW, RAM)
    q(u, MANAGED_HIGH, RAM + PAGES * 0x4000)
    q(u, PAPT_ROOT, RAM + (PAGES - 1) * 0x4000)
    for n in range(PAGES):
        q(u, FT + 16 * n, 1, 2)          # frame entry bit0: tracked
        q(u, FT + 16 * n + 2, 11, 1)     # XNU_DEFAULT
    # One slidable boot range covering the first 0x200 frames.
    q(u, REGION_COUNT, 1, 4)
    q(u, REGIONS + 0x10, RAM)
    q(u, REGIONS + 0x18, SOURCE_VA)
    q(u, REGIONS + 0x20, 0x200, 4)
    q(u, REGIONS + 0x24, 0x10, 4)
    q(u, PTOV_COUNT, 1, 4)
    q(u, PTOV, RAM)
    q(u, PTOV + 8, SOURCE_VA)
    q(u, PTOV + 16, 0x200, 4)

    def run(start, regs):
        for n, value in regs.items():
            u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
        u.reg_write(reg.UC_ARM64_REG_SP, 0x1080000)
        u.reg_write(reg.UC_ARM64_REG_X30, DONE)
        u.emu_start(start, DONE, count=200000)
        return u.reg_read(reg.UC_ARM64_REG_PC)

    def retype(pa, new_type, old_leaf):
        """RETYPE's call: the frame's type byte is already new (0x270f8768)."""
        q(u, FT + 16 * ((pa - RAM) >> 14) + 2, new_type, 1)
        policy = u.mem_read(TYPE_BASE + new_type * 144 + 6, 1)[0]
        q(u, CELL, old_leaf)
        walk.clear()
        pc = run(PAPT_UPDATE, {0: pa, 1: policy, 2: (old_leaf >> 2) & 7, 3: 3})
        if pc != STORED:
            raise ValueError(f'aperture updater stopped at {pc:#x}')
        return dict(va=walk['va'], level=walk['level'], stored=q(u, CELL))

    moved_pa = RAM + 0x100 * 0x4000
    kept_pa = RAM + 0x10 * 0x4000
    def leaf(pa, sel):
        # AF, inner shareable, AttrIndx 0, and the selector's AP/PXN/UXN bits.
        return pa | 0x603 | ((sel & 12) << 4) | ((sel & 3) << 53)
    rw_nx = lambda pa: leaf(pa, 3)            # the NX kernel-RW DEFAULT alias
    before = retype(moved_pa, 11, rw_nx(moved_pa))
    assert before['va'] == SOURCE_VA + 0x100 * 0x4000

    pc = run(SLIDE, {0: SOURCE_VA + 0x100 * 0x4000, 1: 4})
    if pc != DONE:
        raise ValueError(f'SLIDE_REGION stopped at {pc:#x}')
    assert calls == [('unmap', [SOURCE_VA + 0x100 * 0x4000, 4, calls[0][1][2], calls[0][1][3]]),
                     ('map', [DEST_VA, moved_pa, 4, 0xfe])], calls
    table = [(q(u, PTOV + 24 * i), q(u, PTOV + 24 * i + 8), q(u, PTOV + 24 * i + 16, size=4))
             for i in range(q(u, PTOV_COUNT, size=4))]
    # The rebuilt table is qsorted by page count, largest first (0x270e2ae4).
    assert table == [(RAM, SOURCE_VA, 0x100),
                     (moved_pa + 0x10000, SOURCE_VA + 0x104 * 0x4000, 0xfc),
                     (moved_pa, DEST_VA, 4)], table
    assert q(u, CURSOR) == DEST_VA + 0x10000

    rows = []
    frame = moved_pa + 0x4000
    for old_type, new_type, want in ((11, 25, 2), (25, 11, 3), (11, 14, 11), (14, 11, 3)):
        r = retype(frame, new_type, leaf(frame, {11: 3, 25: 2, 14: 11}[old_type]))
        assert r['va'] == DEST_VA + 0x4000 and r['level'] == 3, r
        assert r['stored'] & 0x0000fffffffff000 == frame
        assert selector(r['stored']) == want, (old_type, new_type, hex(r['stored']))
        assert r['stored'] == leaf(frame, want), hex(r['stored'])
        rows.append(dict(old_type=old_type, new_type=new_type, leaf_va=hex(r['va']),
                         stored=hex(r['stored']), selector=selector(r['stored'])))
    # Controls: an unmoved frame of the same boot range keeps its source VA,
    # and a frame outside every table entry takes the linear fallback.
    kept = retype(kept_pa, 25, rw_nx(kept_pa))
    assert kept['va'] == SOURCE_VA + 0x10 * 0x4000 and selector(kept['stored']) == 2
    q(u, PTOV_COUNT, 0, 4)
    fallback = retype(frame, 25, rw_nx(frame))
    assert fallback['va'] == LINEAR_MARK + frame - RAM
    return dict(sptm_sha256=SPTM_SHA,
                slide=dict(unmapped_source=hex(SOURCE_VA + 0x100 * 0x4000), pages=4,
                           mapped_destination=hex(DEST_VA), published_table=[
                               [hex(a), hex(b), c] for a, b, c in table]),
                before_slide_leaf_va=hex(before['va']),
                moved_frame=hex(frame), moved_retypes=rows,
                control_unmoved_leaf_va=hex(kept['va']),
                control_no_entry_leaf_va=hex(fallback['va']),
                boundary='startup selector slices, SLIDE_REGION handler+table rebuild+qsort '
                         'and aperture updater executed; page unmap/map, table walk and '
                         'linear fallback stubbed')


if __name__ == '__main__':
    print(json.dumps(main(), indent=1))
