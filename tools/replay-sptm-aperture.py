#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the selected SPTM permission-table startup slices, without a device.

The exact shipped instructions build the type bitmap, execution-mode bitmap,
permission matrix and dynamic aperture selectors. Allocation/address conversion
between the slices is replaced by zeroed scratch RAM. This is a bounded replay,
not a complete SPTM boot or a hardware qualification.
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

TYPE_BASE = 0xfffffff02709e230
MODE_BASE = 0xfffffff02709dfe0
BITMAP = 0xfffffff02709c320
MATRIX = 0x2000000
SPTM_SHA = 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'


def replay(remove_tpro_write=False, extra_types=()):
    im = runpy.run_path(str(ROOT / 'tools/sptm-dispatch.py'))['Image'](
        ROOT / 'downloads/extracted/j700ap/sptm.t8140.release')
    if hashlib.sha256(im.data).hexdigest() != SPTM_SHA:
        raise ValueError('SPTM differs from the selected 26A428 image')
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0xfffffff027000000, 0x200000)
    for _, va, _, offset, size in im.segs:
        u.mem_write(va, im.data[offset:offset + size])
    u.mem_map(0x1000000, 0x100000)
    u.mem_map(MATRIX, 0x100000)
    u.reg_write(reg.UC_ARM64_REG_SP, 0x1080000)
    u.reg_write(reg.UC_ARM64_REG_X21, MODE_BASE)
    if remove_tpro_write:
        # Negative control: both explicit TPRO ACLs become read-only. The
        # descriptor's aperture-policy byte remains 3 in this counterfactual.
        for offset in (8 + 7, 16 + 7):
            u.mem_write(TYPE_BASE + 17 * 144 + offset, bytes([1]))

    def run(start, end):
        u.emu_start(start, end, count=1000000)
        if u.reg_read(reg.UC_ARM64_REG_PC) != end:
            raise ValueError('startup slice did not reach its expected end')

    # This slice consumes the shipped static ACL and group tables, filling
    # descriptor+0x80 (modes) and mode+0x30 (frame types). No fixup pointers
    # are consumed by either slice.
    run(0xfffffff0270e35fc, 0xfffffff0270e37fc)
    bitmap = int.from_bytes(u.mem_read(BITMAP, 16), 'little')
    targets = [n for n in range(68) if bitmap >> n & 1]
    u.reg_write(reg.UC_ARM64_REG_X0, MATRIX)
    u.reg_write(reg.UC_ARM64_REG_X19, TYPE_BASE)
    run(0xfffffff0270e3910, 0xfffffff0270e3c64)
    permissions = {}
    for kind in dict.fromkeys((11, 17, *extra_types)):
        assert 0 <= kind < 68
        row = (kind * 8 + 3) * len(targets)
        permissions[kind] = u.mem_read(MATRIX + row + targets.index(6), 1)[0]
    # This bit tests the result of the ACL matrix. Reading descriptor byte6
    # alone would incorrectly predict RW even in the negative control.
    if remove_tpro_write:
        assert permissions[11] & 2 and not permissions[17] & 2
        return dict(kernel_write=permissions,
                    negative_control_rejected_aperture3=True)
    run(0xfffffff0270e3c64, 0xfffffff0270e3e40)
    apertures = {kind: u.mem_read(TYPE_BASE + kind * 144 + 0x79, 1)[0]
                 for kind in dict.fromkeys((4, 5, 6, 11, 17, *extra_types))}
    assert {k: apertures[k] for k in (4, 5, 6, 11, 17)} == {4: 0, 5: 8, 6: 10, 11: 3, 17: 3}
    assert permissions[11] & 2 and permissions[17] & 2
    return dict(sptm_sha256=SPTM_SHA, bitmap_frame_types=targets,
                kernel_write=permissions, aperture_selectors=apertures,
                instruction_slices=[['0xfffffff0270e35fc', '0xfffffff0270e37fc'],
                                    ['0xfffffff0270e3910', '0xfffffff0270e3e40']],
                boundary='static shipped policy; allocation replaced by scratch RAM',
                native_populated_tpro_qualified=False)


if __name__ == '__main__':
    assert sys.argv[1:] in ([], ['--txm-donation'])
    result = replay(extra_types=(42,) if sys.argv[1:] else ())
    result['negative_control'] = replay(remove_tpro_write=True)
    print(json.dumps(result, indent=2))
