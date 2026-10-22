#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned SPTM table lifetime, map admission and detach ordering witnesses."""
from pathlib import Path
import hashlib
import runpy
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ROOT = Path(__file__).resolve().parents[1]
h = runpy.run_path(str(ROOT / 'tools/sptm-dispatch.py'))
im = h['Image'](ROOT / 'downloads/extracted/j700ap/sptm.t8140.release')
assert hashlib.sha256(im.data).hexdigest() == 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
rows = h['read_table'](im, h['XNU_BOOTSTRAP_VA'], 47)
assert not h['verify'](rows)
checks = 2
for endpoint, name, handler in (
    (4, 'UNMAP_TABLE', 0xfb1fc),
    (43, 'CONDEMN_LEAF_TABLE', 0xfb934),
    (44, 'UNCONDEMN_LEAF_TABLE', 0xfbe70),
):
    assert rows[endpoint] == (endpoint, 'SPTM_FUNCTIONID_'+name, 0xfffffff027000000+handler, 0)
    checks += 1
decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for offset, mnemonic, operands in (
    (0xfb938, 'mov', 'w2, #1'),
    (0xfbe74, 'mov', 'w2, #0'),
    (0xfb974, 'cmp', 'w8, #0x12'),
    (0xfb99c, 'sub', 'x4, x29, #0x48'),
    (0xfb9a8, 'mov', 'w2, #2'),
    (0xfb9c8, 'mov', 'w8, #7'),
    (0xfb9cc, 'mov', 'w9, #3'),
    (0xfb9d0, 'csel', 'x8, x9, x8, ne'),
    (0xfb9d4, 'and', 'x9, x25, #7'),
    (0xfba00, 'cmp', 'w8, #0x14'),
    (0xfba44, 'ldr', 'x9, [x8, #0x48]'),
    (0xfba54, 'mov', 'w12, #0x4000'),
    (0xfba58, 'and', 'x10, x25, #0xfffffffffffffffb'),
    (0xfba60, 'mov', 'w11, #4'),
    (0xfba70, 'udiv', 'x12, x12, x9'),
    (0xfba78, 'cas', 'x13, x10, [x11]'),
    (0xfba9c, 'mov', 'w21, #0'),
    (0xfbbd8, 'cbz', 'w22, #0xfffffff0270fbdb0'),
    (0xfbbe8, 'mov', 'w21, #7'),
    (0xfbbf0, 'ldclr', 'x10, x11, [x11]'),
    (0xfbc64, 'mov', 'w21, #7'),
    # MAP_PAGE opts out of condemned-table walks; UNMAP_REGION opts in.
    (0xf8fe8, 'mov', 'w3, #0'),
    (0xfc8dc, 'mov', 'w3, #1'),
    (0xec610, 'cbnz', 'w23, #0xfffffff0270ec618'),
    (0xec614, 'tbnz', 'w8, #2, #0xfffffff0270ec6f0'),
    # Whole source allocation-group detach, flush, then reference release.
    (0xfb2d8, 'mov', 'w3, #1'),
    (0xfb2ec, 'mvn', 'w8, w27'),
    (0xfb2f0, 'tst', 'x8, #3'),
    (0xfb390, 'udiv', 'x26, x10, x9'),
    (0xfb3e0, 'casl', 'x13, xzr, [x11]'),
    (0xfb3fc, 'dsb', 'ishst'),
    (0xfb45c, 'bl', '#0xfffffff0270dfea4'),
    (0xfb46c, 'dsb', 'ishnxs'),
    (0xfb470, 'isb', ''),
    (0xfb47c, 'bl', '#0xfffffff0270ed0c0'),
    (0xed0e4, 'cmp', 'w8, #0x17'),
    (0xed0e8, 'b.eq', '#0xfffffff0270ed1ec'),
    (0xed110, 'cash', 'w11, wzr, [x9]'),
    (0xed11c, 'ldrh', 'w9, [x1, #8]'),
    (0xed120, 'cbnz', 'w9, #0xfffffff0270ed22c'),
):
    va = 0xfffffff027000000+offset
    off = im.locate(va)[1]
    ins = next(decoder.disasm(im.data[off:off+4], va))
    assert (ins.mnemonic, ins.op_str) == (mnemonic, operands), (hex(va), ins.mnemonic, ins.op_str)
    checks += 1
print(f'PASS: {checks} shipped user-table lifetime contract checks')
