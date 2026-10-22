#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned endpoint7 witnesses: geometry, old PTEs, invalidation before release."""
from pathlib import Path
import hashlib
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]
h = runpy.run_path(str(ROOT / 'tools/sptm-dispatch.py'))
im = h['Image'](ROOT / 'downloads/extracted/j700ap/sptm.t8140.release')
assert hashlib.sha256(im.data).hexdigest() == 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
rows = h['read_table'](im, h['XNU_BOOTSTRAP_VA'], 47)
assert not h['verify'](rows)
assert rows[7] == (7, 'SPTM_FUNCTIONID_UNMAP_REGION', 0xfffffff0270fd50c, 0)
checks = 3
for offset, word in (
    (0xfd510, 0xaa0303e4),  # caller options x3 -> common x4
    (0xfd518, 0x91091210),  # first callback fd244
    (0xfd52c, 0x9111e210),  # post-invalidation callback fd478
    (0xfd53c, 0xd2800003),  # no replacement descriptor vector
    (0xfd540, 0x17fffcaa),  # common fc7e8
    (0xfc84c, 0x52800802),  # maximum count 64
    (0xfcf9c, 0x340006a1),  # zero count rejected
    (0xfcfa0, 0xeb08005f),  # count against maximum
    (0xfcfa4, 0x54000663),  # over maximum rejected
    (0xfc88c, 0xf9402549),  # format page size +0x48
    (0xfc894, 0x9b097e68),  # count * page size
    (0xfc8a4, 0xf940454a),  # geometry L2 index mask +0x88
    (0xfc8a8, 0xca00012b),  # compare first and last page VA
    (0xfc8b0, 0x54002fa1),  # reject crossed L3 table
    (0xfc9ec, 0xf8377b01),  # old PTE to per-CPU scratch[index]
    (0xfcb38, 0xd37df261),  # absent parent: count * 8 output bytes
    (0xfd25c, 0x71005d3f),  # type23 commpage table rejected
    (0xfd260, 0x54000740),
    (0xfd2c0, 0x5280a008),  # option mask 0x500 forbidden
    (0xfd2c4, 0x6a08007f),
    (0xfd2e8, 0xb2790108),  # transient invalid marker 0x80
    (0xfcb68, 0xd5033a9f),  # DSB ISHST
    (0xfcb84, 0x97ff8cc8),  # TLBI helper
    (0xfcb8c, 0xd5033b9f),  # DSB ISH
    (0xfcba8, 0xd5033fdf),  # ISB, before postcallback loop
    (0xfd4a4, 0x92430843),  # retain only compressed bits, ordinary final PTE=0
    (0xfd4a8, 0xc8a27d43),  # replace transient marker
    (0xfd4c0, 0x17ffbdb3),  # update references only in postcallback
):
    va = 0xfffffff027000000 + offset
    assert struct.unpack_from('<I', im.data, im.locate(va)[1])[0] == word, hex(va)
    checks += 1
for descriptor, inner, size, mask in (
    (0xfffffff02701ec78, 0xfffffff02701a5a8, 0x4000, 0xffe000000),
    (0xfffffff02701ece0, 0xfffffff02701a688, 0x1000, 0x3fe00000),
):
    assert im.pointer(descriptor) == inner
    assert im.word(descriptor + 0x48) == size
    assert im.word(inner + 0x88) == mask
    checks += 3
print(f'PASS: {checks} shipped user-unmap contract checks')
