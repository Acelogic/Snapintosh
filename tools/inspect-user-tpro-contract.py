#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect the selected USER_TPRO lifecycle and kernel selector-to-type path."""
import hashlib
import json
from pathlib import Path
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]
SPTM_SHA = 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
KERNEL_SHA = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'


def inspect():
    path = ROOT / 'downloads/extracted/j700ap/sptm.t8140.release'
    im = runpy.run_path(str(ROOT / 'tools/sptm-dispatch.py'))['Image'](path)
    if hashlib.sha256(im.data).hexdigest() != SPTM_SHA:
        raise ValueError('SPTM differs from the selected 26A428 image')
    rows = {}
    for kind in (11, 17):
        address = 0xfffffff02709e230 + kind * 144
        offset = im.locate(address)[1]
        data = im.data[offset:offset + 144]
        policy = int.from_bytes(data[4:6], 'little')
        transitions = int.from_bytes(data[64:80], 'little')
        rows[kind] = dict(
            name=im.string(im.pointer(0xfffffff02701e6b8 + kind * 8)),
            descriptor=hex(address), policy=hex(policy),
            selectors=[n for n in range(16) if policy >> n & 1],
            aperture_policy=data[6],
            mixed_aliases=bool(data[0x33]),
            preserve_mask=hex(int.from_bytes(data[0x60:0x62], 'little')),
            transitions=[n for n in range(68) if transitions >> n & 1],
            constructor=hex(im.pointer(address + 0x68)),
            destructor=hex(im.pointer(address + 0x70)))
    tpro = rows[17]
    assert tpro['name'] == 'XNU_USER_TPRO'
    assert tpro['selectors'] == [3, 7, 9, 11, 15]
    assert tpro['mixed_aliases'] and tpro['preserve_mask'] == '0x0'
    assert tpro['transitions'] == [11] and 17 in rows[11]['transitions']
    assert tpro['aperture_policy'] == 3
    assert tpro['constructor'] == '0xfffffff0270ebf7c'
    assert tpro['destructor'] == rows[11]['destructor'] == '0xfffffff0270eb29c'
    assert struct.unpack_from('<2I', im.data, im.locate(0xfffffff0270ebf7c)[1]) == (0xd503245f, 0xd65f03c0)
    path = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
    kc = runpy.run_path(str(ROOT / 'tools/kc-xref.py'))['Kernelcache'](path)
    if hashlib.sha256(kc.data).hexdigest() != KERNEL_SHA:
        raise ValueError('kernel differs from the selected 26A428 image')
    # CMP X8,#9; B.NE default path; MOV W2,#17; B store-type.
    words = struct.unpack_from('<4I', kc.data, kc.va2off(0xfffffe000ba63ca8))
    assert words == (0xf100251f, 0x540001a1, 0x52800222, 0x14000002)
    replay=runpy.run_path(str(ROOT/'tools/replay-sptm-aperture.py'))['replay']()
    return dict(sptm_sha256=SPTM_SHA, kernel_sha256=KERNEL_SHA, types=rows,
                selector9_type=17, constructor_preserves_payload=True,
                aperture_selector_requires_startup_policy_resolution=False,
                bounded_startup_replay=replay,
                native_populated_tpro_qualified=False)


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2))
