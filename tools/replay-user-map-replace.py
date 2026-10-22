#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay shipped MAP_PAGE selection for same-PA ordinary and shared leaves.

No instruction replacement. Stops before CAS, TXM validation or references;
the caller's full typed-leaf admission and hardware synchronization are not
proved by this replay. The "status" compared here is the selection slice's
(1 identical, 6 different PA, 0 = proceeds to the CAS); it is NOT the
endpoint's return value. After the CAS the endpoint returns 1 for every valid
same-PA old leaf: see tools/replay-map-page-status.py.
"""
import hashlib
import itertools
import json
from pathlib import Path
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg


def replay(binary):
    im = runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    sha = hashlib.sha256(im.data).hexdigest()
    if sha != 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0':
        raise ValueError('wrong SPTM image')
    base = 0xfffffff027000000
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(base, 0x200000)
    for _, va, _, offset, size in im.segs:
        u.mem_write(va, im.data[offset:offset+size])
    u.mem_map(0x1000000, 0x100000)
    fp, sp, data = 0x10800c0, 0x1080000, 0x1012000
    stops = {0xf92ac, 0xf9374, 0xf9378, 0xf95dc}
    def stop(uc, address, size, user):
        if address-base in stops:
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, stop)
    calls = rejected = 0
    for root_type, data_type in ((18,11), (18,14), (18,17), (19,11), (19,14)):
        classes = {11:(7,15), 14:(13,15), 17:(7,9,15)}[data_type]
        for old_class, new_class, old_bits, new_bits, attrs in itertools.product(
                classes, classes, range(4), range(4), (0,0xc00)):
            def pte(cls, bits):
                return (0x947a0c000 | 0xe03 | ((cls & 12) << 4) |
                        ((cls & 3) << 53) | (bits << 58))
            old, requested = pte(old_class, old_bits), pte(new_class, new_bits) ^ attrs
            u.mem_write(data+2, bytes([data_type]))
            u.mem_write(sp+0x60, data.to_bytes(8,'little'))
            for n, value in {20:requested,21:base+0x9e230,22:0x1032d8000,
                             23:root_type,25:requested & 0xfffffffff000,
                             26:old,28:new_class,29:fp}.items():
                u.reg_write(getattr(reg, f'UC_ARM64_REG_X{n}'), value)
            u.reg_write(reg.UC_ARM64_REG_SP, sp)
            u.emu_start(base+0xf9230, base+0x102d08, count=1000)
            pc = u.reg_read(reg.UC_ARM64_REG_PC)-base
            if pc not in stops:
                raise ValueError(f'unexpected stop {pc:x}')
            failed = pc == 0xf9374
            status = 1 if pc == 0xf9378 else 6 if pc == 0xf95dc else 0
            expected = old if status else u.reg_read(reg.UC_ARM64_REG_X27)
            p = subprocess.run([binary,'--pte',f'{old:x}',f'{requested:x}'],
                               capture_output=True,text=True,check=True)
            error, result, selected = p.stdout.split()
            if bool(int(error)) != failed or (not failed and
                    (int(result) != status or int(selected,16) != expected)):
                raise ValueError(f'mismatch root={root_type} type={data_type} '
                                 f'old={old:x} requested={requested:x} '
                                 f'pc={pc:x} expected={expected:x} C={p.stdout}')
            calls += 1
            rejected += failed
    return dict(sptm_sha256=sha,cases=calls,rejected=rejected,
                boundary='pinned same-PA descriptor selection; excludes CAS, TXM, references and TLBI')


if __name__ == '__main__':
    print(json.dumps(replay(sys.argv[1] if len(sys.argv)>1 else
                           str(ROOT/'build/test-user-map-replace'))))
