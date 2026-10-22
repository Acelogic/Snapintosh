#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin the SWITCH_ROOT identity, register formats and CPU-reference contract."""
from pathlib import Path
import hashlib
import runpy
import struct
import re
ROOT=Path(__file__).resolve().parents[1]
helper=runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))
im=helper['Image'](ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
assert hashlib.sha256(im.data).hexdigest()=='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
rows=helper['read_table'](im,helper['XNU_BOOTSTRAP_VA'],47)
assert not helper['verify'](rows)
assert rows[13]==(13,'SPTM_FUNCTIONID_SWITCH_ROOT',0xfffffff0271003f8,0)
checks=3
for va,word in (
    (0xfffffff02710043c,0x6a0802bf), # two flag-mask checks
    (0xfffffff027100444,0x6a08029f),
    (0xfffffff02710050c,0x39402279), # root's domain
    (0xfffffff02710051c,0x6b18033f), # compared with CPU's domain
    (0xfffffff027100524,0x79400a7b), # ASID from root metadata+4
    (0xfffffff027100530,0x39403268), # format from+12
    (0xfffffff027100544,0x79401669), # flags from+10
    (0xfffffff027100548,0x0a340129), # clear override bits
    (0xfffffff02710054c,0x2a15013c), # set override bits
    (0xfffffff027100734,0xaa1bc108), # ASID in TTBR0 bits63:48
    (0xfffffff027100738,0xd5182008), # actual TTBR0 install
    (0xfffffff027100740,0x91001a68), # active reference in metadata+6
    (0xfffffff027100748,0x78290109), # add one CPU reference
    (0xfffffff027100838,0x91001808), # old root metadata+6
    (0xfffffff027100840,0x78290109), # subtract one CPU reference
    (0xfffffff027100848,0x52800000), # return success
):
    off=im.locate(va)[1]
    assert struct.unpack_from('<I',im.data,off)[0]==word,hex(va);checks+=1
header=(ROOT/'compat/sptm-root.h').read_text()
for fmt,name in enumerate(('SPTM_ROOT_TCR_16K','SPTM_ROOT_TCR_4K')):
    tcr=int(re.search(name+r'\s+UINT64_C\((0x[0-9a-f]+)\)',header)[1],16)
    descriptor=im.pointer(0xfffffff027023bc0+8*fmt)
    assert im.word(descriptor+0x40)==tcr;checks+=1
print(f'PASS: {checks} shipped SPTM root-switch contract checks')
