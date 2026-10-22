#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin positive trust lookup and token consumers to the actual shipped images."""
import hashlib
from pathlib import Path
import runpy
import struct

ROOT=Path(__file__).resolve().parents[1]
h=runpy.run_path(str(ROOT/'tools/kc-disas.py'))
checks=0
def image(name,digest):
    global checks
    raw=(ROOT/'downloads/extracted/j700ap'/name).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==digest;checks+=1
    segments=h['segments'](raw)
    def number(va,fmt='<I'):
        offset=h['locate'](segments,va)[1]
        assert offset is not None
        return struct.unpack_from(fmt,raw,offset)[0]
    return number

t=image('txm.macosx.release','b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246')
k=image('kernelcache.release.mac17p','dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62')
for va,word in (
    (0x1703a108,0x52800001), # boot cache type0
    (0x1703a134,0x9400320d), # native static loader
    (0x17046944,0xa9015674), # module length/payload +16/+24
    (0x17046aa8,0x39002274), # module type at +8
    (0x170466a8,0x910042c0), # static list at runtime+16
    (0x170462e0,0xf100505f), # v2 supplied length >=20
    (0x170462ec,0x97ffff52), # v2 search
    (0x17046060,0xb9401408), # count at +20
    (0x1704607c,0x91006018), # entries at +24
    (0x17046080,0x5280031b), # 24-byte entries
    (0x170460c0,0x52800282), # compare first20 hash bytes
    (0x1704612c,0xf9000517), # token+8 is entry pointer
    (0x17046578,0xf9000297), # token+0 is module pointer
    (0x17046718,0x52800208), # successful library query code16
    (0x1704671c,0x1a800100),
    (0x1703fa78,0x5280004a), # two output words
    (0x1703fa84,0x3d800a60), # copy complete token
    (0x1703fa98,0xb3601d0b), # packed library result high32
    (0x17046244,0xf8687928), # capabilities indexed by version
):
    assert t(0xfffffff000000000+va)==word,hex(va);checks+=1
assert t(0xfffffff01700c3f0,'<Q')==7;checks+=1
for va,word in (
    (0x971aa80,0x350000c0), # token consumed only for successful query
    (0x9739b94,0xa9400408), # load module and entry pointers
    (0x9739b98,0xf9400d00), # module+24 is payload
    (0x9739620,0xb9400109), # payload version
    (0x973964c,0x540001c0), # version2 flags branch
    (0x9739290,0x39405400), # flags directly from original entry+21
):
    assert k(0xfffffe0000000000+va)==word,hex(va);checks+=1
print(f'PASS: {checks} shipped positive trust-cache contract checks')
