# SPDX-License-Identifier: MIT
"""Capture the native ANS controller and free request pool before discarding guest RAM.

Offsets below come from the matching KDK's native functions, checked against
their UUID-matched relocated KC instructions. This does not infer failed-request
arguments from a free request's last values.
"""
import hashlib
from pathlib import Path
import runpy
import struct

ROOT=Path(__file__).resolve().parents[1]
KDK=Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Extensions/IONVMeFamily.kext/Contents/MacOS/IONVMeFamily')


def collect(read,kernel,entries):
    metadata=runpy.run_path(str(ROOT/'tools/kc-symbolicate.py'))['macho_segments']
    raw=KDK.read_bytes()
    slices=[struct.unpack_from('>5I',raw,8+i*20) for i in range(struct.unpack_from('>I',raw,4)[0])]
    _,_,off,size,_=next(v for v in slices if v[0]==0x100000c and v[1]&0xffffff==2)
    thin=raw[off:off+size];kdk_segs,uid=metadata(thin)
    _,_,kc_off=next(v for v in kernel.entries if v[0]=='com.apple.iokit.IONVMeFamily')
    kc_segs,kc_uid=metadata(kernel.data,kc_off)
    if str(uid)!='c24bd447-be4c-30ed-b7b8-f601ea1b1a7e' or uid!=kc_uid:
        raise ValueError('NVMe KDK/KC identity differs')
    def translate(address):
        name,base=next((n,b) for n,(b,s) in kdk_segs.items() if b<=address<b+s)
        return kc_segs[name][0]+address-base
    witnesses=[]
    for address in (0x1cf6c,0x1a3d8,0x39e1c,0x39e6c,0x4f34c,0x4f38c,
                    0x29584,0x29930,0x2a9cc):
        word=struct.unpack_from('<I',thin,address)[0]
        va=translate(address)
        if kernel.u32(va)!=word:raise ValueError('NVMe native field witness differs')
        witnesses.append(dict(kdk_va=hex(address),kc_va=hex(va),word=hex(word)))
    canonical=lambda p:p|0xffff000000000000 if p else 0
    q=lambda b,o:canonical(struct.unpack_from('<Q',b,o)[0])
    controllers=[e for e in entries if e.get('class_name')=='AppleANS3CGv2Controller']
    if len(controllers)!=1:raise ValueError('expected one native ANS3 controller')
    entry=controllers[0];address=int(entry['address'],16)
    controller=read(address,0xaa0)
    if q(controller,0)!=int(entry['vtable'],16):raise ValueError('controller vtable changed')
    pool_address=q(controller,0x218);pool=read(pool_address,0x58)
    sentinel=pool_address+0x10;node=q(pool,0x10);previous=sentinel;seen=set();requests=[]
    while node!=sentinel:
        if not node or node in seen or len(seen)>=128:raise ValueError('bad native request-pool chain')
        seen.add(node);b=read(node,0x218)
        if q(b,0x18)!=previous:raise ValueError('request-pool reciprocal link differs')
        requests.append(dict(address=hex(node),vtable=hex(q(b,0)),raw_hex=b.hex(),
            transfer_bytes=struct.unpack_from('<Q',b,0xd0)[0],
            prp_size=struct.unpack_from('<I',b,0x208)[0],
            prp_buffer=hex(q(b,0x200))))
        previous,node=node,q(b,0x10)
    if previous!=q(pool,0x18):raise ValueError('request-pool tail differs')
    block_entry,=[e for e in entries if e.get('class_name')=='IOEmbeddedNVMeBlockDevice']
    block=read(int(block_entry['address'],16),0x238)
    if q(block,0)!=int(block_entry['vtable'],16):raise ValueError('block-device vtable changed')
    return dict(kext_uuid=str(uid),kdk_sha256=hashlib.sha256(thin).hexdigest(),witnesses=witnesses,
        block_device=dict(**block_entry,raw_hex=block.hex(),namespace_type=block[0x208]),
        controller=dict(**entry,raw_hex=controller.hex()),
        pool=dict(address=hex(pool_address),raw_hex=pool.hex(),free_count=len(requests)),
        requests=requests,
        boundary='Bounded native free-pool snapshot; last transfer fields do not identify which request emitted the earlier assertion.')
