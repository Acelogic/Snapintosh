#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline high-RAM placement with the actual A16 panel below guest RAM."""
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb

checks=0
def check(value):
    global checks
    assert value
    checks+=1

xb.FRAMEBUFFER=(0xf9a20000,2880,1800,11520,32)
base=0x8c0000000
xb.place(base,0x1000000000-base,guest_span=8192<<20)
xb.validate_early_heap()
check(xb.REGION_SPAN==8192<<20)
check(xb.BOOTSTRAP_SPAN==528<<20 and xb.VSPACE_WALK_SPAN==528<<20)
check(xb.bootstrap_reserve(8192<<20)==xb.BOOTSTRAP_SPAN)
check(xb.TABLE_PA==base+0xd800000)
check(xb.FRAMEMAP_SPAN==64<<20)
check(xb.VSPACE_TOP+1==0xfffffe0310000000)
built=xb.build(xb.DEFAULT_KERNELCACHE,ramdisk=sys.argv[1] if len(sys.argv)>1 else None)
words=struct.unpack(f'<{xb.PARAMS_WORDS}Q',xb.params_blob(built))
check(words[27] == xb.SCRATCH_PA == 0x8cec80000)
check(words[29] == built['scratch_va'] == 0xfffffe010ec80000)
check(built['chunks'][xb.SCRATCH_PA] == bytes(6 * 0x8000))
check(all(pa == xb.SCRATCH_PA or pa + len(blob) <= xb.SCRATCH_PA
          or pa >= xb.SCRATCH_PA + xb.SCRATCH_SPAN
          for pa, blob in built['chunks'].items()))
for slot in range(6):
    for offset in (0, 0x3fff, 0x4000, 0x7fff):
        displacement = slot * 0x8000 + offset
        check(built['tables'].walk(words[29] + displacement)
              == words[27] + displacement)
# Pin the current J700 model inventory and parameter ABI independently of
# PARAMS_WORDS so a silently shortened parameter block still fails this test.
check(words[90]==120 and len(words)==1154 and words[-6:]==(0,)*6)   # early_stop params off
check(xb.PARAMS_PA==base+0xc000 and xb.PARAMS_PA+len(words)*8<=xb.DEVICETREE_PA)
saved_params=xb.PARAMS_PA
try:
    for bad in (base+0x2000,xb.DEVICETREE_PA-0x1000):
        xb.PARAMS_PA=bad
        try: xb.validate_layout()
        except SystemExit: checks+=1
        else: raise AssertionError('overlapping parameters admitted')
finally: xb.PARAMS_PA=saved_params
check(words[30:32]==(base,base+(8192<<20)+xb.BOOTSTRAP_SPAN))
check(words[44]==0xf9a20000 and words[45]==words[31])
check(words[46]>=base+0xed00000 and words[47]==base+(8192<<20))
check(built['slide_config'][3:5]==[xb.VSPACE_TOP+1-0x4000000,xb.VSPACE_TOP+1])
aperture=built['chunks'][xb.HANDOFF_PA+xb.REGIONS_OFFSET]
count=struct.unpack_from('<I',aperture)[0]
ranges=[struct.unpack_from('<QQI',aperture,0x10+24*i) for i in range(count)]
check([r[0] for r in ranges]==sorted(r[0] for r in ranges))
check(ranges[0][0]==0xf9a20000 and ranges[1][0]==base)
fm=built['chunks'][xb.FRAMEMAP_PA]
check(len(fm)==((words[45]-words[44])>>14)*16)
for pa,kind in [(0xf9a20000,0xb),(0xfade8000,0),(base-0x4000,0),
                (base,0xb),(words[45]-0x4000,0xb)]:
    check(fm[((pa-words[44])>>14)*16+2]==kind)
for offset in [0,0x1000_0000,0xffffc000,0x100000000,(8192<<20)-0x4000]:
    check(built['tables'].walk(xb.APERTURE_VA+offset)==base+offset)
check(built['tables'].walk(xb.APERTURE_VA+xb.REGION_SPAN)==0xf9a20000)
check(built['tables'].walk(xb.BOOTSTRAP_PA)==xb.BOOTSTRAP_PA)
check(built['tables'].walk(xb.VSPACE_TOP+1) is None)
for offset in range(0,xb.VSPACE_WALK_SPAN,32<<20):
    va=xb.VSPACE_TOP+1+offset
    table=built['tables'].root
    for level in (1,2):
        desc=built['tables'].read(table,xb.index(level,va))
        check(desc&3==3)
        table=desc&0x0000ffffffffc000
    check(built['tables'].read(table,xb.index(3,va))==0)
for pa,blob in built['chunks'].items():
    check(base<=pa and pa+len(blob)<=words[46])
check(xb.stage2_where(base-0x4000,xb.stage2_ranges()) is None)
check(xb.stage2_where(base,xb.stage2_ranges()) is not None)
check(xb.GUEST_PROFILE.early_heap_va==0xfffffe0200000000)
if built['ramdisk_range']:
    disk_pa,disk_size=built['ramdisk_range']
    dt=xb.DeviceTree(built['chunks'][xb.DEVICETREE_PA])
    check(dt.get('/device-tree/chosen/memory-map','RAMDisk')==struct.pack('<QQ',disk_pa,disk_size))
    check(disk_pa+disk_size<=words[46])
    check(built['chunks'][disk_pa][32:36]==b'NXSB')
    built['chunks'][disk_pa].close()
xb.place(0xda000000,guest_span=384<<20)
check((xb.TABLE_PA,xb.FRAMEMAP_PA,xb.FRAMEMAP_SPAN,xb.VSPACE_TOP+1)==
      (0xe3200000,0xe1900000,0x100000,0xfffffe0200000000))
xb.validate_early_heap()
print(f'PASS: {checks} large-memory layout checks (8 GiB high RAM; no hardware)')
