#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise corrupt runtime snapshots without importing the C implementation."""
from pathlib import Path
import runpy
import struct
audit=runpy.run_path(str(Path(__file__).with_name('audit-shared-regions.py')))['audit_shared_regions']
checks=0
def check(blob,count,metadata,valid):
    global checks
    try:
        out=audit(blob,count,metadata)
    except ValueError:
        assert not valid
    else:
        assert valid
        assert out['configured']<=count
    checks+=1

check(bytes(255*32),0,{},True)
for fmt in (0,1):
    page=0x1000 if fmt else 0x4000
    for slot in (0,127,254):
        f=bytearray(16);f[2]=19;f[8]=slot;f[12]=fmt
        root=0x944dd4000
        for state,start,size in [(1,0,0),(3,0,page),(3,0x180000000,0xe40000000),
                                 (3,(1<<47)-(1<<36),1<<36)]:
            blob=bytearray(255*32);struct.pack_into('<4Q',blob,slot*32,state,start,size,root)
            check(blob,1,{root:f},True)
        for case in range(23):
            blob=bytearray(255*32);meta=bytearray(f);count=1
            row=[3,0x180000000,0xe40000000,root];metadata={root:meta}
            if case==0:row[0]=2
            elif case==1:row[0]=255
            elif case==2:row[0]=0
            elif case==3:row[0]=1
            elif case==4:row[2]=0
            elif case==5:row[2]=(1<<36)+page
            elif case==6:row[1]+=1
            elif case==7:row[2]+=1
            elif case==8:row[1]=1<<47
            elif case==9:row[1]=(1<<47)-page
            elif case==10:row[3]+=0x4000
            elif case==11:meta[2]=18
            elif case==12:meta[8]=(slot+1)%255
            elif case==13:meta[12]=2
            elif case==14:meta[0]=1
            elif case==15:meta[10]=2
            elif case==16:metadata={}
            elif case==17:count=0
            elif case==18:count=-1
            elif case==19:metadata[root+0x4000]=bytearray(meta)
            elif case==20:metadata={root+1:meta}
            elif case==21:meta[8]=255
            elif case==22:blob=bytearray(255*32-1)
            if case!=22:struct.pack_into('<4Q',blob,slot*32,*row)
            check(blob,count,metadata,False)
print(f'PASS: {checks} independent shared-region snapshot checks')
