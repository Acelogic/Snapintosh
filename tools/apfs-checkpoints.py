# SPDX-License-Identifier: MIT
"""Read-only checkpoint/checksum evidence, not a complete APFS consistency check.

Layout: Apple's Apple File System Reference, Container / nx_superblock_t.
https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
Only a contiguous descriptor ring with4KiB blocks is supported; retain raw bytes.
"""
import hashlib
import json
from pathlib import Path
import runpy
import struct
import uuid

ROOT=Path(__file__).resolve().parents[1]
checksum=runpy.run_path(str(ROOT/'tools/make-isc-fixture.py'))['checksum']
sha=lambda b:hashlib.sha256(b).hexdigest()


def capture(nv,first,header,output):
    out=Path(output);assert not out.exists()
    result=dict(containers={},source_sha256=sha(Path(__file__).read_bytes()),
        boundary='Primary and selected checkpoint descriptor checksums/geometry only; not fsck or file persistence proof.')
    for name in ('isc','container'):
        base=first*nv.lba_bytes+header[name+'_offset']
        region=header[name+'_region']
        def read(block,count):
            if not 0<=block*4096<(block+count)*4096<=region:
                raise ValueError('APFS metadata request outside provisioned region')
            return nv.read((base+block*4096)//nv.lba_bytes,count*4096//nv.lba_bytes)
        primary=read(0,1)
        if primary[32:36]!=b'NXSB' or primary[:8]!=checksum(primary):
            raise ValueError('invalid primary NXSB magic/checksum')
        block_size,blocks=struct.unpack_from('<IQ',primary,36)
        desc_count=struct.unpack_from('<I',primary,104)[0]
        desc_base=struct.unpack_from('<Q',primary,112)[0]
        identity=primary[72:88]
        if block_size!=4096 or not 0<blocks<=region//4096 or not 0<desc_count<=4096 or not 0<desc_base<blocks-desc_count:
            raise ValueError('unsupported or out-of-range APFS descriptor geometry')
        raw=read(desc_base,desc_count)
        for suffix,data in [('primary',primary),('descriptors',raw)]:
            with out.with_name(out.stem+'-'+name+'-'+suffix+'.bin').open('xb') as f:f.write(data)
        rows=[];supers=[]
        for index in range(desc_count):
            b=raw[index*4096:(index+1)*4096]
            oid,xid,typ=struct.unpack_from('<QQI',b,8)
            good=b[:8]==checksum(b)
            rows.append(dict(index=index,block=desc_base+index,oid=oid,xid=xid,
                type=hex(typ),checksum_valid=good,sha256=sha(b)))
            if b[32:36]==b'NXSB' and good:
                if b[72:88]!=identity or struct.unpack_from('<IQ',b,36)!=(4096,blocks):
                    raise ValueError('checkpoint container identity/geometry differs')
                if struct.unpack_from('<I',b,104)[0]!=desc_count or struct.unpack_from('<Q',b,112)[0]!=desc_base:
                    raise ValueError('checkpoint ring geometry changed')
                supers.append((xid,index,b))
        if not supers:raise ValueError('no valid NXSB in checkpoint ring')
        xid,index,latest=max(supers,key=lambda t:t[0])
        begin,length=struct.unpack_from('<2I',latest,136)
        if begin>=desc_count or not 0<length<=desc_count:raise ValueError('invalid active descriptor interval')
        active=[rows[(begin+i)%desc_count] for i in range(length)]
        if not all(r['checksum_valid'] and r['xid']==xid for r in active) or index not in [r['index'] for r in active]:
            raise ValueError('active checkpoint descriptors fail checksum/xid validation')
        result['containers'][name]=dict(uuid=str(uuid.UUID(bytes=identity)),blocks=blocks,
            primary_sha256=sha(primary),primary_xid=struct.unpack_from('<Q',primary,16)[0],
            descriptor_base=desc_base,descriptor_count=desc_count,descriptor_sha256=sha(raw),
            latest_xid=xid,latest_index=index,active_descriptor_indices=[r['index'] for r in active],
            selected_checkpoint_checksums_valid=True,descriptors=rows)
    with out.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    return result
