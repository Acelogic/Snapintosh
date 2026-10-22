#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay original J700 AGX resource-list bounds helpers with Unicorn.

No native resource object, mapping, GPU command or guest is executed. The
oracle uses original KC instruction bytes, not a reimplementation of parsing.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import runpy

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'build/test-python-deps'))
import unicorn as uc
from unicorn import arm64_const as arm

CODE, DATA, OBJECT, PARSER, STOP = 0x100000, 0x200000, 0x300000, 0x301000, 0x400000
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def execute(function, *, cursor, start, end, count=0):
    machine = uc.Uc(uc.UC_ARCH_ARM64, uc.UC_MODE_ARM)
    for base, size in [(CODE,0x1000),(DATA,0x1000),(OBJECT,0x2000),(STOP,0x1000)]:
        machine.mem_map(base,size)
    machine.mem_write(CODE, bytes.fromhex(function['bytes_hex']))
    # Bounded helpers use only PC-relative local branches. Relocating the
    # entire body preserves each displacement; there are no external calls.
    original = int(function['kc'],16)
    length = len(bytes.fromhex(function['bytes_hex']))
    for insn in function['instructions']:
        if insn['mnemonic'] == 'b' or insn['mnemonic'].startswith('b.') or insn['mnemonic'] in ('cbz','cbnz','tbz','tbnz'):
            assert original <= int(insn['operands'].split('#')[-1],16) < original+length
        assert insn['mnemonic'] not in ('bl','blr','blraa')
    if DATA <= cursor and cursor+64 <= DATA+0x1000:
        payload = bytearray(64)
        struct.pack_into('<Q',payload,0,0x1234567887654321)
        struct.pack_into('<I',payload,28,0x1020304)
        struct.pack_into('<H',payload,62,count)
        machine.mem_write(cursor,bytes(payload))
    machine.mem_write(PARSER,struct.pack('<QQQ',start,end,cursor))
    machine.reg_write(arm.UC_ARM64_REG_X0,OBJECT)
    machine.reg_write(arm.UC_ARM64_REG_X1,PARSER)
    machine.reg_write(arm.UC_ARM64_REG_LR,STOP)
    machine.emu_start(CODE,STOP,count=128)
    assert machine.reg_read(arm.UC_ARM64_REG_PC)==STOP
    raw=bytes(machine.mem_read(OBJECT,32))
    return dict(result=machine.reg_read(arm.UC_ARM64_REG_X0),valid=raw[8],
        error=struct.unpack_from('<I',raw,12)[0],value=struct.unpack_from('<Q',raw,16)[0],
        count=struct.unpack_from('<I',raw,24)[0],
        cursor=struct.unpack('<Q',machine.mem_read(PARSER+16,8))[0])


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--native',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    assert not args.output.exists()
    native=json.loads(args.native.read_text())
    image=next(i for i in native['images'] if i['image']=='AGXG17P')
    assert image['uuid']=='80c847da-77c1-32e5-bc68-9dfc853fb71f'
    assert native['tracer_sha256']==sha(ROOT/'tools/trace-adreno-memory-map.py')
    assert native['resource_list_tracer_sha256']==sha(ROOT/'tools/trace-adreno-resource-list.py')
    Cache=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache']
    cache=Cache(ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p',scope='com.apple.AGXG17P')
    assert hashlib.sha256(cache.data).hexdigest()==image['kernel_sha256']
    cases=[]
    for name,size in [('AGXSegmentResourceList',32),('AGXSegmentResourceDescGroup',64)]:
        function=next(f for f in image['functions'] if name+'16parseAndValidate' in f['symbol'])
        original=bytes.fromhex(function['bytes_hex'])
        at=cache.va2off(int(function['kc'],16))
        assert cache.data[at:at+len(original)]==original
        group=size==64
        vectors=[]
        for alignment in range(8):
            for available in range(size+2):
                for count in (range(9) if group else (0,)):
                    vectors.append((DATA+alignment,DATA,DATA+alignment+available,count))
        vectors.extend([(DATA,DATA+1,DATA+128,0),(DATA,DATA,DATA-1,0),
                        ((1<<64)-16,0,(1<<64)-1,0),(0,0,128,0)])
        for cursor,start,end,count in vectors:
            bounded=cursor>=start and cursor+size < 1<<64 and cursor+size<=end
            good=bounded and cursor!=0 and (not group or count<7)
            got=execute(function,cursor=cursor,start=start,end=end,count=count)
            expected=dict(result=int(good),valid=int(good),error=0 if good else 10,
                value=(cursor if group else 0x1234567887654321) if good else 0,
                count=(count if group else 0x1020304) if good else 0,
                cursor=cursor+size if bounded else cursor)
            assert got==expected,(name,cursor,start,end,count,expected,got)
            cases.append(dict(helper=name,cursor=hex(cursor),start=hex(start),end=hex(end),
                              input_count=count,observed=got))
    result=dict(status='NATIVE_PARSER_HELPERS_QUALIFIED_ONLY',boundary=__doc__,
        native_sha256=sha(args.native),kc_sha256=image['kernel_sha256'],uuid=image['uuid'],
        source_sha256=sha(Path(__file__)),unicorn_version=uc.__version__,checks=len(cases),cases=cases)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('cases','boundary')}))


if __name__=='__main__': main()
