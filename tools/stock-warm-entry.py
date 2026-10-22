#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare a read-only physical trace of the selected stock warm-entry stub.

This is not secondary machine initialization. Only the entry's single 4 KiB
code page is executable; every guest stage-2 leaf is read-only. The reset
handler must fault before its first instruction, leaving native RAM intact.
"""
import hashlib
from pathlib import Path
import runpy
import struct

ROOT=Path(__file__).resolve().parents[1]
KC=ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p'
KC_SHA='dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
ENTRY=0xfffffe000c264000
RESET=0xfffffe000ba7af5c
CPU_ENTRIES=0xfffffe000c738768
OA=0x0000fffffffff000
XN=1<<54


def clone_readonly_stage2(read, source, source_low, source_high, base, limit, executable):
    """Clone bounded 36-bit/4 KiB tables; expose precisely one RX 4 KiB page."""
    if (base|limit|source|executable)&4095 or not base<limit:
        raise ValueError('unaligned or empty stage-2 geometry')
    if base<source_high and source_low<limit:
        raise ValueError('probe tables overlap resident monitor')
    copies={}; originals={}; executable_leaves=[]; next_pa=base

    def walk(table,level,ipa):
        nonlocal next_pa
        if (not source_low<=table<=source_high-4096 or table&4095 or
                table in originals or next_pa+4096>limit):
            raise ValueError('invalid, aliased or oversized source stage-2 tables')
        data=read(table,4096)
        if len(data)!=4096:raise ValueError('short stage-2 table')
        originals[table]=data
        destination=next_pa;next_pa+=4096
        words=list(struct.unpack('<512Q',data))
        span=1<<(12+9*(3-level))
        for index,desc in enumerate(words):
            address=ipa+index*span
            if level==1 and index>=64:
                if desc:raise ValueError('source stage-2 exceeds 36 bits')
                continue
            if not desc&1:
                words[index]=0
            elif level<3 and desc&2:
                if desc!=(desc&OA)|3:raise ValueError('unexpected table attributes')
                words[index]=walk(desc&OA,level+1,address)|3
            else:
                if (desc&3)!=(3 if level==3 else 1) or (desc&OA)!=address:
                    raise ValueError('source stage-2 is not an identity map')
                if desc&~(OA|XN|0xfff):raise ValueError('unexpected leaf attributes')
                if not desc&(1<<6):raise ValueError('source leaf is not readable')
                desc=(desc&~(1<<7))|XN
                if address<=executable<address+span:
                    if level!=3:raise ValueError('entry code needs a dedicated 4 KiB leaf')
                    desc&=~XN;executable_leaves.append(address)
                words[index]=desc
        copies[destination]=struct.pack('<512Q',*words)
        return destination

    root=walk(source,1,0)
    if executable_leaves!=[executable]:raise ValueError('missing or duplicate executable entry')
    return root,copies,originals


def prepare(proxy,info,table_base,table_limit):
    import run
    import xnuboot as xb
    work,work_size=run.resident_work(proxy,info)
    work_end=work+work_size
    # The resident layout is compile-checked by test-device-layout.py. Bind
    # this read-only probe to the completed lifecycle checkpoint before use.
    layout=runpy.run_path(str(ROOT/'tools/monitor_layout.py'))['MonitorLayout']()
    bank=work+layout.offset('context','vcpus')
    services=struct.unpack('<3Q',proxy.readmem(work+layout.offset('context','services'),24,live=True))
    if services!=(0,0x100000001,0x8000000000000003):
        raise ValueError('resident monitor is not quiesced and reusable')
    params_pa,=struct.unpack('<Q',proxy.readmem(work,8,live=True))
    if params_pa!=0x8c000c000:raise ValueError('unexpected selected guest placement')
    params=struct.unpack(f'<{xb.PARAMS_WORDS}Q',proxy.readmem(params_pa,xb.PARAMS_WORDS*8,live=True))
    if params[3]!=ENTRY or params[30:32]!=(0x8c0000000,0xae1000000):
        raise ValueError('wrong stock entry or guest extent')
    guest_low,guest_high=params[30:32]

    def read(pa,n):
        if n<=0 or n>0x10000 or not (
                guest_low<=pa<=guest_high-n or work<=pa<=work_end-n):
            raise ValueError('read outside owned guest/monitor RAM')
        return proxy.readmem(pa,n,live=True)

    def translate(va):
        table=params[0]
        for shift in (36,25,14):
            desc,=struct.unpack('<Q',read(table+8*((va>>shift)&2047),8))
            if desc&3!=3:raise ValueError('missing guest table/page')
            table=desc&0x0000ffffffffc000
        return table+(va&0x3fff)

    def va_read(va,n):
        result=bytearray()
        while n:
            take=min(n,0x4000-(va&0x3fff))
            result+=read(translate(va),take);va+=take;n-=take
        return bytes(result)

    image=KC.read_bytes()
    if hashlib.sha256(image).hexdigest()!=KC_SHA:raise ValueError('kernelcache hash mismatch')
    api=runpy.run_path(str(ROOT/'tools/kc-disas.py'));segs=api['segments'](image)
    for va,n in [(ENTRY,0x200),(RESET,0x100)]:
        _,off=api['locate'](segs,va)
        if off is None or va_read(va,n)!=image[off:off+n]:
            raise ValueError('resident stock entry/reset bytes differ from selected image')
    # All nonzero selectors except 4/5 take the same verified warm branch;
    # x0 is overwritten by MPIDR before the data scan. This is a binary-proven
    # equivalent selector, not a claim about a private SPTM enum's spelling.
    selector=1
    entries=[]; immutable={}
    for slot in range(6):
        pa,va=struct.unpack('<QQ',va_read(CPU_ENTRIES+slot*16,16))
        raw=va_read(va,0x1d0)
        if translate(va)!=pa:raise ValueError('CPU data PA/VA disagree')
        physical,=struct.unpack_from('<I',raw,0x1c8)
        logical,=struct.unpack_from('<I',raw,0x40)
        if physical!=([0,1,2,3,0x100,0x101][slot]) or logical!=slot:
            raise ValueError('unexpected or aliased native CPU identity')
        entries.append(dict(slot=slot,pa=pa,va=va,physical=physical,
            intstack=struct.unpack_from('<Q',raw,0x18)[0],
            excepstack=struct.unpack_from('<Q',raw,0x28)[0],
            reset=struct.unpack_from('<Q',raw,0xb8)[0],
            thread=struct.unpack_from('<Q',raw,0x30)[0]))
        page=pa&~4095;immutable[page]=read(page,4096)
    target=entries[1]
    if target['reset']!=RESET or not target['thread']:
        raise ValueError('CPU1 is not prepared for native arm_init_cpu')
    for name in ('intstack','excepstack'):
        va=target[name]
        if not va or va&15:raise ValueError('invalid target stack')
        pa=translate(va-16)&~4095;immutable[pa]=read(pa,4096)
    entry_pa=translate(ENTRY);reset_pa=translate(RESET)
    if entry_pa&4095:raise ValueError('entry page is unaligned')
    immutable[entry_pa]=read(entry_pa,4096)
    table_pa=translate(CPU_ENTRIES)&~4095;immutable[table_pa]=read(table_pa,4096)
    values=struct.unpack('<12Q',read(bank,96))
    if values[4]!=work or values[5]!=0 or values[8]!=1:
        raise ValueError('wrong boot CPU record')
    shadow=values[9];low=values[11]
    source,=struct.unpack('<Q',read(bank+2368+80,8))
    root,copies,originals=clone_readonly_stage2(read,source,work,work_end,
                                             table_base,table_limit,entry_pa)
    # Both structures are the completed CPU0 shadow maps. Hardware has not
    # switched them since prepare; this bounded stub does not change roots.
    if not all(work<=x<=work_end-4096 and not x&4095 for x in (shadow,low)):
        raise ValueError('unowned stage-1 shadow roots')
    tcr=(params[1]&~((3<<30)|(1<<23)|(1<<7)|(3<<14)|0x3f|(7<<32)))
    tcr|=(2<<30)|((params[1]>>16)&0x3f)|(4<<32) # measured 44-bit target PA
    # A16 readback also sets bits 7/8. Request that measured state explicitly,
    # retaining an exact comparison instead of masking unexpected differences.
    sctlr=1|(1<<2)|(1<<7)|(1<<8)|(1<<11)|(1<<12)|(1<<20)|(1<<22)|(1<<23)|(1<<28)|(1<<29)
    vtcr=28|(1<<6)|(1<<8)|(1<<10)|(3<<12)|(4<<16)
    inputs=(ENTRY,selector,0x80000001,shadow,low,tcr,params[2],sctlr,
            root|(7<<48),vtcr,params[16],RESET,target['va'],
            target['intstack'],target['excepstack'],entry_pa)
    witness=dict(kernelcache_sha256=KC_SHA,entry=hex(ENTRY),entry_pa=hex(entry_pa),
        reset=hex(RESET),reset_pa=hex(reset_pa),cpu1=target,inputs=[hex(x) for x in inputs],
        private_stage2_root=hex(root),private_stage2_pages=len(copies),
        sole_executable_page=hex(entry_pa),all_guest_leaves_readonly=True,
        primary_shadow_root=hex(shadow),source_stage2_root=hex(source),
        immutable_pages={hex(pa):hashlib.sha256(data).hexdigest() for pa,data in immutable.items()})
    return inputs,copies,originals,immutable,witness


def passed(state,inputs,witness):
    if len(state)!=128:return False
    x=state[80:102]
    reset=int(witness['reset'],16)
    target=witness['cpu1']
    return (state[64:80]==tuple(inputs) and state[0]==4 and state[1]==8 and state[7]>>26==0x20 and
        state[7]&0x3c==0xc and state[16]==reset and state[17]&0x3ff==0x3c4 and
        state[30]==6 and state[6]==0 and state[31]==0 and
        x[:4]==(target['va'],0,reset,reset) and x[4:9]==(6,0x80000001,16,0,target['va']) and
        x[10:12]==(target['intstack'],target['excepstack']) and x[12:14]==(0,0) and
        x[15]==reset and
        x[17:22]==(inputs[2],inputs[8],inputs[3],inputs[5],inputs[7]))
