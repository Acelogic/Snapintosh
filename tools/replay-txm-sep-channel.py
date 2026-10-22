#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay pinned TXM7 capability/descriptor branches and the XNU unavailable path.

Original instruction bytes execute. Native initializer prerequisite queries,
current-reply lookup, physical translation, and IOKit calls are explicit fixtures.
PAC is omitted. Enabled initialization stops before allocation/protocol setup;
the successful getter fixture is not a working secure channel.
"""
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'build/test-python-deps'))
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
import unicorn.arm64_const as reg

TXM_SHA='b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246'
KC_SHA='dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
T=0xfffffff017000000
DATA=0x1000000
REPLY=DATA+0x50000
STOP=DATA+0x1000


def replay(binary):
    raw=(ROOT/'downloads/extracted/j700ap/txm.macosx.release').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==TXM_SHA
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.ctl_set_cpu_model(reg.UC_CPU_ARM64_MAX)
    u.mem_map(T,0x200000);u.mem_map(DATA,0x100000)
    for _,va,_,off,size in runpy.run_path(str(ROOT/'tools/kc-disas.py'))['segments'](raw):
        u.mem_write(va,raw[off:off+size])
    u.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
    mode=None;outcome=None;translation=0x2000000;translation_status=0;translated=[]
    def get(n):return u.reg_read(getattr(reg,f'UC_ARM64_REG_X{n}'))
    def put(n,v):u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),v)
    def q(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
    def ret(value):put(0,value);u.reg_write(reg.UC_ARM64_REG_PC,get(30))
    def finish(value):
        nonlocal outcome
        outcome=value;u.emu_stop()
    def hook(uc,pc,size,user):
        if pc==T+0x3d818:finish(('panic',get(0)));return
        if pc==T+0x3ed54:finish(('return',get(0)));return
        if mode=='init':
            if pc in (T+0x3e538,T+0x3e618,T+0x3e10c):ret(0);return
            if pc==T+0x37798:finish('enabled');return
            if pc==T+0x37800:finish('absent');return
        if pc==T+0x41aa8:ret(REPLY);return
        if pc==T+0x3eda4:
            translated.append(get(0));u.mem_write(get(1),struct.pack('<Q',translation))
            ret(translation_status);return
        word,=struct.unpack('<I',uc.mem_read(pc,4))
        if word in (0xd503237f,0xd50323ff):uc.reg_write(reg.UC_ARM64_REG_PC,pc+4)
        elif word==0xd65f0fff:uc.reg_write(reg.UC_ARM64_REG_PC,get(30))
    u.hook_add(UC_HOOK_CODE,hook)
    def start(pc):
        nonlocal outcome
        outcome=None;u.reg_write(reg.UC_ARM64_REG_SP,DATA+0xe0000)
        put(30,STOP);u.emu_start(pc,0,count=2000)
        assert outcome is not None,f'unfinished native path {pc:x}'
        return outcome
    mode='init'
    enabled=[]
    for platform in range(256):
        u.mem_write(T+0x20390,bytes(0x80));u.mem_write(T+0x90e30,bytes(16))
        u.mem_write(T+0x2039a,bytes([platform]))
        result=start(T+0x3770c)
        want=platform in (1,2,3,4,5,7,8)
        assert result==('enabled' if want else 'absent'),(platform,result)
        if want:enabled.append(platform)
        assert bytes(u.mem_read(T+0x203c8,24))==bytes(24)
    mode='getter'
    def query(flag,va=DATA+0x80000,length=0x4000,pa=0x2000000,rc=0):
        nonlocal translation,translation_status
        translation=pa;translation_status=rc;translated.clear()
        u.mem_write(T+0x90e30,bytes([flag]))
        u.mem_write(T+0x203c8,struct.pack('<3Q',va,length,0))
        u.mem_write(REPLY,b'\xa5'*80)
        put(19,REPLY);put(26,7)
        result=start(T+0x3f070)
        return result,q(REPLY+8),q(REPLY+24)
    calls=0
    portable=subprocess.run([binary,'--reply'],capture_output=True,text=True,check=True)
    portable_status,portable_count=map(int,portable.stdout.split())
    for flag in range(0,256,2):
        for va in (0,DATA+0x80000):
            result,status,count=query(flag,va=va);calls+=1
            assert result==('return',0x29) and (status,count)==(portable_status,portable_count)==(0x29,0)
            assert not translated
    for flag in (1,3,255):
        result,status,count=query(flag);calls+=1
        assert result==('return',0) and (status,count)==(0,2)
        assert (q(REPLY+32),q(REPLY+40))==(0x2000000,0x4000)
        assert translated==[DATA+0x80000]
    for kw,panic in [({'va':0},0x2d),({'length':0},0x41),
                     ({'va':(1<<64)-0x4000},0x42),({'va':DATA+1},0xc0),
                     ({'length':1},0xc1),({'length':0x8000},0xc2),
                     ({'pa':0},0x40),({'pa':(1<<64)-0x4000},0x42),
                     ({'pa':0x2000001},0xc0),({'rc':1},0xf2)]:
        result,_,count=query(1,**kw);calls+=1
        assert result==('panic',panic) and count==0,(kw,result,count)

    K=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache']
    k=K(ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p')
    assert hashlib.sha256(k.data).hexdigest()==KC_SHA
    v=Uc(UC_ARCH_ARM64,UC_MODE_ARM);v.mem_map(DATA,0x100000)
    for va,size in [(0xfffffe00099b6000,0x1000),(0xfffffe000befc000,0x1000)]:
        v.mem_map(va,size);off=k.va2off(va);v.mem_write(va,k.data[off:off+size])
    v.mem_map(0xfffffe00081e8000,0x1000)
    v.mem_write(0xfffffe00081e89d0,struct.pack('<Q',DATA+0x70000))
    manager=DATA+0x4000;node=DATA+0x8000;vtable=DATA+0x10000
    v.mem_write(node,struct.pack('<Q',vtable))
    events=[];node_present=False;manager_stop=None
    def vget(n):return v.reg_read(getattr(reg,f'UC_ARM64_REG_X{n}'))
    def vput(n,x):v.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),x)
    def vhook(uc,pc,size,user):
        nonlocal manager_stop
        if pc in (STOP,0xfffffe000befcf64):
            manager_stop=vget(0);v.emu_stop();return
        calls={0xfffffe00099b618c:('dart-tree-lookup',node if node_present else 0),
               0xfffffe00099b61a4:('channel-getter',0x2e),
               0xfffffe00099b62e8:('release-tree-node',0),
               0xfffffe00099b630c:('log-result',0)}
        if pc in calls:
            name,value=calls[pc];events.append(name)
            if name=='channel-getter':
                assert vget(0)==v.reg_read(reg.UC_ARM64_REG_SP)+0x28
                assert vget(1)==v.reg_read(reg.UC_ARM64_REG_SP)+0x20
            if name=='log-result':
                assert bytes(v.mem_read(v.reg_read(reg.UC_ARM64_REG_SP),16))==bytes(16)
            vput(0,value);v.reg_write(reg.UC_ARM64_REG_PC,pc+4);return
        word,=struct.unpack('<I',v.mem_read(pc,4))
        if word in (0xd503237f,0xd50323ff) or pc==0xfffffe00099b62d8:
            v.reg_write(reg.UC_ARM64_REG_PC,pc+4)
        elif word==0xd65f0fff:v.reg_write(reg.UC_ARM64_REG_PC,vget(30))
    v.hook_add(UC_HOOK_CODE,vhook)
    vput(20,portable_status);v.emu_start(0xfffffe000befce94,0,count=40)
    assert manager_stop==0x2e
    for present in (False,True):
        node_present=present;events.clear();manager_stop=None
        v.mem_write(manager,b'\xa5'*0x200)
        v.reg_write(reg.UC_ARM64_REG_SP,DATA+0xe0000);vput(0,manager);vput(30,STOP)
        v.emu_start(0xfffffe00099b614c,0,count=1000)
        assert manager_stop==0 and bytes(v.mem_read(manager+0x130,16))==bytes(16)
        assert events==['dart-tree-lookup','channel-getter']+(['release-tree-node'] if present else [])+['log-result']
    return dict(txm_sha256=TXM_SHA,kernel_sha256=KC_SHA,initializer_platforms=256,
                enabled_platforms=enabled,getter_cases=calls,kernel_cases=3,
                portable_reply=[portable_status,portable_count],
                boundary='native capability/descriptor decisions and unavailable caller return; external queries, translation and IOKit calls are fixtures; no channel execution')


if __name__=='__main__':
    print(json.dumps(replay(sys.argv[1] if len(sys.argv)>1 else str(ROOT/'build/test-txm-sep-channel'))))
