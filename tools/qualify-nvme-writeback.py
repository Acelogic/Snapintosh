#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A16 E2E: production C writes/flushes, independent SSD reads and exact restoration.

Uses only the unused range after the provisioned APFS image, with a saved original.
The same q1n1 controller owns the queues throughout; no guest runs concurrently.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
Q1N1=ROOT.parent/'q1n1'
sys.path[:0]=[str(ROOT/'probes'),str(Q1N1/'tools')]
import nvme_m3 as m3
import answindow
import stagebind

sha=lambda b:hashlib.sha256(b).hexdigest()


def place(hw,info,binary,stage_builds=()):
    # The resident stage, bound by its text to the local build it came from (probes/stagebind.py).
    stage=stagebind.bind(hw.read,info,stage_builds)
    slot,end=stage['slot'],stage['allocated_end']
    code=info['image_base']+slot-0x10000
    assert end<=code and len(binary)<0x10000
    leaf=bytes.fromhex('000080d2c0035fd6')
    hw.write(code,leaf);hw.p.flush_code(code,len(leaf));hw.p.set_exc_guard(3)
    try:
        assert hw.p.call(code,timeout=3)==0 and hw.p.get_exc_count()==0
    finally:hw.p.set_exc_guard(0)
    hw.write(code,binary);hw.p.flush_code(code,len(binary))
    assert hw.read(code,len(binary))==binary
    return code,dict(code=hex(code),stage_allocated_end=hex(end),
        stage_elf_sha256=stage['elf_sha256'],stage_text_sha256=stage['resident_text_sha256'],
        stage_build=str(stage['build']),stage_bin_sha256=stage['bin_sha256'],leaf_passed=True)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',default='udp://en5')
    ap.add_argument('--generation',type=int,required=True)
    ap.add_argument('--build',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--stage-build',type=Path,action='append',default=[],
                    help='q1n1 build/uefi of a resident stage pair other than ../q1n1 (probes/stagebind.py)')
    args=ap.parse_args();out=args.output.resolve()
    assert not out.exists()
    build=json.loads(args.build.read_text())
    for name,digest in build['source_sha256'].items():assert sha((ROOT/name).read_bytes())==digest,name
    binary=Path(build['image_path']).read_bytes();assert sha(binary)==build['image_sha256']
    record=dict(result='RUNNING',started=time.time(),build=build,transactions=[],
        qualifier_sha256=sha(Path(__file__).read_bytes()),stagebind_sha256=sha((ROOT/'probes/stagebind.py').read_bytes()),
        q1n1_sources={n:sha((Q1N1/'tools'/n).read_bytes()) for n in ['nvme_m3.py','q1n1proxy.py']})
    with out.open('x') as f:json.dump(record,f,indent=2)
    def save():out.write_text(json.dumps(record,indent=2)+'\n')
    proxy=m3.q1n1proxy.connect(args.device);proxy.resume_skip=False
    guard=None;nv=None;original=None;changed=False;state=[0]*20;restored=False
    try:
        info=proxy.bootinfo();assert info['stage_generation']==args.generation and info['current_el']==2
        record['bootinfo']=info
        guard=proxy.serror_state();proxy.serror_reset();proxy.serror_strict(True)
        hw=m3.Hw(proxy);bar,sid=m3.locate(hw,info,record);smmu=m3.Smmu(hw,sid)
        assert smmu.mode in ('bypass','s2')
        window=m3.pick_window(hw,info,smmu,record)
        m3.given_window(hw,info,smmu,window,m3.ADOPT_LAYOUT,record)
        nv=m3.Nvme(hw,bar,window,record,m3.ADOPT_LAYOUT)
        nv.takeover(record);nv.identify(record);nv.features(record);nv.io_queues(record)
        first,last=m3.arm_window(nv,'ffea9120-5c2e-47ff-a459-3f645a59654e',record)
        assert (first,last,nv.lba_bytes)==(1170663424,1996187647,512)
        header=nv.read(first+1024,8)
        assert sha(header)=='9975a1bf344b27c5b0be48d62967e71defcc4c63159caf93359fbfc1606f2a3c'
        h=record['window_armed']['header']
        image_end=first*512+h['container_offset']+h['container_image']
        scratch=((image_end+(1<<20)-1)&~((1<<20)-1))+(1<<20)
        size=128<<10
        assert image_end<scratch-4096 and scratch+size+4096<(last+1)*512-(1<<20)
        original=nv.read(scratch//512,size//512)
        backup=out.with_suffix('.original.bin')
        with backup.open('xb') as f:f.write(original);f.flush();os.fsync(f.fileno())
        record['scratch']=dict(lba=scratch//512,bytes=size,original_sha256=sha(original),
            backup=str(backup),outside_provisioned_image=True)
        guard_ranges=[(0,2048),(nv.nsze-2048,2048),(first-8,8),(last+1,8),
                      (scratch//512-8,8),((scratch+size)//512,8),(first+1024,8)]
        def edges():return [sha(nv.read(lba,count)) for lba,count in guard_ranges]
        original_edges=edges();record['edge_ranges']=guard_ranges;record['edges_before']=original_edges
        code,placement=place(hw,info,binary,args.stage_build);record['placement']=placement
        control=window+0x60000
        params=[3,bar,nv.stride,window,nv.io.tail,nv.io.head,nv.io.phase,nv.io.next_cid,
            512,first,last,min(nv.max_transfer,128<<10),5*info['timer_hz'],
            scratch//512,(scratch+size)//512-1,0]
        record['params']=params;save()
        def call(action,lba=0,count=0,at=0,expected=0):
            assert not nv.io.outstanding and not nv.admin.outstanding
            state[2:6]=[nv.io.tail,nv.io.head,nv.io.phase,nv.io.next_cid]
            raw=struct.pack('<39Q',*params,*state,lba,count,at)
            hw.write(control,raw)
            result=proxy.call(code,control,action,timeout=10)
            result=result-(1<<64) if result>>63 else result
            after=hw.read(control,len(raw));assert after[:128]==raw[:128]
            state[:]=struct.unpack_from('<20Q',after,128)
            nv.io.tail,nv.io.head,nv.io.phase,nv.io.next_cid=state[2:6]
            record['transactions'].append(dict(action=action,lba=lba,count=count,at=at,
                result=result,state=dict(zip(answindow.NVMEH_STATE_FIELDS,state))))
            save()
            assert result==expected,(action,result,expected)
        call(0)
        wlba=scratch//512-first
        params[0]=1;call(1,wlba,8,expected=-88);params[0]=3
        for lba,count,at in [(wlba-1,8,0),(wlba+size//512-1,2,0),
                              (wlba,0,0),(wlba,257,0),(wlba,16,0x1f000)]:
            call(1,lba,count,at,expected=-84)
        assert state[16]==0 and nv.read(scratch//512,size//512)==original
        try:
            #96 operations plus independent reads cross the64-entry CQ several times.
            for i in range(33):
                n=(8,16,256)[i%3];pattern=hashlib.shake_256(b'Snapintosh M7 '+str(i).encode()).digest(n*512)
                hw.write(window+0x10000,pattern);changed=True
                call(1,wlba,n);call(3)
                hw.write(window+0x10000,bytes(n*512));call(2,wlba,n)
                assert hw.read(window+0x10000,n*512)==pattern
                assert nv.read(scratch//512,n)==pattern
                record.setdefault('patterns',[]).append(dict(index=i,bytes=n*512,sha256=sha(pattern)))
                save()
            record['qualification_passed']=True
        finally:
            if changed and not state[0]&2:
                hw.write(window+0x10000,original);call(1,wlba,size//512);call(3)
                restored=nv.read(scratch//512,size//512)==original
                record['scratch_restored']=restored;save()
                assert restored,'scratch restoration differs'
        record['edges_after']=edges();assert record['edges_after']==original_edges
        assert restored and not any(state[i] for i in (8,9))
        record['physical_state']=dict(zip(answindow.NVMEH_STATE_FIELDS,state))
        record['exceptions']=proxy.get_exc_count();assert not record['exceptions']
        status=proxy.serror_state();record['serror']={k:status[k] for k in ('before','during','unconsumed')}
        assert not any(record['serror'].values())
        record['result']='PASS'
    except BaseException as error:
        record['result']='FAIL';record['exception']=repr(error);save();raise
    finally:
        try:
            if nv:
                if not state[0]&2:nv.delete_io_queues()
                nv.shutdown(record)
        except BaseException as error:
            record['result']='FAIL';record['cleanup_exception']=repr(error);raise
        finally:
            if guard is not None:proxy.serror_strict(bool(guard['flags']&m3.q1n1proxy.SERROR_STRICT))
            proxy.link.close();record['finished']=time.time();save()
    print(json.dumps(dict(output=str(out),result=record['result'],scratch_restored=restored,
        physical_state=record['physical_state'],boundary='Physical component qualification; no guest boot or power-loss test.')))


if __name__=='__main__':main()
