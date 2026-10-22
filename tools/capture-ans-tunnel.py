#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture the exact refused native NVMe tunnel transaction without resuming it.

Failure inventory: stale guest/monitor, wrong CID, speculative payload lengths,
unregistered physical addresses, and overwritten prior evidence. Bind source,
monitor and stop token; require one mapped D8 matching the recorded refusal;
bound every saved buffer by a live SART region and a1MiB diagnostic cap.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import ansstate
import run
from monitor_layout import MonitorLayout
sha=lambda b:hashlib.sha256(b).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--device',default='udp://en5')
    ap.add_argument('--prefix',required=True);args=ap.parse_args()
    assert re.fullmatch('[a-z0-9-]+',args.prefix)
    base=ROOT/'build'/args.prefix
    path=lambda s:Path(str(base)+s)
    out=path('-ans-tunnel.json');assert not out.exists()
    launch=json.loads(path('-launch.json').read_text());audit=json.loads(path('-audit.json').read_text())
    recorded=json.loads(path('-ans.json').read_text())
    assert launch.get('finished') and launch['exit_code']==7 and audit['runtime_stop_qualified']
    assert recorded['state']['refusal']['reason']=='sart'
    for name,digest in launch['source_sha256'].items():assert sha((ROOT/name).read_bytes())==digest,name
    blob=(ROOT/'build/xnuboot.bin').read_bytes();assert sha(blob)==launch['monitor_sha256']==audit['monitor_sha256']
    proxy=run.connect(args.device,tries=1)
    try:
        def read(pa,size):
            return b''.join(proxy.readmem(pa+i,min(65536,size-i),live=True) for i in range(0,size,65536))
        info=proxy.bootinfo();work,_=run.resident_work(proxy,info);layout=MonitorLayout()
        stop_pa=work+layout.offset('context','services');stop=struct.pack('<8Q',*audit['service'])
        assert read(stop_pa,64)==stop and read(info['heap_base']+run.CODE_AT,len(blob))==blob
        raw=read(recorded['reservation'][0],ansstate.SIZE);state=ansstate.decode(raw)
        assert state==recorded['state']
        regions=[dict(zip(('pa','size','perm','guard'),struct.unpack_from('<2Q2I',raw,ansstate.OFFSETS['sart']+24*i)))
                 for i in range(ansstate.SART_REGIONS)]
        regions=[r for r in regions if r['size']]
        commands=[]
        for cid in range(ansstate.CIDS):
            at=ansstate.OFFSETS['cid']+ansstate.CID_SIZE*cid
            if raw[at:at+2]!=b'\x03\x00':continue
            q=struct.unpack('<16I',read(state['asq']+cid*64,64))
            if q[0]&255==0xd8 and (q[11]|q[12]<<32)==state['refusal']['a']:
                assert q[0]>>16==cid
                commands.append((cid,q))
        assert len(commands)==1;cid,q=commands[0]
        record=dict(monitor_sha256=sha(blob),bootinfo=info,source_bound=True,service=audit['service'],
            cid=cid,sqe=[hex(v) for v in q],regions=regions,buffers={})
        for name,pa,size in [('command',q[11]|q[12]<<32,4096),('data',q[13]|q[14]<<32,q[15])]:
            if not pa and not size:continue
            assert 0<size<=1<<20 and any(pa>=r['pa'] and size<=r['size'] and pa-r['pa']<=r['size']-size for r in regions),(name,hex(pa),size)
            data=read(pa,size);f=path('-ans-tunnel-'+name+'.bin');assert not f.exists()
            f.write_bytes(data);record['buffers'][name]=dict(pa=hex(pa),bytes=size,sha256=sha(data),file=str(f))
            if name=='command':record['subcommand']=struct.unpack_from('<I',data,0xc)[0]
        assert read(stop_pa,64)==stop
        record['boundary']='Stopped input capture only; no command emulation, SSD change or guest resume.'
        out.write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps(dict(output=str(out),cid=cid,subcommand=hex(record['subcommand']),buffers=record['buffers'])))
    finally:proxy.link.close()


if __name__=='__main__':main()
