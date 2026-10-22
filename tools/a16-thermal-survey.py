#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded, read-only Glymur TSENS survey on an explicitly idle A16.

Failure inventory and source provenance: docs/OPERATOR-STOP-CONTROLS-20261018.md.
No configuration writes, EC commands, guest boot, heating or control qualification.
"""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import sys
import time
R=Path(__file__).resolve().parents[1]
BLOCKS=tuple((0x0c22c000+0x1000*n,0x0c222000+0x1000*n) for n in range(8))
def allowed_addresses():
    return {a for tm,srot in BLOCKS for a in (srot,srot+4,tm+0xe4,*(tm+0xa0+4*i for i in range(16)))}
def known_version(version):
    # Glymur's exact resources are v2-compatible in mainline glymur.dtsi.
    # Its observed IP identity is 3.2.0; do not admit unknown v3 revisions.
    return version>>28==2 or version==0x30020000

def replay_blocks(blocks):
    result=[]
    for b in blocks:
        complete=all(k in b for k in ('version','control','ready','status_words')) and len(b.get('status_words',[]))==16
        sensors=[]
        if all(k in b for k in ('version','control','ready','status_words')):
            sensors=[decode_sensor(b['version'],b['control'],b['ready'],v,i) for i,v in enumerate(b['status_words'])]
        result.append(dict(index=b['index'],complete=complete,sensors=sensors))
    return result

def decode_sensor(version,control,ready,status,sensor=0):
    why=[]
    if not known_version(version):why.append('unrecognized_version')
    if not control&1:why.append('controller_disabled')
    if control&2:why.append('controller_in_reset')
    if not control&(1<<(sensor+3)):why.append('sensor_disabled')
    if not control&(1<<21):why.append('not_temperature_mode')
    # v2's get_temp_tsens_valid uses per-sensor VALID, even while TRDY=0.
    # The raw TRDY word remains in the capture; it is not a freshness proof.
    if not status&(1<<21):why.append('sample_invalid')
    code=status&0xfff
    signed=code-4096 if code&0x800 else code
    return dict(sensor=sensor,millidegrees_c=None if why else signed*100,refusals=why)
def read_allowed(proxy,address,journal):
    if address not in allowed_addresses():raise ValueError('address outside TSENS read allowlist')
    row=dict(address=hex(address),started=time.time());journal.append(row)
    value=proxy.read32(address)
    row.update(value=value,finished=time.time())
    return value

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device');ap.add_argument('--generation',type=int);ap.add_argument('--image-base',type=lambda s:int(s,0))
    ap.add_argument('--idle',action='store_true',help='assert no guest workload is resident')
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--replay',type=Path)
    args=ap.parse_args()
    if args.output.exists():ap.error('output exists; captures are not overwritten')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    if args.replay:
        old=json.loads(args.replay.read_text());blocks=old['blocks']
        record=dict(scope='offline replay of retained raw status',source=str(args.replay),source_sha256=hashlib.sha256(args.replay.read_bytes()).hexdigest(),blocks=[])
        record['blocks']=replay_blocks(blocks)
        record['capture_status']=old.get('status','UNKNOWN')
        args.output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'result':'REPLAYED','output':str(args.output)}));return 0
    if not (args.idle and args.device and args.generation is not None and args.image_base is not None):ap.error('hardware needs --idle --device --generation --image-base')
    sys.path[:0]=[str(R/'tools'),str(R/'probes')]
    import run
    from cycle_lib.common import Workspace, require_exclusive, need, serror_clear
    require_exclusive(Workspace(R))
    record=dict(scope='read-only idle A16 TSENS survey; no fan, continuous freshness or shutdown qualification',started=time.time(),status='STARTING',mmio_writes=False,blocks=[],reads=[],source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    def save():args.output.write_text(json.dumps(record,indent=2)+'\n')
    with Path('/tmp/snapintosh-hardware.lock').open('a') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        proxy=None
        try:
            proxy=run.connect(args.device,tries=1)
            info=proxy.bootinfo();record['bootinfo']=info
            need(info['stage_generation']==args.generation,'resident generation mismatch')
            need(info['image_base']==args.image_base,'resident image mismatch')
            record['serror_before']=proxy.serror_state();need(serror_clear(record['serror_before']),'preexisting SError')
            def read(a):
                v=read_allowed(proxy,a,record['reads']);err=proxy.serror_state()
                need(serror_clear(err),f'SError reading {a:#x}: {err}')
                save();return v
            for index,(tm,srot) in enumerate(BLOCKS):
                b=dict(index=index,tm=hex(tm),srot=hex(srot));record['blocks'].append(b)
                b['version']=read(srot)
                need(known_version(b['version']),f'unrecognized TSENS block {index} version {b["version"]:#x}')
                b['control']=read(srot+4);b['ready']=read(tm+0xe4);b['status_words']=[];b['sensors']=[]
                for i in range(16):
                    v=read(tm+0xa0+4*i);b['status_words'].append(v);b['sensors'].append(decode_sensor(b['version'],b['control'],b['ready'],v,i))
            record['serror_after']=proxy.serror_state();need(serror_clear(record['serror_after']),'SError after survey')
            valid=[s['millidegrees_c'] for b in record['blocks'] for s in b['sensors'] if s['millidegrees_c'] is not None]
            record.update(status='READ_COMPLETE',valid_sensors=len(valid),maximum_millidegrees_c=max(valid) if valid else None,finished=time.time());save()
            print(json.dumps({k:record[k] for k in ['status','valid_sensors','maximum_millidegrees_c','scope']}));return 0
        except BaseException as e:
            record.update(status='REFUSED_OR_FAILED',error=repr(e),finished=time.time());save();raise
        finally:
            if proxy:proxy.link.close()
if __name__=='__main__':sys.exit(main())
