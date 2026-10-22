#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read APFS checkpoints after a fully captured writable guest and fresh chainload.

The controller is taken over only after the stopped guest evidence is saved.
This verifies on-media checkpoint advancement, not file contents or power loss.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
Q1N1=ROOT.parent/'q1n1'
sys.path.insert(0,str(Q1N1/'tools'))
import nvme_m3 as m3

sha=lambda b:hashlib.sha256(b).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',default='udp://en5')
    ap.add_argument('--prefix',required=True)
    ap.add_argument('--generation',type=int,required=True)
    args=ap.parse_args();assert re.fullmatch('[a-z0-9-]+',args.prefix)
    base=ROOT/'build'/args.prefix
    def artifact(s):return Path(str(base)+s)
    launch=json.loads(artifact('-launch.json').read_text())
    audit=json.loads(artifact('-audit.json').read_text())
    assert launch.get('finished') and '--ans-writable' in launch['arguments']
    assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
    for suffix in ('-kernel-waits.json','-console-tail.json','-panel.png'):
        assert artifact(suffix).exists(),suffix
    mounts_path=next((artifact(s) for s in ('-mounts.json','-nvme-driver.json')
                      if artifact(s).exists()),None)
    assert mounts_path is not None
    mounts=json.loads(mounts_path.read_text())['mounted_volumes']
    assert mounts['complete'] and any(m['target']=='/System/Volumes/Data' for m in mounts['mounts'])
    ans=audit['ans'][0];assert ans['physical_nvme']['state']['writes']>0
    before_path=artifact('-apfs-before.json');before=json.loads(before_path.read_text())
    reference=json.loads((ROOT/'build/nvme-writeback-a16-v1-20260926.json').read_text())
    out=artifact('-persistence.json');assert not out.exists()
    record=dict(result='RUNNING',started=time.time(),prefix=args.prefix,
        before_sha256=sha(before_path.read_bytes()),audit_sha256=sha(artifact('-audit.json').read_bytes()),
        mounts_sha256=sha(mounts_path.read_bytes()),
        source_sha256=sha(Path(__file__).read_bytes()))
    with out.open('x') as f:json.dump(record,f,indent=2)
    proxy=m3.q1n1proxy.connect(args.device);proxy.resume_skip=False
    nv=None;guard=None
    try:
        info=proxy.bootinfo();assert info['current_el']==2 and info['stage_generation']==args.generation
        record['bootinfo']=info
        guard=proxy.serror_state();proxy.serror_reset();proxy.serror_strict(True)
        hw=m3.Hw(proxy);bar,sid=m3.locate(hw,info,record);smmu=m3.Smmu(hw,sid)
        assert smmu.mode in ('bypass','s2')
        window=m3.pick_window(hw,info,smmu,record)
        nv=m3.Nvme(hw,bar,window,record)
        nv.takeover(record);nv.identify(record);nv.io_queues(record)
        first,last=m3.arm_window(nv,'ffea9120-5c2e-47ff-a459-3f645a59654e',record)
        assert (first,last,nv.lba_bytes)==(1170663424,1996187647,512)
        after=runpy.run_path(str(ROOT/'tools/apfs-checkpoints.py'))['capture'](
            nv,first,record['window_armed']['header'],artifact('-apfs-after.json'))
        progression={}
        for name,old in before['containers'].items():
            new=after['containers'][name]
            assert old['uuid']==new['uuid'] and old['blocks']==new['blocks']
            assert new['latest_xid']>=old['latest_xid']
            progression[name]=dict(before=old['latest_xid'],after=new['latest_xid'],
                selected_checkpoint_checksums_valid=new['selected_checkpoint_checksums_valid'])
        assert progression['container']['after']>progression['container']['before']
        record['checkpoint_progression']=progression
        record['edges_after']=[sha(nv.read(lba,n)) for lba,n in reference['edge_ranges']]
        assert record['edges_after']==reference['edges_before']
        record['edges_unchanged']=True
        status=proxy.serror_state();record['serror']={k:status[k] for k in ('before','during','unconsumed')}
        assert not any(record['serror'].values()) and not proxy.get_exc_count()
        record['result']='PASS'
        record['boundary']='Checksummed on-media checkpoints advanced across chainload/controller takeover; no power-loss or file-level/M8 reboot proof.'
    except BaseException as error:
        record['result']='FAIL';record['exception']=repr(error);raise
    finally:
        try:
            if nv:nv.delete_io_queues();nv.shutdown(record)
        except BaseException as error:
            record['result']='FAIL';record['cleanup_exception']=repr(error);raise
        finally:
            if guard is not None:proxy.serror_strict(bool(guard['flags']&m3.q1n1proxy.SERROR_STRICT))
            proxy.link.close();record['finished']=time.time();out.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(output=str(out),result=record['result'],checkpoints=record['checkpoint_progression'])))


if __name__=='__main__':main()
