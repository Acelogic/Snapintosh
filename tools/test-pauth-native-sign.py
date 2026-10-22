#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Sign-only built-instruction replay; modeled PAC/sysregs, no hardware claim."""
from pathlib import Path
import argparse
import hashlib
import itertools
import json
import runpy

ROOT=Path(__file__).resolve().parents[1]

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    helper=runpy.run_path(str(ROOT/'tools/test-pauth-native.py'))
    run,test_case,cfg=helper['run'],helper['test_case'],helper['CFG']
    blob=run.build('pauth-sign-address',out/'probe')
    inputs=(0,1,0x1cf5382f0,(1<<47)-1,1<<47,1<<55,1<<56,
            0xe0fc8b839d03516b,0xffffffffffffffff)
    default=[0xe0fc8b839d03516b,0xb743,0x0123456789abcdef,0xfedcba9876543210,2,1,1]
    cases=0
    for key,tbi,tbid,pointer,t0sz in itertools.product(range(4),range(2),range(2),inputs,(17,20,24)):
        request=default.copy();request[0],request[4],request[5],request[6]=pointer,key,tbi,tbid
        test_case(blob,request,{'tcr_el2':(cfg['tcr_el2']&~63)|t0sz},raw_sign=True);cases+=1
    for override in ({'currentel':4},{'hcr_el2':1<<34},{'sctlr_el2':0},
                     {'tcr_el2':0x14|(1<<14)},{'tcr_el2':16},{'tcr_el2':25},
                     {'id_aa64isar1_el1':0,'id_aa64isar2_el1':0}):
        test_case(blob,default,override,rejected=True,raw_sign=True);cases+=1
    for index,value in ((4,4),(4,1<<63),(5,2),(6,2),(5,1<<63),(6,1<<63)):
        request=default.copy();request[index]=value
        test_case(blob,request,rejected=True,raw_sign=True);cases+=1
    for key in range(4):
        request=default.copy();request[4]=key
        for field in ('tcr_el2','sctlr_el2',helper['KEYS'][key]+'keylo_el1',helper['KEYS'][key]+'keyhi_el1'):
            test_case(blob,request,corrupt_read=field,raw_sign=True);cases+=1
    test_case(blob,default,inspect=True,raw_sign=True);cases+=1
    result=dict(status='RAW_SIGN_INSTRUCTION_MODEL_PASS',cases=cases,probe_bytes=len(blob),
        probe_sha256=hashlib.sha256(blob).hexdigest(),boundary=__doc__)
    (out/'replay.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

if __name__=='__main__':main()
