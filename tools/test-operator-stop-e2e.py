#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay host wire encoding through both production stop latches, offline only."""
import argparse, hashlib, importlib.util, json, subprocess, sys
from pathlib import Path
R=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
spec=importlib.util.spec_from_file_location('request_stop',R/'tools/request-stop.py');rs=importlib.util.module_from_spec(spec);spec.loader.exec_module(rs)
for name,nonce,session,delay in [('urgent',2,0x5eed5eed12345678,0),('delayed',1,0x5eed5eed12345678,120),('stale',3,0x5eed5eed12345679,0)]:
    (a.output/(name+'.bin')).write_bytes(rs.encode(rs.STOP,nonce,session,1,delay,name))
files=['tools/test-operator-stop-e2e.c','compat/early-stop.c','compat/early-stop.h','compat/service-lock.c','compat/service-lock.h','tools/request-stop.py','../q1n1/platform/uefi/call-service.c','../q1n1/platform/uefi/call-service.h']
cmd=['clang','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-Icompat','-Ishadow','-I../q1n1/platform/uefi','tools/test-operator-stop-e2e.c','compat/early-stop.c','compat/service-lock.c','../q1n1/platform/uefi/call-service.c','-o',str(a.output.resolve()/'replay')]
b=subprocess.run(cmd,cwd=R,text=True,capture_output=True,timeout=60);(a.output/'build.log').write_text(b.stdout+b.stderr)
r=subprocess.run([str(a.output.resolve()/'replay'),str(a.output.resolve())],cwd=R,text=True,capture_output=True,timeout=30) if b.returncode==0 else b
(a.output/'run.log').write_text(r.stdout+r.stderr)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
receipt={'result':'PASS' if r.returncode==0 else 'FAIL','scope':'offline production transport-to-monitor-stop replay; no hardware timer or quiescence proof','exit_code':r.returncode,'command':cmd,'source_sha256':{f:sha(R/f) for f in files},'artifacts':{p.name:sha(p) for p in a.output.iterdir() if p.is_file()}}
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(r.stdout+r.stderr);print(json.dumps({'result':receipt['result'],'receipt':str(a.output/'receipt.json')}));sys.exit(r.returncode)
