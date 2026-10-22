#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline production replay from a retained A16 sensor capture; no hardware."""
import argparse,hashlib,json,struct,subprocess,sys
from pathlib import Path
R=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--capture',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
j=json.loads(a.capture.read_text());words=[v for b in j['blocks'] for v in [b['version'],b['control'],b['ready'],*b['status_words']]]
assert j['status']=='READ_COMPLETE' and len(words)==152
(a.output/'sensors.bin').write_bytes(struct.pack('<152I',*words))
cmd=['clang','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-Icompat','-Ishadow','tools/test-a16-thermal-guard.c','compat/a16-thermal.c','compat/early-stop.c','compat/service-lock.c','-o',str(a.output.resolve()/'replay')]
b=subprocess.run(cmd,cwd=R,capture_output=True,text=True);(a.output/'build.log').write_text(b.stdout+b.stderr)
r=subprocess.run([str(a.output.resolve()/'replay'),str(a.output.resolve()/'sensors.bin')],cwd=R,capture_output=True,text=True) if b.returncode==0 else b
(a.output/'run.log').write_text(r.stdout+r.stderr)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files=['compat/a16-thermal.c','compat/a16-thermal.h','compat/early-stop.c','compat/early-stop.h','compat/service-lock.c','compat/service-lock.h','tools/test-a16-thermal-guard.c','tools/test-a16-thermal-guard.py']
record=dict(result='PASS' if r.returncode==0 else 'FAIL',exit_code=r.returncode,scope='offline production sensor-to-service-stop replay; no sensor or guest timer hardware proof',command=cmd,capture_sha256=sha(a.capture),source_sha256={f:sha(R/f) for f in files if (R/f).exists()},artifacts_sha256={p.name:sha(p) for p in a.output.iterdir() if p.is_file()})
(a.output/'receipt.json').write_text(json.dumps(record,indent=2)+'\n');print(r.stdout+r.stderr);sys.exit(r.returncode)
