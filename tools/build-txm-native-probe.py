#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the production-adapter E2E probe into a new, source-bound directory."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output',type=Path,required=True)
args=ap.parse_args()
out=args.output.resolve();out.mkdir(exist_ok=False)
sources=['tools/txm-native-probe.S','tools/txm-native-probe.c','tools/txm-native-probe.ld',
         'compat/txm-native.c','compat/txm-native.h','tools/build-txm-native-probe.py']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
hashes={name:sha(ROOT/name) for name in sources}
llvm=Path('/opt/homebrew/opt/llvm/bin')
objects=[]
for name in (sources[0],sources[1],sources[3]):
    obj=out/(Path(name).name+'.o');objects.append(str(obj))
    subprocess.run([str(llvm/'clang'),'--target=aarch64-unknown-none-elf','-O2',
        '-ffreestanding','-fno-builtin',*(['-mgeneral-regs-only'] if name.endswith('.c') else []),
        '-Wall','-Wextra','-Werror',
        '-I'+str(ROOT/'compat'),'-c',str(ROOT/name),'-o',str(obj)],check=True)
subprocess.run(['ld.lld','-T',str(ROOT/sources[2]),'-o',str(out/'probe.elf'),*objects],check=True)
subprocess.run([str(llvm/'llvm-objcopy'),'-O','binary',str(out/'probe.elf'),str(out/'probe.bin')],check=True)
assert hashes=={name:sha(ROOT/name) for name in sources}
assert (out/'probe.bin').stat().st_size<0x10000
record=dict(source_sha256=hashes,base='0xb0780000',bytes=(out/'probe.bin').stat().st_size,
            image_sha256=sha(out/'probe.bin'),image_path=str(out/'probe.bin'))
(out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
