#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the production NVMe backend for a bounded physical write/read/restore probe."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output',type=Path,required=True)
args=ap.parse_args();out=args.output.resolve();out.mkdir(exist_ok=False)
sources=['tools/nvme-writeback-probe.c','tools/nvme-writeback-probe.ld',
         'compat/nvme-host.c','compat/nvme-host.h','tools/build-nvme-writeback-probe.py']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
hashes={n:sha(ROOT/n) for n in sources};llvm=Path('/opt/homebrew/opt/llvm/bin')
objects=[]
for name in (sources[0],sources[2]):
    obj=out/(Path(name).name+'.o');objects.append(str(obj))
    subprocess.run([str(llvm/'clang'),'--target=aarch64-unknown-none-elf','-O2',
        '-ffreestanding','-fno-builtin','-fno-stack-protector','-fpie',
        '-mgeneral-regs-only','-Wall','-Wextra','-Werror',
        '-I'+str(ROOT/'compat'),'-c',str(ROOT/name),'-o',str(obj)],check=True)
subprocess.run(['ld.lld','-T',str(ROOT/sources[1]),'-o',str(out/'probe.elf'),*objects],check=True)
assert not subprocess.check_output([str(llvm/'llvm-nm'),'-u',str(out/'probe.elf')]).strip()
subprocess.run([str(llvm/'llvm-objcopy'),'-O','binary',str(out/'probe.elf'),str(out/'probe.bin')],check=True)
assert hashes=={n:sha(ROOT/n) for n in sources} and (out/'probe.bin').stat().st_size<0x10000
record=dict(source_sha256=hashes,bytes=(out/'probe.bin').stat().st_size,
    image_sha256=sha(out/'probe.bin'),image_path=str(out/'probe.bin'))
(out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
