#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross-build the native-qualified SKS wire model without changing a runtime."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

ROOT=Path(__file__).resolve().parents[1]
LLVM=Path('/opt/homebrew/opt/llvm/bin')
LLD=Path('/opt/homebrew/opt/lld/bin/ld.lld')
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();out=args.output_dir.resolve();out.mkdir(exist_ok=False)
    qualification=ROOT/'build/sks-startup-model-20260928-v1/qualification.json'
    expected='3557a6e9a62731dda42ad0455aa386a580028b9f8260ee883dea737ba57fd59c'
    assert sha(qualification)==expected
    inputs=json.loads(qualification.read_text())['source_sha256']
    for path,digest in inputs.items():assert sha(path)==digest,path
    record=dict(status='RUNNING',hardware_access=False,qualification_sha256=expected,
        producer_sha256=sha(__file__),inputs_sha256=inputs,commands=[],artifacts={})
    try:
        crypto=ROOT.parent/'q1n1/platform/uefi'
        common=[str(LLVM/'clang'),'--target=aarch64-none-elf','-march=armv8-a',
            '-mgeneral-regs-only','-ffreestanding','-O2','-fno-stack-protector',
            '-Wall','-Wextra','-Werror','-I'+str(crypto),'-c']
        commands=[common+[str(ROOT/'compat/sep-sks.c'),'-o',str(out/'sep-sks.o')],
            common+[str(crypto/'sha256.c'),'-o',str(out/'sha256.o')],
            [str(LLD),'-r',str(out/'sep-sks.o'),str(out/'sha256.o'),'-o',str(out/'sks-wire.o')]]
        for i,command in enumerate(commands):
            result=subprocess.run(command,text=True,capture_output=True)
            log=out/f'build-{i}.log';log.write_text(result.stdout+result.stderr)
            record['commands'].append(dict(command=command,exit=result.returncode,log_sha256=sha(log)))
            assert result.returncode==0,result.stderr
        undefined=subprocess.check_output([str(LLVM/'llvm-nm'),'--undefined-only',str(out/'sks-wire.o')],text=True)
        assert not undefined.strip(),undefined
        header=subprocess.check_output([str(LLVM/'llvm-readelf'),'-h',str(out/'sks-wire.o')],text=True)
        assert 'AArch64' in header and 'little endian' in header
        (out/'elf-header.txt').write_text(header)
        assembly=subprocess.check_output([str(LLVM/'llvm-objdump'),'-d',str(out/'sks-wire.o')],text=True)
        (out/'disassembly.txt').write_text(assembly)
        for name in ['sep-sks.o','sha256.o','sks-wire.o','elf-header.txt','disassembly.txt']:
            record['artifacts'][name]=dict(bytes=(out/name).stat().st_size,sha256=sha(out/name))
        record.update(status='SKS_WIRE_FREESTANDING_ARM64_BUILD_QUALIFIED',undefined_symbols=[],
            boundary='Relocatable freestanding AArch64 model and crypto only; not linked into, advertised by, or run on the A16 monitor.')
    except Exception as error:
        record.update(status='FAILED',error=repr(error));raise
    finally:
        (out/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],output=str(out/'qualification.json'),
        sha256=sha(out/'qualification.json'))))


if __name__=='__main__':main()
