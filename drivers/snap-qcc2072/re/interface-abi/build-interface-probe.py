#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and link an offline, uninstantiated ABI probe; no kext bundle is made."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
from evidence_guard import start_phase, write_new_text

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
HERE = args.out.resolve()
start_phase(HERE, 'build', ['offline-interface-abi-probe.o','offline-interface-abi-probe',
                          'compile.log','link.log','build-receipt.json'])
sdk = subprocess.check_output(['/usr/bin/xcrun', '--show-sdk-path'], text=True).strip()
kh = sdk + '/System/Library/Frameworks/Kernel.framework/Headers'
commands = [
    ['/usr/bin/xcrun', 'clang++', '-target', 'arm64e-apple-macos27.0', '-isysroot', sdk,
     '-mkernel', '-nostdinc', '-I'+kh, '-DKERNEL', '-DAPPLE', '-DNeXT',
     '-O2', '-g', '-Wall', '-Wextra', '-Werror',
     '-Wno-inconsistent-missing-override', '-Wno-deprecated-declarations',
     '-std=gnu++17', '-fapple-kext', '-fno-exceptions', '-fno-rtti',
     '-ferror-limit=12', '-c', str(HERE/'offline-interface-abi-probe.cpp'),
     '-o', str(HERE/'offline-interface-abi-probe.o')],
    ['/usr/bin/xcrun', 'clang++', '-target', 'arm64e-apple-macos27.0', '-isysroot', sdk,
     '-mkernel', '-nostdlib', '-Xlinker', '-kext', '-Xlinker', '-export_dynamic',
     str(HERE/'offline-interface-abi-probe.o'), '-L'+sdk+'/usr/lib',
     '-lkmodc++', '-lkmod', '-lcc_kext',
     '-o', str(HERE/'offline-interface-abi-probe')],
]
receipt = []
for i, command in enumerate(commands):
    result = subprocess.run(command, capture_output=True, text=True)
    log = HERE/('compile.log' if i == 0 else 'link.log')
    write_new_text(log, result.stdout + result.stderr)
    receipt.append({'argv': command, 'exit': result.returncode, 'log': str(log)})
    if result.returncode:
        write_new_text(HERE/'build-receipt.json', json.dumps(receipt,indent=2)+'\n')
        print(result.stderr[-5500:])
        sys.exit(result.returncode)
write_new_text(HERE/'build-receipt.json', json.dumps(receipt,indent=2)+'\n')
binary = HERE/'offline-interface-abi-probe'
print('OFFLINE_PROBE_LINKED', hashlib.sha256(binary.read_bytes()).hexdigest())
