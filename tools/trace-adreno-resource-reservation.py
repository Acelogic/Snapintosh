#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture the target kernel's DART reservation, insertion and clear contracts.

Uses the existing UUID-matched original-KC tracer. It does not execute the
methods or establish that a particular hardware capability is enabled.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import runpy
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/trace-adreno-memory-map.py'
spec = importlib.util.spec_from_file_location('adreno_mapping_trace', base)
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)
extra = {
    'AppleT8110DART': (
        '__ZN14AppleT8110DART14setTranslationEP13IODARTVMSpacejPvjjjj',
        '__ZN14AppleT8110DART14setTranslationEP13IODARTVMSpacejPvjjjjjj',
        '__ZN6IODART13dartSPTMUnmapEjjmmy',
    ),
    'IODARTFamily': ('__ZN13IODARTVMSpace13invalidateTLBEjj',),
}
for image, names in extra.items():
    scope, wanted = trace.TARGETS[image]
    trace.TARGETS[image] = (scope, wanted + names)
trace.main()
output = Path(sys.argv[sys.argv.index('--output')+1])
record = json.loads(output.read_text())
functions = {f['symbol']: f for image in record['images'] for f in image['functions']}
def witness(symbol, mnemonic, operands):
    matches = [i for i in functions[symbol]['instructions']
               if i['mnemonic'] == mnemonic and i['operands'] == operands]
    assert len(matches) == 1, (symbol, mnemonic, operands)
    return dict(symbol=symbol, **matches[0])

record['reservation_witnesses'] = [
    witness('__ZN12IODARTMapper13iovmMapMemoryEP18IOMemoryDescriptoryyjPK21IODMAMapSpecificationP12IODMACommandPK16IODMAMapPageListPySA_',
            'cbz', 'x21, #0xfffffe000a7e1520'),
    witness('__ZN12IODARTMapper11_iovmInsertEP13IODARTVMSpacejjjj', 'mov', 'w3, #2'),
    witness('__ZN12IODARTMapper16_iovmInsertBatchEyyyj', 'mov', 'w5, #2'),
    witness('__ZN12IODARTMapper9_iovmFreeEP13IODARTVMSpaceb', 'mov', 'w3, #1'),
    witness('__ZN12IODARTMapper9_iovmFreeEP13IODARTVMSpaceb', 'mov', 'w5, #1'),
]
Cache = runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache']
kc = Cache(ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p',
           scope='com.apple.driver.IODARTFamily')
table = 0xfffffe00079ebc00
access = struct.unpack_from('<4I', kc.data, kc.va2off(table))
assert access == (0, 2, 1, 3)
record['access_table'] = dict(address=hex(table), values=list(access),
    meaning='IOMapper low two permission bits; independent of map2 versus unmap1 operation')
kernel = trace.KDK.parent/'Kernels/kernel.release.t8140'
symbols = {line.split()[-1] for line in subprocess.check_output(
    ['nm', '-arch', 'arm64e', str(kernel)], text=True).splitlines() if line.split()}
legacy = ['_IOMapperIOVMAlloc', '_IOMapperIOVMFree', '_IOMapperInsertPage']
assert not set(legacy) & symbols
record['legacy_c_exports_absent'] = legacy
record['reservation_tracer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
record['reservation_boundary'] = __doc__
output.write_text(json.dumps(record, indent=2)+'\n')
