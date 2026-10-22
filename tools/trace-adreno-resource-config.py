#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture native IOGPU config defaults and Apple's paravirtual config reference."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('config_trace', ROOT/'tools/trace-adreno-memory-map.py')
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)
trace.TARGETS = {'IOGPUFamily': ('com.apple.iokit.IOGPUFamily', (
    '__ZN5IOGPU25initializeConfigStructureEv',
))}
trace.FIXED_PATH_WITNESSES = {}
trace.main()
output = Path(sys.argv[sys.argv.index('--output') + 1])
record = json.loads(output.read_text())
path = trace.KDK/'AppleParavirtGPUIOGPUFamily.kext/Contents/MacOS/AppleParavirtGPUIOGPUFamily'
raw = path.read_bytes()
if raw[:4] == b'\xcf\xfa\xed\xfe':
    thin = raw
else:
    slices = [struct.unpack_from('>5I', raw, 8+i*20)
              for i in range(struct.unpack_from('>I', raw, 4)[0])]
    _, _, offset, length, _ = next(v for v in slices if v[0] == 0x100000c and v[1]&0xffffff == 2)
    thin = raw[offset:offset+length]
symbols = []
for line in subprocess.check_output(['nm', '-arch', 'arm64e', '-n', str(path)], text=True).splitlines():
    parts = line.split()
    if len(parts) == 3:
        try:
            symbols.append((int(parts[0], 16), parts[2]))
        except ValueError:
            pass
name = '__ZN16AppleParavirtGPU19populateAccelConfigEP11IOGPUConfig'
start, = [va for va, symbol in symbols if symbol == name]
end = min(va for va, _ in symbols if va > start)
at = 32
file_offset = None
for _ in range(struct.unpack_from('<I', thin, 16)[0]):
    cmd, size = struct.unpack_from('<II', thin, at)
    if cmd == 0x19:
        va, length, off, file_size = struct.unpack_from('<4Q', thin, at+24)
        if va <= start < end <= va+file_size:
            file_offset = off+start-va
    at += size
assert file_offset is not None
code = thin[file_offset:file_offset+end-start]
md = trace.capstone.Cs(trace.capstone.CS_ARCH_ARM64, trace.capstone.CS_MODE_ARM)
record['paravirt_reference'] = {
    'path': str(path), 'thin_sha256': hashlib.sha256(thin).hexdigest(),
    'symbol': name, 'address': hex(start), 'bytes_hex': code.hex(),
    'instructions': [{'address': hex(i.address), 'mnemonic': i.mnemonic, 'operands': i.op_str}
                     for i in md.disasm(code, start)],
    'boundary': 'KDK implementation reference; not code installed in the J700 guest.'}
record['config_tracer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
output.write_text(json.dumps(record, indent=2)+'\n')
