#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind a resource kext to UUID-matched 26A428 virtual-call contracts.

Static artifact qualification only; native resource allocation and GPU execution
still require an A16 run. Failure inventory: ADRENO-KEXT-RESOURCE-LIFETIME-20260926.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
KDK = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library')
sha = lambda data: hashlib.sha256(data).hexdigest()


def macho(path):
    raw = path.read_bytes()
    if raw[:4] != b'\xcf\xfa\xed\xfe':
        slices = [struct.unpack_from('>5I', raw, 8+i*20)
                  for i in range(struct.unpack_from('>I', raw, 4)[0])]
        _, _, offset, length, _ = next(s for s in slices if s[0] == 0x100000c and s[1]&0xffffff == 2)
        raw = raw[offset:offset+length]
    symbols = {}
    for line in subprocess.check_output(['nm', '-arch', 'arm64e', '-n', str(path)], text=True).splitlines():
        fields = line.split()
        if len(fields) == 3:
            try: symbols[fields[2]] = int(fields[0], 16)
            except ValueError: pass
    segments = []
    at = 32
    for _ in range(struct.unpack_from('<I', raw, 16)[0]):
        command, length = struct.unpack_from('<II', raw, at)
        if command == 0x19:
            name, va, span, offset, _ = struct.unpack_from('<16sQQQQ', raw, at+8)
            segments.append((va, span, offset, name.rstrip(b'\0')))
        at += length
    def word(va):
        start, _, offset, _ = next(s for s in segments if s[0] <= va < s[0]+s[1])
        return struct.unpack_from('<Q', raw, offset+va-start)[0]
    return raw, symbols, segments, word


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--native', type=Path, required=True)
    ap.add_argument('--disassembly', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--cache', action='store_true', help='Require the additional cache-maintenance HVC')
    args = ap.parse_args()
    assert not args.output.exists()
    binary = args.bundle/'Contents/MacOS/AdrenoX2'
    subprocess.run(['codesign', '--verify', '--strict', str(args.bundle)], check=True, capture_output=True)
    text = subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-objdump', '--macho',
        '--disassemble', '--no-show-raw-insn', str(binary)], text=True)
    assert text.splitlines()[1:] == args.disassembly.read_text().splitlines()[1:]
    parts, name = {}, None
    for line in text.splitlines():
        if line.startswith('__') and line.endswith(':'):
            name = line[:-1]; parts[name] = []
        elif name: parts[name].append(line)
    has = lambda pattern, rows: any(re.search(pattern, row) for row in rows)
    native = json.loads(args.native.read_text())
    images = {im['image']: im for im in native['images']}
    expected = {'kernel': 'f9f468d7-1f50-354a-becd-6bd6c1c834ad',
                'IOGPUFamily': '6172533f-b127-35e2-90b8-f7b3b1f2c5b7',
                'IODARTFamily': 'e3a7454c-7b0a-3e41-8a5f-ae53e02329e0'}
    parsed = {}
    for image, uuid in expected.items():
        path = (KDK/'Kernels/kernel.release.t8140' if image == 'kernel' else
                KDK/f'Extensions/{image}.kext/Contents/MacOS/{image}')
        parsed[image] = macho(path)
        assert images[image]['uuid'] == uuid
        assert images[image]['kdk_sha256'] == sha(parsed[image][0])
    def rows(suffix):
        return parts['__ZN15AdrenoMemoryMap'+suffix]
    prepare = parts['__ZN19AdrenoAcceleratorX215prepareStampDMAEv']
    release = parts['__ZN19AdrenoAcceleratorX215releaseStampDMAEv']
    # Every entry binds the actual compiled call to a native vtable target and PAC signature.
    specs = [
        ('kernel', 'IODMACommand', 0x148, 0x0b91, 'setMemoryDescriptor', prepare),
        ('kernel', 'IODMACommand', 0x150, 0x9c32, 'clearMemoryDescriptor', release),
        ('kernel', 'IODMACommand', 0x160, 0xfc62, 'prepare', prepare),
        ('kernel', 'IODMACommand', 0x168, 0xe812, 'complete', release),
        ('kernel', 'IODMACommand', 0x178, 0x3968, 'genIOVMSegments', prepare),
        ('kernel', 'IODMACommand', 0x190, 0xc447, 'getPreparedOffsetAndLength', prepare),
        ('kernel', 'IOBufferMemoryDescriptor', 0x218, 0xf5b3, 'prepare', prepare),
        ('kernel', 'IOBufferMemoryDescriptor', 0x220, 0x9285, 'complete', release),
        ('kernel', 'IORangeAllocator', 0x178, 0x9a37, 'allocateRange', prepare),
        ('kernel', 'IORangeAllocator', 0x180, 0x39af, 'deallocate', release),
        ('IODARTFamily', 'IODARTMapper', 0x890, 0x2b52, 'iovmMapMemory', rows('12reservePagesEPvyPyS1_')),
        ('IODARTFamily', 'IODARTMapper', 0x898, 0x3a52, 'iovmUnmapMemory', rows('9freePagesEPvyy')),
        ('IODARTFamily', 'IODARTMapper', 0x8a0, 0x9276, 'iovmInsert', rows('10insertPageEPvyyyy')),
        ('kernel', 'IOMemoryDescriptor', 0x1f0, 0xb392, 'getLength', rows('10pinBackingEPv')),
        ('kernel', 'IOGeneralMemoryDescriptor', 0x218, 0xf5b3, 'prepare', rows('10pinBackingEPv')),
        ('kernel', 'IOGeneralMemoryDescriptor', 0x220, 0x9285, 'complete', rows('12unpinBackingEPv')),
        ('kernel', 'IOGeneralMemoryDescriptor', 0x158, 0x649a, 'getPhysicalSegment', rows('12physicalPageEPvyPy')),
        ('IOGPUFamily', 'IOGPUMemory', 0x1a0, 0x5223, 'get_iomd_ptr', rows('10pinBackingEPv')),
        ('IOGPUFamily', 'IOGPUMemoryMap', 0x158, 0x31a9, 'getGPUVirtualAddress', rows('22allocGPUVirtualAddressEv')),
        ('IOGPUFamily', 'IOGPUMemoryMap', 0x178, 0x2940, 'reserveGPUVirtualAddress', rows('22allocGPUVirtualAddressEv')),
        ('IOGPUFamily', 'IOGPUMemoryMap', 0x180, 0x89eb, 'freeGPUVirtualAddress', rows('14releaseAddressEv')),
        ('IOGPUFamily', 'IOGPUMemoryMap', 0x188, 0x50de, 'getLength', rows('22allocGPUVirtualAddressEv')),
    ]
    abi = []
    for image, cls, slot, disc, method, code in specs:
        raw, symbols, segments, word_at = parsed[image]
        word = word_at(symbols[f'__ZTV{len(cls)}{cls}']+16+slot)
        base = next(s[0] for s in segments if s[3] == b'__TEXT')
        target = base+(word & 0xffffffff)
        names = [name for name, va in symbols.items() if va == target]
        assert any(method in name for name in names), (cls, method, names)
        assert (word >> 32)&0xffff == disc, (cls, method, hex(word))
        call = next(i for i, row in enumerate(code)
                    if re.search(r'movk\s+x(?:16|17), #'+hex(disc)+r', lsl #48', row))
        # Qualified base calls load the named vtable including its two-word
        # header; ordinary virtual calls start from the object's address point.
        compiled_slot = slot+16 if cls == 'IOGPUMemoryMap' else slot
        if cls == 'IOGPUMemoryMap':
            assert any('literal pool symbol address: __ZTV14IOGPUMemoryMap' in row for row in code)
        assert has(r'#'+hex(compiled_slot)+r'(?:\]|$)', code[max(0, call-20):call]), (cls, method, 'slot')
        abi.append(dict(image=image, cls=cls, method=method, slot=hex(slot),
                        discriminator=hex(disc), native_target=hex(target), symbols=names))
    _, syms, _, word_at = macho(binary)
    vtable = syms['__ZTV15AdrenoMemoryMap']+16
    callbacks = []
    for slot, disc, suffix in [(46,0x96f0,'22allocGPUVirtualAddressEv'),
        (47,0x2940,'24reserveGPUVirtualAddressEyy'), (48,0x89eb,'21freeGPUVirtualAddressEv'),
        (50,0x2f93,'22commitIntoGPUPageTableEv'), (52,0xe5b0,'23releaseFromGPUPageTableEv'),
        (54,0xaef7,'18updateGPUPageTableEv'),
        (55,0x34f8,'18updateGPUPageTableEjP18IOMemoryDescriptorS1_')]:
        word = word_at(vtable+slot*8)
        symbol = '__ZN15AdrenoMemoryMap'+suffix
        assert (word >> 32)&0xffff == disc
        assert word&0xffffffff == syms[symbol], (slot, symbol, hex(word))
        callbacks.append(dict(slot=slot, discriminator=hex(disc), symbol=symbol))
    clear = rows('10clearPagesEPvyy')
    for pattern in [r'hvc\s+#0xad16', r'dsb\s+ish', r'mov\s+w0, #0x2',
                    r'movk\s+w0, #0x1, lsl #16']:
        assert has(pattern, clear), pattern
    assert has(r'mov\s+w3, #0x800', rows('12physicalPageEPvyPy'))
    if args.cache:
        cache = rows('13maintainCacheEPvyyj')
        for pattern in [r'hvc\s+#0xad16', r'dsb\s+ish', r'mov\s+w0, #0x3',
                        r'movk\s+w0, #0x1, lsl #16', r'ccmp\s+x1, x\d+,', r'ccmp\s+x2, #0x0,']:
            assert has(pattern, cache), pattern
    assert sum('hvc\t' in row for code in parts.values() for row in code) == (3 if args.cache else 2)
    funcs = {f['symbol']: f for im in native['images'] for f in im['functions']}
    update = funcs['__ZN14IOGPUMemoryMap10update_pteEjP18IOMemoryDescriptorS1_']['instructions']
    assert any(i['mnemonic'] == 'tbnz' and i['operands'].startswith('w0, #0,') for i in update)
    # AdrenoX2.cpp and its ordered parts
    x2_unit = [str(p.relative_to(ROOT)) for p in source_files(ROOT/'gpu/adreno-kext/kext/src/AdrenoX2.cpp')]
    sources = ['compat/adreno-resource.c','compat/adreno-resource.h','compat/adreno-guest.h',
        'gpu/adreno-kext/kext/src/AdrenoMemoryMap.cpp',*x2_unit,
        'gpu/adreno-kext/kext/src/AdrenoX2.h','gpu/adreno-kext/kext/include/IOGPUFamily26A428.h',
        'gpu/adreno-kext/kext/Info.plist','gpu/adreno-kext/kext/build.sh',
        'tools/trace-adreno-resource-kext.py','tools/trace-adreno-memory-map.py',
        'tools/qualify-adreno-resource-kext.py']
    result = dict(status='STATIC_QUALIFIED_AUXKC_AND_A16_PENDING', boundary=__doc__,
        kext_sha256=sha(binary.read_bytes()), native_sha256=sha(args.native.read_bytes()),
        disassembly_sha256=sha(args.disassembly.read_bytes()), virtual_calls=abi, callbacks=callbacks,
        cache_hvc=args.cache,
        sources_sha256={s:sha((ROOT/s).read_bytes()) for s in sources})
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(output=str(args.output), status=result['status'],
        kext_sha256=result['kext_sha256'], virtual_calls=len(abi), callbacks=len(callbacks))))


if __name__ == '__main__': main()
