# SPDX-License-Identifier: MIT
"""Deterministic kmutil-shaped AuxKC fixtures for the offline tests.

Same geometry rules as kmutil's output (build/auxkc-hello-20260925/aux.kc):
RW __PRELINK_INFO at vmaddr 0 and __DATA below the __TEXT header,
__TEXT_EXEC above it, __LINKEDIT on top holding kernel-cache chained fixups
whose segment_offset is relative to the header (so it wraps below zero).
Nothing here is an Apple binary; the bytes are synthetic.
"""
import copy
import hashlib
import json
import plistlib
import struct

PAGE = 0x4000
SEGMENTS = (  # name, vmaddr, fileoff, prot
    ('__TEXT', 0x8000, 0x0000, 1),
    ('__TEXT_EXEC', 0xc000, 0xc000, 5),
    ('__PRELINK_INFO', 0x0000, 0x4000, 3),
    ('__DATA', 0x4000, 0x8000, 3),
    ('__LINKEDIT', 0x10000, 0x10000, 1),
)
MH = 0x8000
CODE_BUNDLE = 'org.snapintosh.test.code'
TEXT = bytes(range(256)) * (PAGE // 256)
KEXT_HEADER = 0x1000         # the code kext's own mach header, inside __TEXT
VTABLE = 0x4100              # a defined vtable symbol inside __DATA


def fixup(target, level, nxt=0, auth=False):
    return (target | (level << 30) | ((0x1234 if auth else 0) << 32) |
            (nxt << 51) | (int(auth) << 63))


def build(boot_id, bundles_info, *, primary_target=0x1000, levels=(0, 3), multi=False,
          fmt=8, mutate=None):
    """bundles_info: prelink dictionaries (without _Prelink keys). Returns bytes."""
    uuid = hashlib.sha256(repr(bundles_info).encode()).digest()[:16]
    info = dict(_BootKCID=boot_id, _PrelinkKCID=uuid,
                _PrelinkInfoDictionary=copy.deepcopy(bundles_info))
    xml = plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=True) + b'\0'
    if len(xml) > PAGE:
        raise ValueError('fixture prelink metadata too large')
    data = bytearray(0x14000)
    # Chained fixups: header, starts_in_image (5 segments), one __DATA start.
    starts = 0x20
    blob = bytearray(0x100)
    struct.pack_into('<7I', blob, 0, 0, starts, 0x80, 0x80, 0, 1, 0)
    struct.pack_into('<I', blob, starts, len(SEGMENTS))
    seg_info = 0x20
    struct.pack_into('<I', blob, starts + 4 + 4 * 3, seg_info)      # __DATA is index 3
    struct.pack_into('<IHHQIHH', blob, starts + seg_info, 24, PAGE, fmt,
                     (0x4000 - MH) & (2 ** 64 - 1), 0, 1, 0x8000 if multi else 0)
    data[0x10000:0x10000 + len(blob)] = blob
    # __DATA chain: primary pointer, then an authenticated self pointer.
    struct.pack_into('<Q', data, 0x8000, fixup(primary_target, levels[0], nxt=2))
    struct.pack_into('<Q', data, 0x8008, fixup(0xc000, levels[1], auth=True))
    data[0xc000:0x10000] = TEXT
    data[0x4000:0x4000 + len(xml)] = xml
    # Code kext header with one defined vtable symbol (nlist at LINKEDIT+0x200).
    symtab = struct.pack('<II4I', 0x2, 24, 0x10200, 1, 0x10300, 32)
    struct.pack_into('<8I', data, KEXT_HEADER, 0xfeedfacf, 0x100000c, 2, 0xb, 1, len(symtab), 0, 0)
    data[KEXT_HEADER + 32:KEXT_HEADER + 32 + len(symtab)] = symtab
    struct.pack_into('<IBBHQ', data, 0x10200, 1, 0x0f, 1, 0, VTABLE)
    name = b'\0__ZTV14SnapFixtureCode\0'
    data[0x10300:0x10300 + len(name)] = name
    # Load commands.
    commands = struct.pack('<II16s', 0x1b, 24, uuid)
    commands += struct.pack('<IIII', 0x80000034, 16, 0x10000, 0x100)
    for name, va, off, prot in SEGMENTS:
        sections = b''
        if name == '__PRELINK_INFO':
            sections = struct.pack('<16s16sQQIIIIIIII', b'__info', b'__PRELINK_INFO',
                                   va, len(xml), off, 0, 0, 0, 0, 0, 0, 0)
        commands += struct.pack('<II16sQQQQiiII', 0x19, 72 + len(sections), name.encode(),
                                va, PAGE, off, PAGE, prot, prot, len(sections) // 80, 0) + sections
    entry_name = CODE_BUNDLE.encode() + b'\0'
    size = (32 + len(entry_name) + 7) & ~7
    commands += struct.pack('<IIQQII', 0x80000035, size, MH + KEXT_HEADER, KEXT_HEADER, 32, 0) + \
        entry_name.ljust(size - 32, b'\0')
    struct.pack_into('<8I', data, 0, 0xfeedfacf, 0x100000c, 2, 12,
                     _count(commands), len(commands), 0, 0)
    data[32:32 + len(commands)] = commands
    if mutate:
        mutate(data)
    return bytes(data)


def _count(commands):
    pos = count = 0
    while pos < len(commands):
        pos += struct.unpack_from('<I', commands, pos + 4)[0]
        count += 1
    return count


def code_info():
    return dict(CFBundleIdentifier=CODE_BUNDLE, CFBundleExecutable='Code',
                IOKitPersonalities=dict(Code=dict(IOClass='SnapFixtureCode',
                                                  IOProviderClass='IOResources')))


def bootfb_info(personality):
    entry = dict(CFBundleIdentifier='org.snapintosh.bootframebuffer',
                 IOKitPersonalities=dict(SnapintoshBootFramebuffer=dict(
                     personality, IOPersonalityPublisher='org.snapintosh.bootframebuffer')))
    return entry


def write(path, data, kernel_sha256, bundles):
    """The fixture plus a manifest in build/build-auxkc.py's format."""
    path.write_bytes(data)
    manifest = dict(format='snapintosh-auxkc-v1', sha256=hashlib.sha256(data).hexdigest(),
                    bytes=len(data), kernel_sha256=kernel_sha256, bundles=sorted(bundles))
    path.with_name(path.name + '.json').write_text(json.dumps(manifest))
    return manifest
