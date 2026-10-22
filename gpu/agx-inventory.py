#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""What the stock kernelcache and device tree say about the GPU.

Every number in docs/AGX.md that is marked Measured comes out of this script,
and re-running it is how you check that it still does. It reads two files and
writes nothing:

    downloads/extracted/j700ap/kernelcache.release.mac17p   (MH_FILESET)
    downloads/extracted/j700ap/DeviceTree.j700ap            (Apple ADT)

It imports tools/kc-load.py and probes/appledt.py rather than re-implementing
them, because a second Mach-O parser is a second place for the fixup trap in
kc-load's docstring to be got wrong.

    python3 gpu/agx-inventory.py              # everything
    python3 gpu/agx-inventory.py --kexts      # just the kext inventory
    python3 gpu/agx-inventory.py --dt         # just the device tree
    python3 gpu/agx-inventory.py --uat        # just the table-7 stubs
    python3 gpu/agx-inventory.py --strings    # firmware paths and IOKit names
    python3 gpu/agx-inventory.py --firmware   # what the IPSW ships (reads the IPSW)

Only --firmware touches the 26 GB restore image; everything else reads the two
already-extracted files.
"""
import argparse
import importlib.util
import pathlib
import re
import struct
import sys

# Importing probes/appledt.py must not leave a __pycache__ entry behind: that
# directory belongs to another part of the tree and this tool is read-only.
sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parent.parent
KERNELCACHE = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
DEVICETREE = ROOT / 'downloads/extracted/j700ap/DeviceTree.j700ap'
IPSW = ROOT / 'downloads/UniversalMac_27.0_26A428_Restore.ipsw'

LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xFEEDFACF


def _load(path, name):
    """Import a module whose filename is not a legal identifier."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


kcload = _load(ROOT / 'tools/kc-load.py', 'kcload')
sys.path.insert(0, str(ROOT / 'probes'))
from appledt import DeviceTree  # noqa: E402


# ---------------------------------------------------------------- kexts

# Substrings that make a kext GPU-related. Deliberately broad: the point is to
# see the whole set and then say which ones matter, not to prejudge it.
GPU_HINTS = ('AGX', 'GPU', 'Graphics', 'Metal', 'Display', 'IOAccel', 'Gfx', 'SGX')


def kext_inventory(image, verbose=True):
    hits = []
    for name, vmaddr, fileoff in image.kexts:
        if any(h.lower() in name.lower() for h in GPU_HINTS):
            hits.append((name, vmaddr, fileoff, None))
    if verbose:
        print(f'{len(image.kexts)} kexts in the fileset, '
              f'{len(hits)} matching {"/".join(GPU_HINTS)}:\n')
        print(f'  {"kext":<46} {"__TEXT_EXEC":>12}  {"__DATA_CONST":>12}')
        for name, vmaddr, fileoff, _ in sorted(hits):
            print(f'  {name:<46} {kext_size(image, fileoff, "__TEXT_EXEC"):>12,}'
                  f'  {kext_size(image, fileoff, "__DATA_CONST"):>12,}')
    return hits


def kext_segments(image, fileoff):
    """The LC_SEGMENT_64s of one fileset member, read from its own header."""
    data = image.data
    magic, _, _, _, ncmds = struct.unpack_from('<IiiII', data, fileoff)
    if magic != MH_MAGIC_64:
        return []
    segs, off = [], fileoff + 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == LC_SEGMENT_64:
            name = data[off + 8:off + 24].rstrip(b'\0').decode()
            vmaddr, vmsize, segfileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            nsects = struct.unpack_from('<I', data, off + 64)[0]
            sects = []
            soff = off + 72
            for _ in range(nsects):
                sname = data[soff:soff + 16].rstrip(b'\0').decode()
                saddr, ssize, soffset = struct.unpack_from('<QQI', data, soff + 32)
                sects.append((sname, saddr, ssize, soffset))
                soff += 80
            segs.append((name, vmaddr, vmsize, segfileoff, filesize, sects))
        off += size
    return segs


def kext_size(image, fileoff, segname):
    """One named segment's vmsize.

    Summing every segment is wrong and the wrongness is not obvious: in an
    MH_FILESET every member's __LINKEDIT load command describes the *shared*
    25 MB __LINKEDIT, so a naive total reports ~25 MB for all 362 kexts and
    hides the two-order-of-magnitude difference between AGXG17P and the little
    RTBuddy shim next to it.
    """
    return sum(s[2] for s in kext_segments(image, fileoff) if s[0] == segname)


# ---------------------------------------------------------------- strings

PRINTABLE = re.compile(rb'[\x20-\x7e]{6,}')


def kext_strings(image, fileoff):
    """Every C string in one fileset member's __TEXT sections."""
    out = []
    for segname, _, _, _, _, sects in kext_segments(image, fileoff):
        if not segname.startswith('__TEXT'):
            continue
        for sname, _, ssize, soffset in sects:
            if sname not in ('__cstring', '__const', '__oslogstring'):
                continue
            blob = image.data[soffset:soffset + ssize]
            out += [m.group().decode('ascii') for m in PRINTABLE.finditer(blob)]
    return out


FIRMWARE_RE = re.compile(r'^/(usr|System|Library|AppleInternal)\S*|\S+\.(im4p|bin|fw|plist)$')
CLASS_RE = re.compile(r'^(AGX|IOGPU|IOAccel|Apple(GPU|AGX)|IOMFB)\w*$')


def string_report(image, hits):
    for name, _, fileoff, _ in sorted(hits):
        strings = kext_strings(image, fileoff)
        if not strings:
            continue
        fw = sorted({s for s in strings if FIRMWARE_RE.match(s) and len(s) < 120})
        classes = sorted({s for s in strings if CLASS_RE.match(s)})
        endpoints = sorted({s for s in strings
                            if re.search(r'(?i)\b(doorbell|mailbox|ringbuffer|rtkit|'
                                         r'firmware|fw_|ktrace|channel)\b', s)
                            and len(s) < 90})
        if not (fw or classes or endpoints):
            continue
        print(f'\n=== {name}  ({len(strings):,} strings) ===')
        for label, items, cap in (('paths', fw, 14), ('classes', classes, 20),
                                  ('handshake', endpoints, 14)):
            if items:
                print(f'  {label}:')
                for s in items[:cap]:
                    print(f'    {s}')
                if len(items) > cap:
                    print(f'    ... {len(items) - cap} more')


# ---------------------------------------------------------------- device tree

def u32s(blob):
    return list(struct.unpack_from(f'<{len(blob) // 4}I', blob, 0)) if blob else []


def u64s(blob):
    return list(struct.unpack_from(f'<{len(blob) // 8}Q', blob, 0)) if blob else []


def is_gpu_node(dt, path):
    leaf = path.rsplit('/', 1)[-1].split('@')[0]
    if leaf in ('sgx', 'gfx-asc', 'agx', 'gpu', 'gfx-shared-region'):
        return True
    for prop in ('compatible', 'device_type', 'name'):
        value = dt.get(path, prop)
        if value and re.search(rb'(?i)agx|sgx|gfx|gpu', value):
            return True
    return False


def dt_report(dt):
    matches = [p for p in dt.nodes if is_gpu_node(dt, p)]
    print(f'{len(dt.nodes)} nodes in the tree, {len(matches)} GPU-related:\n')
    for path in sorted(matches):
        props = dt.nodes[path]
        compat = dt.get(path, 'compatible')
        compat = compat.rstrip(b'\0').decode('utf-8', 'replace') if compat else '-'
        print(f'  {path}')
        print(f'      compatible  {compat}   ({len(props)} properties)')
        reg = dt.get(path, 'reg')
        if reg:
            words = u64s(reg)
            for i in range(0, len(words) - 1, 2):
                print(f'      reg[{i // 2}]      {words[i]:#012x} + {words[i + 1]:#x}')
        for prop in ('interrupts', 'interrupt-parent', 'iommu-parent', 'dart-id',
                     'function-clock_gate', 'clock-frequency', 'gpu-num-cores',
                     'segment-ranges', 'page-size', 'vm-base', 'vm-size'):
            value = dt.get(path, prop)
            if value:
                print(f'      {prop:<11} {_fmt(value)}')
        others = sorted(set(props) - {'compatible', 'reg', 'name', 'interrupts',
                                      'interrupt-parent', 'AAPL,phandle'})
        if others:
            print(f'      also: {", ".join(others[:18])}'
                  + (f' ... +{len(others) - 18}' if len(others) > 18 else ''))
    return matches


def _fmt(value):
    if len(value) <= 8 and len(value) % 4 == 0:
        return ' '.join(f'{w:#x}' for w in u32s(value))
    if 0 not in value[:-1] and value[-1:] == b'\0':
        return value.rstrip(b'\0').decode('utf-8', 'replace')
    if len(value) % 4 == 0 and len(value) <= 64:
        return ' '.join(f'{w:#x}' for w in u32s(value))
    return f'<{len(value)} bytes> ' + value[:16].hex()


# ---------------------------------------------------------------- UAT stubs

GENTER = 0x00201420
ALT_CALL = 0xD4E00000
MONITOR_OPS = (GENTER, ALT_CALL)


def uat_stubs(image):
    """Every domain-0 table-7 call site, with the endpoint it names.

    Same replay as tools/kc-analyze.py's decode_stub, kept here so this script
    reports addresses (which that one does not) without editing it.
    """
    found = []
    for name, vmaddr, vmsize, fileoff, filesize in image.segments:
        if 'TEXT' not in name or not filesize:
            continue
        body = image.data[fileoff:fileoff + filesize]
        words = list(struct.unpack_from(f'<{len(body) // 4}I', body, 0))
        for i, word in enumerate(words):
            if word not in MONITOR_OPS:
                continue
            value, dynamic = _decode(words, i)
            domain, table = (value >> 48) & 0xFF, (value >> 32) & 0xFF
            found.append((domain, table, value & 0xFFFFFFFF, dynamic,
                          vmaddr + i * 4, name))
    return found


def _decode(words, index):
    value, dynamic, start = 0, False, max(0, index - 24)
    head = start
    for i in range(index - 1, start - 1, -1):
        if words[i] == 0xD503237F:              # pacibsp: the stub's first insn
            head = i
            break
    for word in words[head:index]:
        if (word & 0x1F) != 16:
            continue
        imm16, shift = (word >> 5) & 0xFFFF, ((word >> 21) & 3) * 16
        if (word & 0xFF800000) == 0xD2800000:
            value = imm16 << shift
        elif (word & 0xFF800000) == 0xF2800000:
            value = (value & ~(0xFFFF << shift)) | (imm16 << shift)
        elif word in (0x2A0003F0, 0xAA0003F0):
            dynamic = True
    return value, dynamic


# The names m1n1-j700/src/sptm/private.h gives endpoints 0..12 of table 7.
# It defines UAT_C_MAX_ENDPOINTS as 13; this kernelcache has 14 stubs, so the
# last row is what that tree does not cover.
UAT_NAMES = {
    0: 'UAT_FN_INIT_STATE',
    1: 'UAT_FN_DESTROY_STATE',
    2: 'UAT_FN_MAP_TABLE',
    3: 'UAT_FN_UNMAP_TABLE',
    4: 'UAT_FN_MAP_BEGIN',
    5: 'UAT_FN_MAP_CONTINUE',
    6: 'UAT_FN_PREP_FW_UNMAP_BEGIN',
    7: 'UAT_FN_PREP_FW_UNMAP_CONTINUE',
    8: 'UAT_FN_UNMAP_BEGIN',
    9: 'UAT_FN_UNMAP_CONTINUE',
    10: 'UAT_FN_SET_CTX_ID',
    11: 'UAT_FN_REMOVE_CTX_ID',
    12: 'UAT_FN_GET_INFO',
}


def uat_report(image):
    """The table-7 interface, one row per endpoint.

    Each stub carries two call sites -- a `genter` and the `0xd4e00000`
    alternate -- and tools/kc-analyze.py counts only the `genter` of each, so
    its "14 stubs" and the 28 addresses below are the same 14 functions.
    """
    sites = [s for s in uat_stubs(image) if s[0] == 0 and s[1] == 7]
    by_ep = {}
    for _, _, endpoint, dynamic, addr, seg in sites:
        by_ep.setdefault(endpoint, []).append((addr, seg, dynamic))

    print(f'domain 0, table 7 (SPTM_TABLE_UAT): '
          f'{len(by_ep)} endpoints, {len(sites)} call sites\n')
    print(f'  {"ep":>3}  {"genter at":<20} {"alt-call at":<20} name')
    for endpoint in sorted(by_ep):
        addrs = {}
        for addr, seg, _ in by_ep[endpoint]:
            word = struct.unpack_from('<I', image.data, _file_of(image, addr))[0]
            addrs['genter' if word == GENTER else 'alt'] = addr
        name = UAT_NAMES.get(endpoint, '** NOT IN private.h **')
        print(f'  {endpoint:>3}  {addrs.get("genter", 0):#018x}  '
              f'{addrs.get("alt", 0):#018x}  {name}')

    unnamed = sorted(set(by_ep) - set(UAT_NAMES))
    missing = sorted(set(UAT_NAMES) - set(by_ep))
    print()
    if unnamed:
        print(f'  has a stub here but no name in m1n1-j700 private.h '
              f'(UAT_C_MAX_ENDPOINTS is {len(UAT_NAMES)}): '
              + ', '.join(str(e) for e in unnamed))
    if missing:
        print('  named in private.h but with no stub here: '
              + ', '.join(f'{e} ({UAT_NAMES[e]})' for e in missing))
    if not unnamed and not missing:
        print('  the two agree exactly')
    return by_ep


# ---------------------------------------------------------------- firmware

def firmware_report(ipsw, device='j700ap'):
    """Which GPU firmware the restore image ships, read out of BuildManifest.

    This exists because the AGX kext does not load firmware from a filesystem:
    it calls requestFirmwareBinary() and fails with "GFX firmware was not
    loaded by iBoot" if the blob is not already in memory. So the question
    "what would we have to place, and do we have it" is answered here.
    """
    import plistlib
    import zipfile

    with zipfile.ZipFile(ipsw) as z:
        sizes = {i.filename: i.file_size for i in z.infolist()}
        manifest = plistlib.loads(z.read('BuildManifest.plist'))
        for identity in manifest['BuildIdentities']:
            if identity['Info'].get('DeviceClass', '').lower() != device:
                continue
            print(f'{device} GPU firmware components:\n')
            for key in ('GFX', 'Ap,GFX1Firmware'):
                entry = identity['Manifest'].get(key)
                if not entry:
                    print(f'  {key:<18} -- not in this identity')
                    continue
                path = entry['Info'].get('Path')
                print(f'  {key:<18} {path:<34} {sizes.get(path, 0):>10,} bytes')
            for key, path in (('GFX', 'Firmware/agx/armfw_g17p.im4p'),
                              ('GFX1', 'Firmware/agx/armfw1_g17p.im4p')):
                print()
                im4p_report(key, path, z.read(path))
            return
    print(f'no build identity for DeviceClass {device}')


def im4p_report(label, path, data):
    """Unwrap an IM4P and describe the RTKit firmware table inside it.

    The payload is *not* compressed and *not* a Mach-O: it is an `rkosftab`,
    a flat table of named sub-images, which is what an ASC expects to be
    handed. That is the format `requestFirmwareBinary()` returns a pointer
    into, so it is the format we would have to place in memory.
    """
    i = data.index(b'IM4P') + 4
    fields = []
    for _ in range(2):                       # IA5String tag, IA5String version
        kind, length = data[i], data[i + 1]
        if kind != 0x16:
            break
        fields.append(data[i + 2:i + 2 + length])
        i += 2 + length
    tag = fields[0].decode() if fields else '?'

    start = data.find(b'rkosftab')
    if start < 0:
        print(f'  {label}: {path} -- IM4P tag {tag!r}, no rkosftab found')
        return
    count = struct.unpack_from('<I', data, start + 8)[0]
    print(f'  {label}  {path}')
    print(f'    IM4P tag {tag!r}, payload is an rkosftab with {count} sub-images:')
    base = start + 16
    end = 0
    for n in range(count):
        name, off, size, _ = struct.unpack_from('<4sIII', data, base + n * 16)
        print(f'      {name.decode():<6} offset {off:#010x}  size {size:>10,}')
        end = max(end, off + size)
    print(f'    sub-images tile the payload contiguously up to {end:#x} '
          f'({end:,} bytes)')


def _file_of(image, va):
    for _, vmaddr, vmsize, fileoff, filesize in image.segments:
        if vmaddr <= va < vmaddr + vmsize and filesize:
            return fileoff + (va - vmaddr)
    raise KeyError(f'{va:#x} is in no segment')


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--kexts', action='store_true')
    ap.add_argument('--dt', action='store_true')
    ap.add_argument('--uat', action='store_true')
    ap.add_argument('--strings', action='store_true')
    ap.add_argument('--firmware', action='store_true')
    ap.add_argument('--kernelcache', type=pathlib.Path, default=KERNELCACHE)
    ap.add_argument('--devicetree', type=pathlib.Path, default=DEVICETREE)
    ap.add_argument('--ipsw', type=pathlib.Path, default=IPSW)
    args = ap.parse_args()
    everything = not (args.kexts or args.dt or args.uat or args.strings
                      or args.firmware)

    image = None
    if everything or args.kexts or args.uat or args.strings:
        if not args.kernelcache.exists():
            raise SystemExit(f'no kernelcache at {args.kernelcache}')
        image = kcload.Image(args.kernelcache.read_bytes())

    if everything or args.kexts or args.strings:
        print('=' * 72)
        print(f'KEXTS  {args.kernelcache.name}')
        print('=' * 72)
        hits = kext_inventory(image, verbose=everything or args.kexts)
        if everything or args.strings:
            string_report(image, hits)
        print()

    if everything or args.dt:
        print('=' * 72)
        print(f'DEVICE TREE  {args.devicetree.name}')
        print('=' * 72)
        if not args.devicetree.exists():
            raise SystemExit(f'no device tree at {args.devicetree}')
        dt_report(DeviceTree(args.devicetree.read_bytes()))
        print()

    if everything or args.uat:
        print('=' * 72)
        print('UAT STUBS  (SPTM domain 0, table 7)')
        print('=' * 72)
        uat_report(image)
        print()

    if everything or args.firmware:
        print('=' * 72)
        print('GPU FIRMWARE')
        print('=' * 72)
        if not args.ipsw.exists():
            print(f'no IPSW at {args.ipsw}; skipping')
        else:
            firmware_report(args.ipsw)


if __name__ == '__main__':
    main()
