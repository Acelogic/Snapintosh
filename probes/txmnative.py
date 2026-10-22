# SPDX-License-Identifier: MIT
"""Relocate the pinned J700 native Image4 helper for the monitor and replay.

This changes pointer/PAC ABI and diagnostic/panic transport only. The native
crypto, parser, identity and policy instructions are retained byte-for-byte.
"""
import hashlib
from pathlib import Path
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]
TXM_SHA = 'b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246'
LINK_BASE = 0xfffffff017000000
HELPER_BASE = 0xb0600000
BRIDGE_SHA = '5de9ce482912f1c39b1fe5a112bb25011c0349a05810f7f96684f438721279b3'
WORK_BYTES = 0x300000
IMAGE_BYTES = 0x100308
IMAGE_SHA = 'a59de157f4ca6b1a35f03a974ade0cb720270052056f7334b09bdb4c8727d0cd'


def relocate(raw, base=LINK_BASE, bridge=None):
    """Return flat image, native pointer fixups and audited instruction patches."""
    portable_base = base if base != LINK_BASE else None
    if portable_base is not None:
        assert 0x20000000 <= base <= 0xf0000000 and base % 0x4000 == 0
    assert bridge is None or (portable_base is not None
                             and hashlib.sha256(bridge).hexdigest() == BRIDGE_SHA)
    delta = base - LINK_BASE
    sha = lambda b: hashlib.sha256(b).hexdigest()
    assert sha(raw) == TXM_SHA
    load = runpy.run_path(str(ROOT / 'tools/kc-load.py'))
    image = load['Image'](raw)
    fixed = bytearray(raw)
    # TXM uses __chain_starts, not LC_DYLD_CHAINED_FIXUPS. Format7 is
    # ARM64E_KERNEL: the Apple SDK mach-o/fixup-chains.h specifies 4-byte
    # stride, 11-bit next, 43-bit plain offsets and 32-bit authenticated offsets.
    assert image.fixups is None and image.vmin == LINK_BASE + 0x4000
    fmt, count = struct.unpack_from('<II', raw, 0x1a860)
    assert (fmt, count) == (7, 2)
    fixes, visited = [], set()
    for cursor in struct.unpack_from('<2I', raw, 0x1a868):
        while True:
            assert cursor not in visited and cursor + 8 <= len(raw)
            visited.add(cursor)
            word, = struct.unpack_from('<Q', raw, cursor)
            assert not (word >> 62) & 1, 'unexpected bound import'
            target = word & ((1 << (32 if word >> 63 else 43)) - 1)
            if not word >> 63:
                assert (word >> 43) & 0xff == 0, 'unexpected tagged offset'
            assert image.vmin + target < image.vmax
            fixes.append((cursor, image.vmin + target + delta))
            step = (word >> 51) & 0x7ff
            if not step:
                break
            cursor += step * 4
    for off, value in fixes:
        struct.pack_into('<Q', fixed, off, value)
    patches = []
    if portable_base is not None:
        for name, va, _, offset, length in image.segments:
            if name not in ('__TEXT_EXEC', '__TEXT_BOOT_EXEC'):
                continue
            for off in range(offset, offset + length, 4):
                word, = struct.unpack_from('<I', fixed, off)
                changed = None
                if word in (0xd503237f, 0xd50323ff, 0xd503233f, 0xd50323bf):
                    changed = 0xd503201f  # PAC/AUT SP -> NOP
                elif word == 0xd65f0fff:
                    changed = 0xd65f03c0  # RETAB -> RET x30
                elif word & 0xfffffc00 in (0xdac10000, 0xdac10400, 0xdac10800, 0xdac10c00,
                                          0xdac11000, 0xdac11400, 0xdac11800, 0xdac11c00):
                    changed = 0xd503201f  # PAC/AUT register -> NOP
                elif word & 0xfffffc00 in (0xd73f0800, 0xd73f0c00, 0xd71f0800, 0xd71f0c00):
                    link = word & 0xfffffc00 in (0xd73f0800, 0xd73f0c00)
                    changed = (0xd63f0000 if link else 0xd61f0000) | (word & 0x3e0)
                if changed is not None:
                    struct.pack_into('<I', fixed, off, changed)
                    patches.append(dict(offset=hex(va - LINK_BASE + off - offset),
                                        before=hex(word), after=hex(changed), kind='PAC-ABI'))
        for address, instruction in ((LINK_BASE + 0x39cc4, 0x52800000),
                                     (LINK_BASE + 0x39cc8, 0xd65f03c0)):
            segment, = [s for s in image.segments if s[1] <= address < s[1] + s[4]]
            off = segment[3] + address - segment[1]
            before, = struct.unpack_from('<I', fixed, off)
            struct.pack_into('<I', fixed, off, instruction)
            patches.append(dict(offset=hex(address - LINK_BASE), before=hex(before),
                                after=hex(instruction), kind='diagnostic-transport'))
    flat = bytearray(0x100000)
    for _, va, _, off, size in image.segments:
        flat[va - LINK_BASE:va - LINK_BASE + size] = fixed[off:off + size]
    if bridge:
        assert len(bridge) == 0x308 and bridge[-8:] == bytes(8)
        flat.extend(bridge)
        for offset in (0x3d818, 0x3d60c, 0x3d99c):
            displacement = 0x100200 - offset
            before, = struct.unpack_from('<I', flat, offset)
            instruction = 0x14000000 | ((displacement // 4) & 0x3ffffff)
            struct.pack_into('<I', flat, offset, instruction)
            patches.append(dict(offset=hex(offset), before=hex(before), after=hex(instruction),
                                kind='panic-transport'))
    return bytes(flat), fixes, patches


def install(proxy, info, image_path, tree, work):
    """Place verified helper code and private state before entering any guest.

    The caller reserves the final three MiB of the monitor arena and removes
    it from its table pool/stage2 map. This does not initialize the library;
    the monitor invokes the production adapter with its effective guest IDs.
    """
    sha = lambda b: hashlib.sha256(b).hexdigest()
    image = Path(image_path).read_bytes()
    if len(image) != IMAGE_BYTES or sha(image) != IMAGE_SHA:
        raise ValueError('native Image4 helper differs from the qualified image')
    if not work or work & 0x3fff or work + WORK_BYTES >= 1 << 36 or not 0 < len(tree) <= 0x100000:
        raise ValueError('invalid native Image4 private reservation/tree')
    if info['current_el'] != 2 or info['stage_generation'] < 1 or not proxy.stage_features() & 1:
        raise ValueError('native Image4 requires a fresh protected EL2 stage')
    slot = info['stage_size'] // 2
    if info['image_base'] not in (info['stage_base'], info['stage_base'] + slot):
        raise ValueError('unknown resident stage slot')
    if not info['stage_base'] <= HELPER_BASE < HELPER_BASE + len(image) <= info['stage_base'] + info['stage_size']:
        raise ValueError('native Image4 code is outside executable stage reservation')
    # The resident stage, bound by its text to the local build it came from: the
    # regular pair, or the one the launch names in SNAP_STAGE_BUILDS (stagebind.py).
    import stagebind
    stage = stagebind.bind(proxy.readmem, info)
    if stagebind.overlaps(stage, HELPER_BASE, HELPER_BASE + len(image)):
        raise ValueError('native Image4 overlaps resident stage data/code')
    from monitor_work import reserved
    if any(work < hi and lo < work + WORK_BYTES for lo, hi in reserved(info)):
        raise ValueError('native Image4 workspace overlaps reserved host memory')
    guard = proxy.serror_state()
    if any(guard[k] for k in ('before', 'during', 'unconsumed')) or proxy.get_exc_count():
        raise ValueError('native Image4 preflight found host exceptions')
    proxy.writemem(HELPER_BASE, bytes.fromhex('000080d2c0035fd6'))
    proxy.flush_code(HELPER_BASE, 8);proxy.set_exc_guard(3)
    try:
        if proxy.call(HELPER_BASE, timeout=3) or proxy.get_exc_count():
            raise ValueError('native Image4 code reservation is not executable')
    finally:
        proxy.set_exc_guard(0)
    proxy.writemem(HELPER_BASE, image);proxy.flush_code(HELPER_BASE, len(image))
    if proxy.readmem(HELPER_BASE, len(image)) != image:
        raise ValueError('native Image4 image upload failed readback')
    workspace = bytes(0x200000) + tree + bytes(0x100000-len(tree))
    proxy.writemem(work, workspace)
    if proxy.readmem(work + 0x200000, len(tree)) != tree:
        raise ValueError('native Image4 tree upload failed readback')
    return (HELPER_BASE, work, WORK_BYTES, len(tree)), dict(
        image_sha256=sha(image), tree_sha256=sha(tree), stage_text_sha256=stage['resident_text_sha256'],
        stage_elf_sha256=stage['elf_sha256'], stage_build=str(stage['build']),
        stage_bin_sha256=stage['bin_sha256'], generation=info['stage_generation'],
        image=hex(HELPER_BASE), work=hex(work), bytes=WORK_BYTES,
        code=[dict(offset=off,bytes=size,sha256=sha(image[off:off+size]))
              for off,size in ((0x34000,0x5c000),(0x100000,0x300))],
        source_sha256=sha(Path(__file__).read_bytes()),
        stagebind_sha256=sha(Path(stagebind.__file__).read_bytes()))
