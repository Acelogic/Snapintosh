#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The boot profile and the physical layout, checked without a target.

Four things this covers, docs/PLAN-HISTORY-20260922.md section 1 and Section 0's T4:

  - **The guest's memory is a number, not a leftover.** place() used to declare
    whatever the free span happened to be, so the size XNU saw changed with the
    firmware's mood. It now takes the size it is given and only requires the
    free span to be big enough, and the tests below are the difference between
    those two behaviours.
  - **The layout is checked against itself.** Every offset in xnuboot.py was
    chosen separately; an overlap between two of them does not fault, it writes
    one structure over part of another and hands XNU a plausible hybrid.
  - **A firmware swap is detected.** Every address in the loader was measured
    against one set of images, and none of them are re-derived at run time.
  - **Stage 2 covers what we own, and nothing else.** The range list the probe
    maps is derived here from the numbers it is handed and checked against
    every chunk the loader uploads, every table page, and the panel.

No hardware or proxy: identity checks use temporary fixtures; loader
integration checks use the local audited firmware bundle when available.

    python3 tools/test-profile.py
"""
import hashlib
import importlib.util
import pathlib
import re
import struct
import sys
import tempfile
from monitor_layout import MonitorLayout
from source_text import read_source

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('xnuboot', ROOT / 'probes' / 'xnuboot.py')
xb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xb)

checks = 0
MIB = 1 << 20


def ok(name, condition, detail=''):
    global checks
    checks += 1
    if not condition:
        print(f'FAIL: {name}' + (f'\n  {detail}' if detail else ''))
        sys.exit(1)


def raises(name, call, needle=''):
    """The failure has to happen *and* say why: an error nobody can read is
    only marginally better than no error."""
    global checks
    checks += 1
    try:
        call()
    except (ValueError, SystemExit) as error:
        if needle and needle not in str(error):
            print(f'FAIL: {name}\n  raised, but said {str(error)!r}, '
                  f'which does not mention {needle!r}')
            sys.exit(1)
        return
    print(f'FAIL: {name}\n  did not raise')
    sys.exit(1)


# A base on the 32 MiB grid. DEFAULT_PHYS_BASE is not one -- it is the raw
# address the A16's firmware reported once, and place() would reject it -- so
# these tests pick their own rather than depending on that.
GRID_BASE = 0x40000000


def restore():
    """Back to the shipped guest size. place() writes module globals."""
    xb.place(GRID_BASE, guest_span=xb.GUEST_SPAN)


# --------------------------------------------------------------------------
# The guest's memory is stated

ok('the default guest size is 384 MiB',
   xb.DEFAULT_GUEST_MIB == 384 and xb.GUEST_SPAN == 384 * MIB,
   f'DEFAULT_GUEST_MIB is {xb.DEFAULT_GUEST_MIB}')

# A free span far larger than the guest must not grow the guest. This is the
# regression that mattered: under QEMU the free region is over 2 GiB, the old
# place() declared all of it, and the frame table -- sized from a fixed arena --
# could not cover it.
xb.place(0x40000000, 2161 * MIB)
ok('a 2161 MiB free span still declares 384 MiB',
   xb.REGION_SPAN == 384 * MIB,
   f'declared {xb.REGION_SPAN >> 20} MiB')
ok('the reserve sits above the declaration, inside the memory held',
   xb.BOOTSTRAP_PA == 0x40000000 + 384 * MIB
   and xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN <= 0x40000000 + 2161 * MIB)

# And an explicit size is honoured, rather than being a hint.
xb.place(0x40000000, 2161 * MIB, guest_span=512 * MIB)
ok('an explicit guest size is what gets declared', xb.REGION_SPAN == 512 * MIB,
   f'declared {xb.REGION_SPAN >> 20} MiB')
restore()

# Too little memory is a refusal, not a smaller guest.
raises('a free span too small for guest + reserve is refused',
       lambda: xb.place(0x40000000, 400 * MIB), 'not enough')
raises('a guest smaller than the image and its tables is refused',
       lambda: xb.place(0x40000000, 2161 * MIB, guest_span=64 * MIB),
       'not enough')
raises('an unaligned base is refused',
       lambda: xb.place(0x40000001), 'grid')
raises('an unaligned guest size is refused',
       lambda: xb.place(0x40000000, 2161 * MIB, guest_span=100 * MIB), 'grid')
restore()

# free_region() asks for guest + reserve, and place() then requires the same
# thing, so the two must agree about what "enough" means. A span of exactly
# guest + reserve has to be accepted: an off-by-one here rejects every region
# the runner would pick.
xb.place(0x40000000, 384 * MIB + xb.BOOTSTRAP_SPAN)
ok('exactly guest + reserve is enough', xb.REGION_SPAN == 384 * MIB)
restore()


# --------------------------------------------------------------------------
# The layout is checked against itself

placed = sorted(xb.reservations(), key=lambda r: r[1])
for (a_name, a_off, a_span), (b_name, b_off, _) in zip(placed, placed[1:]):
    ok(f'{a_name} does not run into {b_name}', a_off + a_span <= b_off,
       f'{a_name} ends at {a_off + a_span:#x}, {b_name} starts at {b_off:#x}')
last_name, last_off, last_span = placed[-1]
ok('the shipped layout fits the declared region',
   last_off + last_span <= xb.REGION_SPAN,
   f'{last_name} ends at {last_off + last_span:#x} of {xb.REGION_SPAN:#x}')
ok('the six per-CPU result areas fit reserved monitor data',
   xb.SCRATCH_COUNT == 6 and xb.SCRATCH_STRIDE == 0x8000 and
   xb.SCRATCH_SPAN == 6*0x8000 and
   xb.SCRATCH_OFFSET + xb.SCRATCH_SPAN <= xb.SPTM_DATA_SPAN)

# An overlap has to be caught rather than silently written through.
saved = xb.FRAMETABLE_OFFSET
try:
    xb.FRAMETABLE_OFFSET = xb.TABLE_OFFSET + 0x1000
    raises('an overlapping reservation is caught', xb.validate_layout, 'runs into')
finally:
    xb.FRAMETABLE_OFFSET = saved
xb.validate_layout()        # and the real one still passes
checks += 1

saved = xb.SPTM_DATA_SPAN
try:
    xb.SPTM_DATA_SPAN = 512 * MIB
    raises('a reservation past the end of the region is caught',
           xb.validate_layout, 'past the')
finally:
    xb.SPTM_DATA_SPAN = saved
restore()


# --------------------------------------------------------------------------
# A firmware swap is detected

names = list(xb.PROFILE_FIRMWARE)
ok('the profile names every image the loader reads',
   set(names) == {'kernelcache.release.mac17p', 'DeviceTree.j700ap',
                  'sptm.t8140.release', 'txm.macosx.release'},
   f'profile names {names}')
ok('every recorded hash is a sha256',
   all(len(h) == 64 and all(c in '0123456789abcdef' for c in h)
       for h in xb.PROFILE_FIRMWARE.values()))

with tempfile.TemporaryDirectory() as directory:
    fake = pathlib.Path(directory)
    bad = xb.check_profile(fake)
    ok('an empty firmware directory is rejected', len(bad) == len(names),
       f'{len(bad)} complaints for {len(names)} files')
    ok('the complaint names the file that is missing',
       all(any(name in line for line in bad) for name in names))

    # Files present but wrong: the hash has to be what rejects them, not their
    # absence, so each one gets content whose digest is certainly not recorded.
    for name in names:
        (fake / name).write_bytes(name.encode() + b' is not the real image')
    bad = xb.check_profile(fake)
    ok('wrong contents are rejected', len(bad) == len(names))
    ok('the complaint quotes both hashes',
       all('sha256' in line and 'profile' in line for line in bad))

    # And a directory that does match is accepted, which is the half that
    # proves the check is comparing rather than always failing. No file here can
    # be made to hash to a chosen value, so the measured digests are handed in
    # directly: this half tests the comparison, the block below tests the hash.
    measured = {name: xb.PROFILE_FIRMWARE[name] for name in names}
    ok('matching hashes are accepted', xb.check_profile(fake, measured) == [])
    ok('one wrong file out of four is still one complaint',
       len(xb.check_profile(fake, dict(measured, **{names[0]: 'f' * 64}))) == 1)

# The hasher itself, against a file whose digest this test computes the other
# way round.
with tempfile.TemporaryDirectory() as directory:
    fake = pathlib.Path(directory)
    body = b'x' * ((1 << 22) + 7)        # over the read block, to exercise it
    (fake / names[0]).write_bytes(body)
    got = xb.firmware_hashes(fake)
    ok('sha256 is computed over the whole file',
       got[names[0]] == hashlib.sha256(body).hexdigest())
    ok('a missing file hashes to None', got[names[1]] is None)


# --------------------------------------------------------------------------
# The bitmap count at handoff +0x68, and the underflow a zero there causes
#
# This is the shape of bug that is worth a permanent test: the field is four
# bytes of a structure nobody reads back, a zero in it is indistinguishable
# from "not set yet", and the consequence is a 512 MiB memset half a second
# later and a thousand instructions away.
#
# XNU's arithmetic, at 0xfffffe000ba66404:
#   sub w11, w9, #1 ; cmp w11, #0x40 ; b.hs -> bulk
#   lsr w10, w11, #6 ; and x12, x10, #0x3fffff8 ; 64 bytes per iteration


def fill_bytes(count):
    """How much the kernel's loop writes for a given count. 32-bit wrapping."""
    w11 = (count - 1) & 0xFFFFFFFF
    if w11 < 0x40:
        return 0
    return ((w11 >> 6) & 0x3FFFFF8) // 8 * 64


def bitmap_bytes(count):
    """The buffer XNU sizes for that count: ((n + 0x3f) >> 3) & 0x1ffffff8."""
    return ((count + 0x3F) >> 3) & 0x1FFFFFF8


ok('a zero count underflows into a half-gigabyte fill',
   fill_bytes(0) > 500 * MIB,
   f'a zero count fills {fill_bytes(0)} bytes')
ok('the count is 0x10000, the width the free path\'s clamp permits',
   xb.BITMAP_BITS == 0x10000)
ok('0x10000 sizes the bitmap to exactly 8192 bytes',
   bitmap_bytes(xb.BITMAP_BITS) == 8192,
   f'{bitmap_bytes(xb.BITMAP_BITS)} bytes')
ok('which is one 16K page, so it fits a single granule',
   bitmap_bytes(xb.BITMAP_BITS) <= (1 << 14))
ok('and the fill loop becomes 0x3ff iterations',
   ((xb.BITMAP_BITS - 1) >> 6) == 0x3FF,
   f'{(xb.BITMAP_BITS - 1) >> 6:#x}')
ok('the fill covers the whole bitmap and no more',
   fill_bytes(xb.BITMAP_BITS) <= bitmap_bytes(xb.BITMAP_BITS))

# The reason the value changed. The free path clamps its byte offset to 0x1ff8
# and stores eight bytes, so it can reach byte 0x2000 of the bitmap whatever the
# count says -- the bound lives in the allocator, not in the buffer. A count
# that sizes the buffer below that leaves a gap the free path is permitted to
# write into.
FREE_PATH_REACH = 0x1FF8 + 8
ok('the buffer covers everything the free path can reach',
   bitmap_bytes(xb.BITMAP_BITS) >= FREE_PATH_REACH,
   f'{bitmap_bytes(xb.BITMAP_BITS)} bytes, but the free path reaches '
   f'{FREE_PATH_REACH}')
ok('0x800 would not have, which is why it was replaced',
   bitmap_bytes(0x800) < FREE_PATH_REACH,
   f'0x800 sizes {bitmap_bytes(0x800)} bytes')
ok('the count is written as four bytes, not eight',
   ('bitmap count', xb.HANDOFF_BITMAP_COUNT, 4, 'measured') in xb.handoff_fields(),
   'the field table does not carry it as a u32')
ok('the fill stays inside the region we declare',
   fill_bytes(xb.BITMAP_BITS) < xb.GUEST_SPAN)

# And the fields really reach the machine. Building takes a few seconds, so it
# is done once and everything is checked against it.
#
# Flattened the way run.py uploads -- sorted by address, later writes winning --
# rather than by reading chunks out of the dict. Those are not the same thing:
# chunks overlap, and the handoff's 0x4000..0x8000 zero region covers the debug
# table at 0x5000, so reading `chunks[HANDOFF_PA + 0x5000]` and reading the
# uploaded image give different answers. The first version of this check read
# the chunk and concluded the table was all zeros; only the flattened view is
# what XNU sees.
import struct as _struct

built = xb.build(str(xb.DEFAULT_KERNELCACHE))
ok('six result buffers are uploaded completely zeroed',
   built['chunks'][xb.SCRATCH_PA] == bytes(6 * 0x8000))
ok('result buffers do not overlap other uploaded chunks',
   all(pa == xb.SCRATCH_PA or pa + len(blob) <= xb.SCRATCH_PA
       or pa >= xb.SCRATCH_PA + xb.SCRATCH_SPAN
       for pa, blob in built['chunks'].items()))
for slot in range(6):
    for offset in (0, 0x3fff, 0x4000, 0x7fff):
        displacement = slot * 0x8000 + offset
        ok(f'CPU {slot} result buffer +{offset:#x} maps to its own backing',
           built['tables'].walk(built['scratch_va'] + displacement)
           == xb.SCRATCH_PA + displacement)
ok('virtual HCR describes the audited kernel return regime',
   int.from_bytes(built['chunks'][built['vncr_va']][0x78:0x80], 'little')
   == xb.GUEST_PROFILE.kernel_hcr == 0x488000000)
ok('virtual TPIDR_EL2 remains empty until a guest vCPU exists',
   built['chunks'][built['vncr_va']][0x90:0x98] == bytes(8))


def flatten(base, span):
    """The bytes at `base` as the machine will hold them after the upload."""
    image = bytearray(span)
    for pa, blob in sorted(built['chunks'].items()):
        if pa >= base + span or pa + len(blob) <= base:
            continue
        image[pa - base:pa - base + len(blob)] = bytes(blob)
    return bytes(image)


page = flatten(xb.HANDOFF_PA, 0x80000)
ok('+0x68 is the count, as a u32',
   _struct.unpack_from('<I', page, xb.HANDOFF_BITMAP_COUNT)[0] == xb.BITMAP_BITS)
ok('the randseed tag survives it',
   page[xb.RANDSEED_TAG_OFFSET:xb.RANDSEED_TAG_OFFSET + 8] == b'randseed')
ok('the seed length is tag + bytes',
   _struct.unpack_from('<Q', page, xb.RANDSEED_LENGTH_OFFSET)[0]
   == 8 + xb.RANDSEED_BYTES)

# +0x18 is the first physical address XNU's early allocator hands out
# (handoff +0x18 -> 0xfffffe0007d9fd60 -> the cursor at 0xfffffe0007da06c8;
# pmap_bootstrap carves its pv page, ptd arena and ASID bitmap from it). It has
# to clear every byte the upload places AND every fixed reservation, because the
# monitor region's backing is written as chunks after this word is computed: a
# maximum over the chunks that existed at the time stopped at the table arena
# and published the first page behind 0xfffffecfffcfc000 as free.
avail = _struct.unpack_from('<Q', page, xb.SPTM_AVAIL_START)[0]
top_chunk = max(pa + len(b) for pa, b in built['chunks'].items())
ok('+0x18 is above every uploaded chunk', avail >= top_chunk,
   f'+0x18 is {avail:#x}, the upload ends at {top_chunk:#x}')
top_fixed = max(xb.PHYS_BASE + off + span for _, off, span in xb.reservations())
ok('+0x18 is above every fixed reservation', avail >= top_fixed,
   f'+0x18 is {avail:#x}, the reservations end at {top_fixed:#x}')
sptm_backing_end = xb.SPTM_DATA_PA + (xb.SPTM_REGION_END - xb.SPTM_REGION_VA)
# Temporary windows must begin vacant while their complete table hierarchy
# exists. A full-region RAM mapping caused the native "out of windows" panic.
copy_base, copy_pages = xb.GUEST_PROFILE.cpu_copy_windows
copy_count = xb.GUEST_PROFILE.monitor_stack_count * copy_pages
for i in range(copy_count):
    va = copy_base + i * 0x4000
    table = built['tables'].root
    for level in range(xb.start_level(), 3):
        descriptor = built['tables'].read(table, xb.index(level, va))
        assert descriptor & 3 == 3, (i, level, hex(descriptor))
        table = descriptor & 0x0000ffffffffc000
    leaf = built['tables'].read(table, xb.index(3, va))
    ok(f'CPU copy window {i} has allocated tables and a vacant leaf',
       leaf == 0 and built['tables'].walk(va) is None)
for va in (copy_base - 0x4000, copy_base + copy_count * 0x4000, xb.SPTM_REGION_END - 0x4000):
    ok(f'monitor backing beside copy windows remains at its original PA: {va:#x}',
       built['tables'].walk(va) == xb.SPTM_DATA_PA + va - xb.SPTM_REGION_VA)
ok('+0x18 is above the monitor region backing', avail >= sptm_backing_end,
   f'+0x18 is {avail:#x}, the backing ends at {sptm_backing_end:#x}')
# The check has to be able to fail: the old formula, a maximum over the chunks
# placed before the word was written, lands inside the backing.
old_formula = max(max(pa + len(b) for pa, b in built['chunks'].items()
                      if pa < xb.SPTM_DATA_PA),
                  xb.TABLE_PA + xb.TABLE_SPAN)
ok('...and a maximum over the earlier chunks alone would not be',
   old_formula < sptm_backing_end,
   f'old formula {old_formula:#x} is not below {sptm_backing_end:#x}, '
   'so this check cannot tell the two apart')

# The "12 GiB" MAP_PAGEs, derived instead of observed. The five pages XNU asks
# for above its static map are its serial console's registers, out of the tree
# we hand it: /arm-io/dockchannel-uart `reg` translated through arm-io's
# `ranges`. Measured on the device: four pages at 0x308128000 then one at
# 0x30810c000, in that order, with avail_start untouched. If the tree or the
# translation changes, this is where the number moves first.
windows = built['uart_windows']
pages = [base + n * 0x4000
         for base, size in windows for n in range((size + 0x3fff) >> 14)]
ok('the console has two register windows',
   [(b, s) for b, s in windows] == [(0x308128000, 0x10000), (0x30810c000, 0x1000)],
   f'{[(hex(b), hex(s)) for b, s in windows]}')
ok('...which are the five pages the device measured, in order',
   pages == [0x308128000, 0x30812c000, 0x308130000, 0x308134000, 0x30810c000],
   f'{[hex(p) for p in pages]}')
ok('...and none of them is memory we declared',
   all(not (xb.PHYS_BASE <= p < xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN) for p in pages),
   'a console register window inside the memory window would be mapped as RAM')
import types as _types


class _Prop:
    def __init__(self, value):
        self.value = value


_fake = _types.SimpleNamespace(nodes={
    '/device-tree/arm-io': {
        '#address-cells': _Prop(b'\x02\0\0\0'), '#size-cells': _Prop(b'\x02\0\0\0'),
        'ranges': _Prop(_struct.pack('<QQQ', 0, 0x210000000, 0x2f0000000))},
    '/device-tree/arm-io/x': {'reg': _Prop(_struct.pack('<QQ', 0x2f0000000, 0x1000))},
})
raises('a window outside every bus range is refused',
       lambda: xb.device_windows(_fake, 'x'), 'outside every')
_fake.nodes['/device-tree/arm-io']['#size-cells'] = _Prop(b'\x01\0\0\0')
raises('a bus without 64-bit cells is refused',
       lambda: xb.device_windows(_fake, 'x'), '64-bit')

# The seed size is checked for an EXACT value, not a bound. prng_random.c:75
# does `mov w8, #0x100` and panics "Expected %u seed bytes from bootloader, but
# got %u" -- so 64 panics exactly as 0 would, and so would 512. Asserted as an
# equality for that reason.
ok('the seed is exactly 256 bytes, which prng_random.c:75 requires',
   xb.RANDSEED_BYTES == 256, f'{xb.RANDSEED_BYTES} bytes')
ok('so the published length is 0x108',
   _struct.unpack_from('<Q', page, xb.RANDSEED_LENGTH_OFFSET)[0] == 0x108)
ok('the seed really is 256 bytes in the image, and not zeros',
   len(set(page[xb.RANDSEED_DATA_OFFSET:
                xb.RANDSEED_DATA_OFFSET + xb.RANDSEED_BYTES])) > 16,
   'the seed looks constant or short')
# The layout only fits at this size: the seed ends immediately before the
# length field, with nothing spare.
ok('the seed ends just below the length field',
   xb.RANDSEED_DATA_OFFSET + xb.RANDSEED_BYTES <= xb.RANDSEED_LENGTH_OFFSET,
   f'seed ends at {xb.RANDSEED_DATA_OFFSET + xb.RANDSEED_BYTES:#x}, '
   f'length field is at {xb.RANDSEED_LENGTH_OFFSET:#x}')
ok('nothing in the handoff overlaps any more', xb.check_handoff_overlap() == [],
   f'{xb.check_handoff_overlap()}')

# --------------------------------------------------------------------------
# The debug table at +0x60, replaying XNU's validator at 0xfffffe000b88b0e0
#
# A wrong value here does not fault and does not panic -- it takes a bail path
# that calls the same continuation with different arguments. That is precisely
# the kind of wrong answer that never announces itself, so it gets a test.

debug_va = _struct.unpack_from('<Q', page, xb.HANDOFF_DEBUG_TABLE)[0]
ok('+0x60 is not null, which is the validator\'s first check', debug_va != 0)

debug_pa = built['tables'].walk(debug_va)
ok('+0x60 resolves through the tables XNU will walk', debug_pa is not None,
   f'{debug_va:#x} is unmapped')

header = flatten(debug_pa, xb.DEBUG_TABLE_HEADER)
magic, version, count = _struct.unpack_from('<III', header, 0)
ok("the magic is 'DEBG'", magic == xb.DEBUG_TABLE_MAGIC,
   f'{magic:#010x} is {magic.to_bytes(4, "little")!r}, not b"DEBG"')
ok('the magic really spells DEBG in memory order',
   magic.to_bytes(4, 'little') == b'DEBG')
ok('the version is 2', version == xb.DEBUG_TABLE_VERSION, f'version {version}')
# The header is not the whole structure, and this is the regression that taught
# us so, so the pointers are checked BEFORE anything about the count -- a
# failure here is the one that stops a boot, and it should be the line printed.
#
# A second consumer at 0xfffffe000ba7a6ec reads +0x10 and +0x20 WITHOUT
# consulting the count and walks each as a Mach-O. The walk has no bound, so a
# null faults at 0x20 and a wrong pointer wanders -- neither says what happened.
written = max(xb.DEBUG_TABLE_IMAGES) + 8       # the slots are 16 apart, not adjacent
header_full = flatten(debug_pa, written)
for slot, name in zip(xb.DEBUG_TABLE_IMAGES, xb.MONITOR_IMAGES):
    image_va = _struct.unpack_from('<Q', header_full, slot)[0]
    ok(f'+{slot:#x} ({name}) is not null', image_va != 0,
       'a null here faults at 0x20, which is exactly the regression')
    image_pa = built['tables'].walk(image_va)
    ok(f'+{slot:#x} resolves through the guest tables', image_pa is not None,
       f'{image_va:#x} is unmapped')

    macho = flatten(image_pa, 0x4000)
    magic_word, _, _, _, ncmds = _struct.unpack_from('<IiiII', macho, 0)
    ok(f'+{slot:#x} points at a 64-bit Mach-O header',
       magic_word == 0xFEEDFACF, f'magic {magic_word:#x}')

    # XNU: x22 = image + 0x20, then advance by cmdsize until cmd == 0x19 and
    # strncmp(segname, "__TEXT", 16) matches.
    cursor, found, steps = 0x20, None, 0
    while steps < ncmds + 4:
        cmd, cmdsize = _struct.unpack_from('<II', macho, cursor)
        if cmd == 0x19 and macho[cursor + 8:cursor + 14] == b'__TEXT' \
           and macho[cursor + 14] == 0:
            found = cursor
            break
        if not cmdsize:
            break
        cursor += cmdsize
        steps += 1
    ok(f'+{slot:#x} has a __TEXT segment the walk can find', found is not None,
       'the walk advances by cmdsize with no bound, so a miss does not '
       'terminate cleanly')
    ok(f'+{slot:#x} finds it on the first load command', found == 0x20,
       f'found at +{found:#x}; correct but further in than expected')

# Only now the count, which is the weaker claim: a count of 0 leaves the
# validator computing a size of 0x10, which excludes the pointers just checked.
ok('the count is what the loader declares', count == xb.DEBUG_TABLE_COUNT)
validator_size = count * xb.DEBUG_TABLE_ENTRY + xb.DEBUG_TABLE_HEADER
ok('the size the validator computes covers what is actually written',
   validator_size >= written,
   f'validator says {validator_size:#x}, the table is {written:#x} bytes')

# --------------------------------------------------------------------------
# Monitor stack ranges: both XNU's exception predicate and TXM's unconditional
# six-buffer translation must agree with the uploaded memory and reservations.

region_ptr = _struct.unpack_from('<Q', page, xb.HANDOFF_TXM_STACKS)[0]
region_count = _struct.unpack_from('<I', page, xb.HANDOFF_TXM_STACK_COUNT)[0]
region_low = _struct.unpack_from('<Q', page, xb.HANDOFF_CPU_STACK_LOW)[0]
region_high = _struct.unpack_from('<Q', page, xb.HANDOFF_CPU_STACK_HIGH)[0]

ok('the region array pointer is not null', region_ptr != 0)
ok('the region count is not zero, which the predicate rejects outright',
   region_count != 0)
region_pa = built['tables'].walk(region_ptr)
ok('the region array resolves through the guest tables', region_pa is not None,
   f'{region_ptr:#x} is unmapped')

array_bytes = flatten(region_pa, region_count * 8)
array = list(_struct.unpack_from(f'<{region_count}Q', array_bytes, 0))
ok('the array is ascending, as the predicate assumes',
   all(a < b for a, b in zip(array, array[1:])), f'{[hex(a) for a in array]}')
ok('the count matches the entries actually written', len(array) == region_count)


def accepts(x):
    """XNU's predicate, at 0xfffffe000b8b78f0 and two identical siblings."""
    if not (x < region_low) and x < region_high:
        return True                      # the fast window
    if region_count == 0:
        return False
    if x < array[0]:
        return False
    return x < array[region_count - 1] + 0x4000


ok('TXM has one distinct stack per audited guest CPU',
   region_count == xb.GUEST_PROFILE.monitor_stack_count and len(set(array)) == region_count)
for n, va in enumerate(array):
    pa = built['tables'].walk(va)
    ok(f'TXM stack {n} is mapped, aligned and outside the guest allocator',
       pa is not None and pa % 0x4000 == 0 and xb.SPTM_DATA_PA <= pa
       and pa + 0x4000 <= built['alloc_low'])
    ok(f'TXM stack {n} is uploaded as a complete zeroed page',
       pa in built['chunks'] and built['chunks'][pa] == bytes(0x4000))
ok('monitor CPU stacks are mapped and disjoint from the TXM stacks',
   region_low >= array[-1] + 0x4000 and region_high - region_low == 0x100000
   and built['tables'].walk(region_low) is not None
   and built['tables'].walk(region_high - 1) < built['alloc_low'])
for x, want in ((array[0] - 1, False), (array[0], True),
                (array[-1] + 0x3fff, True), (region_low, True),
                (region_high - 1, True), (region_high, False),
                (xb.PHYS_BASE, False), (xb.IMAGE_PA, False), (0, False)):
    ok(f'stack predicate {x:#x} is {"accepted" if want else "rejected"}', accepts(x) == want)


# --------------------------------------------------------------------------
# The flat frame map, replaying sptm_get_frame_type (0xfffffe000c22aaec)
#
# Every page we own must resolve to something other than 0x1a, which is the
# kernel's "not in the map" answer and matches no required type. The exact type
# byte is a hypothesis; that every page resolves at all is not.

fm_low = _struct.unpack_from('<Q', page, xb.HANDOFF_TABLE_OFFSET + xb.FRAMEMAP_LOW)[0]
fm_high = _struct.unpack_from('<Q', page, xb.HANDOFF_TABLE_OFFSET + xb.FRAMEMAP_HIGH)[0]
fm_base = _struct.unpack_from('<Q', page, xb.HANDOFF_TABLE_OFFSET + xb.FRAMEMAP_BASE)[0]
type_info = _struct.unpack_from('<Q', page, xb.HANDOFF_TABLE_OFFSET + xb.HANDOFF_FRAME_TYPES)[0]
ok('frame-reference queries receive the audited SPTM type descriptors',
   type_info == xb.GUEST_PROFILE.frame_type_info_va)
for frame_type, frame_class in ((11, 3), (20, 2), (25, 3), (35, 3)):
    info_pa = built['tables'].walk(type_info + frame_type * 144)
    descriptor = next((blob[info_pa - start:info_pa - start + 8]
                       for start, blob in built['chunks'].items()
                       if info_pa is not None and start <= info_pa and
                       info_pa + 8 <= start + len(blob)), b'')
    ok(f'type {frame_type} descriptor is backed by the audited monitor data',
       len(descriptor) == 8 and descriptor[1] == frame_class)

ok('the frame map bounds are the memory we own',
   (fm_low, fm_high) == (xb.PHYS_BASE, xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN),
   f'{fm_low:#x}..{fm_high:#x}')
ok('the bounds are physical, as the consumer compares them against a paddr',
   fm_low < (1 << 48) and fm_low == xb.PHYS_BASE)
ok('the map base is virtual, as the consumer dereferences it',
   fm_base >= xb.KERNEL_BASE, f'{fm_base:#x} is not an upper-half address')
fm_pa = built['tables'].walk(fm_base)
ok('the map base resolves through the guest tables', fm_pa is not None,
   f'{fm_base:#x} is unmapped')
ok('it resolves to where the loader put the map', fm_pa == xb.FRAMEMAP_PA,
   f'{fm_pa:#x} is not {xb.FRAMEMAP_PA:#x}')

frames = (fm_high - fm_low) >> 14
fm = flatten(xb.FRAMEMAP_PA, frames * xb.FRAMEMAP_ENTRY)
ok('the map is big enough for every frame in range',
   len(fm) == frames * xb.FRAMEMAP_ENTRY)
ok('and fits its arena', frames * xb.FRAMEMAP_ENTRY <= xb.FRAMEMAP_SPAN)


def sptm_get_frame_type(paddr):
    """The consumer, replayed: 16 bytes per 16K frame, type byte at +2."""
    if not (paddr >= fm_low and paddr < fm_high):
        return 0x1A                       # falls to the region search
    index = ((paddr - fm_low) >> 10) & 0x3FFFFFFFFFFFF0
    return fm[index + xb.FRAMEMAP_TYPE_BYTE]


want, _ = xb.frame_type()
for label, pa in (('the first page', fm_low),
                  ('the kernel image', xb.IMAGE_PA),
                  ('our page tables', xb.TABLE_PA),
                  ('the last page', fm_high - 0x4000)):
    ok(f'{label} resolves to a type', sptm_get_frame_type(pa) == want,
       f'{pa:#x} reads {sptm_get_frame_type(pa):#x}, wanted {want:#x}')
    ok(f'{label} is not the not-found answer', sptm_get_frame_type(pa) != 0x1A)

ok('one past the end falls out of range', sptm_get_frame_type(fm_high) == 0x1A)
ok('and so does zero', sptm_get_frame_type(0) == 0x1A)

# The scratch must no longer be published at +0x18: that field is the map's low
# bound, and writing a scratch pointer into it is what this commit corrected.
ok('the scratch base is not published over the frame map bound',
   fm_low != xb.SCRATCH_PA,
   'table +0x18 still holds SCRATCH_PA, which is the bug this fixed')


# --------------------------------------------------------------------------
# The kernel's static virtual map, handoff +0x08 and +0x10
#
# Both were wrong: +0x10 held a physical address and +0x08 was never written,
# leaving XNU carrying the window [0, 0xf2000000]. The test is not that the
# fields are non-zero but that the window covers every kernel VA we map -- a
# window that excludes one is a new silent wrong answer for an old one.

vs_base = _struct.unpack_from('<Q', page, xb.VSPACE_BASE_OFFSET)[0]
vs_top = _struct.unpack_from('<Q', page, xb.VSPACE_TOP_OFFSET)[0]
GUARD = 0xFFFFFED000000000       # 0xfffffe000ba79464: b.hs here and XNU bails

ok('the window base is a kernel VA, not zero and not physical',
   vs_base >= xb.KERNEL_BASE, f'{vs_base:#x}')
ok('the window top is a kernel VA', vs_top >= xb.KERNEL_BASE, f'{vs_top:#x}')
ok('the top passes the guard at 0xfffffe000ba79464', vs_top < GUARD,
   f'{vs_top:#x} is at or above {GUARD:#x} and XNU would bail')
ok('the early heap is inside the narrow queue-pointer range',
   vs_top + 1 < xb.GUEST_PROFILE.queue_pointer_base + (1 << 38))
ok('the top is inclusive, matching the `cset w8, ls` in the consumer',
   vs_top == xb.GUEST_PROFILE.early_heap_va - 1)

# The 42-bit encoding at 0xfffffe000ba770d4: (addr - base) must fit.
span = vs_top - vs_base + 1
ok('the span fits the 42-bit offset field', span.bit_length() <= 42,
   f'{span:#x} needs {span.bit_length()} bits')
ok('a zero base would NOT have fit, which is why it mattered',
   (vs_top - 0 + 1).bit_length() > 42)

# Every kernel VA this loader maps has to be inside it.
built_lo = built['x2']
for label, va in (('the handoff', built_lo),
                  ('the image base', built['vmin']),
                  ('the image top', built['image'].vmax - 1),
                  ('the aperture', xb.APERTURE_VA),
                  ('the aperture top', xb.APERTURE_VA + xb.REGION_SPAN - 1)):
    ok(f'{label} is inside the window', vs_base <= va <= vs_top,
       f'{va:#x} is outside [{vs_base:#x}, {vs_top:#x}]')

ok('one past the top is outside', not (vs_base <= vs_top + 1 <= vs_top))

# The aperture alone would not have done, which is the reason the window is
# this wide rather than sized to what we publish.
ok('an aperture-sized window would have excluded the monitor region',
   not (xb.APERTURE_VA <= xb.SPTM_REGION_VA <= xb.APERTURE_VA + xb.REGION_SPAN))
ok('...and the kernel image', not (xb.APERTURE_VA <= built['vmin']))


# --------------------------------------------------------------------------
# The free-VA walk above the static map, replaying 0xfffffe000ba7a878
#
# XNU walks 24 MiB above VSPACE_TOP expecting the table levels to exist, reads
# the L1 and L2 descriptors, and registers the L3 table page. The L1 entry was
# zero, phystokv(0) failed correctly, and a `csel` substituted zero unchecked.
# Leaves are NOT read, which is the difference between two table pages and the
# whole range's worth of backing.

walk_base = xb.VSPACE_TOP + 1
ok('the walk starts one past the top of the static map',
   walk_base == xb.VSPACE_TOP + 1 and walk_base % (1 << 14) == 0)

# The old heap used L1[2029]; the corrected heap shares the image/aperture L1
# and has its own L2 slot. The walk must still find a complete empty L3 table.
walk_off = walk_base & ((1 << (64 - xb.T1SZ)) - 1)
ok('the heap and image share their L1 region',
   xb.index(1, walk_off) == xb.index(1, built['vmin']),
   f'L1[{xb.index(1, walk_off)}]')
ok('the heap begins at an L3 table boundary', walk_base % (1 << 25) == 0)
ok('one L3 table covers the whole 24 MiB range',
   xb.VSPACE_WALK_SPAN <= (1 << (14 + 11)),
   f'{xb.VSPACE_WALK_SPAN >> 20} MiB needs more than one L3 table')

tbl = built['tables']
leaf_reach = 1 << (14 + 11)                  # one L3 table covers 32 MiB
for step in range(0, xb.VSPACE_WALK_SPAN, leaf_reach):
    off = (walk_base + step) & ((1 << (64 - xb.T1SZ)) - 1)
    table, seen = tbl.root, []
    for level in range(xb.start_level(), 3):
        entry = tbl.read(table, xb.index(level, off))
        seen.append((level, entry))
        ok(f'L{level} for {walk_base + step:#x} is present', entry & 1,
           f'entry {entry:#x} -- phystokv(0) then faults at FAR_EL1 = 0')
        ok(f'L{level} for {walk_base + step:#x} is a table, not a block',
           entry & 2)
        table = entry & 0x0000FFFFFFFFC000
    # Empty AT BUILD TIME, which is what this suite can see: it runs against
    # the loader's output and never against the device. XNU populates these as
    # soon as it boots -- five of them in the last run -- so an assertion that
    # meant "empty on the machine" would be wrong the moment it worked.
    ok(f'the L3 table for {walk_base + step:#x} is empty as built',
       all(tbl.read(table, n) == 0 for n in range(0, 2048, 256)),
       'the loader mapped a leaf here; XNU expects to fill these itself')

# Cost: the whole point of reserving levels rather than mapping the range.
mapped_cost = xb.VSPACE_WALK_SPAN
ok('reserving costs table pages, not the range',
   tbl.size < mapped_cost // 8,
   f'{tbl.size} bytes of tables against {mapped_cost} if it were mapped')
ok('the tables still fit their arena', tbl.next - tbl.base <= xb.TABLE_SPAN)


# --------------------------------------------------------------------------
# The 42-bit offset encoding at 0xfffffe000ba770d4
#
# `sub x11, x9, x10 ; bfi x10, x11, #0x16, #0x2a` encodes (addr - base) in 42
# bits. Two ways out, failing through different instructions and both silent,
# so they are two checks with two messages rather than one range test.


class FakeTables:
    def __init__(self, ranges):
        self.ranges = ranges


def refuses(name, ranges, needle):
    global checks
    checks += 1
    try:
        xb.validate_vspace(FakeTables(ranges))
    except SystemExit as error:
        if needle not in str(error):
            print(f'FAIL: {name}\n  refused, but said {str(error)[:120]!r}')
            sys.exit(1)
        return
    print(f'FAIL: {name}\n  was accepted')
    sys.exit(1)


refuses('a VA below the base is refused, naming the wrap',
        [(xb.VSPACE_BASE - (1 << 14), 1 << 14, 'mapped')], 'would wrap')
refuses('a VA past the 42-bit field is refused, naming the truncation',
        [(xb.VSPACE_BASE + xb.VSPACE_OFFSET_LIMIT - (1 << 14), 1 << 15, 'mapped')],
        'truncated')

# The two messages must differ: same silent outcome, different arithmetic.
def message(ranges):
    try:
        xb.validate_vspace(FakeTables(ranges))
    except SystemExit as error:
        return str(error)
    return ''


below = message([(xb.VSPACE_BASE - (1 << 14), 1 << 14, 'mapped')])
past = message([(xb.VSPACE_BASE + xb.VSPACE_OFFSET_LIMIT - (1 << 14), 1 << 15, 'm')])
ok('the two failures report differently', below != past)
ok('neither message mentions the other cause',
   'truncated' not in below and 'wrap' not in past)

# The identity reserve is low-half and must be skipped, not failed.
xb.validate_vspace(FakeTables([(0xf2000000, 1 << 14, 'mapped')]))
checks += 1

# The base bound is derived from the top, so it cannot go stale if the top
# moves. Checked by moving the top and seeing the bound move with it.
saved = xb.VSPACE_BASE
try:
    xb.VSPACE_BASE = xb.VSPACE_TOP - xb.VSPACE_OFFSET_LIMIT
    refuses('a window wider than the field is refused',
            [], 'spans more than')
finally:
    xb.VSPACE_BASE = saved
xb.validate_vspace(FakeTables([]))          # and the real one still passes
checks += 1

# Every range the loader actually maps must satisfy it -- this is the check
# that would catch a new mapping placed outside the encodable window.
xb.validate_vspace(built['tables'])
checks += 1
ok('the loader maps something in the upper half at all',
   any(va >= xb.KERNEL_BASE for va, _, _ in built['tables'].ranges))
ok('and records the identity reserve as low-half',
   any(va < xb.KERNEL_BASE for va, _, _ in built['tables'].ranges))

# --------------------------------------------------------------------------
# The panel handover -- the first/last panel pages are typed, the gap is not,
# and the fast window still describes only DRAM + reserve.

fb_saved = xb.FRAMEBUFFER
try:
    # The device's own layout, not the module defaults: the runner calls
    # place(0xda000000, ...), which gives a different root and a lower reserve.
    xb.place(0xDA000000, guest_span=xb.GUEST_SPAN)
    xb.FRAMEBUFFER = (0xF9A20000, 2732, 1896, 2732 * 4, 32)
    fb_base, _, fb_height, fb_stride, _ = xb.FRAMEBUFFER
    fb_span = (fb_stride * fb_height + 0x3FFF) & ~0x3FFF
    fb_pa = fb_base & ~0x3FFF

    # The geometry has to be the panel the device actually reported, or this
    # tests an address the machine never asks about. docs/APERTURE-FAULT.md
    # recorded the range read back off the target.
    ok('the panel geometry reproduces the range recorded on the device',
       (fb_pa, fb_pa + fb_span) == (0xF9A20000, 0xFADE4000),
       f'derived {fb_pa:#x}..{fb_pa + fb_span:#x}, recorded 0xf9a20000..0xfade4000')

    fb_built = xb.build(str(xb.DEFAULT_KERNELCACHE))

    def fb_flatten(base, span):
        image = bytearray(span)
        for pa, blob in sorted(fb_built['chunks'].items()):
            if pa >= base + span or pa + len(blob) <= base:
                continue
            image[pa - base:pa - base + len(blob)] = bytes(blob)
        return bytes(image)

    fb_page = fb_flatten(xb.HANDOFF_PA, 0x80000)
    w_low = _struct.unpack_from('<Q', fb_page, xb.HANDOFF_CPU_STACK_LOW)[0]
    w_high = _struct.unpack_from('<Q', fb_page, xb.HANDOFF_CPU_STACK_HIGH)[0]
    m_low = _struct.unpack_from('<Q', fb_page,
                                xb.HANDOFF_TABLE_OFFSET + xb.FRAMEMAP_LOW)[0]
    m_high = _struct.unpack_from('<Q', fb_page,
                                 xb.HANDOFF_TABLE_OFFSET + xb.FRAMEMAP_HIGH)[0]

    ok('the frame map covers the complete panel',
       m_low <= fb_pa and fb_pa + fb_span <= m_high,
       f'panel {fb_pa:#x}, map {m_low:#x}..{m_high:#x}')

    m_frames = (m_high - m_low) >> 14
    m_bytes = fb_flatten(xb.FRAMEMAP_PA, m_frames * xb.FRAMEMAP_ENTRY)

    def fb_frame_type(paddr):
        if not (paddr >= m_low and paddr < m_high):
            return 0x1A
        index = ((paddr - m_low) >> 10) & 0x3FFFFFFFFFFFF0
        return m_bytes[index + xb.FRAMEMAP_TYPE_BYTE]

    # Both ends of the panel, and the hole before it.
    ok('a framebuffer page has the requested frame type',
       fb_frame_type(fb_pa) == xb.frame_type()[0],
       f'reads {fb_frame_type(fb_pa):#x}')
    ok('and so does its last page',
       fb_frame_type(fb_pa + fb_span - 0x4000) == xb.frame_type()[0])
    ok('the gap is described as untyped, not usable RAM',
       all(fb_frame_type(pa) == 0 for pa in range(xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN, fb_pa, 0x4000)))
    ok('the first byte after the panel remains outside the map',
       fb_frame_type(fb_pa + fb_span) == 0x1A)
    ok('while a page we do own still resolves to a real type',
       fb_frame_type(xb.IMAGE_PA) != 0x1A)

    # The panel must never become a monitor stack.
    ok('the panel is outside the monitor CPU-stack window',
       not (fb_pa >= w_low and fb_pa < w_high),
       f'panel {fb_pa:#x}, window {w_low:#x}..{w_high:#x}')

    fb_count = _struct.unpack_from('<I', fb_page, xb.HANDOFF_TXM_STACK_COUNT)[0]
    fb_ptr = _struct.unpack_from('<Q', fb_page, xb.HANDOFF_TXM_STACKS)[0]
    fb_arr_pa = fb_built['tables'].walk(fb_ptr)
    fb_arr = list(_struct.unpack_from(
        f'<{fb_count}Q', fb_flatten(fb_arr_pa, fb_count * 8), 0))
    ok('the panel does not change the monitor stack array',
       fb_count == xb.GUEST_PROFILE.monitor_stack_count
       and all(fb_built['tables'].walk(va) < xb.SPTM_DATA_PA + xb.SPTM_DATA_SPAN
               for va in fb_arr)
       and all(not (va <= fb_pa < va + 0x4000) for va in fb_arr))

finally:
    xb.FRAMEBUFFER = fb_saved
    restore()


# --------------------------------------------------------------------------
# The stage-2 map -- docs/PLAN-HISTORY-20260922.md Section 0, T4: exactly what we own, nothing else
#
# probes/xnuboot.c maps three ranges to themselves at stage 2 -- the memory we
# declared with the reserve above it, the panel when it is handed over, and the
# probe's own work area read-only -- and leaves every other intermediate
# address absent, so a touch stops the run with the IPA. The list is derived by
# xnuboot.stage2_ranges() from the same numbers the probe reads (mem_low,
# mem_high, fb_pa, fb_span in the params blob; the work area from q1n1's heap)
# and is checked here against what the loader actually uploads. The map
# builder itself is walked page by page in tools/test-stage2.c; this is the
# other half, that the list it is handed is the right list.
#
# On the device's own layout, place(0xda000000, ...): the module defaults give
# a different root and a reserve 0x200000 lower, and a check against them is a
# check against a machine that does not exist.

# Historical low-memory work-area fixture, passed as an explicit (base, size).
# Current xnuboot reserves an external arena; test-monitor-work.py and the
# native test-stage2.c cover that placement and its protection boundaries.
S2_WORK = ((0x82000000 + 0x500000 + 0xFFFF) & ~0xFFFF, 0x2000000)

s2_fb_saved = xb.FRAMEBUFFER
try:
    xb.place(0xDA000000, guest_span=xb.GUEST_SPAN)
    xb.FRAMEBUFFER = None
    s2_built = xb.build(str(xb.DEFAULT_KERNELCACHE))
    s2_ranges = xb.stage2_ranges(work=S2_WORK)

    ok('with the panel withheld the map is two ranges: memory and table arena',
       [(w, a) for _, _, a, w in s2_ranges]
       == [('DRAM + reserve', 'rw'), ('shadow table arena; private context excluded', 'ro')],
       f'{s2_ranges}')
    dram_lo, dram_hi = s2_ranges[0][0], s2_ranges[0][1]
    ok('the memory range is 0xda000000..0xf5000000 on the device: 384 MiB declared '
       'plus the 48 MiB reserve',
       (dram_lo, dram_hi) == (0xDA000000, 0xF5000000),
       f'{dram_lo:#x}..{dram_hi:#x}')
    ok('it starts exactly where the loader starts uploading',
       dram_lo == min(s2_built['chunks']) == xb.PHYS_BASE)
    ok('and ends exactly at the top of the reserve, not a page further',
       dram_hi == xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN == xb.REGION_END + xb.BOOTSTRAP_SPAN)

    # Every uploaded chunk, the whole of it, inside the memory range.
    s2_outside = [(pa, len(b)) for pa, b in s2_built['chunks'].items()
                  if not (dram_lo <= pa and pa + len(b) <= dram_hi)]
    ok('every uploaded chunk lies inside the memory range', not s2_outside,
       f'outside: {[(hex(pa), n) for pa, n in s2_outside[:3]]}')
    # Every 16K guest table page too. They are in tables.pages, not in chunks:
    # a walk over chunks reads zeros and looks like a missing table.
    s2_pages = s2_built['tables'].pages
    s2_outside = [pa for pa in s2_pages
                  if not (dram_lo <= pa and pa + len(s2_pages[pa]) <= dram_hi)]
    ok('every 16K guest table page lies inside the memory range', not s2_outside,
       f'outside: {[hex(pa) for pa in s2_outside[:3]]}')
    ok('there are chunks and table pages to cover, so those checks are not vacuous',
       len(s2_built['chunks']) > 10 and len(s2_pages) > 10,
       f'{len(s2_built["chunks"])} chunks, {len(s2_pages)} table pages')
    ok('the reserve the kernel builds into is inside the range',
       dram_lo <= xb.BOOTSTRAP_PA and xb.BOOTSTRAP_PA + xb.BOOTSTRAP_SPAN <= dram_hi)
    ok('the work area is exactly what run.py hands xnuboot_setup, read-only',
       s2_ranges[1][:3] == (S2_WORK[0], S2_WORK[0] + S2_WORK[1], 'ro'),
       f'{s2_ranges[1]}')
    # Every page the probe guards -- the monitor-call pages, XNU's vectors, the
    # watched handoff pages -- has to be in the map already: a guard changes
    # what a mapped page does, and the probe refuses (-4, -5, -7) to guard a
    # page that is absent. Checked here so that refusal cannot be a layout's.
    s2_guarded = (list(s2_built['stub_pa']) + [s2_built['vbar_pa']]
                  + [xb.HANDOFF_PA + n * 0x1000 for n in range(s2_built['watch_count'])])
    ok('every page the probe guards is inside the memory range',
       s2_guarded and all(dram_lo <= pa < dram_hi for pa in s2_guarded),
       f'{[hex(pa) for pa in s2_guarded]}')

    # The params blob carries the same two numbers the probe maps from, and no
    # panel; and both files agree on its length, read out of the C source.
    s2_params = s2_built['chunks'][xb.PARAMS_PA]
    ok('the params blob is PARAMS_WORDS long', len(s2_params) == xb.PARAMS_WORDS * 8)
    s2_words = _struct.unpack(f'<{xb.PARAMS_WORDS}Q', s2_params)
    param_layout=MonitorLayout()
    param_word=lambda field:s2_words[param_layout.offset('params',field)//8]
    ok('physical and virtual clock rates are distinct appended ABI fields',
       (param_word('clock_host_hz'),param_word('clock_guest_hz')) == (xb.HOST_TIMEBASE_HZ, xb.TIMEBASE_HZ) and
       xb.TIMEBASE_HZ == xb.GUEST_PROFILE.virtual_counter_hz)
    ok('const bounds exclude writable data and disposable LINKEDIT',
       (param_word('const_begin'),param_word('const_end'))==(xb.IMAGE_PA,xb.IMAGE_PA+0x5268000))
    fm_table = xb.HANDOFF_TABLE_OFFSET
    fm_handoff = s2_built['chunks'][xb.HANDOFF_PA]
    ok('RETYPE receives the guest-visible frame-map envelope',
       s2_words[43:46] == (xb.FRAMEMAP_PA,
           _struct.unpack_from('<Q', fm_handoff, fm_table + xb.FRAMEMAP_LOW)[0],
           _struct.unpack_from('<Q', fm_handoff, fm_table + xb.FRAMEMAP_HIGH)[0]))
    ok('RETYPE excludes loader reservations and the bootstrap reserve',
       s2_words[46:48] == (
           _struct.unpack_from('<Q', fm_handoff, xb.SPTM_AVAIL_START)[0], xb.REGION_END))
    ok('MAP_PAGE receives the guest RAM aperture for its PTE pointer result',
       s2_words[48] == xb.APERTURE_VA)
    ok('write watch is disabled by default', s2_words[49] == 0)
    ok('TXM receives only its dedicated stack and log allocations',
       s2_words[50:53] == (s2_built['txm_stacks_pa'],
           xb.GUEST_PROFILE.monitor_stack_count, s2_built['txm_log_pa']))
    ok('the TXM log starts empty and remains outside the allocator',
       s2_built['chunks'][s2_built['txm_log_pa']] == bytes(0x4000)
       and s2_built['txm_log_pa'] + 0x4000 <= s2_built['alloc_low'])
    info = s2_built['chunks'][s2_built['txm_ro_pa']]
    ok('virtual TXM publishes platform class0 with no SEP channel descriptor',
       info[0xa] == 0 and _struct.unpack_from('<3Q', info, 0x38) == (0, 0, 0))
    policy_va = _struct.unpack_from('<Q', info, xb.GUEST_PROFILE.txm_policy_pointer_offset)[0]
    ok('TXM policy pointer resolves to the actual zero-feature policy page',
       s2_built['tables'].walk(policy_va) == s2_built['txm_ro_pa'] and info[0x48] == 0)
    ok('monitor signing is explicitly unavailable and developer mode is separate',
       info[xb.GUEST_PROFILE.txm_csm_disabled_offset] == 1 and info[0x3ff0] == 1)
    ok('TXM mutable metrics and policy occupy separate reserved pages',
       s2_words[53:55] == (s2_built['txm_rw_pa'], s2_built['txm_ro_pa'])
       and s2_words[53] != s2_words[54] and s2_words[54] + 0x4000 <= s2_built['alloc_low'])
    pool_pa = s2_built['txm_aspace_pa']
    ok('TXM address-space pool is zeroed, mapped and excluded from the allocator',
       s2_words[55] == pool_pa and pool_pa >= s2_words[54] + 0x4000
       and pool_pa + 0x4000 <= s2_built['alloc_low']
       and s2_built['chunks'][pool_pa] == bytes(0x4000)
       and s2_built['tables'].walk(xb.APERTURE_VA + pool_pa - xb.PHYS_BASE) == pool_pa)
    uat_pa = s2_built['uat_pa']
    uat_va = xb.APERTURE_VA + uat_pa - xb.PHYS_BASE
    state = s2_built['chunks'][uat_pa]
    uat_l1 = s2_built['chunks'][uat_pa + 0x4000]
    ok('UAT geometry is derived from this guest DT and uploaded intact',
       s2_words[56:60] == (uat_pa, 1, 43, 64))
    slide = s2_words[60:90]
    ok('virtual device registry follows the unchanged monitor parameter fields',
        s2_words[90:99] == (120, 1, 0x220000000, 0x140000, 4, 0, 0, 0, 0)
       and s2_words[99:131] == tuple(v for bank in range(4) for v in
           (2, 0x220400000 + bank*0x200000, 0x39000, 0, 0, 0, 0, 0))
       and s2_words[131:155] == tuple(v for i,n in enumerate((31,36,35)) for v in
           (4, 0x24f008000+i*0x1000000, 0x8000, n, 0, 0, 0, 0))
       and s2_words[155:163] == (3, 0x301000000, 0x1cc000, 1280, 4096, 0x40000, 0xa, 0)
       and s2_words[163:171] == (5, 0x3082b0000, 0x4000, 24000000, 0, 0, 0, 0)
       and s2_words[171:179] == (25, 0x3003c0000, 0x14000, 0x10000, 0x1a8, 0x1b8, 8, 0xffb80)
       and s2_words[179:187] == (40, 0x31a000000, 0x100000, 216, 7, 0x7f,
                                5096408961622, 5878381359781)
       and s2_words[187:195] == (7, 0x314838000, 0x4000, 10, 7, 0x70, 0, 0)
       and s2_words[195:203] == (7, 0x310824000, 0x4000, 57, 7, 0x70, 0, 0)
       and s2_words[203:211] == (7, 0x3081f0000, 0x4000, 30, 7, 0x70, 0, 0)
       and s2_words[211:219] == (7, 0x30c820000, 0x4000, 6, 7, 0x60, 0, 0)
       and s2_words[219:227] == (8, 0x3082dc000, 0x8000, 0, 0x40, 0x44, 0x48, 0x30)  # + PMGR BPR word
       and s2_words[227:235] == (47, 0x38500c000, 0x4000, 5, 42, 1107, 21, 1)
       and s2_words[235:243] == (9, 0x308700000, 0x18000, 0x14000, 0x4000, 487, 256, 256)
       and s2_words[243:251] == (9, 0x308600000, 0x18000, 0x14000, 0x4000, 492, 256, 256)
       and s2_words[251:259] == (9, 0x310900000, 0x18000, 0x14000, 0x4000, 432, 256, 256)
       and s2_words[259:267] == (9, 0x308900000, 0xc000, 0x8000, 0x4000, 494, 256, 256)
       and s2_words[267:275] == (10, 0x3082d8000, 0x1000, 8, 1 << 22, 0, 0, 0)
       and s2_words[275:283] == (13, 0x314b00000, 0x35000, 0x14000, 0x28000, 1137, 2048, 0)
       and s2_words[283:331] == tuple(v for i,base in enumerate(
           (0x24f000000,0x250000000,0x251000000,0x252000000,0x25f000000,0x26f000000))
           for v in (14,base,0x4000,i,0,0,0,0))
       and s2_words[331:339] == (15,0x25300a000,0x1000,0x104,1,0,0,0)
       and s2_words[339:347] == (15,0x254000000,0x20000,0x4084,0,0,0,0)
        and s2_words[347:355] == (16,0x3082a8000,0x1000,24000000,0,0,0,0))
    dart_words = [s2_words[i:i+8] for i in range(355,587,8)]
    ok('29 distinct DART banks occupy the expanded registry',
       len(dart_words)==29 and all(d[0]==17 for d in dart_words) and
       len({d[1] for d in dart_words})==29 and
       (17,0x385060000,0x20000,16,300,1120,36,1<<21) in dart_words and
       s2_words[587:603]==(18,0x300700000,0x11000,0,1,0,0,0,
                             18,0x308280000,0x9000,1,0,0,0,0) and
       s2_words[603:627]==(19,0x3082c8000,0x4000,0,0,0,0,0,
                          20,0x210e78000,0x1000,0,0,0,0,0,
                          20,0x211e78000,0x1000,1,0,0,0,0) and
       s2_words[627:643]==(21,0x210e70000,0x1000,0,0,0,0,0,
                           21,0x211e70000,0x1000,1,0,0,0,0) and
       s2_words[643:659]==(22,0x30827b000,0x1000,6,0,0,0,0,
                           22,0x3082b4000,0x1000,7,0,0,0,0) and
       s2_words[659:667]==(23,0x308004000,0x1000,0,0,0,0,0) and
       s2_words[667:675]==(24,0x3003d8000,0x1000,0,0,0,0,0) and
        s2_words[675:683]==(26,0x300780000,0x1000,1,0,0,0,0) and
        s2_words[683:691]==(27,0x300724000,0x1000,0,0,0,0,0) and
        s2_words[691:699]==(28,0x30020a000,0x3000,0,0,0,0,0) and
        s2_words[699:779]==tuple(word for base in (
            0x408000000,0x413000000,0x417000000,0x38b000000,0x380000000,
            0x284000000,0x288000000,0x481000000,0x28c000000,0x396000000)
            for word in (29,base,0x1000,0,0,0,0,0)) and
        s2_words[779:787]==(30,0x3028ac000,0x1000,0,0,0,0,0) and
        s2_words[787:795]==(31,0x302860000,0x1000,0,0,0,0,0) and
        s2_words[795:803]==(32,0x3028a4000,0x6000,0,0,0,0,0) and
        s2_words[803:811]==(33,0x300760000,0x1000,0,0,0,0,0) and
        s2_words[811:859]==tuple(word for group,base,span in (
            (0,0x30006d000,0x2000),(1,0x300720000,0x3000),
            (2,0x300778000,0x1000),(3,0x30077c000,0x1000),
            (4,0x3007a0000,0x1000),(5,0x302900000,0x1000))
            for word in (34,base,span,group,0,0,0,0)) and
        s2_words[859:875]==(35,0x210e20000,0x2000,0,0,0,0,0,
                            35,0x211e20000,0x2000,1,0,0,0,0) and
        s2_words[875:939]==tuple(word for base in (
            0x210059000,0x210159000,0x210259000,0x210359000,
            0x211059000,0x211159000,0x210e48000,0x211e48000)
            for word in (36,base,0x1000,0,0,0,0,0)) and
        s2_words[939:955]==(37,0x210e44000,0x1000,0,0,0,0,0,
                            37,0x211e44000,0x1000,1,0,0,0,0) and
        s2_words[955:963]==(38,0x300740000,0x1000,0,0,0,0,0) and
        s2_words[963:1011]==tuple(word for cpu,base in enumerate((
            0x210010000,0x210110000,0x210210000,0x210310000,0x211010000,0x211110000))
            for word in (39,base,0x1000,cpu,0,0,0,0)) and
        s2_words[1011:1019]==(41,0x385110000,0x5000,0,0,0,0,0) and
        s2_words[1019:1027]==(42,0x300200000,0x4000,0,0,0,0,0) and
        s2_words[1027:1035]==(43,0x385018000,0x4000,2,6,1110,0,0) and
        s2_words[1035:1043]==(44,0x3082b8000,0x1000,8,0,0,0,0) and
        s2_words[1043:1051]==(45,0x282600000,0x9000,8,0,0,0,0) and
        s2_words[1051:1115]==(0,)*64)
    ok('expanded parameters fit between VNCR and the tree',
       xb.PARAMS_PA==xb.HANDOFF_PA+0xc000 and
       xb.PARAMS_PA+len(s2_params)<=xb.DEVICETREE_PA)
    model_dt = xb.DeviceTree(s2_built['chunks'][xb.DEVICETREE_PA])
    ok('serialized AIC EVENT property matches the actual model descriptor',
       model_dt.get('/device-tree/arm-io/aic', 'aic-iack-offset') ==
       _struct.pack('<Q', s2_words[160]))
    ok('SLIDE_REGION owns only bootstrap tables and its published region map',
       slide[:3] == (xb.TABLE_PA, xb.TABLE_PA + xb.TABLE_SPAN,
                     xb.HANDOFF_PA + xb.REGIONS_OFFSET))
    ok('SLIDE_REGION reserves 64 MiB directly below the early heap',
       slide[3:6] == (xb.GUEST_PROFILE.early_heap_va - 0x4000000,
                      xb.GUEST_PROFILE.early_heap_va, 4))
    ok('SLIDE_REGION boot segment extents match the measured guest image',
       [(slide[i], slide[i+2]) for i in range(6, 18, 3)] == [
           (0xfffffe000c6ac000, 3), (0xfffffe000c83c000, 19),
           (0xfffffe000ca78000, 1592), (0xfffffe000c26c000, 243)])
    ok('SLIDE_REGION physical addresses follow the actual image placement',
       all(slide[i+1] == s2_built['image_pa'] + slide[i] - s2_built['image'].vmin
           for i in range(6, 18, 3)) and not any(slide[18:]))
    ok('SLIDE_REGION reserved destination leaves remain absent',
       all(s2_built['tables'].walk(va) is None
           for va in range(slide[3], slide[4], 0x4000)))
    from dataclasses import replace
    saved_profile = xb.GUEST_PROFILE
    for specs in ((), (('fileset', '__MISSING'),),
                  (('com.apple.missing', '__KLDDATA'),),
                  (('fileset', '__TEXT_EXEC'),),
                  saved_profile.slide_segments * 2):
        xb.GUEST_PROFILE = replace(saved_profile, slide_segments=specs)
        try:
            xb.slide_contract(s2_built['image'], s2_built['tables'], s2_built['alloc_low'])
        except ValueError:
            refused_slide = True
        else:
            refused_slide = False
        finally:
            xb.GUEST_PROFILE = saved_profile
        ok('SLIDE_REGION refuses missing, empty, executable and overlapping profiles', refused_slide)
    ok('UAT private state has its audited type, table pointer and geometry',
       state[0] == 8 and _struct.unpack_from('<QHB', state, 0x10) == (uat_va+0x4000,64,2))
    ok('UAT reserves separate mapped pages outside all allocator and TXM objects',
       uat_pa >= pool_pa + 0x4000 and uat_pa+0xc000 <= s2_built['alloc_low']
       and all(s2_built['tables'].walk(uat_va+offset) == uat_pa+offset
               for offset in (0,0x4000,0x8000)))
    ok('UAT firmware L2 is empty and linked only from its private L1 slot',
       _struct.unpack_from('<Q',uat_l1,0x10)[0] == (uat_pa+0x8000)|3
       and uat_l1[:0x10] + uat_l1[0x18:] == bytes(0x4000-8)
       and s2_built['chunks'][uat_pa+0x8000] == bytes(0x4000))
    uat_dt = xb.DeviceTree(pathlib.Path(xb.DEFAULT_DEVICETREE).read_bytes())
    mode_prop = uat_dt.nodes[xb.GUEST_PROFILE.uat_node]['agx-address-space-mgmt-mode']
    for value in (b'\0'*4, b'\1', b'\2\0\0\0'):
        mode_prop.value = bytearray(value)
        try:
            xb.private_uat_geometry(uat_dt)
        except ValueError:
            rejected_uat = True
        else:
            rejected_uat = False
        ok('UAT rejects unsupported or malformed modes',rejected_uat)
    watched = dict(s2_built, write_watch_va=s2_built['entry'], watchdog=10)
    watched_words = _struct.unpack(f'<{xb.PARAMS_WORDS}Q', xb.params_blob(watched))
    ok('write watch follows the guest mapping and keeps runtime overrides',
       watched_words[49] == (s2_built['tables'].walk(s2_built['entry']) & ~0xfff)
       and watched_words[24] == 10)
    try:
        xb.params_blob(dict(s2_built, write_watch_va=1))
    except ValueError:
        invalid_watch_rejected = True
    else:
        invalid_watch_rejected = False
    ok('write watch rejects an unmapped address before upload', invalid_watch_rejected)
    ok('mem_low/mem_high in the params are the memory range the probe maps',
       (s2_words[30], s2_words[31]) == (dram_lo, dram_hi),
       f'{s2_words[30]:#x}..{s2_words[31]:#x}')
    ok('fb_pa/fb_span in the params are zero with the panel withheld',
       (s2_words[32], s2_words[33]) == (0, 0))
    s2_c = read_source(ROOT / 'probes' / 'xnuboot.c')
    s2_m = re.search(r'#define PARAMS_WORDS (\d+)', s2_c)
    ok('PARAMS_WORDS agrees with probes/xnuboot.c',
       s2_m is not None and int(s2_m.group(1)) == xb.PARAMS_WORDS,
       f'C says {s2_m.group(1) if s2_m else None}, loader says {xb.PARAMS_WORDS}')
    ok('struct params in probes/xnuboot.c ends with fb_pa, fb_span',
       re.search(r'uint64_t mem_low, mem_high;.*?uint64_t fb_pa, fb_span;.*?\n\};',
                 s2_c, re.S) is not None)

    # What is NOT in the map, by name. A touch of any of these stops the run.
    for addr, what in ((0, 'address zero'),
                       (0xD9FFF000, 'the page below DRAM'),
                       (0xF5000000, 'the page above the reserve'),
                       (0xF9A20000, 'the panel, while withheld'),
                       (1 << 35, 'an address high in the 36-bit space')):
        ok(f'{what} is in no range', xb.stage2_where(addr, s2_ranges) is None)
    ok('the first and last pages of the memory range are in it',
       xb.stage2_where(dram_lo, s2_ranges) is not None
       and xb.stage2_where(dram_hi - 0x1000, s2_ranges) is not None)

    # With the panel handed over it is the third range, read-write, exactly the
    # panel's own pages -- the range recorded on the device -- and the params
    # carry it, and it is the same range the aperture publishes.
    xb.FRAMEBUFFER = (0xF9A20000, 2732, 1896, 2732 * 4, 32)
    s2_fb_built = xb.build(str(xb.DEFAULT_KERNELCACHE))
    s2_ranges = xb.stage2_ranges(work=S2_WORK)
    ok('with the panel handed over the map is three ranges',
       [w for _, _, _, w in s2_ranges]
       == ['DRAM + reserve', 'panel', 'shadow table arena; private context excluded'])
    s2_panel = s2_ranges[1]
    ok('the panel range is the one recorded on the device, read-write',
       s2_panel[:3] == (0xF9A20000, 0xFADE4000, 'rw'), f'{s2_panel}')
    s2_words = _struct.unpack(f'<{xb.PARAMS_WORDS}Q', s2_fb_built['chunks'][xb.PARAMS_PA])
    ok('fb_pa/fb_span in the params are the panel range',
       (s2_words[32], s2_words[33]) == (s2_panel[0], s2_panel[1] - s2_panel[0]),
       f'{s2_words[32]:#x} +{s2_words[33]:#x}')
    s2_ap = s2_fb_built['chunks'][xb.HANDOFF_PA + xb.REGIONS_OFFSET]
    s2_n = _struct.unpack_from('<I', s2_ap, 0)[0]
    s2_regions = [_struct.unpack_from('<QQI', s2_ap, 0x10 + n * xb.REGION_ENTRY_SIZE)
                  for n in range(s2_n)]
    ok('and the same range the aperture publishes to XNU',
       any((pa, pages << xb.GRANULE) == (s2_panel[0], s2_panel[1] - s2_panel[0])
           for pa, _, pages in s2_regions),
       f'aperture regions {[(hex(pa), hex(pages << 14)) for pa, _, pages in s2_regions]}')
    ok('the memory range is unchanged by the panel',
       s2_ranges[0][:2] == (dram_lo, dram_hi))

    # Refusals say why, and build nothing. The probe refuses the same lists with
    # prepare code -10; a quietly partial map would read like the identity map
    # this replaces with some addresses missing.
    raises('a work area overlapping the memory range is refused',
           lambda: xb.stage2_ranges(work=(0xE0000000, 0x2000000)), 'overlaps')
    raises('an unaligned work area is refused',
           lambda: xb.stage2_ranges(work=(S2_WORK[0] + 0x800, 0x2000000)), 'aligned')
    raises('an empty work area is refused',
           lambda: xb.stage2_ranges(work=(S2_WORK[0], 0)), 'empty')
    raises('a range past the 36-bit IPA space is refused',
           lambda: xb.stage2_ranges(work=((1 << 36) - 0x1000, 0x2000)), 'past')
    xb.FRAMEBUFFER = (0xF0000000, 2732, 1896, 2732 * 4, 32)
    raises('a panel inside the memory range is refused',
           lambda: xb.stage2_ranges(work=S2_WORK), 'overlaps')
finally:
    xb.FRAMEBUFFER = s2_fb_saved
    restore()


# v_display decides whether XNU's console paints glyphs or arms a spinner, and
# only the text arm is the milestone. Pinned because it is a single digit in a
# pack of six, it has no effect until a panel is handed over, and a run with the
# wrong one looks exactly like a run that drew nothing for some other reason.
ok('the panel is handed over in text mode, not graphics mode',
   xb.VIDEO_DISPLAY_MODE == 0,
   f'v_display would be {xb.VIDEO_DISPLAY_MODE}, which selects the spinner path')

saved_fb = xb.FRAMEBUFFER
try:
    xb.FRAMEBUFFER = (0xF9A20000, 2732, 1896, 2732 * 4, 32)
    packed = xb.boot_args(0xfffffe0000000000, 0xda000000, 384 * MIB,
                          0xf2000000, 0xfffffe0006f00000, 0x100)
    video = _struct.unpack_from('<6Q', packed, 0x28)
    ok('and the packed Video structure says so', video[1] == 0,
       f'v_display packed as {video[1]}')
    ok('with the panel base in the first field', video[0] == 0xF9A20000)
finally:
    xb.FRAMEBUFFER = saved_fb


# MAIR_EL1 is SPTM's, not ours.
#
# There is no `msr MAIR_EL1` in kernelcache.release.mac17p at all, and two in
# sptm.t8140.release. The live one is the second, +0xab5c8 in SPTM's common
# start, which every CPU passes before SPTM's C code and XNU run; the first,
# +0xa01ec (0x010000ff), is only the exclave re-entry stub's, and that stub
# always branches into the common start (tools/test-sptm-mair.py decodes both
# from the image). So the kernel inherits XNU's own CACHE_ATTRINDX table and
# indexes it from its PTEs, and a loader that publishes a different one hands
# XNU indices that mean something else.
_mair = built['mair']
ok('MAIR_EL1 is the value SPTM leaves for XNU', _mair == 0x0C0D00FF01A040FF,
   f'{_mair:#018x}')

# Where the stub's 0x010000ff, published until now, differs -- enumerated:
#
#   index 1   0x00 Device-nGnRnE  -> 0x40 Normal NC (WRITECOMB, FEAT_XS XS=0)
#   index 2   0x00 Device-nGnRnE  -> 0xa0 Normal write-through (WRITETHRU)
#   index 4   0x00 Device-nGnRnE  -> 0xff Normal write-back (INNERWRITEBACK)
#   index 6   0x00 Device-nGnRnE  -> 0x0d Device-GRE, XS=0 (POSTED_REORDERED)
#   index 7   0x00 Device-nGnRnE  -> 0x0c Device-GRE (POSTED_COMBINED_REORDERED)
#
# Indices 0 (write-back), 3 (0x01, DISABLE) and 5 (0x00, POSTED) keep theirs.
# Index 1 is the one XNU uses for write-combined DRAM: Device-nGnRnE made
# DC ZVA and unaligned accesses to those buffers fault.
_old, _new = 0x00000000010000FF, _mair
_differ = [i for i in range(8)
           if (_old >> (8 * i)) & 0xff != (_new >> (8 * i)) & 0xff]
ok('it differs from the stub\'s 0x010000ff at indices 1, 2, 4, 6 and 7',
   _differ == [1, 2, 4, 6, 7], f'differs at {_differ}')
ok('...index 1 goes from Device-nGnRnE to Normal non-cacheable',
   ((_old >> 8) & 0xff, (_new >> 8) & 0xff) == (0x00, 0x40))
ok('...and the device indices 3 and 5 are unchanged',
   ((_old >> 24) & 0xff, (_new >> 24) & 0xff, (_old >> 40) & 0xff, (_new >> 40) & 0xff)
   == (0x01, 0x01, 0x00, 0x00))
# Attribute 0 is the one every loader PTE uses, and it is unchanged. If this
# ever moves, every mapping the loader makes changes meaning at once.
ok('...while attribute 0, which every loader PTE uses, is untouched',
   (_old & 0xff) == (_new & 0xff) == 0xFF)

# And no PTE this loader builds uses that index, so the change moves nothing
# that is already mapped. Walked out of the built tables rather than asserted
# from the LEAF constant: LEAF is one default among several map() call sites,
# and a future one passing its own attrs is exactly the case this has to catch.
# Page tables are not in build()'s `chunks` -- they are in tables.pages, and a
# walk over chunks reads zeros and looks like a table that was never built.
_leaves = []
for _page in built['tables'].pages.values():
    for _off in range(0, len(_page), 8):
        _pte = _struct.unpack_from('<Q', _page, _off)[0]
        # A level-3 leaf is 0b11; a block at a higher level is 0b01. Table
        # descriptors are also 0b11, so leaves are picked out by having an
        # output address inside the memory this layout actually covers rather
        # than by their low bits alone -- a table descriptor points at another
        # of these pages.
        if _pte & 1 and (_pte & 0x0000FFFFFFFFC000) not in built['tables'].pages:
            _leaves.append(_pte)
ok('the loader builds leaves at all', len(_leaves) > 100,
   f'{len(_leaves)} -- if this is zero the walk found nothing and the two '
   f'checks below pass vacuously')
_idx1 = [pte for pte in _leaves if (pte >> 2) & 7 == 1]
ok('no loader-built PTE uses attribute index 1', not _idx1,
   f'{len(_idx1)} leaves do, first {_idx1[0]:#018x}' if _idx1 else '')
# No index whose meaning moved is in use, which is what makes this change
# safe rather than merely correct: nothing the loader mapped changes meaning.
_moved = [pte for pte in _leaves if (pte >> 2) & 7 in _differ]
ok('no loader-built PTE uses an index this change moved', not _moved,
   f'{len(_moved)} leaves use one of {_differ}')
_indices = sorted({(pte >> 2) & 7 for pte in _leaves})
ok('every loader-built PTE uses attribute index 0', _indices == [0],
   f'indices in use: {_indices}')


# The device inventory, and the prediction the span table is measured against.
#
# MAP_PAGE now folds every mapping onto an address outside our memory into a
# span of {va, pa, pages, attrs}, and the host turns each physical base back
# into the node of the guest's own tree that named it. What follows is the
# arithmetic that says what the next run should print, written down BEFORE the
# run so it can be wrong. If the table disagrees, the table is right.
#
# 379 is not a guess: it is the MAP_PAGE-completed counter from the last run,
# and the four groups below add up to it out of the tree alone.
def _pages(size):
    """16K pages a window occupies, rounded up.

    Per window, never on a sum: the UART's second window is 0x1000 bytes and
    still needs a whole 16K page, so adding the byte counts first and dividing
    once loses it -- 0x10000 + 0x1000 divides to four pages where the kernel
    maps five. That is exactly the off-by-one this arithmetic is here to get
    right."""
    return (size + 0x3fff) // 0x4000


_dt = xb.build_devicetree()
ok('XNU timebase comes from the running CPU, not only the root clock',
   _dt.get(f'/device-tree/cpus/{xb.BOOT_CPU}', 'timebase-frequency') ==
   struct.pack('<I', xb.TIMEBASE_HZ))
_clock_spec = xb.GUEST_PROFILE.counter_clock
_clock_ids = _dt.get(_clock_spec.consumer, 'clock-ids')
_clock_id = struct.unpack_from('<I', _clock_ids, _clock_spec.consumer_index * 4)[0]
ok('watchdog nclk resolves the running CPU fixed frequency',
   _clock_id == _clock_spec.clock_id and
   _dt.get(_clock_spec.source_cpu, 'fixed-frequency') == struct.pack('<I', xb.TIMEBASE_HZ))
_inv = xb.device_inventory(_dt)
ok('the device inventory finds windows in the guest tree', len(_inv) > 50,
   f'{len(_inv)} windows')

# The interrupt controller. One window, and the size is where the 115 comes
# from: 0x1cc000 / 0x4000. The base is the node's `reg` translated through
# arm-io's `ranges`, whose child zero sits at 0x210000000 -- so 0xf1000000
# becomes 0x301000000, which is the address the last run logged.
_aic = xb.device_windows(_dt, 'aic')
ok('the AIC has exactly one register window', len(_aic) == 1, str(_aic))
ok('the AIC window is at 0x301000000', _aic[0][0] == 0x301000000,
   f'{_aic[0][0]:#x}')
ok('...which is arm-io child 0xf1000000 through its ranges',
   0x210000000 + 0xf1000000 == _aic[0][0])
ok('and it is 115 pages of 16K', _aic[0][1] // 0x4000 == 115,
   f'{_aic[0][1]:#x} bytes = {_aic[0][1] / 0x4000} pages')
ok('the AIC window is a whole number of 16K pages', _aic[0][1] % 0x4000 == 0)

# The console. Two windows, NOT one: 0x308128000 for four pages and
# 0x30810c000 for one, and they are not adjacent. That matters for the span
# table -- a span is extended only when the next page continues it in both
# address spaces, so these are two rows however the kernel maps them.
_uart = xb.device_windows(_dt, 'dockchannel-uart')
ok('the dock-channel UART has two register windows', len(_uart) == 2, str(_uart))
ok('...totalling five 16K pages',
   sum(_pages(s) for _, s in _uart) == 5, str(_uart))
ok('...which are not contiguous, so they cannot coalesce into one span',
   _uart[0][0] + _uart[0][1] != _uart[1][0] and
   _uart[1][0] + _uart[1][1] != _uart[0][0], str(_uart))


# The per-core and per-cluster windows. Six cores, five `*-reg` properties
# each, but two of those five are shared between the cores of a cluster --
# acc-impl-reg and cpm-impl-reg name the cluster, not the core -- so the
# distinct spans are 6*3 + 2*2 = 22, not 30.
_cpu = sorted({(pa, size) for pa, size, who in _inv if who.startswith('cpu')})
ok('the per-core and per-cluster windows are 22 distinct spans',
   len(_cpu) == 22, f'{len(_cpu)}: {[(hex(p), hex(s)) for p, s in _cpu]}')
ok('...totalling 144 pages of 16K',
   sum(_pages(s) for _, s in _cpu) == 144,
   str(sum(_pages(s) for _, s in _cpu)))

_predicted = (sum(_pages(s) for _, s in _uart)          # the console
              + _pages(_aic[0][1]) * 2                  # the AIC, mapped twice
              + sum(_pages(s) for _, s in _cpu))        # the cores
ok('the four groups add up to the 379 maps the last run completed',
   _predicted == 379, f'predicted {_predicted}')

# ...and the count of SPANS, which is what the 24-slot table has to hold. This
# is the check that says the prediction does not fit: two UART windows, the AIC
# twice, and 22 core windows is 26 rows, and the table has 24. The overflow
# counter is what keeps that from being a silent truncation, but the shortfall
# is stated here rather than discovered in a transcript.
_predicted_spans = len(_uart) + 2 + len(_cpu)
import run as _span_run
ok('the predicted span count is 26', _predicted_spans == 26,
   str(_predicted_spans))
ok('the span table covers both the prediction and the 45 spans observed live',
   max(_predicted_spans, 45) <= _span_run.MAP_RANGES)

# The resolver, on the addresses the last run actually logged.
ok('0x301000000 resolves to the AIC',
   xb.owner_of(0x301000000, _inv)[0] == 'aic',
   str(xb.owner_of(0x301000000, _inv)))
ok('0x308128000 resolves to the dock-channel UART',
   xb.owner_of(0x308128000, _inv)[0] == 'dockchannel-uart',
   str(xb.owner_of(0x308128000, _inv)))
ok('0x30810c000 resolves to it as well',
   xb.owner_of(0x30810c000, _inv)[0] == 'dockchannel-uart',
   str(xb.owner_of(0x30810c000, _inv)))
ok('an address inside a window resolves, not just its base',
   xb.owner_of(0x301000000 + 0x1cb000, _inv)[0] == 'aic')
ok('and one past its end does not',
   xb.owner_of(0x301000000 + 0x1cc000, _inv) is None or
   xb.owner_of(0x301000000 + 0x1cc000, _inv)[0] != 'aic')
# An address no node claims is a real answer, printed as one. DRAM is not a
# device and must not be resolved to a neighbouring window by an off-by-one.
ok('an address no node claims resolves to nothing',
   xb.owner_of(0xda000000, _inv) is None,
   str(xb.owner_of(0xda000000, _inv)))

# Windows nest, and the resolver must name the device rather than the block it
# sits in. This is not hypothetical: pmgr claims 0x308100000 for 0xa8000 and
# the UART's registers are inside it, so taking the first match in address
# order resolves the kernel's console to the power manager. Pinned with both
# the real tree and a synthetic pair, so the property survives a tree that
# stops happening to contain an example of it.
_pmgr = [w for w in _inv if w[2] == 'pmgr' and w[0] <= 0x308128000 < w[0] + w[1]]
ok('the real tree still has a window enclosing the UART\'s', len(_pmgr) == 1,
   str(_pmgr))
ok('...and the UART wins it, because its window is the tighter one',
   xb.owner_of(0x308128000, _inv)[2] < _pmgr[0][1])
_nested = [(0x1000, 0x8000, 'outer'), (0x2000, 0x1000, 'inner')]
ok('the smallest containing window wins',
   xb.owner_of(0x2500, _nested)[0] == 'inner', str(xb.owner_of(0x2500, _nested)))
ok('...and the enclosing one answers where it is the only claim',
   xb.owner_of(0x1500, _nested)[0] == 'outer', str(xb.owner_of(0x1500, _nested)))


# The report readers, exercised against a synthetic report.
#
# Every one of these runs exactly once per hardware run, at the end, on a
# machine with one USB link -- so a NameError in one of them costs a run of the
# only device there is. That is not hypothetical: `xb` is a LOCAL of
# run_xnuboot(), and two of these functions were written at module scope
# reaching for it. Nothing offline touched them, so nothing said so.
#
# They all swallow exceptions and print "could not read it", which is the right
# behaviour on the device -- a readback is a nicety and the run's evidence is
# elsewhere -- and is also why these assert on the OUTPUT rather than on not
# raising. A swallowed NameError is a passing test and an empty section.
import contextlib as _contextlib
import io as _io

_spec = importlib.util.spec_from_file_location('run', ROOT / 'probes' / 'run.py')
_run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_run)


class _FakeProxy:
    """Serves a report buffer the probe would have written, at `out` = 0."""

    def __init__(self, size=1 << 16):
        self.mem = bytearray(size)

    def put(self, off, *words):
        for i, w in enumerate(words):
            _struct.pack_into('<Q', self.mem, off + 8 * i, w)

    def readmem(self, pa, n):
        if pa + n > len(self.mem):
            raise AssertionError(f'read of {n} at {pa:#x} runs past the report')
        return bytes(self.mem[pa:pa + n])


def _capture(fn, *a, **k):
    buf = _io.StringIO()
    with _contextlib.redirect_stdout(buf):
        fn(*a, **k)
    return buf.getvalue()


_fake = _FakeProxy()
# Three endpoints called, plus two calls that went elsewhere.
_fake.put(_run.ENDPOINTS_OFFSET + 0x02 * 8, 379)
_fake.put(_run.ENDPOINTS_OFFSET + 0x2d * 8, 1200)
_fake.put(_run.ENDPOINTS_OFFSET + 0x32 * 8, 1)
_fake.put(_run.ENDPOINTS_OFFSET + 64 * 8, 2)
_out = _capture(_run.endpoint_calls, _fake, 0, 1582)
ok('the endpoint table prints SPTM\'s names', 'MAP_PAGE' in _out, _out)
ok('...and the "everything else" bucket', 'another domain' in _out, _out)
ok('...and totals the columns', '1582' in _out, _out)

# Two spans, one of them the AIC, and one that did not fit.
_fake.put(_run.RANGES_OFFSET, 2, 1)
_fake.put(_run.RANGES_OFFSET + 16, 0xfffffe000c838000, 0x301000000, 115, 0x703)
_fake.put(_run.RANGES_OFFSET + 16 + 32, 0xfffffe000c900000, 0x308128000, 4, 0x703)
_out = _capture(_run.map_ranges, _fake, 0, xb, built, 119)
ok('the span table resolves a base to the AIC', 'aic' in _out, _out)
ok('...and to the dock-channel UART', 'dockchannel-uart' in _out, _out)
ok('...and says when spans did not fit', 'did not fit' in _out, _out)
ok('the span reader never reports a NameError or the like',
   'could not' not in _out and 'Error' not in _out, _out)

# The guest's translation registers, with MAIR as we published it.
_fake.put(_run.GUEST_SYSREGS_OFFSET, 0, 0x1234000, 0x1234, built['mair'], 0)
_out = _capture(_run.guest_sysregs, _fake, 0, built)
ok('the sysreg readback prints MAIR', 'MAIR_EL1' in _out, _out)
ok('...and says it is unchanged when it matches what we published',
   'unchanged' in _out, _out)
ok('the sysreg readback does not fall into its except',
   'could not read' not in _out, _out)
# ...and notices when it does not match, which is the whole point of reading it.
_fake.put(_run.GUEST_SYSREGS_OFFSET + 3 * 8, 0x44FF)
_out = _capture(_run.guest_sysregs, _fake, 0, built)
ok('...and says CHANGED when MAIR is not what we published',
   'CHANGED' in _out, _out)

# The two measured addresses, pinned. Nothing re-derives these at run time, and
# both ship as values common in __DATA_CONST -- 0x01 and null -- so a digit
# wrong reads some other variable and prints a confident number about it. The
# offsets within the page are what distinguish them; 0x160 and 0x220 are 0xc0
# apart and a transposition lands on neither.
ok('the kprintf gate address is the one measured in mac17p',
   _run.KPRINTF_GATE == 0xfffffe0007ebf160, f'{_run.KPRINTF_GATE:#x}')
ok('and PE_kputc\'s is too', _run.PE_KPUTC == 0xfffffe0007ebf220,
   f'{_run.PE_KPUTC:#x}')
ok('both are in the same __DATA_CONST page, 0xc0 apart',
   _run.PE_KPUTC - _run.KPRINTF_GATE == 0xc0)
# And they are addresses this loader actually uploads, so `peek` can reach
# them. An address outside every chunk would print "could not read it" on the
# device and the run would be spent.
for _va, _what in ((_run.KPRINTF_GATE, 'the gate'), (_run.PE_KPUTC, 'PE_kputc')):
    try:
        _run.uploaded(built, _va, 4)
        ok(f'{_what} is inside a chunk the loader uploads', True)
    except KeyError as _exc:
        ok(f'{_what} is inside a chunk the loader uploads', False, str(_exc))

# The kprintf gate, against the bytes the loader actually uploaded.
_out = _capture(_run.kprintf_gate,
                lambda va, n=8: _run.uploaded(built, va, n), built)
ok('the kprintf readback runs without falling into its except',
   'could not read it' not in _out, _out)
ok('...and reads the shipped 0x01 at +0x160', '0x01 (image ships 0x01)' in _out,
   _out)
ok('...and reports PE_kputc null in the image as shipped',
   'still null' in _out, _out)
ok('...and says witness 3 cannot arrive while bit 0 is set',
   'witness 3 cannot arrive' in _out, _out)
# The other arm: a gate that opened and a function pointer installed.
ok('...and still names the closed serial-init gate when only +0x160 opens',
   'serial-init gate is still closed' in _capture(
       _run.kprintf_gate,
       lambda va, n=8: (0x00000100 if va == 0xfffffe0007ebf160
                        else 0xfffffe000b91c000), built))


_refs_tables = xb.Tables(0x90000000)
_refs_aperture = 0xfffffe0100000000
_refs_tables.map(_refs_aperture, 0x91000000, 0x4000)
_refs_tables.validate_allocator_baseline(0x91000000, 0x91004000,
                                         _refs_aperture, 0x91000000)
ok('physical aperture leaves the initial counted baseline empty', True)
_refs_tables.map(0xfffffe0200000000, 0x91000000, 0x4000)
raises('a preinstalled allocator alias needs reference seeding',
       lambda: _refs_tables.validate_allocator_baseline(
           0x91000000, 0x91004000, _refs_aperture, 0x91000000), 'alias already exists')
raises('bootstrap tables cannot occupy counted allocator frames',
       lambda: _refs_tables.validate_allocator_baseline(
           0x90000000, 0x90010000, _refs_aperture, 0x91000000), 'bootstrap table')

print(f'PASS: {checks} profile and layout checks '
      '(offline, no hardware or proxy; local firmware integration)')
