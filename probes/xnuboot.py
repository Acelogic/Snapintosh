#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build XNU's initial address space on the host, the way SPTM would.

XNU never writes SCTLR_EL1 -- the instruction does not appear anywhere in the
kernelcache -- so it cannot enable its own MMU. It has to be entered with
translation already live and the kernel mapped at its link addresses. On a real
Mac SPTM does that; here it is ours to do.

This builds the whole thing offline and checks it before anything is uploaded:

  * the kernelcache, laid out and rebased (tools/kc-load.py)
  * 16K TTBR1 page tables mapping the image at 0xfffffe00_........
  * the two handoff structures XNU's entry stub validates
  * a list of (physical address, bytes) chunks to write

and then walks its own tables for every address the entry path is known to
touch. A table that does not resolve XNU's entry point is a hang with nothing
to report, so it is checked here, where a failure is a printed line.

    python3 probes/xnuboot.py --check
    python3 probes/xnuboot.py --check --verbose
"""
import argparse
import hashlib
import os
import pathlib
import secrets
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import importlib
kc_load = importlib.import_module('kc-load')
sys.path.insert(0, str(ROOT / 'probes'))
from appledt import DeviceTree
from devicemodel import (mcc_models, mcc_ptd_models, aic_models, watchdog_models,
                        gpio_models, aes_key_models, spmi_models, dock_models,
                        dock_fifo_models, mcc_error_models, socni_error_models,
                        platform_error_models, aop_timebase_models, dart_models,
                        pmgr_power_models, pmp_active_models, qspi_models, dwi_models,
                        i2c_empty_models, sep_asc_models, device_model_words,
                        ans_models, ans_reservation_span, populate_ans_firmware)
from bootcontract import Framebuffer, PhysicalRange, checked_ranges
from guestprofile import get_profile
from sepboot import populate_sep_boot
from chipid import populate_chip_id, populate_board_id, populate_image4_identity
from pmgrboot import populate_pmgr_boot
from soctunerboot import populate_soctuner_boot
from coresight import coresight_models
from nvram import populate_boot_nvram
from iommu import populate_dart_ids, populate_dart_apf_exceptions, validate_apf_memory
from pcie import populate_pcie_reset
from deferred import defer_subtrees
from clocktree import populate_counter_clock
from clockcontract import validate_counter_image
from ramdisk import load_ramdisk, root_cmdline, load_root_hash, populate_ramdisk_policy, ROOT_HASH_NODE
from trustcache import reserve_size as trust_reserve_size

FIRMWARE_DIR = ROOT / 'downloads/extracted/j700ap'
DEFAULT_KERNELCACHE = FIRMWARE_DIR / 'kernelcache.release.mac17p'
DEFAULT_DEVICETREE = FIRMWARE_DIR / 'DeviceTree.j700ap'

# --------------------------------------------------------------------------
# The boot profile: which firmware this loader was read out of.
#
# Nearly every constant in this file is an address or an offset measured by
# reading one specific set of binaries -- the entry point, VBAR_EL1, the stack
# tops, the handoff field at +0x320, the monitor stub pages, the fixed SPTM
# region. None of them are derived at run time and none of them are checked
# against the image they came from. Swap the firmware under this loader and it
# keeps running: it reads a different kernelcache with a table of addresses from
# the old one, and whatever happens next is evidence about a machine that does
# not exist.
#
# That failure is silent, and it is silent in the worst direction: the run still
# produces a console, a monitor trace and an exit code, all of which look like
# findings. So the profile names the firmware and records a hash of every file
# read, and a mismatch is a loader failure rather than a warning.
#
# The hashes are of the images in downloads/extracted/j700ap, which is excluded
# from Git -- so this is the only record in the repository of which firmware the
# measurements were taken against. `--profile --record` prints candidate
# hashes only; a deliberate firmware change needs a newly audited profile.
GUEST_PROFILE = get_profile('j700ap-26A428')
PROFILE_NAME = GUEST_PROFILE.name
PROFILE_TARGET = GUEST_PROFILE.target
PROFILE_BUILD = GUEST_PROFILE.build
PROFILE_FIRMWARE = dict(GUEST_PROFILE.firmware)


def firmware_hashes(directory=None, kernelcache=None):
    """sha256 of each file the profile names, or None where it is missing."""
    return GUEST_PROFILE.hashes(directory or FIRMWARE_DIR, kernelcache)


def check_profile(directory=None, measured=None, kernelcache=None):
    """[] if the firmware is what the profile was measured against.

    Each complaint is one line naming the file and what is wrong with it, so a
    caller can print them all rather than stopping at the first."""
    measured = measured if measured is not None else firmware_hashes(directory, kernelcache)
    bad = []
    for name, expected in PROFILE_FIRMWARE.items():
        got = measured.get(name)
        if got is None:
            bad.append(f'{name}: missing from {directory or FIRMWARE_DIR}')
        elif got != expected:
            bad.append(f'{name}: sha256 {got[:16]}..., '
                       f'profile {PROFILE_NAME} was measured against '
                       f'{expected[:16]}...')
    return bad


def configure_guest(name='j700ap-26A428', directory=None):
    """Select an audited firmware bundle before building any guest structures.

    This loader implements one ABI. A new ABI needs a loader and EL2 decoder,
    not a permissive fallback to these offsets. Legacy globals remain for the
    current probe; profile selection is per run, not concurrent in one module.
    """
    profile = get_profile(name)
    if profile.abi != 'sptm-mac-v1':
        raise ValueError(f'unsupported monitor ABI {profile.abi}')
    global GUEST_PROFILE, PROFILE_NAME, PROFILE_TARGET, PROFILE_BUILD
    global PROFILE_FIRMWARE, FIRMWARE_DIR, DEFAULT_KERNELCACHE, DEFAULT_DEVICETREE
    global MONITOR_IMAGES, XNU_VBAR, BOOT_CPU, BOOT_MPIDR, CONSOLE_NODE
    global VSPACE_TOP, TIMEBASE_HZ, DEVICETREE_PA
    GUEST_PROFILE = profile
    DEVICETREE_PA = HANDOFF_PA + (0x18000 if profile.boot_framebuffer_aux else 0x10000)
    PROFILE_NAME, PROFILE_TARGET, PROFILE_BUILD = profile.name, profile.target, profile.build
    PROFILE_FIRMWARE = dict(profile.firmware)
    FIRMWARE_DIR = pathlib.Path(directory) if directory else ROOT / 'downloads/extracted' / profile.firmware_subdir
    DEFAULT_KERNELCACHE = FIRMWARE_DIR / profile.kernelcache
    DEFAULT_DEVICETREE = FIRMWARE_DIR / profile.devicetree
    MONITOR_IMAGES, XNU_VBAR = profile.monitors, profile.vbar
    BOOT_CPU, BOOT_MPIDR = profile.boot_cpu, profile.boot_mpidr
    CONSOLE_NODE = profile.console_node
    VSPACE_TOP = profile.early_heap_va - 1
    TIMEBASE_HZ = profile.virtual_counter_hz

# The guest's clock contract is independent of the adapter's physical rate.
# Both rates are serialized to EL2, which scales samples and deadlines. The
# physical rate below is an offline default; run.py replaces it from bootinfo.
TIMEBASE_HZ = GUEST_PROFILE.virtual_counter_hz
HOST_TIMEBASE_HZ = 19200000

# Which /cpus node the guest is told it is running on. cpu0 is an E core
# ("apple,sawtooth") in cluster 0 with reg = 0, so the MPIDR that has to agree
# with it -- VMPIDR_EL2, below -- is just the RES1 bit. The other five stay
# "waiting", which is the truth: nothing has released them.
BOOT_CPU = GUEST_PROFILE.boot_cpu
# MPIDR_EL1 as that node describes it. A cpu node's `reg` is the affinity value,
# and bit 31 of MPIDR_EL1 is RES1. cpu4 has reg = 0x100, i.e. Aff1 = 1, which is
# the second cluster -- so the encoding is plainly affinity, not an index.
BOOT_MPIDR = GUEST_PROFILE.boot_mpidr

# Set to withhold one loader input, to make XNU exercise its console. See
# build_devicetree().
PROVOKE = None

# The panel, as q1n1 captured it from GOP: (base, width, height, stride_bytes,
# depth). run.py fills this from the target's boot info, because it is a fact
# about the machine in front of us and not about the kernel.
#
# This is what makes the console XNU's own rather than a transcript of it. XNU
# has the real thing -- `initialize_screen` is in this kernelcache, with its own
# diagnostic line ("b=%08llX, w=%08X, h=%08X, r=%08X, d=%08X") -- and it is
# driven from boot_args.Video, whose first field is v_baseAddr. Hand it a zero
# and 0xfffffe000ba55830 reads it, finds nothing, and takes the no-display path;
# hand it the panel and XNU maps it and records its geometry.
#
# It does NOT follow that glyphs appear. Two boot arguments choose the route,
# and initialize_screen must later acquire the console (operation 4):
#
#   v_display = 1 below puts XNU in graphics mode, where the acquire path paints
#   nothing and arms a progress spinner on a timer instead. Text mode -- v_display
#   = 0 -- is the one where the CPU paints glyphs synchronously.
#
#   `serial=3` in BOOT_CMDLINE has bit 0 set, and with a working UART that makes
#   cons_ops_index 0: printf goes to the serial line and the panel console is
#   never the console at all.
#
# Text mode uses v_display = 0 and a `serial` without bit 0. debug=0x8 stays,
# but this RELEASE kernel's separate kprintf gate still prevents relying on
# its diagnostics. The profile's memory witness reports actual acquisition.
FRAMEBUFFER = None

# boot_args.Video.v_display. Text mode is the one where XNU's console draws
# glyphs itself; see build_boot_args().
VIDEO_DISPLAY_MODE = 0


def panel_range():
    """The panel as a physical range, (base, span) on 16K pages, or None.

    One derivation for the aperture region, the params the probe reads and
    the stage-2 range list, so the three cannot disagree about where it is."""
    if not FRAMEBUFFER:
        return None
    region = Framebuffer(*FRAMEBUFFER).physical_range(GRANULE).validate(
        GRANULE, STAGE2_IPA_BITS)
    return region.base, region.size


def owned_ranges():
    """RAM/reserve and optional panel; holes are never resources."""
    ranges = [PhysicalRange(PHYS_BASE, BOOTSTRAP_PA + BOOTSTRAP_SPAN - PHYS_BASE,
                            'DRAM + reserve')]
    panel = panel_range()
    if panel:
        ranges.append(PhysicalRange(*panel, 'panel'))
    return checked_ranges(ranges, GRANULE, STAGE2_IPA_BITS)


# -- the stage-2 map ---------------------------------------------------------
#
# What probes/xnuboot.c maps at stage 2, derived here from the same numbers
# the probe is handed, so the host can state the map before a run and check it
# offline (tools/test-profile.py) against what the loader actually uploads.
#
# Three ranges, each mapped to itself, and nothing else: the DRAM we declared
# with the reserve above it; the panel, when it is handed over; the probe's own
# table arena, read-only, because the hardware walks the 4K shadow tables through
# stage 2 and the guest must never write them. A touch of anything else is a
# stage-2 fault carrying the address, and the run stops there. This is docs/PLAN-HISTORY-20260922.md's
# narrow-and-report state: honest, and less far-reaching than the identity map
# it replaced, which passed every device access through unreported.
STAGE2_IPA_BITS = 36                    # VTCR_EL2.T0SZ = 28 in the probe


def stage2_ranges(work=None):
    """The stage-2 map as [(lo, hi, access, what)], in the probe's own order.

    `work` is the table arena's (base, size), after the private monitor context.
    run.py derives that boundary from the compiled C layout. None leaves the
    table arena out, for a check that concerns only the memory
    this loader lays out. Refuses -- as the probe does, with -10 -- a list
    that is empty, unaligned, past the IPA width or overlapping itself: a map
    that is quietly partial reads like the identity map it replaced, with some
    addresses missing, and would be the same silence under a different name."""
    ranges = [(PHYS_BASE, BOOTSTRAP_PA + BOOTSTRAP_SPAN, 'rw', 'DRAM + reserve')]
    panel = panel_range()
    if panel:
        ranges.append((panel[0], panel[0] + panel[1], 'rw', 'panel'))
    if GUEST_PROFILE.adreno is not None:
        import adreno
        ranges += adreno.stage2_ranges(GUEST_PROFILE.adreno)
    if GUEST_PROFILE.i2c_input is not None:
        import i2cinput
        ranges += i2cinput.stage2_ranges(GUEST_PROFILE.i2c_input)
    if QCC2072_WIFI is not None:
        import qcc2072wifi
        ranges += qcc2072wifi.stage2_ranges(QCC2072_WIFI)
    if DISPLAY_TIMING is not None:
        import displaytiming
        ranges += displaytiming.stage2_ranges(DISPLAY_TIMING)
    if work:
        base, size = work
        ranges.append((base, base + size, 'ro', 'shadow table arena; private context excluded'))
    limit = 1 << STAGE2_IPA_BITS
    for n, (lo, hi, _, what) in enumerate(ranges):
        if lo >= hi:
            raise SystemExit(f'stage 2: the {what} range {lo:#x}..{hi:#x} is empty')
        if (lo | hi) & 0xFFF:
            raise SystemExit(f'stage 2: the {what} range {lo:#x}..{hi:#x} is not '
                             f'4K aligned')
        if hi > limit:
            raise SystemExit(f'stage 2: the {what} range ends at {hi:#x}, past the '
                             f'{STAGE2_IPA_BITS}-bit intermediate address space')
        for lo2, hi2, _, what2 in ranges[:n]:
            if lo < hi2 and lo2 < hi:
                raise SystemExit(f'stage 2: the {what} range {lo:#x}..{hi:#x} '
                                 f'overlaps the {what2} range {lo2:#x}..{hi2:#x}')
    return ranges


def stage2_where(ipa, ranges):
    """The range holding `ipa`, or None -- the first thing to know about a
    stage-2 fault: inside a range it is a permission fault, in none it is an
    address that does not exist for the guest."""
    for entry in ranges:
        if entry[0] <= ipa < entry[1]:
            return entry
    return None


# Where the image and everything around it goes, as offsets from one base.
#
# These were absolute once, copied from a conventional-memory region on the A16
# -- 0xd9dc0000 .. 0xf9a20000, 508 MiB. That is one machine's memory map on one
# firmware, which is a fact with an expiry date, and it made the whole probe
# unrunnable anywhere else: under QEMU there is simply no RAM at 0xd9e00000, so
# a target that was sitting idle could not be used. So the layout is now
# relative, and `place()` moves it to whatever free memory the target actually
# reports. The default keeps the A16's addresses, so nothing changes for a run
# that does not ask.
#
# The handoff comes *first*, below the kernel image, because XNU says so:
#
#   panic: EXTRADATA is in an unexpected place: 0xfffffe000e370000 >
#          0xfffffe0007004000 @arm_init_sptm.c:1725
#
# 0xfffffe000ba7ae44 compares the device tree's address against a running
# low-water mark that starts at virtBase, and anything above it is rejected.
# That is not arbitrary: iBoot lays the region out with boot_args and the device
# tree before the kernel, and XNU is reconstructing that region by walking what
# it was handed. Putting the handoff below the image makes the whole region one
# linear VA-to-PA mapping -- handoff_va - virtBase + physBase lands exactly on
# the handoff's own physical address -- which is the property XNU is entitled to
# assume and the reason it can get away with the arithmetic.
HANDOFF_OFFSET = 0x00000000
IMAGE_OFFSET = 0x00080000      # == HANDOFF_SPAN
MONITOR_OFFSET = 0x07400000    # the real SPTM and TXM images, past the kernel
MONITOR_STRIDE = 0x00200000
FRAMETABLE_OFFSET = 0x07800000 # SPTM's per-physical-page table
FRAMETABLE_SPAN = 0x00100000
FRAMEMAP_OFFSET = 0x07900000   # the flat frame map sptm_get_frame_type reads
FRAMEMAP_SPAN = 0x00100000
TABLE_OFFSET = 0x09200000      # 16K guest tables, bump-allocated upward
TABLE_SPAN = 0x01000000        # the arena they are allowed to grow into
SPTM_DATA_OFFSET = 0x0A200000  # backing for the monitor's own fixed-VA region
SPTM_DATA_SPAN = 0x00500000   # fixed region plus separate monitor stacks
# Six separate result areas in the reserved monitor-data arena. The handoff
# had room for only one; sharing it would alias simultaneous CPU results.
SCRATCH_OFFSET = 0x00480000  # relative to SPTM_DATA_PA, after stacks/UAT
# The 8-page TXM arena's values; configure_txm_arena() moves both for 64.
SPTM_DATA_SPAN_NARROW, SCRATCH_OFFSET_NARROW = SPTM_DATA_SPAN, SCRATCH_OFFSET
SCRATCH_COUNT = 6
SCRATCH_STRIDE = 0x8000
SCRATCH_SPAN = SCRATCH_COUNT * SCRATCH_STRIDE
# A kmutil-linked AuxKC (probes/auxkc.py) gets its own reservation right after
# the monitor data: the image reservation has only 0x2c000 spare and the
# handoff span holds boot data. Present only for aux_collection_linked
# profiles, so every other profile keeps its exact physical layout.
AUXKC_SPAN = 0x01000000


def auxkc_offset():
    return SPTM_DATA_OFFSET + SPTM_DATA_SPAN

# How much memory the guest gets, as a number rather than as a consequence.
#
# This was 0x18000000 written once and then quietly overruled: place() took the
# whole free span the target reported and declared all of it, so the size XNU
# saw was whatever the firmware happened to leave free that boot -- 2161 MiB
# under QEMU, ~508 MiB on the A16. That is not a setting, it is an accident, and
# it is the accident docs/PLAN-HISTORY-20260922.md records as the reason the default QEMU boot failed
# before reaching XNU at all: the frame table is sized from a fixed arena here
# and the RAM it has to cover was not.
#
# So the guest's memory is now stated, in megabytes, and the free region only
# has to be big enough to hold it. 384 MiB is the size every measurement in
# docs/ was taken at.
DEFAULT_GUEST_MIB = 384
GUEST_SPAN = DEFAULT_GUEST_MIB << 20
REGION_SPAN = GUEST_SPAN        # the DRAM we declare, base to end

# The monitor's own region, at a virtual address compiled into both binaries.
#
# SPTM establishes it itself. Its bootstrap at 0xfffffff0270e91e8 builds the
# bounds with the same mov/movk idiom the kernel uses to refer into it --
#
#   mov  x20, #-0xc000 ; movk #0xffde, lsl 16 ; movk #0xfecf, lsl 32
#   mov  x22, #-0x4001 ;                        movk #0xfecf, lsl 32
#   loop: add x20, x20, #0x4000 ; ... ; bl 0xfffffff0270e1898 ; cmp x20, x22
#
# -- and walks 0xfffffecfffde4000 to 0xfffffecfffffbfff a 16K page at a time.
# The kernelcache refers to seven addresses in the same window (see
# docs/APERTURE-FAULT.md), the lowest being 0xfffffecfffcfc000, so the region as
# the kernel sees it starts there and runs to the top of the window.
#
# Backed from inside the declared DRAM, so phystokv resolves these pages through
# region 0, and written as chunks so avail_start accounts for them like anything
# else the loader places.
# Free kernel VA, immediately above the static map, whose tables XNU expects to
# find already built.
#
# The walk at 0xfffffe000ba7a878 starts at VSPACE_TOP + 1 -- the first address
# past the top of the static map, which is where free kernel VA begins -- and
# runs for 24 MiB. It reads an L1 descriptor, resolves it through phystokv,
# reads the L2 descriptor under it, and hands the L3 table's physical address to
# `ptd_info_init` (0xfffffe000ba6d41c, named by its own panic strings at
# 0xfffffe000706e9ef and pmap_data.c at 0xfffffe000706e876), which registers
# that table page in the pmap's descriptor array. With the L1 entry zero the
# chain is: descriptor 0 -> phystokv(0) fails, correctly, because no region
# holds physical 0 -> `csel x9, x8, xzr, eq` substitutes zero unchecked -> the
# next load faults with FAR_EL1 = 0.
#
# The selected profile now starts free VA at 0xfffffe0200000000, within the
# kernel's packed vm-page queue pointer range. It shares the image's L1 table
# and needs one additional L3 table: 32 MiB covers this 24 MiB reservation.
# The earlier 0xfffffed000000000 boundary required a new L2 as well, but was
# outside that queue encoding and silently corrupted pointers later in boot.
#
# Every step of that is right given a zero entry. The only thing wrong is the
# entry, which is the same shape as the 48 MiB reserve and the monitor's own
# fixed region: an address space XNU expects to already exist.
#
# Tables only, no leaves. See Tables.reserve(). This is the small-guest default;
# place() scales the coverage for larger metadata allocations.
VSPACE_WALK_SPAN = 0x1800000            # 24 MiB

SPTM_REGION_VA = 0xfffffecfffcfc000
SPTM_REGION_END = 0xfffffed000000000

# Memory held back above the declared DRAM, for the structure the kernel places
# there itself.
#
# 0xfffffe000ba7a824 sizes it at 10 MiB per 256 MiB of RAM, rounds, adds about
# another 10, and aligns the end down to 8 MiB. It starts it at the top of the
# DRAM we declare and then walks the page tables across it, so it has to be
# memory we actually own and have mapped. Confirmed by moving the declaration:
# a 480 MiB region put the walk at 0xf8000000 and a 384 MiB one at 0xf2000000,
# with FAR_EL1 tracking the level-2 index each time. See
# docs/APERTURE-FAULT.md.
#
# 48 MiB is what both of those sizes produced, because both round to two 256 MiB
# units. This remains the small-guest default. bootstrap_reserve() scales a
# conservative bound for larger guests; all formula inputs are not yet
# identified, so it must not be described as the exact amount XNU consumes.
BOOTSTRAP_SPAN = 0x03000000


def bootstrap_reserve(guest_span):
    """Conservative metadata backing; discovery must request it with RAM.

    The stock bootstrap adds 10 MiB per rounded 256 MiB plus its table-array
    term. Keep the established small-guest reserve; use 16 MiB per unit plus
    16 MiB for larger guests. The initial heap needs matching empty table
    coverage, not just a larger physical RAM aperture.
    """
    if guest_span <= 0:
        raise ValueError('guest memory must be positive')
    return max(0x3000000, ((guest_span+0xfffffff)//0x10000000+1)*0x1000000)

# DRAM has to start and end on a 32 MiB boundary, because XNU rounds to one:
#
#   0xfffffe000ba7a7e0  mov w8, #0x1ffffff
#   0xfffffe000ba7a7e8  add x21, x9, x8
#   0xfffffe000ba7a7ec  and x20, x21, #0xfffffffffe000000
#
# With the region at 0xd9dc0000..0xf99e0000 -- what the A16's firmware reports,
# neither end aligned -- that round-up produced 0xfa000000, past the end of the
# memory we own, and everything computed from it was outside the aperture. A
# real machine's DRAM bank is aligned far more coarsely than this, so the
# assumption is reasonable and ours was the odd shape. Trimming to a 32 MiB
# grid costs about 28 MiB of a 508 MiB region and removes a whole class of
# off-the-end arithmetic.
REGION_ALIGN = 0x2000000

DEFAULT_PHYS_BASE = 0xD9E00000


def place(base, span=None, guest_span=None):
    """Move the physical layout to `base`. Returns the region's end.

    `span` is how much memory is free there; `guest_span` is how much of it the
    guest is given, and defaults to the profile's GUEST_SPAN. The two are
    separate on purpose -- the old signature took only the free span and
    declared all of it, which meant the guest's memory size was decided by
    whatever the firmware left over rather than by this file.

    Everything downstream reads these as module globals, and they are read at
    build time rather than captured, so setting them before build() is enough."""
    global PHYS_BASE, IMAGE_PA, HANDOFF_PA, TABLE_PA, REGION_END, REGION_SPAN
    global PARAMS_PA, DEVICETREE_PA, MONITOR_PA, FRAMETABLE_PA, BOOTSTRAP_PA
    global SPTM_DATA_PA, SCRATCH_PA, FRAMEMAP_PA
    global FRAMETABLE_SPAN, FRAMEMAP_OFFSET, FRAMEMAP_SPAN, TABLE_OFFSET, SPTM_DATA_OFFSET
    global VSPACE_TOP, BOOTSTRAP_SPAN, VSPACE_WALK_SPAN
    if base % REGION_ALIGN:
        raise ValueError(f'{base:#x} is not on the {REGION_ALIGN >> 20} MiB grid')
    want = (GUEST_SPAN if guest_span is None else guest_span) if span is not None or guest_span is not None else REGION_SPAN
    BOOTSTRAP_SPAN = bootstrap_reserve(want)
    VSPACE_WALK_SPAN = 0x1800000 if want <= 0x20000000 else BOOTSTRAP_SPAN
    PhysicalRange(base, want + BOOTSTRAP_SPAN, 'DRAM + reserve').validate(GRANULE, STAGE2_IPA_BITS)
    # High RAM can be far above the panel. The flat frame map covers that
    # entire physical envelope, including unowned holes. Reserve capacity for
    # the 36-bit IPA range instead of silently overlapping the table arena.
    large = base + want + BOOTSTRAP_SPAN > 1 << 32 or want > 1 << 30
    FRAMETABLE_SPAN = 0x02000000 if large else 0x00100000
    FRAMEMAP_OFFSET = FRAMETABLE_OFFSET + FRAMETABLE_SPAN
    FRAMEMAP_SPAN = 0x04000000 if large else 0x00100000
    TABLE_OFFSET = FRAMEMAP_OFFSET + FRAMEMAP_SPAN if large else 0x09200000
    SPTM_DATA_OFFSET = TABLE_OFFSET + TABLE_SPAN
    # Leave room for the panel aperture and the 64 MiB slide destination
    # below the heap. Admission still checks the actual panel and guest's
    # packed queue-pointer range at build time.
    heap = max(GUEST_PROFILE.early_heap_va, APERTURE_VA + want + 0x10000000)
    VSPACE_TOP = ((heap + REGION_ALIGN - 1) // REGION_ALIGN * REGION_ALIGN) - 1
    if span is not None or guest_span is not None:
        want = GUEST_SPAN if guest_span is None else guest_span
        if want % REGION_ALIGN:
            raise ValueError(f'{want >> 20} MiB of guest memory is not on the '
                             f'{REGION_ALIGN >> 20} MiB grid XNU rounds to')
        if want < TABLE_OFFSET + TABLE_SPAN:
            raise SystemExit(f'{want >> 20} MiB is not enough for the image and '
                             f'its tables, which need '
                             f'{(TABLE_OFFSET + TABLE_SPAN) >> 20} MiB')
        # The reserve comes out of what we were given, not out of thin air: the
        # kernel puts its structure above the DRAM we declare, so the memory we
        # hold has to extend past the declaration by that much.
        if span is not None and span < want + BOOTSTRAP_SPAN:
            raise SystemExit(f'{span >> 20} MiB free is not enough for a '
                             f'{want >> 20} MiB guest plus the '
                             f'{BOOTSTRAP_SPAN >> 20} MiB the kernel places '
                             f'above it')
        REGION_SPAN = want
    PHYS_BASE = base
    MONITOR_PA = base + MONITOR_OFFSET
    FRAMETABLE_PA = base + FRAMETABLE_OFFSET
    IMAGE_PA = base + IMAGE_OFFSET
    HANDOFF_PA = base + HANDOFF_OFFSET
    TABLE_PA = base + TABLE_OFFSET
    SPTM_DATA_PA = base + SPTM_DATA_OFFSET
    FRAMEMAP_PA = base + FRAMEMAP_OFFSET
    SCRATCH_PA = SPTM_DATA_PA + SCRATCH_OFFSET
    REGION_END = base + REGION_SPAN
    BOOTSTRAP_PA = REGION_END
    PARAMS_PA = HANDOFF_PA + 0xc000
    DEVICETREE_PA = HANDOFF_PA + (0x18000 if GUEST_PROFILE.boot_framebuffer_aux else 0x10000)
    validate_layout()
    return REGION_END


def reservations():
    """Everything placed at a fixed offset, as (name, offset, span).

    The image's own span is not here: it is whatever the kernelcache turns out
    to need, and build() checks it against the room between IMAGE_OFFSET and
    MONITOR_OFFSET. Everything below is a size this file chose, so it can be
    checked before a single byte is read."""
    return [
        ('handoff',     HANDOFF_OFFSET,     HANDOFF_SPAN),
        ('image',       IMAGE_OFFSET,       MONITOR_OFFSET - IMAGE_OFFSET),
        ('monitors',    MONITOR_OFFSET,     MONITOR_STRIDE * len(MONITOR_IMAGES)),
        ('frame table', FRAMETABLE_OFFSET,  FRAMETABLE_SPAN),
        ('frame map',   FRAMEMAP_OFFSET,    FRAMEMAP_SPAN),
        ('page tables', TABLE_OFFSET,       TABLE_SPAN),
        ('sptm data',   SPTM_DATA_OFFSET,   SPTM_DATA_SPAN),
    ] + ([('aux collection', auxkc_offset(), AUXKC_SPAN)]
         if GUEST_PROFILE.aux_collection_linked else [])


def validate_layout():
    """Reject a layout that overlaps itself or runs off the end of the region.

    These offsets were each chosen for its own reason, at different times, and
    nothing until now compared them to each other. An overlap here does not
    fault: one structure is written and then partly overwritten by the next, and
    what XNU reads is a plausible-looking hybrid. Checking is four lines and it
    happens before anything is built."""
    placed = sorted(reservations(), key=lambda r: r[1])
    for (a_name, a_off, a_span), (b_name, b_off, _) in zip(placed, placed[1:]):
        if a_off + a_span > b_off:
            raise SystemExit(f'layout: {a_name} ({a_off:#x} +{a_span:#x}) runs '
                             f'into {b_name} at {b_off:#x}')
    name, off, span = placed[-1]
    if off + span > REGION_SPAN:
        raise SystemExit(f'layout: {name} ends at {off + span:#x}, past the '
                         f'{REGION_SPAN >> 20} MiB declared to the guest')
    if SCRATCH_OFFSET + SCRATCH_SPAN > SPTM_DATA_SPAN:
        raise SystemExit(f'layout: the per-CPU scratch ends at '
                         f'{SCRATCH_OFFSET + SCRATCH_SPAN:#x}, past the '
                         f'{SPTM_DATA_SPAN:#x} monitor-data span it lives in')
    # The expanded registry needs more than the old 4 KiB slot at +0x2000.
    # Keep it in the dedicated interval after VNCR and before the device tree.
    if not (HANDOFF_PA + 0xc000 <= PARAMS_PA and
            PARAMS_PA + (PARAMS_WORDS + 6 + 12 + 4) * 8 <= DEVICETREE_PA):  # + i2cinput, qcc2072wifi, displaytiming
        raise SystemExit('layout: parameters overlap VNCR or the device tree')
    if GUEST_PROFILE.boot_framebuffer_aux:
        import bootfb
        if (PARAMS_PA + PARAMS_WORDS * 8 > HANDOFF_PA + bootfb.OFFSET or
                DEVICETREE_PA != HANDOFF_PA + bootfb.DT_OFFSET):
            raise SystemExit('layout: auxiliary collection overlaps boot data')


PHYS_BASE = DEFAULT_PHYS_BASE
MONITOR_PA = DEFAULT_PHYS_BASE + MONITOR_OFFSET
FRAMETABLE_PA = DEFAULT_PHYS_BASE + FRAMETABLE_OFFSET
IMAGE_PA = DEFAULT_PHYS_BASE + IMAGE_OFFSET
TABLE_PA = DEFAULT_PHYS_BASE + TABLE_OFFSET
SPTM_DATA_PA = DEFAULT_PHYS_BASE + SPTM_DATA_OFFSET
FRAMEMAP_PA = DEFAULT_PHYS_BASE + FRAMEMAP_OFFSET
SCRATCH_PA = SPTM_DATA_PA + SCRATCH_OFFSET
HANDOFF_PA = DEFAULT_PHYS_BASE + HANDOFF_OFFSET
REGION_END = DEFAULT_PHYS_BASE + REGION_SPAN
BOOTSTRAP_PA = REGION_END


def ans_reservation():
    """The virtual ANS2's monitor-private (base, span), or None without one.

    Directly above the monitor work arena that run.py places at the
    first 64 KiB boundary past the bootstrap reserve; run.py asks the
    firmware for room for both and checks the result against q1n1's own
    allocations. Outside every stage-2 range: the guest reaches the disk only
    through the virtual controller."""
    spec = GUEST_PROFILE.ans_boot
    if spec is None:
        return None
    import monitor_work
    work = (BOOTSTRAP_PA + BOOTSTRAP_SPAN + 65535) & ~65535
    base = work + monitor_work.WORK_SIZE
    if spec.window:     # the SSD's DMA window inside it must be 1 MiB aligned (compat/nvme-host.h)
        base = (base + (1 << 20) - 1) & ~((1 << 20) - 1)
    return base, ans_reservation_span(spec.disk_bytes, spec.window)


# ADRENO_VA_WIDE (agents/gpu-va-wide): the GPU VA window [1 GiB, 16 GiB) for a -DADRENO_VA_WIDE=1 monitor and kext
# and a q1n1 `cp-fence/adopt --va-wide` CB0. configure_adreno_va_wide() sets it (None reads SNAP_ADRENO_VA_WIDE, 0 or
# 1); False leaves every Adreno path as it was.
ADRENO_VA_WIDE = False
ADRENO_VA_WIDE_ENV = 'SNAP_ADRENO_VA_WIDE'


def configure_adreno_va_wide(wide=None):
    """The loader half of -DADRENO_VA_WIDE=1 (both or neither): the dart-adreno vm-size, the GPU node's
    snapintosh,gpu-va-bits, the monitor-private table reservation and the params pool word."""
    global ADRENO_VA_WIDE
    if wide is None:
        value = os.environ.get(ADRENO_VA_WIDE_ENV, '0')
        if value not in ('0', '1'):
            raise ValueError(f'{ADRENO_VA_WIDE_ENV} must be 0 or 1')
        wide = value == '1'
    ADRENO_VA_WIDE = bool(wide)
    import devicemodel
    devicemodel.ADRENO_DART_WIDE = ADRENO_VA_WIDE     # its dart-adreno fingerprint
    return ADRENO_VA_WIDE


def adreno_spec():
    """The profile's AdrenoSpec as this launch uses it: va_wide from configure_adreno_va_wide(); None without one."""
    spec = GUEST_PROFILE.adreno
    if spec is None or not ADRENO_VA_WIDE:
        return spec
    import dataclasses
    return dataclasses.replace(spec, va_wide=True)


def gpu_pool_reservation():
    """The wide GPU table pool's monitor-private (base, span), or None (default window, or no Adreno profile).

    Directly above the monitor's last reservation (the virtual ANS2 one, else the work arena), on the 64 KiB grid.
    run.py asks the firmware for room for it with the rest and checks it like the ANS2 reservation. Outside every
    stage-2 range: XNU never reaches it; only the monitor writes it and only the GPU SMMU walks it."""
    spec = adreno_spec()
    if spec is None or not spec.va_wide:
        return None
    import adreno
    import monitor_work
    work = (BOOTSTRAP_PA + BOOTSTRAP_SPAN + 65535) & ~65535
    end = work + monitor_work.WORK_SIZE
    ans = ans_reservation()
    if ans is not None:
        end = ans[0] + ans[1]
    base = (end + adreno.POOL_RESERVATION_ALIGN - 1) & ~(adreno.POOL_RESERVATION_ALIGN - 1)
    return base, adreno.pool_reservation_bytes()


def ans_windows(dt, node='ans', bus='/device-tree/arm-io'):
    """device_windows() for a node whose reg carries empty (0, 0) placeholders.

    /arm-io/ans lists 13 pairs, three of them empty; those name no window and
    are skipped. Every non-empty pair must translate, as in device_windows."""
    raw = bytes(dt.nodes[f'{bus}/{node}']['reg'].value)
    if not raw or len(raw) % 16:
        raise ValueError(f'{node} reg is not whole 64-bit (address, size) pairs')
    ranges = bytes(dt.nodes[bus]['ranges'].value)
    ranges = [struct.unpack_from('<QQQ', ranges, off) for off in range(0, len(ranges), 24)]
    out = []
    for off in range(0, len(raw), 16):
        child, size = struct.unpack_from('<QQ', raw, off)
        if (child, size) == (0, 0):
            continue
        for lo, parent, span in ranges:
            if size > 0 and lo <= child < child + size <= lo + span:
                out.append((parent + (child - lo), size))
                break
        else:
            raise ValueError(f'{node} reg {child:#x} is outside every {bus} range')
    return out

# The upper translation regime, taken from the kernel rather than inferred.
#
# This was 23 for a long time, on the reasoning that 41 VA bits puts offset 0 of
# the regime exactly at 0xfffffe0000000000, where the kernelcache is linked. The
# arithmetic is right and the conclusion is not: a kernel linked there can sit
# near the bottom of a larger regime just as well, and this one does.
#
# XNU's own page-table geometry descriptor says so. At 0xfffffe0007d9f798 it
# carries start level 1 and a VA mask of 0x00007fffffffffff -- 47 bits, which is
# T1SZ 17. Its walker reads the top-level table at index (va >> 36) & 0x7ff, and
# the run that died at 0xfffffe000ba7ab68 was reading index 2028 out of a table
# we had built with 32 entries. See docs/APERTURE-FAULT.md.
T1SZ = 17
GRANULE = 14
KERNEL_BASE = (1 << 64) - (1 << (64 - T1SZ))

# Stage-1 leaf attributes. AF set, inner shareable, AP=00 (EL1 read/write, no
# EL0), attribute index 0. Permissions are deliberately uniform for a first
# boot: getting XNU to run at all comes before getting it to run confined.
PT_VALID, PT_TABLE, PT_AF = 1 << 0, 1 << 1, 1 << 10
LEAF = PT_VALID | PT_TABLE | PT_AF | (3 << 8)
# Non-executable AuxKC segments: PXN and UXN, still EL1 read/write because
# kernel_collection_slide writes their chained fixups at EL1 before lockdown.
# Executable ones keep the primary image's LEAF.
LEAF_NX = LEAF | (1 << 53) | (1 << 54)

# The SPTM handoff, from the validator at 0xfffffe000c26a920 (docs/BOOT-CHAIN.md
# section 5). The magic is checked against the first quadword of *x2; the
# versioned table lives at +0x1a0. Version 1 keeps every version-gated field out
# of play -- including the one at +0xa8 whose bit 6 selects the second,
# unidentified call instruction.
HANDOFF_MAGIC = 0xD00F000000000000
HANDOFF_TABLE_OFFSET = 0x1A0
HANDOFF_VERSION = 1

# The SPTM handoff is 856 bytes -- XNU memcpys exactly 0x358 of them at
# 0xfffffe000c2447f4 -- and its last word is a set of build flags that have to
# agree with the kernel's own, or arm_init_sptm gives up before anything else
# happens:
#
#   ldr x8, [x8, #0x350]          ; the flags
#   tbz w8, #4,  panic            ; ARM_LARGE_MEMORY must be set
#   and x8, x8, #0x20
#   cbnz x8, panic                ; ARM_LARGE_MEMORY_KERNONLY must be clear
#
#   panic: Mismatch of ARM_LARGE_MEMORY in SPTM (0)/XNU (0x10) @arm_init_sptm.c:1100
#
# This is a compile-time agreement between two binaries Apple ships together,
# and we are standing in for one of them, so the answer is simply what the
# kernel was built expecting. ARM_LARGE_MEMORY is the 64-bit-physical kernel
# layout; KERNONLY is the variant that keeps it out of the user half, and this
# kernelcache is not that one.
# Where free physical memory starts, and where it ends.
#
# This one was worth reversing the producer for. XNU's early physical allocator
# is a bump cursor at 0xfffffe0007da06c8, and it was zero -- zero in the image,
# zero after all 1,001,004 fixups, and across every TEXT segment there are
# exactly eight writes to it, all of which only *align* it. Nothing in the
# kernel seeds it. It arrives from here:
#
#   0xfffffe000c24480c  ldr x8, [x21, #0x18]   ; this field
#   0xfffffe000c244814  str x8, [x9, #0xd60]   ; -> 0xfffffe0007d9fd60
#   0xfffffe000ba79474  ldr x8, [x8, #0xd60]
#   0xfffffe000ba7947c  str x8, [x25, #0x6c8]  ; -> the cursor
#
# and with it zero the first allocation is at physical 0, phystokv(0) correctly
# fails, and XNU hands the NULL to bzero without checking. So +0x18 is
# avail_start: the first physical address the monitor is not using.
#
# The real sptm.t8140.release agrees. It writes +0x10 and +0x18 as a pair at
# 0xfffffff0270c0324, and computes +0x10 as a base plus a page count shifted by
# 14 -- an end address. That is the other half: the end of the memory being
# handed over.
SPTM_AVAIL_START = 0x18

# +0x08 and +0x10 are not an available-memory range. They are the kernel's
# static virtual map, and both were wrong: +0x10 held a physical address and
# +0x08 was never written at all.
#
# The producer-side observation that led to "avail_end" still stands -- SPTM
# does write +0x10 and +0x18 as a pair at 0xfffffff0270c0324, computing +0x10 as
# a base plus a page count shifted by 14. What does not follow is that the base
# is physical; a VA base plus a page count is equally an end address, and the
# consumers settle it the other way.
#
# XNU reads the two together at 0xfffffe000ba79440 -- `ldp x9, x10, [x8, #0x8]`,
# which is why neither showed up in a scan that matched single `ldr` -- and uses
# them at 0xfffffe000ba7c300 as a range test:
#
#   ldr  x12, [+0xba8]          ; the +0x08 value
#   cmp  x11, x12 ; b.hs        -> carry on, else fail
#   bfxil x10, x8, #0, #47      ; splice a 47-bit address under a fixed top
#   ldr  x8,  [+0x210]          ; the +0x10 value
#   cmp  x10, x8 ; cset w8, ls  ; ...and must be <= it, so the top is INCLUSIVE
#
# The 47-bit splice is the giveaway: T1SZ is 17, so 47 bits is exactly a kernel
# VA. Three more things agree, and together they pin the values:
#
# - The guard at 0xfffffe000ba79464 bails when +0x10 is at or above
#   0xfffffed000000000. This is a ceiling, not a suitable heap placement.
# - 0xfffffe000ba770d4 encodes addresses as `bfi x10, x11, #22, #42` of
#   (addr - base). A zero base makes the offset the raw address and overflows
#   the field; the chosen base keeps the kernel's static offsets encodable.
# - 0xfffffe000b88b164 carries 0xfffffe0000000000 as a literal it clamps the
#   +0x08 value against, so the kernel's own code names this neighbourhood.
#
# The static window covers the image and RAM aperture. The monitor's fixed
# region has its own mapping and does not dictate where the kernel heap starts.
# Choosing the ceiling as the top put that heap outside the narrower vm-page
# queue encoding (32-bit VA>>6). It silently reconstructed ...fed0019ed3c0 as
# ...fe10019ed3c0. Keep the free-VA boundary in the selected guest's queue range.
VSPACE_BASE_OFFSET = 0x08
VSPACE_TOP_OFFSET = 0x10
VSPACE_BASE = 0xFFFFFE0000000000
VSPACE_TOP = GUEST_PROFILE.early_heap_va - 1   # inclusive, per the `ls` above

# How wide the encoding at 0xfffffe000ba770d4 can express.
#
#   sub x11, x9, x10            ; addr - base
#   bfi x10, x11, #0x16, #0x2a  ; 42 bits of it, at bit 22
#
# Two ways to fall outside, and they fail through different instructions, so
# they are two checks rather than one range test:
#
#   addr <  base            the subtraction wraps and the unsigned shift that
#                           decodes it yields garbage
#   addr >= base + 2^42     the value is truncated to 42 bits, silently
#
# Both are silent, which is why this is checked at build time at all. The lower
# bound on the base is DERIVED from the top rather than written down: a
# hard-coded figure goes stale the moment VSPACE_TOP moves, and a check whose
# premise has quietly become false is the exact failure the dead overflow guard
# was -- something that appears to be watching and is not.
VSPACE_OFFSET_BITS = 42
VSPACE_OFFSET_LIMIT = 1 << VSPACE_OFFSET_BITS


def validate_vspace(tables):
    """Every kernel VA we map must be encodable as an offset from VSPACE_BASE.

    Low-half addresses are skipped, and that is not an oversight. The bootstrap
    reserve is identity mapped at VA == PA (0xf2000000 and up) so the kernel can
    walk addresses numerically equal to physical ones; those live in the TTBR0
    regime, not in the static map this encoding describes, and testing them
    against it would fail a check that was never about them.

    This checks the ENCODING, not the window. The two are different bounds and
    only one of them covers everything: SPTM and TXM are mapped at their linked
    addresses, 0xfffffff027004000 and 0xfffffff017004000, which are above
    VSPACE_TOP -- and must be, because the guard at 0xfffffe000ba79464 caps the
    top below 0xfffffed000000000, so no legal window could reach them. They are
    the monitor's addresses rather than the kernel's static map, and XNU reaches
    them through the DEBG table's pointers rather than by translating them
    through this window. Their offsets are 41 bits, so the encoding still holds
    for them, which is what this function is about."""
    if VSPACE_BASE <= VSPACE_TOP - VSPACE_OFFSET_LIMIT:
        raise SystemExit(
            f'the static map {VSPACE_BASE:#x}..{VSPACE_TOP:#x} spans more than '
            f'{VSPACE_OFFSET_BITS} bits; the lowest base this top allows is '
            f'{VSPACE_TOP - VSPACE_OFFSET_LIMIT + 1:#x}')
    for va, size, what in tables.ranges:
        if va < KERNEL_BASE:
            continue                       # the identity reserve; see above
        if va < VSPACE_BASE:
            raise SystemExit(
                f'{what} {va:#x} +{size:#x} is below the static map base '
                f'{VSPACE_BASE:#x}; `sub x11, x9, x10` at 0xfffffe000ba770d4 '
                f'would wrap and the unsigned shift that decodes it would '
                f'yield garbage')
        if va + size - VSPACE_BASE > VSPACE_OFFSET_LIMIT:
            raise SystemExit(
                f'{what} {va:#x} +{size:#x} ends {va + size - VSPACE_BASE:#x} '
                f'above the static map base, past the {VSPACE_OFFSET_BITS}-bit '
                f'field in `bfi x10, x11, #0x16, #0x2a`; it would be truncated '
                f'silently')

# The frame table: one entry per physical page, saying what that page is.
#
# XNU reaches it through the versioned table at +0x38, translates it, and then
# walks three levels (0xfffffe000ba7a860):
#
#   dir   = phystokv(table[+0x38])
#   entry = dir[(pa >> 36) & 0x7ff]          ; one per 64 GiB
#   leaf  = phystokv(entry & ~0xfff)         ; then a 32 MiB stride (x25)
#
# and maps each leaf into its own address space. The leaf's shape falls out of
# the arithmetic: a leaf covers 32 MiB, which at 16K pages is 2048 frames, and
# 2048 eight-byte entries is exactly one 16K page. SPTM's own assertion strings
# say what those eight bytes hold --
#
#   fte(%p), fte->type(%s), new_type(%s), mapping_refcnt(%u), nested_refcnt(%u)
#   fte(%p), fte->type(%s), read_refcnt(%d), write_exec_refcnt(%d)
#
# -- a type and a handful of refcounts, packed. Zero is the untyped state, which
# is what every frame is before anything claims it, so an all-zero table is the
# honest starting point rather than a placeholder.
#
# This is the half of SPTM that can be built from the outside. The other half --
# keeping it true across every retype and map -- is the monitor's actual job and
# is not done here.
FRAME_SHIFT = 14                # 16K frames
FRAME_ENTRY = 8                 # bytes per frame
LEAF_SPAN = 0x2000000           # 32 MiB of physical memory per leaf
DIR_SHIFT = 36                  # one directory entry per 64 GiB
DIR_ENTRIES = 2048


def build_frametable(pa, base, span):
    """The three levels, as {physical address: bytes}. Returns (chunks, root)."""
    leaf_bytes = (LEAF_SPAN >> FRAME_SHIFT) * FRAME_ENTRY
    page = 1 << GRANULE
    if leaf_bytes != page:
        raise SystemExit(f'a leaf is {leaf_bytes:#x}, not one {page:#x} page')

    chunks = {}
    root = pa
    directory = bytearray(page)
    level2 = bytearray(page)
    cursor = pa + 2 * page

    first, last = base >> DIR_SHIFT, (base + span - 1) >> DIR_SHIFT
    if first != last:
        raise SystemExit('the region straddles a 64 GiB boundary; one level-2 '
                         'table is not enough')
    struct.pack_into('<Q', directory, first * 8, pa + page)

    for offset in range(0, span, LEAF_SPAN):
        index = ((base + offset) >> 25) & (DIR_ENTRIES - 1)
        struct.pack_into('<Q', level2, index * 8, cursor)
        chunks[cursor] = bytes(page)          # every frame untyped
        cursor += page
    if cursor > pa + FRAMETABLE_SPAN:
        raise SystemExit(f'the frame table needs {cursor - pa:#x}, more than its arena')

    chunks[pa] = bytes(directory)
    chunks[pa + page] = bytes(level2)
    return chunks, root

# The flat frame map, and the three fields that describe it.
#
# `sptm_get_frame_type` at 0xfffffe000c22aaec is the consumer, and it is not
# ambiguous:
#
#   x8 = [table + 0x18]                 ; low
#   x9 = [table + 0x20]                 ; high
#   subs x8, x0, x8                     ; x0 is a PHYSICAL address
#   ccmp x0, x9, #0x2, hs ; b.lo        -> in range, use the map
#     x9  = [table + 0x40]              ; the map
#     lsr x8, x8, #10
#     and x8, x8, #0x3ffffffffffff0     ; ((paddr - low) >> 14) * 16
#     ldrb w8, [x9 + x8, #0x2]          ; the type byte
#   otherwise, and when the map pointer is null:
#     w8 = 0x1a                         ; the "no idea" answer
#
# Three things fall out, and two of them correct what this loader does now:
#
# 1. +0x40 is DEREFERENCED at EL1, so it is a virtual address. +0x18 and +0x20
#    are compared against a physical one, so they are physical. That asymmetry
#    is real and not a transcription error.
#
# 2. The map is FLAT: sixteen bytes per 16K page, indexed off +0x18. It is not
#    the three-level structure build_frametable() emits, so that root could not
#    have been published here even if it had been wired up -- the consumer would
#    have indexed a tree as an array.
#
# 3. +0x18 is the map's low bound, NOT the per-CPU scratch base. This loader has
#    been writing SCRATCH_PA there. That is the same "one field, two consumers"
#    trap again, and it is why docs/PLAN-HISTORY-20260922.md records that publishing the scratch there
#    "changed nothing observable": with +0x20 left at zero the range test can
#    never be taken, so a wrong low bound was invisible. Endpoint 0x32 is where
#    XNU actually gets the scratch, and it is answered.
FRAMEMAP_LOW = 0x18             # table offset: first physical address covered
FRAMEMAP_HIGH = 0x20            # ...and one past the last
FRAMEMAP_BASE = 0x40            # the map itself, as a VA
FRAMEMAP_ENTRY = 16             # bytes per 16K frame
FRAMEMAP_TYPE_BYTE = 2          # where in the entry the type lives

# The type byte, and where the value comes from.
#
# 0x1a is what the kernel uses for "not in the map", and it matches nothing --
# that is the symptom. The required type is computed from the PTE's protection
# bits and is one of 0x0b, 0x0e or 0x11.
#
# This started as a hypothesis, because the comparison at 0xfffffe000ba62d30 is
# between two bytes both computed at run time and so names no literal. It is now
# a measurement from the other side: on the device, all 379 maps that succeeded
# before the panic required 0x0b. A uniform 0x0b is therefore the value that
# makes the in-range path agree for every page seen so far.
#
# Still a single value standing in for a computed one, so the switch stays:
# SNAP_FRAME_TYPE sweeps it and the run prints which value was used and whether
# it was asked for. A boot that advances on a constant must not look like one
# that advances because the constant was right.
FRAMEMAP_DEFAULT_TYPE = 0x0B


def frame_type():
    """The type byte every frame gets, and whether it was asked for."""
    want = os.environ.get('SNAP_FRAME_TYPE')
    return (int(want, 0), True) if want else (FRAMEMAP_DEFAULT_TYPE, False)


def build_framemap(pa, low, high, type_byte, ranges=None):
    """The flat map, as {physical address: bytes}. One entry per 16K frame."""
    PhysicalRange(low, high - low, 'frame map').validate(FRAME_SHIFT, STAGE2_IPA_BITS)
    if not 0 <= type_byte <= 255:
        raise ValueError('frame type must fit in one byte')
    frames = (high - low) >> FRAME_SHIFT
    size = frames * FRAMEMAP_ENTRY
    if size > FRAMEMAP_SPAN:
        raise SystemExit(f'the frame map needs {size:#x} for {frames} frames, '
                         f'more than the {FRAMEMAP_SPAN:#x} reserved')
    blob = bytearray(size)
    typed = ranges if ranges is not None else [PhysicalRange(low, high - low, 'frame map')]
    for region in checked_ranges(typed, FRAME_SHIFT, STAGE2_IPA_BITS):
        if region.base < low or region.end > high:
            raise ValueError(f'{region.name} lies outside the frame map')
        for n in range((region.base - low) >> FRAME_SHIFT,
                       (region.end - low) >> FRAME_SHIFT):
            blob[n * FRAMEMAP_ENTRY + FRAMEMAP_TYPE_BYTE] = type_byte
    return {pa: bytes(blob)}, size


SPTM_FLAGS_OFFSET = 0x350
SPTM_ARM_LARGE_MEMORY = 1 << 4
SPTM_ARM_LARGE_MEMORY_KERNONLY = 1 << 5
SPTM_FLAGS = SPTM_ARM_LARGE_MEMORY

# The versioned table at +0x1a0 is the SPTM/XNU interface proper, and the entry
# stub consumes it before anything else runs:
#
#   0xfffffe000c268558  ldr x8, [x0]        ; the magic above
#   0xfffffe000c268568  add x0, x0, #0x1a0  ; this table
#   0xfffffe000c26856c  bl  ...             ; nonzero return -> wfe forever
#
# The consumer (0xfffffe000c26a920) copies it field by field into globals at
# 0xfffffe0007ec0240 and up, and the version at +0x00 gates how much of it is
# read -- 3, 5, 6 and 8 each unlock more. Every one of those globals is read
# somewhere in the kernel, so this table is not decoration; standing in for SPTM
# means filling it. The map below is the copy loop read straight off, so a fault
# on one of those globals names the field that is still missing:
#
#   +0x08 -> 0x240   +0x10 -> 0x248   +0x18 -> 0x250   +0x20 -> 0x258
#   +0x28 -> 0x260   +0x30 -> 0x268   +0x38 -> 0x270   +0x40 -> 0x278
#   +0x48 -> 0x280   +0x50 -> 0x288   +0x58 -> 0x290   +0x60 -> 0x298 (u32)
#   +0x68 -> 0x2a0   +0x70 -> 0x2a8   +0x78 -> 0x2b0
#   version >= 3: +0x80 -> 0x2b8      > 3: +0x88 -> 0x2c0
#   version >= 5: +0x90 -> 0x2c8, +0x98 -> 0x2d0 (u32)
#   version >= 6: +0xa0 -> 0x2d8      > 6: +0xa8 -> 0x2e0, bit 6 -> 0x2e8
#   version >= 8: +0xb0 -> 0x2f0, +0xb8 -> ... (u32)
#
# Version 1 is deliberate: it stops the copy at +0x78, so the fields we cannot
# yet answer for are ones XNU never asks about.
HANDOFF_REGIONS = 0x08          # -> 0x240: pointer to a u32 count
HANDOFF_REGION_TABLE = 0x10     # -> 0x248: {u64 phys, u64 delta, u32 pages} * n
HANDOFF_PAGETABLE = 0x38        # -> 0x270: root of the kernel's 16K page tables
HANDOFF_FRAME_TYPES = 0x48      # -> 0x280: SPTM's 144-byte type descriptors
# -> 0x250: base of the per-CPU scratch pages the monitor writes its results
# into, one page per CPU indexed by CPU id. m1n1-j700/src/sptm/private.h:1437
# names it scratch_pa; the offsets here are the versioned table's and the
# comments are where XNU stores each one, which is 0x238 + this.
HANDOFF_SCRATCH = 0x18
# A zeroed byte inside the handoff, for fields that are pointers to flags we
# have nothing to say about. Clear of the versioned table, which the kernel
# copies as far as +0x4f8.
FLAGS_OFFSET = 0x700
PANIC_HANDOFF_OFFSET = 0x198
PANIC_PAGE_SIZE = 0x4000


def panic_state_reservation(trust_end=0):
    """One owned page immediately below scratch, outside UAT/static cache."""
    pa = SCRATCH_PA - PANIC_PAGE_SIZE
    if pa < SPTM_DATA_PA or trust_end > pa or pa & (PANIC_PAGE_SIZE - 1):
        raise ValueError('panic state overlaps monitor data or static trust cache')
    return pa, APERTURE_VA + pa - PHYS_BASE, PANIC_PAGE_SIZE

def static_trust_window(cpu_count):
    """[begin, end) available to the boot trust cache (its runtime page plus
    payload), between the UAT pages and the panic page below scratch. build()
    derives the same addresses and refuses to run if the two disagree."""
    sptm_span = SPTM_REGION_END - SPTM_REGION_VA
    txm_pa = SPTM_DATA_PA + sptm_span
    txm_log_pa = txm_pa + cpu_count * MONITOR_STACK_GRAIN + 0x100000
    uat_pa = txm_log_pa + 0x8000 + MONITOR_STACK_GRAIN + TXM_ASPACE_PAGES * MONITOR_STACK_GRAIN
    return uat_pa + 3 * MONITOR_STACK_GRAIN, SCRATCH_PA - PANIC_PAGE_SIZE


def static_trust_fits(payload_size, cpu_count=SCRATCH_COUNT):
    """Both limits: TXM's version-2 payload bound and the loader window."""
    from trustcache import reserve_size, MAX_PAYLOAD
    if not 24 <= payload_size <= MAX_PAYLOAD:
        return False
    begin, end = static_trust_window(cpu_count)
    return reserve_size(payload_size) <= end - begin


# Where those two point. The physical aperture table is the first thing XNU
# touches through this interface: 0xfffffe000c22aa40 walks it to turn a physical
# address into a virtual one, entry by 24-byte entry --
#
#   base = entry[0x00];  if addr <  base                      : next
#   end  = base + (entry[0x10] << 14);  if addr >= end        : next
#   result = addr - base + entry[0x08]
#
# -- which is phystokv over regions SPTM published.
#
# An empty table was the first answer here, on the reading that publishing no
# regions is simply the truth while this hypervisor maps the kernel and nothing
# else, and that a count of zero takes the same exit as an address matching no
# region. Both halves of that are right and the conclusion was still wrong,
# because of what the caller does with the failure:
#
#   0xfffffe000ba76738  bl   phystokv(pa, &out)
#   0xfffffe000ba7674c  csel x0, x8, xzr, eq     ; success ? va : NULL
#   0xfffffe000ba76750  bl   bzero(x0, x1)       ; and zeroes it either way
#
# XNU does not treat "not found" as a condition to handle; it hands the result to
# bzero unchecked. So an empty table is not a modest answer, it is a guaranteed
# null write. The aperture has to be real: one region covering the memory we were
# given, mapped linearly -- which is what a physmap is, and what the entry format
# describes.
REGIONS_OFFSET = 0x3000
REGION_ENTRY_SIZE = 0x18
# Clear of the kernel (0xfffffe0007004000..0xfffffe000e358000) and of the monitor
# images at 0xfffffff0........; the regime leaves room for all three.
#
# Absolute, not KERNEL_BASE-relative. It used to be the latter, which was the
# same address while the regime was 41 bits. Widening to 47 would have dragged
# the aperture down to 0xffff800100000000 as a side effect of a change that is
# about table geometry -- and where the aperture sits is a separate decision,
# already settled by the gap this comment describes. XNU only learns of it
# through the region table we publish, so any mapped VA would work; this one is
# the one that has been working.
APERTURE_VA = 0xfffffe0100000000

# Two more pointers, at +0x60 and +0x68 of the handoff itself rather than of the
# versioned table. Each is a small descriptor whose +0x10 is a Mach-O header:
# 0xfffffe000ba7a6f0 follows it, walks the load commands for `__TEXT`, takes its
# vmaddr as a slide and counts the segments (0xfffffe000c098000). XNU registers
# `sptm` and `txm` as pseudo-kexts -- the strings `sptm.no.binname.in.macho` and
# `txm.no.binname.in.macho` are in the kernelcache -- so what it wants is the
# monitor binaries' own headers, for identification and for panic symbolication.
#
# We have them. `sptm.t8140.release` and `txm.macosx.release` come out of the
# same IPSW as the kernelcache and are ordinary arm64e Mach-Os, contiguous and
# 16K aligned, linked at 0xfffffff027004000 and 0xfffffff017004000 -- both
# inside the TTBR1 regime. So rather than inventing a header, the real images are
# loaded at their real addresses. They are never executed: their entry points are
# the monitor calls this hypervisor answers itself. But everything XNU reads
# about them is then true, and the slide is zero, which is one less thing that
# can be subtly wrong.
MONITOR_IMAGES = GUEST_PROFILE.monitors

# +0x60 is a debug table, not a monitor image descriptor.
#
# The descriptor reading is retired here, and it is worth saying what was wrong
# with it because the evidence looked good at the time. Filling `+0x10` of the
# structure moved a fault to `+0x20` of the same structure, which read as "one
# descriptor, two images, SPTM then TXM". What it actually showed was that
# something walks this pointer and reads increasing offsets -- which is equally
# true of a table of 0x44-byte entries, and that is what it is.
#
# XNU validates it at 0xfffffe000b88b0e0, and the check is unambiguous:
#
#   x8 = [0xfffffe0007ebf100]      ; the handoff copy, same global as randseed
#   cbz x8            -> bail
#   x8 = [x8 + 0x60]              ; a pointer, and it must not be null
#   cbz x8            -> bail
#   w9 = [x8]         ; cmp against 0x47424544          -- 'DEBG', LE
#   w9 = [x8 + 0x4]   ; cmp #2                          -- version
#   w8 = [x8 + 0x8]   ; count
#   x1 = w8 * 0x44 + 0x10 ; x0 = w8 + 1 ; braa          -- size, and entries + 1
#
# Failing any of those three checks takes the bail path, which calls the same
# continuation with (1, 0x10) instead. Not a panic, which is why the old
# descriptor value never announced itself: a VA at +0x60 is non-null, so it
# passed the first check, failed the magic, and quietly took the wrong branch.
#
# AND THE HEADER IS NOT THE WHOLE STRUCTURE. This cost a regression, so it is
# written down at length. The validator above is happy with a count of zero --
# the size it computes is `count * 0x44 + 0x10`, and it dereferences nothing.
# A DIFFERENT consumer, at 0xfffffe000ba7a6ec, reads the table's +0x10 without
# consulting the count at all, and treats it as a pointer to a Mach-O:
#
#   ldr x8,  [x23, #0x100]   ; the handoff copy
#   ldr x8,  [x8, #0x60]     ; this table
#   ldr x20, [x8, #0x10]     ; a POINTER, read whatever the count says
#   str x20, [x8, #0xb88]    ; cached into __DATA_CONST
#   add x22, x20, #0x20      ; skip a 32-byte mach_header_64
#   loop: ldr w8, [x22] ; cmp #0x19 (LC_SEGMENT_64) ; b.ne next
#         strncmp(x22 + 8, "__TEXT", 16) ; b.ne next
#   next: ldr w8, [x22, #4] ; add x22, x22, x8     ; cmdsize
#
# and then the identical walk again on +0x20. So +0x10 is SPTM's Mach-O header
# and +0x20 is TXM's, which is exactly what the code this replaced already had
# right -- it was wrong only about the first sixteen bytes. Both readings were
# half of one structure.
#
# Two consequences worth stating plainly. There IS a monitor image pointer in
# the handoff after all, nested in this table rather than at handoff +0x60/+0x68
# where it was first put; "there is no image descriptor anywhere" was too
# strong. And the walk has no bound: it advances by cmdsize until it finds a
# named segment, so a null or a non-Mach-O here does not fail cleanly -- a null
# faults at 0x20 (the measured FAR of the regression) and a wrong pointer would
# wander. `__TEXT` is the first segment of both images, so the real walk stops
# on its first load command.
#
# The count: 1, not 0. Nothing measured says what an "entry" contains, and the
# 0x44 stride is not corroborated by this walker -- +0x10 and +0x20 are sixteen
# bytes apart, not 0x44. What is certain is that a count of 0 makes the
# validator compute a size of 0x10, which excludes the very pointers the walker
# requires: the structure would be declaring itself smaller than its own
# contents. One entry gives 0x54, which covers the 0x20 bytes actually written,
# and is consistent with those two pointers being fields of a single entry
# beginning at +0x10.
HANDOFF_DEBUG_TABLE = 0x60
DEBUG_TABLE_OFFSET = 0x5000     # in the handoff span
DEBUG_TABLE_MAGIC = 0x47424544  # 'DEBG'
DEBUG_TABLE_VERSION = 2
DEBUG_TABLE_ENTRY = 0x44
DEBUG_TABLE_HEADER = 0x10
DEBUG_TABLE_COUNT = 1
# Mach-O header VAs, in the order the two walks read them.
DEBUG_TABLE_IMAGES = (0x10, 0x20)   # SPTM, TXM

# +0x30/+0x38: TXM thread-stack VA array and count; +0x40/+0x48:
# monitor CPU-stack VA window. The identical predicates at ...b8b78f0,
# ...ba8a790 and ...ba96a14 validate stack VAs against either range.
# They do not describe physical memory ownership. TXM initialization at
# ...befd3d4..befd578 translates six array entries, which disproved the earlier
# two-physical-boundaries interpretation. See MMU-PROGRESS-20260918.md.
HANDOFF_TXM_STACKS = 0x30
HANDOFF_TXM_STACK_COUNT = 0x38
HANDOFF_CPU_STACK_LOW = 0x40
HANDOFF_CPU_STACK_HIGH = 0x48
TXM_STACK_ARRAY_OFFSET = 0x6000    # in the handoff span
# The array entries each name a 16K stack page.
MONITOR_STACK_GRAIN = 1 << 14
# compat/txm.h TXM_ASPACE_PAGES: contiguous 16 KiB pages of 256-byte TXM
# address-space objects (512). UAT follows the whole arena.
TXM_ASPACE_PAGES = 8
# -DSNAP_TXM_ASPACE_WIDE=1 monitors (compat/txm.h A1-A9): 64 pages, 4096
# objects. Run v47 filled all 512 with live processes 15 minutes after login.
TXM_ASPACE_PAGES_NARROW, TXM_ASPACE_PAGES_WIDE = 8, 64
TXM_ASPACE_WIDE_ENV = 'SNAP_TXM_ASPACE_WIDE'


def configure_txm_arena(wide=None):
    """The TXM arena size the monitor was built for: 8 pages, or 64 with
    -DSNAP_TXM_ASPACE_WIDE=1. None reads SNAP_TXM_ASPACE_WIDE (0 or 1, default
    0), the launch parameter cycle.py sets with that define. Call it before
    place() and build(). The wide arena keeps the narrow order -- arena, three
    UAT pages, the ten-page trust window, the panic page, the scratch -- so the
    scratch moves up by the 56 extra pages and the monitor-data span by a whole
    MiB (keeping the AuxKC reservation after it MiB-aligned). Every address is
    derived from these globals; the narrow call restores the default layout
    exactly. A wide monitor refuses the narrow layout (xnuboot_prepare -22)."""
    global TXM_ASPACE_PAGES, SCRATCH_OFFSET, SPTM_DATA_SPAN, SCRATCH_PA
    if wide is None:
        value = os.environ.get(TXM_ASPACE_WIDE_ENV, '0')
        if value not in ('0', '1'):
            raise ValueError(f'{TXM_ASPACE_WIDE_ENV} must be 0 or 1')
        wide = value == '1'
    pages = TXM_ASPACE_PAGES_WIDE if wide else TXM_ASPACE_PAGES_NARROW
    extra = (pages - TXM_ASPACE_PAGES_NARROW) * MONITOR_STACK_GRAIN
    TXM_ASPACE_PAGES = pages
    SCRATCH_OFFSET = SCRATCH_OFFSET_NARROW + extra
    SPTM_DATA_SPAN = SPTM_DATA_SPAN_NARROW + ((extra + (1 << 20) - 1) & ~((1 << 20) - 1))
    SCRATCH_PA = SPTM_DATA_PA + SCRATCH_OFFSET
    return pages

# +0x68: a u32 count, and a zero here is what the boot has been stopping on.
#
# This was an 8-byte "TXM image descriptor" on the strength of one observed read
# of the word at 0x68. It is four bytes, and it is a number rather than a
# pointer. XNU saves it and then, at 0xfffffe000ba66404:
#
#   ldr  w9, [x22, #0xa64]      ; the count, as XNU kept it
#   sub  w11, w9, #0x1          ; n - 1
#   cmp  w11, #0x40 ; b.hs      -> the bulk path
#   lsr  w10, w11, #6
#   and  x12, x10, #0x3fffff8   ; iterations
#   movi v0.2d, #0xffffffffffffffff
#   stp  q0, q0, [x15] ; stp q0, q0, [x15, #0x20]     ; 64 bytes a time, all 1s
#
# `sub w11, w9, #1` on a zero field underflows to 0xffffffff, so `lsr w10, w11,
# #6` is 0x3ffffff and the loop fills about 512 MiB. That is not a guess: the
# fault measured on hardware has exactly that x10, and the fill runs off the top
# of the 384 MiB region at exactly the FAR_EL1 that came back. Every number
# agrees.
#
# The count is a number of bits -- XNU turns it into a bitmap, one bit each,
# which is why the arithmetic is `(n - 1) >> 6` words of 64.
#
# WHAT THE BITMAP IS: the pmap ASID allocator's free-id map. All-ones means all
# free, which is why the fill writes 0xFF. Allocation takes a lock, scans from a
# u16 cursor with rbit/clz for the lowest set bit, clears it and `strh`s a
# 16-bit id into the object, so the id space is 16 bits wide.
#
# WHAT PINS THE SIZE is the free path at 0xfffffe000ba609e0:
#
#   ldr x8, [x8, #0xbb8]        ; the bitmap
#   mov w9, #1 ; lsl x9, x9, x20            ; bit = 1 << id
#   lsr x10, x20, #3 ; and x10, x10, #0x1ff8  ; byte offset, CLAMPED
#   ldr x11, [x8, x10] ; orr x9, x11, x9 ; str x9, [x8, x10]
#
# The clamp caps the byte offset at 0x1ff8, and the access is eight bytes wide,
# so the highest byte this path can touch is 0x2000 -- 8192 bytes, 65536 bits.
# 0x10000 makes the buffer exactly what the kernel's own indexing permits:
# ((0x10000 + 0x3f) >> 3) & 0x1ffffff8 is 0x2000, one 16K page, and the fill
# loop's x10 becomes 0x3ff.
#
# This is not tidiness. At 0x800 the bitmap is 256 bytes, and that clamp still
# permits a write 8 KiB into it. Nothing does today, because allocation is
# bounded by the count so no id above 2047 is handed out and therefore none is
# ever freed -- but the safety rests on the allocator and the free path
# agreeing, and the free path has no bound of its own. 0x10000 removes the
# discrepancy rather than relying on it.
#
# 0x10000 is the value for THIS firmware, not a constant the interface
# mandates: it is what the clamp in this kernelcache permits. A different build
# could clamp differently, and the offset above is where to re-derive it.
#
# A zero here is not "unset". `sub w11, w9, #1` underflows to 0xffffffff, w10
# becomes 0x3ffffff, and the loop fills 536,870,848 bytes -- half a gigabyte,
# off the end of any region we declare. That was the stop this field fixed.
#
# Two things worth knowing before someone re-reads this code. There is exactly
# ONE reader of +0x68 in the whole 120 MB kernelcache, this bitmap, so setting
# it affects nothing else. And the `movk x15, #0xc8a2, lsl #48` on the path
# before the store is NOT part of any of this: it is a compiler-inserted
# pointer-overflow guard that poisons the address so a wrapped store faults
# loudly. It never fired here -- the measured FAR's top bits were 0xfffe, not
# 0xc8a2 -- the loop was simply too long.
#
# The offset-to-offset link (handoff +0x68 becoming [x22 + 0xa64]) is a hardware
# measurement rather than something re-derived from the disassembly here; the
# underflow arithmetic is what confirms it, because no other value of that field
# produces the x10 and FAR that were observed.
HANDOFF_BITMAP_COUNT = 0x68
BITMAP_BITS = 0x10000

# The random seed, and the panic that found it.
#
#   panic: random seed field too short @pexpert/gen/pe_gen.c:165
#
# This is read out of the kernel's own instructions rather than inferred, which
# is why it outranks everything else in this page. At 0xfffffe000c1eddf8:
#
#   adrp x8, 0xfffffe0007ebf000 ; ldr x21, [x8, #0x100]   ; the handoff copy
#   ldr  x22, [x21, #0x178]                               ; length
#   tst  x22, #0xfffffff8 ; b.eq -> panic line 165        ; must be >= 8
#   add  x0, x21, #0x6c ; x1 = "randseed" ; w2 = 8 ; memcmp
#   cbnz w0 -> panic line 169                             ; tag must match
#   subs w8, w22, #0x8                                    ; usable = length - 8
#   add  x9, x21, #0x74                                   ; the bytes themselves
#
# `"randseed"` is at 0xfffffe0007030f70, eight characters with no terminator,
# and the compare is a memcmp of exactly 8. x21 is the copy XNU takes of this
# handoff page, so these are offsets into the page we build.
#
# /chosen/random-seed in the device tree is a different thing and is not what
# this code reads -- do not "fix" this in build_devicetree().
RANDSEED_TAG_OFFSET = 0x6C
RANDSEED_TAG = b'randseed'
RANDSEED_DATA_OFFSET = 0x74
RANDSEED_LENGTH_OFFSET = 0x178
# 256 bytes, and this is a requirement rather than a choice.
#
# It was 64, on the reading that the check above constrains nothing beyond "more
# than 8" -- the consumer at 0xfffffe000c1eddf8 asks for what it wants and takes
# the smaller of that and what is here. That reading is correct about that
# consumer and wrong about the interface, which is the same trap the DEBG table
# set: a second consumer with a different contract.
#
# `prng_random.c:75` requires an exact count, and says so:
#
#   0xfffffe000ba5d9b0  mov  w8, #0x100        ; 256, the expected count
#   0xfffffe000ba5d9b4  stp  x8, x0, [sp]      ; expected, got
#   0xfffffe000ba5d9c0  bl   panic             ; "Expected %u seed bytes from
#                                              ;  bootloader, but got %u."
#
# Exact, not a minimum: 64 panics just as 0 would, and so would 512. A future
# change that shortens this does not degrade, it panics, which is why the test
# asserts the value rather than a bound.
#
# The layout agrees independently. The seed starts at +0x74 and the length field
# is at +0x178; 0x74 + 0x100 is 0x174, which lands immediately before it. The
# structure only fits at 256, and the length we publish is 8 + 256 = 0x108.
RANDSEED_BYTES = 256


def random_seed(count=RANDSEED_BYTES):
    """The seed bytes, random by default and reproducible on request.

    Both modes exist because the two things we want here are in tension. A boot
    seed that is the same every run is a lie about what the kernel is being
    handed, and the whole point of this project is that XNU is treated as if it
    were running on real hardware -- so the default comes from the system CSPRNG.

    But a run that fails is evidence, and evidence that cannot be replayed is
    much weaker. Anything downstream of the seed -- an address the kernel derives
    from it, a hash it keys, a slide -- differs every boot, so "it panicked once"
    and "it panics every time" become impossible to tell apart. SNAP_SEED makes
    the bytes a pure function of a string, so a failing run can be repeated
    exactly by quoting the value from its own transcript.

    SHAKE-256 rather than a raw hash so the length is ours to choose, and so a
    short human-typed SNAP_SEED still fills the whole field."""
    label = os.environ.get('SNAP_SEED')
    if label is None:
        return secrets.token_bytes(count)
    return hashlib.shake_256(b'snapintosh-randseed\0' + label.encode()).digest(count)


def handoff_fields():
    """Every byte range this loader writes into the SPTM handoff page.

    Two independent derivations have been laid over the same page at different
    times and there is no schema anywhere to catch them colliding. This is that
    schema, to the extent we have one, and check_handoff_overlap() reads it."""
    table = HANDOFF_TABLE_OFFSET
    fields = [
        ('magic',            0x00, 8, 'measured'),
        ('vspace base',      VSPACE_BASE_OFFSET, 8, 'measured'),
        ('vspace top',       VSPACE_TOP_OFFSET, 8, 'measured'),
        ('avail_start',      SPTM_AVAIL_START, 8, 'measured'),
        ('TXM stack array', HANDOFF_TXM_STACKS, 8, 'measured'),
        ('TXM stack count',     HANDOFF_TXM_STACK_COUNT, 4, 'measured'),
        ('CPU stacks low',       HANDOFF_CPU_STACK_LOW, 8, 'measured'),
        ('CPU stacks high',      HANDOFF_CPU_STACK_HIGH, 8, 'measured'),
        ('debug table ptr',  HANDOFF_DEBUG_TABLE, 8, 'measured'),
        ('bitmap count',     HANDOFF_BITMAP_COUNT, 4, 'measured'),
        ('randseed tag',     RANDSEED_TAG_OFFSET, len(RANDSEED_TAG), 'measured'),
        ('randseed bytes',   RANDSEED_DATA_OFFSET, RANDSEED_BYTES, 'measured'),
        ('randseed length',  RANDSEED_LENGTH_OFFSET, 8, 'measured'),
        ('panic flag ptr', PANIC_HANDOFF_OFFSET, 8, 'measured'),
        ('table version',    table, 4, 'measured'),
        ('table regions',    table + HANDOFF_REGIONS, 8, 'measured'),
        ('table region map', table + HANDOFF_REGION_TABLE, 8, 'measured'),
        ('framemap low',     table + FRAMEMAP_LOW, 8, 'measured'),
        ('framemap high',    table + FRAMEMAP_HIGH, 8, 'measured'),
        ('framemap base',    table + FRAMEMAP_BASE, 8, 'measured'),
        ('table pagetable',  table + HANDOFF_PAGETABLE, 8, 'measured'),
        ('frame type info',  table + HANDOFF_FRAME_TYPES, 8, 'measured'),
        ('monitor flags ptr', 0x320, 8, 'measured'),
        ('sptm flags',       SPTM_FLAGS_OFFSET, 8, 'measured'),
    ]
    if GUEST_PROFILE.boot_framebuffer_aux or GUEST_PROFILE.aux_collection_linked:
        fields.extend((('auxkc base', 0x2d8, 8, 'measured'),
                       ('auxkc header', 0x2e0, 8, 'measured'),
                       ('auxkc end', 0x2e8, 8, 'measured')))
    return fields


def check_handoff_overlap():
    """Fields that write over each other, worst evidence named first.

    Not an exception. A collision here is a fact about two readings of the same
    structure, and the run that happens anyway is what tells us which reading
    was right -- so this reports and continues rather than refusing to build.
    What it must not do is stay quiet, because then a boot that advances looks
    like proof that both fields were correct."""
    fields = sorted(handoff_fields(), key=lambda f: f[1])
    clashes = []
    for i, (a_name, a_off, a_len, a_why) in enumerate(fields):
        for b_name, b_off, b_len, b_why in fields[i + 1:]:
            if b_off >= a_off + a_len:
                break
            clashes.append((a_name, a_off, a_len, a_why,
                            b_name, b_off, b_len, b_why))
    return clashes


def report_handoff_overlap():
    """Print the collisions, if any, in a form nobody can skim past."""
    clashes = check_handoff_overlap()
    for a_name, a_off, a_len, a_why, b_name, b_off, b_len, b_why in clashes:
        print(f'\n!! handoff fields overlap: {a_name} (+{a_off:#x}, {a_len} bytes, '
              f'{a_why}) and {b_name} (+{b_off:#x}, {b_len} bytes, {b_why})')
        print('   Both cannot be right. "measured" was read out of the kernel\'s '
              'own instructions;')
        print('   "derived" was reasoned out from behaviour, which is the weaker '
              'of the two.')
        print('   build() writes the randseed fields last, so where they overlap '
              'they win and the')
        print('   other field is left damaged. A run that advances is NOT '
              'evidence that the')
        print('   overlapping field was correct.\n')
    return clashes


def load_monitor_images(tables, chunks):
    """Place the real SPTM and TXM at their linked addresses.

    Returns [(name, header_va, pa, span)] in handoff order."""
    out = []
    for n, name in enumerate(MONITOR_IMAGES):
        path = DEFAULT_KERNELCACHE.parent / name
        if not path.exists():
            continue
        data = path.read_bytes()
        image = kc_load.Image(data)
        segments = [s for s in image.segments if s[2]]
        lo = min(s[1] for s in segments)
        hi = max(s[1] + s[2] for s in segments)
        pa = MONITOR_PA + n * MONITOR_STRIDE
        span = (hi - lo + (1 << GRANULE) - 1) & ~((1 << GRANULE) - 1)
        if span > MONITOR_STRIDE:
            raise SystemExit(f'{name} is {span:#x}, more than the stride')
        tables.map(lo, pa, span)
        for _, vmaddr, _, fileoff, filesize in segments:
            if filesize:
                chunks[pa + (vmaddr - lo)] = data[fileoff:fileoff + filesize]
        out.append((name, lo, pa, span))
    return out

# Every segment, __LINKEDIT included.
#
# It was left out at first on the reasoning that symbol and fixup data is not
# dereferenced at runtime. XNU disagreed: the self-location routine faulted on
# 0xfffffe000e354004, a translation fault near the top of __LINKEDIT, 22
# instructions into the boot stub. The whole file is 115 MiB and uploads in
# about 45 seconds, so mapping all of it costs less than being clever.
WANTED_SEGMENTS = None


def index(level, va):
    """Table index for a 16K granule: 11 bits per level, level 3 at bit 14."""
    shift = GRANULE + (3 - level) * (GRANULE - 3)
    return (va >> shift) & ((1 << (GRANULE - 3)) - 1)


def start_level():
    va_bits = 64 - T1SZ
    bits = GRANULE - 3
    levels = (va_bits - GRANULE + bits - 1) // bits
    return 4 - levels


class Tables:
    """16K guest page tables, built in the target's physical address space."""

    def __init__(self, base):
        self.base = base
        self.next = base
        self.pages = {}                       # pa -> bytearray(16384)
        self.ranges = []                      # (va, size, what) actually mapped
        self.root = self.alloc()

    def alloc(self):
        pa = self.next
        self.next += 1 << GRANULE
        self.pages[pa] = bytearray(1 << GRANULE)
        return pa

    def read(self, pa, slot):
        return struct.unpack_from('<Q', self.pages[pa], slot * 8)[0]

    def write(self, pa, slot, value):
        struct.pack_into('<Q', self.pages[pa], slot * 8, value)

    def map(self, va, pa, size, attrs=LEAF):
        """Map [va, va+size) with 16K pages. The regime's offset space is what
        the tables index, so the caller's VA has its top bits stripped here.

        Masking rather than subtracting KERNEL_BASE. For an address in the upper
        regime the two are identical -- KERNEL_BASE is exactly the top of the
        complement space -- but the kernel also walks this table at addresses
        numerically equal to physical ones, down at level-1 entry 0, and
        subtracting would make those negative and reject them. The table indexes
        an offset space; what the caller calls the address is not its business.
        """
        offset = va & ((1 << (64 - T1SZ)) - 1)
        if (va | pa | size) & ((1 << GRANULE) - 1):
            raise ValueError(f'{va:#x} -> {pa:#x} +{size:#x} is not 16K aligned')
        self.ranges.append((va, size, 'mapped'))
        for step in range(0, size, 1 << GRANULE):
            self._put(offset + step, pa + step, attrs)

    def reserve(self, va, size):
        """Create the table levels over [va, va+size) without mapping anything.

        XNU walks ranges whose tables it expects to already exist and populates
        the leaves itself. What it needs is a hierarchy to descend, not memory:
        0xfffffe000ba7a8a0 reads an L1 descriptor, resolves it with phystokv,
        reads the L2 descriptor under it, and hands the L3 table's address to
        0xfffffe000ba6d41c, which registers that page in the pmap's descriptor
        array. No leaf is ever read.

        So the leaves are left zero, which is also what they would be on real
        hardware before XNU maps them -- and it is the difference between two
        table pages and the whole range's worth of backing."""
        offset = va & ((1 << (64 - T1SZ)) - 1)
        if (va | size) & ((1 << GRANULE) - 1):
            raise ValueError(f'{va:#x} +{size:#x} is not 16K aligned')
        self.ranges.append((va, size, 'tables reserved'))
        leaf_span = 1 << (GRANULE + (GRANULE - 3))      # one L3 table's reach
        for step in range(0, size, leaf_span):
            self._descend(offset + step)

    def _descend(self, offset):
        """Walk to the level-3 table for `offset`, creating levels as needed."""
        table = self.root
        for level in range(start_level(), 3):
            slot = index(level, offset)
            entry = self.read(table, slot)
            if entry & PT_VALID:
                if not entry & PT_TABLE:
                    raise ValueError(f'offset {offset:#x}: a block is already here')
                table = entry & 0x0000FFFFFFFFC000
            else:
                fresh = self.alloc()
                self.write(table, slot, fresh | PT_VALID | PT_TABLE)
                table = fresh
        return table

    def _put(self, offset, pa, attrs):
        self.write(self._descend(offset), index(3, offset), pa | attrs)

    def walk(self, va):
        """Resolve a VA the way the hardware would. None if unmapped."""
        offset = (va - KERNEL_BASE) & ((1 << (64 - T1SZ)) - 1)
        table = self.root
        for level in range(start_level(), 4):
            entry = self.read(table, index(level, offset))
            if not entry & PT_VALID:
                return None
            if level == 3:
                if not entry & PT_TABLE:
                    return None
                return (entry & 0x0000FFFFFFFFC000) | (offset & ((1 << GRANULE) - 1))
            if not entry & PT_TABLE:
                size = 1 << (GRANULE + (3 - level) * (GRANULE - 3))
                return (entry & ~(size - 1) & 0x0000FFFFFFFFC000) | (offset & (size - 1))
            table = entry & 0x0000FFFFFFFFC000
        return None

    def chunks(self):
        return sorted(self.pages.items())

    def validate_allocator_baseline(self, low, high, aperture_va, aperture_pa):
        """Zero reference counts are valid only before counted aliases exist.

        The privileged physical aperture is deliberately uncounted. Reject a
        changed loader recipe that pre-maps allocator frames elsewhere; it
        needs explicit initial reference seeding, not a guessed zero baseline.
        Bootstrap table pages themselves must also remain outside the arena.
        """
        mask = (1 << (64 - T1SZ)) - 1
        if low >= high or (low | high) & 0x3fff:
            raise ValueError('invalid allocator reference baseline range')
        if any(low <= pa < high for pa in self.pages):
            raise ValueError('bootstrap table overlaps counted allocator arena')

        def visit(pa, level, prefix, path):
            if pa in path or pa not in self.pages:
                raise ValueError('invalid bootstrap reference walk')
            for slot, (entry,) in enumerate(struct.iter_unpack('<Q', self.pages[pa])):
                if not entry:
                    continue
                if entry & 3 != 3:
                    raise ValueError('unsupported bootstrap reference descriptor')
                off = prefix | (slot << (14 + (3 - level) * 11))
                target = entry & 0x0000ffffffffc000
                if level < 3:
                    visit(target, level + 1, off, path + (pa,))
                elif low <= target < high:
                    expected = (aperture_va + target - aperture_pa) & mask
                    if off != expected:
                        raise ValueError(f'counted allocator alias already exists at {off:#x}')

        visit(self.root, 1, 0, ())

    @property
    def size(self):
        return self.next - self.base


# Watching the handoff unmaps it at stage 2 so every field access faults with
# its own offset -- which is how +0x60/+0x68 was identified as the device tree
# rather than guessed from a boot_args header. It is off by default now that the
# layout is known: XNU memcpys the whole structure, and 60 events of memcpy
# crowd out everything that follows. SNAP_WATCH=1 turns it back on.
WATCH_OFF = True
GENTER = 0x00201420
ALT_CALL = 0xD4E00000
PARAMS_PA = HANDOFF_PA + 0xc000
DEVICETREE_PA = HANDOFF_PA + 0x10000
HANDOFF_SPAN = 0x80000          # handoff pages, the zero region, and the tree
XNU_VBAR = GUEST_PROFILE.vbar


def monitor_pages(image, data):
    """The 4K pages holding monitor calls, as physical addresses.

    Computed rather than quoted, so a different kernelcache does not silently
    keep the old answer. tools/kc-analyze.py prints the same set."""
    if len(data) != len(image.data):
        raise ValueError('monitor-call scan does not cover the selected kernel image')
    pages = set()
    for name, vmaddr, _, fileoff, filesize in image.segments:
        if 'TEXT' not in name or filesize == 0:
            continue
        body = data[fileoff:fileoff + filesize]
        for i in range(0, len(body) - 3, 4):
            if int.from_bytes(body[i:i + 4], 'little') in (GENTER, ALT_CALL):
                pages.add((vmaddr + i) & ~0xFFF)
    if not pages:
        raise ValueError('selected kernel has no intercepted monitor-call pages')
    return sorted(IMAGE_PA + (va - image.vmin) for va in pages)


# `struct params` in probes/xnuboot.c, as a word count. Kept the same on both
# sides by a _Static_assert there and a check in params_blob() here.
PARAMS_WORDS = 1154
# q1n1's adoption record for an Adreno profile (probes/adreno.py). run.py sets
# it from SNAP_ADRENO_ADOPT after validating it against the live bootinfo; an
# offline build uses adreno.fixture_record().
ADRENO_RECORD = None
# tools/early_stop.Settings from SNAP_EARLY_STOP*, or None (off). run.py sets
# it before build(); a guest trigger advertises ADRENO_GUEST_STOP on the GPU node.
EARLY_STOP = None
# The QCC2072 Wi-Fi admission (probes/qcc2072wifi.Grant), or None (off). run.py
# sets it from SNAP_QCC2072_WIFI after the live admission; an offline build uses
# qcc2072wifi.fixture_spec(). Pair it with a -DSNAP_QCC2072_WIFI=1 monitor.
QCC2072_WIFI = None
# --present-beam's read-only DPU INTF_5 page (probes/displaytiming.SPEC), or None (off). run.py sets it from
# SNAP_DISPLAY_TIMING=1; installed_fresh sets it for the offline image. Pair it with a -DSNAP_DISPLAY_TIMING=1 monitor.
DISPLAY_TIMING = None


def const_region_contract(image, image_pa):
    """The contiguous immutable KC prefix, excluding disposable LINKEDIT.

    The selected fileset puts constants and executable text before writable
    PRELINK_INFO/DATA. Derive the prefix from Mach-O protections, not a broad
    image envelope that also blesses mutable data as const memory.
    """
    end=image.vmin
    count=0
    for name,va,size,maxprot,initprot in sorted(image.segment_protections,key=lambda s:s[1]):
        if not size:continue
        if (maxprot|initprot)&2:break
        if va!=end or (va|size)&0x3fff or initprot not in (1,5) or maxprot!=initprot:
            raise ValueError('noncontiguous or unsupported kernel const prefix')
        if WANTED_SEGMENTS and name not in WANTED_SEGMENTS:
            raise ValueError('kernel const prefix omitted by segment selection')
        end=va+size;count+=1
    if not count or end==image.vmax or image_pa&0x3fff:
        raise ValueError('kernel const prefix requires an aligned, bounded image')
    return image_pa,image_pa+end-image.vmin


def slide_contract(image, tables, alloc_low):
    """Resolve the audited boot-only segment allowlist and reserve empty VAs.

    The destination is below the early heap and inside the static VA map.
    Nothing is mapped there until a validated SLIDE_REGION call arrives.
    """
    page = 1 << GRANULE
    end = VSPACE_TOP + 1
    begin = end - 0x4000000
    if not (VSPACE_BASE <= begin < end <= VSPACE_TOP + 1 and begin % page == 0):
        raise ValueError('SLIDE_REGION destination is outside the static VA map')
    specs = GUEST_PROFILE.slide_segments
    if not 1 <= len(specs) <= 8:
        raise ValueError('SLIDE_REGION requires 1..8 audited segment inputs')
    sources = []
    for scope, name in specs:
        source = image
        if scope != 'fileset':
            matches = [off for ident, _, off in image.kexts if ident == scope]
            if len(matches) != 1:
                raise ValueError(f'SLIDE_REGION fileset entry {scope!r} is missing or ambiguous')
            source = kc_load.Image(image.data[matches[0]:])
        matches = [s for s in source.segments if s[0] == name]
        if len(matches) != 1:
            raise ValueError(f'SLIDE_REGION segment {scope}:{name} is missing or ambiguous')
        _, va, span, _, _ = matches[0]
        pa = IMAGE_PA + va - image.vmin
        if (not span or (va | span | pa) % page or
                not IMAGE_PA <= pa < pa + span <= alloc_low or
                va < end and begin < va + span):
            raise ValueError(f'SLIDE_REGION segment {scope}:{name} has invalid geometry')
        if any(va < exec_va + exec_span and exec_va < va + span
               for _, exec_va, exec_span, _, _ in image.executable_segments):
            raise ValueError('disposable boot storage overlaps executable image content')
        for other_va, other_pa, pages in sources:
            if va < other_va + pages * page and other_va < va + span:
                raise ValueError('SLIDE_REGION source segments overlap')
        if any(tables.walk(va + n) != pa + n for n in range(0, span, page)):
            raise ValueError(f'SLIDE_REGION segment {scope}:{name} is not mapped to its image bytes')
        sources.append((va, pa, span // page))
    if any(tables.walk(va) is not None for va in range(begin, end, page)):
        raise ValueError('SLIDE_REGION destination overlaps an existing mapping')
    tables.reserve(begin, end - begin)
    return [TABLE_PA, TABLE_PA + TABLE_SPAN, HANDOFF_PA + REGIONS_OFFSET,
            begin, end, len(sources),
            *(word for region in sources for word in region),
            *([0] * (3 * (8 - len(sources))))]


def params_blob(built):
    """The block probes/xnuboot.c reads. Field order is the struct's."""
    stubs = built['stub_pa']
    if len(stubs) > 8:
        raise SystemExit(f'{len(stubs)} monitor pages; the probe holds 8')
    from nativecalls import count_word
    stub_count = count_word(stubs, built.get('native_calls', False),
                            built.get('sptm_hvc_calls', False))
    words = [built['tables'].root, built['tcr'], built['mair'], built['entry'],
             built['x1'], built['x2'], built['vbar_pa'], stub_count]
    words += stubs + [0] * (8 - len(stubs))
    words.append(XNU_VBAR if built['vbar_pa'] else 0)
    # The handoff pages, watched so XNU's reads of them are reported by offset.
    words += [HANDOFF_PA, built.get('watch_count', 0), built['x1'] & ~0xFFF]
    words.append(built['vncr_va'])
    words.append(1 if built.get('permissive') else 0)
    words.append(BOOT_MPIDR)
    words.append(1 if built.get('let_panic') else 0)
    words.append(built.get('watchdog', 2))
    # The low regime. The kernel walks and then loads addresses numerically
    # equal to physical ones, so the hardware needs a TTBR0 to reach them; this
    # is the range the probe shadows there. Same guest tables, shadowed twice.
    words += [BOOTSTRAP_PA, BOOTSTRAP_SPAN, SCRATCH_PA,
              1 if built.get('skip_undef') else 0]
    # The scratch again, as XNU sees it. SPTM_FUNCTIONID_OUTPUT_AREA (endpoint
    # 0x32) is asked for this and the answer is dereferenced at EL1, so the
    # probe needs the virtual view as well as the physical one it writes through.
    words.append(built['scratch_va'])
    # The physical memory we declared: what MAP_PAGE compares a PTE against,
    # and the first range of the stage-2 map -- the probe maps exactly this,
    # the panel below, and its own work area, and nothing else.
    words += [PHYS_BASE, BOOTSTRAP_PA + BOOTSTRAP_SPAN]
    # The panel, when it is handed over: the one range outside that memory the
    # guest may touch. (0, 0) is no panel, and the probe maps none.
    panel = panel_range()
    words += list(panel) if panel else [0, 0]
    # Device register windows the guest's own device tree names. On the machine
    # that tree describes these are real registers; here nothing is there. They
    # are listed so MAP_PAGE can tell a device the kernel is right to ask for
    # from an address we cannot account for, install the first, and let the
    # access trap at stage 2 where a model can answer it.
    windows = built.get('uart_windows', [])
    if len(windows) > 4:
        raise ValueError(f'{len(windows)} console windows exceed the probe ABI limit of 4')
    words.append(len(windows))
    words += [w[0] for w in windows] + [0] * (4 - len(windows))
    words += [w[1] for w in windows] + [0] * (4 - len(windows))
    # RETYPE updates the same frame map XNU reads, and can clear only pages
    # from its allocator arena, never the loader/monitor backing or panel.
    words += [built['frame_map_pa'], built['frame_low'], built['frame_high'],
              built['alloc_low'], built['alloc_high']]
    words.append(APERTURE_VA)  # MAP_PAGE output PTE pointer, not a physical PA
    watch_va = built.get('write_watch_va', 0)
    watch_pa = built['tables'].walk(watch_va) if watch_va else 0
    if watch_va and (watch_pa is None or not PHYS_BASE <= watch_pa < BOOTSTRAP_PA + BOOTSTRAP_SPAN):
        raise ValueError('write watch must resolve to owned guest memory')
    words.append(watch_pa & ~0xfff)
    words += [built['txm_stacks_pa'], built['txm_stack_count'], built['txm_log_pa']]
    words += [built['txm_rw_pa'], built['txm_ro_pa'], built['txm_aspace_pa']]
    words += [built['uat_pa'], *built['uat_geometry']]
    words += built['slide_config']
    words += device_model_words(built.get('device_models', ()),
        excluded=[(PHYS_BASE, BOOTSTRAP_PA + BOOTSTRAP_SPAN - PHYS_BASE),
                  *((panel,) if panel else ()), *windows])
    words += [built['host_counter_hz'], built['guest_counter_hz']]
    words += built['const_region']
    words += built['trust_cache']
    import seppreload
    payload_base=PHYS_BASE+max(off+span for _,off,span in reservations())
    words += seppreload.dma_contract(built,GUEST_PROFILE.sep_preload,
                                     (payload_base+0x3fff)&~0x3fff)
    # The linked AuxKC's VA and PA extents, observed (never gated) by the
    # monitor's MAP_PAGE/UPDATE/RETYPE counters. Zero when there is none.
    aux_va, aux_pa = built.get('auxkc_va_range'), built.get('auxkc_range')
    words += ([aux_va[0], aux_va[1], aux_pa[0], aux_pa[0] + aux_pa[1]]
              if aux_va else [0, 0, 0, 0])
    # Stage 4: struct adreno_params (compat/adreno.h). Zero without a profile.
    import adreno
    pool = gpu_pool_reservation()
    words += adreno.params_words(adreno_spec(), ADRENO_RECORD, pool_pa=pool[0] if pool else None)
    words += built.get('txm_native', (0, 0, 0, 0))
    # struct early_stop_params (compat/early-stop.h): run.py fills it from
    # SNAP_EARLY_STOP*; all zero leaves every early-stop path off.
    early_stop = list(built.get('early_stop', (0,) * 6))
    if len(early_stop) != 6:
        raise ValueError('early_stop params are six words')
    words += early_stop
    # struct i2c_input_params (compat/i2c-input.h), appended only for a profile
    # with i2c_input, whose monitor is built with -DSNAP_I2C_INPUT=1.
    expected = PARAMS_WORDS
    if GUEST_PROFILE.i2c_input is not None:
        import i2cinput
        words += i2cinput.params_words(GUEST_PROFILE.i2c_input)
        expected += i2cinput.PARAMS_WORDS
    # struct qcc2072_wifi_params (compat/qcc2072-wifi.h), appended last and
    # only with an admission, for a monitor built with -DSNAP_QCC2072_WIFI=1.
    if QCC2072_WIFI is not None:
        import qcc2072wifi
        words += qcc2072wifi.params_words(QCC2072_WIFI)
        expected += qcc2072wifi.PARAMS_WORDS
    # struct display_timing_params (compat/display-timing.h), appended last and only for --present-beam, for a
    # monitor built with -DSNAP_DISPLAY_TIMING=1.
    if DISPLAY_TIMING is not None:
        import displaytiming
        words += displaytiming.params_words(DISPLAY_TIMING)
        expected += displaytiming.PARAMS_WORDS
    # The other half of xnuboot.c's _Static_assert. A field added on one side
    # and not the other shifts every field after it, and the guest is then
    # handed a plausible address out of the wrong one -- which does not fault.
    if len(words) != expected:
        raise SystemExit(f'params blob is {len(words)} words, but struct params '
                         f'in probes/xnuboot.c is {expected}')
    return struct.pack(f'<{len(words)}Q', *words)


def build_handoff(pa):
    """The two structures the entry stub is handed, as one blob at `pa`.

    x2 -> pa            SPTM handoff: magic, then a versioned table at +0x1a0.
    x1 -> pa + 0x1000   its (u64, u32) at +0x60/+0x68 is a *virtual* region.

    The region was a physical one at first, on the reading that a base and a
    length published into globals had to be memory. XNU disagreed at
    0xfffffe000c1ecca4: it range-checks a pointer against exactly those globals
    and then dereferences it, faulting on 0xd9e00000 -- the physical base
    itself. So the pair is a virtual window, and it is given a mapped page of
    zeros: the first word being zero is a case XNU already branches on, which
    makes "nothing here" a path it knows rather than a fault.
    """
    # 0x1000, not 0x400.
    #
    # XNU copies [handoff, handoff+0x358) at 0xfffffe000c2447f0. The native
    # copied buffer begins with HANDOFF_MAGIC; it does not begin at the
    # versioned subtable at +0x1a0. Keep a fully initialized page because
    # the handoff also contains pointer targets outside that copied prefix.
    # In particular +0x320 is relative to the handoff base, as are the AuxKC
    # fields at +0x2d8..0x2e8. See the measured copy explanation below.
    sptm = bytearray(0x1000)
    struct.pack_into('<Q', sptm, 0, HANDOFF_MAGIC)
    struct.pack_into('<I', sptm, HANDOFF_TABLE_OFFSET, HANDOFF_VERSION)
    struct.pack_into('<Q', sptm, SPTM_FLAGS_OFFSET, SPTM_FLAGS)

    other = bytearray(0x1000)
    regions = bytearray(0x1000)
    return ({pa: sptm, pa + 0x1000: other, pa + REGIONS_OFFSET: regions,
             pa + 0x4000: bytearray(0x4000)}, pa, pa + 0x1000)


# `boot_args`, from XNU's pexpert/arm64. The offsets were not taken on faith:
# the handoff watchpoint showed exactly three fields being read for meaning
# rather than copied -- +0x60 as a pointer, +0x68 as a length, and +0x6c as the
# first argument to a function at 0xfffffe000c1ed40c that skips spaces and tabs
# and walks a string. That is PE_parse_boot_argn, and +0x6c is CommandLine. A
# device tree pointer at +0x60 with the command line at +0x6c pins every field
# before it, because the struct is fixed:
#
#   0x00 Revision u16      0x02 Version u16
#   0x08 virtBase          0x10 physBase       0x18 memSize
#   0x20 topOfKernelData   0x28 Video[6]       0x58 machineType u32
#   0x60 deviceTreeP       0x68 deviceTreeLength u32
#   0x6c CommandLine[1024] 0x470 bootFlags     0x478 memSizeActual
#
# The command line is 1024 bytes, not the 256 of the embedded builds, and the
# struct is 1152. That is not a guess either: XNU copies exactly 0x480 bytes out
# of this pointer at 0xfffffe000c2447cc, and 0x480 - 0x6c - 16 is 1024 to the
# byte.
BOOT_ARGS_SIZE = 0x480
BOOT_LINE_LENGTH = 1024
BOOT_ARGS_REVISION = 1
BOOT_ARGS_VERSION = 2

# The command line is the one place a stock kernel invites us to change its mind
# without touching a byte of it. `serial=3` selects serial output with bit 0;
# run.py clears that bit for the native panel console (the default when a
# framebuffer is available, or explicit --console panel). The UART model captures the
# kernel's serial writes. This does not override the separate kprintf gates.
#
# `cluster_power=0` is read at 0xfffffe000ba88f68, right where the topology is
# being set up, and turning it off keeps XNU from driving PMGR cluster power
# states that have no hardware behind them here.
BOOT_CMDLINE = '-v debug=0x8 serial=3 cluster_power=0 wdt=-1'


def boot_args(virt_base, phys_base, mem_size, top_of_kernel_data,
              devicetree_va, dt_len, cmdline=None):
    b = bytearray(BOOT_ARGS_SIZE)
    struct.pack_into('<HH', b, 0, BOOT_ARGS_REVISION, BOOT_ARGS_VERSION)
    struct.pack_into('<QQQQ', b, 8, virt_base, phys_base, mem_size,
                     top_of_kernel_data)
    # Boot_Video: v_baseAddr, v_display, v_rowBytes, v_width, v_height, v_depth.
    # A physical address -- XNU maps it itself -- so the aperture has to cover it
    # too, which is why build() publishes the panel as a second region.
    if FRAMEBUFFER:
        base, width, height, stride, depth = FRAMEBUFFER
        # v_display 0, not 1: text mode. PE_create_console passes
        # (v_display == 0) ? kPETextMode : kPEGraphicsMode, and only the text
        # arm paints glyphs with the CPU. Graphics mode paints nothing at
        # acquire and arms a progress spinner on a timer instead, which would
        # put the first pixel behind interrupt delivery and a thread switch --
        # the work this milestone deliberately cut.
        struct.pack_into('<6Q', b, 0x28, base, VIDEO_DISPLAY_MODE, stride,
                         width, height, depth)
    struct.pack_into('<I', b, 0x58, 0)                  # machineType
    struct.pack_into('<Q', b, 0x60, devicetree_va)
    struct.pack_into('<I', b, 0x68, dt_len)
    cmdline = BOOT_CMDLINE if cmdline is None else cmdline
    line = cmdline.encode()
    if len(line) >= BOOT_LINE_LENGTH or b'\0' in line:
        raise ValueError('boot command line is too long or contains a NUL')
    b[0x6c:0x6c + len(line)] = line
    struct.pack_into('<Q', b, 0x478, mem_size)          # memSizeActual
    return b


def uniform_cpu_clusters(dt):
    """Relabel cluster 1 as type E after every CPU-topology model has bound.

    XNU's Edge scheduler starts every thread group preferring pset0, and its
    default E->P edge allows neither migration nor steal; CLPC normally
    changes that. This profile has no CLPC, so cpu4/cpu5 would never run a
    thread. Only `cluster-type` changes: reg, cluster-id, cpu-id and MPIDR
    routing are untouched, and cluster 1 remains its own pset."""
    prefix = '/device-tree/cpus/'
    nodes = {p for p in dt.nodes if p.startswith(prefix) and p.count('/') == 3}
    if nodes != {prefix + f'cpu{i}' for i in range(6)}:
        raise ValueError('uniform CPU clusters require the audited six-node topology')
    for cpu in range(6):
        prop = dt.nodes[prefix + f'cpu{cpu}'].get('cluster-type')
        if prop is None or prop.placeholder or bytes(prop.value) != (b'P\0' if cpu >= 4 else b'E\0'):
            raise ValueError(f'cpu{cpu}: cluster-type differs from the shipped E/P topology')
    for cpu in (4, 5):
        dt.set(prefix + f'cpu{cpu}', 'cluster-type', b'E\0')


def build_devicetree(path=None, *, include_deferred=False):
    """The stock j700 tree with the placeholders iBoot would have filled.

    XNU reads the running CPU's `timebase-frequency` for counter conversion.
    Setting only the root clock leaves its 24 MHz fallback active."""
    if type(TIMEBASE_HZ) is not int or not 0 < TIMEBASE_HZ <= 0xffffffff:
        raise ValueError('counter timebase must be a nonzero u32 frequency')
    dt = DeviceTree(pathlib.Path(path or DEFAULT_DEVICETREE).read_bytes())
    if GUEST_PROFILE.chip_id_boot is None:
        raise ValueError('guest profile has no audited chip ID boot contract')
    populate_chip_id(dt, GUEST_PROFILE.chip_id_boot)
    populate_board_id(dt, GUEST_PROFILE.chip_id_boot)
    populate_image4_identity(dt, GUEST_PROFILE.chip_id_boot)
    resolved = dt.resolve_placeholders()
    dt.set_u32('/device-tree', 'clock-frequency', TIMEBASE_HZ)

    # Every cpu node ships `state = "waiting"`. iBoot rewrites exactly one of
    # them to "running" before it jumps, and that is how XNU decides which
    # entry in /cpus is the core it is executing on:
    #
    #   ml_parse_cpu_topology() walks /cpus, and the child whose `state` is
    #   "running" becomes topology_info.boot_cpu. With none running that
    #   pointer stays NULL -- and it is dereferenced immediately afterwards,
    #   without a check, because the check is an assert() that RELEASE drops:
    #
    #     0xfffffe000ba88f6c  ldr x8, [x19]        ; topology_info.boot_cpu
    #     0xfffffe000ba88f70  ldr w9, [x8]         ; ESR 0x96000004, FAR 0
    #
    # which is the null dereference this was stopping at. "running" and
    # "waiting" are both eight bytes, so it patches in place.
    dt.set(f'/device-tree/cpus/{BOOT_CPU}', 'state', b'running\0')
    dt.put(f'/device-tree/cpus/{BOOT_CPU}', 'timebase-frequency',
           struct.pack('<I', TIMEBASE_HZ))
    if GUEST_PROFILE.counter_clock is None:
        raise ValueError('guest profile has no audited peripheral counter clock')
    populate_counter_clock(dt, GUEST_PROFILE.counter_clock, TIMEBASE_HZ)

    # /chosen/dram-base and /chosen/dram-size are not in the tree Apple ships at
    # all -- iBoot adds them -- and arm_init will not go a line further without
    # both:
    #
    #   panic: arm_init: Unable to find 'dram-base' entry in the 'chosen' DT
    #          node @arm_init_sptm.c:1120
    #
    # Each is dereferenced as a u64 right after the lookup (0xfffffe000c244c98),
    # so eight bytes, and they describe the memory this kernel is being given:
    # the same span boot_args publishes as physBase/memSize, because two
    # different answers to "where is DRAM" is a bug waiting for a page.
    # The region, not the image: DRAM starts below the kernel, because the
    # handoff and the device tree are down there. boot_args.physBase is the
    # kernel's own base and is higher; that pairing is what a real boot looks
    # like.
    # PROVOKE withholds one loader input on purpose. Every panic XNU prints is
    # a whole working console path -- format, SPTM_FN_SERIAL_PUTC, our handler,
    # the proxy, the panel -- exercised end to end on real hardware, and the
    # cheapest way to prove that path is still intact is to ask the kernel to
    # use it. It is a smoke test, not a workaround, so it names what it skipped.
    if PROVOKE != 'dram':
        dt.put_u64('/device-tree/chosen', 'dram-base', PHYS_BASE)
        dt.put_u64('/device-tree/chosen', 'dram-size', REGION_SPAN)

    if GUEST_PROFILE.nvram_boot is None:
        raise ValueError('guest profile has no audited NVRAM boot contract')
    populate_boot_nvram(dt, GUEST_PROFILE.nvram_boot)

    if GUEST_PROFILE.adreno is not None:
        # Stage 4: the GPU node and its virtual DART, before the DART registry
        # assigns ids (dart-adreno carries its own, 31) and models are bound.
        import adreno
        dt.adreno = adreno.prepare_tree(dt, adreno_spec(),
                                        [(r.base, r.size) for r in owned_ranges()])
        if EARLY_STOP is not None and EARLY_STOP.guest:
            adreno.advertise_early_stop(dt, EARLY_STOP.delay)
        if EARLY_STOP is not None and EARLY_STOP.net:
            adreno.advertise_guest_net(dt)
    if GUEST_PROFILE.i2c_input is not None:
        # The SnapI2CHID node(s) and their arm-io ranges (probes/i2cinput.py).
        import i2cinput
        dt.i2c_input = i2cinput.prepare_tree(dt, GUEST_PROFILE.i2c_input,
                                             [(r.base, r.size) for r in owned_ranges()])
    if QCC2072_WIFI is not None:
        # The SnapintoshQCC2072 node and its arm-io ranges (probes/qcc2072wifi.py).
        import qcc2072wifi
        dt.qcc2072_wifi = qcc2072wifi.prepare_tree(dt, QCC2072_WIFI,
                                                   [(r.base, r.size) for r in owned_ranges()])
    if DISPLAY_TIMING is not None:
        # The beam's two GPU-node properties (probes/displaytiming.py); the GPU node exists by now.
        import displaytiming
        dt.display_timing = displaytiming.advertise(dt, DISPLAY_TIMING, [(r.base, r.size) for r in owned_ranges()])
    if GUEST_PROFILE.dart_boot is None:
        raise ValueError('guest profile has no audited DART boot contract')
    dart_spec = GUEST_PROFILE.dart_boot
    dt.dart_devices = populate_dart_ids(dt, dart_spec,
        lambda path: device_windows(dt, path.rsplit('/', 1)[1], dart_spec.bus))
    dt.dart_apf_slices = (() if PROVOKE == 'dram' else populate_dart_apf_exceptions(
        dt, dart_spec, dt.dart_devices, PHYS_BASE,
        [(r.base, r.size) for r in owned_ranges()]))
    populate_pcie_reset(dt, GUEST_PROFILE.pcie_reset_boot)

    if GUEST_PROFILE.mcc_boot is None:
        raise ValueError('guest profile has no audited MCC boot contract')
    mcc = GUEST_PROFILE.mcc_boot
    bus, name = mcc.node.rsplit('/', 1)
    dt.device_models = mcc_models(dt, mcc, device_windows(dt, name, bus))
    if GUEST_PROFILE.aic_boot is None:
        raise ValueError('guest profile has no audited AIC boot contract')
    aic = GUEST_PROFILE.aic_boot
    bus, name = aic.node.rsplit('/', 1)
    dt.device_models += aic_models(dt, aic, device_windows(dt, name, bus))
    if GUEST_PROFILE.watchdog_boot is None:
        raise ValueError('guest profile has no audited watchdog boot contract')
    wdt = GUEST_PROFILE.watchdog_boot
    bus, name = wdt.node.rsplit('/', 1)
    watchdog = watchdog_models(dt, wdt, device_windows(dt, name, bus), TIMEBASE_HZ)
    dt.device_models += watchdog[:1]
    if GUEST_PROFILE.mcc_ptd_boot is None:
        raise ValueError('guest profile has no audited MCC PTD boot contract')
    ptd = GUEST_PROFILE.mcc_ptd_boot
    bus, name = ptd.node.rsplit('/', 1)
    dt.device_models += mcc_ptd_models(dt, ptd, device_windows(dt, name, bus))
    for gpio in GUEST_PROFILE.gpio_boot:
        bus, name = gpio.node.rsplit('/', 1)
        dt.device_models += gpio_models(dt, gpio, device_windows(dt, name, bus))
    if GUEST_PROFILE.aes_keys_boot is not None:
        aes = GUEST_PROFILE.aes_keys_boot
        bus, name = aes.node.rsplit('/', 1)
        dt.device_models += aes_key_models(dt, aes, device_windows(dt, name, bus))
    for spmi in GUEST_PROFILE.spmi_boot:
        bus, name = spmi.node.rsplit('/', 1)
        dt.device_models += spmi_models(dt, spmi, device_windows(dt, name, bus))
    if GUEST_PROFILE.dock_boot is not None:
        dt.device_models += dock_models(dt, GUEST_PROFILE.dock_boot)
    if GUEST_PROFILE.dock_fifo_boot is not None:
        fifo = GUEST_PROFILE.dock_fifo_boot
        bus, name = fifo.node.rsplit('/', 1)
        dt.device_models += dock_fifo_models(dt, fifo, device_windows(dt, name, bus))
    aic_limit = GUEST_PROFILE.aic_boot.irq_count
    if GUEST_PROFILE.mcc_error_node is not None:
        node = GUEST_PROFILE.mcc_error_node
        bus, name = node.rsplit('/', 1)
        dt.device_models = mcc_error_models(dt, node, device_windows(dt, name, bus), dt.device_models)
        dt.device_models += socni_error_models(dt, node, device_windows(dt, name, bus))
        dt.device_models += platform_error_models(dt, node, device_windows(dt, name, bus))
    if GUEST_PROFILE.aop_timebase_boot is not None:
        timebase = GUEST_PROFILE.aop_timebase_boot
        bus, name = timebase.node.rsplit('/', 1)
        dt.device_models += aop_timebase_models(dt, timebase, device_windows(dt, name, bus), TIMEBASE_HZ)
    dt.device_models += dart_models(dt, dt.dart_devices)
    if GUEST_PROFILE.sep_boot is not None:
        populate_sep_boot(dt,GUEST_PROFILE.sep_boot)
    if GUEST_PROFILE.pmgr_boot is not None:
        pmgr=GUEST_PROFILE.pmgr_boot
        populate_pmgr_boot(dt,pmgr)
        bus,name=pmgr.node.rsplit('/',1)
        dt.device_models += pmgr_power_models(dt,pmgr,device_windows(dt,name,bus))
        dt.device_models = pmp_active_models(dt,dt.device_models)
    if GUEST_PROFILE.soctuner_boot is not None:
        populate_soctuner_boot(dt,GUEST_PROFILE.soctuner_boot)
    if GUEST_PROFILE.coresight_boot:
        dt.device_models += coresight_models(dt,GUEST_PROFILE.coresight_boot)
    if GUEST_PROFILE.qspi_boot is not None:
        qspi = GUEST_PROFILE.qspi_boot
        bus, name = qspi.node.rsplit('/', 1)
        dt.device_models += qspi_models(dt, qspi, device_windows(dt, name, bus))
    if GUEST_PROFILE.dwi_startup is not None:
        dwi = GUEST_PROFILE.dwi_startup
        bus, name = dwi.node.rsplit('/', 1)
        dt.device_models += dwi_models(dt, dwi, device_windows(dt, name, bus))
    if GUEST_PROFILE.i2c_empty is not None:
        i2c = GUEST_PROFILE.i2c_empty
        bus, name = i2c.node.rsplit('/', 1)
        dt.device_models += i2c_empty_models(dt, i2c, device_windows(dt, name, bus))
    # Keep established device indices stable in runtime captures; append the
    # auxiliary watchdog contract after the original registry.
    dt.device_models += watchdog[1:]
    if GUEST_PROFILE.sep_asc is not None:
        sep = GUEST_PROFILE.sep_asc
        bus, name = sep.node.rsplit('/', 1)
        dt.device_models += sep_asc_models(dt, sep, device_windows(dt, name, bus))
    if GUEST_PROFILE.ans_boot is not None:
        # iBoot boots ANS2, quiesces it and publishes pre-loaded/running and the
        # firmware segments on the nub; without them RTBuddy(ANS2) never wakes
        # the IOP (docs/ANS2-FIRMWARE-STATE-20260925.md). Publish the virtual
        # IOP's equivalent, then bind the models to exactly that state.
        ans = GUEST_PROFILE.ans_boot
        reservation = ans_reservation()[0]
        populate_ans_firmware(dt, ans, reservation)
        dt.device_models += ans_models(dt, ans, ans_windows(dt), device_windows(dt, 'sart-ans'),
                                       reservation)
    if any(model.kind in (9, 13, 17, 43, 48, 50) and model.config[2] >= aic_limit for model in dt.device_models):
        raise ValueError('device interrupt exceeds the virtual AIC capacity')
    if any(model.kind==49 and max(model.config[1:3])>=aic_limit for model in dt.device_models):
        raise ValueError('device interrupt exceeds the virtual AIC capacity')
    if any(model.kind==45 and model.config[1] and
           max(model.config[2:4])>=aic_limit for model in dt.device_models):
        raise ValueError('SEP mailbox interrupts exceed the virtual AIC capacity')
    device_model_words(dt.device_models)

    if not isinstance(include_deferred, bool):
        raise ValueError('include_deferred must be boolean')
    # The private SPTM interface retains its empty address-space objects even
    # when the software-display board omits the Apple GPU nub. Derive their
    # geometry from this resolved firmware before changing publication; do
    # not invent a fallback for an unexpectedly missing or malformed node.
    dt.monitor_uat_geometry = private_uat_geometry(dt)
    if GUEST_PROFILE.uniform_cpu_clusters:
        uniform_cpu_clusters(dt)
    if GUEST_PROFILE.sip_lp_sip0 is not None:
        local_boot_policy(dt, GUEST_PROFILE.sip_lp_sip0)
    if GUEST_PROFILE.apfs_without_sep:
        if not GUEST_PROFILE.installed_root:
            raise ValueError('APFS no-SEP setting requires the installed profile')
        filesystems_without_sep(dt)
    dt.deferred_nodes = (() if include_deferred else
                         defer_subtrees(dt, GUEST_PROFILE.deferred_subtrees,
                                        GUEST_PROFILE.deferred_functions))
    # AdrenoDisplay's display-subsystem entry, once disp0 is withdrawn. The
    # include_deferred tree keeps disp0 (the hash reference), so it has no slot.
    if (GUEST_PROFILE.adreno is not None and GUEST_PROFILE.adreno.display_slot
            and not include_deferred):
        import adreno
        dt.display_slot = adreno.display_slot(dt)
    dt.resolved = resolved
    return dt


def filesystems_without_sep(dt):
    """Native apfs_mount_crypto_check reads this presence property via DT_property.

    The matching APFS UUID and failure inventory are in DATA-MOUNT-O5-20260926.md.
    Adding this leaf does not change the chosen identity or signing inputs.
    """
    from appledt import Property
    root, path = '/device-tree', '/device-tree/filesystems'
    if root not in dt.nodes or root not in dt.children:
        raise ValueError('device tree has no root')
    if path in dt.nodes:
        if dt.get(path, 'DoNotUseSEP') is not None:
            raise ValueError('filesystem no-SEP setting already present')
        if dt.get(path, 'name') != b'filesystems\0' or dt.children[root].count(path) != 1:
            raise ValueError('malformed filesystem node')
    else:
        if path in dt.children or path in dt.children[root]:
            raise ValueError('filesystem child conflicts with tree nodes')
        dt.nodes[path] = {'name': Property('name', b'filesystems\0')}
        dt.children[path] = []
        dt.children[root].append(path)
    dt.add(path, 'DoNotUseSEP', b'')


LOCAL_POLICY_NODE = '/device-tree/chosen/asmb'
# bsd/sys/csr.h CSR_VALID_FLAGS: bits 0..12. APPLE_INTERNAL (bit 4) is
# stripped by csr_bootstrap on a non-IUOU device; refusing it keeps the
# published policy equal to the one XNU will actually enforce.
CSR_VALID_FLAGS = (1 << 13) - 1
CSR_ALLOW_APPLE_INTERNAL = 1 << 4


def local_boot_policy(dt, csr_config):
    """Publish csr_config the way iBoot's local boot policy does.

    csr_bootstrap reads /chosen/asmb lp-sip0 with _csr_get_dt_uint64, which
    panics on any size but 8 (pinned kernel strings: "lp-sip0", "unexpected
    size %xu for uint64 property"). The shipped firmware node carries only
    its name and phandle, so this adds a property and never replaces one.
    """
    if type(csr_config) is not int or not 0 < csr_config <= CSR_VALID_FLAGS:
        raise ValueError('lp-sip0 must be a nonzero csr_config within CSR_VALID_FLAGS')
    if csr_config & CSR_ALLOW_APPLE_INTERNAL:
        raise ValueError('lp-sip0 cannot carry CSR_ALLOW_APPLE_INTERNAL on this device')
    if LOCAL_POLICY_NODE not in dt.nodes:
        raise ValueError('firmware tree has no /chosen/asmb local-policy node')
    for prop in ('lp-sip0', 'lp-sip1'):
        if dt.get(LOCAL_POLICY_NODE, prop) is not None:
            raise ValueError(f'firmware tree already sets {prop}')
    dt.add(LOCAL_POLICY_NODE, 'lp-sip0', struct.pack('<Q', csr_config))


# The first physical addresses XNU maps that are not memory: its serial
# console's registers, straight out of the tree we hand it.
#
# This is where the "12 GiB" MAP_PAGEs come from. The story, measured on the
# device (avail_start never moved; virtual_space_start advanced five pages):
#
#   serial init at 0xfffffe000c1f0190 looks /arm-io/dockchannel-uart up,
#   calls ml_io_map (0xfffffe000ba803d0) once per `reg` entry -- at
#   0xfffffe000c1f04cc and 0xfffffe000c1f04e8 -- and keeps the two VAs at
#   0xfffffe000c838020 and 0xfffffe000c832258. ml_io_map this early takes its
#   VA off virtual_space_start (0xfffffe000ba80420..44c) and hands every 16K
#   page to 0xfffffe000ba65810, which is the MAP_PAGE caller: x0 the root, x1
#   the VA, x2 a device PTE whose output address is the `reg` base translated
#   through arm-io's `ranges` (child 0 sits at physical 0x210000000). The
#   first register read, ml_io_read(second window, 4) at 0xfffffe000c1f0b18,
#   is the data abort at 0xfffffed000010000 that ends every run today.
#
# So the addresses are right by the kernel's reckoning: they are where the
# J700's UART lives, and this machine has nothing there. They are not memory
# and must never be in the memory window; they are the IPAs step B's UART
# model answers and step T4's stage-2 map deliberately leaves absent, so an
# access traps to EL2 instead of reaching the Snapdragon's bus.
CONSOLE_NODE = GUEST_PROFILE.console_node


def private_uat_geometry(dt):
    """Read the audited SPTM UAT geometry, with its DT defaults.

    This adapter implements private mode only. A different mode or ABI must
    add its own state constructor rather than reusing these objects.
    """
    if GUEST_PROFILE.uat_node not in dt.nodes:
        raise ValueError('guest UAT node is missing')
    node = dt.nodes[GUEST_PROFILE.uat_node]
    defaults = dt.nodes.get('/device-tree/defaults', {})

    def word(name, fallback):
        prop = node.get(name, defaults.get(name))
        if prop is None:
            return fallback
        if len(prop.value) != 4:
            raise ValueError(f'UAT {name} must be a 32-bit property')
        return int.from_bytes(prop.value, 'little')

    mode = word('agx-address-space-mgmt-mode', 0)
    bits = word('uat-vaddr-size', 40)
    segments = word('uat-segment-limit', 64)
    if mode != 1 or not 40 <= bits <= 48 or not segments:
        raise ValueError('unsupported UAT mode or geometry')
    return mode, bits, segments


def device_windows(dt, node=None, bus='/device-tree/arm-io'):
    """The register windows of `node`, as (physical base, size) pairs.

    Apple's `reg` is (child address, size) pairs in the bus's address space;
    the bus's `ranges` is (child, parent, span) triples. Two 64-bit cells each
    on this tree, which is checked rather than assumed."""
    node = CONSOLE_NODE if node is None else node
    cells = struct.unpack('<I', dt.nodes[bus]['#address-cells'].value)[0]
    if cells != 2 or struct.unpack('<I', dt.nodes[bus]['#size-cells'].value)[0] != 2:
        raise SystemExit(f'{bus} does not use 64-bit address and size cells')
    raw = dt.nodes[bus]['ranges'].value
    ranges = [struct.unpack_from('<QQQ', raw, off) for off in range(0, len(raw), 24)]
    raw = dt.nodes[f'{bus}/{node}']['reg'].value
    # (address, size) pairs of two 64-bit cells each, which the bus's own
    # #address-cells/#size-cells above have just been checked to say. Some
    # nodes on this tree carry a `reg` that is not that shape at all -- a bare
    # address with no size, or a four-byte index -- and decoding one as a pair
    # would silently read the next property's bytes as a size. Refused by
    # length, in the same words as the other two refusals, so a caller that
    # cannot use it can skip it and a caller that needs it stops.
    if not raw or len(raw) % 16:
        raise SystemExit(f'{node} reg is {len(raw)} bytes, not whole '
                         f'64-bit (address, size) pairs')
    out = []
    for off in range(0, len(raw), 16):
        child, size = struct.unpack_from('<QQ', raw, off)
        for lo, parent, span in ranges:
            if size > 0 and lo <= child < child + size <= lo + span:
                out.append((parent + (child - lo), size))
                break
        else:
            raise SystemExit(f'{node} reg {child:#x} is outside every {bus} range')
    return out


def device_inventory(dt, bus='/device-tree/arm-io'):
    """Every register window the guest's tree names, as (pa, size, who).

    So that a physical address in a report can be turned back into the node
    that asked for it. MAP_PAGE tells us the kernel mapped 0x301000000; only
    the tree can tell us that is the interrupt controller, and the tree is the
    one the kernel is reading.

    Two shapes, because the tree has two. Children of `arm-io` carry `reg` in
    the bus's child address space and are translated through its `ranges`,
    exactly as device_windows does -- this reuses it rather than repeating the
    decode. Nodes under `/cpus` instead carry several `*-reg` properties whose
    addresses are already the parent's, one per unit of the core: the
    per-core implementation registers, the coresight block, the per-cluster
    ones shared between siblings. Those are the spans XNU maps when it
    registers its CPUs, so a report that could not name them would be a report
    full of unexplained addresses at exactly the point the boot gets
    interesting."""
    found = []
    prefix = bus + '/'
    for path in dt.nodes:
        if not path.startswith(prefix) or '/' in path[len(prefix):]:
            continue
        if 'reg' not in dt.nodes[path]:
            continue
        name = path[len(prefix):]
        try:
            windows = device_windows(dt, name, bus)
        except SystemExit:
            # A node whose `reg` no range covers. Skipped rather than guessed
            # at: naming it from the wrong range would be worse than not
            # naming it, and the address still prints unresolved.
            continue
        for pa, size in windows:
            if size:
                found.append((pa, size, name))

    cpus = '/device-tree/cpus/'
    for path in dt.nodes:
        if not path.startswith(cpus) or '/' in path[len(cpus):]:
            continue
        name = path[len(cpus):]
        for prop, value in dt.nodes[path].items():
            # (address, size) pairs only. `reg` here is a four-byte cpu number
            # and `reg-private` a bare address with no size, so neither is a
            # window and neither is taken for one.
            if not prop.endswith('-reg') or len(value.value) != 16:
                continue
            pa, size = struct.unpack('<QQ', value.value)
            if size:
                found.append((pa, size, f'{name} {prop}'))
    return sorted(found)


def owner_of(pa, inventory):
    """Which node's window contains `pa`, or None.

    The SMALLEST containing window, because they nest: `pmgr` claims
    0x308100000 for 0xa8000, and the dock-channel UART's own registers sit
    inside that at 0x308128000. Both statements are true and only one is
    useful -- an address resolved to the enclosing block instead of the device
    reads as "the power manager" when the kernel was talking to its console,
    which is a wrong answer with a confident name on it. Taking the first
    match in address order gives exactly that wrong answer, so it takes the
    tightest instead.

    None is a real answer and is printed as one: an address no node claims is
    the interesting case, not an error to be papered over."""
    best = None
    for base, size, who in inventory:
        if base <= pa < base + size and (best is None or size < best[2]):
            best = (who, base, size)
    return best


def early_mapping_budget(dt):
    """Conservative page demand for this ABI's observed pre-VM device maps.

    All CPU register windows (including duplicates), the console, and two AIC
    mappings. The timer's reuse of the AIC is an observed J700 behaviour, not a
    universal XNU rule. New ABI implementations must supply their own recipe.
    """
    windows = device_windows(dt) + 2 * device_windows(dt, 'aic')
    windows += [(pa, size) for pa, size, who in device_inventory(dt)
                if who.startswith('cpu')]
    if panel_range():
        windows.append(panel_range())
    page = 1 << GRANULE
    demand = sum(((pa & (page - 1)) + size + page - 1) // page
                 for pa, size in windows)
    leaf_span = page * (page // 8)
    start = VSPACE_TOP + 1
    capacity = (((start & (leaf_span - 1)) + VSPACE_WALK_SPAN + leaf_span - 1)
                // leaf_span * (page // 8) - (start & (leaf_span - 1)) // page)
    if demand > capacity:
        raise ValueError(f'early mappings need {demand} pages, but only {capacity} '
                         'are reserved before MAP_TABLE is implemented')
    return demand, capacity


def validate_early_heap():
    start = VSPACE_TOP + 1
    GUEST_PROFILE.validate_queue_range(start, VSPACE_WALK_SPAN)
    if start % (1 << (GRANULE + 11)):
        raise ValueError('early heap must begin on a guest L3-table boundary')
    if start >= SPTM_REGION_VA:
        raise ValueError('early heap overlaps the monitor virtual region')
    panel = panel_range()
    aperture_end = APERTURE_VA + REGION_SPAN + (panel[1] if panel else 0)
    if start < aperture_end:
        raise ValueError('early heap overlaps the RAM/framebuffer aperture')


def trust_cache_spec(trust_additions=None):
    """The profile's static trust cache, bound to this run's appended rows.

    Plain Apple caches take no input. An augmented spec needs the additions
    file and refuses to load without it; loader and audits call this alike.
    """
    from trustcache import AugmentedTrustCacheSpec, load_additions
    spec = GUEST_PROFILE.trust_cache
    if isinstance(spec, AugmentedTrustCacheSpec):
        if trust_additions is None:
            raise ValueError(f'profile {PROFILE_NAME} appends CDHashes; pass --trust-additions')
        return spec.bind(load_additions(trust_additions))
    if trust_additions is not None:
        raise ValueError(f'profile {PROFILE_NAME} pins the unmodified Apple trust cache')
    return spec


def linked_auxkc(image, path):
    """Admit the kmutil collection for this profile, or refuse before any build."""
    import auxkc
    import bootfb
    import plistlib
    if not GUEST_PROFILE.aux_collection_linked:
        if path is not None:
            raise ValueError(f'profile {PROFILE_NAME} does not take a linked AuxKC')
        return None
    if path is None:
        raise ValueError(f'profile {PROFILE_NAME} requires --auxkc (build/build-auxkc.py output)')
    data, manifest = auxkc.load(path, PROFILE_FIRMWARE[GUEST_PROFILE.kernelcache])
    collection = auxkc.Collection(data)
    personality = None
    if GUEST_PROFILE.boot_framebuffer_aux:
        info = plistlib.loads((ROOT / 'drivers/boot-framebuffer/SnapintoshBootFramebuffer.kext/'
                               'Contents/Info.plist').read_bytes())
        personality = bootfb.collection_personality(
            info, dedicated=GUEST_PROFILE.boot_framebuffer_nub)
    elif bootfb.BUNDLE_ID in manifest['bundles']:
        # Without the provider half (disp0 property or nub) the personality
        # would match something this profile did not prepare.
        raise ValueError(f'profile {PROFILE_NAME} has no boot framebuffer experiment; '
                         f'use a collection without {bootfb.BUNDLE_ID}')
    summary = auxkc.admit(collection, image, bootfb._prelink_info(image), manifest['bundles'],
                          personality)
    executable = [(name, va, vmsize, off, filesize)
                  for name, va, vmsize, off, filesize, _, initprot in collection.segments
                  if initprot & 4 and filesize]
    validate_counter_image(collection.data, executable, HOST_TIMEBASE_HZ, TIMEBASE_HZ)
    summary['sha256'] = manifest['sha256']
    return collection, summary


def build(kernelcache, verbose=False, ramdisk=None, root_hash=None, ramdisk_mode='md0', isc_image=None,
          auxkc=None, trust_additions=None, sysreg_zero=None, refmod_skip=None, user_4k=None, hide_amx=None):
    if isc_image is not None and (ramdisk is None or ramdisk_mode != 'iokit'):
        raise ValueError('ISC image requires the authenticated IOKit RAM disk path')
    if root_hash is not None and ramdisk is None and GUEST_PROFILE.installed_root is None:
        raise ValueError('root-hash requires a RAMDisk root image (or an installed-root profile)')
    if GUEST_PROFILE.installed_root is not None and ramdisk is not None:
        raise ValueError('an installed-root profile boots without a RAMDisk')
    if ramdisk_mode not in ('md0', 'iokit'):
        raise ValueError('unknown RAMDisk boot mode')
    if ramdisk_mode == 'iokit' and (ramdisk is None or root_hash is None or
                                  GUEST_PROFILE.root_hash is None or
                                  not GUEST_PROFILE.root_hash.boot_uuid):
        raise ValueError('IOKit RAM image requires a profile-bound image, root-hash and boot UUID')
    bad = check_profile(kernelcache=kernelcache)
    if bad:
        raise ValueError('firmware does not match the selected guest profile: ' + '; '.join(bad))
    # Whether or not place() was called: the module's default layout is a
    # placement too, and it is the one an offline --check runs against.
    validate_layout()
    validate_early_heap()
    memory = owned_ranges()
    image = kc_load.Image(pathlib.Path(kernelcache).read_bytes())
    validate_counter_image(image.data, image.executable_segments,
                           HOST_TIMEBASE_HZ, TIMEBASE_HZ)
    linked = linked_auxkc(image, auxkc)
    trust_spec = trust_cache_spec(trust_additions)
    data = bytearray(image.data)
    for offset, value in kc_load.chained_fixups(image, 0):
        struct.pack_into('<Q', data, offset, value)

    native_option = os.environ.get('SNAP_NATIVE_CALLS', '0')
    if native_option not in ('0', '1'):
        raise ValueError('SNAP_NATIVE_CALLS must be 0 or 1')
    hvc_option = os.environ.get('SNAP_SPTM_HVC_CALLS', '0')
    if hvc_option not in ('0', '1') or (hvc_option == '1' and native_option != '1'):
        raise ValueError('SNAP_SPTM_HVC_CALLS must be 0 or 1 and requires SNAP_NATIVE_CALLS=1')
    native_contract = None
    if native_option == '1':
        from nativecalls import contract, patch_hvc_calls
        native_contract = (patch_hvc_calls if hvc_option == '1' else contract)(image, data, IMAGE_PA)
    # Opt-in: trapped Apple IMPDEF accesses whose monitor handling is the
    # ignore default become MOVZ #0/NOP (probes/sysregzero.py). The keyword
    # wins over SNAP_KERNEL_SYSREG_ZERO, which run.py's boot build reads.
    sysreg_option = os.environ.get('SNAP_KERNEL_SYSREG_ZERO', '0')
    if sysreg_option not in ('0', '1'):
        raise ValueError('SNAP_KERNEL_SYSREG_ZERO must be 0 or 1')
    if sysreg_zero is None:
        sysreg_zero = sysreg_option == '1'
    elif type(sysreg_zero) is not bool:
        raise ValueError('sysreg_zero must be an explicit boolean')
    sysreg_contract = None
    if sysreg_zero:
        from sysregzero import patch as patch_sysregs
        sysreg_contract = patch_sysregs(image, data)
        print(f'  kernel sysreg-zero: {sysreg_contract["movz"]} MRS -> MOVZ #0, '
              f'{sysreg_contract["nop"]} -> NOP (closure {sysreg_contract["closure_sha256"][:16]}...)')
    # Opt-in: XNU's NOFLUSH page-aging reference clears (one SPTM
    # UPDATE_DISJOINT each, plus the Access flag fault that follows) become NOP
    # (probes/refmodskip.py). The keyword wins over SNAP_KERNEL_REFMOD_SKIP,
    # which run.py's boot build reads.
    refmod_option = os.environ.get('SNAP_KERNEL_REFMOD_SKIP', '0')
    if refmod_option not in ('0', '1'):
        raise ValueError('SNAP_KERNEL_REFMOD_SKIP must be 0 or 1')
    if refmod_skip is None:
        refmod_skip = refmod_option == '1'
    elif type(refmod_skip) is not bool:
        raise ValueError('refmod_skip must be an explicit boolean')
    refmod_contract = None
    if refmod_skip:
        from refmodskip import patch as patch_refmod
        refmod_contract = patch_refmod(image, data)
        print(f'  kernel refmod-skip: {refmod_contract["sites"]} NOFLUSH reference-clear calls -> NOP '
              f'(closure {refmod_contract["closure_sha256"][:16]}...)')
    # Opt-in: every user pmap is created 4K (SPTM format 1), as Apple's
    # psa_4k spawn switch does (probes/user4k.py), so SNAP_USER_HW_WALK can
    # let the hardware walk XNU's own tables. The keyword wins over
    # SNAP_KERNEL_USER_4K, which run.py's boot build reads.
    user4k_option = os.environ.get('SNAP_KERNEL_USER_4K', '0')
    if user4k_option not in ('0', '1'):
        raise ValueError('SNAP_KERNEL_USER_4K must be 0 or 1')
    if user_4k is None:
        user_4k = user4k_option == '1'
    elif type(user_4k) is not bool:
        raise ValueError('user_4k must be an explicit boolean')
    user4k_contract = None
    if user_4k:
        from user4k import patch as patch_user4k
        user4k_contract = patch_user4k(image, data)
        print(f'  kernel user-4k: {user4k_contract["sites"]} branches forced (4K user pmaps, '
              f'closure {user4k_contract["closure_sha256"][:16]}...)')

    hide_option = os.environ.get('SNAP_HIDE_AMX', '0')
    if hide_option not in ('0', '1'):
        raise ValueError('SNAP_HIDE_AMX must be 0 or 1')
    if hide_amx is None:
        hide_amx = hide_option == '1'
    elif type(hide_amx) is not bool:
        raise ValueError('hide_amx must be an explicit boolean')
    hide_contract = kc_load.hide_amx(image, data) if hide_amx else None
    if hide_contract:
        print(f'  hide-amx: {len(hide_contract["sites"])} application capability publication sites; '
              'kernel AMXIDR and SME visibility unchanged')


    tables = Tables(TABLE_PA)
    chunks = {}
    mapped = 0
    for name, vmaddr, vmsize, fileoff, filesize in image.segments:
        if vmsize == 0 or (WANTED_SEGMENTS and name not in WANTED_SEGMENTS):
            continue
        span = (vmsize + (1 << GRANULE) - 1) & ~((1 << GRANULE) - 1)
        pa = IMAGE_PA + (vmaddr - image.vmin)
        tables.map(vmaddr, pa, span)
        mapped += span
        body = bytes(data[fileoff:fileoff + filesize])
        if body:
            chunks[pa] = body
        if verbose:
            print(f'    {name:<18} {vmaddr:#018x} -> {pa:#012x}  +{span:#x}')

    handoff, x2, x1 = build_handoff(HANDOFF_PA)
    chunks.update(handoff)
    chunks[HANDOFF_PA + 0x1000] = bytearray(chunks[HANDOFF_PA + 0x1000])
    chunks[HANDOFF_PA] = bytearray(chunks[HANDOFF_PA])
    # The handoff structures are read through the kernel regime too, so XNU can
    # dereference the pointers it is given. Identity within the regime is not
    # possible for a low PA, so they get a VA above the image.
    dt = build_devicetree()
    auxkc_payload = None
    if GUEST_PROFILE.boot_framebuffer_aux:
        import bootfb
        import plistlib
        personality_path = ROOT / 'drivers/boot-framebuffer/SnapintoshBootFramebuffer.kext/Contents/Info.plist'
        if linked is None:
            auxkc_payload = bootfb.prepare(dt, image, plistlib.loads(personality_path.read_bytes()),
                                          dedicated=GUEST_PROFILE.boot_framebuffer_nub)
        else:
            # The bundle travels inside the linked collection; only the
            # provider half of the codeless experiment is applied here.
            bootfb.prepare_tree(dt, dedicated=GUEST_PROFILE.boot_framebuffer_nub)
    cmdline = BOOT_CMDLINE
    if dt.deferred_nodes:
        print(f'  virtual board defers {len(dt.deferred_nodes)} Apple device nodes '
              f'declared absent by profile {PROFILE_NAME}')
    ramdisk_range = None
    ramdisk_root_range = None
    ramdisk_isc_range = None
    trust_payload = b''
    trust_fallback_pa = None
    next_payload_pa = PHYS_BASE + max(off+span for _, off, span in reservations())
    next_payload_pa = (next_payload_pa+0x3fff) & ~0x3fff
    sep_preload_range = None
    if GUEST_PROFILE.sep_preload is not None:
        import seppreload
        sep_payload = seppreload.prepare(dt, image, GUEST_PROFILE.sep_preload,
                                         FIRMWARE_DIR, next_payload_pa, REGION_END)
        chunks[next_payload_pa] = sep_payload
        sep_preload_range = (next_payload_pa, len(sep_payload))
        next_payload_pa += len(sep_payload)
        print(f'  SEP preload: {len(sep_payload)} unchanged bytes at '
              f'{sep_preload_range[0]:#x}; native DMA/startup still required')
    if ramdisk is not None:
        cmdline = root_cmdline(cmdline, ramdisk_mode)
        disk_pa = next_payload_pa
        payload = load_ramdisk(ramdisk, disk_pa, REGION_END)
        auxiliary = None
        try:
            if root_hash is not None:
                spec = GUEST_PROFILE.root_hash
                auth_blob = load_root_hash(root_hash, payload, spec)
                dt.add(ROOT_HASH_NODE, spec.property_name, auth_blob)
                populate_ramdisk_policy(dt, spec)
                if GUEST_PROFILE.acm_software_mode:
                    from credential import software_cmdline
                    cmdline = software_cmdline(image, dt, cmdline)
                    print('  credentials: native ACM software mode; no SEP device services')
                if trust_spec is not None:
                    trust_payload = trust_spec.load(FIRMWARE_DIR)
                    appended = len(getattr(trust_spec, 'appended', ()))
                    print(f'  static trust cache: {trust_spec.entries - appended} '
                          f'Apple entries matched to the authenticated BaseSystem'
                          + (f' + {appended} appended CDHashes' if appended else ''))
                print(f'  root-hash {len(auth_blob)} bytes bound to the selected root image; '
                      f'forwarded as {spec.property_name}')
            if isc_image is not None:
                import bootmedia
                auxiliary = load_ramdisk(isc_image, disk_pa, REGION_END)
                media_chunks, media_layout = bootmedia.assemble(payload, auxiliary, disk_pa, REGION_END)
                ramdisk_range = (disk_pa, media_layout['bytes'])
                offset, size = media_layout['root']
                ramdisk_root_range = (disk_pa + offset, size)
                offset, size = media_layout['isc']
                ramdisk_isc_range = (disk_pa + offset, size)
                chunks.update(media_chunks)
                print(f'  GPT auxiliary ISC: {size >> 20} MiB; stock root bytes unchanged')
            else:
                ramdisk_range = ramdisk_root_range = (disk_pa, len(payload))
                chunks[disk_pa] = payload
        except Exception:
            if auxiliary is not None:
                auxiliary.close()
            payload.close()
            raise
        if ramdisk_mode == 'md0':
            dt.add('/device-tree/chosen/memory-map', 'RAMDisk', struct.pack('<QQ', *ramdisk_range))
        else:
            # Shipped IOFindBSDRoot calls di_root_ramfile before root matching.
            # These physical extents create normal IOKit disk-image media;
            # APFS's own media driver then imports the firmware root hash.
            dt.add('/device-tree/chosen', 'boot-ramdmg-size', struct.pack('<Q', ramdisk_range[1]))
            dt.add('/device-tree/chosen', 'boot-ramdmg-extents', struct.pack('<QQ', *ramdisk_range))
            boot_uuid = GUEST_PROFILE.root_hash.boot_uuid.encode('ascii')+b'\0'
            dt.add('/device-tree/chosen', 'boot-uuid', boot_uuid)
            # boot-uuid publishes the resource which starts AppleFileSystemDriver;
            # this companion property selects its APFS-volume UUID matcher.
            # The supplied firmware tree has a zero-filled iBoot placeholder.
            dt.put('/device-tree/chosen', 'apfs-preboot-uuid', boot_uuid)
        print(f'  RAMDisk {ramdisk_range[1] >> 20} MiB at {disk_pa:#x}; '
              f'root {"rd=md0" if ramdisk_mode == "md0" else "IOKit boot UUID"}')
    elif GUEST_PROFILE.installed_root is not None:
        # Full-install M6: no RAM disk. The root is the installed System volume on the virtual
        # ANS2's window; AppleFileSystemDriver selects the APFS volume group.
        from ramdisk import load_installed_root_hash
        spec = GUEST_PROFILE.installed_root
        if root_hash is None:
            raise ValueError('an installed-root profile needs --root-hash (the SystemVolume payload)')
        if GUEST_PROFILE.ans_boot is None or not GUEST_PROFILE.ans_boot.window:
            raise ValueError('an installed-root profile needs the virtual ANS2 window')
        auth_blob = load_installed_root_hash(root_hash, spec)
        dt.add(ROOT_HASH_NODE, spec.property_name, auth_blob)
        if spec.no_protected_data_recipe or spec.no_sep_firmware_recipe:
            populate_ramdisk_policy(dt, spec)
            print('  installed root: no-SEP virtual-board policy applied (protected data and SEP '
                  'firmware declared absent)')
        # kern.bootuuid feeds libignition's Preboot directory lookup. It must
        # be the volume group, not the System volume's distinct UUID.
        boot_uuid = spec.volume_group_uuid.encode('ascii') + b'\0'
        dt.add('/device-tree/chosen', 'boot-uuid', boot_uuid)
        if spec.root_snapshot_name:
            dt.add('/device-tree/chosen', 'root-snapshot-name', spec.root_snapshot_name.encode('ascii') + b'\0')
        dt.put('/device-tree/chosen', 'apfs-preboot-uuid', boot_uuid)
        if GUEST_PROFILE.acm_software_mode:
            from credential import software_cmdline
            cmdline = software_cmdline(image, dt, cmdline)
        if trust_spec is not None:
            trust_payload = trust_spec.load(FIRMWARE_DIR)
            print(f'  static trust cache: {trust_spec.entries} entries of the installed OS '
                  f'({trust_spec.member})')
            if not static_trust_fits(len(trust_payload), SCRATCH_COUNT):
                # Too large for the window between UAT and the scratch pages (~441 KB). With no
                # RAM disk the payload area after the fixed reservations is free: reserve it here,
                # as a chunk, so avail_start (computed below) covers it and XNU never allocates it.
                trust_fallback_pa = next_payload_pa
                span = trust_reserve_size(len(trust_payload))
                if trust_fallback_pa + span > REGION_END:
                    raise ValueError('static trust cache does not fit the guest region')
                chunks[trust_fallback_pa] = bytes(span)
                next_payload_pa += span
                print(f'  static trust cache reserved in the payload area at {trust_fallback_pa:#x} '
                      f'({span >> 10} KiB)')
        print(f'  installed root: System volume {spec.system_uuid}, volume group {spec.volume_group_uuid}; '
              f'root-hash {len(auth_blob)} bytes forwarded as {spec.property_name}')
    mapping_pages, mapping_capacity = early_mapping_budget(dt)
    print(f'  early mapping budget {mapping_pages}/{mapping_capacity} pages '
          '(device-tree recipe, not a bound on all future guest mappings)')
    tree = dt.serialize()               # once: the tree is rebuilt on every read
    dt_len = len(tree)
    if DEVICETREE_PA + dt_len > HANDOFF_PA + HANDOFF_SPAN:
        raise ValueError('device tree exceeds its handoff reservation')
    chunks[DEVICETREE_PA] = tree

    # Below the image, and by exactly the distance that separates them
    # physically, so the whole region is one linear map.
    handoff_va = image.vmin - HANDOFF_SPAN
    if handoff_va < KERNEL_BASE:
        raise SystemExit(f'no room for the handoff below {image.vmin:#x}')
    tables.map(handoff_va, HANDOFF_PA, HANDOFF_SPAN)
    devicetree_va = handoff_va + (DEVICETREE_PA - HANDOFF_PA)
    auxkc_range = None
    if auxkc_payload is not None:
        auxkc_pa = HANDOFF_PA + bootfb.OFFSET
        chunks[auxkc_pa] = auxkc_payload
        auxkc_range = (auxkc_pa, len(auxkc_payload))
        struct.pack_into('<QQQ', chunks[HANDOFF_PA], bootfb.HANDOFF_BASE,
                         *bootfb.handoff_values(handoff_va, image.vmax))
        print(f'  experimental codeless AuxKC: {len(auxkc_payload)} bytes at '
              f'{auxkc_pa:#x}; native admission and driver matching unqualified')
    auxkc_va_range = None
    if linked is not None:
        import auxkc as auxkc_format
        import bootfb
        collection, auxkc_summary = linked
        # Directly above the primary image: auxkc_end then bounds both
        # collections (end_kern/vm_kernelcache_top) with no hole between.
        auxkc_base = image.vmax
        auxkc_pa = PHYS_BASE + auxkc_offset()
        span = (collection.top + (1 << GRANULE) - 1) & ~((1 << GRANULE) - 1)
        if span > AUXKC_SPAN:
            raise ValueError(f'linked AuxKC needs {span:#x}, more than its {AUXKC_SPAN:#x} reservation')
        maps = auxkc_format.mappings(collection, auxkc_base, auxkc_pa)
        if sum(size for _, _, _, size, _, _ in maps) != span:
            raise ValueError('linked AuxKC segments leave a virtual hole')
        for name, va, pa, size, body, executable in maps:
            if any(tables.walk(va + n) is not None for n in range(0, size, 1 << GRANULE)):
                raise ValueError(f'linked AuxKC {name} overlaps an existing kernel mapping')
            tables.map(va, pa, size, LEAF if executable else LEAF_NX)
            chunks[pa] = body
            if verbose:
                print(f'    aux {name:<14} {va:#018x} -> {pa:#012x}  +{size:#x}'
                      f'{"  X" if executable else ""}')
        auxkc_range = (auxkc_pa, span)
        auxkc_va_range = (auxkc_base, auxkc_base + span)
        handoff_words = auxkc_format.handoff_values(collection, auxkc_base, image.vmax)
        if handoff_words[2] < auxkc_va_range[1] or handoff_words[2] < image.vmax:
            raise ValueError('auxkc_end must cover every mapped kernel-collection VA')
        struct.pack_into('<QQQ', chunks[HANDOFF_PA], bootfb.HANDOFF_BASE, *handoff_words)
        print(f'  linked AuxKC {auxkc_summary["sha256"][:16]}...: {span:#x} bytes at '
              f'{auxkc_pa:#x}, base {auxkc_base:#x}, header {handoff_words[1]:#x}; '
              f'{len(auxkc_summary["bundles"])} bundles, '
              f'{sum(auxkc_summary["fixups"][k] for k in ("primary", "auxiliary"))} '
              'unresolved fixups left to XNU; kext load unqualified')
    # Initial FEAT_NV2 register image. The monitor copies this seed to its
    # private CPU0 page and allocates independent register pages for other CPUs.
    # Which regime translates VNCR_EL2 decides what address goes in it. A guest
    # VA faulted at level 0 -- a level the guest's own regime does not even have
    # -- so the walk is not the guest's. EL2 here runs flat over physical
    # memory, so the physical address is the one that resolves.
    vncr_va = HANDOFF_PA + 0x8000
    chunks[HANDOFF_PA + 0x8000] = bytearray(0x4000)
    # NV2 redirects HCR_EL2 to VNCR +0x78. CurrentEL already reports EL2
    # under NV, so leaving this zero sends ordinary kernel exceptions into
    # XNU's VM-exit handler (which requires a guest vCPU in TPIDR_EL2).
    # This is guest register state, never the host's actual HCR_EL2.
    struct.pack_into('<Q', chunks[vncr_va], 0x78, GUEST_PROFILE.kernel_hcr)
    # Everything the loader placed, so XNU treats none of it as free: it
    # allocates upward from here. The tables are still growing at this point, so
    # their whole arena counts rather than what has been used.
    #
    # Every fixed reservation counts too, not just the chunks that exist yet.
    # The monitor region's backing (SPTM_DATA_OFFSET) is written as chunks
    # further down this function, after this word is computed, so a maximum
    # over `chunks` alone stopped at the table arena and published 0xe4200000 --
    # the first byte of the memory behind 0xfffffecfffcfc000. XNU reads this
    # word into its early physical allocator (handoff +0x18 -> 0xfffffe0007d9fd60
    # -> the cursor at 0xfffffe0007da06c8) and carves pmap_bootstrap's pv page,
    # ptd arena and ASID bitmap from it, so those landed on the same physical
    # pages that back the monitor's fixed region: one memory, two owners.
    avail_start = max(max(pa + len(b) for pa, b in chunks.items()),
                      max(PHYS_BASE + off + span for _, off, span in reservations()))
    avail_start = (avail_start + (1 << GRANULE) - 1) & ~((1 << GRANULE) - 1)
    struct.pack_into('<Q', chunks[HANDOFF_PA], SPTM_AVAIL_START, avail_start)
    # The kernel's static virtual map, both ends. +0x08 had never been
    # written and +0x10 held REGION_END, a physical address.
    struct.pack_into('<Q', chunks[HANDOFF_PA], VSPACE_BASE_OFFSET, VSPACE_BASE)
    struct.pack_into('<Q', chunks[HANDOFF_PA], VSPACE_TOP_OFFSET, VSPACE_TOP)

    # x1 is boot_args, and now it is filled out as one rather than as three
    # fields in a page of zeros. Written after the mapping exists because
    # deviceTreeP is a virtual address in the guest's own regime -- XNU
    # range-checks every tree pointer against it and then dereferences it, so a
    # physical one faults on the base itself (0xfffffe000c1ecca4 does exactly
    # that check, and the node it goes on to read starts with the property count
    # an Apple tree node begins with).
    chunks[HANDOFF_PA + 0x1000][:BOOT_ARGS_SIZE] = boot_args(
        virt_base=image.vmin,
        phys_base=IMAGE_PA,
        mem_size=REGION_END - IMAGE_PA,
        top_of_kernel_data=avail_start,
        devicetree_va=devicetree_va,
        dt_len=dt_len, cmdline=cmdline)

    # The physical aperture: the whole region we were given, mapped linearly, and
    # one entry saying so. Published and mapped together -- an entry covering
    # memory that is not mapped just moves the fault later and makes it harder to
    # read.
    # Ordinary RAM aliases are data (selector3, EL1 RW/NX), not executable
    # aliases of every page. ROZONE RETYPE changes only its selected frame
    # to selector2; the monitor translates its per-CPU permission state.
    tables.map(APERTURE_VA, PHYS_BASE, REGION_SPAN, LEAF | (3 << 53))
    regions = [(PHYS_BASE, APERTURE_VA, REGION_SPAN)]

    # The panel is its own region: it lives outside the memory we were given
    # (0xf9a20000 on the A16, above our 0xf8000000), so a single aperture cannot
    # reach it and XNU's translation of v_baseAddr would fail exactly the way
    # every other unpublished address has failed today.
    # The structure the kernel places above the declared DRAM, identity mapped.
    # It walks it at addresses numerically equal to the physical ones -- level-1
    # entry 0 -- so VA must equal PA here, and publishing it with virt == phys
    # keeps phystokv consistent with the mapping instead of merely alongside it.
    tables.map(BOOTSTRAP_PA, BOOTSTRAP_PA, BOOTSTRAP_SPAN)
    regions.append((BOOTSTRAP_PA, BOOTSTRAP_PA, BOOTSTRAP_SPAN))

    # The fixed region contains both monitor backing and XNU's temporary
    # per-CPU copy windows. The latter need table levels but EMPTY leaves:
    # pmap_map_cpu_windows_copy_internal finds a free slot by testing its PTE.
    # Backing the whole interval with RAM makes every window look occupied.
    sptm_span = SPTM_REGION_END - SPTM_REGION_VA
    if sptm_span > SPTM_DATA_SPAN:
        raise SystemExit(f'the monitor region needs {sptm_span:#x}, more than the '
                         f'{SPTM_DATA_SPAN:#x} reserved for it')
    cpu_count = sum(path.startswith('/device-tree/cpus/') and path.count('/') == 3
                    for path in dt.nodes)
    copy_base, copy_pages = GUEST_PROFILE.cpu_copy_windows
    copy_span = cpu_count * copy_pages * (1 << GRANULE)
    copy_end = copy_base + copy_span
    if (cpu_count != GUEST_PROFILE.monitor_stack_count or cpu_count != SCRATCH_COUNT or
            copy_pages != 4 or copy_base & ((1 << GRANULE) - 1) or
            not SPTM_REGION_VA < copy_base < copy_end < SPTM_REGION_END):
        raise ValueError('copy-window geometry differs from the selected CPU contract')
    tables.map(SPTM_REGION_VA, SPTM_DATA_PA, copy_base - SPTM_REGION_VA)
    tables.reserve(copy_base, copy_span)
    tables.map(copy_end, SPTM_DATA_PA + copy_end - SPTM_REGION_VA,
               SPTM_REGION_END - copy_end)
    for step in range(0, sptm_span, 1 << GRANULE):
        chunks[SPTM_DATA_PA + step] = bytes(1 << GRANULE)

    # Free kernel VA above the static map: the levels, not the pages.
    before = len(tables.pages)
    tables.reserve(VSPACE_TOP + 1, VSPACE_WALK_SPAN)
    print(f'  reserved {VSPACE_WALK_SPAN >> 20} MiB of tables at '
          f'{VSPACE_TOP + 1:#x} for XNU to populate, '
          f'{len(tables.pages) - before} table pages, no leaves')

    panel = panel_range()
    if panel:
        fb_pa, fb_span = panel
        fb_va = APERTURE_VA + REGION_SPAN
        tables.map(fb_va, fb_pa, fb_span)
        regions.append((fb_pa, fb_va, fb_span))

    slide_config = slide_contract(image, tables, avail_start)
    if auxkc_range is not None and linked is not None:
        # phystokv, the frame table and the typed frame map must all see it.
        pa, span = auxkc_range
        if not any(r_pa <= pa and pa + span <= r_pa + r_span for r_pa, _, r_span in regions):
            raise ValueError('linked AuxKC is outside every published aperture region')
        if not any(m.base <= pa and pa + span <= m.end for m in memory) or pa + span > avail_start:
            raise ValueError('linked AuxKC is outside owned, loader-reserved memory')

    # SLIDE_REGION validates and splits a physically ordered aperture map.
    # On high-RAM hosts the panel can precede DRAM, rather than follow it.
    regions.sort(key=lambda region: region[0])
    aperture = bytearray(0x1000)
    struct.pack_into('<I', aperture, 0, len(regions))
    for n, (pa, va, span) in enumerate(regions):
        struct.pack_into('<QQI', aperture, 0x10 + n * REGION_ENTRY_SIZE,
                         pa, va, span >> GRANULE)
    chunks[HANDOFF_PA + REGIONS_OFFSET] = aperture

    # Its two pointers in the versioned table. XNU dereferences them at EL1, so
    # they are virtual addresses in the guest's regime, not physical ones -- the
    # same lesson deviceTreeP taught.
    # The frame table, and its root in the versioned table. Physical: XNU
    # translates it through the aperture itself, which is why the aperture had
    # to come first.
    # It has to cover every physical address we published, not just our RAM.
    # The panel lives above the region (0xf9a20000 on the A16, past our
    # 0xf8000000), and handing XNU an aperture for it without a frame table
    # entry is what 0xfffffe000ba7ab68 died on: the level-2 slot for the
    # framebuffer was zero, phystokv(0) failed, and the NULL was indexed. The
    # leaves in between describe memory we do not own, and describing it as
    # untyped -- which is what all-zero means -- is true.
    ft_span = REGION_SPAN
    for pa, _, span in regions:
        ft_span = max(ft_span, pa + span - PHYS_BASE)
    ft_span = (ft_span + LEAF_SPAN - 1) // LEAF_SPAN * LEAF_SPAN
    ft_chunks, ft_root = build_frametable(FRAMETABLE_PA, PHYS_BASE, ft_span)
    chunks.update(ft_chunks)
    del ft_root                 # nothing consumes the three-level root; see below

    # Flat frame map: the full envelope, with only owned ranges typed. The
    # panel is outside DRAM; the intervening hole must retain type zero.
    framemap_low = memory[0].base
    framemap_high = memory[-1].end
    fill, asked = frame_type()
    fm_chunks, fm_size = build_framemap(FRAMEMAP_PA, framemap_low,
                                        framemap_high, fill, memory)
    chunks.update(fm_chunks)
    framemap_va = APERTURE_VA + (FRAMEMAP_PA - PHYS_BASE)
    print(f'  frame map {fm_size:#x} bytes at {FRAMEMAP_PA:#x} '
          f'(va {framemap_va:#x}), owned frames type {fill:#04x}, gaps type 0'
          + ('  (SNAP_FRAME_TYPE)' if asked
             else '  -- the type all 379 measured maps required; one value '
                  'standing in for a computed one, SNAP_FRAME_TYPE sweeps it'))

    regions_va = handoff_va + REGIONS_OFFSET
    table = HANDOFF_TABLE_OFFSET
    # +0x38 is a page-table root, not a frame table.
    #
    # The structure XNU builds from it settles this: {root VA, root PA, VA range
    # start, VA range end, level descriptors}, and the descriptors are a standard
    # four-level 16K walk. The arithmetic agrees -- for the address it faulted on
    # the level-1 index is (va >> 36) & 0x7ff = 2028, and the thing we supplied
    # had exactly one entry, at index 0.
    #
    # So it wants the page tables SPTM built for the kernel, which is the table
    # this loader already builds. Handing it our own root is both simpler and
    # more likely to be true than any structure invented for the purpose.
    struct.pack_into('<Q', chunks[HANDOFF_PA], table + HANDOFF_PAGETABLE,
                     tables.root)
    # handoff +0x320 is a pointer XNU dereferences and tests bit 0 of.
    #
    # The offset is measured, not derived. 0xfffffe000c2447f0 memcpy's 0x358
    # bytes into a static buffer and publishes it; reading that buffer back off
    # the target after a run and searching for its first 64 bytes in our handoff
    # page finds them at offset 0, and its first quadword is the handoff magic.
    # So the copy is [handoff, handoff+0x358) and the field the kernel died on
    # is simply +0x320 of the handoff itself. An earlier guess put the copy at
    # the versioned table and this field at +0x4c0; that was wrong, and the run
    # that tested it is what said so.
    #
    # It is read straight after the "aprr_jit" boot argument is parsed, and the
    # test at 0xfffffe000ba97d58 branches past the work when bit 0 is clear. So
    # for a feature this monitor does not implement, the honest value is a valid
    # pointer to a byte that reads zero -- not a null, and not a fabricated
    # structure. It points inside the handoff, which is mapped and ours.
    struct.pack_into('<Q', chunks[HANDOFF_PA], 0x320, handoff_va + FLAGS_OFFSET)

    # The scratch pages, zeroed and published. XNU reads what the monitor left
    # here after a call; a zero where it expects a pointer is the null read this
    # loader spent a run on.
    #
    # Endpoint 0x32, SPTM_FUNCTIONID_OUTPUT_AREA, is where XNU gets this -- it
    # dereferences that answer directly at EL1 (0xfffffe000ba62e0c, the
    # instruction after a MAP_PAGE returns), so it cannot be a physical address.
    # The scratch is reserved monitor data, mapped in the guest RAM aperture.
    # Every declared CPU owns a separate 32 KiB result area.
    #
    # It is NOT published at table +0x18 any more. That field is the frame map's
    # low bound (see FRAMEMAP_LOW), compared against a physical address by
    # sptm_get_frame_type; writing the scratch base into it was wrong and was
    # invisible only because +0x20 was zero, which makes the range test
    # unreachable. docs/PLAN-HISTORY-20260922.md's note that publishing it there "changed nothing
    # observable" is explained by that, not by the field being spare.
    chunks[SCRATCH_PA] = bytes(SCRATCH_SPAN)
    scratch_va = APERTURE_VA + SCRATCH_PA - PHYS_BASE
    # The frame map: its bounds as physical addresses, its base as a virtual
    # one. sptm_get_frame_type compares the first two against a paddr and
    # dereferences the third, so the asymmetry is the consumer's, not ours.
    struct.pack_into('<Q', chunks[HANDOFF_PA], table + FRAMEMAP_LOW, framemap_low)
    struct.pack_into('<Q', chunks[HANDOFF_PA], table + FRAMEMAP_HIGH, framemap_high)
    struct.pack_into('<Q', chunks[HANDOFF_PA], table + FRAMEMAP_BASE, framemap_va)
    struct.pack_into('<Q', chunks[HANDOFF_PA], table + HANDOFF_REGIONS, regions_va)
    struct.pack_into('<Q', chunks[HANDOFF_PA], table + HANDOFF_REGION_TABLE,
                     regions_va + 0x10)

    # The monitor images, at their linked addresses.
    monitors = load_monitor_images(tables, chunks)
    type_info = GUEST_PROFILE.frame_type_info_va
    # The guest directly indexes type 35 as part of page-release checks. Use
    # the audited monitor's actual data, and reject an out-of-image profile.
    if not any(name == GUEST_PROFILE.monitors[0] and
               lo <= type_info and type_info + 36 * 144 <= lo + span
               for name, lo, _, span in monitors):
        raise ValueError('frame-type descriptor table is outside the monitor images')
    struct.pack_into('<Q', chunks[HANDOFF_PA], table + HANDOFF_FRAME_TYPES, type_info)
    # SPTM startup ...270e3d90 -> ...3d74/78 initializes ROZONE's runtime
    # PAPT selector to2. We provide that initialized data while emulating
    # its services; the original on-disk SPTM image remains unchanged.
    selector_pa = tables.walk(type_info + 25 * 144 + 0x79)
    containing = [(pa, payload) for pa, payload in chunks.items()
                  if selector_pa is not None and pa <= selector_pa < pa + len(payload)]
    if len(containing) != 1:
        raise ValueError('ROZONE runtime descriptor lacks one backing chunk')
    selector_chunk_pa, selector_chunk = containing[0]
    if selector_chunk[selector_pa - selector_chunk_pa] != 0:
        raise ValueError('unexpected uninitialized ROZONE aperture selector')
    selector_chunk = bytearray(selector_chunk)
    selector_chunk[selector_pa - selector_chunk_pa] = 2
    chunks[selector_chunk_pa] = selector_chunk

    # +0x60: the debug table. A 'DEBG' header, then the two monitor Mach-O
    # header addresses that 0xfffffe000ba7a6ec walks looking for __TEXT.
    #
    # Both pointers have to be real. The walk advances by cmdsize with no bound
    # until it matches, so a null faults on the header's first load command and
    # a wrong pointer wanders -- neither fails in a way that says what happened.
    if len(monitors) != len(DEBUG_TABLE_IMAGES):
        raise SystemExit(
            f'the debug table needs {len(DEBUG_TABLE_IMAGES)} monitor images '
            f'and {len(monitors)} were loaded from {FIRMWARE_DIR}; XNU walks '
            f'each of these pointers as a Mach-O and a null one faults')
    # The two slots are sixteen bytes apart rather than adjacent, so the table
    # runs to the end of the last one and not to header + 8 per image.
    debug_table = bytearray(max(DEBUG_TABLE_IMAGES) + 8)
    struct.pack_into('<III', debug_table, 0, DEBUG_TABLE_MAGIC,
                     DEBUG_TABLE_VERSION, DEBUG_TABLE_COUNT)
    for offset, (_, header_va, _, _) in zip(DEBUG_TABLE_IMAGES, monitors):
        struct.pack_into('<Q', debug_table, offset, header_va)
    chunks[HANDOFF_PA + DEBUG_TABLE_OFFSET] = debug_table
    struct.pack_into('<Q', chunks[HANDOFF_PA], HANDOFF_DEBUG_TABLE,
                     handoff_va + DEBUG_TABLE_OFFSET)

    # These are monitor stack VAs, not physical-memory boundaries. TXM's
    # initializer translates all six entries at ...befd3d4..befd578. The
    # exception/stack predicates compare VAs against these same two ranges.
    # Keep the stacks separate from the fixed monitor region and the heap.
    cpu_count = sum(path.startswith('/device-tree/cpus/') and path.count('/') == 3
                    for path in dt.nodes)
    if cpu_count != GUEST_PROFILE.monitor_stack_count or cpu_count != SCRATCH_COUNT:
        raise ValueError('device-tree CPU count disagrees with audited monitor stack layout')
    txm_pa = SPTM_DATA_PA + sptm_span
    cpu_stack_pa = txm_pa + cpu_count * MONITOR_STACK_GRAIN
    cpu_stack_span = 0x100000
    txm_log_pa = cpu_stack_pa + cpu_stack_span
    txm_rw_pa, txm_ro_pa = txm_log_pa + 0x4000, txm_log_pa + 0x8000
    txm_aspace_pa = txm_ro_pa + MONITOR_STACK_GRAIN
    uat_pa = txm_aspace_pa + TXM_ASPACE_PAGES * MONITOR_STACK_GRAIN
    if static_trust_window(cpu_count)[0] != uat_pa + 3 * MONITOR_STACK_GRAIN:
        raise ValueError('static trust window arithmetic disagrees with the monitor layout')
    if uat_pa + 3 * MONITOR_STACK_GRAIN > SCRATCH_PA:
        raise ValueError('monitor stacks exceed their loader reservation')
    stack_vas = [APERTURE_VA + txm_pa - PHYS_BASE + n * MONITOR_STACK_GRAIN
                 for n in range(cpu_count)]
    array = bytearray(cpu_count * 8)
    for n, value in enumerate(stack_vas):
        struct.pack_into('<Q', array, n * 8, value)
    for pa in range(txm_pa, uat_pa, MONITOR_STACK_GRAIN):
        chunks[pa] = bytes(MONITOR_STACK_GRAIN)
    # Explicit development environment: monitor code-signing enforcement is
    # absent. No signature/trust-cache operation is acknowledged by this flag.
    info = bytearray(MONITOR_STACK_GRAIN)
    # Native TXM initializer excludes platform class0 from SEP secure-channel
    # support. This virtual backend has no channel allocation or protocol.
    # Keep the class and descriptor absent, and reject a contradictory tree.
    if dt.get('/device-tree/arm-io/dart-sep', 'txm-secure-channel-base') is not None:
        raise ValueError('virtual TXM has no SEP secure-channel backend')
    info[0xa] = 0
    struct.pack_into('<3Q', info, 0x38, 0, 0, 0)
    policy_off, disabled_off = (GUEST_PROFILE.txm_policy_pointer_offset,
                                GUEST_PROFILE.txm_csm_disabled_offset)
    if not (0 <= policy_off <= 0x3ff8 and 0 <= disabled_off < 0x3ff0):
        raise ValueError('TXM policy layout does not fit its reserved page')
    struct.pack_into('<Q', info, policy_off, APERTURE_VA + txm_ro_pa - PHYS_BASE)
    info[disabled_off] = 1
    info[0x3ff0] = 1  # separate developer-mode flag, not the CSM policy byte
    chunks[txm_ro_pa] = bytes(info)
    uat_geometry = dt.monitor_uat_geometry
    uat_va = APERTURE_VA + uat_pa - PHYS_BASE
    # SPTM ...bb6f0..bb744: private-mode state flags 8, L1 pointer at +10,
    # 64 entries at +18 and level 2 at +1a. ...bb864..878 installs the
    # firmware's shared L2 in L1 slot 2. No GPU translations exist initially.
    uat_state = bytearray(MONITOR_STACK_GRAIN)
    uat_state[0] = 8
    struct.pack_into('<Q', uat_state, 0x10, uat_va + MONITOR_STACK_GRAIN)
    struct.pack_into('<HB', uat_state, 0x18, 64, 2)
    uat_l1 = bytearray(MONITOR_STACK_GRAIN)
    struct.pack_into('<Q', uat_l1, 0x10, (uat_pa + 2 * MONITOR_STACK_GRAIN) | 3)
    chunks[uat_pa] = bytes(uat_state)
    chunks[uat_pa + MONITOR_STACK_GRAIN] = bytes(uat_l1)
    chunks[uat_pa + 2 * MONITOR_STACK_GRAIN] = bytes(MONITOR_STACK_GRAIN)
    # Boot-loaded static cache follows UAT without moving any existing reserve.
    # The monitor constructs the runtime/module page, then makes the complete
    # reservation read-only in every CPU's stage-2 map before guest entry.
    trust_cache = (0, 0, 0)
    trust_end = uat_pa + 3 * MONITOR_STACK_GRAIN
    if trust_payload:
        trust_pa = uat_pa + 3 * MONITOR_STACK_GRAIN
        trust_span = trust_reserve_size(len(trust_payload))
        if trust_pa + trust_span > SCRATCH_PA:
            # The installed OS's cache (~441 KB) is larger than the window between UAT and the
            # scratch pages. Without a RAM disk the payload area after the fixed reservations is
            # free: place it there, below avail_start like every other loader payload, so XNU
            # never allocates it, and still inside the physical aperture for AMFI's reads.
            if trust_fallback_pa is None:
                raise ValueError('static trust cache exceeds loader reservation')
            trust_pa = trust_fallback_pa
        trust_blob = bytes(MONITOR_STACK_GRAIN) + trust_payload
        trust_blob += bytes(trust_span - len(trust_blob))
        chunks[trust_pa] = trust_blob
        trust_cache = (trust_pa, APERTURE_VA + trust_pa - PHYS_BASE, len(trust_payload))
        if trust_pa != trust_fallback_pa:    # a relocated cache leaves the window (and the panic page) as if empty
            trust_end = trust_pa + trust_span
    panic_state = panic_state_reservation(trust_end)
    chunks[panic_state[0]] = bytes(panic_state[2])
    struct.pack_into('<Q', chunks[HANDOFF_PA], PANIC_HANDOFF_OFFSET, panic_state[1])
    chunks[HANDOFF_PA + TXM_STACK_ARRAY_OFFSET] = array
    struct.pack_into('<Q', chunks[HANDOFF_PA], HANDOFF_TXM_STACKS,
                     handoff_va + TXM_STACK_ARRAY_OFFSET)
    struct.pack_into('<I', chunks[HANDOFF_PA], HANDOFF_TXM_STACK_COUNT,
                     cpu_count)
    struct.pack_into('<Q', chunks[HANDOFF_PA], HANDOFF_CPU_STACK_LOW,
                     APERTURE_VA + cpu_stack_pa - PHYS_BASE)
    struct.pack_into('<Q', chunks[HANDOFF_PA], HANDOFF_CPU_STACK_HIGH,
                     APERTURE_VA + cpu_stack_pa + cpu_stack_span - PHYS_BASE)

    # +0x68 is not a descriptor either. It is a u32 count, and leaving it zero
    # is what the previous stop was.
    struct.pack_into('<I', chunks[HANDOFF_PA], HANDOFF_BITMAP_COUNT, BITMAP_BITS)

    # The seed, written last on purpose: its offsets come from the kernel's own
    # instructions, so where anything overlaps it, it has to be the survivor.
    seed = random_seed()
    blob = chunks[HANDOFF_PA]
    blob[RANDSEED_TAG_OFFSET:RANDSEED_TAG_OFFSET + len(RANDSEED_TAG)] = RANDSEED_TAG
    blob[RANDSEED_DATA_OFFSET:RANDSEED_DATA_OFFSET + len(seed)] = seed
    struct.pack_into('<Q', blob, RANDSEED_LENGTH_OFFSET, len(RANDSEED_TAG) + len(seed))
    report_handoff_overlap()

    region_va = devicetree_va

    tables.validate_allocator_baseline(avail_start, REGION_END, APERTURE_VA, PHYS_BASE)

    # TCR_EL1 as XNU's own regime: T1SZ from above, TG1 = 0b01 (16K), write-back inner
    # shareable, TTBR0 disabled because the kernelcache is entirely upper-half.
    tcr = ((T1SZ << 16) | (1 << 24) | (1 << 26) | (3 << 28) | (1 << 30)
           | (1 << 7))                       # EPD0
    built = {
        'image': image,
        'tables': tables,
        'chunks': chunks,
        'entry': image.entry,
        'tcr': tcr,
        # MAIR_EL1 as SPTM leaves it for XNU, byte for byte.
        #
        # SPTM owns this register. There is no `msr MAIR_EL1` anywhere in
        # kernelcache.release.mac17p -- not one, in 120 MiB of image -- and two
        # in sptm.t8140.release. The one live when XNU runs is the second, at
        # file offset +0xab5c8 in SPTM's common start, which every CPU passes
        # (cold boot and warm entries) before SPTM's C code: 0x0c0d00ff01a040ff,
        # XNU's own CACHE_ATTRINDX table (WB, write-combine = Normal NC,
        # write-through, device, inner WB, posted, posted-reordered GRE,
        # combined GRE). The first, +0xa01ec (0x010000ff), is set only inside
        # the exclave re-entry stub, which always branches into that start.
        # tools/test-sptm-mair.py decodes both from the image and pins this.
        #
        # This loader once published 0x44ff and then the stub's 0x010000ff,
        # which made XNU's write-combined DRAM Device-nGnRnE. Every PTE this
        # loader builds uses index 0, which no choice has changed.
        #
        # This also retires a plan item and a risk. docs/PLAN-HISTORY-20260922.md's step C proposed
        # applying "the kernel's MAIR_EL1 write" instead of swallowing it, and
        # R5 said MAIR is fixed inside C; both assume a write that cannot
        # happen. The SR_MAIR_EL1 arm of the sysreg trap is unreachable from
        # XNU and is kept only because SPTM's value is now what it would
        # return.
        'mair': GUEST_PROFILE.mair,
        'guest_profile': GUEST_PROFILE.name,
        'host_counter_hz': HOST_TIMEBASE_HZ,
        'guest_counter_hz': TIMEBASE_HZ,
        'monitor_abi': GUEST_PROFILE.abi,
        'video_console_witness': GUEST_PROFILE.video_console,
        'framebuffer': FRAMEBUFFER,
        'ramdisk_range': ramdisk_range,
        'sep_preload_range': sep_preload_range,
        'auxkc_range': auxkc_range,
        'auxkc_va_range': auxkc_va_range,
        'auxkc': linked[1] if linked else None,
        'trust_entries': trust_spec.entries if trust_payload else 0,
        'ramdisk_root_range': ramdisk_root_range,
        'ramdisk_isc_range': ramdisk_isc_range,
        'ramdisk_mode': ramdisk_mode,
        'frame_map_pa': FRAMEMAP_PA,
        'frame_low': framemap_low,
        'frame_high': framemap_high,
        'alloc_low': avail_start,
        'alloc_high': REGION_END,
        'region_va': region_va,
        'vncr_va': vncr_va,
        'devicetree_va': devicetree_va,
        'devicetree_len': dt_len,
        'dt_resolved': dt.resolved,
        # The tree object itself, not just its resolution flag. A report that
        # turns a physical address back into a node has to consult the tree the
        # guest was actually handed, and rebuilding one to look at would be a
        # second tree that is only probably the same.
        'dt': dt,
        'dart_devices': dt.dart_devices,
        'dart_apf_slices': dt.dart_apf_slices,
        'device_models': dt.device_models,
        # Where the image was uploaded. Carried in `built` rather than read
        # from the module by the caller, because probes/run.py loads this
        # module into a local and its module-level helpers cannot see it.
        'image_pa': IMAGE_PA,
        'txm_stacks_pa': txm_pa, 'txm_stack_count': cpu_count, 'txm_log_pa': txm_log_pa,
        'txm_rw_pa': txm_rw_pa, 'txm_ro_pa': txm_ro_pa, 'txm_aspace_pa': txm_aspace_pa,
        'trust_cache': trust_cache,
        'panic_state': panic_state,
        'uat_pa': uat_pa, 'uat_geometry': uat_geometry,
        'slide_config': slide_config,
        'const_region': const_region_contract(image, IMAGE_PA),
        'watch_count': 2 if not WATCH_OFF else 0,
        'x1': handoff_va + (x1 - HANDOFF_PA),
        'x2': handoff_va + (x2 - HANDOFF_PA),
        'mapped': mapped,
        'vmin': image.vmin,
        'stub_pa': native_contract['pages'] if native_contract else monitor_pages(image, data),
        'native_calls': native_contract is not None,
        'sptm_hvc_calls': hvc_option == '1',
        'native_call_contract': native_contract,
        'kernel_sysreg_zero': sysreg_contract,
        'kernel_refmod_skip': refmod_contract,
        'kernel_user_4k': user4k_contract,
        'vbar_pa': IMAGE_PA + (XNU_VBAR - image.vmin),
        'scratch_va': scratch_va,
        # The console's register windows, from the tree above: the first
        # non-memory physical addresses the kernel will ask us to map.
        'uart_windows': device_windows(dt),
    }
    if hide_contract:
        built['hide_amx'] = hide_contract
    validate_vspace(tables)
    built['chunks'][PARAMS_PA] = params_blob(built)
    built['params_pa'] = PARAMS_PA
    return built


# Every address the entry path is known to touch, from reading the boot stub.
def critical(image):
    return [('entry point', image.entry), *GUEST_PROFILE.critical_addresses]


def print_profile(built=None):
    """The whole profile: what it was measured against, and what it measured.

    Firmware hashes, the ABI offsets inside the handoff, the pages that hold
    monitor call sites and the addresses the entry path has to resolve -- the
    four things docs/PLAN-HISTORY-20260922.md asks a boot profile to pin down, in one place, so a run
    can be reproduced from its transcript."""
    print(f'profile   {PROFILE_NAME}   {PROFILE_TARGET}, {PROFILE_BUILD}')
    print(f'guest     {GUEST_SPAN >> 20} MiB declared, '
          f'{BOOTSTRAP_SPAN >> 20} MiB held back above it, '
          f'{REGION_ALIGN >> 20} MiB grid')
    print(f'output    {"serial only" if not FRAMEBUFFER else "serial + panel"}')

    measured = firmware_hashes()
    print('\nfirmware:')
    for name, expected in PROFILE_FIRMWARE.items():
        got = measured.get(name)
        state = 'ok  ' if got == expected else 'FAIL'
        print(f'  {state} {name:<32} {got or "missing"}')

    print('\nhandoff ABI offsets (versioned table, XNU stores each at 0x238 + this):')
    for label, off in (('regions', HANDOFF_REGIONS),
                       ('region table', HANDOFF_REGION_TABLE),
                       ('page-table root', HANDOFF_PAGETABLE),
                       ('framemap low', FRAMEMAP_LOW),
                       ('framemap high', FRAMEMAP_HIGH),
                       ('framemap base', FRAMEMAP_BASE)):
        print(f'  {label:<18} +{off:#04x}  -> {0x238 + off:#x}')
    print(f'  {"debug table ptr":<18} +{HANDOFF_DEBUG_TABLE:#04x} (absolute, '
          f"'DEBG' v{DEBUG_TABLE_VERSION}, 0 entries)")
    print(f'  {"bitmap count":<18} +{HANDOFF_BITMAP_COUNT:#04x} (absolute, u32 '
          f'= {BITMAP_BITS:#x})')

    print('\nphysical layout, as offsets from the region base:')
    for name, off, span in reservations():
        print(f'  {name:<12} {off:#010x} +{span:#010x}')

    if built is None:
        return
    image = built['image']
    print('\nmonitor sites (pages marked execute-never at stage 2):')
    for pa in built['stub_pa']:
        print(f'  {pa:#012x}  == VA {image.vmin + (pa - IMAGE_PA):#018x}')
    print('\ncheckpoints (every address the entry path is known to touch):')
    for label, va in critical(image):
        print(f'  {label:<20} {va:#018x}')


def record_profile():
    """Print candidate hashes; changing identity cannot certify new addresses."""
    measured = firmware_hashes()
    missing = [n for n, h in measured.items() if h is None]
    if missing:
        print(f'refusing to record: {", ".join(missing)} not in {FIRMWARE_DIR}')
        return 1
    for name, digest in measured.items():
        print(f'  {name}: {digest}')
    print('Candidate hashes only. Audit the ABI and addresses before adding a '
          'profile in probes/guestprofile.py; no profile was changed.')
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--kernelcache', help='image path; must match the selected profile')
    ap.add_argument('--guest-profile', default=PROFILE_NAME)
    ap.add_argument('--firmware-dir', help='directory containing the audited firmware bundle')
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--profile', action='store_true',
                    help='print the boot profile and check the firmware against it')
    ap.add_argument('--record', action='store_true',
                    help='print candidate hashes without certifying a new firmware profile')
    ap.add_argument('--guest-mib', type=int, default=DEFAULT_GUEST_MIB,
                    help=f'guest memory, in MiB (default {DEFAULT_GUEST_MIB})')
    ap.add_argument('--auxkc', help='kmutil AuxKC with its pinned .json manifest '
                    '(aux_collection_linked profiles only)')
    ap.add_argument('--trust-additions', help='JSON CDHash rows for an augmented trust-cache profile')
    ap.add_argument('--hide-amx', action='store_true', default=None,
                    help='clear application AMX-version capabilities; does not expose SME')
    ap.add_argument('--adreno-adopt', help='q1n1 `a16gpu.py adopt` record for an Adreno profile '
                    '(offline builds default to adreno.fixture_record())')
    args = ap.parse_args()
    try:
        configure_guest(args.guest_profile, args.firmware_dir)
    except ValueError as error:
        ap.error(str(error))
    kernelcache = args.kernelcache or DEFAULT_KERNELCACHE

    if args.record:
        return record_profile()

    if args.guest_mib != DEFAULT_GUEST_MIB:
        place(PHYS_BASE, guest_span=args.guest_mib << 20)

    bad = check_profile(kernelcache=kernelcache)
    if bad:
        print('the firmware is not what this profile was measured against:')
        for line in bad:
            print(f'  {line}')
        print('A different image needs an audited guest profile, not new hashes alone.')
        return 1

    if GUEST_PROFILE.adreno is not None:
        global ADRENO_RECORD
        import adreno
        import json
        configure_adreno_va_wide()
        if args.adreno_adopt:
            ADRENO_RECORD = json.loads(pathlib.Path(args.adreno_adopt).read_text())
            adreno.validate_adoption(ADRENO_RECORD, ADRENO_VA_WIDE)
        else:
            ADRENO_RECORD = adreno.fixture_record(wide=ADRENO_VA_WIDE)
            print('adreno    offline build: fixture adoption record (a run needs q1n1\'s)')
    built = build(kernelcache, args.verbose, auxkc=args.auxkc,
                  trust_additions=args.trust_additions, hide_amx=args.hide_amx)
    image, tables = built['image'], built['tables']
    total = sum(len(b) for b in built['chunks'].values())

    print(f'image     {image.vmin:#018x} .. {image.vmax:#018x}'
          f'   -> {IMAGE_PA:#x}   {built["mapped"] / (1 << 20):.1f} MiB mapped')
    print(f'upload    {len(built["chunks"])} chunks, {total / (1 << 20):.1f} MiB'
          f'  ({total / 2.6e6:.0f}s at the measured 2.6 MB/s)')
    print(f'tables    {tables.root:#x}, {len(tables.pages)} pages'
          f' ({tables.size / 1024:.0f} KiB), start level {start_level()}')
    print(f'entry     x0 = 0   x1 = {built["x1"]:#x}   x2 = {built["x2"]:#x}'
          f'   pc = {built["entry"]:#x}')
    print(f'tree      {built["devicetree_va"]:#x} +{built["devicetree_len"]:#x}'
          f'   clock-frequency {TIMEBASE_HZ / 1e6:.1f} MHz, '
          f'{built["dt_resolved"]} placeholders resolved')
    print(f'protect   {len(built["stub_pa"])} monitor pages '
          + ' '.join(f'{a:#x}' for a in built['stub_pa'])
          + f'   vectors {built["vbar_pa"]:#x}')
    for lo, hi, access, what in stage2_ranges():
        print(f'stage 2   {lo:#x} .. {hi:#x}  {access}  {what}')
    print('stage 2   + the work area, read-only, from q1n1\'s heap at run time; '
          'everything else absent, a touch stops the run with its IPA')

    if args.profile:
        print()
        print_profile(built)
        return 1 if bad else 0

    if tables.next > REGION_END or IMAGE_PA + built['mapped'] > TABLE_PA:
        print('\nFAILED: the layout does not fit the region it was given.')
        return 1

    if not args.check:
        return 0

    print('\nresolving every address the entry path touches:')
    bad = 0
    for label, va in critical(image):
        pa = tables.walk(va)
        want = IMAGE_PA + (va - image.vmin) if image.segment_of(va) else None
        ok = pa is not None and (want is None or pa == want)
        print(f'  {"ok " if ok else "FAIL"} {label:<20} {va:#018x} -> '
              f'{pa:#x}' if pa else f'  FAIL {label:<20} {va:#018x} -> unmapped')
        if not ok:
            bad += 1

    for label, va in (('x1 handoff', built['x1']), ('x2 handoff', built['x2'])):
        pa = tables.walk(va)
        ok = pa is not None
        print(f'  {"ok " if ok else "FAIL"} {label:<20} {va:#018x} -> '
              f'{pa:#x}' if pa else f'  FAIL {label:<20} {va:#018x} -> unmapped')
        if not ok:
            bad += 1

    # The magic has to be readable at the VA XNU will dereference, not just
    # present in a buffer somewhere.
    pa = tables.walk(built['x2'])
    blob = built['chunks'].get(pa & ~0xFFF) or built['chunks'].get(HANDOFF_PA)
    magic = struct.unpack_from('<Q', blob, 0)[0] if blob else 0
    ok = magic == HANDOFF_MAGIC
    print(f'  {"ok " if ok else "FAIL"} handoff magic        {magic:#018x}')
    bad += 0 if ok else 1

    if bad:
        print(f'\nFAILED: {bad} addresses do not resolve.')
        return 1
    print('\nEvery address the entry path is known to touch resolves through '
          'the 16K tables. Nothing has been uploaded; this is the offline check.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
