#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Extract the reached permission-register contract from the shipped images.

This is a read-only binary witness, not a SPRR hardware emulator. In particular,
the per-class UMPRR fields do not by themselves specify write-mask semantics.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]
SPTM_SHA = 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
KERNEL_SHA = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
SPTM_BASE = 0xfffffff000000000
KERNEL_BASE = 0xfffffe0000000000

# Root flag3 -> UMPRR bit18; root flag0 -> bit11. User activation then
# initializes UPERM and PPERM. Startup also initializes PMPRR.
SPTM_WORDS = (
    (0x270af808, 0xf2e40200), (0x270af80c, 0xf2c00400),
    (0x270af810, 0xf2a60200), (0x270af814, 0xf2800000),
    (0x270af81c, 0xf2e00000), (0x270af820, 0xf2c00000),
    (0x270af824, 0xf2a00080), (0x270af828, 0xf2800200),
    (0x270af82c, 0xd51ef320),
    (0x27100694, 0x53114388), (0x27100698, 0x120e0108),
    (0x2710069c, 0x33150388), (0x271006a0, 0xd51ef308),
    (0x271006ac, 0xd2a60208), (0x271006b0, 0xf2c00408),
    (0x271006b4, 0xf2e40208), (0x271006b8, 0xd51ef1a8),
    (0x271006bc, 0xd2975cc8), (0x271006c0, 0xf2a60548),
    (0x271006c4, 0xf2d4a548), (0x271006c8, 0xf2e40408),
    (0x271006cc, 0xd51ef1c8),
    # SPTM startup assigns XNU_ROZONE (25) the PAPT selector2. RETYPE
    # consumes that initialized byte through its mapping-permission helper.
    (0x270e3d74, 0x5280004f), (0x270e3d78, 0x3901e5cf),
    (0x270e3d90, 0xf100651f), (0x270e3d94, 0x54ffff00),
    (0x270f8764, 0xd73f0911), (0x270f8768, 0x39000a95),
    (0x270f8770, 0x39401ae1), (0x270f8784, 0x97ff9ce6),
    (0x270dfd00, 0x12000ec9), (0x270dfd0c, 0x71000d3f),
    (0x270dfd14, 0x39400908), (0x270dfd28, 0x3941e508),
    (0x270dfd2c, 0xd34b2909), (0x270dfd30, 0xaa081128),
    (0x270dfd44, 0x927ac108), (0x270dfd48, 0x924b4908),
    (0x270dfd4c, 0xaa180108), (0x270dfd78, 0xf9000008),
    (0x270dfdb0, 0xd5033a9f), (0x270dfdcc, 0x94000036),
    (0x270dfdec, 0xd5033fdf),
)

# The same pmap byte (+0x75) gates CONFIGURE_ROOT(value=mask=8), SPRR
# thread-state restoration, and the index9 privileged-copy permission change.
# The fault path extracts a TWO-bit UMPRR field using the PTE class, then
# checks index9 against UPERM bits37:36. None of these reads may return zero
# merely because Snapdragon lacks the corresponding Apple register.
KERNEL_WORDS = (
    (0xba29380, 0x3901d614), (0xba293b8, 0x3901d614),
    (0xba293c8, 0x52800101), (0xba293cc, 0x52800102),
    (0xba293d0, 0x942008aa),
    (0xba6c04c, 0xd344fea8), (0xba6c050, 0x927e0509),
    (0xba6c054, 0xb375daa9), (0xba6c058, 0xd53ef308),
    (0xba6c05c, 0xd37ff92a), (0xba6c060, 0x9aca2508),
    (0xba6c064, 0xf240051f), (0xba6c06c, 0xf100253f),
    (0xba6c12c, 0xd53ef1aa), (0xba6c174, 0xf100253f),
    (0xba6c180, 0x925c0549), (0xba6c184, 0xd2c0060a),
    (0xba6c188, 0xeb0a013f),
    (0xba7c868, 0x3941d608), (0xba7c870, 0xd53ef1a8),
    (0xba7c874, 0xd2c0060a), (0xba7c878, 0xea28015f),
    (0xba7c888, 0xf2d4a748), (0xba7c890, 0xd51ef1c8),
    # The earlier native CPU0 stop grants selector2 kernel-data writes,
    # performs the copy, then restores read-only. Pin both sides of it.
    (0xba7319c, 0xd53ef1c8), (0xba731a0, 0xd2800169),
    (0xba731a4, 0xb3780d28), (0xba731a8, 0xd51ef1c8),
    (0xba731ac, 0xd5033fdf), (0xba731d4, 0x941f7e77),
    (0xba731d8, 0xd53ef1c8), (0xba731dc, 0xd2800149),
    (0xba731e0, 0xb3780d28), (0xba731e4, 0xd51ef1c8),
    (0xba731e8, 0xd5033fdf),
)


def require_words(read, base, witnesses):
    for low, expected in witnesses:
        actual = read(base | low)
        if actual != expected:
            raise ValueError(f'instruction mismatch at {base | low:#x}: '
                             f'{actual:#010x} != {expected:#010x}')


def mov_wide(read, start, count, register):
    """Decode complete A64 MOVZ/MOVK constant construction, not its spelling."""
    value = defined = 0
    for i in range(count):
        word = read(start + i * 4)
        opcode = word & 0xff800000
        if opcode not in (0xd2800000, 0xf2800000) or word & 31 != register:
            raise ValueError('not an A64 MOVZ/MOVK for the expected register')
        shift = ((word >> 21) & 3) * 16
        mask = 0xffff << shift
        if opcode == 0xd2800000:
            value, defined = 0, (1 << 64) - 1
        value = (value & ~mask) | (((word >> 5) & 0xffff) << shift)
        defined |= mask
    if defined != (1 << 64) - 1:
        raise ValueError('constant depends on unobserved incoming register bits')
    return value


def inspect():
    sptm_helper = runpy.run_path(str(ROOT / 'tools/sptm-dispatch.py'))
    kernel_helper = runpy.run_path(str(ROOT / 'tools/kc-disas.py'))
    sptm = sptm_helper['Image'](ROOT / 'downloads/extracted/j700ap/sptm.t8140.release')
    kernel = (ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes()
    for name, data, expected in (('SPTM', sptm.data, SPTM_SHA),
                                 ('kernel', kernel, KERNEL_SHA)):
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'{name} image does not match the selected 26A428 contract')
    segments = kernel_helper['segments'](kernel)

    def sr(va):
        return struct.unpack_from('<I', sptm.data, sptm.locate(va)[1])[0]

    def kr(va):
        offset = kernel_helper['locate'](segments, va)[1]
        if offset is None:
            raise ValueError(f'unmapped kernel instruction {va:#x}')
        return struct.unpack_from('<I', kernel, offset)[0]

    require_words(sr, SPTM_BASE, SPTM_WORDS)
    require_words(kr, KERNEL_BASE, KERNEL_WORDS)
    up = mov_wide(sr, SPTM_BASE | 0x271006ac, 3, 8)
    pp = mov_wide(sr, SPTM_BASE | 0x271006bc, 4, 8)
    startup_up = mov_wide(sr, SPTM_BASE | 0x270af808, 4, 0)
    pm = mov_wide(sr, SPTM_BASE | 0x270af81c, 4, 0)
    if startup_up != up:
        raise ValueError('startup and user activation UPERM constants disagree')
    type_va = SPTM_BASE | (0x2709e230 + 25 * 144)
    type_offset = sptm.locate(type_va)[1]
    raw_type = sptm.data[type_offset:type_offset + 144]
    type_name = sptm.string(sptm.pointer(SPTM_BASE | (0x2701e6b8 + 25 * 8)))
    if type_name != 'XNU_ROZONE' or raw_type[6] != 3 or raw_type[0x79] != 0:
        raise ValueError('ROZONE descriptor differs from the pinned startup contract')
    classes = []
    for index in range(16):
        # The shipped LSR/AND/BFXIL sequence gives [AP1 AP0 UXN PXN].
        classes.append(dict(index=index, ap=index >> 2, uxn=(index >> 1) & 1,
                            pxn=index & 1, uperm_nibble=(up >> (4 * index)) & 15,
                            pperm_nibble=(pp >> (4 * index)) & 15,
                            umprr_field_flag8=(0x40000 >> (2 * index)) & 3,
                            pmprr_field=(pm >> (2 * index)) & 3))
    return dict(kernel_sha256=KERNEL_SHA, sptm_sha256=SPTM_SHA,
                instruction_witnesses=len(SPTM_WORDS) + len(KERNEL_WORDS),
                registers=dict(UPERM=f'{up:016x}', PPERM=f'{pp:016x}',
                               PMPRR=f'{pm:016x}', UMPRR_flags_0a='0000000000040000'),
                kernel_data_copy=dict(selector=2, before_nibble=10,
                    write_nibble=11, restored_nibble=10,
                    grant_pc=hex(KERNEL_BASE | 0xba731a8),
                    copy_call_pc=hex(KERNEL_BASE | 0xba731d4),
                    restore_pc=hex(KERNEL_BASE | 0xba731e4),
                    changed_pperm=f'{(pp & ~(15 << 8)) | (11 << 8):016x}'),
                rozone_aperture=dict(frame_type=25, name=type_name,
                    descriptor_va=hex(type_va), runtime_selector_offset=0x79,
                    file_selector=raw_type[0x79], initialized_selector=2,
                    retype_permission_argument=raw_type[6],
                    initialization_store_pc=hex(SPTM_BASE | 0x270e3d78),
                    retype_mapping_call_pc=hex(SPTM_BASE | 0x270f8784),
                    mapping_selector_read_pc=hex(SPTM_BASE | 0x270dfd28)),
                classes=classes,
                qualification='binary evidence only; native execution requires a separate runtime audit',
                not_established_by_this_tool=['UMPRR write filtering semantics',
                            'correct implementation of per-CPU register state and context switching',
                            'effective shadow permissions and TLB updates for changed classes'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    result = inspect()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"PASS: {result['instruction_witnesses']} instruction witnesses; both image hashes match")
        for name, value in result['registers'].items():
            print(f'{name}: {value}')
        print('Root flag8 selects UMPRR field9; the kernel consults UPERM bits37:36 for that class.')
        print(result['qualification'])
