# SPDX-License-Identifier: MIT
"""Read native J700 26A428 saved EL0 registers without invoking guest code.

These are the last saved exception registers, not a live instruction trace.
The native exception vector authenticates thread+0x110, saves SP at+0x100,
and uses the ARM64 saved-state header (flavor21, count74).
"""
import struct

WITNESSES = (
    (0xfffffe000b86ecb0, 0xd538d080),  # current thread
    (0xfffffe000b86ecb4, 0x91044001),  # thread+0x110
    (0xfffffe000b86ecb8, 0xf9400020),  # saved-state pointer
    (0xfffffe000b86ecbc, 0xf2e3d221),  # pointer discriminator
    (0xfffffe000b86ecc0, 0xdac11820),  # authenticate
    (0xfffffe000b86ecc4, 0xd5384101),  # SP_EL0
    (0xfffffe000b86ecc8, 0xf9008001),  # save SP at+0x100
    (0xfffffe000b86ecd8, 0xa90087e0),  # x0,x1 at+8
    (0xfffffe000b86ec64, 0x528002a0),  # flavor21
    (0xfffffe000b86ec68, 0x52800941),  # count74
    (0xfffffe000b86ec6c, 0x290007e0),  # header pair
    (0xfffffe000b86f508, 0xd5384036),  # ELR_EL1
    (0xfffffe000b86f50c, 0xd5384017),  # SPSR_EL1
    (0xfffffe000b86f558, 0xf9008c14),  # FAR at+0x118
    (0xfffffe000b86f55c, 0xf9008416),  # PC at+0x108
    (0xfffffe000b86f560, 0xf9009015),  # ESR at+0x120
    (0xfffffe000b86f564, 0xb9011017),  # CPSR at+0x110
)


def make_reader(read, instruction):
    for address, word in WITNESSES:
        if instruction(address) != word:
            raise ValueError(f'user saved-state native witness differs at {address:#x}')

    def collect(thread, thread_data):
        if len(thread_data) < 0x118:
            raise ValueError('short native thread capture')
        raw_pointer, = struct.unpack_from('<Q', thread_data, 0x110)
        if not raw_pointer:
            return None
        pointer = raw_pointer | 0xffff000000000000
        if pointer & 15 or not 0xfffffe0000000000 <= pointer < pointer+0x130 <= 1 << 64:
            raise ValueError('saved user state pointer outside aligned kernel memory')
        header = read(pointer, 8)
        if struct.unpack('<II', header) != (21, 74):
            raise ValueError(f'native saved user state header differs for thread {thread:#x}: {header.hex()}')
        raw = read(pointer, 0x130)
        if raw[:8] != header:
            raise ValueError('saved user state changed during stopped capture')
        regs = struct.unpack_from('<29Q', raw, 8)
        fp, lr, sp, pc = struct.unpack_from('<4Q', raw, 0xf0)
        cpsr, = struct.unpack_from('<I', raw, 0x110)
        far, esr = struct.unpack_from('<2Q', raw, 0x118)
        if cpsr & 15:
            raise ValueError('saved user state is not EL0')
        return dict(address=hex(pointer), raw_pointer=hex(raw_pointer),
                    pc=hex(pc), sp=hex(sp), fp=hex(fp), lr=hex(lr),
                    cpsr=hex(cpsr), far=hex(far), esr=hex(esr),
                    registers={str(i): hex(v) for i, v in enumerate(regs)},
                    boundary='Last saved EL0 exception state; may precede current kernel execution')
    return collect
