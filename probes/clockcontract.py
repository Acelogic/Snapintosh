# SPDX-License-Identifier: MIT
"""Conservative admission check for a scaled kernel counter domain.

CNTFRQ remains the host frequency: EL2 cannot generally trap an EL1 read or
write the EL3-owned register. A different guest rate therefore requires an
audited kernel using its DT timebase instead. This scan is an additional guard
on the hash-qualified image, not proof about dynamically loaded or user code.
"""
import struct


def validate_counter_image(data, executable_segments, host_hz, guest_hz):
    if not all(isinstance(hz, int) and 0 < hz <= 0xffffffff
               for hz in (host_hz, guest_hz)):
        raise ValueError('counter frequencies must be nonzero u32 Hz')
    scanned = 0
    for name, va, vmsize, offset, size in executable_segments:
        if (min(va, vmsize, offset, size) < 0 or size > vmsize or
                offset + size > len(data) or (va | offset | size) & 3):
            raise ValueError(f'invalid executable counter-audit range {name}')
        for pos in range(offset, offset + size, 4):
            word, = struct.unpack_from('<I', data, pos)
            # MRS/MSR CNTFRQ_EL0, any general register (including XZR).
            if host_hz != guest_hz and word & 0xffdfffe0 == 0xd51be000:
                raise ValueError(f'scaled counter cannot virtualize CNTFRQ_EL0 '
                                 f'at {va + pos - offset:#x} in {name}')
        scanned += size // 4
    if not scanned:
        raise ValueError('counter audit has no executable instructions')
    return scanned
