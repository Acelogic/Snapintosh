# SPDX-License-Identifier: MIT
"""Pinned J700 guest topology, collected through an already-audited RAM reader.

The caller must verify the kernel identity and stopped monitor. This module
opens no transport and makes no assumptions about physical guest placement.
"""
import struct

BOOTARGS = 0xfffffe0007ebf208
NUM_CPUS = 0xfffffe0007e2c654
CPU_SIGNAL = 0xfffffe000c6fa778
MACHINE_INIT = 0xfffffe000c738510
CPU_DATA = 0xfffffe000c738768
PMAP_CPU = 0xfffffe000c6f8000

# Native secondary-entry table geometry, consumed cpu_data fields, and boot
# pmap CPU_ID/OUTPUT_AREA stores. These are separate per-CPU structures.
WITNESSES = {
    0xfffffe000c2640d4: 0x900026a1,
    0xfffffe000c2640d8: 0x911da021,
    0xfffffe000c2640e8: 0xf2800213,
    0xfffffe000c2640ec: 0xd28000c4,
    0xfffffe000c2640f8: 0xf9400435,
    0xfffffe000c264100: 0xb941caa2,
    0xfffffe000c264120: 0xf94016aa,
    0xfffffe000c26412c: 0xf9400eaa,
    0xfffffe000c26413c: 0xf9405ea2,
    0xfffffe000ba78838: 0x90006409,
    0xfffffe000ba7883c: 0x91000129,
    0xfffffe000ba78918: 0x793a52a0,
    0xfffffe000ba78950: 0xf90002a0,
}


def collect(read, physical_read, code32, *, loader_bootargs_pa, result_area_va):
    for va, word in WITNESSES.items():
        if code32(va) != word:
            raise ValueError(f'native CPU topology layout differs at {va:#x}')

    def unpack(fmt, address):
        return struct.unpack(fmt, read(address, struct.calcsize(fmt)))

    def pointer(value):
        if not 0xffff800000000000 <= value < 1 << 64 or value & 7:
            raise ValueError('invalid native topology pointer')
        return value

    def command_line(raw):
        if b'\0' not in raw:
            raise ValueError('unterminated native command line')
        return raw.split(b'\0', 1)[0].decode('ascii')

    def video(raw):
        base,display,stride,width,height,depth=struct.unpack('<6Q',raw)
        return dict(base=hex(base),display=display,stride=stride,width=width,height=height,depth=depth)

    bootargs = pointer(unpack('<Q', BOOTARGS)[0])
    count = unpack('<I', NUM_CPUS)[0]
    if not 1 <= count <= 6:
        raise ValueError('native CPU count outside pinned profile')
    slot = unpack('<H', PMAP_CPU+0x1d28)[0]
    output = unpack('<Q', PMAP_CPU)[0]
    if slot != 0 or output != result_area_va:
        raise ValueError('boot pmap CPU disagrees with monitor result area')
    result = dict(
        num_cpus=count, cpu_signal=hex(unpack('<I', CPU_SIGNAL)[0]),
        machine_init_completed_mask=hex(unpack('<Q', MACHINE_INIT)[0]),
        bootargs_va=hex(bootargs),
        loader_command_line=command_line(physical_read(loader_bootargs_pa+0x6c, 1024)),
        kernel_command_line=command_line(read(bootargs+0x6c, 1024)),
        loader_video=video(physical_read(loader_bootargs_pa+0x28,48)),
        kernel_video=video(read(bootargs+0x28,48)),
        boot_pmap_cpu=dict(slot=slot, result_area_va=hex(output),
                           matches_monitor_parameter=True), cpu_data_entries=[])
    for index in range(6):
        data_pa, data_va = unpack('<QQ', CPU_DATA+index*16)
        item = dict(index=index, data_pa=hex(data_pa), data_va=hex(data_va))
        if bool(data_va) != bool(data_pa):
            raise ValueError('native CPU data pointer pair is incomplete')
        if data_va:
            raw = read(pointer(data_va), 0x1d0)
            # Read both aliases: no stale physical/virtual pair is accepted.
            if physical_read(data_pa, len(raw)) != raw:
                raise ValueError('native CPU data physical and virtual aliases differ')
            item.update(
                physical_id=struct.unpack_from('<I', raw, 0x1c8)[0],
                logical_id=struct.unpack_from('<I', raw, 0x40)[0],
                intstack_top=hex(struct.unpack_from('<Q', raw, 0x18)[0]),
                excepstack_top=hex(struct.unpack_from('<Q', raw, 0x28)[0]),
                reset_handler=hex(struct.unpack_from('<Q', raw, 0xb8)[0]),
                thread=hex(struct.unpack_from('<Q', raw, 0x30)[0]))
        result['cpu_data_entries'].append(item)
    result['boundary'] = ('Native stopped-state topology and command lines; '
                          'not proof of current execution or GUI presentation.')
    return result
