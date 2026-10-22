#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read queue counters behind pinned native IPC-send blocking frames.

The caller must supply stopped, audited J700 process frames and a bounded
kernel reader. This collector opens no transport and writes no guest state.
"""
import struct

WAIT_EVENT = 0xfffffe0007010b1c
RETURN_PC = 0xfffffe000b89d534
WITNESSES = (
    (0xfffffe000b92fea0, 0xa9054ff4),  # save x20/x19 at FP-16/FP-8
    (0xfffffe000b92fea4, 0xa9067bfd),
    (0xfffffe000b92fea8, 0x910183fd),
    (0xfffffe000b89d070, 0xaa0003f4),  # x20 = mqueue
    (0xfffffe000b89d074, 0xd100a013),  # x19 = mqueue - 0x28 (port)
    (0xfffffe000b89d078, 0x79402008),  # u16 msgcount at mqueue+0x10
    (0xfffffe000b89d07c, 0x79402409),  # u16 qlimit at mqueue+0x12
    (0xfffffe000b89d530, 0x94024a57),  # call the pinned blocking function
    (0xfffffe000b89d4d0, 0xf0fdbb81),  # IPC_MQUEUE_FULL event address
    (0xfffffe000b89d4d4, 0x912c7021),
)

# Native typed PAC access chains, not offsets borrowed from another kernel.
# port.io_state: byte1 bits0..2, in-space states1/2; port+0x48 -> space,
# space+0x50 -> task, task+0x318 -> space. Discriminators match Apple's field
# names ipc_port.ip_receiver / ipc_space.is_task / task.itk_space.
RECEIVER_WITNESSES = (
    (0xfffffe000b8960c8, 0x39400688),
    (0xfffffe000b8960cc, 0x72000908),
    (0xfffffe000b8960d0, 0x540005c0),
    (0xfffffe000b8960e4, 0x7100091f),
    (0xfffffe000b8960e8, 0x540004e8),
    (0xfffffe000b8960ec, 0xaa1403e8),
    (0xfffffe000b8960f0, 0xf8448d10),
    (0xfffffe000b8960f4, 0xaa0803f1),
    (0xfffffe000b8960f8, 0xf2f2fed1),
    (0xfffffe000b8960fc, 0xdac11a30),
    (0xfffffe000b896100, 0xf8450e08),
    (0xfffffe000b896104, 0xb4000408),
    (0xfffffe000b896108, 0xaa1003f1),
    (0xfffffe000b89610c, 0xaa0803f0),
    (0xfffffe000b896110, 0xf2f8a8f1),
    (0xfffffe000b896114, 0xdac11a30),
    (0xfffffe000b892bac, 0xf9418c10),
    (0xfffffe000b892bb0, 0xb4000110),
    (0xfffffe000b892bb4, 0x910c6011),
    (0xfffffe000b892bb8, 0xf2f05011),
    (0xfffffe000b892bbc, 0xdac11a30),
)


def pointer(value, alignment=8):
    if not 0xfffffe0000000000 <= value < 0xfffffffffffff000 or value % alignment:
        raise ValueError('unaligned or noncanonical kernel pointer')
    return value


def receiver(port, queue_raw, processes, read):
    def exact(address, size):
        raw = read(address, size)
        if len(raw) != size:
            raise ValueError('short IPC receiver read')
        return raw
    def pac_pointer(raw):
        value, = struct.unpack('<Q', raw)
        return pointer(value | 0xffff000000000000 if value else 0)
    raw = exact(port, 0x50)
    state = raw[1] & 7
    if state not in (1, 2):
        raise ValueError('port does not hold an in-space receive right')
    if raw[0x38:0x3c] != queue_raw:
        raise ValueError('receiver port queue counters differ')
    space = pac_pointer(raw[0x48:0x50])
    task_raw = exact(space+0x50, 8)
    task = pac_pointer(task_raw)
    matches = [p for p in processes if p.get('task_present') and int(p['task'], 16) == task]
    if len(matches) != 1:
        raise ValueError('receiver task does not uniquely match the captured process inventory')
    reverse = exact(task+0x318, 8)
    if pac_pointer(reverse) != space:
        raise ValueError('receiver task-space reciprocal link differs')
    process = matches[0]
    return dict(pid=process['pid'], name=process['name'], task=hex(task), space=hex(space),
                port_state=state, port_header_hex=raw.hex(), space_task_hex=task_raw.hex(),
                task_space_hex=reverse.hex(),
                boundary='Typed native field accesses and reciprocal task-space links match '
                         'the captured process inventory. PAC stripped for lookup, not authenticated; '
                         'receiver identity alone does not establish service readiness or deadlock.')


def collect(processes, read, instruction, *, receivers=False):
    for address, word in WITNESSES + (RECEIVER_WITNESSES if receivers else ()):
        if instruction(address) != word:
            raise ValueError(f'native IPC send witness differs at {address:#x}')
    result = []
    for process in processes:
        for thread in process['threads']:
            if thread.get('on_cpu') or int(thread['wait_event'], 16) != WAIT_EVENT:
                continue
            frames = [f for f in thread.get('frames', []) if int(f['raw_lr'], 16) == RETURN_PC]
            if not frames:
                continue
            row = dict(pid=process['pid'], name=process['name'], tid=thread['tid'],
                       wait_event=hex(WAIT_EVENT), return_pc=hex(RETURN_PC))
            try:
                if len(frames) != 1:
                    raise ValueError('ambiguous native IPC-send frame')
                fp = pointer(int(frames[0]['fp'], 16), 16)
                stack = pointer(int(thread.get('kernel_stack', '0x0'), 16))
                if not stack <= fp-16 < fp+16 <= stack+0x4000:
                    raise ValueError('IPC-send saved registers outside captured kernel stack')
                raw = read(fp-16, 32)
                if len(raw) != 32:
                    raise ValueError('short IPC-send frame read')
                mqueue, port, parent, lr = struct.unpack('<4Q', raw)
                pointer(port)
                if (mqueue != port+0x28 or lr != RETURN_PC or
                        not fp < parent < parent+16 <= stack+0x4000 or parent & 15):
                    raise ValueError('IPC-send frame register/return relationship differs')
                raw_queue = read(mqueue+0x10, 4)
                if len(raw_queue) != 4:
                    raise ValueError('short IPC-send queue counter read')
                count, limit = struct.unpack('<2H', raw_queue)
                row.update(frame_fp=hex(fp), frame_hex=raw.hex(), port=hex(port),
                           mqueue=hex(mqueue), queue_counter_hex=raw_queue.hex(),
                           message_count=count, queue_limit=limit, at_or_above_limit=count >= limit)
                if receivers:
                    try:
                        row['receiver'] = receiver(port, raw_queue, processes, read)
                    except ValueError as error:
                        row['receiver_error'] = str(error)
            except ValueError as error:
                row['error'] = str(error)
            result.append(row)
    out = dict(waits=result,
                boundary='Stopped native IPC-send blocking frames and current queue counters. '
                         'A shared event address does not identify a shared destination. '
                         'Receiver identity and deadlock are not established.')
    if receivers:
        out['receiver_layout_witnesses'] = [dict(address=hex(a), word=hex(w)) for a, w in RECEIVER_WITNESSES]
        out['boundary'] = ('Stopped native IPC-send frames, current queues and optional individually '
                           'qualified receiver records. Failed receiver reads remain errors; '
                           'a full queue or identified receiver does not establish deadlock.')
    return out
