#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only process/thread inventory for the pinned J700 26A428 kernel.

Call only after checking the kernel hash and the stopped monitor state.
Layout evidence: proc_find bebe350..390 (SMR PID hash, link at proc+a0),
proc_pid bebed00 (+60), proc_name bec0d58 (+5bc), proc_task bec122c..238
(task at proc+7c0, flags458 bit1), get_bsdtask_info b984934..93c
(task flags6e0 bit0), proc_ppid bec01c8 (+20). Thread queues use the
independently captured layout.
Addresses below are guest virtual addresses, never host pointers.
"""
import struct

PID_HASH = 0xfffffe000c829bb8


def pid_hash(pid):
    value = (pid ^ (pid >> 16)) * 0x7feb352d & 0xffffffff
    value = (value ^ (value >> 15)) * 0x846ca68b & 0xffffffff
    return value ^ (value >> 16)


def collect(read, describe, on_cpu, pid_limit=64, *, user_state=None, scheduler_state=None):
    if not 1 <= pid_limit <= 256:
        raise ValueError('invalid PID capture bound')
    def q(address):
        return struct.unpack('<Q', read(address, 8))[0]
    def canonical(value):
        return value | 0xffff000000000000 if value else 0
    encoded = q(PID_HASH)
    mask = ((1 << 64)-1) >> ((encoded >> 48) & 63)
    table = encoded | 0x00ff000000000000
    if mask > 0xfffff or table < 0xffff000000000000 or table & 7:
        raise ValueError('invalid native PID hash geometry')
    processes = []
    for pid in range(1, pid_limit+1):
        node = q(table+8*(pid_hash(pid) & mask))
        seen = set()
        while node:
            if node in seen or len(seen) >= 256 or node < 0xffff0000000000a0:
                raise ValueError('cyclic or oversized PID bucket')
            seen.add(node)
            candidate, = struct.unpack('<I', read(node-0x40, 4))
            if candidate == pid:
                break
            node = q(node)
        if not node:
            continue
        proc = node-0xa0
        raw = read(proc, 0xea8)
        if struct.unpack_from('<I', raw, 0x60)[0] != pid:
            raise ValueError('process identity changed')
        name = raw[0x5bc:0x5bc+17].split(b'\0', 1)[0].decode('utf-8', 'replace')
        ppid, = struct.unpack_from('<i', raw, 0x20)
        if ppid < 0:
            raise ValueError('invalid native parent process identity')
        row = dict(pid=pid, ppid=ppid, proc=hex(proc), name=name, threads=[])
        if not raw[0x458] & 2:
            row['task_present'] = False
            processes.append(row)
            continue
        task = proc+0x7c0
        if not struct.unpack_from('<I', raw, 0x7c0+0x6e0)[0] & 1:
            raise ValueError('native task-to-process reverse mapping differs')
        head = task+0x50
        first, last = struct.unpack_from('<2Q', raw, 0x7c0+0x50)
        count, = struct.unpack_from('<I', raw, 0x7c0+0x78)
        if count > 128:
            raise ValueError('process thread capture bound exceeded')
        seen, previous, thread = set(), head, first
        while thread != head:
            if thread in seen or len(seen) >= count:
                raise ValueError('cyclic or oversized process thread queue')
            seen.add(thread)
            data = read(thread, 0x8c0)
            get = lambda off: struct.unpack_from('<Q', data, off)[0]
            next_, prev = get(0x410), get(0x418)
            if prev != previous or not 0 < get(0x510) < 1 << 32:
                raise ValueError('process thread queue reciprocity or identity differs')
            item = dict(thread=hex(thread), tid=get(0x510),
                        wait_event=hex(get(0x18)), on_cpu=thread in on_cpu,
                        continuation=describe(get(0xe0)),
                        continuation_raw=hex(get(0xe0)))
            if scheduler_state is not None:
                item['scheduler_state'] = scheduler_state(data)
            stack, ctx = canonical(get(0xf0)), canonical(get(0x158))
            item['kernel_stack'] = hex(stack)
            if not get(0xe0) and thread not in on_cpu and stack and stack <= ctx < ctx+0xb8 <= stack+0x4000:
                saved = read(ctx, 0xb8)
                fp, lr, sp = struct.unpack_from('<3Q', saved, 0x50)
                item['saved_context'] = dict(fp=hex(fp), lr=hex(lr), sp=hex(sp))
                frames = []
                while stack <= fp < fp+16 <= stack+0x4000 and not fp & 15 and len(frames) < 48:
                    next_fp, return_pc = struct.unpack('<2Q', read(fp, 16))
                    frames.append(dict(fp=hex(fp), raw_lr=hex(return_pc), return_to=describe(return_pc)))
                    if next_fp <= fp:
                        break
                    fp = next_fp
                item['frames'] = frames
            if user_state is not None:
                item['saved_user_state'] = user_state(thread, data)
            row['threads'].append(item)
            previous, thread = thread, next_
        if len(seen) != count or previous != last:
            raise ValueError('process thread count or tail differs')
        row.update(task_present=True, task=hex(task), thread_count=count)
        processes.append(row)
    return dict(pid_limit=pid_limit, hash_mask=hex(mask), processes=processes)
