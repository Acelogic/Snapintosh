#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode saved mach_msg2 arguments from an existing, audited stopped capture.

No target connection is opened. A same-prefix CPU snapshot supplies a unique
64-byte cache-code match; the native trap stub guards the saved-register ABI.
Message IDs and process-local port names do not identify a receiving service.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy

Cache = runpy.run_path(str(Path(__file__).with_name('dyld-cache.py')))['Cache']
LIBKERNEL = '/usr/lib/system/libsystem_kernel.dylib'
TRAP_BYTES = bytes.fromhex('d0058092011000d4c0035fd6')
MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1


def number(value):
    result = int(value, 0) if isinstance(value, str) else int(value)
    if not 0 <= result <= MASK64:
        raise ValueError('register value outside uint64')
    return result


def validate_pair(capture_path, snapshot_path, capture, snapshot):
    suffix = '-kernel-waits.json'
    if not capture_path.name.endswith(suffix):
        raise ValueError('expected a kernel-waits capture filename')
    prefix = capture_path.name[:-len(suffix)]
    if not re.fullmatch(re.escape(prefix) + r'-cpu[0-5]-stop\.json', snapshot_path.name):
        raise ValueError('snapshot must have the same run prefix')
    if capture_path.resolve().parent != snapshot_path.resolve().parent:
        raise ValueError('snapshot and capture must belong to the same directory')
    identity = capture.get('monitor_sha256')
    if not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity):
        raise ValueError('capture has no valid monitor identity')
    if snapshot.get('monitor_sha256') != identity:
        raise ValueError('monitor identity differs between captures')
    if snapshot.get('user_mapping_qualified') is not True:
        raise ValueError('snapshot user mappings were not qualified')
    if number(snapshot['pstate']) & 0xf:
        raise ValueError('slide witness is not an EL0 snapshot')


def decode_state(state, trap_return):
    if number(state['pc']) != trap_return:
        return None
    regs = state['registers']
    # MOV X16, #-47; SVC #0x80; RET. EL0 exception PC points at RET.
    if (number(state['cpsr']) & 0xf or number(state['esr']) != 0x56000080
            or number(regs['16']) != MASK64 - 46):
        raise ValueError('saved state at mach_msg2 return fails the trap ABI')
    r = [number(regs[str(i)]) for i in range(8)]
    lo = lambda x: x & MASK32
    hi = lambda x: x >> 32
    options, bits = r[1], lo(r[2])
    message_id = hi(r[4])
    if message_id & (1 << 31):
        message_id -= 1 << 32
    send = bool(options & 1)
    receive = bool(options & 2)
    vector = bool(options & (1 << 32))
    result = dict(
        data=hex(r[0]), options=hex(options), send=send, receive=receive,
        vector=vector, send_timeout_enabled=bool(options & 0x10),
        destination_policy={1 << 33: 'kernel_object', 1 << 34: 'message_queue',
                            1 << 35: 'any', 1 << 36: 'driverkit'}.get(
                                options & (0xf << 33), 'other'),
        receive_name=hex(hi(r[5])), timeout=lo(r[7]),
        priority=hi(r[6]))
    # Vector mode stores vector counts here, not byte lengths.
    result['send_vector_count' if vector else 'send_size'] = hi(r[2])
    result['receive_vector_count' if vector else 'receive_size'] = lo(r[6])
    if send:
        result.update(bits=hex(bits), message_id=message_id,
                      complex=bool(bits & (1 << 31)),
                      remote_port=hex(lo(r[3])), local_port=hex(hi(r[3])),
                      voucher_port=hex(lo(r[4])))
        if bits & (1 << 31):
            result['descriptor_count'] = lo(r[5])
    return result


def summarize(capture, trap_return):
    messages = []
    for process in capture['user_processes']['processes']:
        for thread in process.get('threads', []):
            state = thread.get('saved_user_state')
            if not state or 'pc' not in state:
                continue
            decoded = decode_state(state, trap_return)
            if decoded is not None:
                messages.append(dict(pid=process['pid'], name=process['name'],
                                     tid=thread['tid'], wait_event=thread.get('wait_event'),
                                     saved_call=decoded))
    return messages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    args = parser.parse_args()
    raw = args.capture.read_bytes()
    snapshot_raw = args.snapshot.read_bytes()
    capture, snapshot = json.loads(raw), json.loads(snapshot_raw)
    validate_pair(args.capture, args.snapshot, capture, snapshot)
    with Cache(args.cache) as cache:
        match = cache.match_code(number(snapshot['pc']),
                                 bytes.fromhex(snapshot['instruction']['data_hex']))
        if match['slide'] < 0 or match['slide'] % 0x4000:
            raise ValueError('cache slide is not a nonnegative 16 KiB multiple')
        symbols = {row[0] for row in cache.symbols(LIBKERNEL)
                   if row[1] == '_mach_msg2_trap'}
        if len(symbols) != 1:
            raise ValueError('cache has no unique mach_msg2_trap symbol')
        trap = symbols.pop()
        if cache.read(trap, len(TRAP_BYTES)) != TRAP_BYTES:
            raise ValueError('native mach_msg2 trap instructions differ')
        report = dict(
            capture=str(args.capture), capture_sha256=hashlib.sha256(raw).hexdigest(),
            snapshot=str(args.snapshot), snapshot_sha256=hashlib.sha256(snapshot_raw).hexdigest(),
            monitor_sha256=capture['monitor_sha256'], kernel_sha256=capture['kernel_sha256'],
            code_match=match, libkernel_uuid=cache.image(LIBKERNEL)['uuid'],
            trap=hex(trap), trap_bytes=TRAP_BYTES.hex(),
            messages=summarize(capture, trap + match['slide'] + 8),
            boundary='Saved EL0 arguments may precede current kernel execution. '
                     'Port names belong to each process; equal IDs or wait events '
                     'do not prove a common receiver, queue fullness, or deadlock.')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
