#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real q1n1 wire/guard/thermal-collector integration, without hardware.

Failure inventory (before this replay): docs/A16-CPU-POLICY-20261018.md and
docs/A16-CPU-POLICY-REVIEW-20261018.md. Nonclear SError or unknown TSENS revision
must freeze before cleanup; cached/raw requests and scratch restoration must
not revive I/O. A valid over-threshold reading is a known thermal refusal, not
an unknown native result. Every case must still allow local transport close.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    if args.output.exists():
        ap.error('output already exists')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    replay = runpy.run_path(str(ROOT / 'tools/replay-a16-control-guard.py'))
    policy = runpy.run_path(str(ROOT / 'tools/qualify-a16-cpu-policy.py'))
    guard_module = replay['module']('thermal_guard_replay', ROOT / 'tools/a16-control-guard.py')
    q = policy['run'].q1n1
    result = dict(schema='a16-thermal-guard-wire-replay-v1', hardware=False, cases=[])

    def case(name):
        record = dict(name=name)
        memory = {}
        for tm, srot in policy['thermal']['BLOCKS']:
            memory[srot] = 0x30020000 if name != 'unknown-revision' else 0x90000000
            memory[srot + 4] = (0xffff << 3) | (1 << 21) | 1
            memory[tm + 0xe4] = 1
            for n in range(16):
                memory[tm + 0xa0 + 4 * n] = ((1 << 21) | (460 if name == 'hot' else 330)) \
                    if name != 'invalid-coverage' else 0
        error_words = {key: 0 for key in q.SERROR_FIELDS}
        error_words.update(magic=q.SERROR_MAGIC, mechanism=1, flags=1, checks=1)
        if name in ('before', 'during', 'unconsumed'):
            error_words[name] = 1
        error_blob = struct.pack('<12Q', *(error_words[k] for k in q.SERROR_FIELDS))

        class Transport:
            def __init__(self):
                self.queue = bytearray(); self.trace = []; self.closed = False
            def close(self): self.closed = True
            def frame(self, command, data):
                prefix = struct.pack('<Ii24s', command, 0, data.ljust(24, b'\0'))
                return prefix + struct.pack('<I', q.checksum(prefix))
            def write(self, data):
                assert len(data) == 64 and q.checksum(data[:-4]) == struct.unpack('<I', data[-4:])[0]
                command = struct.unpack_from('<I', data)[0]
                if command == q.REQ_PROXY:
                    opcode, *a = struct.unpack_from('<7Q', data, 4)
                    self.trace.append(dict(command=command, opcode=opcode, address=a[0]))
                    assert opcode in (q.Proxy.P_READ32, q.Proxy.P_Q1N1_SERROR)
                    value = 0x8000 if opcode == q.Proxy.P_Q1N1_SERROR else memory[a[0]]
                    self.queue.extend(self.frame(command, struct.pack('<QqQ', opcode, 0, value)))
                else:
                    assert command == q.REQ_MEMREAD
                    address, size = struct.unpack_from('<QQ', data, 4)
                    self.trace.append(dict(command=command, address=address, size=size))
                    assert address == 0x8000 and size == len(error_blob)
                    self.queue.extend(self.frame(command, struct.pack('<I', q.checksum(error_blob))))
                    self.queue.extend(error_blob)
            def read(self, size, timeout):
                assert len(self.queue) >= size
                data = bytes(self.queue[:size]); del self.queue[:size]
                return data

        transport = Transport()
        proxy = q.Proxy(q.Link('offline-only', transport=transport))
        saves = []
        guard = guard_module.ControlGuard(proxy, record, lambda: saves.append(json.loads(json.dumps(record))))
        p = guard.proxy
        cached = p.read32
        error = None
        try:
            policy['temperature_snapshot'](p, record, name, lambda: None, guard=guard)
        except BaseException as exc:
            error = f'{type(exc).__name__}: {exc}'
        frozen = name in ('unknown-revision', 'before', 'during', 'unconsumed')
        assert guard.frozen == frozen
        assert (error is None) == (name == 'normal')
        at = len(transport.trace)
        scratch_calls = []
        class Scratch:
            def restore(self):
                scratch_calls.append(True)
                p.write32(0x9000, 0)
                return dict(restored=True)
        restoration = None
        if frozen:
            restoration = guard.restore_scratch(Scratch())
            for operation in (lambda: cached(0x9000), lambda: p.serror_state(),
                              lambda: p.serror_strict(False), lambda: p.call(0x1000),
                              lambda: proxy.request(q.Proxy.P_READ32, 0x9000)):
                try: operation()
                except BaseException: pass
                else: raise AssertionError('frozen operation unexpectedly succeeded')
            assert not scratch_calls and not restoration['restored']
            assert len(transport.trace) == at
        guard.close()
        assert transport.closed
        return dict(name=name, passed=True, error=error, frozen=guard.frozen, reason=guard.reason,
                    target_requests=len(transport.trace), target_requests_after_failure=len(transport.trace)-at,
                    scratch=restoration, local_close=transport.closed, wire_trace=transport.trace,
                    record=record)

    for name in ('normal', 'hot', 'invalid-coverage', 'unknown-revision', 'before', 'during', 'unconsumed'):
        result['cases'].append(case(name))
    result['passed'] = all(x['passed'] for x in result['cases'])
    sources = ['tools/qualify-a16-cpu-policy.py', 'tools/a16-control-guard.py',
               'tools/a16-thermal-survey.py', 'tools/replay-a16-control-guard.py',
               'tools/replay-a16-thermal-guard.py', '../q1n1/tools/q1n1proxy.py']
    result['sources'] = {f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in sources}
    replay['save_json'](args.output, result)
    print(json.dumps(dict(passed=result['passed'], cases=len(result['cases']), artifact=str(args.output),
                         frozen_cases=sum(x['frozen'] for x in result['cases']))))


if __name__ == '__main__':
    main()
