#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay four production observation phases using captured parent registers."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = [ROOT / 'build/fan-gpi-20261018' / name for name in
            ('dma-identity-current.json', 'dma-streams-current.json',
             'dma-context-bank1-current.json')]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    if args.output.exists():
        ap.error('output exists; retain evidence')
    capture = runpy.run_path(str(ROOT / 'tools/a16-fan-dma-survey.py'))['capture']
    guards = runpy.run_path(str(ROOT / 'tools/a16-control-guard.py'))
    cases = ('enabled_stage2', 'disabled_stage2', 'fault_separate_from_format',
             'changed_parent', 'invalid_link', 'self_link', 'wrong_stage2_type',
             'changed_stage2_ttbr', 'lost_reply', 'exception_callback')
    receipt = dict(scope='offline four-phase replay; captured parent, synthetic linked bank', cases=[])
    for case in cases:
        registers = {}
        for path in FIXTURES:
            for row in json.loads(path.read_text())['reads']:
                registers[int(row['address'], 0)] = row['value']
        linked = {0x150011ac: 3, 0x150019ac: 1,
                  0x150eb000: 0xe1, 0x150eb004: 0,
                  0x150eb020: 0x88000000, 0x150eb024: 0,
                  0x150eb030: 0x80023558,
                  0x150eb058: 0x400, 0x150eb060: 0, 0x150eb064: 0,
                  0x150eb068: 0, 0x150eb06c: 0, 0x150eb7f4: 0}
        if case == 'disabled_stage2':
            linked[0x150eb000] &= ~1
        if case == 'fault_separate_from_format':
            linked[0x150eb058] = 0x402
        if case == 'wrong_stage2_type':
            linked[0x150011ac] = 0x10003
        if case == 'invalid_link':
            registers[0x15001004] = 0x36f03
        if case == 'self_link':
            registers[0x15001004] = 0x30103
        registers.update(linked)
        operations, records, closes, seen = [], [], [], {}
        phase = None

        class Link:
            def close(self):
                closes.append(True)

            def exception_handler(self, *args):
                raise AssertionError('default exception handler ran')

        class Proxy:
            P_CALL = 3

            def __init__(self):
                self.link = Link()

            def request(self, *args, **kwargs):
                raise AssertionError('unexpected request/native call')

            def bootinfo(self):
                operations.append(dict(phase=phase, operation='bootinfo'))
                return dict(current_el=2, image_base=0xb0000000, stage_generation=1)

            def serror_state(self):
                operations.append(dict(phase=phase, operation='serror'))
                return dict(before=0, during=0, unconsumed=0)

            def read32(self, address):
                operations.append(dict(phase=phase, operation='read32', address=hex(address)))
                key = (phase, address)
                seen[key] = seen.get(key, 0) + 1
                if phase == 'linked' and address in linked:
                    if case == 'lost_reply':
                        raise TimeoutError('injected linked register timeout')
                    if case == 'exception_callback':
                        self.link.exception_handler(2, 0xdead)
                    if case == 'changed_stage2_ttbr' and address == 0x150eb024 and seen[key] == 2:
                        return 1
                return registers[address]

        identity = streams = context_capture = None
        for phase in ('identity', 'streams', 'context', 'linked'):
            if phase == 'linked' and case == 'changed_parent':
                registers[0x15001004] ^= 0x100
            record = dict(phase=phase, status='STARTING', reads=[])
            guard = guards['ControlGuard'](Proxy(), record, lambda: None)
            try:
                capture(guard.proxy, record, lambda: None, 1, 0xb0000000,
                        time.monotonic() + 10, identity, streams, context_capture)
                if phase == 'identity':
                    identity = record
                elif phase == 'streams':
                    streams = record
                elif phase == 'context':
                    context_capture = record
            except Exception as exc:
                assert phase == 'linked' and case not in (
                    'enabled_stage2', 'disabled_stage2', 'fault_separate_from_format'), str(exc)
                guard.freeze(str(exc))
                before = len(operations)
                try:
                    guard.proxy.serror_state()
                except guards['Frozen']:
                    pass
                else:
                    raise AssertionError('target I/O escaped frozen guard')
                assert len(operations) == before
                record.update(status='REFUSED_OR_FAILED', error=str(exc), post_freeze_io=0)
            finally:
                guard.close()
            records.append(record)
        last = records[-1]
        assert context_capture['decoded']['fault_bits'] == 0
        assert context_capture['decoded']['fault_format'] == 2
        if case in ('enabled_stage2', 'disabled_stage2', 'fault_separate_from_format'):
            assert last['status'] == 'READ_COMPLETE' and len(last['reads']) == 59
            decoded = last['decoded']
            assert decoded['parent_bank'] == 1 and decoded['observed_stage2_bank'] == 107
            assert decoded['translation_enabled'] == (case != 'disabled_stage2')
            assert decoded['fault_bits'] == (2 if case == 'fault_separate_from_format' else 0)
            assert decoded['fault_format'] == 2 and decoded['ttbr0'] == 0x88000000
            assert not decoded['mapping_admitted'] and not decoded['table_walk_admitted']
            assert not decoded['mapping_coverage_complete']
        else:
            assert last['status'] == 'REFUSED_OR_FAILED'
        addresses = [int(op['address'], 0) for op in operations
                     if op['phase'] == 'linked' and 'address' in op]
        if case in ('changed_parent', 'invalid_link', 'self_link'):
            assert not set(addresses) & linked.keys()
        if case == 'wrong_stage2_type':
            assert set(addresses) & linked.keys() == {0x150011ac}
        assert len(closes) == 4
        assert not any(r.get('decoded', {}).get('hardware_lease_admitted') for r in records)
        receipt['cases'].append(dict(case=case, result='PASS', records=records,
                                     operations=operations, local_closes=len(closes)))
    paths = [Path(__file__), ROOT / 'tools/a16_fan_dma.py', ROOT / 'tools/a16-fan-dma-survey.py',
             ROOT / 'tools/a16-control-guard.py', ROOT / 'tools/a16_fan_gpi.py']
    receipt.update(status='PASS', source_sha256={str(p.relative_to(ROOT)):
        hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}, fixture_sha256={
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in FIXTURES})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(status='PASS', scenarios=len(cases), output=str(args.output))))


if __name__ == '__main__':
    main()
