#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay all three production survey phases against a shared, partial route table."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import time
from a16_fan_dma import identity_plan

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    if args.output.exists():
        ap.error('output exists; retain evidence')
    capture = runpy.run_path(str(ROOT / 'tools/a16-fan-dma-survey.py'))['capture']
    guards = runpy.run_path(str(ROOT / 'tools/a16-control-guard.py'))
    cases = ('stable_partial_shared', 'changed_route', 'changed_header', 'changed_ttbr',
             'changed_cbar', 'exception_callback', 'lost_reply', 'different_generation',
             'invalid_bank', 'bypass_route', 'no_route')
    receipt = dict(scope='offline three-phase production capture replay', cases=[])
    for case in cases:
        registers = {address: 0 for _, address in identity_plan()}
        registers.update({0x15000000: 0x270406, 0x15000020: 0x7c017eba,
                          0x15000024: 0x6000006f, 0x15000028: 0x5222,
                          0x1500003c: 0x24})
        for index in range(128):
            registers[0x15000800 + 4 * index] = 0
            registers[0x15000c00 + 4 * index] = 2 << 16
        for index, sid in enumerate((0x460, 0xd36, 0xd23, 0xcb6, 0xca3, 0xd76, 0xd63)):
            registers[0x15000800 + 4 * index] = 0x80000000 | sid
            registers[0x15000c00 + 4 * index] = 0 if index == 0 else 1
        # Literal bank1 register addresses, independent of the plan generator.
        bank_registers = {0x15001004: 0x10000, 0x15001804: 1,
                          0x15081000: 1, 0x15081004: 0, 0x15081010: 0x38003,
                          0x15081020: 0x88000000, 0x15081024: 0,
                          0x15081028: 0, 0x1508102c: 0,
                          0x15081030: 0x80800020, 0x15081038: 0xff44,
                          0x1508103c: 0, 0x15081058: 0,
                          0x15081060: 0, 0x15081064: 0,
                          0x15081068: 0, 0x1508106c: 0, 0x150817f4: 0}
        registers.update(bank_registers)
        if case == 'invalid_bank':
            registers[0x15000c0c] = 255
        if case == 'bypass_route':
            registers[0x15000c0c] = 1 << 16
        if case == 'no_route':
            registers[0x1500080c] = 0
        operations, closes, records, seen = [], [], [], {}
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
                return dict(current_el=2, image_base=0xb0000000,
                            stage_generation=2 if case == 'different_generation' and
                            phase == 'context' else 1)

            def serror_state(self):
                operations.append(dict(phase=phase, operation='serror'))
                return dict(before=0, during=0, unconsumed=0)

            def read32(self, address):
                operations.append(dict(phase=phase, operation='read32', address=hex(address)))
                key = (phase, address)
                seen[key] = seen.get(key, 0) + 1
                if phase == 'context' and address in bank_registers:
                    if case == 'exception_callback':
                        self.link.exception_handler(2, 0xdead)
                    if case == 'lost_reply':
                        raise TimeoutError('injected context read timeout')
                    if case == 'changed_ttbr' and address == 0x15081024 and seen[key] == 2:
                        return 1
                    if case == 'changed_cbar' and address == 0x15001004 and seen[key] == 2:
                        return 0
                return registers[address]

        identity = streams = None
        for phase in ('identity', 'streams', 'context'):
            if phase == 'context':
                if case == 'changed_route':
                    registers[0x15000c0c] = 2
                if case == 'changed_header':
                    registers[0x15000000] ^= 1
            record = dict(phase=phase, status='STARTING', reads=[])
            guard = guards['ControlGuard'](Proxy(), record, lambda: None)
            try:
                capture(guard.proxy, record, lambda: None, 1, 0xb0000000,
                        time.monotonic() + 10, identity, streams)
                if phase == 'identity':
                    identity = record
                if phase == 'streams':
                    streams = record
            except Exception as exc:
                assert phase == 'context' and case != 'stable_partial_shared', str(exc)
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
        if case == 'stable_partial_shared':
            assert last['status'] == 'READ_COMPLETE' and len(last['reads']) == 45
            decoded = last['decoded']
            assert decoded['observed_bank'] == 1 and decoded['cbar_type'] == 1
            assert decoded['observed_shared_bank_groups'] == [1, 2, 3, 4, 5, 6]
            assert not decoded['mapping_coverage_complete'] and len(decoded['unsurveyed_groups']) == 58
            assert decoded['ttbr0'] == 0x88000000 and decoded['translation_enabled']
            assert decoded['controls_stable_between_reads'] and decoded['observation_only']
            assert not decoded['mapping_admitted'] and not decoded['table_walk_admitted']
        else:
            assert last['status'] == 'REFUSED_OR_FAILED' and last['post_freeze_io'] == 0
        if case in ('changed_route', 'changed_header', 'different_generation',
                    'invalid_bank', 'bypass_route', 'no_route'):
            assert not any(op['phase'] == 'context' and op.get('address') in
                           {hex(a) for a in bank_registers} for op in operations)
        assert len(closes) == 3
        assert not any(record.get('decoded', {}).get('hardware_lease_admitted') for record in records)
        receipt['cases'].append(dict(case=case, result='PASS', records=records,
                                     operations=operations, local_closes=len(closes)))
    paths = [Path(__file__), ROOT / 'tools/a16_fan_dma.py', ROOT / 'tools/a16-fan-dma-survey.py',
             ROOT / 'tools/a16-control-guard.py', ROOT / 'tools/a16_fan_gpi.py']
    receipt.update(status='PASS', source_sha256={str(p.relative_to(ROOT)):
        hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(status='PASS', scenarios=len(cases), output=str(args.output))))


if __name__ == '__main__':
    main()
