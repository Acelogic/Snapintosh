#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline staged identity/SMR capture replay, including guard failure paths."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import time
from a16_fan_dma import identity_plan, streams_plan

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    if args.output.exists():
        ap.error('output exists')
    survey = runpy.run_path(str(ROOT / 'tools/a16-fan-dma-survey.py'))
    guard_module = runpy.run_path(str(ROOT / 'tools/a16-control-guard.py'))
    receipt = dict(scope='synthetic staged capture, no hardware', cases=[])
    cases = ('exact', 'wildcard', 'overlap', 'shared_bank', 'no_match', 'extended_ids',
             'invalid_extended', 'changed_header', 'zero_identity', 'zero_groups',
             'groups128', 'groups129', 'captured186', 'groups255', 'suffix_only',
             'exception_callback', 'lost_reply')
    for case in cases:
        calls, closes = [], []
        registers = {address: 0 for _, address in identity_plan()}
        registers.update({0x15000020: 0x48001a04, 0x15000024: 0x60000070,
                          0x15000028: 0x1000, 0x1500003c: 0x20})
        for index in range(4):
            registers[0x15000800 + 4 * index] = 0
            registers[0x15000c00 + 4 * index] = 2 << 16
        registers[0x15000800] = 0x80000cb6
        registers[0x15000c00] = 3
        if case == 'wildcard':
            registers[0x15000800] = 0x800f0cb0
        if case == 'overlap':
            registers[0x15000804] = 0x800f0cb0
        if case == 'shared_bank':
            registers[0x15000804] = 0x80001234
            registers[0x15000c04] = 3
        if case == 'no_match':
            registers[0x15000800] = 0
        if case in ('extended_ids', 'invalid_extended'):
            registers[0x15000000] = 8
            registers[0x15000020] |= 256
            registers[0x15000800] = 0x00000cb6
            registers[0x15000c00] = 0x403 if case == 'extended_ids' else 3
        if case == 'zero_identity':
            registers[0x15000020] = 0
        if case == 'zero_groups':
            registers[0x15000020] = 0x48001a00
        groups = {'groups128': 128, 'groups129': 129, 'captured186': 186,
                  'groups255': 255, 'suffix_only': 186}.get(case)
        if groups:
            registers[0x15000020] = 0x48001a00 | groups
            if case == 'captured186':
                registers[0x15000000] = 0x270406
                registers[0x15000020] = 0x7c017eba
                registers[0x15000024] = 0x6000006f
                registers[0x15000028] = 0x5222
                registers[0x1500003c] = 0x24
            for index in range(4, groups):
                registers[0x15000800 + 4 * index] = 0
                registers[0x15000c00 + 4 * index] = 2 << 16
            if case == 'suffix_only':
                registers[0x15000800] = 0
                registers[0x15000800 + 4 * 128] = 0x80000cb6
                registers[0x15000c00 + 4 * 128] = 3

        class Link:
            def close(self):
                closes.append(True)

            def exception_handler(self, *args):
                raise AssertionError('unsafe default handler')

        class Proxy:
            P_CALL = 3

            def __init__(self):
                self.link = Link()

            def request(self, *args, **kwargs):
                raise AssertionError('unexpected request')

            def bootinfo(self):
                calls.append('bootinfo')
                return dict(current_el=2, stage_generation=1, image_base=0xb0000000)

            def serror_state(self):
                calls.append('serror')
                return dict(before=0, during=0, unconsumed=0)

            def read32(self, address):
                calls.append(address)
                if case == 'exception_callback':
                    self.link.exception_handler(2, 0xdead)
                if case == 'lost_reply':
                    raise TimeoutError('injected read timeout')
                return registers[address]

        records = []
        prior = None
        for phase in ('identity', 'streams'):
            record = dict(phase=phase, reads=[], status='STARTING', hardware=False)
            guard = guard_module['ControlGuard'](Proxy(), record, lambda: None)
            try:
                if phase == 'streams':
                    if prior['decoded']['next_phase'] is None:
                        guard.close()
                        break
                    if case == 'changed_header':
                        registers[0x15000000] = 1
                survey['capture'](guard.proxy, record, lambda: None, 1, 0xb0000000,
                                  time.monotonic() + 10, prior)
                if phase == 'identity':
                    prior = record
            except Exception as exc:
                assert case in ('exception_callback', 'lost_reply', 'changed_header'), str(exc)
                guard.freeze(str(exc))
                count = len(calls)
                try:
                    guard.proxy.serror_state()
                except guard_module['Frozen']:
                    pass
                else:
                    raise AssertionError('target cleanup escaped freeze')
                assert len(calls) == count
                record.update(status='REFUSED_OR_FAILED', error=str(exc), post_freeze_io=0)
            finally:
                guard.close()
            records.append(record)
            if record['status'] != 'READ_COMPLETE':
                break
        last = records[-1]
        if case in ('exact', 'wildcard', 'extended_ids', 'shared_bank', 'groups128'):
            decoded = last['decoded']
            assert decoded['unique_translation_bank'] == 3
            plan = decoded['next_context_read_plan']
            assert plan[0]['address'] == '0x1500100c' and plan[2]['address'] == '0x15083000'
            assert len(plan) == 18
            assert decoded['mapping_coverage_complete']
            if case == 'shared_bank':
                assert decoded['shared_bank_matches'] == [0, 1]
        if case == 'overlap':
            assert len(last['decoded']['matching_routes']) == 2
            assert last['decoded']['unique_translation_bank'] is None
        if case in ('no_match', 'invalid_extended'):
            assert last['decoded']['matching_routes'] == []
        if case in ('zero_identity', 'zero_groups'):
            assert last['decoded']['next_phase'] is None
        if groups:
            decoded = last['decoded']
            assert len(last['reads']) == 267
            assert decoded['implemented_groups'] == groups and decoded['surveyed_groups'] == 128
            assert decoded['mapping_coverage_complete'] == (groups == 128)
            # The replay has a populated suffix but the production capture must
            # never access the potentially trapped nonarchitected registers.
            assert not any(isinstance(a, int) and
                           (0x15000a00 <= a < 0x15000c00 or 0x15000e00 <= a < 0x15001000)
                           for a in calls)
            if groups > 128:
                assert decoded['unique_translation_bank'] is None
                assert decoded['next_context_read_plan'] == []
                assert decoded['unsurveyed_groups'] == list(range(128, groups))
                assert decoded['context_plan_refusal']
            if case == 'suffix_only':
                assert decoded['matching_routes'] == []
        if case == 'changed_header':
            assert not any(isinstance(address, int) and 0x15000800 <= address < 0x15001000
                           for address in calls)
        assert not any(r.get('decoded', {}).get('hardware_lease_admitted') for r in records)
        receipt['cases'].append(dict(case=case, result='PASS', records=records,
                                     operations=calls, local_closes=len(closes)))
    paths = [Path(__file__), ROOT / 'tools/a16_fan_dma.py', ROOT / 'tools/a16-fan-dma-survey.py',
             ROOT / 'tools/a16-control-guard.py']
    receipt.update(status='PASS', source_sha256={str(p.relative_to(ROOT)):
        hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(status='PASS', scenarios=len(cases), output=str(args.output))))


if __name__ == '__main__':
    main()
