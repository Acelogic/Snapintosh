#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline protocol integration, failure inventory in A16-CPU-POLICY-20261018.md.

Exercise the real SCMI serializer/parser, real PMU decoder and policy sequence
against the retained A16 protocol model. No hardware calls or GPU proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]
p = runpy.run_path(str(ROOT / 'tools/qualify-a16-cpu-policy.py'))
m = runpy.run_path(str(ROOT / 'tools/test-a16-cpu-perf.py'), run_name='scmi_model')

class Firmware(m['A16Platform']):
    def __init__(self, fault=None):
        super().__init__()
        self.fault = fault
        self.commands = []
        self.cap_writes = 0

    def answer(self, proto, msg, payload):
        self.commands.append([proto, msg, list(payload)])
        if proto == 0x13 and payload and payload[0] == 0:
            if msg == 5:
                _, top, bottom = payload
                if not top and not bottom: return -5, []
                if self.fault != 'ignore-limits':
                    self.limits[0] = (top or self.limits[0][0], bottom or self.limits[0][1])
                if top == 8: self.cap_writes += 1
                if self.fault == 'change-minimum': self.limits[0] = (top, 1)
                return 0, []
            if msg == 7:
                level = payload[1]
                maximum, minimum = self.limits[0]
                if level > maximum:
                    if self.fault == 'accept-clamp':
                        self.requested[0] = level;self.apply(0, maximum);return 0, []
                    if self.fault == 'cap-not-physical':
                        self.requested[0] = level;self.apply(0, level);return 0, []
                    return -5, []
                self.requested[0] = level
                if self.fault == 'ignore-level': return 0, []
                if self.fault == 'fallback-ineffective' and level == 16: return 0, []
                self.apply(0, level)
                return 0, []
        status, words = super().answer(proto, msg, payload)
        if proto == 0x13 and msg == 4:
            if self.fault == 'short-level-page': words = words[:-1]
            if self.fault == 'reserved-count-bits': words[0] |= 0x1000
            if self.fault == 'stalled-pagination': words = [1 << 16]
        return status, words


class Observer:
    # PolicyChannel uses only freeze here; production guard has separate real-
    # proxy method/link/native fault integration, not substituted by this model.
    frozen = False
    reason = None
    def freeze(self, reason): self.frozen = True;self.reason = reason


def run_case(name, dest):
    platform = Firmware(name)
    proxy = m['FakeProxy'](platform=platform)
    guard = Observer()
    record = dict(case=name, scope='offline protocol and PMU-report replay')
    path = dest / (name + '.json')
    def save(): path.write_text(json.dumps(record, indent=2) + '\n')
    kinds = {addr: ('normal-nc' if addr == (m['SHM'] & ~4095) else 'device') for addr in p['perf']['PAGES'].values()}
    access = p['PolicyAccess'](proxy, kinds, lambda *a: None, p['perf']['TRANSPORTS']['pdp0'])
    channel = p['PolicyChannel'](access, p['perf']['TRANSPORTS']['pdp0'], guard, record, save, token=123)
    scmi = p['PolicyScmi'](channel)
    record['base'] = scmi.base()
    if name in ('short-level-page', 'reserved-count-bits', 'stalled-pagination'):
        try: scmi.domain(0, True)
        except Exception as error:
            assert not [x for x in platform.commands if x[0] == 0x13 and x[1] in (5, 7)]
            record.update(outcome='REFUSED', oracle='FAULT_DETECTED', error=str(error));save()
            return dict(case=name, oracle=record['oracle'], error=str(error))
        raise AssertionError('malformed level enumeration accepted')
    domain = scmi.domain(0, True)
    def measure(phase):
        words = m['stub_words'](0x80000000, 4, 192000, [platform.mhz(0) / 1000] * 4, False, True)
        words[4] = 0x512f0021
        blob = struct.pack('<64Q', *words);(dest / (name + '-' + phase + '.bin')).write_bytes(blob)
        return p['clock']['decode'](words, 4, 192000, 19200000)
    baseline = measure('baseline')
    if name == 'ambiguous-baseline': domain['levels'][15]['mhz'] = 3072
    if name == 'unknown-minimum': domain['limits']['min'] = 99
    if name == 'wrong-target': baseline['midr'] = '0x512f0010'
    expected_pass = name in ('normal', 'accept-clamp')
    try:
        plan = p['plan_policy'](domain, baseline);record['plan'] = plan
        if name == 'mismatched-reply': proxy.b['token_mismatch'] = True
        p['policy_sequence'](channel, plan, measure, lambda n: None, record, save, sleep=lambda _: None)
        record['outcome'] = 'PASS'
    except Exception as error:
        record['outcome'] = 'REFUSED';record['error'] = str(error)
    record['commands'] = platform.commands
    record['frozen'] = guard.frozen;record['reason'] = guard.reason
    writes = [x for x in platform.commands if x[0] == 0x13 and x[1] in (5, 7)]
    assert all(x[2][0] == 0 for x in writes), 'touched secondary domain'
    assert all(x[2][1] > 0 and x[2][2] == 0 for x in writes if x[1] == 5), 'invalid zero/minimum limits write'
    assert all(x[2][1] <= 16 for x in writes), 'request exceeded baseline'
    assert (record['outcome'] == 'PASS') == expected_pass, (name, record.get('error'))
    if expected_pass:
        assert platform.limits[0] == (8, 0) and platform.applied[0] == 8
        assert len(record['phases']) == 4 and all(x['verified'] for x in record['phases'])
        assert record['phases'][2]['measurement']['ghz_median'] == 3.072
    if name == 'mismatched-reply': assert guard.frozen and len(writes) == 1
    if name in ('ambiguous-baseline', 'unknown-minimum', 'wrong-target', 'short-level-page', 'reserved-count-bits', 'stalled-pagination'): assert not writes
    record['oracle'] = 'EXPECTED_PASS' if expected_pass else 'FAULT_DETECTED';save()
    return dict(case=name, oracle=record['oracle'], error=record.get('error'))


def main():
    ap = argparse.ArgumentParser();ap.add_argument('--output', type=Path, required=True);args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    names = ('normal', 'accept-clamp', 'ignore-limits', 'ignore-level', 'change-minimum',
             'cap-not-physical', 'fallback-ineffective', 'mismatched-reply', 'ambiguous-baseline',
             'unknown-minimum', 'wrong-target', 'short-level-page', 'reserved-count-bits', 'stalled-pagination')
    results = [run_case(n, args.output) for n in names]
    sources = ['tools/qualify-a16-cpu-policy.py', 'tools/replay-a16-cpu-policy.py',
               'tools/test-a16-cpu-perf.py', 'tools/a16-cpu-perf.py', 'tools/measure-a16-cpu-clock.py',
               'docs/A16-CPU-POLICY-20261018.md']
    receipt = dict(status='PASS_PROTOCOL_REPLAY', hardware=False, cases=results,
                   sources={s: hashlib.sha256((ROOT / s).read_bytes()).hexdigest() for s in sources},
                   artifacts={x.name: hashlib.sha256(x.read_bytes()).hexdigest() for x in args.output.iterdir() if x.is_file()})
    (args.output / 'qualification.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(status=receipt['status'], cases=len(results), artifacts=len(receipt['artifacts']))))

if __name__ == '__main__': main()
