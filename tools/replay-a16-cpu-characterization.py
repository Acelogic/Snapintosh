#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay real SCMI protocol and PMU decoding for the documented GET deviation.

Failure inventory predates this code in docs/A16-CPU-POLICY-20261018.md.
This is a model of hypotheses to falsify, not an assertion about firmware internals.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]
p = runpy.run_path(str(ROOT / 'tools/qualify-a16-cpu-policy.py'))
r = runpy.run_path(str(ROOT / 'tools/replay-a16-cpu-policy.py'))
m = r['m']


class Firmware(r['Firmware']):
    def __init__(self, fault):
        super().__init__(fault)
        self.limits[0] = (8, 0);self.apply(0, 8)
        self.challenge = False

    def answer(self, protocol, message, payload):
        if protocol == 0x13 and payload and payload[0] == 0:
            if message == 7 and payload[1] > 8:
                self.challenge = True
            if message == 7 and payload[1] > self.limits[0][0]:
                if self.fault in ('raw-bound-only', 'ignore-physical-cap'):
                    self.commands.append([protocol, message, list(payload)])
                    if self.fault == 'raw-bound-only' and payload[1] > self.limits[0][0] + 4:
                        return -5, []
                    self.requested[0] = payload[1];self.apply(0, payload[1]);return 0, []
                if self.fault == 'accepted-clamp':
                    self.commands.append([protocol, message, list(payload)])
                    self.requested[0] = payload[1];self.apply(0, self.limits[0][0]);return 0, []
            if message == 7 and payload[1] == 8 and self.fault == 'lower-ignored' and self.challenge:
                self.commands.append([protocol, message, list(payload)]);return 0, []
            if message == 7 and payload[1] == 16 and self.limits[0][0] == 16 and self.fault == 'fallback-too-high':
                self.commands.append([protocol, message, list(payload)]);self.apply(0, 17);return 0, []
        status, words = super().answer(protocol, message, payload)
        if protocol == 0x13 and payload and payload[0] == 0 and status == 0:
            if message == 6:
                words = [self.limits[0][0] + 4, self.limits[0][1]]
                if self.fault == 'raw-bound-drift' and self.challenge: words[0] += 1
            if message == 8: words = [0]
        return status, words


def replay(name, output, plan):
    firmware = Firmware(name)
    proxy = m['FakeProxy'](platform=firmware)
    guard = r['Observer']();record = dict(case=name, hardware=False)
    def save(): (output / (name + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    kinds = {addr: ('normal-nc' if addr == (m['SHM'] & ~4095) else 'device') for addr in p['perf']['PAGES'].values()}
    access = p['PolicyAccess'](proxy, kinds, lambda *a: None, p['perf']['TRANSPORTS']['pdp0'])
    channel = p['PolicyChannel'](access, p['perf']['TRANSPORTS']['pdp0'], guard, record, save, token=64)
    def measure(phase):
        ghz = firmware.mhz(0) / 1000
        words = m['stub_words'](0x80000000, 4, 192000, [ghz] * 4, False, True)
        words[4] = 0x512f0021
        (output / (name + '-' + phase + '.bin')).write_bytes(struct.pack('<64Q', *words))
        return p['clock']['decode'](words, 4, 192000, 19200000)
    def temperatures(phase):
        if name == 'uncertain-challenge' and phase == 'challenge-9-before': proxy.b['token_mismatch'] = True
        if name == 'thermal-failure' and phase == 'challenge-9-before': raise p['Refused']('thermal admission failed')
        if name == 'thermal-after-fallback' and phase == 'fallback-after': raise p['Refused']('thermal admission failed')
    try:
        p['characterize_sequence'](channel, plan, measure, temperatures, record, save, sleep=lambda _: None)
        record['outcome'] = 'PASS'
    except Exception as error:
        record['outcome'] = 'REFUSED';record['error'] = str(error)
    writes = [x for x in firmware.commands if x[0] == 0x13 and x[1] in (5, 7)]
    record.update(commands=firmware.commands, frozen=guard.frozen, physical_mhz=firmware.mhz(0))
    expected = name in ('normal', 'accepted-clamp')
    assert (record['outcome'] == 'PASS') == expected, (name, record.get('error'))
    assert all(x[2][0] == 0 and 0 < x[2][1] <= 16 for x in writes)
    assert all(x[2][2] == 0 for x in writes if x[1] == 5)
    if expected:
        assert firmware.mhz(0) == 1939.2 and firmware.limits[0] == (8, 0)
        assert [x['requested_index'] for x in record['phases'] if 'requested_index' in x] == [9, 12, 16]
        assert next(x for x in record['phases'] if x['name'] == 'fallback')['measurement']['ghz_median'] == 3.072
        assert all(x['verified'] for x in record['phases'])
    if name in ('raw-bound-only', 'ignore-physical-cap'):
        assert firmware.mhz(0) == 1939.2 and writes[-1][2] == [0, 8]
        assert not [x for x in writes if x[1] == 5], 'widened after escaped cap'
    if name in ('fallback-ineffective', 'fallback-too-high'):
        assert firmware.mhz(0) == 1939.2 and firmware.limits[0] == (8, 0)
    if name == 'uncertain-challenge':
        assert guard.frozen and len(writes) == 2, 'issued containment after uncertain reply'
    if name == 'raw-bound-drift': assert len(writes) == 2
    if name == 'thermal-failure': assert len(writes) == 1
    if name == 'thermal-after-fallback':
        assert firmware.mhz(0) == 3072 and record['final_conservative_policy_verified'] is False
        assert record['last_acknowledged_policy_write'] == dict(message=7, payload=[0, 16])
    record['oracle'] = 'EXPECTED_PASS' if expected else 'FAULT_DETECTED';save()
    return dict(case=name, oracle=record['oracle'], error=record.get('error'))


def main():
    ap = argparse.ArgumentParser();ap.add_argument('--output', type=Path, required=True);args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    history = [json.loads((ROOT / 'build/controls-goal-20261018' / n / 'receipt.json').read_text())
               for n in ('cpu-query-v3', 'cpu-cap-v1', 'cpu-after-cap-query-v1')]
    plan = p['characterization_history'](*history)
    cases = [replay(n, args.output, plan) for n in ('normal', 'accepted-clamp', 'raw-bound-only',
             'ignore-physical-cap', 'fallback-ineffective', 'fallback-too-high', 'raw-bound-drift',
             'uncertain-challenge', 'thermal-failure', 'thermal-after-fallback')]
    for name, mutate in (
        ('history-stage-drift', lambda x: x[2]['bootinfo'].update(stage_generation=2)),
        ('history-uncertain', lambda x: x[1]['control_guard'].update(frozen=True)),
        ('history-extra-write', lambda x: x[1]['transactions'].append(dict(protocol='0x13', message=7, payload=[0, 8]))),
        ('history-physical-drift', lambda x: x[2]['measurements']['baseline'].update(ghz_median=2.496, ghz_max=2.496)),
        ('history-settle-drift', lambda x: (x[0]['plan'].update(settle_seconds=10), x[1]['plan'].update(settle_seconds=10))),
    ):
        changed = copy.deepcopy(history);mutate(changed)
        try: p['characterization_history'](*changed)
        except Exception as error: cases.append(dict(case=name, oracle='FAULT_DETECTED', error=str(error)))
        else: raise AssertionError(name + ' accepted')
    sources = ['tools/qualify-a16-cpu-policy.py', 'tools/replay-a16-cpu-characterization.py',
        'tools/replay-a16-cpu-policy.py', 'tools/test-a16-cpu-perf.py', 'tools/a16-cpu-perf.py',
        'tools/measure-a16-cpu-clock.py', 'docs/A16-CPU-POLICY-20261018.md']
    receipt = dict(status='PASS_CHARACTERIZATION_REPLAY', hardware=False, cases=cases,
        sources={s: hashlib.sha256((ROOT / s).read_bytes()).hexdigest() for s in sources},
        artifacts={x.name: hashlib.sha256(x.read_bytes()).hexdigest() for x in args.output.iterdir() if x.is_file()})
    (args.output / 'qualification.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(status=receipt['status'], cases=len(cases))))


if __name__ == '__main__': main()
