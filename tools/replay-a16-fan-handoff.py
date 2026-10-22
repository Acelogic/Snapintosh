#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline command-protocol replay for preserved GPI9 STOP/START."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
from a16_fan_gpi_handoff import CommandRoundTrip

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    if args.output.exists():
        ap.error('output exists; retain evidence')
    fixture = ROOT / 'build/fan-gpi-20261018/dma-identity-current.json'
    guard_module = runpy.run_path(str(ROOT / 'tools/a16-control-guard.py'))
    cases = ('roundtrip', 'stop_in_process', 'queued_before', 'prior_irq', 'drift_before',
             'ring_drift_stopped', 'stop1_timeout', 'wrong_completion_state', 'unowned_irq',
             'lost_command_reply', 'lost_ack_reply', 'lost_read_reply',
             'ring_drift_restarted', 'missing_exclusion')
    receipt = dict(scope='offline production handoff backend and ControlGuard replay', cases=[])
    for case in cases:
        registers = {int(r['address'], 0): r['value'] for r in json.loads(fixture.read_text())['reads']
                     if r['name'].startswith('firmware_gpi9.')}
        registers.update({0xa37098: 3, 0xa3709c: 1, 0xa370b0: 0, 0xa370b8: 1,
                          0xa84040: 0, 0xa84908: 7})
        if case == 'queued_before':
            registers[0xa34018] += 16
        if case == 'prior_irq':
            registers[0xa37090] = 1
        operations, writes, commands, closes, seen = [], [], [], [], {}
        clock = 0
        intermediate = None

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
                raise AssertionError('unexpected request/native call')

            def read32(self, address):
                nonlocal intermediate
                operations.append(dict(operation='read32', address=hex(address)))
                seen[address] = seen.get(address, 0) + 1
                if case == 'lost_read_reply' and commands and address == 0xa37090:
                    raise TimeoutError('injected read reply loss')
                if case == 'drift_before' and address == 0xa34008 and seen[address] == 2:
                    return registers[address] + 16
                if intermediate is not None and address == 0xa37090 and registers[address] == 0:
                    channel = intermediate
                    registers[0xa34000 + 0x80 * channel] = (
                        registers[0xa34000 + 0x80 * channel] & ~(15 << 20)) | 3 << 20
                    registers[0xa37090] = 1 << channel
                    registers[0xa37080] = 1
                    intermediate = None
                return registers[address]

            def write32(self, address, value):
                nonlocal intermediate
                operations.append(dict(operation='write32', address=hex(address), value=value))
                writes.append((address, value))
                assert address in (0xa37008, 0xa370a0), 'unqualified write address'
                if address == 0xa370a0:
                    assert value in (1, 2), 'unowned IRQ acknowledgement'
                    registers[0xa37090] &= ~value
                    registers[0xa37080] = 0 if not registers[0xa37090] else 1
                    if case == 'lost_ack_reply':
                        raise TimeoutError('injected acknowledgement reply loss')
                    return
                assert value in (0x02000000, 0x02000001, 0x01000000, 0x01000001)
                opcode, channel = value >> 24, value & 255
                commands.append(value)
                if case == 'stop1_timeout' and value == 0x02000001:
                    return
                state = 3 if opcode == 2 else 2
                if case == 'wrong_completion_state' and opcode == 2:
                    state = 2
                if case == 'stop_in_process' and opcode == 2:
                    state, intermediate = 4, channel
                registers[0xa34000 + 0x80 * channel] = (
                    registers[0xa34000 + 0x80 * channel] & ~(15 << 20)) | state << 20
                registers[0xa37090] = 3 if case == 'unowned_irq' else 1 << channel
                registers[0xa37080] = 1
                if case == 'ring_drift_stopped' and value == 0x02000001:
                    registers[0xa34010] += 16
                if case == 'ring_drift_restarted' and value == 0x01000001:
                    registers[0xa35010] += 16
                if case == 'lost_command_reply':
                    raise TimeoutError('command may have executed; reply lost')

        record = dict(case=case, hardware=False)
        guard = guard_module['ControlGuard'](Proxy(), record, lambda: None)

        class Bus:
            def __init__(self):
                self.read32 = guard.proxy.read32
                self.write32 = guard.proxy.write32
                self.freeze = guard.freeze

            @staticmethod
            def time_us():
                nonlocal clock
                clock += 1000
                return clock

        evidence = dict(generation=1, image_base=0xb0000000, cpu0_sole_operator=True,
                        other_17_cpus_off=True, exit_boot_services_completed=True,
                        ncm_smem_clients_do_not_use_ic10=True, exclusive_host_client=True,
                        receipt_sha256={'offline_fixture': hashlib.sha256(fixture.read_bytes()).hexdigest()})
        if case == 'missing_exclusion':
            evidence['other_17_cpus_off'] = False
        roundtrip = CommandRoundTrip(Bus(), evidence, 1, 0xb0000000)
        try:
            result = roundtrip.run()
            assert case in ('roundtrip', 'stop_in_process')
            assert result['status'] == 'ROUNDTRIP_VERIFIED' and result['initial_state_restored']
            assert commands == [0x02000000, 0x02000001, 0x01000000, 0x01000001]
            assert not result['retained_lease'] and not result['dma_admitted']
            assert len(writes) == (10 if case == 'stop_in_process' else 8)
        except Exception as exc:
            assert case not in ('roundtrip', 'stop_in_process'), str(exc)
            assert roundtrip.result['status'] == 'FROZEN_REFUSAL'
            before = len(operations)
            try:
                guard.proxy.read32(0xa37090)
            except guard_module['Frozen']:
                pass
            else:
                raise AssertionError('target cleanup escaped freeze')
            assert len(operations) == before
            record['post_freeze_io'] = 0
        finally:
            guard.close()
        if case in ('queued_before', 'prior_irq', 'drift_before', 'missing_exclusion'):
            assert not writes
        if case == 'ring_drift_stopped':
            assert commands == [0x02000000, 0x02000001]
        if case == 'lost_command_reply':
            assert len(writes) == 1
        assert len(closes) == 1
        record.update(result='PASS', handoff=roundtrip.result, operations=operations,
                      local_closes=len(closes))
        receipt['cases'].append(record)
    paths = [Path(__file__), ROOT / 'tools/a16_fan_gpi_handoff.py', ROOT / 'tools/a16_fan_dma.py',
             ROOT / 'tools/a16_fan_gpi.py', ROOT / 'tools/a16-control-guard.py']
    receipt.update(status='PASS', source_sha256={str(p.relative_to(ROOT)):
        hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}, fixture_sha256={
        str(fixture.relative_to(ROOT)): hashlib.sha256(fixture.read_bytes()).hexdigest()})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(dict(status='PASS', scenarios=len(cases), output=str(args.output))))


if __name__ == '__main__':
    main()
