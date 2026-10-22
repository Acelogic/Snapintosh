#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline test of tools/check-a16-hid-input.py's transaction path.

perform_input_check runs against a fake q1n1 proxy that models the IC20 GENI
engine (FIFO mode, generation57 register values), the keyboard's I2C-HID
behaviour (descriptor, SET_POWER, RESET with an active-low attention line and
0x0000 acknowledgment, queued input reports), TLMM GPIO 67 and the GIC
distributor. It checks the bus transcript, the journal, the writable-register
set, FIFO discipline, cleanup and the verdict, plus the failure paths.
"""
from pathlib import Path
import importlib.util
import json
import struct
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('check_input', ROOT / 'tools/check-a16-hid-input.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

REPORT = json.loads((ROOT / tool.EVIDENCE['report'][0]).read_text())
DESCRIPTOR = bytes.fromhex(tool.plan_inputs()['hid_descriptor'])
RDESC = bytes.fromhex(REPORT['report_descriptor_transaction']['attempts'][0]['raw_hex'])
VALUES = {name: row['value'] for name, row in REPORT['registers'].items()}
OFFSETS = {name: int(row['address'], 16) - tool.BASE for name, row in REPORT['registers'].items()}
WRITABLE = {int(v, 16) for v in tool.WRITABLE}


class Transport(Exception):
    pass


class FakeProxy:
    def __init__(self, **faults):
        self.regs = {OFFSETS[n]: v for n, v in VALUES.items()}
        self.status = self.regs[0x610]
        self.irq_en = self.regs[0x614]
        self.txq, self.rxq, self.active, self.last_bytes, self.final = [], [], None, 0, False
        self.held = None
        self.log, self.writes, self.pops, self.bad = [], [], 0, []
        self.powered, self.resets, self.reset_done, self.sentinel = True, 0, 0.0, False
        self.queue, self.power_after_reset, self.level_reads = [], 0, 0
        self.faults = dict(nack_power=0, tx_retained=False, latch_needs_enable=False,
                           script=[], fail_pop=None, never_assert=False)
        self.faults.update(faults)

    # -- q1n1 proxy surface -------------------------------------------------
    def bootinfo(self):
        return dict(gic_distributor=tool.GICD)

    def serror_state(self):
        return dict(mechanism=2, flags=1, before=0, during=0, unconsumed=0, address=0x1000)

    def read32(self, address):
        if tool.GPIO_PAGE <= address < tool.GPIO_PAGE + 0x10:
            return self.tlmm(address - tool.GPIO_PAGE)
        if tool.GICD <= address < tool.GICD + 0x10000:
            return {0x14c: 0, 0x24c: 0, 0x34c: 0, 0x7348: 0, 0x734c: 0}[address - tool.GICD]
        offset = address - tool.BASE
        if not 0 <= offset < 0x1000:
            self.bad.append(('read', hex(address)))
            return 0
        if offset == 0x40:
            return 1 if self.active else 0
        if offset == 0x610:
            return self.status & self.irq_en if self.faults['latch_needs_enable'] else self.status
        if offset == 0x614:
            return self.irq_en
        if offset == 0x800:
            return len(self.txq)
        if offset == 0x804:
            value = len(self.rxq)
            if self.rxq and self.final:
                value |= 1 << 31 | self.last_bytes << 28
            return value
        if offset == 0x780:
            self.pops += 1
            if self.faults['fail_pop'] == self.pops:
                raise Transport('lost pop reply')
            if not self.rxq:
                self.bad.append(('underflow', self.pops))
                return 0
            word = self.rxq.pop(0)
            if not self.rxq:
                self.final = False
            return word
        return self.regs.get(offset, 0)

    def write32(self, address, value):
        offset = address - tool.BASE
        self.writes.append((offset, value))
        if offset not in WRITABLE:
            self.bad.append(('write', hex(address)))
            return
        if offset in (0x26c, 0x270):
            self.regs[offset] = value
        elif offset == 0x614:
            self.irq_en = value
        elif offset == 0x618:
            self.status &= ~value
        elif offset == 0x604:
            self.active = None
            self.status |= tool.CANCEL if value & 4 else tool.ABORT
            if not self.faults['tx_retained']:
                self.txq = []
        elif offset == 0x700:
            self.txq.append(value)
            self.maybe_write()
        elif offset == 0x600:
            op, addr, stretch = value >> 27, (value >> 9) & 0x7f, bool(value & 4)
            self.active = (op, addr, stretch)
            if op == 2:
                self.do_read(addr)
            else:
                self.maybe_write()

    # -- engine -------------------------------------------------------------
    def complete(self, bits):
        self.status |= bits
        self.active = None

    def maybe_write(self):
        if not self.active or self.active[0] != 1:
            return
        length = self.regs[0x26c]
        if len(self.txq) * 4 < length:
            return
        data = b''.join(struct.pack('<I', w) for w in self.txq)[:length]
        op, addr, stretch = self.active
        if addr == tool.ADDR and not stretch and data[:2] == b'\x05\x00' and data[3] == 8 \
                and self.faults['nack_power']:
            self.faults['nack_power'] -= 1
            self.log.append(('W', data.hex(), 'nack'))
            if not self.faults['tx_retained']:
                self.txq = []
            return self.complete(tool.NACK | 8 | tool.DONE)
        self.txq = []
        self.log.append(('W' + ('s' if stretch else ''), data.hex()))
        self.held = data if stretch else None
        if not stretch:
            self.command(data)
        self.complete(tool.DONE)

    def command(self, data):
        if data[:2] == b'\x05\x00' and data[3] == 8:
            self.powered = not data[2] & 1
            if self.resets and self.sentinel is False and self.power_after_reset == 0:
                self.power_after_reset = 1
        elif data[:2] == b'\x05\x00' and data[3] == 1:
            self.resets += 1
            self.queue = []
            self.sentinel = True
            self.reset_done = time.monotonic() + 0.02

    def do_read(self, addr):
        length = self.regs[0x270]
        if self.held == b'\x01\x00':
            data = DESCRIPTOR
        elif self.held == b'\x02\x00':
            data = RDESC
        else:
            data = self.input_register()
        self.held = None
        data = data.ljust(length, b'\0')[:length]
        self.log.append(('R', length, data[:12].hex()))
        self.rxq = [struct.unpack_from('<I', data.ljust((length + 3) // 4 * 4, b'\0'), i)[0]
                    for i in range(0, (length + 3) // 4 * 4, 4)]
        self.final, self.last_bytes = True, length % 4
        self.complete(tool.DONE | tool.RX_LAST)

    # -- keyboard -----------------------------------------------------------
    def pending(self):
        if self.sentinel:
            return time.monotonic() >= self.reset_done and not self.faults['never_assert']
        return bool(self.queue)

    def input_register(self):
        if self.sentinel and time.monotonic() >= self.reset_done:
            self.sentinel = False
            return b'\x00\x00'
        if self.queue:
            report = self.queue.pop(0)
            return struct.pack('<H', len(report) + 2) + report
        return b'\x00\x00'

    def tlmm(self, offset):
        if offset == 4:
            if self.power_after_reset:
                self.level_reads += 1
                for due, report in list(self.faults['script']):
                    if self.level_reads >= due:
                        self.queue.append(report)
                        self.faults['script'].remove((due, report))
            return 0 if self.pending() else 1
        return {0: 0x200, 8: 0xe2, 12: 0}[offset]


PRESS_A = bytes.fromhex('360000040000000000')
RELEASE = bytes.fromhex('360000000000000000')


def run(proxy, window=0.4):
    tool.WINDOW_SECONDS = window
    directory = Path(tempfile.mkdtemp())
    output = directory / 'result.json'
    record = dict(status='RUNNING', registers={}, mmio_writes=False, fifo_data_reads=False)
    output.write_text('{}')
    error = None
    try:
        tool.perform_input_check(proxy, dict(VALUES), record, output)
    except Exception as caught:                     # the tool raises on failure
        error = caught
    journal = [json.loads(line) for line in (directory / 'result.journal.jsonl').read_text().splitlines()]
    return record, journal, error


class CheckInputTests(unittest.TestCase):
    def test_keys_observed_and_state_restored(self):
        proxy = FakeProxy(script=[(3, PRESS_A), (6, RELEASE)])
        record, journal, error = run(proxy)
        self.assertIsNone(error)
        check = record['input_check']
        self.assertEqual(check['verdict'], 'KEY_REPORTS_OBSERVED')
        self.assertEqual(check['reset_sentinel']['kind'], 'empty')
        self.assertTrue(check['reset_attention']['asserted'])
        self.assertEqual(check['level_after_sentinel'], 1)
        reports = check['window']['reports']
        self.assertEqual([r['key_usages'] for r in reports], [[4], []])
        self.assertTrue(all(r['via'] == 'attention' and r['level_after'] == 1 for r in reports))
        self.assertGreater(check['window']['empty_blind'], 0)
        self.assertTrue(check['latch_probe']['done_latched'])
        # Transcript: identity x2, PWR_ON, RESET, sentinel, PWR_ON, window reads, probe.
        writes = [e[1] for e in proxy.log if e[0].startswith('W')]
        self.assertEqual(writes, ['0100', '0100', '05000008', '05000001', '05000008'])
        reads = [e for e in proxy.log if e[0] == 'R']
        self.assertEqual([r[1] for r in reads[:3]], [30, 30, 64])      # identity x2, sentinel
        self.assertTrue(all(r[1] == 64 for r in reads[2:]))
        self.assertEqual(proxy.bad, [])
        cleanup = check['cleanup']
        self.assertTrue(cleanup['restored'] and cleanup['fifos_empty'] and cleanup['io_inputs_match'])
        self.assertEqual(proxy.irq_en, VALUES['master_irq_enable'])
        self.assertEqual((proxy.regs[0x26c], proxy.regs[0x270]),
                         (VALUES['tx_transfer_length'], VALUES['rx_transfer_length']))
        # Every write and pop has an intent and a confirmation, in order.
        intents = [e for e in journal if e['kind'] in ('write', 'pop')]
        confirms = [e for e in journal if e['kind'] in ('write-confirmed', 'pop-confirmed')]
        self.assertEqual(len(intents), len(confirms))
        self.assertEqual(len([e for e in journal if e['kind'] == 'write']), check['writes'])
        self.assertEqual([e['seq'] for e in journal], list(range(1, len(journal) + 1)))

    def test_no_keys_is_responsive_not_success(self):
        record, _, error = run(FakeProxy())
        self.assertIsNone(error)
        self.assertEqual(record['input_check']['verdict'], 'RESPONSIVE_NO_KEY_REPORTS')

    def test_press_without_release_is_not_success(self):
        record, _, error = run(FakeProxy(script=[(3, PRESS_A)]))
        self.assertIsNone(error)
        self.assertEqual(record['input_check']['verdict'], 'KEY_PRESS_WITHOUT_RELEASE')

    def test_power_on_nack_is_retried_once(self):
        proxy = FakeProxy(nack_power=1, script=[(3, PRESS_A), (6, RELEASE)])
        record, _, error = run(proxy)
        self.assertIsNone(error)
        self.assertEqual(len(record['input_check']['nacks']), 1)
        self.assertEqual([e[1] for e in proxy.log if e[0] == 'W'][:4],
                         ['05000008', '05000008', '05000001', '05000008'])

    def test_nack_leaving_transmit_words_fails_without_replay(self):
        proxy = FakeProxy(nack_power=1, tx_retained=True)
        record, _, error = run(proxy)
        # The NACK evidence raises; cleanup then refuses to call the result clean.
        self.assertIsInstance(error, AssertionError)
        self.assertIsInstance(error.__context__, RuntimeError)
        check = record['input_check']
        self.assertEqual(check['status'], 'FAILED')
        self.assertEqual(check['nacks'][0]['tx_fifo'], '0x1')
        self.assertFalse(check['cleanup']['fifos_empty'])
        self.assertEqual([e for e in proxy.log if e[0] == 'W' and len(e) == 2 and e[1] == '05000008'], [])

    def test_masked_probe_without_latching(self):
        proxy = FakeProxy(latch_needs_enable=True)
        record, _, error = run(proxy)
        self.assertIsNone(error)
        probe = record['input_check']['latch_probe']
        self.assertFalse(probe['done_latched'])
        self.assertEqual(probe['kind'], 'empty')

    def test_attention_never_asserting_still_reads_after_100ms(self):
        record, _, error = run(FakeProxy(never_assert=True))
        self.assertIsNone(error)
        self.assertFalse(record['input_check']['reset_attention']['asserted'])
        self.assertEqual(record['input_check']['reset_sentinel']['kind'], 'empty')

    def test_uncertain_pop_stops_all_mmio(self):
        proxy = FakeProxy(fail_pop=40)
        record, journal, error = run(proxy)
        self.assertIsInstance(error, Transport)
        check = record['input_check']
        self.assertFalse(check['cleanup']['transport_sound'])
        self.assertIn('no further MMIO', check['cleanup']['reason'])
        self.assertEqual(journal[-1]['kind'], 'pop-uncertain')
        writes_after = [e for e in journal if e['kind'] == 'write' and e['seq'] > journal[-1]['seq']]
        self.assertEqual(writes_after, [])


if __name__ == '__main__':
    unittest.main(verbosity=1)
