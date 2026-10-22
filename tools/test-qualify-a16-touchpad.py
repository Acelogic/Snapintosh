#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""tools/qualify-a16-touchpad.py against a fake q1n1 proxy and GENI controller. No hardware.

    python3 tools/test-qualify-a16-touchpad.py

Failure inventory: a survey that writes, pops or clears anything; a survey that qualifies a
controller geni_i2c_start would refuse (each check flipped); a read past the planned set; the
descriptor stage driving anything but the tools' writable set; an uncertain proxy write replayed
instead of ending the process; descriptors that differ between the two reads accepted; the SError
guard left strict; a stop that does not restore TX/RX length and M_IRQ_EN.
"""
from pathlib import Path
import importlib.util
import json
import re
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('qualify_touchpad', ROOT / 'tools/qualify-a16-touchpad.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
FIXTURE = (ROOT / 'tools/test-snap-i2c-hid-fixture.h').read_text()


def c_array(name):
    m = re.search(r'\b%s\[\d*\] = \{(.*?)\};' % re.escape(name), FIXTURE, re.S)
    return bytes(int(v, 16) for v in re.findall(r'0x([0-9a-f]{2})\b', m[1]))


RDESC = c_array('synthetic_tpad_report_desc')
HID_DESC = struct.pack('<11H2HI', 30, 0x100, len(RDESC), 2, 3, 12, 4, 0, 5, 6, 0x2808, 0x0219, 1, 0)
IC20 = {int(o, 16): int(v, 16) for o, v in re.findall(r'\{(0x[0-9a-f]+), (0x[0-9a-f]+)\}', FIXTURE)}


class Abort(Exception):
    pass


class FakeProxy:
    """IC20's surveyed register values at the touchpad's base; commands complete at once."""
    def __init__(self, regs=None, nack=False, fail_write_at=None, flip_second=False):
        self.regs = dict(IC20 if regs is None else regs)
        self.rx, self.tx, self.selected, self.nack = [], [], None, nack
        self.reads, self.writes, self.strict, self.reads_of = [], [], [False], {}
        self.fail_write_at, self.flip_second, self.descriptor_reads = fail_write_at, flip_second, 0
        self.pending_write, self.last_bytes = False, 0
        self.guard = dict(mechanism=1, before=0, during=0, unconsumed=0, flags=0, address=0x1000)

    def _off(self, address):
        assert tool.BASE <= address < tool.BASE + tool.EXTENT, hex(address)
        return address - tool.BASE

    def read32(self, address):
        off = self._off(address)
        self.reads.append(off)
        if off == 0x804:
            words = min(32, len(self.rx))
            last = len(self.rx) <= 32 and self.rx
            return words | ((1 << 31) | ((self.last_bytes & 7) << 28) if last else 0)
        if off == 0x780:
            word = self.rx.pop(0)
            if not self.rx:
                self.regs[0x610] |= 1 | (1 << 27)
            return word
        if off == 0x800:
            return 0
        return self.regs.get(off, 0)

    def write32(self, address, value):
        off = self._off(address)
        if self.fail_write_at is not None and len(self.writes) == self.fail_write_at:
            raise TimeoutError('proxy reply lost')
        self.writes.append((off, value))
        if off == 0x618:
            self.regs[0x610] &= ~value
        elif off == 0x700:
            self.tx += list(struct.pack('<I', value))
            if self.pending_write and len(self.tx) >= self.regs[0x26c]:
                self.selected = self.tx[0] | self.tx[1] << 8
                self.tx, self.pending_write = [], False
                self.regs[0x610] |= 1
        elif off == 0x600:
            op, addr = value >> 27, (value >> 9) & 0x7f
            if addr != 0x15 or self.nack:
                self.regs[0x610] |= 1 | (1 << 10)
                self.tx = []
                return
            if op == 1:
                self.pending_write = True             # completes once its words are in the FIFO
            else:
                length = self.regs[0x270]
                data = HID_DESC if self.selected == 1 else RDESC if self.selected == 2 else b''
                if self.selected == 1:
                    self.descriptor_reads += 1
                    if self.flip_second and self.descriptor_reads == 2:
                        data = data[:20] + b'\x00\x00' + data[22:]
                data = (data + bytes(length))[:length]
                self.last_bytes = length % 4
                self.rx = [int.from_bytes(data[i:i + 4].ljust(4, b'\0'), 'little') for i in range(0, length, 4)]
        else:
            self.regs[off] = value

    def read64(self, address):
        return 0

    def serror_state(self):
        return dict(self.guard)

    def serror_reset(self):
        pass

    def serror_strict(self, enabled):
        self.strict.append(bool(enabled))


def run_stage(stage, proxy, out=None, abort=None):
    out = out or Path(tempfile.mkdtemp()) / 'out.json'
    record = dict(status='RUNNING')
    if stage == 'survey':
        tool.survey(proxy, record, out)
    else:
        tool.descriptors(proxy, record, out, abort=abort or (lambda code: (_ for _ in ()).throw(Abort(code))))
    return record


class Survey(unittest.TestCase):
    def test_qualifies_ic20_like_state_read_only(self):
        p = FakeProxy()
        r = run_stage('survey', p)
        self.assertEqual(r['status'], 'STOPPED_TOUCHPAD_CONTROLLER_QUALIFIED', r['qualification'])
        self.assertEqual(p.writes, [])
        self.assertEqual(sorted(p.reads), sorted(o for _, o in tool.REGISTERS))
        self.assertNotIn(0x780, p.reads)
        self.assertEqual(p.strict, [False, True, False])

    def test_each_refusal(self):
        flips = {0x68: 0x204, 0x64: 1, 0x258: 1, 0x48: 0, 0x254: 1, 0x260: 0x7f8ff, 0x288: 0xffeff,
                 0xe24: 0x10202a68, 0xe28: 0x20044802, 0x40: 1, 0x804: 3, 0x610: 1 << 10}
        for off, value in flips.items():
            regs = {**IC20, off: value}
            p = FakeProxy(regs)
            if off == 0x804:
                p.rx = [0, 0, 0]
                p.last_bytes = 0
            r = run_stage('survey', p)
            self.assertEqual(r['status'], 'STOPPED_TOUCHPAD_CONTROLLER_NOT_QUALIFIED', hex(off))
            self.assertTrue(r['qualification']['reasons'])
            self.assertEqual(p.writes, [])


class Descriptors(unittest.TestCase):
    def test_reads_both_descriptors_and_restores(self):
        p = FakeProxy()
        r = run_stage('descriptors', p)
        self.assertEqual(r['status'], 'STOPPED_TOUCHPAD_DESCRIPTORS_VERIFIED', json.dumps(r.get('stop')))
        self.assertEqual(r['hid_descriptor']['identity'], '2808:0219')
        self.assertEqual(r['report_descriptor']['bytes'], len(RDESC))
        self.assertTrue({o for o, _ in p.writes} <= tool.WRITABLE)
        self.assertEqual(p.regs[0x614], IC20[0x614])           # M_IRQ_EN restored
        self.assertEqual((p.regs[0x26c], p.regs[0x270]), (IC20[0x26c], IC20[0x270]))
        self.assertIn((0x614, 0), p.writes)                       # masked while driving it
        self.assertEqual(p.strict[-1], False)

    def test_nack_is_reported_and_cleaned_up(self):
        p = FakeProxy(nack=True)
        r = run_stage('descriptors', p)
        self.assertEqual(r['status'], 'STOPPED_TOUCHPAD_DESCRIPTORS_FAILED')
        self.assertEqual(r['descriptor_attempts'][0]['result'], 'nack')
        self.assertEqual(r['stop']['result'], 'ok')
        self.assertEqual(p.regs[0x614], IC20[0x614])

    def test_differing_reads_are_not_accepted(self):
        r = run_stage('descriptors', FakeProxy(flip_second=True))
        self.assertEqual(r['status'], 'STOPPED_TOUCHPAD_DESCRIPTORS_FAILED')
        self.assertNotIn('report_descriptor', r)

    def test_uncertain_write_ends_without_replay(self):
        # The abort happens inside the transport's callback, so it must end the process (os._exit):
        # run it in a child and read what it saved.
        import os
        out = Path(tempfile.mkdtemp()) / 'out.json'
        pid = os.fork()
        if pid == 0:
            try:
                run_stage('descriptors', FakeProxy(fail_write_at=3), out, abort=os._exit)
            finally:
                os._exit(9)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 3)
        record = json.loads(out.read_text())
        self.assertEqual(record['status'], 'FAILED_TRANSPORT_UNCERTAIN_NO_FURTHER_MMIO')
        writes = [row for row in record['journal'] if row['op'] == 'write']
        self.assertEqual(len(writes), 4)
        self.assertTrue(writes[-1].get('transport_uncertain') and not writes[-1]['confirmed'])
        self.assertIs(record['journal'][-1], record['journal'][-1])
        self.assertEqual(record['journal'][-1]['op'], 'write')       # nothing after the uncertain write

    def test_firmware_busy_start_refused(self):
        p = FakeProxy({**IC20, 0x610: 1 << 10})
        r = run_stage('descriptors', p)
        self.assertEqual(r['status'], 'STOPPED_TOUCHPAD_START_REFUSED')
        self.assertEqual(p.writes, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
