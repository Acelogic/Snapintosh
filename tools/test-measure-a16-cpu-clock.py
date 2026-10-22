#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests for tools/measure-a16-cpu-clock.py and tools/a16-cpu-stub.S. No A16 access.

  python3 tools/test-measure-a16-cpu-clock.py            # fake proxy + stub audit + QEMU E2E
  SNAP_SKIP_QEMU=1 python3 tools/test-measure-a16-cpu-clock.py   # without QEMU

The fake proxy plays q1n1 and the stub's report contract; the QEMU cases run the
real stub at EL2 on two emulated CPUs (QEMU's cycle counter is a 1 GHz clock)
and, with the PMCCFILTR_EL0.NSH write patched out, prove the stub's EL2
cycle-counting setup is what makes the counter count.
"""
import copy
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
tool = runpy.run_path(str(ROOT / 'tools' / 'measure-a16-cpu-clock.py'), run_name='measure_clock')
Refused = tool['Refused']
HEAP = 0xb9e00000
MAGIC = tool['MAGIC']
NSH = 1 << 27


class FakeLink:
    def close(self):
        pass


class FakeProxy:
    """q1n1's proxy surface as the tool uses it, with the stub's effects simulated."""
    P_DC_CVAC, P_DC_CIVAC, P_DC_IVAC = 0x308, 0x30A, 0x303

    def __init__(self, ghz=None, cntfrq=19200000, behaviour=None):
        self.memory = {}
        self.link = FakeLink()
        self.exceptions = []
        self.ghz = ghz or {0x0: 1.2, 0x100: 1.2, 0x10000: 2.1}
        self.cntfrq = cntfrq
        self.b = dict(behaviour or {})
        self.calls = []
        self.cpu_on = []
        self.started = {}
        self.code = HEAP + tool['CODE_AT']
        # Pre-existing scratch content the tool must put back.
        for offset in (0x480000, 0x490000, 0x4a0000, 0x4b0000, 0x4b1000):
            self.writemem(HEAP + offset, bytes((offset >> 16) & 255 for _ in range(0x1000)))
        self.original = self.snapshot()

    def snapshot(self):
        return {a: bytes(self.readmem(HEAP + a, 0x1000)) for a in (0x480000, 0x490000, 0x4a0000, 0x4b0000, 0x4b1000)}

    def bootinfo(self):
        return dict(current_el=2, heap_base=HEAP, heap_size=64 << 20, stage_generation=1,
                    image_base=0xb0000000, timer_hz=self.cntfrq)

    def readmem(self, address, size, live=False):
        return bytes(self.memory.get(address + i, 0) for i in range(size))

    def writemem(self, address, data):
        for i, byte in enumerate(data):
            self.memory[address + i] = byte

    def words(self, address, count):
        return list(struct.unpack(f'<{count}Q', self.readmem(address, 8 * count)))

    def put(self, address, words):
        self.writemem(address, struct.pack(f'<{len(words)}Q', *words))

    def request(self, op, *args):
        self.calls.append(('request', op) + args)
        if op == self.P_DC_IVAC:
            for mpidr, cpu in self.started.items():
                if cpu.get('hold') and args[0] == cpu['report'] and not cpu.get('done'):
                    self.advance(mpidr, cpu)       # time passes between host polls

    def advance(self, mpidr, cpu):
        stop = struct.unpack('<Q', self.readmem(cpu['report'] + 4096, 8))[0]
        if not stop and cpu['progress'] < cpu['windows']:
            cpu['progress'] += 1
        words = self.report(mpidr, cpu['windows'], cpu['ticks'], secondary=True, count=cpu['progress'])
        if stop or cpu['progress'] >= cpu['windows'] or self.b.get('hold_fails'):
            cpu['done'] = True
            if self.b.get('hold_fails'):
                words[1] = 2
        else:
            words[0] = words[21] = 0                 # still running: no magic, not done
        words[24] = words[25] = cpu['progress']
        self.put(cpu['report'], words)

    def ic_ivau(self, address, size):
        self.calls.append(('ic_ivau', address, size))

    def flush_code(self, address, size):
        self.calls.append(('flush', address, size))

    def nop(self):
        pass

    def serror_state(self):
        return dict(before=0, during=0, unconsumed=0)

    def report(self, mpidr, windows, ticks, secondary=False, count=None):
        b = self.b
        count = windows if count is None else count
        pmcr, cfilt, mdcr = 0x41013000, 0, 0x6
        words = [0] * (64 if count == windows and windows <= 16 else 512)
        words[:26] = [MAGIC, b.get('status', 0), 8, (0x80000000 | mpidr) if not secondary else mpidr,
                      0x512f0010, self.cntfrq, 0, pmcr, 0, cfilt, mdcr,
                      pmcr | 1 if not b.get('d_left_set') else pmcr | 9,
                      mdcr, pmcr if not b.get('pmcr_not_restored') else pmcr | 1, 0, cfilt, mdcr,
                      windows, ticks, 0, 0, 1 if secondary else 0,
                      cfilt | (0 if b.get('nsh_missing') else NSH), b.get('pmintenset', 0), 0, count]
        words[6] = 0x000000001030500a | b.get('pmuver', 6) << 8
        rate = self.ghz.get(mpidr, 1.0)
        for i in range(count):
            dt = ticks + 7 if not b.get('long_window') else 3 * ticks
            dc = 0 if b.get('zero_cycles') else round(rate * 1e9 * dt / self.cntfrq)
            words[32 + 2 * i:34 + 2 * i] = [dt, dc]
        if b.get('sentinel'):
            words[7] = 2**64 - 1
        return words

    def call(self, address, *args, timeout=None):
        entry = address - self.code
        if entry == 0:
            out, windows, ticks = args
            if self.b.get('boot_exception'):
                self.exceptions.append(dict(esr=0x2000000))
            self.put(out, self.report(0x0, windows, ticks))
            return 0
        if entry in (4, 16):
            out, mpidr, report = args
            self.cpu_on.append(mpidr)
            returned = self.b.get('cpu_on', {}).get(mpidr, 0)
            self.put(out, [returned & (2**64 - 1), 8, mpidr, report, self.code + 0x340, 1, 0, 0])
            if returned == 0:
                windows, ticks = self.words(report + 136, 2)
                self.started[mpidr] = dict(polls=self.b.get('polls', 2), report=report, windows=windows, ticks=ticks,
                                           hold=entry == 16, progress=0)
            return 0
        if entry == 8:
            out, mpidr = args
            cpu = self.started.get(mpidr)
            if cpu is not None and cpu.get('hold'):
                if not cpu.get('done') and self.b.get('never_off') != mpidr:
                    self.advance(mpidr, cpu)
                state = 1 if cpu.get('done') and self.b.get('never_off') != mpidr else 0
                self.put(out, [state, 0, mpidr, 0, 0, 1, 0, 0])
                return 0
            if cpu is None:
                state = 1
            elif self.b.get('never_off') == mpidr or cpu['polls'] > 0:
                cpu['polls'] -= 1
                state = 0
            else:
                state = 1
                if not cpu.get('reported'):
                    self.put(cpu['report'], self.report(mpidr, cpu['windows'], cpu['ticks'], secondary=True))
                    cpu['reported'] = True
            self.put(out, [state, 0, mpidr, 0, 0, 1, 0, 0])
            return 0
        raise AssertionError(f'call to unexpected address {address:#x}')


def inventory(states=None, classes=None):
    cpus = []
    for mpidr in (0x0, 0x100, 0x200, 0x10000, 0x20000):
        cpus.append(dict(mpidr=hex(mpidr), flags=1, efficiency_class=(classes or {}).get(mpidr, int(mpidr >= 0x10000)),
                         affinity_state=(states or {}).get(mpidr, int(mpidr != 0))))
    return dict(boot_mpidr='0x0', psci_version_raw=0x10001, cpus=cpus,
                features={'0xc4000003': 0, '0x84000002': 0, '0xc4000004': 0})


class Measure(unittest.TestCase):
    blob = bytes(0x1000)
    psci = bytes(0x200)

    def session(self, proxy, inv=None, targets=(0x100, 0x10000), **options):
        record, saves = {}, []

        def collect(p, blob, query):
            self.assertIs(p, proxy)
            self.assertTrue(query)
            return copy.deepcopy(inv or inventory())
        options.setdefault('poll', 0)
        options.setdefault('sleep', lambda s: None)
        tool['session'](proxy, self.blob, self.psci, collect, list(targets), 8, 20.0, record,
                        lambda: saves.append(json.dumps(record)), a16=True, timer_hz=proxy.cntfrq, **options)
        return record, saves

    def test_boot_and_two_secondaries_measured_labelled_and_restored(self):
        proxy = FakeProxy()
        record, saves = self.session(proxy)
        cpus = record['cpus']
        self.assertEqual([c['affinity'] for c in cpus], ['0x0', '0x100', '0x10000'])
        self.assertEqual([c['route'] for c in cpus], ['P_CALL', 'PSCI CPU_ON', 'PSCI CPU_ON'])
        for cpu, ghz in zip(cpus, (1.2, 1.2, 2.1)):
            self.assertAlmostEqual(cpu['ghz_median'], ghz, places=3)
            self.assertTrue(cpu['stable'])
        self.assertEqual([c['tier'] for c in cpus], ['Performance', 'Performance', 'Prime'])
        self.assertAlmostEqual(cpus[2]['fraction_of_nominal'], round(2.1 / 4.4, 3))
        self.assertEqual(proxy.cpu_on, [0x100, 0x10000])          # one CPU_ON each, never retried
        self.assertTrue(record['scratch']['restored'])
        self.assertEqual(proxy.snapshot(), proxy.original)
        self.assertEqual(record['ticks'], 384000)
        self.assertIn('in_flight', json.loads(saves[1]))          # saved before the first call

    def test_secondary_report_cleaned_before_and_invalidated_after(self):
        proxy = FakeProxy()
        self.session(proxy, targets=(0x100,))
        ops = [c for c in proxy.calls if c[0] == 'request']
        secondary = HEAP + tool['SECONDARY_AT']
        self.assertIn(('request', proxy.P_DC_CIVAC, secondary, 512), ops)
        self.assertIn(('request', proxy.P_DC_IVAC, secondary, 512), ops)
        self.assertLess(ops.index(('request', proxy.P_DC_CIVAC, secondary, 512)),
                        ops.index(('request', proxy.P_DC_IVAC, secondary, 512)))
        self.assertIn(('request', proxy.P_DC_CVAC, proxy.code, len(self.blob)), ops)

    def test_a_cpu_already_on_refuses_before_any_cpu_on(self):
        proxy = FakeProxy()
        with self.assertRaisesRegex(Refused, 'must be OFF'):
            self.session(proxy, inv=inventory(states={0x200: 0}))
        self.assertEqual(proxy.cpu_on, [])
        self.assertEqual(proxy.snapshot(), proxy.original)

    def test_unknown_affinity_state_refuses(self):
        proxy = FakeProxy()
        inv = inventory()
        inv['cpus'][3].pop('affinity_state')
        with self.assertRaisesRegex(Refused, 'must be OFF'):
            self.session(proxy, inv=inv)
        self.assertEqual(proxy.cpu_on, [])

    def test_off_never_confirmed_keeps_scratch_reserved(self):
        proxy = FakeProxy(behaviour=dict(never_off=0x100))
        ticks = iter(range(0, 10**6, 1))
        with self.assertRaisesRegex(Refused, 'not confirmed OFF'):
            self.session(proxy, clock=lambda: next(ticks), off_seconds=3)
        self.assertEqual(proxy.cpu_on, [0x100])
        self.assertNotEqual(proxy.snapshot(), proxy.original)      # stub left in place: the CPU may run it

    def test_cpu_on_refusals_that_never_started_continue(self):
        proxy = FakeProxy(behaviour=dict(cpu_on={0x100: -3}))
        record, _ = self.session(proxy)
        self.assertEqual(record['cpus'][1], dict(affinity='0x100', role='secondary', route='PSCI CPU_ON',
                                                 refused='DENIED'))
        self.assertEqual(record['cpus'][2]['affinity'], '0x10000')
        self.assertTrue(record['scratch']['restored'])

    def test_uncertain_cpu_on_returns_stop_and_reserve(self):
        for code in (-4, -5, -6):
            proxy = FakeProxy(behaviour=dict(cpu_on={0x100: code}))
            with self.assertRaisesRegex(Refused, 'uncertain'):
                self.session(proxy)
            self.assertEqual(proxy.cpu_on, [0x100])
            self.assertNotEqual(proxy.snapshot(), proxy.original)

    def test_boot_exception_stops_before_secondaries(self):
        proxy = FakeProxy(behaviour=dict(boot_exception=True))
        with self.assertRaisesRegex(Refused, 'exception'):
            self.session(proxy)
        self.assertEqual(proxy.cpu_on, [])
        self.assertEqual(proxy.snapshot(), proxy.original)

    def test_boot_cpu_cannot_be_a_cpu_on_target(self):
        with self.assertRaisesRegex(Refused, 'P_CALL'):
            self.session(FakeProxy(), targets=(0x0,))

    def test_bad_reports_refused(self):
        for behaviour, reason in [(dict(status=2), 'status'), (dict(zero_cycles=True), 'cycles'),
                                  (dict(long_window=True), 'ticks for'), (dict(nsh_missing=True), 'NSH'),
                                  (dict(d_left_set=True), 'every cycle'), (dict(pmcr_not_restored=True), 'restored'),
                                  (dict(sentinel=True), 'sentinel'),
                                  (dict(status=4, pmintenset=0x80000001), 'PMINTENSET 0x80000001')]:
            proxy = FakeProxy(behaviour=behaviour)
            with self.assertRaisesRegex(Refused, reason, msg=str(behaviour)):
                self.session(proxy, targets=())

    def test_decode_checks_magic_parameters_and_timer(self):
        proxy = FakeProxy()
        words = proxy.report(0, 8, 384000)
        tool['decode'](words, 8, 384000, 19200000)
        for slot, value, reason in [(0, 0, 'magic'), (2, 4, 'EL2'), (17, 7, 'parameters'), (5, 0, 'CNTFRQ')]:
            bad = list(words)
            bad[slot] = value
            with self.assertRaisesRegex(Refused, reason):
                tool['decode'](bad, 8, 384000, None if slot == 5 else 19200000)
        with self.assertRaisesRegex(Refused, 'timer_hz'):
            tool['decode'](words, 8, 384000, 24000000)
        drift = list(words)
        drift[33] = int(drift[33] * 1.05)
        self.assertFalse(tool['decode'](drift, 8, 384000, 19200000)['stable'])

    def hold(self, proxy, inv=None, mpidr=0x10000, windows=240, **kw):
        record, saves = {}, []
        inv = copy.deepcopy(inv or inventory())
        scratch = tool['Scratch'](proxy, tool['scratch_ranges'](HEAP, self.blob, len(self.psci)))
        tool['upload'](proxy, proxy.code, self.blob)
        kw.setdefault('sleep', lambda s: None)
        kw.setdefault('poll', 0)
        h = tool['Hold'](proxy, inv, mpidr, 384000, scratch, record, lambda: saves.append(1),
                         timer_hz=19200000, windows=windows, **kw)
        return h, scratch, record

    def test_hold_keeps_a_cpu_busy_until_stopped(self):
        proxy = FakeProxy()
        h, scratch, record = self.hold(proxy)
        h.start()
        self.assertIsNotNone(scratch.reserved)                  # a CPU may be executing the stub
        self.assertGreaterEqual(h.wait(5), 5)
        ghz = h.samples()
        self.assertGreaterEqual(len(ghz), 5)
        self.assertTrue(all(abs(g - 2.1) < 0.01 for g in ghz))
        result = h.stop()
        self.assertIsNone(scratch.reserved)
        self.assertEqual(result['role'], 'hold')
        self.assertGreaterEqual(result['windows_done'], 5)
        self.assertLess(result['windows_done'], 240)
        self.assertAlmostEqual(result['ghz_median'], 2.1, places=3)
        self.assertEqual(proxy.cpu_on, [0x10000])
        self.assertTrue(scratch.restore()['restored'])
        self.assertEqual(proxy.snapshot(), proxy.original)
        stop = HEAP + tool['HOLD_STOP']
        self.assertIn(('request', proxy.P_DC_CVAC, stop, 64), proxy.calls)   # stop word cleaned to PoC

    def test_hold_refuses_unless_every_other_cpu_is_off(self):
        proxy = FakeProxy()
        h, _, _ = self.hold(proxy, inv=inventory(states={0x100: 0}))
        with self.assertRaisesRegex(Refused, 'must be OFF'):
            h.start()
        self.assertEqual(proxy.cpu_on, [])

    def test_hold_that_never_powers_off_keeps_scratch_reserved(self):
        proxy = FakeProxy(behaviour=dict(never_off=0x10000))
        ticks = iter(range(10**6))
        h, scratch, _ = self.hold(proxy, clock=lambda: next(ticks))
        h.start()
        h.wait(3)
        with self.assertRaisesRegex(Refused, 'not confirmed OFF'):
            h.stop()
        self.assertFalse(scratch.restore()['restored'])

    def test_hold_that_ends_early_or_fails_is_reported(self):
        proxy = FakeProxy()
        h, _, _ = self.hold(proxy, windows=4)
        h.start()
        with self.assertRaisesRegex(Refused, 'ended after 4'):
            h.wait(10)
        proxy = FakeProxy(behaviour=dict(hold_fails=True))
        h, _, _ = self.hold(proxy)
        h.start()
        with self.assertRaisesRegex(Refused, 'hold stub status'):
            h.wait(3)


class Admission(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / 'Snapintosh'
        (self.root / 'build' / 'run1').mkdir(parents=True)
        (self.root / 'tools').mkdir()
        self.ws = tool['Workspace'](self.root)
        self.ws.processes = lambda: {}

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def args(self, **kw):
        base = dict(output=self.tmp / 'out.json', after=None, idle=False, generation=1)
        base.update(kw)
        return type('Args', (), base)

    def launch(self, **kw):
        record = dict(status='STOPPED_PRESERVED', preservation_sha256='ab' * 32, pid=99, finished=1.0,
                      bootinfo=dict(stage_generation=1, heap_base=HEAP))
        record.update(kw)
        (self.root / 'build' / 'run1' / 'launch.json').write_text(json.dumps(record))

    def test_preserved_stop_admitted(self):
        self.launch()
        got = tool['admit'](self.args(after='run1'), self.ws)
        self.assertEqual(got['heap_base'], HEAP)

    def test_refusals(self):
        self.launch(status='STOPPED_STATE_CAPTURED')
        with self.assertRaisesRegex(Refused, 'not a preserved stop'):
            tool['admit'](self.args(after='run1'), self.ws)
        self.launch(bootinfo=dict(stage_generation=2, heap_base=HEAP))
        with self.assertRaisesRegex(Refused, 'generation'):
            tool['admit'](self.args(after='run1'), self.ws)
        self.launch()
        self.ws.processes = lambda: {99: (0.5, 1, 'python3 tools/cycle.py')}    # started before it finished
        with self.assertRaisesRegex(Refused, 'still present'):
            tool['admit'](self.args(after='run1'), self.ws)
        self.ws.processes = lambda: {}
        with self.assertRaisesRegex(Refused, 'no launch record'):
            tool['admit'](self.args(after='run2'), self.ws)
        with self.assertRaisesRegex(Refused, '--idle'):
            tool['admit'](self.args(), self.ws)
        (self.tmp / 'out.json').write_text('{}')
        with self.assertRaisesRegex(Refused, 'never overwritten'):
            tool['admit'](self.args(idle=True), self.ws)

    def test_snap_tree_points_a_copy_at_the_real_records(self):
        other = self.tmp / 'tree'
        (other / 'build' / 'run9').mkdir(parents=True)
        record = dict(status='STOPPED_PRESERVED', preservation_sha256='cd' * 32, pid=99, finished=1.0,
                      bootinfo=dict(stage_generation=1, heap_base=HEAP))
        (other / 'build' / 'run9' / 'launch.json').write_text(json.dumps(record))
        os.environ['SNAP_TREE'] = str(other)
        try:
            self.assertIn('run9', tool['admit'](self.args(after='run9'), self.ws)['launch'])
        finally:
            del os.environ['SNAP_TREE']
        with self.assertRaisesRegex(Refused, 'no launch record'):
            tool['admit'](self.args(after='run9'), self.ws)

    def test_other_hardware_client_refused(self):
        self.ws.processes = lambda: {4242: (1.0, 1, 'python3 ../q1n1/tools/q1n1proxy.py status')}
        with self.assertRaisesRegex(Refused, 'another hardware client'):
            tool['admit'](self.args(idle=True), self.ws)

    def test_resident_generation_and_boot_checked(self):
        proxy = FakeProxy()
        with self.assertRaisesRegex(Refused, 'generation 1, expected 2'):
            tool['check_resident'](proxy, self.args(generation=2), {})
        with self.assertRaisesRegex(Refused, 'another q1n1 boot'):
            tool['check_resident'](proxy, self.args(after='run1'), dict(heap_base=HEAP + 0x1000))
        proxy.serror_state = lambda: dict(before=1, during=0, unconsumed=0)
        with self.assertRaisesRegex(Refused, 'SError'):
            tool['check_resident'](proxy, self.args(), {})


class StubAudit(unittest.TestCase):
    """Every write the assembled stub can make, from its instructions."""

    @classmethod
    def setUpClass(cls):
        cls.out = Path(tempfile.mkdtemp())
        cls.blob = tool['build_stub'](cls.out)
        dump = subprocess.check_output([str(tool['run'].LLVM / 'llvm-objdump'), '-d', '--no-show-raw-insn',
                                        str(cls.out / 'a16-cpu-stub.o')], text=True)
        cls.insns = [re.sub(r'\s+', ' ', m[1]).strip()
                     for m in re.finditer(r'^\s+[0-9a-f]+:\s+(\S.*)$', dump, re.M)]
        cls.labels = {m[2]: int(m[1], 16) for m in re.finditer(r'^([0-9a-f]+) <(\w+)>:', dump, re.M)}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.out)

    def test_system_register_writes_are_the_declared_set(self):
        targets = {re.match(r'msr\s+(\w+),', i)[1].lower() for i in self.insns if i.startswith('msr')}
        self.assertEqual(targets, {'mdcr_el2', 'pmccfiltr_el0', 'pmcr_el0', 'pmcntenset_el0', 'pmcntenclr_el0',
                                   'vbar_el2', 'daifset'})

    def test_stores_only_through_report_or_stack(self):
        bases = set()
        for insn in self.insns:
            m = re.match(r'(str|stp|stur|strb|strh|stnp)\w*\s+.*\[(\w+)', insn)
            if m:
                bases.add(m[2])
        self.assertEqual(bases, {'sp', 'x19', 'x15', 'x17'})     # x17: report + R_PROGRESS
        self.assertFalse([i for i in self.insns if i.startswith(('dc zva', 'dc ivac', 'tlbi', 'at '))])

    def test_three_psci_calls_and_entry_table(self):
        self.assertEqual(sum(i.startswith('smc') for i in self.insns), 3)
        self.assertEqual(sum(i.startswith('hvc') for i in self.insns), 0)
        for offset, name in enumerate(('measure', 'start_secondary', 'affinity', 'sync', 'start_hold')):
            word = struct.unpack_from('<I', self.blob, 4 * offset)[0]
            self.assertEqual(word >> 26, 0b000101)
            self.assertEqual(4 * offset + 4 * (word & 0x3ffffff), self.labels[name])
        self.assertEqual(self.labels['secondary_vectors'] % 2048, 0)
        self.assertEqual(self.labels['secondary_entry'] % 64, 0)
        self.assertEqual(self.labels['hold_entry'] % 64, 0)
        self.assertLessEqual(len(self.blob), tool['RESULT_AT'] - tool['CODE_AT'])
        relocations = subprocess.check_output([str(tool['run'].LLVM / 'llvm-readelf'), '-r',
                                               str(self.out / 'a16-cpu-stub.o')], text=True)
        self.assertIn('There are no relocations', relocations)


@unittest.skipIf(os.environ.get('SNAP_SKIP_QEMU') or not shutil.which('qemu-system-aarch64') or
                 not (ROOT.parent / 'q1n1/build/uefi/q1n1.efi').exists(), 'QEMU or q1n1.efi unavailable')
class QemuE2E(unittest.TestCase):
    """The real stub at EL2 on q1n1 in QEMU, two CPUs, PSCI over SMC."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_cli_measures_both_cpus_at_qemus_one_ghz(self):
        out = self.tmp / 'clock.json'
        subprocess.run(['python3', str(ROOT / 'tools/measure-a16-cpu-clock.py'), '--qemu', '--output', str(out)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        record = json.loads(out.read_text())
        self.assertEqual(record['status'], 'MEASURED')
        self.assertEqual([c['affinity'] for c in record['cpus']], ['0x0', '0x1'])
        for cpu in record['cpus']:
            self.assertAlmostEqual(cpu['ghz_median'], 1.0, delta=0.01)
            self.assertTrue(all(cpu['pmu']['restored'].values()))
        self.assertTrue(record['scratch']['restored'])

    def test_hold_runs_until_the_stop_word(self):
        blob = tool['build_stub'](self.tmp / 'stub')
        collect = runpy.run_path(str(ROOT / 'tools/probe-a16-cpus.py'))['collect']
        psci = tool['run'].build('psci-info', self.tmp / 'probe')
        with tool['QemuSmp'](self.tmp / 'qemu') as sock:
            proxy = tool['run'].connect(sock, tries=90)
            try:
                base = proxy.bootinfo()['heap_base']
                scratch = tool['Scratch'](proxy, tool['scratch_ranges'](base, blob, len(psci)))
                inv = collect(proxy, psci, True)
                tool['upload'](proxy, base + tool['CODE_AT'], blob)
                hz = tool['probe_cntfrq'](proxy, blob, base)
                record = {}
                h = tool['Hold'](proxy, inv, 0x1, round(hz / 50), scratch, record, lambda: None, timer_hz=hz)
                h.start()
                h.wait(3)
                ghz = h.samples()
                self.assertTrue(len(ghz) >= 3 and all(abs(g - 1.0) < 0.01 for g in ghz), ghz)
                result = h.stop()
                self.assertTrue(3 <= result['windows_done'] < 240, result['windows_done'])
                self.assertAlmostEqual(result['ghz_median'], 1.0, delta=0.01)
                self.assertTrue(scratch.restore()['restored'])
            finally:
                proxy.link.close()

    def test_without_the_nsh_write_el2_counts_nothing(self):
        """Negative control: the same stub with its PMCCFILTR_EL0 write patched to a NOP."""
        out = self.tmp / 'stub'
        blob = bytearray(tool['build_stub'](out))
        dump = subprocess.check_output([str(tool['run'].LLVM / 'llvm-objdump'), '-d', str(out / 'a16-cpu-stub.o')],
                                       text=True)
        sites = [int(m[1], 16) for m in re.finditer(r'^\s+([0-9a-f]+):.*msr\s+PMCCFILTR_EL0, x28', dump, re.M)]
        self.assertEqual(len(sites), 1)
        struct.pack_into('<I', blob, sites[0], 0xd503201f)          # NOP
        with tool['QemuSmp'](self.tmp / 'qemu') as sock:
            proxy = tool['run'].connect(sock, tries=90)
            try:
                base = proxy.bootinfo()['heap_base']
                code, out_at = base + tool['CODE_AT'], base + tool['RESULT_AT']
                scratch = tool['Scratch'](proxy, [(code, len(blob)), (out_at, 512)])
                proxy.writemem(code, bytes(blob))
                proxy.flush_code(code, len(blob))
                proxy.writemem(out_at, bytes(512))
                proxy.call(code, out_at, 2, 1000000, timeout=10)
                words = tool['words_at'](proxy, out_at, 512)
                self.assertEqual(words[0], MAGIC)
                self.assertEqual(words[1], 0)
                self.assertFalse(words[22] & NSH)                       # PMCCFILTR_EL0 while measuring
                self.assertEqual([words[33], words[35]], [0, 0])        # no cycles counted at EL2
                with self.assertRaisesRegex(Refused, 'NSH'):
                    tool['decode'](words, 2, 1000000)
                self.assertTrue(scratch.restore()['restored'])
            finally:
                proxy.link.close()

if __name__ == '__main__':
    unittest.main()
