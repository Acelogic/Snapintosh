#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Initialise the A16 keyboard as an I2C-HID host would and read its input
register while the user presses keys, after a qualified XNU stop.

Failure inventory and plan: docs/A16-INPUT-DRIVER-20260928.md. --check-inputs
is offline: it verifies every pinned source, evidence artifact and derived
address, and writes the plan. Without it, this is a bounded hardware
transaction on IC20 (0x0088c000) and read-only observation of TLMM GPIO 67 and
of the GIC distributor's state for INTID 617. No clock, pin, interrupt-routing,
DMA, NVS or guest state is written. Never run beside another A16 client.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'tools/survey-a16-input-transaction.py'
TEMPLATE_SHA = '6b7532d982bd097c64794732421867aa75915f9e83330fedae3041bf595bde8f'
READER = ROOT / 'tools/read-a16-hid-descriptor.py'
READER_SHA = '1dbc171f55cfa135ea99f848caff29483408e964199a67b5bd261cbd75dddc61'
EVIDENCE = {
    'descriptor': ('build/a16-hid-descriptor-gen56-20260928-v1.json',
                   '3a8895c73445ad76141a9bf825a45a7b2e9f2220ab94f1c73711a7d92a811ff6'),
    'report': ('build/a16-hid-report-descriptor-gen57-20260928-v1.json',
               '7c55ad9ecc308853472f4f3c8e22461f93cb3b185217c5cb533be90193d7b8dc'),
    'state': ('build/a16-keyboard-state-gen59-20260928-v1.json',
              'ba7c0d49ebf7bf79c10e847983317200966ff0503d3b4b8601054f76bbe7889c'),
    'inventory': ('build/a16-input-resources-20260927-v1.json',
                  '7da1fb40b58e4dbc600ec5c3c68f74fb0125df6fad12b50e423e3c8798ff7b6b'),
}
REPORT_SHA = '0887190d374bd8f4ff9e5278af8e7831fc149714b1f681860cc87a9c27cbaacb'
# Facts only, read-only: the pinned A16 DSDT and the local copies of Linux's
# glymur.dtsi and ASUS Zenbook A16 (UX3607OA) device tree.
PROJECT = ROOT.parent
DSDT = (PROJECT / 'q1n1/build/a16-acpi/DSDT.dsl',
        '34b9c2f178c994dbea199cffe4ffbe77e7e7dc0435a247904e2e558b44e17a0b')
LINUX_DT = PROJECT / 'Snapintosh/gpu/adreno/adreno-hw/src'
DTS = (LINUX_DT / 'glymur-asus-zenbook-a16-ux3607oa.dts',
       'd771a6b89b4293288a77625e834753b4196c373f4c6317ce3d91af389740134f')
DTSI = (LINUX_DT / 'glymur.dtsi',
        '68ddaa6487a7d15e0f3bd4a868c1f4e1b3340d8b19b8ab5ab2ab5e534caf6a0d')
# Linux drivers/pinctrl/qcom/pinctrl-glymur.c (SHA256 07d26284..., fetched
# 2026-09-28): REG_SIZE 0x1000 per GPIO, io_reg = 0x4 + REG_SIZE * id, in_bit 0.
GPIO_STRIDE, GPIO_IO_OFFSET = 0x1000, 0x4

BASE, ADDR = 0x0088c000, 0x15
TLMM_BASE, TLMM_SPAN, GPIO = 0x0f100000, 0xf00000, 67
GPIO_PAGE = TLMM_BASE + GPIO * GPIO_STRIDE
GPIO_REGS = [('cfg', 0x0), ('in_out', 0x4), ('intr_cfg', 0x8), ('intr_status', 0xc)]
GICD, INTID = 0x17000000, 617
GIC_REGS = [('isenabler', 0x100 + 4 * (INTID // 32)), ('ispendr', 0x200 + 4 * (INTID // 32)),
            ('isactiver', 0x300 + 4 * (INTID // 32)), ('irouter_lo', 0x6000 + 8 * INTID),
            ('irouter_hi', 0x6000 + 8 * INTID + 4)]
DONE, CANCEL, ABORT, NACK = 1, 1 << 4, 1 << 5, 1 << 10
RX_WM, RX_LAST, TX_WM = 1 << 26, 1 << 27, 1 << 30
ERRORS = sum(1 << bit for bit in (1, 2, 3, 9, 10, 12, 13, 24, 25, 28, 29))
EVENTS = DONE | CANCEL | ABORT | RX_WM | RX_LAST | TX_WM | ERRORS
ACTIVE, TX_WORDS, RX_WORDS = 1 | (1 << 12), (1 << 28) - 1, (1 << 25) - 1
SET_POWER_ON, RESET = bytes.fromhex('05000008'), bytes.fromhex('05000001')
INPUT_BYTES, INPUT_WORDS = 64, 16
WINDOW_SECONDS, MAX_INPUT_READS, BLIND_INTERVAL = 30, 600, 0.25
WRITABLE = ['0x26c', '0x270', '0x600', '0x604', '0x614', '0x618', '0x700']
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def pinned(path, digest):
    assert sha(path) == digest, f'{path} differs from its pinned SHA256'
    return Path(path).read_text()


def load(key):
    rel, digest = EVIDENCE[key]
    return json.loads(pinned(ROOT / rel, digest))


def plan_inputs():
    """Everything the transaction relies on, derived from pinned inputs."""
    assert sha(TEMPLATE) == TEMPLATE_SHA and sha(READER) == READER_SHA
    descriptor = load('descriptor')['descriptor_transaction']
    assert descriptor['status'] == 'TWO_IDENTICAL_HID_DESCRIPTORS'
    first = descriptor['attempts'][0]
    fields = first['descriptor']
    assert (fields['vendor_id'], fields['product_id']) == (0x0b05, 0x4b42)
    assert (fields['command_register'], fields['maximum_input_length']) == (5, INPUT_BYTES)
    assert SET_POWER_ON[:2] == RESET[:2] == struct.pack('<H', fields['command_register'])
    report = load('report')['report_descriptor_transaction']
    assert {row['sha256'] for row in report['attempts']} == {REPORT_SHA}
    sizes = {row['report_id']: row['length_prefixed_bytes']
             for row in report['decoded']['reports'] if row['type'] == 'input'}
    assert sizes == {54: 11, 55: 5, 90: 8}
    state = load('state')['keyboard_state_transaction']
    assert state['status'] == 'FAILED' and state['error'] == "AssertionError('wrong HID length prefix')"
    assert {row['raw_hex'] for row in state['attempts']} == {'0000360000000000000000'}
    inventory = load('inventory')['devices']
    gpio = [r for r in inventory['ECKB']['resources']['RBUF']['decoded'] if r['type'] == 'gpio_interrupt']
    irq = [r for r in inventory['IC20']['resources']['RBUF']['decoded'] if r['type'] == 'extended_interrupt']
    assert len(gpio) == 1 and gpio[0]['pins'] == [704] and gpio[0]['provider'] == '\\_SB.GIO0'
    assert len(irq) == 1 and irq[0]['firmware_interrupts'] == [INTID]
    dsdt = pinned(*DSDT)
    gio0 = dsdt[dsdt.index('Device (GIO0)'):]
    head = re.search(r'/\* 0000 \*/([^/]*)//[^\n]*\n\s*/\* 0008 \*/([^/]*)//', gio0)
    raw = bytes(int(v, 16) for v in re.findall(r'0x([0-9A-F]{2})', head.group(1) + head.group(2)))
    assert raw[0] == 0x86 and struct.unpack_from('<II', raw, 4) == (TLMM_BASE, TLMM_SPAN), raw.hex()
    dts = pinned(*DTS)
    block = dts[dts.index('&i2c19 {'):]
    block = block[:block.index('\n};')]
    assert '/* ASUSTek 0B05:4B42 */' in block and 'keyboard@15 {' in block
    assert 'reg = <0x15>;' in block and 'hid-descr-addr = <0x1>;' in block
    assert f'interrupts-extended = <&tlmm {GPIO} IRQ_TYPE_LEVEL_LOW>;' in block
    reserved = dts[dts.index('gpio-reserved-ranges'):]
    reserved = reserved[:reserved.index(';')]
    for start, count in re.findall(r'<(\d+) (\d+)>', reserved):
        assert not int(start) <= GPIO < int(start) + int(count), 'GPIO 67 is reserved'
    dtsi = pinned(*DTSI)
    node = dtsi[dtsi.index('i2c19: i2c@88c000 {'):][:400]
    assert 'reg = <0x0 0x0088c000 0x0 0x4000>;' in node
    assert f'interrupts = <GIC_SPI {INTID - 32} IRQ_TYPE_LEVEL_HIGH>;' in node
    tlmm = dtsi[dtsi.index('tlmm: pinctrl@f100000 {'):][:400]
    assert f'reg = <0x0 {TLMM_BASE:#010x} 0x0 {TLMM_SPAN:#x}>;' in tlmm, tlmm[:200]
    assert 'gpio-ranges = <&tlmm 0 0 249>;' in tlmm
    intc = dtsi[dtsi.index('intc: interrupt-controller@17000000 {'):][:300]
    assert f'reg = <0x0 {GICD:#x} 0x0 0x10000>,' in intc
    assert TLMM_BASE <= GPIO_PAGE and GPIO_PAGE + 0x10 <= TLMM_BASE + TLMM_SPAN
    return dict(hid_descriptor=first['raw_hex'], input_sizes=sizes,
                command_register=fields['command_register'])


def classify(raw):
    length = int.from_bytes(raw[:2], 'little')
    if length in (0, 2):
        return dict(kind='empty', length=length)
    if length == 0xffff:
        return dict(kind='bogus', length=length)
    if length < 2 or length > INPUT_BYTES:
        return dict(kind='bad_length', length=length, raw=raw.hex())
    report = raw[2:length]
    row = dict(length=length, report_id=report[0], raw=raw[:length].hex())
    want = {54: 11, 55: 5, 90: 8}.get(report[0])
    if want is None:
        return dict(row, kind='unknown_id')
    if length != want:
        return dict(row, kind='wrong_size')
    row['kind'] = 'report'
    if report[0] == 54:
        keys = list(report[3:9])
        row.update(modifiers=report[1], reserved=report[2], keys=keys,
                   key_usages=[k for k in keys if k > 3], error_usages=[k for k in keys if 1 <= k <= 3])
    elif report[0] == 55:
        row.update(consumer_usage=int.from_bytes(report[1:3], 'little'))
    else:
        row.update(vendor=report[1:].hex())
    return row


def perform_input_check(proxy, values, record, output):
    expected = plan_inputs()
    # Repeat the qualified identity read with the pinned implementation first.
    source = READER.read_text().split('\ntemplate = ROOT / ', 1)[0]
    namespace = dict(__file__=str(READER))
    exec(compile(source, str(READER), 'exec'), namespace)
    namespace.update(ERRORS=ERRORS | CANCEL | ABORT, EVENTS=EVENTS)
    namespace['perform_descriptor'](proxy, values, record, output)
    assert record['descriptor_transaction']['attempts'][0]['raw_hex'] == expected['hid_descriptor'], \
        'physical HID descriptor identity changed'

    check = record['input_check'] = dict(
        controller_base=hex(BASE), peripheral_address=ADDR, gpio=GPIO, gpio_page=hex(GPIO_PAGE),
        intid=INTID, writes=0, pops=0, observations=[], status='STARTING')
    journal_path = output.with_name(output.stem + '.journal.jsonl')
    journal_file = journal_path.open('x')
    check['journal'] = str(journal_path)
    sound, changed, seq = True, False, 0

    def journal(entry):
        nonlocal seq
        seq += 1
        entry['seq'] = seq
        journal_file.write(json.dumps(entry) + '\n')
        journal_file.flush()
        os.fsync(journal_file.fileno())

    def save():
        output.write_text(json.dumps(record, indent=2) + '\n')

    def rd(address):
        nonlocal sound
        try:
            return proxy.read32(address)
        except BaseException:
            sound = False
            raise

    def read(offset):
        return rd(BASE + offset)

    def write(offset, value, purpose):
        nonlocal sound, changed
        assert hex(offset) in WRITABLE
        journal(dict(kind='write', offset=hex(offset), value=hex(value), purpose=purpose,
                     time=time.time()))
        record['mmio_writes'] = changed = True
        check['writes'] += 1
        try:
            proxy.write32(BASE + offset, value)
        except BaseException:
            sound = False
            journal(dict(kind='write-uncertain', offset=hex(offset)))
            raise
        journal(dict(kind='write-confirmed', offset=hex(offset), time=time.time()))

    def pop(index):
        nonlocal sound
        journal(dict(kind='pop', word=index, time=time.time()))
        record['fifo_data_reads'] = True
        check['pops'] += 1
        try:
            value = proxy.read32(BASE + 0x780)
        except BaseException:
            sound = False
            journal(dict(kind='pop-uncertain', word=index))
            raise
        journal(dict(kind='pop-confirmed', word=index, value=hex(value)))
        return value

    def guard():
        nonlocal sound
        try:
            state = proxy.serror_state()
            assert state['mechanism'] and not any(state[k] for k in ('before', 'during', 'unconsumed')), state
            return state
        except BaseException:
            sound = False
            raise

    def idle():
        return not read(0x40) & ACTIVE

    def acknowledge(status, purpose):
        if status & EVENTS:
            write(0x618, status & EVENTS, purpose)

    def wait_for(bits, label, timeout):
        deadline = time.monotonic() + timeout
        for _ in range(1024):
            status = read(0x610)
            if status & bits:
                return status
            if time.monotonic() >= deadline:
                break
            time.sleep(0.001)
        raise TimeoutError(label)

    def level():
        return rd(GPIO_PAGE + GPIO_IO_OFFSET) & 1

    def observe(label):
        row = dict(label=label, time=time.time())
        for name, offset in GPIO_REGS:
            row['gpio67_' + name] = hex(rd(GPIO_PAGE + offset))
        for name, offset in GIC_REGS:
            row['gicd_' + name] = hex(rd(GICD + offset))
        for name in ('isenabler', 'ispendr', 'isactiver'):
            row['intid617_' + name[2:]] = bool(int(row['gicd_' + name], 16) >> (INTID % 32) & 1)
        check['observations'].append(row)
        save()
        return row

    def begin(label):
        assert idle() and not read(0x800) & TX_WORDS and not read(0x804) & RX_WORDS, \
            f'{label}: busy or nonempty controller'
        status = read(0x610)
        assert not status & ERRORS, f'{label}: preexisting controller error {status:#x}'
        acknowledge(status, f'{label}: acknowledge prior events')

    def nacked(status, label):
        """A NACK that completed cleanly is a bus answer, not uncertainty."""
        if not (status & NACK and status & DONE):
            return False
        tx, rx = read(0x800), read(0x804)
        check.setdefault('nacks', []).append(dict(label=label, status=hex(status), tx_fifo=hex(tx),
                                                  rx_fifo=hex(rx), idle=idle()))
        save()
        if not idle() or tx & TX_WORDS or rx & RX_WORDS:
            raise RuntimeError(f'{label}: NACK left state behind (tx {tx:#x}, rx {rx:#x})')
        acknowledge(status, f'{label}: acknowledge NACK')
        return True

    def command(packet, label, allow_nack=False):
        """One complete I2C-HID command: WRITE ending with STOP."""
        begin(label)
        write(0x26c, len(packet), f'{label}: {len(packet)}-byte command')
        write(0x600, (1 << 27) | (ADDR << 9), f'{label}: WRITE with final STOP')
        for offset in range(0, len(packet), 4):
            write(0x700, int.from_bytes(packet[offset:offset + 4].ljust(4, b'\0'), 'little'),
                  f'{label}: TX FIFO word')
        status = wait_for(DONE | ERRORS, label, 1.0)
        if allow_nack and nacked(status, label):
            return 'nack'
        if status & ERRORS:
            raise RuntimeError(f'{label}: controller error {status:#x}')
        assert idle() and not read(0x800) & TX_WORDS, f'{label}: DONE with work left'
        final = read(0x610)
        assert not final & ERRORS, f'{label}: late error {final:#x}'
        acknowledge(status | final, f'{label}: acknowledge completion')
        return 'ok'

    def input_read(label, masked=False, allow_nack=False):
        """Plain READ of wMaxInputLength bytes: no register is written first."""
        begin(label)
        write(0x270, INPUT_BYTES, f'{label}: input read length')
        write(0x600, (2 << 27) | (ADDR << 9), f'{label}: plain READ with final STOP')
        words, seen = [], 0
        deadline = time.monotonic() + 1.0
        for _ in range(1024):
            status = read(0x610)
            seen |= status
            if status & ERRORS:
                if allow_nack and nacked(status, label):
                    return 'nack', seen, None
                raise RuntimeError(f'{label}: controller error {status:#x}')
            fifo = read(0x804)
            count = fifo & RX_WORDS
            assert count <= 32 and len(words) + count <= INPUT_WORDS, f'{label}: extra words {fifo:#x}'
            if count and fifo & (1 << 31):
                assert (fifo >> 28) & 7 in (0, 4) and len(words) + count == INPUT_WORDS, \
                    f'{label}: early or partial last word {fifo:#x}'
            for _ in range(count):
                words.append(pop(len(words)))
            engine_idle = idle() if masked else None
            if (not masked and status & DONE) or (masked and engine_idle and len(words) == INPUT_WORDS):
                assert len(words) == INPUT_WORDS, f'{label}: short read at completion'
                assert idle() and not read(0x804) & RX_WORDS, f'{label}: completion with work left'
                final = read(0x610)
                seen |= final
                assert not final & ERRORS, f'{label}: late error {final:#x}'
                acknowledge(status | final, f'{label}: acknowledge completion')
                return 'ok', seen, struct.pack(f'<{INPUT_WORDS}I', *words)
            if masked and engine_idle and not read(0x804) & RX_WORDS:
                raise RuntimeError(f'{label}: engine idle after {len(words)} words (status {seen:#x})')
            acknowledge(status & (RX_WM | RX_LAST), f'{label}: acknowledge receive service')
            if time.monotonic() >= deadline:
                break
            if not count:
                time.sleep(0.001)
        raise TimeoutError(label)

    saved = {0x26c: values['tx_transfer_length'], 0x270: values['rx_transfer_length'],
             0x614: values['master_irq_enable']}
    try:
        check['guard_before'] = guard()
        info = proxy.bootinfo()
        assert info['gic_distributor'] == GICD, f"bootinfo GICD {info['gic_distributor']:#x}"
        observe('before-commands')
        write(0x614, saved[0x614] | EVENTS, 'enable polled completion/error events (qualified path)')

        # SET_POWER(ON); a sleeping device may NACK once (Linux retries once).
        if command(SET_POWER_ON, 'set-power-on', allow_nack=True) == 'nack':
            time.sleep(0.001)
            command(SET_POWER_ON, 'set-power-on-retry')
        time.sleep(0.060)
        check['level_before_reset'] = level()

        # RESET, then watch the attention line (active low) for the acknowledgment.
        command(RESET, 'reset')
        reset_at = time.monotonic()
        samples = []
        while time.monotonic() - reset_at < 1.0 and len(samples) < 400:
            value = level()
            samples.append([round(time.monotonic() - reset_at, 4), value])
            if value == 0:
                break
            time.sleep(0.005)
        asserted = bool(samples) and samples[-1][1] == 0
        check['reset_attention'] = dict(asserted=asserted, samples=samples[:40],
                                        latency=samples[-1][0] if asserted else None)
        if not asserted:
            time.sleep(max(0.0, 0.1 - (time.monotonic() - reset_at)))
        while True:
            outcome, seen, raw = input_read('reset-sentinel', allow_nack=True)
            if outcome == 'ok':
                break
            if time.monotonic() - reset_at >= 1.0:
                raise RuntimeError('device NACKed input reads for one second after RESET')
            time.sleep(0.01)
        check['reset_sentinel'] = dict(raw=raw.hex(), **classify(raw))
        check['level_after_sentinel'] = level()
        command(SET_POWER_ON, 'set-power-on-after-reset')
        time.sleep(0.060)
        observe('initialised')

        # Capture window: read on attention, plus a blind read every 250 ms.
        window = check['window'] = dict(seconds=WINDOW_SECONDS, reads=0, attention_reads=0,
                                        blind_reads=0, level_samples=0, level_changes=[],
                                        empty_attention=0, empty_blind=0, bogus=0, nacks=0,
                                        reports=[], rejected=[])
        print(json.dumps(dict(prompt='PRESS AND RELEASE KEYS ON THE A16 NOW', seconds=WINDOW_SECONDS,
                              suggested=['A', 'Shift+A', 'Caps Lock', 'Volume Up'])),
              file=sys.stderr, flush=True)
        start = time.monotonic()
        blind_next, last_level = start, None
        while time.monotonic() - start < WINDOW_SECONDS and window['reads'] < MAX_INPUT_READS:
            value = level()
            window['level_samples'] += 1
            now = time.monotonic()
            if value != last_level and len(window['level_changes']) < 2000:
                window['level_changes'].append([round(now - start, 4), value])
            last_level = value
            if value and now < blind_next:
                time.sleep(0.002)
                continue
            via = 'attention' if not value else 'blind'
            if via == 'blind':
                blind_next = now + BLIND_INTERVAL
            window['reads'] += 1
            window[via + '_reads'] += 1
            outcome, seen, raw = input_read(f'input-{window["reads"]}', allow_nack=True)
            if outcome == 'nack':
                window['nacks'] += 1
                continue
            row = dict(classify(raw), t=round(now - start, 4), via=via)
            if row['kind'] == 'report':
                row['level_after'] = level()
                window['reports'].append(row)
                save()
            elif row['kind'] == 'empty':
                window['empty_' + via] += 1
            elif row['kind'] == 'bogus':
                window['bogus'] += 1
            else:
                window['rejected'].append(row)
                save()

        # Does M_IRQ_STATUS latch with every master enable cleared?
        write(0x614, 0, 'clear master interrupt enables for the latch probe')
        outcome, seen, raw = input_read('latch-probe', masked=True)
        check['latch_probe'] = dict(status_seen=hex(seen), done_latched=bool(seen & DONE),
                                    rx_last_latched=bool(seen & RX_LAST), **classify(raw))
        write(0x614, saved[0x614] | EVENTS, 're-enable polled events after the latch probe')
        acknowledge(read(0x610), 'acknowledge events latched during the probe')
        observe('after-commands')
        check['status'] = 'INPUT_CHECKED'
    except BaseException as error:
        check.update(status='FAILED', error=repr(error))
        raise
    finally:
        cleanup = check['cleanup'] = dict(transport_sound=sound, restored=False)
        try:
            if changed and sound:
                cleanup['guard_before'] = guard()
                if not idle():
                    for control, completed, label in ((4, CANCEL, 'cancel'), (2, ABORT, 'abort')):
                        write(0x604, control, 'bounded cleanup ' + label)
                        try:
                            acknowledge(wait_for(completed, label, 0.5), 'acknowledge cleanup ' + label)
                        except TimeoutError:
                            cleanup[label + '_timeout'] = True
                        if idle():
                            break
                assert idle(), 'cleanup could not idle the controller'
                acknowledge(read(0x610), 'acknowledge observed final events')
                for offset, value in saved.items():
                    write(offset, value, 'restore saved controller setting')
                    assert read(offset) == value, 'controller setting did not restore'
                cleanup.update(restored=True, engine_status=hex(read(0x40)),
                               tx_fifo_status=hex(read(0x800)), rx_fifo_status=hex(read(0x804)),
                               io_status=hex(read(0x908)), guard_after=guard())
                cleanup['fifos_empty'] = not (int(cleanup['tx_fifo_status'], 16) & TX_WORDS or
                                              int(cleanup['rx_fifo_status'], 16) & RX_WORDS)
                cleanup['io_inputs_match'] = int(cleanup['io_status'], 16) & 3 == values['io_status'] & 3
                assert cleanup['fifos_empty'] and cleanup['io_inputs_match'], \
                    'cleanup left data or changed IO inputs'
            elif changed:
                cleanup['reason'] = 'uncertain transport or SError; no further MMIO attempted'
        except BaseException as error:
            cleanup['error'] = repr(error)
            check['status'] = 'FAILED'
            raise
        finally:
            journal_file.close()
            check['journal_sha256'] = sha(journal_path)
            save()
    assert check['status'] == 'INPUT_CHECKED' and cleanup['restored']
    reports = check['window']['reports']
    pressed = [i for i, r in enumerate(reports) if r['report_id'] == 54 and r['key_usages']]
    released = bool(pressed) and any(r['report_id'] == 54 and not any(r['keys']) and not r['modifiers']
                                     for r in reports[pressed[0] + 1:])
    if not pressed:
        check['verdict'] = 'RESPONSIVE_NO_KEY_REPORTS'
    elif not released:
        check['verdict'] = 'KEY_PRESS_WITHOUT_RELEASE'
    elif check['reset_sentinel']['kind'] != 'empty':
        check['verdict'] = 'KEY_REPORTS_WITHOUT_RESET_ACKNOWLEDGMENT'
    else:
        check['verdict'] = 'KEY_REPORTS_OBSERVED'

    save()


def main():
    plan = plan_inputs()
    source = TEMPLATE.read_text()
    dispatch = "exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))"
    assert source.count(dispatch) == 1
    namespace = dict(__file__=str(TEMPLATE), __name__='prepared_survey')
    exec(compile(source.replace(dispatch, 'GENERATED_SOURCE = source'), str(TEMPLATE), 'exec'), namespace)
    source = namespace['GENERATED_SOURCE']
    anchor = '    if args.check_inputs:'
    assert source.count(anchor) == 1
    details = dict(
        peripheral_address=ADDR, identity_hid_descriptor=plan['hid_descriptor'],
        commands=dict(set_power_on=SET_POWER_ON.hex(), reset=RESET.hex()),
        input_read=dict(bytes=INPUT_BYTES, words=INPUT_WORDS, register_write=False,
                        report_sizes=plan['input_sizes']),
        sequence=['29-register survey', 'pinned 30-byte HID descriptor read x2',
                  'read-only GIC INTID617 + TLMM GPIO67 observation', 'SET_POWER(ON), 60 ms',
                  'RESET, wait for GPIO67 low (<=1 s, >=100 ms without it)',
                  'input read: expect length 0', 'SET_POWER(ON), 60 ms',
                  f'{WINDOW_SECONDS} s window: read on GPIO67 low, blind read every {BLIND_INTERVAL} s',
                  'one input read with M_IRQ_EN=0 (latch probe)', 'restore TX/RX length and M_IRQ_EN'],
        writable_offsets=WRITABLE, fifo_pop_offset='0x780',
        read_only=dict(gpio_page=hex(GPIO_PAGE), gpio_registers=[hex(GPIO_PAGE + o) for _, o in GPIO_REGS],
                       gicd=hex(GICD), gic_registers=[hex(GICD + o) for _, o in GIC_REGS]),
        bounds=dict(window_seconds=WINDOW_SECONDS, max_input_reads=MAX_INPUT_READS,
                    command_timeout_seconds=1, cleanup_timeout_seconds=0.5),
        pins=dict(template=TEMPLATE_SHA, descriptor_reader=READER_SHA,
                  evidence={k: v[1] for k, v in EVIDENCE.items()},
                  dsdt=DSDT[1], dts=DTS[1], dtsi=DTSI[1]),
        guest_input_verified=False)
    source = source.replace(anchor,
        "    record['operation'] = 'BOUNDED_ECKB_I2C_HID_RESET_AND_INPUT_READS'\n"
        "    record['boundary'] = 'Physical keyboard input-register reports only; no guest IOHID delivery'\n"
        "    record['input_check_plan'] = " + repr(details) + '\n' + anchor)
    anchor = "        proxy.read64(previous['address'])  # Poll a late SError after successful reads."
    assert source.count(anchor) == 1
    source = source.replace(anchor,
        "        perform_input_check(proxy, {name: row['value'] for name,row in record['registers'].items()}, record, args.output)\n" + anchor)
    source = source.replace('STOPPED_IC20_REGISTERS_CAPTURED', 'STOPPED_A16_HID_INPUT_CHECKED')
    exec(compile(source, str(TEMPLATE), 'exec'), dict(__file__=__file__, __name__='__main__',
                                                     perform_input_check=perform_input_check))


if __name__ == '__main__':
    main()
