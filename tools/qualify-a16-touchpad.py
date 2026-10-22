#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify the A16 touchpad's I2C controller on a stopped, quiesced installed-fresh run.

The touchpad is TCPD (firmware-selected ASUF1209, generation 57): I2C1 / Linux i2c0 at 0x00B80000,
HID-over-I2C address 0x15, HID descriptor register 1, expected 2808:0219 (Linux DTS label). Nothing has
read that controller yet: an unclocked QUP can fault or stall on the first read, which is why the
kext's loader refuses the touchpad (probes/i2cinput.py TOUCHPAD_QUALIFIED) until this passes.
Same discipline as IC20 in generations 54-57 (docs/A16-INPUT-SURVEY-20260928.md,
docs/A16-HID-DESCRIPTOR-TRANSACTION-20260928.md, docs/A16-HID-REPORT-DESCRIPTOR-20260928.md).

    python3 tools/qualify-a16-touchpad.py plan --output OUT.json
    python3 tools/qualify-a16-touchpad.py survey --after-prefix RUN --output SURVEY.json
    python3 tools/qualify-a16-touchpad.py descriptors --after-prefix RUN --survey SURVEY.json --output DESC.json

survey: reads 29 status/configuration registers, one at a time, under q1n1's strict SError guard,
stopping at the first failed read. It writes nothing, issues no command, pops no FIFO word and
clears no interrupt. It qualifies the controller only when every check geni_i2c_start makes holds:
protocol 3 (I2C), FIFO interface on, DMA off, serial clock on with a divider, byte granularity 0,
packing 0x7f8fe/0xffefe both ways, 32-bit FIFO words at least 8 deep, both engines idle, both FIFOs
empty, no latched error.

descriptors: needs a qualifying survey of the same stopped generation. It drives the controller
through the kext's own transport (drivers/snap-i2c-hid/src/geni-i2c.c, built here as a host
library; every register access goes to the q1n1 proxy and is journaled, intent then
confirmation). geni_i2c_start with the masked policy (writes M_IRQ_EN = 0), then per read a WRITE
of the 2-byte register select with STOP_STRETCH and a READ: the 30-byte HID descriptor twice, which
must agree, then (when the descriptor parses) the report descriptor twice. geni_i2c_stop restores
TX/RX length and M_IRQ_EN. No SET_POWER, no RESET, no input-report read. Writes are limited to
TX/RX length, M_CMD0, M_CMD_CTRL, M_IRQ_EN, M_IRQ_CLEAR and the TX FIFO, all inside the first 4 KiB;
any other write, or any proxy error, ends the process at once (an uncertain RPC is never replayed;
a controller left mid-transfer has M_IRQ_EN = 0, which SnapI2CHID's start recovers).

Both stages: the run must be STOPPED_PRESERVED with its preservation record intact and its GPU
quiesced (quiesce.json); the resident stage, generation, locator and parked service words are
admitted as cycle.py installed-fresh --after-quiesce admits them; no other hardware client; the
hardware lock is held. Outputs are new files outside build/RUN*.
"""
from pathlib import Path
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'probes'))
BASE, EXTENT, PAGE = 0x00B80000, 0x4000, 0x1000
ADDRESS, DESCRIPTOR_REGISTER, EXPECTED = 0x15, 1, (0x2808, 0x0219)
# The IC20 survey's 16 registers plus the transaction survey's 13 (tools/survey-a16-input*.py).
REGISTERS = [('firmware_revision', 0x68), ('fifo_disabled', 0x64), ('engine_status', 0x40),
             ('master_clock', 0x48), ('clock_control', 0x60), ('clock_select', 0x7c), ('dma_mode', 0x258),
             ('master_irq_status', 0x610), ('slave_irq_status', 0x640), ('tx_fifo_status', 0x800),
             ('rx_fifo_status', 0x804), ('io_status', 0x908), ('dma_interface', 0xe20),
             ('hardware_parameter0', 0xe24), ('hardware_parameter1', 0xe28), ('hardware_parameter2', 0xe2c),
             ('byte_granularity', 0x254), ('tx_packing0', 0x260), ('tx_packing1', 0x264),
             ('tx_transfer_length', 0x26c), ('rx_transfer_length', 0x270), ('scl_counters', 0x278),
             ('rx_packing0', 0x284), ('rx_packing1', 0x288), ('master_irq_enable', 0x614),
             ('slave_irq_enable', 0x644), ('tx_watermark', 0x80c), ('rx_watermark', 0x810),
             ('rx_rfr_watermark', 0x814)]
WRITABLE = {0x26c, 0x270, 0x600, 0x604, 0x614, 0x618, 0x700}
IRQ_ERRORS = 0x3300360E           # geni-i2c.h GENI_IRQ_ERRORS
DRIVER = ROOT / 'drivers/snap-i2c-hid/src'
TIME_SCALE = 10                   # the transport's deadlines, stretched for ~2 ms proxy round trips
LOCK = Path('/tmp/snapintosh-hardware.lock')

sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def qualify(values):
    """geni_i2c_start's checks on the surveyed values: (qualified, [reasons])."""
    v = values
    reasons = []
    checks = [
        ((v['firmware_revision'] >> 8) & 0xff == 3, 'protocol is not 3 (I2C)'),
        (not v['fifo_disabled'] & 1, 'FIFO interface disabled'),
        (not v['dma_mode'] & 1, 'DMA mode enabled'),
        (v['master_clock'] & 1 and (v['master_clock'] >> 4) & 0xfff, 'serial clock off or no divider'),
        (v['byte_granularity'] == 0, 'byte granularity not 0'),
        (v['tx_packing0'] == 0x7f8fe and v['tx_packing1'] == 0xffefe, 'TX packing differs'),
        (v['rx_packing0'] == 0x7f8fe and v['rx_packing1'] == 0xffefe, 'RX packing differs'),
        ((v['hardware_parameter0'] >> 24) & 63 == 32 and (v['hardware_parameter1'] >> 24) & 63 == 32,
         'FIFO words are not 32 bits'),
        ((v['hardware_parameter0'] >> 16) & 63 >= 8 and (v['hardware_parameter1'] >> 16) & 63 >= 8,
         'FIFO shallower than 8 words'),
        (not v['engine_status'] & ((1 << 0) | (1 << 12)), 'an engine is active'),
        (not v['tx_fifo_status'] & 0x0fffffff and not v['rx_fifo_status'] & 0x01ffffff, 'a FIFO holds words'),
        (not v['master_irq_status'] & IRQ_ERRORS, 'an error is latched'),
    ]
    for ok, why in checks:
        if not ok:
            reasons.append(why)
    return not reasons, reasons


def stopped_run(prefix, device):
    """The installed-fresh run this observation follows: stopped, preserved, GPU quiesced."""
    from cycle_lib import installed_fresh as f
    from cycle_lib.bootstrap_smoke import modules
    runner, layout, admission = modules(ROOT)
    dest = ROOT / 'build' / prefix
    launch = json.loads((dest / 'launch.json').read_text())
    assert launch['status'] == 'STOPPED_PRESERVED', launch['status']
    assert sha(dest / 'preservation.json') == launch['preservation_sha256'], 'preservation record changed'
    quiet = json.loads((dest / 'quiesce.json').read_text())
    assert quiet.get('quiesce') == 'graceful', 'the GPU was not quiesced gracefully'
    predecessor = f.predecessor_stop(ROOT, prefix, layout)
    admission.other_clients(device)
    return runner, f, launch, predecessor


def connect(runner, f, launch, predecessor, device, record):
    proxy = runner.connect(device, tries=1)
    generation = launch['bootinfo']['stage_generation']
    info = f.admit(proxy, record, generation, runner, predecessor)
    blob = proxy.readmem(info['heap_base'] + runner.CODE_AT, launch['monitor_bytes'])
    assert hashlib.sha256(blob).hexdigest() == launch['monitor_sha256'], 'resident monitor differs from the run'
    return proxy, info


def guarded(proxy, record, body):
    """Strict SError guard around body(); restore the previous strictness whatever happens."""
    previous = proxy.serror_state()
    record['guard_before'] = previous
    assert previous['mechanism'] and not any(previous[k] for k in ('before', 'during', 'unconsumed'))
    proxy.serror_reset()
    proxy.serror_strict(True)
    try:
        body()
        proxy.read64(previous['address'])           # poll a late SError after the last access
        record['guard_after'] = proxy.serror_state()
        assert not any(record['guard_after'][k] for k in ('before', 'during', 'unconsumed')), record['guard_after']
    finally:
        proxy.serror_strict(bool(previous['flags'] & 1))


def write_record(path, record):
    path.write_text(json.dumps(record, indent=2, default=str) + '\n')


# ------------------------------------------------------------------ survey ----
def survey(proxy, record, output):
    record['registers'] = {}

    def body():
        for name, offset in REGISTERS:
            record['reading'] = dict(name=name, address=hex(BASE + offset))
            write_record(output, record)
            value = proxy.read32(BASE + offset)
            record['registers'][name] = dict(address=hex(BASE + offset), value=value, hex=hex(value))
        record.pop('reading', None)
    guarded(proxy, record, body)
    values = {n: r['value'] for n, r in record['registers'].items()}
    ok, reasons = qualify(values)
    record['qualification'] = dict(qualified=ok, reasons=reasons,
        protocol=(values['firmware_revision'] >> 8) & 0xff,
        tx_fifo_words=(values['hardware_parameter0'] >> 16) & 63,
        rx_fifo_words=(values['hardware_parameter1'] >> 16) & 63,
        scl_high=(values['scl_counters'] >> 20) & 1023, scl_low=(values['scl_counters'] >> 10) & 1023,
        scl_cycle=values['scl_counters'] & 1023, master_irq_enable=hex(values['master_irq_enable']))
    record['status'] = ('STOPPED_TOUCHPAD_CONTROLLER_QUALIFIED' if ok
                        else 'STOPPED_TOUCHPAD_CONTROLLER_NOT_QUALIFIED')


# ------------------------------------------------------------- descriptors ----
SHIM = r'''
#include "geni-i2c.h"
#include "i2c-hid.h"
#include "hid-rdesc.h"
static struct geni_i2c bus;
int shim_start(uint32_t (*r)(void *, uint32_t), void (*w)(void *, uint32_t, uint32_t),
               uint64_t (*n)(void *), void (*d)(void *, uint32_t))
{
    const struct geni_i2c_io io = {0, r, w, n, d};
    return geni_i2c_start(&bus, &io, 400000, GENI_I2C_IRQ_MASKED);
}
int shim_read_register(uint8_t addr, uint16_t reg, uint8_t *buf, uint32_t len)
{
    uint8_t sel[2] = {(uint8_t)reg, (uint8_t)(reg >> 8)};
    int r = geni_i2c_write(&bus, addr, sel, 2, 1);
    return r ? r : geni_i2c_read(&bus, addr, buf, len);
}
int shim_stop(void) { return geni_i2c_stop(&bus); }
void shim_state(uint32_t *o)
{
    o[0] = bus.found_status; o[1] = bus.found_irq; o[2] = bus.found_irq_en; o[3] = bus.found_tx_fifo;
    o[4] = bus.found_rx_fifo; o[5] = bus.recovered; o[6] = bus.wedged; o[7] = bus.last_status;
    o[8] = bus.last_tx_fifo; o[9] = bus.last_rx_fifo; o[10] = bus.last_result; o[11] = bus.saved_irq_en;
    o[12] = bus.saved_tx_len; o[13] = bus.saved_rx_len; o[14] = bus.tx_fifo_words; o[15] = bus.rx_fifo_words;
}
int shim_parse_desc(const uint8_t *raw, uint16_t *o)
{
    struct i2c_hid_desc d;
    int r = i2c_hid_parse_desc(raw, 30, &d);
    o[0] = d.version; o[1] = d.rdesc_length; o[2] = d.rdesc_register; o[3] = d.input_register;
    o[4] = d.max_input; o[5] = d.output_register; o[6] = d.max_output; o[7] = d.command_register;
    o[8] = d.data_register; o[9] = d.vendor_id; o[10] = d.product_id; o[11] = d.device_version;
    return r;
}
int shim_parse_rdesc(const uint8_t *raw, uint32_t len) { struct hid_rdesc_info i; return hid_rdesc_parse(raw, len, &i); }
const char *shim_result(int r) { return geni_i2c_result_name(r); }
'''
SOURCES = ('geni-i2c.c', 'i2c-hid.c', 'hid-rdesc.c')
STATE = ('found_status', 'found_irq', 'found_irq_en', 'found_tx_fifo', 'found_rx_fifo', 'recovered', 'wedged',
         'last_status', 'last_tx_fifo', 'last_rx_fifo', 'last_result', 'saved_irq_en', 'saved_tx_len',
         'saved_rx_len', 'tx_fifo_words', 'rx_fifo_words')


def transport_library(work):
    shim = Path(work) / 'shim.c'
    shim.write_text(SHIM)
    lib = Path(work) / 'libtouchpad-transport.dylib'
    subprocess.run(['cc', '-std=gnu11', '-O1', '-shared', '-fPIC', '-Wall', '-Werror', f'-I{DRIVER}', str(shim),
                    *(str(DRIVER / s) for s in SOURCES), '-o', str(lib)], check=True)
    return ctypes.CDLL(str(lib))


def descriptors(proxy, record, output, abort=os._exit):
    """The bounded descriptor transactions through the kext's transport. abort() ends the process
    on any proxy error or disallowed write, after the record and journal are saved."""
    journal = record.setdefault('journal', [])
    work = tempfile.mkdtemp(prefix='touchpad-transport-')
    lib = transport_library(work)
    record['transport_sources_sha256'] = {s: sha(DRIVER / s) for s in SOURCES}

    def fatal(why):
        record['status'] = 'FAILED_TRANSPORT_UNCERTAIN_NO_FURTHER_MMIO'
        record['error'] = why
        write_record(output, record)
        abort(3)

    READ = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32)
    WRITE = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32)
    NOW = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)
    DELAY = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint32)
    counts = dict(reads=0, writes=0, rx_pops=0)

    def read32(_, offset):
        if offset >= PAGE or offset & 3:
            fatal(f'read outside the first page: {offset:#x}')
        counts['reads'] += 1
        if offset == 0x780:
            counts['rx_pops'] += 1
            journal.append(dict(op='rx-pop-intent', time=time.time()))
        try:
            value = proxy.read32(BASE + offset)
        except BaseException as error:
            fatal(f'read {offset:#x}: {error!r}')
        if offset == 0x780:
            journal[-1].update(op='rx-pop', confirmed=True)
        return value & 0xffffffff

    def write32(_, offset, value):
        if offset not in WRITABLE:
            fatal(f'write outside the tools\' set: {offset:#x}')
        row = dict(op='write', offset=hex(offset), value=hex(value), intent_time=time.time(), confirmed=False)
        journal.append(row)
        counts['writes'] += 1
        try:
            proxy.write32(BASE + offset, value)
        except BaseException as error:
            row['transport_uncertain'] = True
            fatal(f'write {offset:#x}: {error!r}')
        row.update(confirmed=True)

    now = NOW(lambda _: int(time.monotonic() * 1e6) // TIME_SCALE)
    delay = DELAY(lambda _, us: time.sleep(us / 1e6))
    callbacks = (READ(read32), WRITE(write32), now, delay)       # kept alive for the C side
    lib.shim_result.restype = ctypes.c_char_p
    name = lambda r: lib.shim_result(r).decode()
    state = (ctypes.c_uint32 * 16)()

    def snapshot():
        lib.shim_state(state)
        return {k: (hex(v) if k.startswith(('found', 'last_s', 'last_t', 'last_rx', 'saved_irq')) else v)
                for k, v in zip(STATE, state)}

    def body():
        r = lib.shim_start(*callbacks)
        record['start'] = dict(result=name(r), state=snapshot())
        write_record(output, record)
        if r:
            record['status'] = 'STOPPED_TOUCHPAD_START_REFUSED'
            return
        attempts = record.setdefault('descriptor_attempts', [])
        for _ in range(2):
            buf = (ctypes.c_uint8 * 30)()
            r = lib.shim_read_register(ADDRESS, DESCRIPTOR_REGISTER, buf, 30)
            attempts.append(dict(result=name(r), raw_hex=bytes(buf).hex() if not r else None, state=snapshot()))
            write_record(output, record)
            if r:
                break
        ok = len(attempts) == 2 and all(a['result'] == 'ok' for a in attempts) and \
            attempts[0]['raw_hex'] == attempts[1]['raw_hex']
        if ok:
            raw = bytes.fromhex(attempts[0]['raw_hex'])
            fields = (ctypes.c_uint16 * 12)()
            parsed = lib.shim_parse_desc(raw, fields)
            names = ('version', 'report_descriptor_length', 'report_descriptor_register', 'input_register',
                     'max_input', 'output_register', 'max_output', 'command_register', 'data_register',
                     'vendor_id', 'product_id', 'device_version')
            record['hid_descriptor'] = dict(parse_result=parsed, **{n: v for n, v in zip(names, fields)})
            identity = (fields[9], fields[10])
            record['hid_descriptor']['identity'] = '%04x:%04x' % identity
            record['hid_descriptor']['expected_identity'] = '%04x:%04x' % EXPECTED
            if parsed == 0:
                rlen, rreg = fields[1], fields[2]
                rattempts = record.setdefault('report_descriptor_attempts', [])
                for _ in range(2):
                    rbuf = (ctypes.c_uint8 * rlen)()
                    r = lib.shim_read_register(ADDRESS, rreg, rbuf, rlen)
                    raw2 = bytes(rbuf)
                    rattempts.append(dict(result=name(r), raw_hex=raw2.hex() if not r else None,
                                          sha256=hashlib.sha256(raw2).hexdigest() if not r else None,
                                          state=snapshot()))
                    write_record(output, record)
                    if r:
                        break
                same = len(rattempts) == 2 and all(a['result'] == 'ok' for a in rattempts) and \
                    rattempts[0]['raw_hex'] == rattempts[1]['raw_hex']
                if same:
                    record['report_descriptor'] = dict(bytes=rlen, sha256=rattempts[0]['sha256'],
                        parse_result=lib.shim_parse_rdesc(bytes.fromhex(rattempts[0]['raw_hex']), rlen))
        r = lib.shim_stop()
        record['stop'] = dict(result=name(r), state=snapshot())
        good = (ok and record['hid_descriptor']['parse_result'] == 0 and
                record.get('report_descriptor', {}).get('parse_result') == 0 and r == 0)
        record['status'] = ('STOPPED_TOUCHPAD_DESCRIPTORS_VERIFIED' if good and
                            record['hid_descriptor']['identity'] == record['hid_descriptor']['expected_identity']
                            else 'STOPPED_TOUCHPAD_DESCRIPTORS_UNEXPECTED_IDENTITY' if good
                            else 'STOPPED_TOUCHPAD_DESCRIPTORS_FAILED')
    guarded(proxy, record, body)
    record['mmio'] = counts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('stage', choices=('plan', 'survey', 'descriptors'))
    ap.add_argument('--after-prefix')
    ap.add_argument('--survey', type=Path, help='descriptors: the qualifying survey record')
    ap.add_argument('--device', help='default: the workspace device (cycle_lib pins.json)')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    if args.output.exists():
        raise SystemExit(f'{args.output} exists; outputs are written once')
    record = dict(schema='snapintosh-a16-touchpad-qualification-v1', stage=args.stage, status='PLAN_VERIFIED',
                  hardware_access=False, tool_sha256=sha(__file__), controller=hex(BASE), extent=hex(EXTENT),
                  address=hex(ADDRESS), descriptor_register=DESCRIPTOR_REGISTER,
                  expected_identity='%04x:%04x' % EXPECTED, started=time.time(),
                  registers_planned=[dict(name=n, address=hex(BASE + o)) for n, o in REGISTERS],
                  writable=[hex(o) for o in sorted(WRITABLE)] if args.stage == 'descriptors' else [])
    if args.stage == 'plan':
        transport_library(tempfile.mkdtemp(prefix='touchpad-plan-'))
        record['transport_sources_sha256'] = {s: sha(DRIVER / s) for s in SOURCES}
        with args.output.open('x') as stream:
            stream.write(json.dumps(record, indent=2) + '\n')
        print(json.dumps(dict(status=record['status'], output=str(args.output), hardware_access=False)))
        return 0
    assert args.after_prefix and args.output.name and not args.output.name.startswith(args.after_prefix), \
        'outputs never go under build/RUN*'
    if args.stage == 'descriptors':
        survey_record = json.loads(args.survey.read_text())
        assert survey_record['status'] == 'STOPPED_TOUCHPAD_CONTROLLER_QUALIFIED', survey_record['status']
        assert survey_record['after_prefix'] == args.after_prefix and survey_record['tool_sha256'] == sha(__file__)
        record['survey_sha256'] = sha(args.survey)
    from cycle_lib.common import PINS
    device = args.device or PINS['device']
    record.update(after_prefix=args.after_prefix, device=device)
    with LOCK.open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        runner, f, launch, predecessor = stopped_run(args.after_prefix, device)
        with args.output.open('x') as stream:
            stream.write(json.dumps(record, indent=2) + '\n')
        proxy = None
        try:
            proxy, info = connect(runner, f, launch, predecessor, device, record)
            record.update(status='RUNNING', hardware_access=True, generation=info['stage_generation'])
            write_record(args.output, record)
            (survey if args.stage == 'survey' else descriptors)(proxy, record, args.output)
        except BaseException as error:
            record.setdefault('error', repr(error))
            if record['status'] in ('RUNNING', 'PLAN_VERIFIED'):
                record['status'] = 'FAILED'
            raise
        finally:
            record['finished'] = time.time()
            write_record(args.output, record)
            if proxy is not None:
                proxy.link.close()
    print(json.dumps(dict(status=record['status'], output=str(args.output),
                          qualification=record.get('qualification'), identity=record.get('hid_descriptor', {}).get('identity'))))
    return 0 if record['status'] in ('STOPPED_TOUCHPAD_CONTROLLER_QUALIFIED', 'STOPPED_TOUCHPAD_DESCRIPTORS_VERIFIED') else 1


if __name__ == '__main__':
    sys.exit(main())
