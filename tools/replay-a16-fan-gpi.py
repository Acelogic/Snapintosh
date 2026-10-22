#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Whole fan-read protocol replay with separate CPU/DMA memory and GPI/EC model.

Produces raw TRE/event images, bus transactions, MMIO/cache journals and hashes.
No target connector is imported; this is software evidence, not hardware proof.
Failure inventory was recorded in docs/A16-FAN-GPI-20261018.md first.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import runpy
import time
from a16_fan_gpi import Arena, Timing, RingReader, Refused, decode_survey, survey_plan, go, dma

ROOT = Path(__file__).resolve().parents[1]


class Model:
    """Literal GPI register/TRE interpretation independent of the encoder.

    The I2C side implements only the ACPI-derived fan command. The CPU and DMA
    images differ until clean/invalidate; thus missing cache operations really
    change the bytes interpreted by the engine or returned to the caller.
    """
    def __init__(self, fault='none'):
        self.fault = fault
        self.cpu, self.device = {}, {}
        self.registers = {0xA84040: 0, 0xA84064: 1, 0xA84258: 1,
                          0xA84048: 0x21, 0xA84278: 0x503018,
                          0xA13100: 0, 0xA13118: 0, 0xA13090: 0, 0xA13094: 0}
        self.clock = 0
        self.trace, self.bus, self.tres, self.eres = [], [], [], []
        self.rx_descriptor = None
        self.event_index = 0
        self.requested = None
        self.selector_seen = False
        self.high_reads = 0
        self.submissions = 0
        self.stops = 0
        for c, base, config, scratch in [(0xA10000, 0x12000000, 0x1020000A, 0x10031),
                                          (0xA10080, 0x12000100, 0x10200002, 0x00031),
                                          (0xA11000, 0x12000400, 0x10110002, None)]:
            self.registers[c] = config
            self.registers[c + 4] = 1024 if scratch is None else 256
            for offset in (8, 16, 24):
                self.registers[c + offset] = base
                self.registers[c + offset + 4] = 0
            if scratch is not None:
                self.registers[c + 0x60] = scratch
        if fault == 'wrong_route':
            self.registers[0xA10060] = 0x10030
        if fault == 'nonempty_ring':
            self.registers[0xA10018] += 16
        if fault == 'channel_busy':
            self.registers[0xA84040] = 1
        if fault == 'global_error':
            self.registers[0xA13100] = 1
        if fault == 'changed_timing':
            self.registers[0xA84278] = 0x503019

    def lease_evidence(self):
        return dict(exclusive=self.fault != 'unowned',
                    dma_mapping_qualified=self.fault != 'unmapped',
                    cache_maintenance_qualified=True, stream_id=0xcb6, instance=0,
                    arena=asdict(Arena(0x12000000, 0x12000100, 0x12000400,
                                      0x12000800, 0x12000810, 0x12000820)),
                    synthetic=True)

    def log(self, kind, **values):
        self.trace.append(dict(operation=kind, **values))

    def time_us(self):
        self.clock += 10
        return self.clock

    def read32(self, address):
        value = self.registers[address]
        if self.fault == 'bad_event_rp' and address == 0xA11010 and self.submissions:
            value += 1
        if self.fault == 'unretired_tx' and address == 0xA10010 and self.submissions:
            value -= 16
        self.log('read32', address=hex(address), value=hex(value))
        return value

    def write32(self, address, value):
        self.log('write32', address=hex(address), value=hex(value))
        if address == 0xA12000:
            self.submissions += 1
            self.execute_tx(value)
        elif address == 0xA12008:
            start = self.registers[0xA10090]
            raw = self.device_bytes(start, 16)
            a, high, length, flags = struct.unpack('<4I', raw)
            assert flags == 0x00100200 and length == 1
            self.rx_descriptor = (start, a | high << 32)
            self.tres.append(dict(channel=1, address=start, hex=raw.hex()))
            self.registers[0xA10098] = value
        elif address in (0xA12100, 0xA130C0):
            pass
        elif address == 0xA13008:
            assert value in (0x02000000, 0x02000001), 'only STOP commands admitted'
            self.stops += 1
            channel = value & 1
            config = 0xA10000 + channel * 0x80
            if self.fault in ('stop_timeout', 'stop_after_success') and channel == 1:
                self.registers[config] = self.registers[config] & ~(15 << 20) | 4 << 20
            else:
                self.registers[config] = self.registers[config] & ~(15 << 20) | 3 << 20
                self.registers[0xA13090] |= 1 << channel
        elif address == 0xA130A0:
            self.registers[0xA13090] &= ~value
        else:
            raise AssertionError(f'write outside owned doorbell/IEOB set: {address:#x}')

    def write_dma(self, address, data):
        for index, value in enumerate(data):
            self.cpu[address + index] = value
        self.log('cpu_write', address=hex(address), data=data.hex())

    def read_dma(self, address, length):
        self.log('cpu_read', address=hex(address), length=length)
        return bytes(self.cpu.get(address + index, 0) for index in range(length))

    def device_bytes(self, address, length):
        return bytes(self.device.get(address + index, 0) for index in range(length))

    def clean(self, address, length):
        self.log('clean', address=hex(address), length=length)
        for index in range(length):
            self.device[address + index] = self.cpu.get(address + index, 0)

    def invalidate(self, address, length):
        self.log('invalidate', address=hex(address), length=length)
        for index in range(length):
            self.cpu[address + index] = self.device.get(address + index, 0)

    def barrier(self):
        self.log('barrier')

    def stop_requested(self):
        return self.fault == 'operator_stop' and self.submissions > 0

    def event(self, channel, pointer, length):
        if self.fault in ('missing_event', 'stop_timeout'):
            return
        code, status, kind = 2, 0, 0x22
        if self.fault == 'nack':
            code = 16
        if self.fault == 'short_transfer':
            length -= 1
        if self.fault == 'stale_pointer':
            pointer += 16
        if self.fault == 'unknown_event':
            kind = 0x31
        if self.fault == 'status_error':
            status = 1
        if self.fault == 'wrong_channel':
            channel = 7
        raw = struct.pack('<QIHBB', pointer, length | code << 24, status, kind, channel)
        for _ in range(2 if self.fault == 'duplicate_event' else 1):
            where = 0x12000400 + self.event_index
            for index, value in enumerate(raw):
                self.device[where + index] = value
            self.eres.append(dict(address=where, hex=raw.hex()))
            self.event_index = (self.event_index + 16) % 1024
        self.registers[0xA11010] = 0x12000400 + self.event_index

    def execute_tx(self, end):
        current = self.registers[0xA10010]
        operation = None
        while current != end:
            raw = self.device_bytes(current, 16)
            w0, w1, w2, flags = struct.unpack('<4I', raw)
            self.tres.append(dict(channel=0, address=current, hex=raw.hex()))
            kind = flags >> 16
            if kind == 0x22:
                # Captured firmware counters: low12, high5, cycle24, divider2.
                assert (w0, w1, w2, flags) == (0x0318050C, 0, 2, 0x00220001)
            elif kind == 0x20:
                assert (w0 >> 8) & 0x7f == 0x76
                command, stretch = w0 & 31, bool(w0 & (1 << 26))
                if command == 1:
                    assert flags == 0x00200001 and w2 in (1, 6)
                    operation = ('write', stretch)
                else:
                    assert command == 2 and flags == 0x00200800 and w2 == 1 and not stretch
                    assert self.selector_seen and self.requested in (0x0602, 0x0603)
                    assert self.rx_descriptor is not None, 'RX must precede linked GO'
                    pointer, destination = self.rx_descriptor
                    self.rx_descriptor = None
                    if self.requested == 0x0603:
                        value = 0x09
                        self.high_reads += 1
                        if self.fault == 'torn_rpm' and self.high_reads == 2:
                            value = 0x0a
                    else:
                        value = 0x60
                    self.device[destination] = value  # 0x0960 = 2400 RPM
                    self.bus.append(dict(direction='read', address=0x76, data=bytes([value]).hex(),
                                         repeated_start=True, stop=True))
                    self.event(1, pointer, 1)
                    self.registers[0xA10090] = self.registers[0xA10098]
                    self.selector_seen = False
                    self.requested = None
                    self.registers[0xA84040] = 0
            elif kind == 0x10:
                assert flags == 0x00100200 and operation is not None
                data = self.device_bytes(w0 | w1 << 32, w2)
                if w2 == 6:
                    assert data in (bytes.fromhex('520603010000'), bytes.fromhex('520602010000'))
                    assert not operation[1] and self.requested is None
                    self.requested = data[1] << 8 | data[2]
                    self.bus.append(dict(direction='write', address=0x76, data=data.hex(), stop=True))
                else:
                    assert w2 == 1 and data == b'\x52' and operation[1]
                    assert self.requested is not None
                    self.selector_seen = True
                    self.bus.append(dict(direction='write', address=0x76, data='52', stop=False))
                    self.registers[0xA84040] = 1
                self.event(0, current, w2)
                operation = None
            else:
                raise AssertionError(f'bad TRE type {kind:#x}')
            current = 0x12000000 + ((current - 0x12000000 + 16) % 256)
        self.registers[0xA10010] = end
        self.registers[0xA10018] = end

def run_case(fault, directory):
    model = Model(fault)
    arena = Arena(0x12000000, 0x12000100, 0x12000400, 0x12000800, 0x12000810, 0x12000820)
    reader = RingReader(model, 0, arena, Timing(12, 5, 24, 2), max_us=2000, max_polls=100)
    result, error = None, None
    try:
        result = reader.read_rpm()
    except Refused as exc:
        error = str(exc)
    expected_error = fault != 'none'
    assert bool(error) == expected_error, (fault, result, error)
    if fault == 'none':
        assert result['rpm'] == 2400 and result['bytes'] == [9, 96, 9]
        assert len(model.bus) == 9 and len(reader.events) == 9
        assert [x['data'] for x in model.bus if len(x['data']) == 12] == [
            '520603010000', '520602010000', '520603010000']
        assert not reader.pinned
        assert any(t['address'] == 0x12000000 for t in model.tres[1:]), 'TX ring wrapping not exercised'
    if fault in ('unowned', 'unmapped', 'wrong_route', 'nonempty_ring', 'channel_busy', 'global_error', 'changed_timing'):
        assert model.submissions == 0 and model.stops == 0
        assert not any(t['operation'] in ('write32', 'cpu_write') for t in model.trace)
    else:
        assert model.stops == 2
    if fault in ('stop_timeout', 'stop_after_success'):
        assert reader.pinned
    path = directory / fault
    path.mkdir()
    (path / 'trace.json').write_text(json.dumps(dict(scope='synthetic MMIO/DMA/EC replay', fault=fault,
        result=result, error=error, arena_pinned=reader.pinned, stop_evidence=reader.stop_evidence,
        bus=model.bus, events=reader.events,
        operations=model.trace, tres=model.tres, eres=model.eres), indent=2) + '\n')
    (path / 'tx-rx-tres.bin').write_bytes(b''.join(bytes.fromhex(t['hex']) for t in model.tres))
    (path / 'events.bin').write_bytes(b''.join(bytes.fromhex(e['hex']) for e in model.eres))
    return dict(case=fault, result='PASS', error=error, arena_pinned=reader.pinned,
                doorbells=model.submissions, event_count=len(reader.events), elapsed_model_us=model.clock)


def linux_oracle(directory):
    """Compile the unmodified pinned Linux encoder behind a minimal type shim.

    This checks the actual upstream function, not another hand-copied encoder.
    It is not a Linux driver or hardware simulation.
    """
    reference = ROOT / 'build/fan-gpi-20261018/references/gpi.c'
    pin = json.loads(reference.with_name('source.json').read_text())
    assert pin['linux_commit'] == 'c03c1a14507dfaf8b856c2608f9ac216021fc222'
    assert hashlib.sha256(reference.read_bytes()).hexdigest() == next(
        entry['sha256'] for entry in pin['files'] if entry['file'] == 'gpi.c')
    source = reference.read_text()
    begin = source.index('static int gpi_create_i2c_tre(')
    end = source.index('\nstatic int gpi_create_spi_tre(', begin)
    function = source[begin:end]
    defines = '\n'.join(line for line in source.splitlines()[:69] if line.startswith('#define'))
    shim = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
typedef uint64_t dma_addr_t;
#define BIT(n) (1U << (n))
#define GENMASK(h,l) ((~0U >> (31-(h))) & (~0U << (l)))
#define u32_encode_bits(v,m) (((uint32_t)(v) << __builtin_ctz(m)) & (m))
#define lower_32_bits(v) ((uint32_t)(v))
#define upper_32_bits(v) ((uint32_t)((uint64_t)(v) >> 32))
#define sg_dma_address(s) ((s)->address)
#define sg_dma_len(s) ((s)->length)
#define DMA_PREP_INTERRUPT 1
#define dev_dbg(...) ((void)0)
#define true 1
#define false 0
enum { I2C_WRITE=1, I2C_READ=2 };
enum dma_transfer_direction { DMA_MEM_TO_DEV, DMA_DEV_TO_MEM };
struct device { int unused; };
struct gpi_dev { struct device *dev; };
struct gpii { struct gpi_dev *gpi_dev; };
struct gpi_i2c_config { unsigned low_count, high_count, cycle_count, pack_enable,
    clk_div, set_config, op, multi_msg, addr, stretch, rx_len; };
struct gchan { struct gpi_i2c_config *config; struct gpii *gpii; };
struct gpi_tre { u32 dword[4]; };
struct gpi_desc { struct gpi_tre tre[4]; };
struct scatterlist { uint64_t address; unsigned length; };
'''
    main = r'''
int main(void) {
    struct gpi_dev dev={0}; struct gpii instance={&dev};
    struct gpi_i2c_config config={.low_count=12,.high_count=5,.cycle_count=24,
        .pack_enable=3,.clk_div=2,.addr=0x76,.set_config=1,.op=I2C_WRITE,.rx_len=6};
    struct gchan channel={&config,&instance}; struct gpi_desc desc={0};
    struct scatterlist sg={0x12000800,6}; int n;
    n=gpi_create_i2c_tre(&channel,&desc,&sg,DMA_MEM_TO_DEV,DMA_PREP_INTERRUPT);
    fwrite(desc.tre,16,n,stdout);
    memset(&desc,0,sizeof(desc)); config.set_config=0;config.stretch=1;config.rx_len=1;
    sg.address=0x12000810;sg.length=1;
    n=gpi_create_i2c_tre(&channel,&desc,&sg,DMA_MEM_TO_DEV,DMA_PREP_INTERRUPT);
    fwrite(desc.tre,16,n,stdout);
    memset(&desc,0,sizeof(desc));config.stretch=0;config.multi_msg=1;
    n=gpi_create_i2c_tre(&channel,&desc,&sg,DMA_MEM_TO_DEV,DMA_PREP_INTERRUPT);
    fwrite(desc.tre,16,n,stdout);
    memset(&desc,0,sizeof(desc));config.op=I2C_READ;sg.address=0x12000820;
    n=gpi_create_i2c_tre(&channel,&desc,&sg,DMA_DEV_TO_MEM,DMA_PREP_INTERRUPT);
    fwrite(desc.tre,16,n,stdout);
    return 0;
}
'''
    cfile = directory / 'linux-encoder-oracle.c'
    cfile.write_text('// Extracted Linux function SPDX-License-Identifier: GPL-2.0-only\n' +
                     '// Source: ' + str(reference) + '\n' + shim + defines + '\n' + function + main)
    executable = directory / 'linux-encoder-oracle'
    build = subprocess.run(['cc', '-std=c11', '-O2', str(cfile), '-o', str(executable)],
                           capture_output=True, text=True, timeout=30)
    (directory / 'linux-encoder-build.log').write_text(build.stdout + build.stderr)
    assert build.returncode == 0, build.stderr
    actual = subprocess.run([str(executable.resolve())], capture_output=True, check=True, timeout=5).stdout
    expected = b''.join([Timing(12, 5, 24, 2).config(), go(length=6), dma(0x12000800, 6),
                         go(stretch=True), dma(0x12000810, 1), go(read=True), dma(0x12000820, 1)])
    (directory / 'linux-encoder-tres.bin').write_bytes(actual)
    (directory / 'candidate-encoder-tres.bin').write_bytes(expected)
    assert actual == expected, 'candidate TREs differ from pinned Linux encoder'
    return dict(status='BYTE_IDENTICAL', bytes=len(actual),
                upstream_sha256=hashlib.sha256(reference.read_bytes()).hexdigest(),
                tre_sha256=hashlib.sha256(actual).hexdigest())


def survey_guard_replay(directory):
    survey = runpy.run_path(str(ROOT / 'tools/a16-fan-gpi-survey.py'))
    guard_module = runpy.run_path(str(ROOT / 'tools/a16-control-guard.py'))
    cases = []
    for fault in ('none', 'exception_callback', 'unexpected_boot', 'read_timeout',
                  'serror', 'identity', 'deadline'):
        calls, closes = [], []
        record = dict(status='STARTING', reads=[], synthetic=True, fault=fault)
        durable = []

        def save():
            durable.append(json.loads(json.dumps(record)))

        def need(condition, message):
            if not condition:
                raise Refused(message)

        class Link:
            def close(self):
                closes.append(True)

            def exception_handler(self, code, info):
                calls.append('UNSAFE_DEFAULT_EXCEPTION_HANDLER')
                raise RuntimeError('default handler must be replaced')

            def handle_boot(self, data):
                calls.append('UNSAFE_DEFAULT_BOOT_HANDLER')
                raise RuntimeError('default handler must be replaced')

        class Proxy:
            P_CALL = 3

            def __init__(self):
                self.link = Link()
                self.read_count = 0

            def request(self, *args, **kwargs):
                raise AssertionError('survey issued a raw request')

            def bootinfo(self):
                calls.append('bootinfo')
                return dict(current_el=2, stage_generation=2 if fault == 'identity' else 1,
                            image_base=0xb0000000)

            def serror_state(self):
                calls.append('serror_state')
                return dict(during=int(fault == 'serror' and self.read_count != 0))

            def read32(self, address):
                calls.append(dict(read32=address))
                self.read_count += 1
                if fault == 'exception_callback':
                    self.link.exception_handler(2, 0xdead)
                if fault == 'unexpected_boot':
                    self.link.handle_boot(struct.pack('<IIQ', 0, 2, 0xdead))
                if fault == 'read_timeout':
                    raise TimeoutError('injected lost read reply')
                return 0

        guard = guard_module['ControlGuard'](Proxy(), record, save)
        try:
            survey['capture'](guard.proxy, record, save, 1, 0xb0000000,
                              time.monotonic() + (-1 if fault == 'deadline' else 10),
                              need, lambda state: not any(state.values()))
            assert fault == 'none' and record['status'] == 'READ_COMPLETE'
            assert len(record['reads']) == 243 and not guard.frozen
        except Exception as exc:
            assert fault != 'none', str(exc)
            guard.freeze(f'survey refused: {exc}')
            boundary = len(calls)
            try:
                guard.proxy.serror_state()
            except guard_module['Frozen']:
                pass
            else:
                raise AssertionError('frozen survey allowed target cleanup')
            assert len(calls) == boundary
            record.update(status='REFUSED_OR_FAILED', error=str(exc), post_freeze_target_io=0)
        finally:
            guard.close()
        assert len(closes) == 1
        assert not any(isinstance(x, str) and x.startswith('UNSAFE') for x in calls)
        if fault in ('exception_callback', 'unexpected_boot', 'read_timeout'):
            assert calls[-1] == {'read32': 0xA84040}, 'target I/O followed failed read'
        cases.append(dict(fault=fault, status=record['status'], calls=calls, receipt=record,
                          durable_snapshots=len(durable), local_closes=len(closes)))
    (directory / 'survey-guard-replay.json').write_text(json.dumps(cases, indent=2) + '\n')
    return dict(status='PASS', scenarios=len(cases),
                scope='production capture loop and ControlGuard with injected proxy callbacks')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    oracle = linux_oracle(args.output_dir)
    guarded_survey = survey_guard_replay(args.output_dir)
    cases = ['none', 'unowned', 'unmapped', 'wrong_route', 'nonempty_ring', 'channel_busy',
             'global_error', 'operator_stop', 'missing_event', 'stop_timeout', 'bad_event_rp',
             'unretired_tx', 'nack', 'short_transfer', 'stale_pointer', 'unknown_event',
             'status_error', 'wrong_channel', 'duplicate_event', 'torn_rpm', 'stop_after_success', 'changed_timing']
    rows = [run_case(case, args.output_dir) for case in cases]
    # Whole capture decoder replay: explicit route at instance2, other pairs free.
    reads = [dict(name=name, address=hex(address), value=0) for name, address in survey_plan()]
    for row in reads:
        if row['name'] in ('gpi2.ch0.config', 'gpi2.ch1.config'):
            row['value'] = 2 << 20
        if row['name'] in ('gpi2.ch0.scratch0', 'gpi2.ch1.scratch0'):
            row['value'] = 0x31
    decoded = decode_survey(reads)
    assert decoded['instances'][2]['routes_ic10'] and not decoded['dma_launch_admitted']
    assert not decoded['instances'][2]['appears_unallocated']
    (args.output_dir / 'ownership-replay.json').write_text(json.dumps(dict(
        scope='synthetic capture', reads=reads, decoded=decoded), indent=2) + '\n')
    for invalid in (reads[:-1], reads + [reads[0]], [dict(reads[0], address='0x0')] + reads[1:]):
        try:
            decode_survey(invalid)
        except Refused:
            pass
        else:
            raise AssertionError('bad survey admitted')
    summary = dict(status='PASS', scope='offline software evidence only; hardware fan gate remains closed',
                   cases=rows, ownership_capture_faults=3, linux_encoder_oracle=oracle,
                   guarded_survey=guarded_survey, source_sha256={
                       str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in [Path(__file__), ROOT / 'tools/a16_fan_gpi.py',
                                 ROOT / 'tools/a16-fan-gpi-survey.py', ROOT / 'tools/a16-control-guard.py',
                                 ROOT / 'docs/A16-FAN-GPI-20261018.md']})
    (args.output_dir / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    manifest = {str(p.relative_to(args.output_dir)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(args.output_dir.rglob('*')) if p.is_file()}
    (args.output_dir / 'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name, digest in manifest.items()))
    print(json.dumps(dict(status='PASS', scenarios=len(rows), ownership_capture_faults=3,
                         artifact=str(args.output_dir / 'summary.json'), files_hashed=len(manifest))))


if __name__ == '__main__':
    main()
