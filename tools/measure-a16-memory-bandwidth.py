#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Measure the A16's memory bandwidth and latency at EL2, from a stopped, idle q1n1 (agents/dvfs lever 1).

Runs tools/a16-bw-stub.S through P_CALL on q1n1's boot CPU with q1n1's EL2 MMU and caches on: READ, WRITE and
COPY streams over two buffers (default 64 MiB each, far beyond the 12 MB L2 and the LLCC), and a dependent-load
CHASE over every 64-byte line of the first buffer in a full-period LCG order. Each kernel runs --passes times,
timed with CNTPCT. One run before and one after `a16gpu.py ddr-vote` tell what the DDR vote gained; the record
says which CPU and which buffer were measured.

--sweep adds a READ and CHASE pass at each listed size (default none; the batch uses 8, 16 and 32 MiB): sizes around
the boot CPU's L2 and the LLCC, where activating the system cache (a16gpu.py llcc-activate) shows as a shorter chase.

Single core only. Secondaries started through PSCI run with their MMU off (measure-a16-cpu-clock.py), so every
access they make is Device-nGnRnE and would measure the wrong thing; an MMU-on secondary (the regime the
monitor's secondaries copy, probes/secondary.S) is the extension for a multi-core figure.

Failure modes (agents/dvfs FAILURE-MODES.md P1-P10), and what the tool does:
 P1 the buffer is chosen only inside one EFI Conventional region and outside q1n1's image, heap, DMA pool and
    stage slots, the GPU arena, the panel framebuffer, the SSD preload table and cmd-db; --buffer-pa must satisfy
    the same; by default the lowest such window at or above 0x900000000 (the guest's future RAM, which the loader
    writes later anyway);
 P2 every 2 MiB of both buffers is walked in q1n1's EL2 tables (probe-el2-memory's regime): identity,
    writable, MAIR write-back (0xff); otherwise refused before anything is written;
 P3 bytes is a power of two of at least 32 MiB (8 MiB with --qemu);
 P4 CNTFRQ must equal bootinfo timer_hz (hardware), at least 4 passes;
 P5 each pass is kept; the median is reported, passes over twice the median are flagged;
 P6 one P_CALL, never retried, with a timeout from the work size; the scratch stays reserved on an unknown
    outcome;
 P7 the stub's scratch (heap + 0x480000..0x490080, 0x4a0000.., 0x4b0000..) is saved first and restored;
 P10 run it only before a guest is loaded (the batch: before the GPU steps), or after a preserved stop.
The buffers' previous contents are not kept: Conventional memory holds nothing after ExitBootServices.

  python3 tools/measure-a16-memory-bandwidth.py --device udp://en6 --generation N --idle --output NEW.json
  python3 tools/measure-a16-memory-bandwidth.py --qemu --output NEW.json        # q1n1 in QEMU, no A16
  python3 tools/measure-a16-memory-bandwidth.py --decode-host REPORT.bin          # tools/test-a16-bw.c's report
"""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import runpy
import statistics
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
clock = runpy.run_path(str(ROOT / 'tools' / 'measure-a16-cpu-clock.py'), run_name='cpu_clock')
perf = runpy.run_path(str(ROOT / 'tools' / 'a16-cpu-perf.py'), run_name='cpu_perf')
run, need, Refused, Workspace = clock['run'], clock['need'], clock['Refused'], clock['Workspace']
Scratch, serror_clear = clock['Scratch'], clock['serror_clear']
walk = perf['walk']
collect = runpy.run_path(str(ROOT / 'tools' / 'probe-el2-memory.py'))['collect']

STUB_SOURCE = ROOT / 'tools' / 'a16-bw-stub.S'
STUB_BUILD = ROOT / 'build' / 'bw-probe'
INVENTORY_CODE, INVENTORY_OUT = 0x480000, 0x490000
CODE_AT, RESULT_AT, REPORT_BYTES = 0x4A0000, 0x4B0000, 640
MAGIC = 0x3130305742363141                      # "A16BW001"
KERNELS = ('read', 'write', 'copy', 'chase')
ALL_KERNELS = 0xF
SWEEP_KERNELS = 0x9                             # READ and CHASE
CONVENTIONAL = 7
CMD_DB = (0x81C60000, 0x20000)
PREFERRED_FLOOR = 0x900000000                   # inside the guest's future RAM (SNAP_PHYS_BASE 0x8c0000000 + 8 GiB)
TWO_MIB = 2 << 20


def sha(data):
    return hashlib.sha256(data).hexdigest()


# probes/run.py's default probe flags, fixed here: a launcher may have set run.FLAGS to a monitor's flag list.
STUB_FLAGS = ['--target=aarch64-unknown-none-elf', '-ffreestanding', '-fno-pic', '-mgeneral-regs-only', '-O1', '-Wall',
              '-Wextra', '-Werror', '-fno-stack-protector', '-mcmodel=tiny']


def assemble(source, out_dir, name):
    out_dir.mkdir(parents=True, exist_ok=True)
    obj, binary = out_dir / f'{name}.o', out_dir / f'{name}.bin'
    subprocess.run([str(run.LLVM / 'clang'), *STUB_FLAGS, '-c', str(source), '-o', str(obj)], check=True)
    subprocess.run([str(run.LLVM / 'llvm-objcopy'), '-O', 'binary', '--only-section=.text', str(obj), str(binary)],
                   check=True)
    return binary.read_bytes()


def build_stub(out_dir=STUB_BUILD):
    blob = assemble(STUB_SOURCE, out_dir, 'a16-bw-stub')
    need(0 < len(blob) <= RESULT_AT - CODE_AT, 'stub size')
    return blob


def build_memory_probe(out_dir=STUB_BUILD):
    """probes/el2-memory.S (probe-el2-memory.py's regime reader), built with the same fixed flags."""
    blob = assemble(ROOT / 'probes' / 'el2-memory.S', out_dir, 'el2-memory')
    need(0 < len(blob) <= 0x10000, 'el2-memory probe size')
    return blob


def efi_regions(raw, stride):
    out = []
    for offset in range(0, len(raw) - 39, stride):
        kind, start, _virt, pages, attribute = struct.unpack_from('<I4xQQQQ', raw, offset)
        out.append(dict(type=kind, start=start, end=start + pages * 4096, attribute=attribute))
    return out


def exclusions(info):
    spans = [(info.get(f'{n}_base') or 0, info.get(f'{n}_size') or 0) for n in ('heap', 'dma', 'stage')]
    spans += [(info.get('image_base') or 0, info.get('image_size') or 0),
              (info.get('gpu_arena_base') or 0, info.get('gpu_arena_size') or 0),
              (info.get('fb_base') or 0, info.get('fb_size') or 0),
              (info.get('preload_table') or 0, info.get('preload_size') or 0), CMD_DB]
    return [(b, b + s) for b, s in spans if b and s]


def choose_buffer(regions, excluded, span, requested=None, floor=PREFERRED_FLOOR):
    """(base, region) of a 2 MiB-aligned window of `span` bytes inside one Conventional region, clear of every
    excluded span: the requested base if it qualifies (else refused), or the lowest one at or above floor, else
    the lowest anywhere."""
    def clear(base):
        return all(base + span <= lo or hi <= base for lo, hi in excluded)

    def region_of(base):
        return next((r for r in regions if r['type'] == CONVENTIONAL and r['start'] <= base and
                     base + span <= r['end']), None)
    if requested is not None:
        need(requested % TWO_MIB == 0, '--buffer-pa must be 2 MiB aligned')
        region = region_of(requested)
        need(region is not None, f'{requested:#x}+{span:#x} is not inside one Conventional region')
        need(clear(requested), f'{requested:#x}+{span:#x} overlaps q1n1, the GPU arena, the framebuffer or cmd-db')
        return requested, region
    for low in (floor, 0):
        for r in sorted((r for r in regions if r['type'] == CONVENTIONAL), key=lambda r: r['start']):
            base = max((r['start'] + TWO_MIB - 1) & ~(TWO_MIB - 1), (low + TWO_MIB - 1) & ~(TWO_MIB - 1))
            while base + span <= r['end']:
                if clear(base):
                    return base, r
                base += TWO_MIB
    need(False, f'no Conventional window of {span:#x} bytes clear of q1n1')


def check_mapping(read64, regime, base, span):
    """P2: identity, writable, write-back cacheable, every 2 MiB (and the last page)."""
    pages = []
    for va in list(range(base, base + span, TWO_MIB)) + [base + span - 4096]:
        page = walk(read64, regime, va)
        need(page is not None, f'{va:#x} is not mapped at EL2')
        need(int(page['pa'], 16) == va and page['writable'] and page['attr'] == '0xff',
             f'{va:#x} is not identity, writable, write-back at EL2: {page}')
        pages.append(page)
    return dict(checked=len(pages), attr=pages[0]['attr'], leaf_shift=sorted({p['leaf_shift'] for p in pages}))


def decode(raw, bytes_hint=None):
    """The stub's report: header, then per-pass ticks of each kernel and the chase's build/walk ticks."""
    w = struct.unpack('<80Q', raw[:REPORT_BYTES])
    need(w[0] == MAGIC, f'report magic {w[0]:#x}')
    out = dict(status=w[1], current_el=w[2], cntfrq=w[3], bytes=w[4], passes=w[5], kernels=w[6], done=w[10])
    if w[1] != 0 or not w[10]:
        return out
    hz, size, passes = w[3], w[4], w[5]
    need(hz and size and 1 <= passes <= 16, 'report header out of range')
    for k, name in enumerate(KERNELS[:3]):
        if not w[6] >> k & 1:
            continue
        ticks = list(w[16 + 16 * k:16 + 16 * k + passes])
        need(all(ticks), f'{name}: a pass has no time')
        rates = [size / (t / hz) / 1e9 for t in ticks]
        median = statistics.median(ticks)
        out[name] = dict(gbs_best=round(max(rates), 3), gbs_median=round(size / (median / hz) / 1e9, 3),
                         passes_gbs=[round(r, 3) for r in rates],
                         outliers=[i for i, t in enumerate(ticks) if t > 2 * median],
                         traffic_gbs_best=round(max(rates) * (2 if name == 'copy' else 1), 3))
    if w[6] >> 3 & 1:
        steps = w[8]
        need(steps == size // 64, 'chase step count')
        out['chase'] = dict(ns_per_load=round(w[65] / hz * 1e9 / steps, 2), build_ms=round(w[64] / hz * 1e3, 2),
                            steps=steps, cycle_closed=bool(bytes_hint is None or w[9] == bytes_hint))
    return out


def measure(proxy, info, blob, memory_blob, args, record, save, timer_hz=None):
    base = info['heap_base']
    need(info['current_el'] == 2 and info['heap_size'] >= RESULT_AT + 0x400, 'q1n1 is not at EL2 or its heap is small')
    span = 2 * args.bytes
    scratch = Scratch(proxy, [(base + INVENTORY_CODE, len(memory_blob)), (base + INVENTORY_OUT, 128),
                              (base + CODE_AT, len(blob)), (base + RESULT_AT, 0x400)])
    try:
        regime = collect(proxy, memory_blob)
        record['regime'] = {k: regime[k] for k in ('sctlr', 'tcr', 'ttbr0', 'mair', 'mpidr')}
        raw = proxy.readmem(info['memory_map'], info['memory_map_size'], live=True)
        regions = efi_regions(raw, info['memory_map_stride'])
        excluded = exclusions(info)
        buf, region = choose_buffer(regions, excluded, span, args.buffer_pa,
                                    floor=0 if args.qemu else PREFERRED_FLOOR)
        read64 = lambda pa: struct.unpack('<Q', proxy.readmem(pa, 8, live=True))[0]   # noqa: E731
        record['buffer'] = dict(base=hex(buf), bytes_each=args.bytes, region=dict(start=hex(region['start']),
                                end=hex(region['end'])), excluded=[[hex(a), hex(b)] for a, b in excluded],
                                mapping=check_mapping(read64, regime, buf, span))
        save()
        clock['upload'](proxy, base + CODE_AT, blob)
        proxy.writemem(base + RESULT_AT, bytes(REPORT_BYTES))
        work = args.passes * 4 * args.bytes + args.bytes
        timeout = 30 + work / 0.2e9 + (args.bytes // 64) * 2e-6
        record['in_flight'] = dict(call='a16_bw', timeout_s=round(timeout, 1))
        scratch.keep('bandwidth call in flight')
        save()
        started = time.monotonic()
        proxy.call(base + CODE_AT, base + RESULT_AT, buf, args.bytes, args.passes | ALL_KERNELS << 16,
                   timeout=timeout)                       # never retried
        record['call_seconds'] = round(time.monotonic() - started, 3)
        scratch.release()
        record.pop('in_flight')
        need(not proxy.exceptions, f'proxy exception during the call: {proxy.exceptions}')
        result = decode(proxy.readmem(base + RESULT_AT, REPORT_BYTES, live=True), bytes_hint=buf)
        record['result'] = result
        need(result['status'] == 0 and result['done'], f'stub status {result["status"]}')
        if timer_hz:
            need(result['cntfrq'] == timer_hz, f'CNTFRQ {result["cntfrq"]} is not bootinfo timer_hz {timer_hz}')
        need(result['current_el'] == 2, 'the stub did not run at EL2')
        for size in getattr(args, 'sweep', None) or []:
            proxy.writemem(base + RESULT_AT, bytes(REPORT_BYTES))
            record['in_flight'] = dict(call='a16_bw sweep', bytes=size)
            scratch.keep('bandwidth sweep call in flight')
            save()
            proxy.call(base + CODE_AT, base + RESULT_AT, buf, size, args.passes | SWEEP_KERNELS << 16,
                       timeout=timeout)                   # never retried
            scratch.release()
            record.pop('in_flight')
            need(not proxy.exceptions, f'proxy exception during the sweep: {proxy.exceptions}')
            swept = decode(proxy.readmem(base + RESULT_AT, REPORT_BYTES, live=True), bytes_hint=buf)
            need(swept['status'] == 0 and swept['done'], f'sweep stub status {swept["status"]}')
            record.setdefault('sweep', {})[str(size)] = swept
    finally:
        record['scratch'] = scratch.restore()
        save()
    return record


def summary(record):
    r = record.get('result') or {}
    out = {k: (r[k].get('gbs_best') if k != 'chase' else r[k].get('ns_per_load')) for k in KERNELS if k in r}
    for size, s in (record.get('sweep') or {}).items():
        out[f'chase_ns_{int(size) >> 20}MiB'] = (s.get('chase') or {}).get('ns_per_load')
        out[f'read_gbs_{int(size) >> 20}MiB'] = (s.get('read') or {}).get('gbs_best')
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--device')
    ap.add_argument('--output', type=Path)
    ap.add_argument('--generation', type=int)
    ap.add_argument('--after', help='preserved stop this follows: build/PREFIX/launch.json')
    ap.add_argument('--idle', action='store_true', help='no guest ran in this generation')
    ap.add_argument('--bytes', type=lambda v: int(v, 0), default=64 << 20, help='each buffer (power of two)')
    ap.add_argument('--passes', type=int, default=6)
    ap.add_argument('--buffer-pa', type=lambda v: int(v, 0))
    ap.add_argument('--sweep', default='', help='extra READ+CHASE sizes in MiB, comma separated (powers of two, '
                                               '4..the main size), e.g. 8,16,32')
    ap.add_argument('--label', default='', help='free text kept in the record (e.g. before-vote)')
    ap.add_argument('--qemu', action='store_true', help='E2E control on q1n1 in QEMU; no A16 access')
    ap.add_argument('--decode-host', type=Path, help='decode a report written by tools/test-a16-bw.c and exit')
    args = ap.parse_args(argv)
    if args.decode_host:
        print(json.dumps(decode(args.decode_host.read_bytes()), indent=2))
        return 0
    need(args.output is not None, '--output is required')
    need(not args.output.exists(), f'{args.output} exists; captures are never overwritten')
    need(4 <= args.passes <= 16, '--passes must be 4..16')
    minimum = (8 << 20) if args.qemu else (32 << 20)
    need(args.bytes >= minimum and not args.bytes & (args.bytes - 1), f'--bytes must be a power of two >= {minimum}')
    args.sweep = [int(x) << 20 for x in args.sweep.split(',') if x.strip()]
    need(all(4 << 20 <= s <= args.bytes and not s & (s - 1) for s in args.sweep),
         '--sweep sizes must be powers of two from 4 MiB to --bytes')
    if args.qemu:
        lock_path, admission = Path('/tmp/snapintosh-clock-qemu.lock'), dict(qemu=True)
    else:
        need(args.device and args.generation is not None, '--device and --generation are required on hardware')
        need(bool(args.after) != bool(args.idle), 'give exactly one of --after PREFIX or --idle')
        ws = Workspace(ROOT)
        admission = clock['admit'](args, ws)
        lock_path = Path('/tmp/snapintosh-hardware.lock')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    blob = build_stub()
    memory_blob = build_memory_probe()
    record = dict(schema='snapintosh-memory-bandwidth-v1', label=args.label, admission=admission,
                  started=time.time(), bytes_each=args.bytes, passes=args.passes,
                  stub=dict(source=str(STUB_SOURCE), source_sha256=sha(STUB_SOURCE.read_bytes()), sha256=sha(blob),
                            bytes=len(blob)),
                  qualification='single core (q1n1 boot CPU), EL2, MMU and caches on; not a multi-core or '
                                'guest-load figure')

    def save():
        args.output.write_text(json.dumps({k: v for k, v in record.items() if not k.startswith('_')}, indent=2) + '\n')

    with lock_path.open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        context = clock['QemuSmp'](args.output.parent / (args.output.stem + '-qemu'), cpus=1) if args.qemu else None
        sock = context.__enter__() if context else None
        try:
            proxy = run.connect(sock if args.qemu else args.device, tries=90 if args.qemu else 1)
            try:
                if args.qemu:
                    info, timer_hz = proxy.bootinfo(), None
                else:
                    info, record['serror_before'] = clock['check_resident'](proxy, args, admission)
                    timer_hz = info['timer_hz']
                record['bootinfo'] = {k: info.get(k) for k in ('stage_generation', 'heap_base', 'heap_size',
                                                               'image_base', 'timer_hz', 'current_el')}
                measure(proxy, info, blob, memory_blob, args, record, save, timer_hz=timer_hz)
                if not args.qemu:
                    record['serror_after'] = proxy.serror_state()
                    need(serror_clear(record['serror_after']), 'SError recorded during the measurement')
                record['finished'] = time.time()
                record['status'] = 'MEASURED'
                save()
                proxy.nop()
            finally:
                proxy.link.close()
        except BaseException as error:
            record['status'] = 'FAILED'
            record['error'] = f'{type(error).__name__}: {error}'
            save()
            raise
        finally:
            if context:
                context.__exit__(None, None, None)
    print(json.dumps(dict(output=str(args.output), status=record['status'], label=args.label,
                          best=summary(record)), indent=2))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Refused as refusal:
        print(f'refused: {refusal}', file=sys.stderr)
        sys.exit(2)
