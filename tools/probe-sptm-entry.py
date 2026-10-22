#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fresh-idle SPTM call-entry E2E microbenchmark; no XNU or SSD access.

Original private call -> synthetic EL1 HVC vector versus direct HVC #0x5350.
This does not model the production guarded-vector fault or SPTM handler cost.
Failure inventory: docs/SPTM-CALL-ENTRY-20260930.md (written before code).
An uncertain P_CALL permanently freezes this run: no retry or scratch restore.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import statistics
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import run
import monitor_work

FIELDS = ('magic', 'version', 'status', 'mode', 'iterations', 'genter_calls',
          'alternate_calls', 'hvc_exits', 'genter_esr', 'genter_pc',
          'genter_spsr', 'genter_far', 'alternate_esr', 'alternate_pc',
          'alternate_spsr', 'alternate_far', 'last_esr_el2', 'last_elr_el2',
          'last_spsr_el2', 'fault_esr', 'fault_elr', 'fault_far', 'last_nzcv',
          'native_adds', 'restore_failures', 'start_counter', 'end_counter',
          'counter_hz', 'id_aa64mmfr2', 'original_hcr', 'active_hcr', 'guest_sp',
          'direct_calls', 'initial_elr_el1', 'initial_spsr_el1', 'initial_esr_el1',
          'initial_far_el1', 'el1_state_mismatch')
IDENTITY = ('current_el', 'stage_generation', 'image_base', 'image_size',
            'heap_base', 'heap_size', 'stage_base', 'stage_size', 'call_service')
ITERATIONS = 1024
REPETITIONS = 5
REPORT_BYTES = 384
CALL_TIMEOUT = 3


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def save(dest, report):
    path = dest / 'result.json'
    temporary = dest / 'result.json.tmp'
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(path)


def build(dest):
    blob = run.build('sptmentry', dest)
    obj = dest / 'sptmentry.o'
    reloc = subprocess.check_output([str(run.LLVM / 'llvm-readobj'), '--relocations', str(obj)], text=True)
    require(re.search(r'Relocations \[\s*\]', reloc), 'unresolved probe relocations')
    symbols = subprocess.check_output([str(run.LLVM / 'llvm-nm'), '--defined-only', str(obj)], text=True)
    sites = {}
    names = {'genter_site', 'alternate_site', 'direct_genter_site', 'direct_alternate_site'}
    for line in symbols.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in names:
            sites[parts[2]] = int(parts[0], 16)
    require(set(sites) == names, 'missing call-site symbols')
    for name, word in [('genter_site', 0x00201420), ('alternate_site', 0xd4e00000),
                       ('direct_genter_site', 0xd40a6a02), ('direct_alternate_site', 0xd40a6a02)]:
        require(struct.unpack_from('<I', blob, sites[name])[0] == word, 'unexpected instruction at ' + name)
    return blob, sites


def other_clients(device):
    """Inspect actual Python script arguments, never arbitrary parent command text."""
    output = subprocess.check_output(['ps', '-axo', 'pid=,comm=,args='], text=True)
    found = []
    known = {'q1n1proxy.py', 'cycle.py', 'probe-sptm-entry.py', 'probe-nativecalls.py'}
    for line in output.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3 or int(parts[0]) == os.getpid() or 'python' not in Path(parts[1]).name.lower():
            continue
        try:
            argv = shlex.split(parts[2])
        except ValueError:
            continue
        # -c and -m invocations are not file runners; do not search their payload.
        if len(argv) < 2 or argv[1].startswith('-'):
            continue
        name = Path(argv[1]).name
        if (name in known or name.startswith(('nvme_', 'a16gpu', 'run-installed-')) or
                (name == 'run.py' and (str(ROOT) in argv[1] or device in argv))):
            found.append(dict(pid=int(parts[0]), script=argv[1]))
    require(not found, f'other potential hardware clients: {found}')


def validate(row, mode, sites, scratch):
    direct = bool(mode & 4)
    checks = {
        'identity': row['magic'] == 0x5350544d454e5431 and row['version'] == 1,
        'completed': row['status'] == 1 and row['mode'] == mode,
        'iterations': row['iterations'] == ITERATIONS,
        'exits': row['hvc_exits'] == 2 * ITERATIONS + 1,
        'work': row['native_adds'] == ITERATIONS * 64 and row['last_nzcv'] == 0xa0000000,
        'stack': row['guest_sp'] == scratch + (0x3000 if mode & 2 else 0x4000) - 16,
        'restore': row['restore_failures'] == 0 and row['el1_state_mismatch'] == 0,
        'clock': row['counter_hz'] > 0 and row['end_counter'] > row['start_counter'],
        'hcr': row['active_hcr'] == (1 << 31) | (((1 << 42) | (1 << 45)) if mode & 1 else 0),
        'calls': (row['direct_calls'], row['genter_calls'], row['alternate_calls']) ==
                 ((2 * ITERATIONS, 0, 0) if direct else (0, ITERATIONS, ITERATIONS)),
    }
    if not direct:
        expected_spsr = (0xa00003c4 if mode & 2 else 0xa00003c5) + (4 if mode & 1 else 0)
        for name in ('genter', 'alternate'):
            checks[name + '_undefined'] = row[name + '_esr'] == 1 << 25
            checks[name + '_pc'] = row[name + '_pc'] == sites[name + '_site']
            checks[name + '_spsr'] = row[name + '_spsr'] == expected_spsr
    row['checks'] = checks
    row['ticks'] = row['end_counter'] - row['start_counter']
    row['ticks_per_call'] = row['ticks'] / (2 * ITERATIONS)
    require(all(checks.values()), 'probe failed: ' + ', '.join(k for k, v in checks.items() if not v))


def execute(args, dest, blob, offsets, *, qemu=False):
    report = dict(schema='snapintosh-sptm-entry-probe-v1', result='INCOMPLETE',
                  qualification='synthetic vector/HVC call-entry microbenchmark; not production guarded fault, XNU, SPTM endpoint, or macOS performance proof',
                  hardware='QEMU' if qemu else 'A16', started=time.time(),
                  iterations=ITERATIONS, repetitions=REPETITIONS, call_timeout_seconds=CALL_TIMEOUT,
                  binary_sha256=sha(blob), source_sha256={str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in
                      (ROOT / 'probes/sptmentry.S', Path(__file__), ROOT / 'probes/run.py')},
                  calls=[], scratch_restored=False, execution_state_unknown=False)
    save(dest, report)
    proxy = None
    changed = False
    returned = True
    try:
        if not qemu:
            other_clients(args.device)
        proxy = run.connect(args.device, tries=30 if qemu else 1)
        info = proxy.bootinfo()
        report['bootinfo'] = info
        require(info['current_el'] == 2 and info['stage_generation'] == 0 and (qemu or not info['call_service']),
                'requires fresh generation0 EL2 firmware without guest call service')
        report['stage_features'] = proxy.stage_features()
        # The current QEMU fixture is a newer EFI build than this A16 resident.
        # Its function pointers are populated even at generation0. It is a
        # separately spawned emulator with no guest; hardware admission stays exact.
        require(qemu or report['stage_features'] == 0, 'unexpected resident stage features')
        if not qemu:
            for key in ('image_base', 'image_size', 'heap_base', 'heap_size'):
                require(info[key] == getattr(args, key), 'fresh firmware identity differs: ' + key)
        require(proxy.get_base() == info['image_base'], 'proxy image differs from bootinfo')
        identity = {key: info[key] for key in IDENTITY}
        resident_prefix = proxy.readmem(info['image_base'], 4096)
        report['resident_prefix_sha256'] = sha(resident_prefix)
        locator_at = monitor_work.locator_address(info)
        locator = proxy.readmem(locator_at, monitor_work.LOCATOR_SIZE)
        require(locator in (bytes(len(locator)), bytes([0xaf]) * len(locator)),
                'monitor work locator is not fresh EFI allocation fill')
        report['locator_sha256'] = sha(locator)
        guard = proxy.serror_state()
        require(not any(guard[k] for k in ('before', 'during', 'unconsumed')) and not proxy.get_exc_count(),
                'host exception counters are not clean')
        if qemu:
            report['battery'] = {'qualification': 'not applicable to QEMU'}
        else:
            returned = False
            status, battery = proxy.live_battery()
            returned = True
            report['battery'] = battery
            require(status == 0 and battery['plausible'] and (battery['ac'] or battery['percent'] >= 80),
                    'battery below 80 percent without AC or sample invalid')
        code = info['heap_base'] + run.CODE_AT
        out = code + 0x10000
        scratch = code + 0x12000
        span = 0x16000
        require(len(blob) <= 0x10000 and run.CODE_AT + span < info['heap_size'], 'invalid scratch reservation')
        require(code + span <= locator_at or locator_at + len(locator) <= code, 'scratch overlaps work locator')
        original = proxy.readmem(code, span)
        (dest / 'original-scratch.bin').write_bytes(original)
        report['reservation'] = dict(address=hex(code), bytes=span, sha256=sha(original))
        report['sites'] = {name: hex(code + off) for name, off in offsets.items()}
        sites = {name: code + off for name, off in offsets.items()}
        save(dest, report)
        changed = True
        proxy.writemem(code, blob)
        proxy.flush_code(code, len(blob))
        require(proxy.readmem(code, len(blob)) == blob, 'probe upload readback differs')
        for variant in range(4):
            for repeat in range(REPETITIONS):
                # Reverse the pair order to expose drift and cache-order effects.
                for direct in ((0, 1) if repeat % 2 == 0 else (1, 0)):
                    mode = variant | direct << 2
                    proxy.writemem(out, bytes(REPORT_BYTES))
                    proxy.writemem(scratch, bytes(0x4000))
                    report['pending_call'] = dict(variant=variant, repeat=repeat, direct=bool(direct), mode=mode)
                    save(dest, report)
                    returned = False
                    start = time.monotonic()
                    result = proxy.call(code, out, scratch, 0x4000, mode, timeout=CALL_TIMEOUT)
                    returned = True
                    elapsed = time.monotonic() - start
                    raw = proxy.readmem(out, REPORT_BYTES)
                    (dest / f'variant-{variant}-repeat-{repeat}-direct-{direct}.bin').write_bytes(raw)
                    row = dict(zip(FIELDS, struct.unpack_from('<' + 'Q' * len(FIELDS), raw)))
                    row.update(variant=variant, repeat=repeat, direct=bool(direct), proxy_result=result,
                               host_call_seconds=elapsed, raw_sha256=sha(raw))
                    report['calls'].append(row)
                    report.pop('pending_call')
                    save(dest, report)
                    require(result == 0, 'probe call returned an error')
                    validate(row, mode, sites, scratch)
                    save(dest, report)
        report['comparisons'] = []
        for variant in range(4):
            medians = {direct: statistics.median(row['ticks_per_call'] for row in report['calls']
                                                if row['variant'] == variant and row['direct'] == direct)
                       for direct in (False, True)}
            report['comparisons'].append(dict(variant=variant, control_ticks_per_call=medians[False],
                direct_ticks_per_call=medians[True], synthetic_control_over_direct=medians[False] / medians[True]))
        require(all(sha((ROOT / name).read_bytes()) == digest for name, digest in report['source_sha256'].items()),
                'probe sources changed during measurement')
        report['result'] = 'PASS'
    except BaseException as error:
        report['error'] = repr(error)
        report['result'] = 'FAIL'
        raise
    finally:
        try:
            if not returned:
                report['execution_state_unknown'] = True
                report['result'] = 'UNKNOWN_CALL_OUTCOME_NO_RETRY_NO_RESTORE'
            elif changed:
                proxy.writemem(code, original)
                proxy.flush_code(code, len(blob))
                require(proxy.readmem(code, span) == original, 'scratch restore readback differs')
                report['scratch_restored'] = True
                after = proxy.bootinfo()
                require({key: after[key] for key in IDENTITY} == identity, 'resident identity changed')
                require(proxy.readmem(info['image_base'], 4096) == resident_prefix, 'resident prefix changed')
                require(proxy.readmem(locator_at, len(locator)) == locator, 'monitor locator changed')
                guard = proxy.serror_state()
                require(not any(guard[k] for k in ('before', 'during', 'unconsumed')) and not proxy.get_exc_count(),
                        'new host exception after probe')
                report['identity_restored'] = True
        except BaseException as error:
            report['restore_error'] = repr(error)
            report['result'] = 'FAIL'
            raise
        finally:
            report['finished'] = time.time()
            save(dest, report)
            if proxy:
                proxy.link.close()
    print(json.dumps({key: report[key] for key in ('result', 'hardware', 'scratch_restored', 'comparisons')}, indent=2))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--prefix', required=True)
    ap.add_argument('--device', default='udp://en6')
    ap.add_argument('--build-only', action='store_true')
    ap.add_argument('--qemu', action='store_true', help='emulated E2E only; no A16 access')
    for key in ('image-base', 'image-size', 'heap-base', 'heap-size'):
        ap.add_argument('--' + key, type=lambda value: int(value, 0))
    args = ap.parse_args()
    if not re.fullmatch('[a-z0-9-]+', args.prefix):
        ap.error('prefix must use lowercase letters, digits and hyphens')
    if not args.build_only and not args.qemu and any(getattr(args, key) is None for key in
                                                    ('image_base', 'image_size', 'heap_base', 'heap_size')):
        ap.error('hardware requires explicit fresh image and heap base/size')
    dest = ROOT / 'build' / args.prefix
    dest.mkdir(exist_ok=False)
    blob, sites = build(dest)
    build_record = dict(binary_sha256=sha(blob), bytes=len(blob), sites=sites,
                        source_sha256=sha((ROOT / 'probes/sptmentry.S').read_bytes()),
                        qualification='build only, not native execution')
    (dest / 'build.json').write_text(json.dumps(build_record, indent=2) + '\n')
    if args.build_only:
        print(json.dumps(build_record, indent=2))
        return
    lock_path = Path('/tmp') / ('snapintosh-sptm-qemu.lock' if args.qemu else 'snapintosh-hardware.lock')
    with lock_path.open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.qemu:
            # Isolate the standard QEMU helper's ESP/log outputs in this run.
            fixture_root = dest / 'fixture'
            (fixture_root / 'build').mkdir(parents=True)
            (dest / 'q1n1').symlink_to(ROOT.parent / 'q1n1', target_is_directory=True)
            with run.Qemu(fixture_root) as socket:
                args.device = socket
                execute(args, dest, blob, sites, qemu=True)
        else:
            execute(args, dest, blob, sites)


if __name__ == '__main__':
    main()
