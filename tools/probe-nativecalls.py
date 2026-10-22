#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded Apple-call exception probe, preserving the stopped guest's payload.

This does not boot XNU, touch its RAM or qualify a production trap replacement.
The previously captured monitor code/report reservation is backed up, replaced
temporarily, restored, and read back. A timed-out P_CALL is never retried and
does not authorize writes into a potentially executing payload.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import run

FIELDS = ('magic', 'version', 'status', 'mode', 'iterations', 'genter_calls',
          'alternate_calls', 'hvc_exits', 'genter_esr', 'genter_pc',
          'genter_spsr', 'genter_far', 'alternate_esr', 'alternate_pc',
          'alternate_spsr', 'alternate_far', 'last_esr_el2', 'last_elr_el2',
          'last_spsr_el2', 'fault_esr', 'fault_elr', 'fault_far', 'last_nzcv',
          'native_adds', 'restore_failures', 'start_counter', 'end_counter',
          'counter_hz', 'id_aa64mmfr2', 'original_hcr', 'active_hcr', 'guest_sp')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate(row, mode, sites, scratch):
    """Require actual native exceptions, exact PCs, and correct native results."""
    checks = {
        'identity': row['magic'] == 0x4e43414c4c533031 and row['version'] == 1,
        'completion': row['status'] == 1 and row['mode'] == mode,
        'bounded_calls': row['iterations'] == 64 and
            row['genter_calls'] == row['alternate_calls'] == 64 and
            row['hvc_exits'] == 129,
        'native_work': row['native_adds'] == 4096 and row['last_nzcv'] == 0xa0000000,
        'guest_stack': row['guest_sp'] == scratch + (0x3000 if mode & 2 else 0x4000) - 16,
        'state_restored': row['restore_failures'] == 0,
        'counter': row['counter_hz'] > 0 and row['end_counter'] > row['start_counter'],
        'nested_mode': row['active_hcr'] ==
            ((1 << 31) | (((1 << 42) | (1 << 45)) if mode & 1 else 0)),
    }
    saved = (0xa00003c4 if mode & 2 else 0xa00003c5) + (4 if mode & 1 else 0)
    for name in ('genter', 'alternate'):
        checks[name + '_undefined'] = row[name + '_esr'] == (1 << 25)
        checks[name + '_pc'] = row[name + '_pc'] == sites[name]
        checks[name + '_state'] = row[name + '_spsr'] == saved
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        raise ValueError('native-call qualification failed: ' + ', '.join(failed))
    return checks


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', default='udp://en5')
    ap.add_argument('--baseline', required=True)
    ap.add_argument('--prefix', required=True)
    args = ap.parse_args()
    for value in (args.baseline, args.prefix):
        if not re.fullmatch('[a-z0-9-]+', value):
            ap.error('prefixes must be lowercase letters, digits and hyphens')
    dest = ROOT / 'build' / args.prefix
    dest.mkdir(exist_ok=False)
    launch = json.loads((ROOT / 'build' / (args.baseline + '-launch.json')).read_text())
    audit = json.loads((ROOT / 'build' / (args.baseline + '-audit.json')).read_text())
    if launch.get('exit_code') != 9 or not audit.get('runtime_stop_qualified'):
        raise ValueError('baseline is not a captured watchdog stop')
    try:
        os.kill(launch['pid'], 0)
    except ProcessLookupError:
        pass
    else:
        raise ValueError('recorded launcher PID still exists; inspect it before probing')
    monitor = (ROOT / 'build/xnuboot.bin').read_bytes()
    if not sha(monitor) == launch['monitor_sha256'] == audit['monitor_sha256']:
        raise ValueError('baseline monitor binding mismatch')
    blob = run.build('nativecalls', dest)
    # Single-object extraction is valid only when no unresolved relocations exist.
    reloc = subprocess.check_output([str(run.LLVM / 'llvm-readobj'), '--relocations',
                                    str(dest / 'nativecalls.o')], text=True)
    if not re.search(r'Relocations \[\s*\]', reloc):
        raise ValueError('unresolved probe relocations')
    symbols = subprocess.check_output([str(run.LLVM / 'llvm-nm'), '--defined-only',
                                      str(dest / 'nativecalls.o')], text=True)
    offsets = {}
    for line in symbols.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in ('genter_site', 'alternate_site'):
            offsets[parts[2].removesuffix('_site')] = int(parts[0], 16)
    if set(offsets) != {'genter', 'alternate'}:
        raise ValueError('probe site symbols missing')
    api = runpy.run_path(str(ROOT / 'tools/secondary-runtime.py'))
    report = dict(baseline=args.baseline, probe_sha256=sha(blob),
                  source_sha256=sha((ROOT / 'probes/nativecalls.S').read_bytes()),
                  runner_sha256=sha(Path(__file__).read_bytes()), results=[],
                  monitor_restored=False, report_reservation_restored=False,
                  qualification='standalone MMU-off EL1 exception proof; not XNU integration')
    proxy = run.connect(args.device, tries=1)
    may_restore = True
    modified = False
    try:
        info = proxy.bootinfo()
        if info['current_el'] != 2:
            raise ValueError('probe requires an EL2 host')
        report['bootinfo'] = info
        work, size = run.resident_work(proxy, info)
        service = list(struct.unpack('<8Q', proxy.readmem(work + api['SERVICES_OFFSET'], 64)))
        if service != audit['service'] or service[0] != 0 or service[2] >> 63 != 1:
            raise ValueError('live stopped-service binding mismatch')
        base = proxy.read64(work + api['SECONDARY_BASE_OFFSET'])
        if base & 4095 or not work <= base <= work + size - 6 * 4096:
            raise ValueError('invalid live secondary records')
        rows = []
        for slot in range(1, 6):
            raw = struct.unpack('<37Q', proxy.readmem(base + slot * 4096, 296))
            row = dict(zip(api['FIELDS'], raw))
            prior = audit['physical_secondaries'][slot - 1]
            if any(row[k] != prior[k] for k in api['FIELDS']):
                raise ValueError('secondary record changed since stopped capture')
            if row['phase'] != 4 or row['error'] or row['cleanup'] != 1:
                raise ValueError('secondary is not in its captured completed state')
            rows.append(dict(slot=slot, phase=row['phase'], cleanup=row['cleanup']))
        report['stopped_secondaries'] = rows
        code = info['heap_base'] + run.CODE_AT
        out = info['heap_base'] + run.OUT_AT
        span = run.WORK_AT - run.CODE_AT
        if run.WORK_AT > info['heap_size']:
            raise ValueError('code/report reservation outside q1n1 heap')
        original = proxy.readmem(code, span)
        if original[:len(monitor)] != monitor:
            raise ValueError('resident monitor differs from the captured binary')
        (dest / 'original-code-and-report.bin').write_bytes(original)
        report['reservation'] = dict(address=hex(code), size=span, sha256=sha(original))
        scratch = (out + 0x40000 + 4095) & ~4095
        if scratch + 0x4000 > code + span:
            raise ValueError('probe scratch would leave the backed-up reservation')
        sites = {key: code + offset for key, offset in offsets.items()}
        report['sites'] = {key: hex(value) for key, value in sites.items()}
        modified = True
        proxy.writemem(code, blob)
        proxy.flush_code(code, len(blob))
        if proxy.readmem(code, len(blob)) != blob:
            raise ValueError('probe upload readback mismatch')
        for mode in range(4):
            proxy.writemem(scratch, bytes(0x4000))
            proxy.writemem(out, bytes(256))
            may_restore = False
            start = time.monotonic()
            result = proxy.call(code, out, scratch, 0x4000, mode, timeout=10)
            may_restore = True
            elapsed = time.monotonic() - start
            raw = proxy.readmem(out, 256)
            (dest / f'mode-{mode}.bin').write_bytes(raw)
            row = dict(zip(FIELDS, struct.unpack('<32Q', raw)))
            row.update(proxy_result=result, host_call_seconds=elapsed)
            report['results'].append(row)
            # Persist the failure report before validation can raise.
            (dest / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
            row['checks'] = validate(row, mode, sites, scratch)
            seconds = (row['end_counter'] - row['start_counter']) / row['counter_hz']
            row['hardware_seconds'] = seconds
            print(f'mode {mode}: 128 native exceptions, 4096 native adds, '
                  f'{seconds:.6f}s, host state restored', flush=True)
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        try:
            if modified and may_restore:
                proxy.writemem(code, original)
                proxy.flush_code(code, run.OUT_AT - run.CODE_AT)
                restored = proxy.readmem(code, span)
                report['monitor_restored'] = restored[:len(monitor)] == monitor
                report['report_reservation_restored'] = restored == original
                if restored != original:
                    raise ValueError('restored reservation readback mismatch')
                after = proxy.bootinfo()
                report['same_resident_stage'] = all(after[key] == info[key] for key in
                    ('stage_generation', 'heap_base', 'heap_size', 'current_el'))
                if not report['same_resident_stage']:
                    raise ValueError('resident stage identity changed')
                print('Saved monitor and report bytes restored and verified.', flush=True)
            elif modified:
                report['execution_state_unknown'] = True
                print('P_CALL completion is unknown: no retry or overwrite attempted.', flush=True)
        finally:
            (dest / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
            proxy.link.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
