#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve captured SIGABRT frame candidates without a hardware connection.

Failure inventory: docs/GEN57-OBJC-ABORT-20260928.md. These are not authenticated
unwinds, PID attribution, or proof of the original Objective-C exception.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CACHE = Path('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld')
CACHE_READER = ROOT / 'tools/dyld-cache.py'
CACHE_READER_SHA = 'e4c9ae7ad501e8b9ccf8fc7a90e052db7ceaf8c923074cc661f462b837d924a7'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--prefix', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    assert re.fullmatch('[a-z0-9-]+', args.prefix) and not args.output.exists()
    paths = {kind: ROOT / 'build' / (args.prefix + suffix) for kind, suffix in (
        ('launch', '-launch.json'), ('audit', '-audit.json'),
        ('native', '-native-startup-state-v1.json'),
        ('binding', '-native-startup-state-v1-binding.json'))}
    inputs = {kind: json.loads(path.read_text()) for kind, path in paths.items()}
    pins = {str(path): sha(path) for path in [*paths.values(), CACHE_READER, Path(__file__)]}
    assert pins[str(CACHE_READER)] == CACHE_READER_SHA
    launch, audit, native, binding = [inputs[k] for k in ('launch', 'audit', 'native', 'binding')]
    assert launch.get('finished') and isinstance(launch.get('exit_code'), int)
    assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
    assert binding['status'] == 'NATIVE_STARTUP_STATE_CAPTURED'
    assert binding['output_sha256'] == sha(paths['native'])
    assert binding['verification_sha256'] == sha(paths['audit'])
    assert launch['monitor_sha256'] == audit['monitor_sha256'] == native['monitor_sha256'] == binding['monitor_sha256']
    ring = audit['el0_crashes']['user_crashes']
    assert not any(ring['lost']), 'incomplete crash history'
    rows = [row for row in ring['rows'] if row['kind'] == 'self_signal' and row['signal'] == 'SIGABRT']
    assert rows and all(row['x16'] == 328 for row in rows), 'unexpected self-signal syscall'
    sites = {row['elr'] for row in rows}
    assert len(sites) == 1, 'multiple pthread-kill syscall sites'
    live_syscall = next(iter(sites))
    processes = [p for p in native['user_processes']['processes'] if p.get('name') == 'WindowServer']
    assert len(processes) == 1
    anchors = [t['saved_user_state'] for t in processes[0]['threads']
               if t.get('saved_user_state', {}).get('instruction_hex')]
    assert anchors
    anchor = anchors[0]
    code, live_pc = bytes.fromhex(anchor['instruction_hex']), int(anchor['pc'], 16)
    assert len(code) >= 64
    build = subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip()
    assert build == '26A428', 'unreviewed shared-cache build'
    spec = importlib.util.spec_from_file_location('saved_abort_cache', CACHE_READER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with module.Cache(CACHE) as cache:
        symbols = [s for s in cache.symbols('/usr/lib/system/libsystem_kernel.dylib')
                   if s[1] == '___pthread_kill' and s[0]]
        assert len(symbols) == 1
        slides = []
        for offset in range(0, 32, 4):
            slide = live_syscall - symbols[0][0] - offset
            if slide >= 0 and slide % 0x4000 == 0 and cache.read(live_pc - slide, len(code)) == code:
                slides.append(slide)
        assert len(set(slides)) == 1, 'cache slide is not uniquely byte-verified'
        slide = slides[0]
        groups, symbol_cache = {}, {}
        for row in rows:
            candidates = tuple((raw & ((1 << 39) - 1)) for raw in [row['lr'], *row['frames']])
            group = groups.setdefault(candidates, dict(events=[], frames=[]))
            group['events'].append(dict(cpu=row['cpu'], sequence=row['seq'], root=hex(row['root']),
                                        guest_seconds=row['guest_s']))
        for candidates, group in groups.items():
            for live in candidates:
                # These are return addresses. A noreturn call may leave LR at
                # the next symbol boundary, so attribute the call instruction.
                returned = live - slide
                pc = returned - 4
                result = dict(live_return_candidate=hex(live), unslid_return_candidate=hex(returned),
                              unslid_call_site_candidate=hex(pc), authenticated=False)
                owners = cache.owner(pc)
                if len(owners) == 1:
                    image, segment = owners[0]
                    if image not in symbol_cache:
                        symbol_cache[image] = sorted((s for s in cache.symbols(image)
                            if s[0] and s[3] and (s[2] & 14) == 14), key=lambda s: s[0])
                    preceding = [s for s in symbol_cache[image] if s[0] <= pc]
                    result.update(image=image, segment=segment, image_uuid=cache.image(image)['uuid'],
                        call_site_hex=cache.read(pc, 4).hex(),
                        preceding_symbol=preceding[-1][1] if preceding else None,
                        symbol_offset=hex(pc - preceding[-1][0]) if preceding else None)
                else:
                    result['unresolved_owner_count'] = len(owners)
                group['frames'].append(result)
    for name, digest in pins.items():
        assert sha(name) == digest, name
    result = dict(status='SAVED_ABORT_CANDIDATES_RESOLVED', hardware_access=False,
        generation=binding['generation'], inputs_sha256=pins, cache_build=build,
        common_slide=hex(slide), anchor_process_id=processes[0]['pid'],
        live_anchor_pc=hex(live_pc), live_anchor_hex=code.hex(), anchor_bytes_matched=len(code),
        abort_events=len(rows), groups=list(groups.values()),
        boundary='Byte-verified cache slide; PAC-stripped frame candidates and nearest symbols only. '
                 'No authenticated unwind, direct PID attribution or original exception reason.')
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status=result['status'], output=str(args.output), sha256=sha(args.output),
                          common_slide=result['common_slide'], group_counts=[len(g['events']) for g in groups.values()])))


if __name__ == '__main__':
    main()
