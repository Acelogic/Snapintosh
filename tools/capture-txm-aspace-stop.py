#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read a bounded 16K hierarchy for a qualified TXM36 cleanup stop."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import run


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True)
    ap.add_argument('--prefix', required=True)
    ap.add_argument('--cpu', required=True, type=int, choices=range(6))
    args = ap.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+', args.prefix):
        raise ValueError('invalid prefix')
    base = ROOT / 'build' / args.prefix
    audit = json.loads(Path(f'{base}-audit.json').read_text())
    stop = json.loads(Path(f'{base}-cpu{args.cpu}-stop.json').read_text())
    if (not audit['runtime_stop_qualified'] or audit['ownership']['mismatches'] or
            audit['service'][1] != 0x100000001 + args.cpu or
            int(stop['registers']['16'], 16) != 0x2000000000024):
        raise ValueError('requires a qualified TXM36 stop on the selected CPU')
    handle = int(stop['registers']['1'], 16)
    obj = next(o for o in audit['shared_root_state']['objects']
               if int(o['handle'], 16) == handle)
    metadata = bytes.fromhex(obj['metadata'])
    if obj['shared'] or metadata[12] != 0:
        raise ValueError('this capture covers ordinary 16K roots only')
    root = int(obj['root'], 16)
    geometry = audit['geometry']
    blob = (ROOT / 'build/xnuboot.bin').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != audit['monitor_sha256'] or digest != stop['monitor_sha256']:
        raise ValueError('monitor differs from the saved stop')
    secondary = runpy.run_path(str(ROOT / 'tools/secondary-runtime.py'))
    proxy = run.connect(args.device, tries=1)
    try:
        def read(pa, size):
            if not 0 < size <= 0x40000:
                raise ValueError('read outside capture bound')
            return b''.join(proxy.readmem(pa+i, min(65536, size-i), live=True)
                            for i in range(0, size, 65536))

        info = proxy.bootinfo()
        work, work_size = run.resident_work(proxy, info)
        if read(info['heap_base'] + run.CODE_AT, len(blob)) != blob:
            raise ValueError('resident monitor differs')
        service_pa = work + secondary['SERVICES_OFFSET']
        expected_service = struct.pack('<8Q', *audit['service'])
        if read(service_pa, 64) != expected_service:
            raise ValueError('resident stop changed')

        def meta(pa):
            if (pa & 0x3fff or not geometry['frame_low'] <= pa < geometry['frame_high']):
                raise ValueError('table outside frame metadata')
            return read(geometry['frame_map'] + ((pa-geometry['frame_low']) >> 14)*16, 16)

        if meta(root) != metadata:
            raise ValueError('root metadata changed')
        seen = set()
        rows = []

        def walk(pa, level, va):
            if pa in seen or len(seen) >= 64:
                raise ValueError('cycle, alias or hierarchy exceeds bounded capture')
            seen.add(pa)
            m = meta(pa)
            if m[2] not in (18, 20, 21, 23):
                raise ValueError('unexpected table type')
            words = struct.unpack('<2048Q', read(pa, 0x4000))
            entries = [dict(index=i, descriptor=hex(w), valid=bool(w & 1))
                       for i, w in enumerate(words) if w]
            rows.append(dict(pa=hex(pa), level=level, va=hex(va), type=m[2],
                             metadata=m.hex(), entries=entries))
            if level < 3:
                for i, word in enumerate(words):
                    if word & 3 == 3:
                        walk(word & 0x0000ffffffffc000, level+1,
                             va + (i << (14+(3-level)*11)))

        walk(root, 1, 0)
        if read(service_pa, 64) != expected_service or meta(root) != metadata:
            raise ValueError('stop changed during capture')
        report = dict(monitor_sha256=digest, cpu=args.cpu, handle=hex(handle),
                      object=obj, tables=rows,
                      boundary='read-only source hierarchy; no cleanup or release performed')
        path = Path(f'{base}-txm-aspace.json')
        path.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(dict(path=str(path), root=hex(root), tables=[
            {k:r[k] for k in ('pa', 'level', 'type', 'metadata')} |
            dict(nonzero=len(r['entries']), valid=sum(e['valid'] for e in r['entries']))
            for r in rows])))
    finally:
        proxy.link.close()


if __name__ == '__main__':
    main()
