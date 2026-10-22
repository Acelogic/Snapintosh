#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check a tools/host/blit-chunks run (agents/gpu-perf FAILURE-MODES.md C1-C4): execute its stream over a byte model
(tools/ubocheck.py's Memory: snapshots, then every CP_MEMCPY in order) and require (a) the destination equals the
source over every copied range, (b) no destination byte outside the ranges changed, (c) every CP_MEMCPY is at most
--max-bytes (default 1 MiB).
    blit-chunk-check.py RUN_DIR [--max-bytes N]"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture as C  # noqa: E402
import ubocheck as U  # noqa: E402
run = Path(sys.argv[1])
limit = int(sys.argv[sys.argv.index('--max-bytes') + 1]) if '--max-bytes' in sys.argv else 1 << 20
report = json.loads((run / 'report.json').read_text())
E = C.regs()['E']
fail, sizes = [], []
for c in report['commits']:
    rows = {r['id']: r for r in c.get('resources', [])}
    mem = U.Memory(run / c['dir'], rows)
    before = {rid: bytes(mem.get(rid)[0]) for rid in rows}
    for kind, cmd in C.kernel_commands((run / c['dir'] / 'commands.bin').read_bytes()):
        if kind != C.KCMD_IB:
            continue
        pkg = C.parse_package(cmd); relocs = {r['lo']: r for r in pkg['relocs']}
        for ev in C.walk(C.ib_words(pkg)):
            if ev[0] == 'pkt' and ev[2] == E['CP_MEMCPY']:
                s, d = relocs[4 * (ev[1] + 2)], relocs[4 * (ev[1] + 4)]
                n = 4 * ev[3][0]
                sizes.append(n)
                mem.write(d['rid'], d['offset'], mem.read(s['rid'], s['offset'], n))
    for cp in report['copies']:
        got = mem.read(cp['destination'], cp['destination_offset'], cp['bytes'])
        want = before[cp['source']][cp['source_offset']:cp['source_offset'] + cp['bytes']]
        if got != want:
            fail.append(f'copy of {cp["bytes"]} bytes: destination differs from source')
    dest = report['copies'][0]['destination']
    after = mem.get(dest)[0]
    covered = bytearray(len(after))
    for cp in report['copies']:
        covered[cp['destination_offset']:cp['destination_offset'] + cp['bytes']] = b'\x01' * cp['bytes']
    outside = sum(1 for i in range(0, len(after), 4) if not covered[i] and after[i:i + 4] != before[dest][i:i + 4])
    if outside:
        fail.append(f'{outside} destination dwords outside the copied ranges changed')
big = [n for n in sizes if n > limit]
if big:
    fail.append(f'{len(big)} CP_MEMCPY larger than {limit} bytes: {big[:4]}')
print(f'CP_MEMCPY sizes: {sizes}')
for f in fail:
    print('FAIL', f)
print('PASS' if not fail else 'FAIL')
sys.exit(1 if fail else 0)
