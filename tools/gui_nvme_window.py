#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bound GUI deployment adapter; stream rollback overlays within existing RAM.

Failure inventory and physical E2E requirement: ADRENO-GUI-INTEGRATION-20260927.md.
The native helper remains read-only and its 1 MiB/256-entry reservation is fixed.
"""
from pathlib import Path
import hashlib
import struct
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[1]
Q1N1 = ROOT.parent / 'q1n1'
PINNED = {
    'tools/nvme_window.py': '3da657ad5ccc2963e4f37482565b149d6722de9399763f1ce2de9dd87ed76b55',
    'tools/nvme_rw.py': '5027a4090c04a69feeff4f4eb41aee10fff764a022df6ff1e39374a7ea8bace8',
    'tools/nvme_hash.py': 'e09c74877dc5e2189f7ea68dc84e06a300dc006e98593aa77974157b92980861',
}
for name, expected in PINNED.items():
    assert hashlib.sha256((Q1N1 / name).read_bytes()).hexdigest() == expected, name
sys.path.insert(0, str(Q1N1 / 'tools'))
from nvme_hash import NativeHash, MAGIC, HEADER, WORK_BYTES
from nvme_m3 import Refused, Misbehaved


class GuiNativeHash(NativeHash):
    def digest(self, lba, count, progress=None, overlays=()):
        if not overlays:
            return super().digest(lba, count, progress)
        nv = self.nvme
        if lba < 0 or count <= 0 or lba + count > nv.nsze or nv.io.outstanding:
            raise Refused('GUI native hash range/queue invalid')
        low, high = lba * nv.lba_bytes, (lba + count) * nv.lba_bytes
        checked = []
        total = 0
        end = low
        for absolute, data in overlays:
            if (type(absolute) is not int or not isinstance(data, bytes) or not data
                    or absolute % 4096 or len(data) % 4096
                    or absolute < end or absolute + len(data) > high):
                raise Refused('GUI overlay must be sorted, disjoint, aligned and inside hash range')
            total += len(data)
            if total > 128 << 20:
                raise Refused('GUI overlay exceeds declared 128 MiB payload ceiling')
            end = absolute + len(data)
            checked.append((absolute, data))
        q = nv.io
        done = commands = calls = peak = 0
        state = bytes(136)
        t0 = time.monotonic()

        def clipped(begin, finish):
            result = []
            for absolute, data in checked:
                lo, hi = max(begin, absolute), min(finish, absolute + len(data))
                if lo < hi:
                    result.append((lo, data[lo - absolute:hi - absolute]))
            return result

        while done < count:
            n = min((16 << 20) // nv.lba_bytes, count - done)
            begin = (lba + done) * nv.lba_bytes
            rows = clipped(begin, begin + n * nv.lba_bytes)
            if len(rows) > 256 or sum(len(data) for _, data in rows) > 1 << 20:
                n = min((1 << 20) // nv.lba_bytes, count - done)
                rows = clipped(begin, begin + n * nv.lba_bytes)
            table, payload = bytearray(), bytearray()
            for absolute, data in rows:
                table.extend(struct.pack('<3Q', absolute, nv.w + 0x70000 + len(payload), len(data)))
                payload.extend(data)
            if len(rows) > 256 or len(payload) > 1 << 20:
                raise Refused('GUI clipped overlay exceeds unchanged helper RAM reservation')
            if rows:
                nv.hw.write(nv.w + 0x61000, table)
                nv.hw.write(nv.w + 0x70000, payload)
            peak = max(peak, len(payload))
            fields = [MAGIC, nv.bar, nv.w, lba + done, n, nv.lba_bytes, nv.max_transfer, nv.nsze,
                      q.tail, q.head, q.phase, q.next_cid, nv.stride, q.entries, 0, 0, 0, commands,
                      nv.w + 0x61000 if rows else 0, len(rows)]
            nv.hw.write(self.state, HEADER.pack(*fields) + state)
            result = nv.hw.p.call(self.code, self.state, int(done == 0), int(done + n == count), timeout=30)
            output = nv.hw.read(self.state, WORK_BYTES)
            after = HEADER.unpack_from(output)
            q.tail, q.head, q.phase, q.next_cid = after[8:12]
            commands = after[17]
            if result != 0 or after[14] != 0 or after[15] != n:
                raise Misbehaved('GUI native overlay hash failed', result=result, status=after[14],
                                 done_blocks=after[15], completion=hex(after[16]))
            state = output[HEADER.size:]
            done += n
            calls += 1
            if progress:
                progress(done * nv.lba_bytes, count * nv.lba_bytes, time.monotonic() - t0)
        result = state[-32:].hex()
        nv.log.setdefault('native_hashes', []).append(dict(lba=lba, blocks=count, sha256=result,
            commands=commands, seconds=round(time.monotonic() - t0, 3), overlay_bytes=total,
            overlay_entries=len(checked), overlay_calls=calls, overlay_peak_bytes=peak,
            overlay_adapter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
        return result


base = Q1N1 / 'tools/nvme_window.py'
source = base.read_text()
changes = {
    "m['payload_bytes'] <= 64 * MIB, 'package byte bound'":
        "m['payload_bytes'] <= p['max_delta_bytes'] == 128 * MIB, 'GUI package byte bound'",
    "            if args.mode != 'check':":
        "            if args.mode == 'check':\n"
        "                candidate = [(co + e['container_offset'], after[e['pack_offset']:e['pack_offset'] + e['bytes']]) for e in m['extents']]\n"
        "                require(hash_range('container-forward-overlay', co, cb, candidate) == m['container']['after_sha256'], 'complete native GUI overlay differs from replay')\n"
        "                record['gui_forward_overlay_verified'] = True\n"
        "            if args.mode != 'check':",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
module = types.ModuleType('_gui_nvme_window_base')
module.__file__ = str(base)
exec(compile(source, str(base), 'exec'), module.__dict__)
module.NativeHash = GuiNativeHash
original_sources = module.sources


def sources():
    result = original_sources()
    result['../Snapintosh-adreno-pipeline/tools/gui_nvme_window.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return result


module.sources = sources
package = module.package
main = module.main

if __name__ == '__main__':
    raise SystemExit(main())
