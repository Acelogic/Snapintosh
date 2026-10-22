#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The kept console of a preserved run, read with its own build's layout.

tools/monitor_layout.py used to compile xnuboot.c without the run's -D flags.
With SNAP_UNNEST_4K_FAST, struct sptm_root_memo is 0xf8000 bytes larger, so
the define-free console_log offset lands inside root_memo's entries (32-byte
{table, base, record, epoch|flags|shift} rows) and console.txt began with
binary records; the capture was also 0xf8000 bytes short. This reads
context.bin at the offsets of the run's flags (launch.json, else
qualification.json), refuses bytes the capture did not retain, and writes the
console to --output, which must lie outside build/PREFIX (preserve hashes
every file there).

  python3 tools/recover-console-log.py --run build/PREFIX --output OUT.txt
"""
import argparse
import json
import runpy
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_flags(run):
    for name in ('launch.json', 'qualification.json'):
        path = run / name
        if path.is_file():
            flags = json.loads(path.read_text()).get('flags')
            if flags:
                return name, flags
    raise SystemExit(f'{run}: no launch.json or qualification.json with flags')


def recover(run, partial=False):
    layouts = runpy.run_path(str(ROOT / 'tools/monitor_layout.py'))
    source, flags = run_flags(run)
    built, bare = layouts['MonitorLayout'](flags), layouts['MonitorLayout']()
    context = (run / 'context.bin').read_bytes()
    total = struct.unpack_from('<Q', context, built.offset('context', 'console_tail_bytes'))[0]
    head_at, head_cap = built.offset('context', 'console_log'), built.length('context', 'console_log')
    tail_at, tail_cap = built.offset('context', 'console_tail'), built.length('context', 'console_tail')
    kept = min(total, head_cap)
    unretained = max(0, head_at + kept - len(context))
    if unretained and not partial:
        raise SystemExit(f'{run}: context.bin holds {len(context)} bytes; console_log needs '
                         f'{head_at + kept} (a capture retained short of the build\'s context; --partial '
                         f'writes the {kept - unretained} retained bytes and marks the rest)')
    text = context[head_at:head_at + kept - unretained]
    if unretained:
        # The 64 KiB ring (before root_memo, always retained) still holds the console's last bytes.
        ring = context[tail_at:tail_at + tail_cap]
        start = max(kept - unretained, total - tail_cap)
        missing = start - (kept - unretained)
        text += (b'\n[... %d console_log bytes never retained (context.bin short) ...]\n' % missing if missing
                 else b'') + bytes(ring[i % tail_cap] for i in range(start, min(total, head_cap)))
    lost = 0
    if total > head_cap:
        ring = context[tail_at:tail_at + tail_cap]
        start = max(head_cap, total - tail_cap)
        lost = start - head_cap
        text += (b'\n[... %d console bytes not kept ...]\n' % lost if lost else b'') + \
            bytes(ring[i % tail_cap] for i in range(start, total))
    return text, dict(run=str(run), flags_from=source, console_bytes=total, kept=len(text), lost=lost,
                      unretained=unretained,
                      context_bin_bytes=len(context), build_context_bytes=built.size('context'),
                      define_free_context_bytes=bare.size('context'),
                      console_log_offset=head_at, define_free_console_log_offset=bare.offset('context', 'console_log'),
                      printable=round(sum(32 <= b < 127 or b in (9, 10, 13) for b in text) / max(1, len(text)), 6))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run', required=True, type=Path, help='a preserved run directory (build/PREFIX)')
    ap.add_argument('--output', required=True, type=Path, help='new file, outside the run directory')
    ap.add_argument('--partial', action='store_true',
                    help='a capture retained short: write the retained console_log bytes and mark the rest')
    args = ap.parse_args(argv)
    run, out = args.run.resolve(), args.output.resolve()
    if out.is_relative_to(run) or out.exists():
        raise SystemExit(f'{out}: never write into the run directory or over an existing file')
    text, info = recover(run, args.partial)
    out.write_bytes(text)
    print(json.dumps(dict(info, output=str(out)), indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
