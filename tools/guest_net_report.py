#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the guest-network record (probes/xnuboot.c OUT_GUEST_NET, compat/guest-net-link.h) from report.bin.

    python3 tools/guest_net_report.py --report build/PREFIX/report.bin -D... (the run's qualification flags)

The record sits after the last report record before it, as in the monitor:
the fast timer-IRQ record, else the token costs, else the fine profile, else
the exit profile, else the early-stop record. "GUESTNT1", a word of
net-enabled | link bytes << 32, struct guest_net_link, struct guest_net_view.
docs/GUEST-NETWORK-20261019.md.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'probes'))
import perf_counters  # noqa: E402

MAGIC = 0x31544e5453455547          # "GUESTNT1"
DEFINE = '-DSNAP_GUEST_NET=1'
LINK = ('attached ring_pa generation tx_tail rx_head attaches detaches refusals last_refusal polls views '
        'frames_out frames_in ring_lost protocol_errors ref_failures poll2_unsupported taken_clamped '
        'filled_clamped').split() + [f'reserved{n}' for n in range(5)]
VIEW = ('magic version tx_base rx_base slots slot_bytes frame_max tx_first tx_avail rx_first rx_room tx_taken '
        'rx_filled owner owner_changes requests refused frames_in frames_out rx_full bad_frames reply_failures '
        'polls_seen').split()
REFUSALS = {-1: 'disabled', -2: 'origin', -3: 'op', -4: 'range', -5: 'frame', -6: 'header'}
EARLY_STOP_WORDS = 30


def offset(defines):
    """Byte offset of the record in report.bin for a monitor built with `defines`."""
    if perf_counters.FAST_IRQ_DEFINE in defines:
        start, size = perf_counters.fast_irq_spec(defines)
    elif any(d in defines for d in perf_counters.TOKEN_DEFINES):
        start, size = perf_counters.token_costs_spec(defines)
    elif '-DSNAP_FINE_LOCKS=1' in defines:
        start, size = perf_counters.fine_profile_spec(defines)
    elif '-DSNAP_FAST_EL0_SYSREG=1' in defines or '-DSNAP_SERVICE_SUBCLASS=1' in defines:
        start, size = perf_counters.exit_profile_spec(defines)
    else:
        import run  # probes/run.py: EARLY_STOP_OFFSET
        start, size = run.EARLY_STOP_OFFSET, 8 * EARLY_STOP_WORDS
    return start + size


def decode(record):
    if len(record) < 16 + 8 * (len(LINK) + len(VIEW)):
        raise ValueError('short guest-network record')
    magic, bits = struct.unpack_from('<2Q', record, 0)
    if magic != MAGIC or bits >> 32 != 8 * len(LINK) or bits & ~1 & 0xffffffff:
        raise ValueError('no guest-network record here (magic or size word differs)')
    link = dict(zip(LINK, struct.unpack_from(f'<{len(LINK)}Q', record, 16)))
    view = dict(zip(VIEW, struct.unpack_from(f'<{len(VIEW)}Q', record, 16 + 8 * len(LINK))))
    if any(link[f'reserved{n}'] for n in range(5)):
        raise ValueError('guest-network reserved words are not zero')
    for n in range(5):
        del link[f'reserved{n}']
    last = struct.unpack('<q', struct.pack('<Q', link['last_refusal']))[0]
    link['last_refusal'] = REFUSALS.get(last, last) if last else None
    link['ring_pa'] = f'{link["ring_pa"]:#x}'
    for k in ('magic', 'tx_base', 'rx_base'):
        view[k] = f'{view[k]:#x}'
    return dict(enabled=bool(bits & 1), link=link, view=view)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--report', type=Path, required=True)
    args, rest = ap.parse_known_args()
    if any(not r.startswith('-D') for r in rest):
        ap.error(f'unrecognized arguments: {" ".join(r for r in rest if not r.startswith("-D"))}')
    if DEFINE not in rest:
        ap.error(f'this monitor build has no guest-network record ({DEFINE} absent)')
    at = offset(rest)
    report = args.report.read_bytes()
    print(json.dumps(decode(report[at:at + 16 + 8 * (len(LINK) + len(VIEW))]), indent=1))


if __name__ == '__main__':
    main()
