#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Which Apple device windows can still end a run, before a run finds them.

Offline and read-only: no proxy, no hardware. It builds the selected guest
profile's device tree exactly as the loader does, then places every register
window of every /arm-io child against the virtual device registry:

  modeled   every byte of every window is answered by a virtual model
  partial   some window bytes have no model: a touch there is an EV_S2_FAULT
  absent    no model at all; any MMIO access stops the run with its IPA
  deferred  withdrawn by the profile; XNU never sees the node
  console   the monitor's own DockChannel console windows (not a model)

A model answering a window is not a claim that every register in it is
implemented; a model still refuses what it does not implement (exit 7).

With --capture, a stopped-state kernel-waits JSON (tools/capture-kernel-waits.py)
supplies the native IOService plane. A node whose nub has an attached driver
and an unmodeled window is a LATENT stop: the driver exists, and its first
register access ends the run. That list is where the next "absent IPA" stops
come from, and each entry is either a model to write or a node to defer.

    tools/audit-device-exposure.py --profile j700ap-26A428-bootfb-xars-uniform \\
        --capture build/<prefix>-kernel-waits.json [--json out.json]
"""
import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import devicemodel                                                  # noqa: E402
import xnuboot as xb                                                # noqa: E402

BUS = '/device-tree/arm-io'
# Loader constants that share the V1 suffix but are configuration values.
NOT_KINDS = {'PMGR_CPU0_BOOT_V1', 'PMGR_AVE_CLUSTER_V1', 'MODEL_MAX', 'MODEL_WORDS'}


def kind_names():
    names = {}
    for name, value in vars(devicemodel).items():
        if (name.endswith(('_V1', '_V2')) and name not in NOT_KINDS and
                type(value) is int and 0 < value < 128 and value not in names):
            names[value] = name
    return names


def build(profile):
    xb.configure_guest(profile)
    xb.place(0x8c0000000, guest_span=8192 << 20)
    with contextlib.redirect_stdout(io.StringIO()):
        return xb.build_devicetree()


def uncovered(base, size, models):
    """Sub-ranges of [base, base+size) that no model window answers."""
    gaps, cursor, end = [], base, base + size
    for m in sorted(models, key=lambda m: m.base):
        if m.base + m.span <= cursor or m.base >= end:
            continue
        if m.base > cursor:
            gaps.append((cursor, m.base - cursor))
        cursor = max(cursor, m.base + m.span)
        if cursor >= end:
            break
    if cursor < end:
        gaps.append((cursor, end - cursor))
    return gaps


def drivers_from_capture(path):
    """Nub name -> attached driver classes, from a stopped IOService plane."""
    data = json.loads(Path(path).read_text())
    plane = data.get('ioreg_state') or {}
    entries = {e['address']: e for e in plane.get('entries', ())}
    children = {}
    for parent, child in plane.get('edges', ()):
        children.setdefault(parent, []).append(child)
    attached = {}
    for address, entry in entries.items():
        if entry.get('class_name') not in ('AppleARMIODevice', 'IOPlatformDevice'):
            continue
        name = entry.get('name')
        if not name:
            continue
        kids = [entries[c]['class_name'] for c in children.get(address, ())
                if c in entries and entries[c].get('class_name')]
        attached.setdefault(name, []).extend(kids)
    if not entries:
        raise ValueError(f'{path}: no ioreg_state entries; not a stopped-state capture')
    return attached


def audit(dt, attached=None):
    names = kind_names()
    models = tuple(dt.device_models)
    rows = []
    prefix = BUS + '/'
    for path, props in dt.nodes.items():
        if not path.startswith(prefix) or '/' in path[len(prefix):] or 'reg' not in props:
            continue
        name = path[len(prefix):]
        try:
            windows = xb.device_windows(dt, name, BUS)
        except SystemExit:
            continue                  # reg outside every arm-io range: not a bus window
        windows = [(pa, size) for pa, size in windows if size]
        if not windows:
            continue
        total = sum(size for _, size in windows)
        if name == xb.CONSOLE_NODE:
            # probes/xnuboot.c answers these through mmio_dispatch, before
            # the model registry; its own refusals are MMIO_STOP_* events.
            rows.append(dict(node=path, compatible='', state='console',
                             windows=[[hex(pa), hex(size)] for pa, size in windows],
                             unmodeled=[], models=[], latent_stop=False,
                             drivers=None if attached is None else attached.get(name, [])))
            continue
        gaps = [gap for pa, size in windows for gap in uncovered(pa, size, models)]
        missing = sum(size for _, size in gaps)
        owners = sorted({m.kind for m in models for pa, size in windows
                         if m.base < pa + size and pa < m.base + m.span})
        state = 'modeled' if not missing else 'absent' if missing == total else 'partial'
        compatible = bytes(props['compatible'].value).split(b'\0')[0].decode(
            errors='replace') if 'compatible' in props else ''
        drivers = None if attached is None else attached.get(name, [])
        rows.append(dict(
            node=path, compatible=compatible, state=state,
            windows=[[hex(pa), hex(size)] for pa, size in windows],
            unmodeled=[[hex(pa), hex(size)] for pa, size in gaps],
            models=[f'{kind} {names.get(kind, "?")}' for kind in owners],
            drivers=drivers,
            latent_stop=bool(drivers) and state != 'modeled'))
    rows.sort(key=lambda r: ({'absent': 0, 'partial': 1, 'modeled': 2, 'console': 3}[r['state']],
                             r['node']))
    deferred = sorted(dt.deferred_nodes)
    kinds = {}
    for m in models:
        kinds.setdefault(m.kind, []).append(m.node)
    registry = [dict(kind=kind, name=names.get(kind, '?'), instances=len(nodes),
                     nodes=sorted(set(nodes))) for kind, nodes in sorted(kinds.items())]
    return dict(profile=xb.GUEST_PROFILE.name, models=len(models), registry=registry,
                deferred=deferred, nodes=rows,
                latent_stops=[r['node'] for r in rows if r['latent_stop']])


def text(report):
    lines = [f"profile {report['profile']}: {report['models']} model descriptors, "
             f"{len(report['deferred'])} deferred nodes"]
    for r in report['nodes']:
        drv = '' if r['drivers'] is None else f" driver {','.join(r['drivers']) or '-'}"
        mark = '  LATENT STOP' if r['latent_stop'] else ''
        lines.append(f"  {r['state']:<8} {r['node'][len(BUS)+1:]:<28} {r['compatible'][:24]:<24}"
                     f"{drv}{mark}")
        if r['state'] == 'partial':
            lines.append(f"           unmodeled {r['unmodeled'][:4]}")
    lines.append('deferred: ' + ', '.join(n[len(BUS)+1:] if n.startswith(BUS) else n
                                          for n in report['deferred']))
    lines.append('latent stops: ' + (', '.join(report['latent_stops']) or 'none'))
    return '\n'.join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--profile', default='j700ap-26A428-bootfb-xars-uniform')
    ap.add_argument('--capture', help='stopped-state kernel-waits JSON with ioreg_state')
    ap.add_argument('--json', help='write the full report here')
    args = ap.parse_args(argv)
    attached = drivers_from_capture(args.capture) if args.capture else None
    report = audit(build(args.profile), attached)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=1) + '\n')
    print(text(report))
    return 0


if __name__ == '__main__':
    sys.exit(main())
