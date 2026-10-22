#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Staged verdict for a linked-AuxKC run, from its stopped-state JSON only.

    tools/auxkc-verdict.py --prefix auxkc-hello-600s-20260925

Reads build/PREFIX-audit.json (audit-secondary-runtime.py --auxkc) and
build/PREFIX-kernel-waits.json (capture-kernel-waits.py --auxkc --ioreg).
Each stage needs the one before it; the first unmet stage is the answer:

  placed    the audit found our bytes at the loader's PA and the handoff words
  slid      arm_auxkc_init ran kernel_collection_slide over it (fixups_raw 0)
  accepted  the kernel registered the header and its UUID (uuid_valid)
  activated kernelmanagerd sent loadfilesetkc (daemon_ready)
  started   an AuxKC instance is in the registry and/or the kext's own log
            line is in the message buffer

Exit 0 only when every stage is met. Known refusal lines from OSKext are
listed whatever the stage, since they name the cause directly.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGES = ('placed', 'slid', 'accepted', 'activated', 'started')
MARKERS = {'org.snapintosh.driver.SnapHello': 'SnapHello: AuxKC kext started'}
# OSKext refusal text, each checked against `strings` of the pinned 26A428
# kernel (kernel.release.t8140); "marked as NOT loadable" is the runtime
# expansion of "KextLog: AuxKC bundle %s marked as %s".
REFUSALS = ('is not loadable', 'in exclude list', 'did not find UUID in deferred Aux KC',
            "PRELINK_INFO wasn't an OSDictionary", 'UUID from key', 'marked as NOT loadable',
            'Kext loading is disabled', 'start failed', 'failed to load', 'failed to start',
            'Failed to load executable')


def verdict(audit, waits):
    linked = audit.get('linked_auxkc')
    if not linked:
        raise ValueError('the audit has no linked_auxkc block (run it with --auxkc)')
    resident = linked['resident']
    state = waits.get('auxkc_state') or {}
    capture = waits.get('linked_auxkc') or {}
    text = (waits.get('kernel_messages') or {}).get('text', '')
    lines = text.splitlines()
    bundles = capture.get('bundles', [])
    markers = {b: MARKERS[b] for b in bundles if b in MARKERS}
    logged = {b: any(m in line for line in lines) for b, m in markers.items()}
    registry = capture.get('registry_entries') or []
    facts = dict(
        placed=resident['executable_bytes_verified'] > 0,
        slid=resident['state'] == 'slid' and resident['fixups_raw'] == 0,
        accepted=bool(state.get('uuid_valid')) and state.get('handoff', {}).get('base') == capture.get('base'),
        activated=bool(state.get('daemon_ready')),
        started=bool(registry) or (bool(logged) and all(logged.values())),
    )
    reached = None
    for stage in STAGES:
        if not facts[stage]:
            break
        reached = stage
    missing = STAGES[STAGES.index(reached) + 1] if reached != STAGES[-1] else None
    return dict(
        reached=reached, first_unmet=missing, stages=facts,
        resident=dict((k, resident.get(k)) for k in (
            'state', 'fixups_applied', 'fixups_raw', 'structors_resigned', 'fixups_rewritten',
            'executable_bytes_verified', 'base', 'header_pa')),
        monitor_counters=linked.get('monitor_counters'),
        uuid_valid=state.get('uuid_valid'), daemon_ready=state.get('daemon_ready'),
        load_enabled=state.get('load_enabled'),
        registry_entries=[dict((k, r.get(k)) for k in ('class_name', 'name', 'vtable', 'state', 'registered'))
                          for r in registry][:8],
        logged=logged,
        refusals=[line for line in lines if any(r in line for r in REFUSALS)][-16:],
        auxkc_lines=capture.get('kernel_messages', [])[-16:],
        boundary=('Stopped-state reads only. "started" is registry or message-buffer evidence of '
                  'start(); it does not qualify GPU or display function.'),
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--prefix', required=True)
    args = ap.parse_args()
    base = ROOT / 'build' / args.prefix
    audit = json.loads(Path(f'{base}-audit.json').read_text())
    waits = json.loads(Path(f'{base}-kernel-waits.json').read_text())
    result = verdict(audit, waits)
    print(json.dumps(result, indent=2))
    return 0 if result['reached'] == STAGES[-1] else 1


if __name__ == '__main__':
    sys.exit(main())
