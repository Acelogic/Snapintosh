#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Staged verdict for a full-install M2 run (virtual ANS2), from stopped-state JSON only.

    tools/ans-verdict.py --prefix ans-m2-300s-20260925

Reads build/PREFIX-launch.json, build/PREFIX-ans.json (run.py's read of the
monitor's ANS2 state after the stop), build/PREFIX-audit.json (its `ans`
block) and build/PREFIX-kernel-waits.json (--ioreg). Each stage needs the one
before it; the first unmet stage is the answer (docs/ANS2-M2-20260925.md,
RUNBOOK.md):

  reached    the driver touched the virtual ANS2 at all (MMIO or SPTM table 6)
  rtbuddy    RTBuddy(ANS2) completed: HELLO and EPMAP, IOP running (STARTEP is not
             required: ans-m2-fw-300s-20260925 reached the NVMe controller without one,
             RTBuddy's wake path never sent it; it stays in diagnostics)
  nvme       the controller came ready (CC.EN, CSTS.RDY) and Identify answered;
             AppleANS3CGv2Controller has a child in the registry
  storage    the namespace's block device (IOEmbeddedNVMeBlockDevice "NS_01" on
             26A428, as ans-m2-queues-300s-20260925 registered it; the older
             IONVMeBlockStorageDevice/IOBlockStorageDevice names also count) and reads
  gpt        IOGUIDPartitionScheme enumerated the test partition by its GPT name
  apfs       an AppleAPFSContainerScheme/AppleAPFSContainer probed that partition

`clean` is separate and required for a pass: zero model refusals, no
EV_ANS stop, the watchdog exit (9) at the full budget. Exit 0 only when every
stage is met and the run is clean.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGES = ('reached', 'rtbuddy', 'nvme', 'storage', 'gpt', 'apfs')
# The block device AppleANS3CGv2Controller registers for a namespace. 26A428 uses
# IOEmbeddedNVMeBlockDevice (ans-m2-queues-300s-20260925: "NS_01", under it the disk's IOMedia).
BLOCK_DEVICES = ('IOEmbeddedNVMeBlockDevice', 'IONVMeBlockStorageDevice', 'IOBlockStorageDevice')
PARTITION = 'Snapintosh ANS2 test'   # probes/ansdisk.py NAME
MODEL = 'Snapintosh virtual ANS2'    # compat/ans.c Identify model number
# The auxkc-hello-600s-20260925 registry: the RAM-disk path's own storage
# objects. M2 must add to these, never replace them.
BASELINE = {'IOGUIDPartitionScheme': 1, 'AppleAPFSContainerScheme': 2, 'AppleAPFSContainer': 2}


def classes(waits):
    io = waits.get('ioreg_state') or {}
    entries = io.get('entries') or []
    count = {}
    for entry in entries:
        count[entry.get('class_name')] = count.get(entry.get('class_name'), 0) + 1
    return io, entries, count


def verdict(launch, ans, audit, waits):
    state = ans['state']
    c = state['counters']
    io, entries, count = classes(waits)
    names = {entry.get('name') for entry in entries}
    controller = [e for e in entries if e.get('class_name') == 'AppleANS3CGv2Controller']
    text = (waits.get('kernel_messages') or {}).get('text', '')
    facts = dict(
        reached=c['mmio'] > 0 or c['sptm6'] > 0,
        rtbuddy=(state['iop'] == 'running' and state['epmap_acked'] and
                 c['msg_in'] > 0 and c['msg_out'] > 0),
        nvme=(state['cc'] & 1 and state['csts'] & 1 and c['admin'] > 0 and
              any(e.get('children') for e in controller)),
        storage=any(count.get(k, 0) > 0 for k in BLOCK_DEVICES) and c['reads'] > 0,
        gpt=count.get('IOGUIDPartitionScheme', 0) > BASELINE['IOGUIDPartitionScheme'] and
            PARTITION in names,
        apfs=count.get('AppleAPFSContainerScheme', 0) > BASELINE['AppleAPFSContainerScheme'] or
             count.get('AppleAPFSContainer', 0) > BASELINE['AppleAPFSContainer'] or
             'SnapM2' in names,
    )
    reached = None
    for stage in STAGES:
        if not facts[stage]:
            break
        reached = stage
    audited = (audit.get('ans') or [{}])[0].get('state') if audit else None
    firmware = (audit.get('ans') or [{}])[0].get('firmware_state_published') if audit else None
    clean = dict(refusals=c['refusals'] == 0 and state['refusal']['reason'] == 'ok',
                 audit_agrees=audited is None or audited == state,
                 exit_code=launch.get('exit_code') == 9,
                 registry_complete=bool(io.get('complete')))
    return dict(reached=reached, facts=facts, clean=clean,
                counters=c, refusal=state['refusal'], iop=state['iop'],
                # Not stages: what the firmware-state rerun needs to tell its branches
                # apart (docs/ANS2-FIRMWARE-STATE-RUNBOOK-20260925.md).
                diagnostics=dict(firmware_state_published=firmware,
                                 endpoint_published='ANS2Endpoint1' in names,
                                 iop_power=state.get('iop_power'), ap_power=state.get('ap_power'),
                                 startep=c['startep'],
                                 # The I/O queue rerun (docs/ANS2-QUEUES-RUNBOOK-20260925.md):
                                 # both admin Creates completed, what was answered Invalid
                                 # Opcode, and the last error status. Absent from older states.
                                 **({} if 'io_queue' not in state else dict(
                                     io_queue=state['io_queue'],
                                     invalid_opcodes=state['invalid_opcodes'],
                                     last_status=state['last_status']))),
                registry={k: count.get(k, 0) for k in (
                    'RTBuddy', 'AppleANS3CGv2Controller', *BLOCK_DEVICES,
                    'IOBlockStorageDriver', 'IOMedia', 'IOGUIDPartitionScheme',
                    'AppleAPFSContainerScheme', 'AppleAPFSContainer', 'AppleAPFSVolume')},
                log_lines=[line for line in text.splitlines()
                           if MODEL in line or 'ANS2' in line or 'nvme:' in line][:40])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--prefix', required=True)
    args = ap.parse_args()
    def load(suffix, required=True):
        path = ROOT / 'build' / f'{args.prefix}-{suffix}.json'
        if not path.exists() and not required:
            return None
        return json.loads(path.read_text())
    result = verdict(load('launch'), load('ans'), load('audit', False), load('kernel-waits', False) or {})
    print(json.dumps(result, indent=2))
    passed = result['reached'] == STAGES[-1] and all(result['clean'].values())
    print('PASS' if passed else f"NOT MET: reached {result['reached']}, "
          f"first unmet {next((s for s in STAGES if not result['facts'][s]), 'none')}, "
          f"clean {result['clean']}")
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
