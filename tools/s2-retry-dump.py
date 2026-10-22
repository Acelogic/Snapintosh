#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the SNAP_S2_FAULT_RETRY state (compat/s2-fault-retry.h) from a monitor work-area dump.

    python3 tools/s2-retry-dump.py RUN_DIR [--work work-dump/work.bin] [--base 0x...] [--source TREE] [--json OUT]

Offline, read only. RUN_DIR is a build/installed-fresh-* directory with qualification.json (its flags,
which must include -DSNAP_S2_FAULT_RETRY=1, give the layout) and work-dump/work.{bin,json} (the whole
monitor work area; the context sits at its first byte). context.s2_retry is found through clang's
record layout of probes/xnuboot.c under the run's own defines (tools/hw-walk-dump.py layouts), so
--source must be the tree the run was built from.

Prints, and with --json writes: the counters (faults seen, retried, stopped, and the retried split
into MAPPED: the hardware's IPA, from HPFAR, is mapped guest RAM; and STAGE1: it is not, but the
stage-1 re-walk's IPA is), each vCPU's bounds state, and every ring entry oldest first. An entry
says which IPA the hardware named (HPFAR) and which the tables name now (AT S1E1R), whether they
are the same page, whether VTTBR/VTCR/HCR.VM were this vCPU's, and both stage-2 walks' descriptors.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFINE = '-DSNAP_S2_FAULT_RETRY=1'
KINDS = {0: 'none', 1: 'MAPPED', 2: 'STAGE1'}
VERDICTS = {0: 'resumed', 1: 'stopped: VTTBR/VTCR/HCR.VM not this vCPU\'s', 2: 'stopped: neither IPA is mapped RAM',
            3: 'stopped: the same access again', 4: 'stopped: over the rate bound',
            5: 'stopped: STAGE1 (SNAP_S2_FAULT_RETRY_STAGE1 off)'}
VTCR_FIELDS = 0xfffff


def _dump_module():
    spec = importlib.util.spec_from_file_location('hw_walk_dump', ROOT / 'tools/hw-walk-dump.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def decode(run, work=None, base=None, source=ROOT, defines=None):
    dump = _dump_module()
    run = Path(run)
    if defines is None:
        qual = json.loads((run / 'qualification.json').read_text())
        defines = [f for f in qual['flags'] if f.startswith('-D')]
    if DEFINE not in defines:
        raise SystemExit('this run was not built with SNAP_S2_FAULT_RETRY=1')
    work = Path(work) if work else run / 'work-dump/work.bin'
    meta = json.loads((work.parent / 'work.json').read_text()) if (work.parent / 'work.json').exists() else {}
    base = base if base is not None else int(meta['work'], 16)
    mem = dump.Memory(work.read_bytes(), base)
    lay = dump.layouts(defines, Path(source))
    state = mem.u(base + lay['context']['fields']['s2_retry'][0])
    sf = lay['s2_retry_state']['fields']
    cf, ef = lay['s2_retry_cpu']['fields'], lay['s2_retry_entry']['fields']
    csize, esize = lay['s2_retry_cpu']['size'], lay['s2_retry_entry']['size']
    ncpu = int(sf['cpu'][1].split('[')[1].rstrip(']'))
    nring = int(sf['ring'][1].split('[')[1].rstrip(']'))
    counters = {k: mem.u(state + sf[k][0]) for k in ('next', 'faults', 'resumed', 'stopped', 'mapped', 'stage1')}
    cpus = [{k: mem.u(state + sf['cpu'][0] + i * csize + cf[k][0]) for k in cf} for i in range(ncpu)]
    entries = []
    for i in range(nring):
        at = state + sf['ring'][0] + i * esize
        e = {}
        for name, (off, typ) in ef.items():
            if '[' in typ:
                count = int(typ.split('[')[1].rstrip(']'))
                e[name] = [mem.u(at + off + 8 * n) for n in range(count)]
            else:
                e[name] = mem.u(at + off)
        if not e['seq']:
            continue
        info = e['info']
        e.update(slot=info & 0xff, level=(info >> 8) & 0xff, kind=KINDS.get((info >> 16) & 0xff, '?'),
                 verdict=VERDICTS.get((info >> 24) & 0xff, '?'),
                 same_page=(e['ipa_hw'] >> 12) == (e['ipa_at'] >> 12) if e['ipa_at'] else None,
                 vttbr_ok=e['vttbr'] == e['vttbr_expected'],
                 vtcr_ok=(e['vtcr'] & VTCR_FIELDS) == (e['vtcr_expected'] & VTCR_FIELDS),
                 vm=bool(e['hcr'] & 1), s1ptw=bool((e['esr'] >> 7) & 1))
        entries.append(e)
    entries.sort(key=lambda e: e['seq'])
    return dict(run=str(run), state=hex(state), counters=counters, cpus=cpus, entries=entries)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('run')
    ap.add_argument('--work')
    ap.add_argument('--base', type=lambda s: int(s, 0))
    ap.add_argument('--source', type=Path, default=ROOT, help='Snapintosh tree the run was built from')
    ap.add_argument('--json')
    a = ap.parse_args()
    out = decode(a.run, a.work, a.base, a.source)
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=1) + '\n')
    c = out['counters']
    print(f"s2_retry {out['state']}: {c['faults']} stage-2 translation faults at the stop, {c['resumed']} retried "
          f"({c['mapped']} MAPPED, {c['stage1']} STAGE1), {c['stopped']} stopped")
    for i, cpu in enumerate(out['cpus']):
        if cpu['resumed'] or cpu['stopped']:
            print(f"  vCPU {i}: {cpu['resumed']} retried, {cpu['stopped']} stopped; last pc {cpu['last_pc']:#x} "
                  f"far {cpu['last_far']:#x} x{cpu['repeats']}")
    for e in out['entries']:
        regs = 'registers ok' if e['vttbr_ok'] and e['vtcr_ok'] and e['vm'] else (
            f"VTTBR {e['vttbr']:#x} (want {e['vttbr_expected']:#x}) VTCR {e['vtcr']:#x} "
            f"(want {e['vtcr_expected']:#x}) HCR {e['hcr']:#x}")
        print(f"#{e['seq']} vCPU {e['slot']} mpidr {e['mpidr']:#x} t={e['counter']:#x}: {e['verdict']}, {e['kind']}; "
              f"level {e['level']}{' S1PTW' if e['s1ptw'] else ''}; ESR {e['esr']:#x} FAR {e['far']:#x} "
              f"pc {e['elr']:#x} SPSR {e['spsr']:#x}")
        print(f"    HPFAR {e['hpfar']:#x}: IPA {e['ipa_hw']:#x} walk {' '.join(f'{d:#x}' for d in e['d_hw'])}")
        print(f"    re-walk IPA {e['ipa_at']:#x} walk {' '.join(f'{d:#x}' for d in e['d_at'])}; "
              f"{'same page' if e['same_page'] else 'a DIFFERENT page' if e['same_page'] is not None else 'no re-walk'}")
        print(f"    {regs}; TTBR0 {e['ttbr0']:#x} TCR {e['tcr']:#x}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
