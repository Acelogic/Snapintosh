#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline fault replay of GPU teardown through its native/host handoff boundary.

Failure inventory: docs/A16-GPU-QUIESCE-REVIEW-20261018.md (written first).
Reuses the existing noncoherent arena/CP/SMMU model, runs production teardown,
then exercises the production witness with returned quarantine and lost replies.
No hardware access. Each invocation must use a new retained artifact directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from source_text import read_source, source_files

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'probes')]

C_REPLAY = r'''
#define main existing_adreno_model_main
#include "test-adreno.c"
#undef main
static int late_hijack;
static unsigned cb_reads;
static uint32_t replay_rd(void *ctx, uint64_t pa)
{
    if (pa == ADRENO_CB0 + ADRENO_CB_TTBR0 && ++cb_reads == 2 && late_hijack)
        r.tcr ^= 1;
    return m_rd(ctx, pa);
}
int main(void)
{
    dram=calloc(1,RAM_SIZE); cache=calloc(1,RAM_SIZE);
    if (!dram || !cache) return 2;
    const char *names[]={"success","halt_timeout","tlbi_timeout","root_hijack",
        "tcr_hijack","sctlr_bypass","late_hijack","gx_off","cx_off","gx_partial"};
    for (unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) {
        q1n1_cp_fence();
        if(adreno_adopt(&ops,&P,&S,MEM_LOW,MEM_HIGH)) return 3;
        memset(dart,0,sizeof(dart)); dart[0]=dart_desc(GUEST_PAGE,0,0x4000,0,0);
        if(mirror(0x40000000,0x4000)) return 4;
        (void)smmu_walk(0x40000000,1);
        if(i==1)r.halt_stuck=1;
        if(i==2)r.tlb_stuck=1;
        if(i==3)r.ttbr_lo^=0x1000;
        if(i==4)r.tcr^=1;
        if(i==5)r.sctlr&=~1u;
        if(i==7)r.pwr=3;
        if(i==8)r.cx=0;
        if(i==9)r.pwr=2;
        late_hijack=i==6;cb_reads=0;
        struct adreno_ops instrumented=ops;instrumented.rd=replay_rd;
        nlog=0; uint64_t start=clock_now;
        adreno_quiesce(&instrumented,&P,&S);
        unsigned writes=nlog;uint64_t status=S.status,q=S.quiesce;
        uint64_t root1=dev_rd64(ROOT+8);
        adreno_quiesce(&instrumented,&P,&S);
        unsigned retry_writes=nlog-writes;
        int fence=adreno_fence(&instrumented,&P,&S,0x1234);
        unsigned submit_writes=nlog-writes;
        printf("{\"case\":\"%s\",\"status\":%llu,\"quiesce\":%llu,"
               "\"root1\":%llu,\"writes\":%u,\"retry_writes\":%u,"
               "\"submit_writes\":%u,\"fence\":%d,\"ticks\":%llu}\n",
               names[i],(unsigned long long)status,(unsigned long long)q,
               (unsigned long long)root1,writes,retry_writes,submit_writes,fence,
               (unsigned long long)(clock_now-start));
    }
    free(dram);free(cache);return 0;
}
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True, type=Path)
    args = ap.parse_args()
    dest = args.out.resolve()
    dest.mkdir(parents=True, exist_ok=False)
    receipt = dict(schema='a16-gpu-quiesce-boundary-replay-v1', hardware_access=False,
                   failure_inventory='docs/A16-GPU-QUIESCE-REVIEW-20261018.md', checks=[])
    def check(name, passed, **evidence):
        receipt['checks'].append(dict(name=name, passed=bool(passed), **evidence))
    harness = dest / 'quiesce-model.c'
    harness.write_text(C_REPLAY)
    sources = ['tools/test-adreno.c', 'compat/adreno-submit.c', 'compat/adreno-resource.c',
               'compat/adreno.c', 'compat/irq-forward.c', 'shadow/stage2.c',
               'shadow/shadow.c', 'shadow/mmu.c']
    cmd = ['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
           '-Wall', '-Wextra', '-Werror', '-Icompat', '-Ishadow', '-Itools',
           str(harness), *sources[1:], '-o', str(dest / 'quiesce-model')]
    compiled = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    (dest / 'build.log').write_text(compiled.stdout + compiled.stderr)
    check('sanitized_model_build', compiled.returncode == 0, command=cmd)
    if compiled.returncode == 0:
        ran = subprocess.run([str(dest / 'quiesce-model')], cwd=ROOT, capture_output=True, text=True)
        (dest / 'model.log').write_text(ran.stdout + ran.stderr)
        check('sanitized_model_execution', ran.returncode == 0)
        rows = [json.loads(line) for line in ran.stdout.splitlines() if line.startswith('{')]
        receipt['gpu_cases'] = rows
        for row in rows:
            name = row['case']; good = name in ('success', 'gx_off')
            check(name + '_success_truth', bool(row['status'] & 16) == good, result=row)
            check(name + '_sticky_no_resubmit', row['retry_writes'] == row['submit_writes'] == 0
                  and row['fence'] != 0)
            check(name + '_bounded_poll', row['ticks'] <= 3000)
            if name == 'halt_timeout':
                check('halt_failure_no_unlink_or_halted_bit', not (row['quiesce'] & (8 | 32))
                      and row['root1'] != 0)
            if name == 'tlbi_timeout':
                check('tlbi_failure_attached_uncertain', row['status'] & 2 and not (row['quiesce'] & 32))
            if name in ('root_hijack', 'tcr_hijack', 'sctlr_bypass'):
                check(name + '_no_old_root_mutation', row['root1'] != 0)
    try:
        from cycle_lib.bootstrap_smoke import WitnessProxy
        class Link:
            def __init__(self): self.closed = False
            def close(self): self.closed = True
        class Fake:
            P_CALL = 0x30
            def __init__(self, result): self.result, self.link, self.io = result, Link(), []
            def readmem(self, pa, n): self.io.append('readmem'); return b'code'
            def call(self, *a, **kw):
                return self.request(self.P_CALL, *a, **kw)
            def request(self, opcode, *a, **kw):
                self.io.append('call')
                if isinstance(self.result, BaseException): raise self.result
                return self.result
            def serror_state(self): self.io.append('serror_state'); return {}
            def writemem(self, *a): self.io.append('writemem')
        for result in (0, 0x51554e01, 0x51554e02, 19, TimeoutError('lost native reply')):
            tag = str(result) if isinstance(result, int) else 'timeout'
            raw = Fake(result)
            record = dict(source_sha256={}, monitor_bytes=4, monitor_sha256=hashlib.sha256(b'code').hexdigest(),
                          calls=[], uploads=[])
            witness = WitnessProxy(raw, dest / ('native-' + tag + '.json'), record, 0x1000)
            error = None
            try: witness.call(0x1000, 1, 2, 3, 4, 0)
            except BaseException as exc: error = repr(exc)
            at = len(raw.io)
            if result != 0:
                for op in (lambda: witness.readmem(1, 1), lambda: witness.serror_state(),
                           lambda: witness.writemem(1, b'x'), lambda: witness.call(2)):
                    try: op()
                    except BaseException: pass
            witness.link.close()
            check('native_' + tag, (error is None and witness.main_returned) if result == 0 else
                  (error is not None and len(raw.io) == at and not witness.main_returned),
                  error=error, io=raw.io, record=record)
            check('native_' + tag + '_close', raw.link.closed)
            if isinstance(result, int) and result:
                check('native_' + tag + '_known_quarantine', not witness.unknown and
                      bool(getattr(witness, 'quarantined', False)) and record.get('native_terminal') == result)
    except BaseException as exc:
        check('host_boundary_replay_available', False, error=repr(exc))
    # These are integration ordering assertions, not substitutes for the replay.
    monitor = read_source(ROOT / 'probes/xnuboot.c')
    report = monitor[monitor.index('uint64_t xnuboot_report(uint64_t *out)\n{'):]
    check('monitor_gate_before_publication', 'if (!gpu_quiesce(c))' in report and
          report.index('if (!gpu_quiesce(c))') < report.index('publish(c->params->mem_low'))
    asm = (ROOT / 'probes/xnuboot.S').read_text().split('bl xnuboot_report', 1)[1].split('ret', 1)[0]
    check('assembly_preserves_terminal_status', 'mov x0, #0' not in asm)
    runner = (ROOT / 'probes/run.py').read_text()
    check('runner_gates_before_collection', 'require_xnuboot_terminal(result)' in runner and
          runner.index('require_xnuboot_terminal(result)') < runner.index("secondary_api['collect']"))
    for fn in ('bootstrap_smoke.py', 'speed_test.py', 'installed_fresh.py'):
        text = (ROOT / 'tools/cycle_lib' / fn).read_text()
        check(fn + '_quarantine_before_capture', 'witness.quarantined' in text and
              text.index('witness.quarantined') < text.index('witness.main_returned', text.index('finally:')))
    bound = sources + ['compat/adreno.h', 'compat/adreno-fill.c', 'compat/adreno-ib.c',
                      *[str(p.relative_to(ROOT)) for p in source_files(ROOT / 'probes/xnuboot.c')],
                      'probes/xnuboot.S', 'probes/run.py',
                      'probes/xnuboot-terminal.h', 'probes/xnuboot_terminal.py',
                      'tools/cycle_lib/bootstrap_smoke.py', 'tools/cycle_lib/speed_test.py',
                      'tools/cycle_lib/installed_fresh.py', 'tools/a16-control-guard.py',
                      'tools/replay-a16-gpu-quiesce.py', 'docs/A16-GPU-QUIESCE-REVIEW-20261018.md']
    receipt['source_sha256'] = {name: sha(ROOT / name) for name in bound}
    receipt['passed'] = all(c['passed'] for c in receipt['checks'])
    receipt['artifact_sha256'] = {p.name: sha(p) for p in dest.iterdir() if p.is_file()}
    (dest / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    failed = [c['name'] for c in receipt['checks'] if not c['passed']]
    print(json.dumps(dict(passed=receipt['passed'], checks=len(receipt['checks']), failed=failed,
                         receipt=str(dest / 'receipt.json'))))
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
