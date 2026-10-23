#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify the monitor performance defines offline and write one artifact.

    python3 tools/test-monitor-perf.py --output DIR [--seed BUILD_JSON]

No hardware and no proxy. Runs, from fresh output paths:
  1. the new native suites (sanitized; thread-sanitized fast traps; the
     verified index) and each regression's pre-change model, which must FAIL;
  2. the canonical-view differential over every existing suite that proves a
     canonical or fixed user view (each proof runs reference and fast walks);
  3. the source cross-check and counter-decoder tests;
  4. host timings of the replaced work (bitmap vs index flush, reference vs
     fast canonical proof) at the installed runs' scale;
  5. the aarch64 monitor with the deployed defines, OFF and with each new
     define, checking -Werror compiles and the code budget.
DIR/result.json binds every source, binary and result by SHA-256.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
# build/active-root-policy-20260926/monitor-v2/build.json build_defines, the set
# every installed run since has used (monitor 84922c94... at pipeline 2cdbae5).
DEPLOYED = ['--target=aarch64-unknown-none-elf', '-ffreestanding', '-fno-pic',
    '-mgeneral-regs-only', '-Os', '-Wall', '-Wextra', '-Werror', '-fno-stack-protector',
    '-mcmodel=tiny', '-flto', '-DSNAP_SERVICE_PROFILE=1', '-DSNAP_STEP_TRANSLATION_VERIFY=1',
    '-DSNAP_STEP_ALU=0', '-DSNAP_NATIVE_CALLS=1', '-DSNAP_USER_VIEW_BATCH=1',
    '-DSNAP_USER_VIEW_CACHE=1', '-DSNAP_USER_VIEW_VERIFY=1', '-DSNAP_USER_ONLY_TLBI=1',
    '-DSNAP_SERVICE_DETAIL=1', '-DSNAP_KERNEL_DIRTY_PUBLISH=1', '-DSNAP_KERNEL_VIEW_REUSE=1',
    '-DSNAP_USER_VIEW_FUSED=1', '-DSNAP_KERNEL_CLASS_PROOF=1', '-DSNAP_USER_PREPARE_FUSED=1',
    '-DSNAP_PRIVATE_VIEW_EPOCH=1', '-DSNAP_ROOT_DIRTY_PUBLISH=1', '-DSNAP_USER_DIRTY_PUBLISH=1',
    '-DSNAP_USER_TABLE_READ=1', '-DSNAP_VIEW_TABLE_READ=1', '-DSNAP_USER_ZERO_GROUP=1',
    '-DSNAP_NATIVE_WRITER_ADMISSION=1', '-DSNAP_NATIVE_WRITER_BREAKPOINTS=1',
    '-DSNAP_VIEW_STORE_COMPARE=1', '-DSNAP_USER_FUSED_COMPARE=1', '-DSNAP_USER_MODE_SKIP=1',
    '-DSNAP_GUEST_BRK_REFLECT=1', '-DSNAP_USER_TREE_MEMO=1', '-DSNAP_TXN_DIRTY_PUBLISH=1',
    '-DSNAP_KERNEL_PPERM_REUSE=1', '-DSNAP_USER_UPDATE_KERNEL_SKIP=1',
    '-DSNAP_INSTALL_TLBI_DEFER=1', '-DSNAP_CLASS_PROOF_MAPPED=1', '-DSNAP_ROOT_VALIDATE_WORDS=1',
    '-DSNAP_ROOT_PUBLISH_BATCH_DSB=1', '-DSNAP_USER_CRASH_RING=1', '-DSNAP_CLASS_LEAF_MEMO=0']
BOUNDARY = ['-DSNAP_FAST_VCPU_TRAPS=1', '-DSNAP_VECTOR_BRANCH=1', '-DSNAP_ERET_SNAPSHOT=1',
            '-DSNAP_FAST_CROSSINGS=1', '-DSNAP_NATIVE_WFE=1', '-DSNAP_FAST_TIMER_WRITE=1',
            '-DSNAP_FAST_IDLE_POLL=1']
# build-fast-traps-monitor.py's native-tables set and fast set, as the speed
# test's fast variant builds them.
RECIPE = {t.id: ast.literal_eval(n.value) for n in ast.parse((ROOT / 'tools/build-fast-traps-monitor.py')
          .read_text()).body if isinstance(n, ast.Assign) for t in n.targets
          if isinstance(t, ast.Name) and t.id in ('ADDED', 'FAST')}
CONFIGS = {
    'off': [],
    'fast-traps': ['-DSNAP_FAST_VCPU_TRAPS=1'],
    'census': ['-DSNAP_SYSREG_CENSUS=1'],
    'incremental-publish': ['-DSNAP_INCREMENTAL_PUBLISH=1'],
    'incremental-publish-verify': ['-DSNAP_INCREMENTAL_PUBLISH=1', '-DSNAP_INCREMENTAL_PUBLISH_VERIFY=1'],
    'canonical-view': ['-DSNAP_CANONICAL_VIEW_FAST=1'],
    'vector-branch': ['-DSNAP_VECTOR_BRANCH=1'],
    'eret-snapshot': ['-DSNAP_ERET_SNAPSHOT=1'],
    'fast-crossings': ['-DSNAP_FAST_VCPU_TRAPS=1', '-DSNAP_VECTOR_BRANCH=1', '-DSNAP_FAST_CROSSINGS=1'],
    'native-wfe': ['-DSNAP_NATIVE_WFE=1'],
    'timer-write': ['-DSNAP_FAST_VCPU_TRAPS=1', '-DSNAP_FAST_TIMER_WRITE=1'],
    'idle-poll': ['-DSNAP_FAST_VCPU_TRAPS=1', '-DSNAP_FAST_IDLE_POLL=1'],
    'boundary': BOUNDARY,
    'all': ['-DSNAP_FAST_VCPU_TRAPS=1', '-DSNAP_SYSREG_CENSUS=1', '-DSNAP_INCREMENTAL_PUBLISH=1',
            '-DSNAP_CANONICAL_VIEW_FAST=1', *BOUNDARY[1:]],
    'native-tables': RECIPE['ADDED'],
    'pperm-variants': [*RECIPE['ADDED'], '-DSNAP_KERNEL_PPERM_VARIANTS=1'],
    'fast-recipe': [*RECIPE['ADDED'], *RECIPE['FAST'], '-DSNAP_SYSREG_CENSUS=1'],
}
OWNED = ['compat/fast-trap.h', 'compat/perf-state.h', 'compat/service-lock.h',
         'compat/sptm-root.c', 'compat/sptm-root.h', 'shadow/root-publish-index.h',
         'compat/fast-vector.h', 'compat/native-writer.h', 'compat/native-writer-debug.h',
         'compat/clock.c', 'compat/clock.h',
         'probes/xnuboot.c', 'tools/test-fast-trap.c', 'tools/test-fast-trap.py',
         'tools/test-fast-vector.c', 'tools/test-fast-vector.py',
         'tools/test-native-writer-debug.c', 'tools/test-clock.c', 'tools/build-fast-traps-monitor.py',
         'tools/test-root-publish-index.c', 'tools/test-canonical-view-fast.c',
         'tools/canonical-view-differential.c', 'tools/perf_counters.py',
         'tools/test-perf-counters.py', 'tools/test-monitor-perf.py',
         'compat/fast-mmio.h', 'tools/test-fast-mmio.c',
         'shadow/sprr-variants.h', 'tools/test-kernel-pperm-variants.c',
         'tools/test-speed-test-console.py', 'tools/cycle_lib/speed_test.py', 'tools/monitor_layout.py',
         'compat/device.c', 'compat/device.h', 'tools/test-pmgr-ioreport.c', 'tools/pmgr-ioreport-accesses.h']
OWNED += [str(p.relative_to(ROOT)) for o in OWNED if o.endswith('.c') for p in source_files(ROOT / o)[1:]]
SAN = ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']
BASE = ['cc', '-std=gnu11', '-g', '-Wall', '-Wextra', '-Icompat', '-Ishadow']
SPTM = ['compat/sptm-root.c', 'compat/sptm-user.c', 'compat/sptm.c', 'compat/sptm-refs.c',
        'shadow/shadow.c', 'shadow/mmu.c']
FAST = ['tools/test-fast-trap.c', 'compat/pauth.c', 'compat/pauth-user.c', 'compat/clock.c',
        'compat/service-lock.c']
VECTOR = ['tools/test-fast-vector.c', 'compat/exception.c', 'compat/service-lock.c']
MMIO = ['tools/test-fast-mmio.c', 'compat/device.c', 'compat/mmio.c', 'compat/sep-bootstrap.c',
        'compat/sep-pnon.c', 'compat/aes.c', 'compat/aic.c', 'compat/dart.c',
        'compat/sep-sks-endpoint.c', 'compat/sep-xars.c', 'compat/watchdog.c']
VARIANTS = ['tools/test-kernel-pperm-variants.c', 'shadow/sprr-view.c', 'shadow/shadow.c', 'shadow/mmu.c']
IOREPORT = ['tools/test-pmgr-ioreport.c', 'compat/device.c', 'compat/mmio.c', 'compat/sep-bootstrap.c',
            'compat/sep-pnon.c', 'compat/aes.c', 'compat/aic.c', 'compat/dart.c',
            'compat/sep-sks-endpoint.c', 'compat/sep-xars.c', 'compat/watchdog.c', 'compat/clock.c']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--seed', type=Path, help='optional build.json whose build_defines must equal DEPLOYED')
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    bins = out / 'bin'
    bins.mkdir()
    result = dict(status='FAIL', sources={n: sha(ROOT / n) for n in OWNED}, native={},
                  pre_change={}, differential={}, python={}, bench={}, monitor={})
    if args.seed:
        assert json.loads(args.seed.read_text())['build_defines'] == DEPLOYED

    def build(name, flags, sources):
        binary = bins / name
        subprocess.run([*BASE, *flags, *sources, '-o', str(binary)], cwd=ROOT, check=True,
                       timeout=600)
        return binary

    def execute(binary, *argv, env=None):
        r = subprocess.run([str(binary), *argv], cwd=ROOT, capture_output=True, text=True,
                           timeout=1800, env=env)
        return r.returncode, (r.stdout + r.stderr).strip().splitlines()

    tsan = dict(os.environ, TSAN_OPTIONS='halt_on_error=1:exitcode=66')
    native = {
        'fast-trap': (['-O1', *SAN], FAST, None),
        'fast-trap-tsan': (['-O1', '-fsanitize=thread', '-pthread', '-DFAST_TRAP_THREADS=1'], FAST, tsan),
        'root-publish-index': (['-O2', *SAN], ['tools/test-root-publish-index.c'], None),
        'root-publish-index-verify': (['-O2', *SAN, '-DSNAP_INCREMENTAL_PUBLISH_VERIFY=1'],
                                      ['tools/test-root-publish-index.c'], None),
        'canonical-view-fast': (['-O1', *SAN], ['tools/test-canonical-view-fast.c', *SPTM], None),
        'fast-vector': (['-O1', *SAN], VECTOR, None),
        'fast-vector-tsan': (['-O1', '-fsanitize=thread', '-pthread', '-DFAST_VECTOR_THREADS=1'],
                             VECTOR, tsan),
        'native-writer-debug': (['-O1', *SAN], ['tools/test-native-writer-debug.c'], None),
        'clock': (['-O1', *SAN], ['tools/test-clock.c', 'compat/clock.c'], None),
        'fast-mmio': (['-O1', *SAN], MMIO, None),
        'kernel-pperm-variants': (['-O1', *SAN], VARIANTS, None),
        'pmgr-ioreport': (['-O1', *SAN, '-Itools'], IOREPORT, None),
    }
    for name, (flags, sources, env) in native.items():
        code, lines = execute(build(name, flags, sources), env=env)
        result['native'][name] = dict(exit=code, summary=[l for l in lines if 'PASS' in l or ':' in l][-3:])
    pre = {
        'fast-trap': (['-O1', *SAN, '-DFAST_TRAP_PRE_CHANGE=1'], FAST, 'e.acquisitions<=5'),
        'root-publish-index': (['-O2', *SAN, '-DINDEX_PRE_CHANGE=1'],
                               ['tools/test-root-publish-index.c'], 'B.calls==RUNTIME_PAGES+4'),
        'canonical-view-fast': (['-O1', *SAN, '-DCANONICAL_PRE_CHANGE=1'],
                                ['tools/test-canonical-view-fast.c', *SPTM], 'source_reads<=bound'),
        'fast-vector': (['-O1', *SAN, '-DFAST_VECTOR_PRE_CHANGE=1'], VECTOR,
                        'e.acquisitions<=FAST_CROSS_CLASSES'),
        'kernel-pperm-variants': (['-O1', *SAN, '-DVARIANTS_PRE_CHANGE=1'], VARIANTS,
                                  'same_tree(ref.ttbr1[cpu],cand.ttbr1[cpu],0)'),
    }
    for name, (flags, sources, expected) in pre.items():
        code, lines = execute(build(name + '-pre-change', flags, sources))
        result['pre_change'][name] = dict(exit=code, failed_as_expected=code != 0 and
                                          any(expected in l for l in lines), lines=lines[-2:])
    suites = ['test-sptm-root', 'test-user-tpro', 'test-shared-page', 'test-shared-region',
              'test-user-update', 'test-user-was-writable']
    for suite in suites:
        obj = bins / (suite + '-cv.o')
        subprocess.run([*BASE, '-w', '-O1', *SAN, '-c', f'tools/{suite}.c',
                        '-Dsptm_root_canonical_view=cv_differential_canonical',
                        '-Dsptm_root_fixed_view=cv_differential_fixed', '-o', str(obj)],
                       cwd=ROOT, check=True, timeout=600)
        binary = build(suite + '-cv', ['-w', '-O1', *SAN],
                       [str(obj), 'tools/canonical-view-differential.c', *SPTM, 'shadow/sprr-view.c',
                        'compat/txm.c', 'compat/txm-copy.c', 'compat/aes.c'])
        code, lines = execute(binary)
        result['differential'][suite] = dict(exit=code, lines=lines[-2:])
    for script in ('tools/test-fast-trap.py', 'tools/test-perf-counters.py',
                   'tools/test-fast-vector.py', 'tools/test-speed-test-console.py'):
        r = subprocess.run([sys.executable, script], cwd=ROOT, capture_output=True, text=True,
                           timeout=1800)
        result['python'][script] = dict(exit=r.returncode, tail=r.stderr.strip().splitlines()[-1:])
    for name, sources in (('root-publish-index', ['tools/test-root-publish-index.c']),
                          ('canonical-view-fast', ['tools/test-canonical-view-fast.c', *SPTM])):
        binary = build(name + '-bench', ['-O2'], sources)
        runs = [json.loads(execute(binary, '--bench')[1][-1]) for _ in range(3)]
        result['bench'][name] = runs
    sys.path.insert(0, str(ROOT / 'probes'))
    sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
    import run  # noqa: E402  (import only: build() needs no hardware)
    budget = run.OUT_AT - run.CODE_AT
    for name, extra in CONFIGS.items():
        run.FLAGS = DEPLOYED + extra
        blob = run.build('xnuboot', out / 'monitor' / name)
        result['monitor'][name] = dict(defines=extra, bytes=len(blob), headroom=budget - len(blob),
                                       sha256=hashlib.sha256(blob).hexdigest())
    ok = (all(v['exit'] == 0 for v in result['native'].values()) and
          all(v['failed_as_expected'] for v in result['pre_change'].values()) and
          all(v['exit'] == 0 and any('0 differences' in l for l in v['lines'])
              for v in result['differential'].values()) and
          all(v['exit'] == 0 for v in result['python'].values()) and
          all(v['headroom'] > 0 for v in result['monitor'].values()))
    result['status'] = 'PASS' if ok else 'FAIL'
    result['binaries'] = {p.name: sha(p) for p in sorted(bins.iterdir()) if p.is_file() and
                          os.access(p, os.X_OK)}
    (out / 'result.json').write_text(json.dumps(result, indent=1) + '\n')
    print(json.dumps(dict(status=result['status'], result=str(out / 'result.json'),
                          result_sha256=sha(out / 'result.json'))))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
