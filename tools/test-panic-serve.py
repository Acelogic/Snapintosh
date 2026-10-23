#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_PANIC_SERVE: after XNU's PANIC_ENTRY, ordinary monitor calls are served, not stopped.

    python3 tools/test-panic-serve.py [--build]

1. The gate in probes/xnuboot.c monitor_call_impl is extracted verbatim and compiled on the host
   against compat/panic-state.c, with SNAP_PANIC_SERVE 0 and 1: before a panic every call passes;
   after a valid panic entry the default stops on every non-entry call and the opt-in serves it
   (counted in panic_state.rejected); a corrupt panic state stops in both.
2. --build: the monitor's control, fast and fast+WFI default builds equal their -DSNAP_PANIC_SERVE=0
   builds and differ from =1.
"""
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
checks = 0


def expect(ok, what):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(what)


def gate():
    text = read_source(ROOT / 'probes/xnuboot.c')
    expect(text.count('#ifndef SNAP_PANIC_SERVE\n#define SNAP_PANIC_SERVE 0\n#endif') == 1, 'define block')
    m = re.search(r'    if\(!sptm_panic_dispatch\(&c->panic_state,\(unsigned\)vcpu_of\(c\)->slot,x16\)\n'
                  r'(#if SNAP_PANIC_SERVE\n.*?\n#endif\n)       \) \{\n'
                  r'        record\(c,EV_PANIC_STATE_FAILED,\*elr,x16,c->panic_state\.owner,vcpu_of\(c\)->slot\);\n'
                  r'        return 0;\n', text, re.S)
    expect(m is not None, 'gate shape in monitor_call_impl')
    expect(text.count('SNAP_PANIC_SERVE') == 3, 'SNAP_PANIC_SERVE used only in the define block and the gate')
    return m.group(1)


HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include "panic-state.h"
struct vcpu { unsigned slot; };
struct context { struct sptm_panic_state panic_state; struct vcpu v; };
static struct vcpu *vcpu_of(struct context *c) { return &c->v; }
static int stops;
static void record(struct context *c, int kind, uint64_t a, uint64_t b, uint64_t d, uint64_t e)
{ (void)c; (void)kind; (void)a; (void)b; (void)d; (void)e; stops++; }
#define EV_PANIC_STATE_FAILED 43
static int call(struct context *c, uint64_t x16, unsigned cpu)
{
    uint64_t elr0 = 0, *elr = &elr0;
    c->v.slot = cpu;
    if(!sptm_panic_dispatch(&c->panic_state,(unsigned)vcpu_of(c)->slot,x16)
@GATE@       ) {
        record(c,EV_PANIC_STATE_FAILED,*elr,x16,c->panic_state.owner,vcpu_of(c)->slot);
        return 0;
    }
    return 1;
}
#define CHECK(x) do { if (!(x)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #x); exit(1); } n++; } while (0)
int main(void)
{
    int n = 0;
    struct context c;
    sptm_panic_init(&c.panic_state);
    for (unsigned cpu = 0; cpu < 6; cpu++) CHECK(call(&c, 0xd, cpu) == 1);
    CHECK(c.panic_state.rejected == 0 && stops == 0);
    CHECK(sptm_panic_enter(&c.panic_state, 2));
    CHECK(c.panic_state.owner == 2);
    /* v32: CPU 1 calls SWITCH_ROOT (endpoint 0xd) after CPU 2's entry. */
    CHECK(call(&c, 0xd, 1) == @SERVE@);
    CHECK(call(&c, 0x2, 2) == @SERVE@);                     /* the owner's ordinary call */
    CHECK(call(&c, UINT64_C(0x0200000000000000), 3) == 1); /* exact PANIC_ENTRY word: admitted either way */
    CHECK(c.panic_state.rejected == 2);
    CHECK(stops == (@SERVE@ ? 0 : 2));
    /* A corrupt panic state stops in both builds. */
    c.panic_state.owner = 7;
    int before = stops;
    CHECK(call(&c, 0xd, 1) == 0 && stops == before + 1);
    c.panic_state.owner = 2; c.panic_state.phase = 0;
    CHECK(call(&c, 0xd, 1) == 0 && stops == before + 2);
    c.panic_state.phase = 1;
    CHECK(call(&c, 0xd, 6) == 0);                         /* CPU out of range */
    printf("%d\n", n);
    return 0;
}
'''


def host(serve):
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / 'h.c'
        src.write_text(HARNESS.replace('@SERVE@', str(serve)).replace('@GATE@', gate()))
        exe = Path(tmp) / 'h'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Werror', '-fsanitize=address,undefined',
                        f'-DSNAP_PANIC_SERVE={serve}', '-I', str(ROOT / 'compat'), str(src),
                        str(ROOT / 'compat/panic-state.c'), '-o', str(exe)], check=True)
        out = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
        expect(int(out) >= 14, f'harness checks ran (serve={serve})')


def build():
    sys.path.insert(0, str(ROOT / 'probes'))
    sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
    import importlib.util
    spec = importlib.util.spec_from_file_location('test_wfi_resume', ROOT / 'tools/test-wfi-resume.py')
    argv, sys.argv = sys.argv, [sys.argv[0]]
    twr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(twr)
    sys.argv = argv
    import run
    sets, _ = twr.flag_sets()
    saved = list(run.FLAGS)
    out = Path(tempfile.mkdtemp(prefix='panic-serve-build-'))
    try:
        for name, flags in (('control', sets['control']), ('fast', sets['fast']),
                            ('fast+wfi', sets['fast'] + ['-DSNAP_WFI_RESUME=1'])):
            blobs = {}
            for label, extra in (('default', []), ('off', ['-DSNAP_PANIC_SERVE=0']), ('on', ['-DSNAP_PANIC_SERVE=1'])):
                run.FLAGS[:] = flags + extra
                blobs[label] = run.build('xnuboot', out / f'{name}-{label}')
                expect(run.OUT_AT - run.CODE_AT - len(blobs[label]) > 0, f'{name}-{label} fits')
            expect(blobs['default'] == blobs['off'], f'{name}: default equals SNAP_PANIC_SERVE=0')
            expect(blobs['default'] != blobs['on'], f'{name}: SNAP_PANIC_SERVE=1 changes the build')
            print(f'{name}: default {hashlib.sha256(blobs["default"]).hexdigest()[:16]}, '
                  f'on {hashlib.sha256(blobs["on"]).hexdigest()[:16]}', file=sys.stderr)
    finally:
        run.FLAGS[:] = saved


def main():
    os.chdir(ROOT)
    host(0)
    host(1)
    if '--build' in sys.argv[1:]:
        build()
    print(f'OK ({checks} checks)')


if __name__ == '__main__':
    main()
