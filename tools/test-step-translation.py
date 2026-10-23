#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the production step translation cache with a changing AT oracle."""
from pathlib import Path
import os
import runpy
import subprocess
import tempfile
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
function = runpy.run_path(str(ROOT / 'tools/test-guard-step.py'))['function']
HARNESS = r'''
#include "step-translation.h"
#include "exception.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SNAP_STEP_TRANSLATION 1
#define SNAP_STEP_TRANSLATION_VERIFY 1
#define GUARD_EXEC 0
#define GUARD_DATA 1
struct guard { uint64_t pa, slot, descriptor, mode; };
struct vcpu {
    uint64_t slot, guard_count, open_guards;
    struct exception_step stepping;
    struct guard guards[3];
};
struct context {
    struct vcpu v[2];
    struct step_translation step_translation[2];
    uint64_t shadow_tlb_syncs, kernel_view_failed;
};
static unsigned cpu, checks;
static uint64_t slots[2][3], at_calls, mapped_va, mapped_pa;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static struct vcpu *vcpu_of(struct context *c) { return &c->v[cpu]; }
static uint64_t oracle(uint64_t va)
{ return (va & ~UINT64_C(0xfff)) == mapped_va && mapped_pa ? mapped_pa | (va & 0xfff) : 0; }
static uint64_t guest_pa(uint64_t va) { at_calls++; return oracle(va); }
/* PRODUCTION */
static void init(struct context *c)
{
    memset(c,0,sizeof(*c)); cpu=0; at_calls=0;
    mapped_va=UINT64_C(0xfffffe000c22a000); mapped_pa=0x8c0040000;
    for(unsigned n=0;n<2;n++) {
        c->v[n].slot=n; c->v[n].guard_count=3; c->v[n].open_guards=1;
        c->v[n].stepping.active=1;
        for(unsigned j=0;j<3;j++) {
            slots[n][j]=mapped_pa+j*4096+0x7ff;
            c->v[n].guards[j]=(struct guard){mapped_pa+j*4096,
                (uintptr_t)&slots[n][j],slots[n][j],j==2 ? GUARD_DATA : GUARD_EXEC};
        }
    }
}
static void prime(struct context *c)
{
    CHECK(step_instruction_pa(c,mapped_va,5)==mapped_pa);
    CHECK(c->step_translation[cpu].valid);
}
int main(void)
{
    struct context c; init(&c); prime(&c);
    for(unsigned i=0;i<1024;i++) {
        CHECK(step_instruction_pa(&c,mapped_va+(i*4),5)==oracle(mapped_va+i*4));
        CHECK(!c.kernel_view_failed);
    }
    CHECK(at_calls==2 && c.step_translation[0].hits==1024);
    CHECK(c.step_translation[0].verified==1 && !c.step_translation[0].mismatches);
    /* Cross-CPU mapping replacement, including a recycled physical page. */
    for(unsigned i=0;i<1000;i++) {
        c.shadow_tlb_syncs++; mapped_pa^=4096;
        CHECK(step_instruction_pa(&c,mapped_va+4,5)==oracle(mapped_va+4));
        CHECK(c.step_translation[0].generation==c.shadow_tlb_syncs);
        cpu=1;
        CHECK(step_instruction_pa(&c,mapped_va+8,5)==oracle(mapped_va+8));
        CHECK(c.step_translation[1].generation==c.shadow_tlb_syncs);
        cpu=0;
    }
    /* Every loss of eligibility uses AT even with an otherwise matching key. */
    for(unsigned kind=0;kind<10;kind++) {
        init(&c); prime(&c); uint64_t va=mapped_va, spsr=5;
        switch(kind) {
        case 0: c.v[0].open_guards=0; break;
        case 1: c.v[0].open_guards=2; break;
        case 2: c.v[0].stepping.active=0; break;
        case 3: c.v[0].guards[0].mode=GUARD_DATA; break;
        case 4: slots[0][0]^=1UL<<54; break;
        case 5: c.step_translation[0].guard=3; break;
        case 6: c.v[0].guards[0].pa+=4096; break;
        case 7: spsr=0; break;
        case 8: va+=2; break;
        case 9: va+=4096; break;
        }
        uint64_t before=at_calls;
        CHECK(step_instruction_pa(&c,va,spsr)==oracle(va));
        CHECK(at_calls==before+1 && !c.step_translation[0].hits);
    }
    init(&c); prime(&c);
    step_translation_clear(&c.step_translation[0]); /* interrupt/sysreg/call boundary */
    mapped_pa=0; CHECK(!step_instruction_pa(&c,mapped_va,5));
    CHECK(!c.step_translation[0].valid && at_calls==2);
    init(&c); prime(&c);
    c.shadow_tlb_syncs=UINT64_MAX;
    CHECK(step_instruction_pa(&c,mapped_va,5)==mapped_pa);
    c.shadow_tlb_syncs=0; mapped_pa+=4096;
    CHECK(step_instruction_pa(&c,mapped_va,5)==mapped_pa && at_calls==3);
    /* The diagnostic fail-closed path catches an unreported mapping mutation. */
    init(&c); prime(&c); c.step_translation[0].hits=1023; mapped_pa+=4096;
    CHECK(!step_instruction_pa(&c,mapped_va,5));
    CHECK(c.kernel_view_failed && c.step_translation[0].mismatches==1);
    CHECK(!c.step_translation[0].valid);
    printf("PASS: %u production cache, invalidation, CPU and verification checks\n",checks);
}
'''


def main():
    source = read_source(ROOT / 'probes/xnuboot.c')
    production = '\n'.join(function(source, signature) for signature in (
        'static struct guard *guard_find(', 'static uint64_t step_instruction_pa('))
    with tempfile.TemporaryDirectory(prefix='snapintosh-step-translation-') as tmp:
        c = Path(tmp) / 'test.c'
        exe = Path(tmp) / 'test'
        c.write_text(HARNESS.replace('/* PRODUCTION */', production))
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                        '-Werror', '-O1', '-fsanitize=address,undefined',
                        '-I' + str(ROOT / 'compat'), str(c),
                        str(ROOT / 'compat/exception.c'), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    main()
