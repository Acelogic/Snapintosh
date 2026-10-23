#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the monitor's actual guard-step transition with host stage-2 slots.

Only the hardware operations are mocked. Compile the production guard lookup
and step transition together with the real exception mask implementation.
"""
from pathlib import Path
import os
import subprocess
import tempfile
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]


def function(source, signature):
    start = source.index(signature)
    body = source.index('{', start)
    depth = 1
    end = body + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


HARNESS = r'''
#include "exception.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define GUARD_EXEC 0
#define GUARD_DATA 1
#define S2_XN (1UL << 54)
#define PT_VALID 1UL
struct guard { uint64_t pa, slot, descriptor, mode; };
struct vcpu {
    struct guard guards[3];
    uint64_t guard_count, open_guards;
    struct exception_step stepping;
};
struct context {
    struct vcpu v;
    uint64_t slots[3], spsr, mdscr, pending, irq, flushes, rearm, disarm;
};
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static struct vcpu *vcpu_of(struct context *c) { return &c->v; }
static void guard_write(struct guard *g, int open)
{
    *(uint64_t *)g->slot = open ? g->descriptor :
        g->mode == GUARD_EXEC ? g->descriptor | S2_XN : g->descriptor & ~PT_VALID;
}
static void guard_open(struct context *c, struct guard *g)
{
    guard_write(g, 1); c->v.open_guards++; c->flushes++;
}
static void guards_close(struct context *c)
{
    if (!c->v.open_guards) return;
    for (unsigned i = 0; i < c->v.guard_count; i++) guard_write(&c->v.guards[i], 0);
    c->v.open_guards = 0; c->flushes++;
}
static void step_arm(struct context *c, int on)
{
    if (on) c->rearm++; else c->disarm++;
    exception_step_set(&c->v.stepping, on, &c->spsr, &c->mdscr);
    c->irq = exception_step_fiq(&c->v.stepping, c->pending);
}
/* PRODUCTION */
static void init(struct context *c, uint64_t d)
{
    *c = (struct context){0};
    c->v.guard_count = 3; c->spsr = 0xa04001c5 | d; c->mdscr = 0x8000;
    c->pending = 1;
    for (unsigned i = 0; i < 3; i++) {
        c->v.guards[i] = (struct guard){
            .pa = (i + 1) * 0x1000, .slot = (uintptr_t)&c->slots[i],
            .descriptor = (i + 1) * 0x1000 | 0x7ff,
            .mode = i == 2 ? GUARD_DATA : GUARD_EXEC};
        guard_write(&c->v.guards[i], 0);
    }
}
static int opened(struct context *c, unsigned i)
{
    return c->slots[i] == c->v.guards[i].descriptor;
}
int main(void)
{
    for (unsigned masked = 0; masked < 2; masked++) {
        struct context c;
        init(&c, masked << 9);
        uint64_t original = c.spsr;
        guard_step(&c, 0); /* failed translation cannot retain a page */
        CHECK(!c.v.stepping.active && !c.flushes && c.spsr == original);
        guard_step(&c, 0x1000);
        CHECK(c.flushes == 1 && opened(&c, 0) && c.v.open_guards == 1);
        uint64_t disarm = c.disarm;
        for (unsigned n = 0; n < 1024; n++) {
            /* Hardware consumes SS; each continuation must rearm it. */
            c.spsr &= ~(1UL << 21);
            guard_step(&c, 0x1000 + 4 * (n % 1024));
            CHECK(c.flushes == 1 && c.disarm == disarm && c.v.open_guards == 1);
            CHECK(c.v.stepping.active && (c.spsr & (1UL << 21)) && !c.irq);
            CHECK(c.v.stepping.saved_d == (original & (1UL << 9)));
        }
        guard_step(&c, 0x2000); /* cross into a different guarded page */
        CHECK(c.flushes == 3 && !opened(&c, 0) && opened(&c, 1));
        CHECK(c.v.open_guards == 1 && !c.irq);
        guard_step(&c, 0x4000); /* branch out: reclose and restore guest D */
        CHECK(c.flushes == 4 && !opened(&c, 1) && !c.v.open_guards);
        CHECK(c.spsr == original && c.mdscr == 0x8000 && c.irq);

        /* A data access inside an EXEC page must close DATA after one step. */
        guard_step(&c, 0x1000);
        guard_open(&c, &c.v.guards[2]);
        step_arm(&c, 1);
        uint64_t before = c.flushes;
        guard_step(&c, 0x1004);
        CHECK(c.flushes == before + 2 && opened(&c, 0) && !opened(&c, 2));
        CHECK(c.v.open_guards == 1 && !c.irq);

        /* Duplicate opens and a second EXEC page cannot take the shortcut. */
        for (unsigned i = 0; i < 2; i++) {
            guard_open(&c, &c.v.guards[i]);
            before = c.flushes;
            guard_step(&c, 0x1008);
            CHECK(c.flushes == before + 2 && c.v.open_guards == 1);
            CHECK(opened(&c, 0) && !opened(&c, 1) && !opened(&c, 2));
        }
        /* A changed descriptor or suspended step requires full restoration. */
        c.slots[0] |= S2_XN;
        before = c.flushes;
        guard_step(&c, 0x100c);
        CHECK(c.flushes == before + 2 && opened(&c, 0));
        step_arm(&c, 0);
        before = c.flushes;
        guard_step(&c, 0x1010);
        CHECK(c.flushes == before + 2 && c.v.stepping.active);
        guard_step(&c, 0);
        CHECK(c.spsr == original && c.irq);

        /* DATA alone is never retained, including a PC on that same page. */
        for (unsigned i = 0; i < 2; i++) {
            guard_open(&c, &c.v.guards[2]);
            step_arm(&c, 1);
            before = c.flushes;
            guard_step(&c, i ? 0x3000 : 0x4000);
            CHECK(c.flushes == before + 1 && !opened(&c, 2));
            CHECK(!c.v.open_guards && !c.v.stepping.active && c.spsr == original);
        }
    }
    /* Private stage-2 views must retain/close independently for two CPUs. */
    struct context a, b;
    init(&a, 0); init(&b, 1UL << 9);
    guard_step(&a, 0x1000); guard_step(&b, 0x2000);
    guard_step(&a, 0x1004); guard_step(&b, 0x4000);
    CHECK(a.flushes == 1 && opened(&a, 0) && a.v.open_guards == 1);
    CHECK(b.flushes == 2 && !opened(&b, 1) && !b.v.open_guards);
    printf("PASS: %u guard transition and interrupt-mask checks\n", checks);
}
'''


def main():
    source = read_source(ROOT / 'probes/xnuboot.c')
    production = '\n'.join(function(source, signature) for signature in (
        'static struct guard *guard_find(', 'static void guard_step('))
    with tempfile.TemporaryDirectory(prefix='snapintosh-guard-step-') as tmp:
        c = Path(tmp) / 'guard-step.c'
        exe = Path(tmp) / 'guard-step'
        c.write_text(HARNESS.replace('/* PRODUCTION */', production))
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                        '-Werror', '-O1', '-fsanitize=address,undefined',
                        '-I' + str(ROOT / 'compat'), str(c),
                        str(ROOT / 'compat/exception.c'), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    main()
