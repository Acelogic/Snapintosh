#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the production decoder with native AArch64 instructions on macOS.

The assembly uses caller-saved X9/X10/X11 for destination/operands. Each case
also runs with aliased original register numbers and XZR. ADR/ADRP use the real
native instruction address as the decoder PC. No generated code is writable
and executable: the assembler/linker create a regular signed host executable.
"""
from pathlib import Path
import os
import platform
import random
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
RNG = random.Random(0xA164)
cases = []


def add(word, family):
    rd = word & 31
    rn = (word >> 5) & 31 if family in ('imm', 'logical', 'shift') else 31
    rm = (word >> 16) & 31 if family in ('logical', 'shift') else 31
    native = (word & ~31) | (31 if rd == 31 else 9)
    if family in ('imm', 'logical', 'shift'):
        native = (native & ~(31 << 5)) | ((31 if rn == 31 else 10) << 5)
    if family in ('logical', 'shift'):
        native = (native & ~(31 << 16)) | ((31 if rm == 31 else 11) << 16)
    cases.append((word, native, rd, rn, rm))


for sf in (0, 1):
    width = 64 if sf else 32
    for op in (0, 2, 3):
        for hw in range(width // 16):
            for imm in (0, 1, 0x8000, 0xffff, RNG.randrange(65536)):
                for rd in (0, 17, 30, 31):
                    add((sf << 31) | (op << 29) | 0x12800000 | (hw << 21) | (imm << 5) | rd, 'wide')
    for sub in (0, 1):
        for sh in (0, 1):
            for imm in (0, 1, 0x800, 0xfff):
                for rd, rn in ((0, 1), (29, 29), (17, 30)):
                    add((sf << 31) | (sub << 30) | 0x11000000 | (sh << 22) | (imm << 10) | (rn << 5) | rd, 'imm')
    for family in ('logical', 'shift'):
        for op in range(3 if family == 'logical' else 2):
            for invert in range(2 if family == 'logical' else 1):
                for kind in range(4 if family == 'logical' else 3):
                    for amount in sorted({0, 1, 16, width - 1, RNG.randrange(width)}):
                        for rd, rn, rm in ((0, 1, 2), (17, 17, 17), (29, 31, 30), (30, 29, 31), (31, 30, 29)):
                            base = 0x0a000000 | (op << 29) | (invert << 21) if family == 'logical' else 0x0b000000 | (op << 30)
                            add((sf << 31) | base | (kind << 22) | (rm << 16) | (amount << 10) | (rn << 5) | rd, family)
for page in (0, 1):
    for imm in (0, 1, 3, 0xfffff, 0x100000, 0x1fffff):
        for rd in (0, 17, 30, 31):
            add((page << 31) | 0x10000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | rd, 'adr')
cases.append((0xd503201f, 0xd503201f, 31, 31, 31))

HARNESS = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "step-alu.h"
typedef uint64_t (*native_fn)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t *);
struct test { uint32_t w; unsigned rd,rn,rm; native_fn fn; const char *pc; };
static unsigned long checks;
#define CHECK(c) do {checks++;if(!(c)){fprintf(stderr,"FAIL line %u case %u word %08x: %s\n",__LINE__,idx,w,#c);return 1;}}while(0)
static uint64_t seed=0x987654321abcdef0ULL;
static uint64_t random64(void) {seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed;}
DECLS
static struct test tests[]={ROWS};
int main(void) {
    unsigned idx=0; uint32_t w=0;
    uint64_t values[]={0,1,UINT64_MAX,0x8000000080000000ULL,0x7fffffff7fffffffULL,0x12345678fedcba98ULL};
    for(idx=0;idx<sizeof(tests)/sizeof(*tests);idx++) {
        struct test *t=&tests[idx];w=t->w;
        for(unsigned flags=0;flags<16;flags++) for(unsigned trial=0;trial<10;trial++) {
            uint64_t x[31],before[31],native_flags=UINT64_MAX;
            for(unsigned j=0;j<31;j++)x[j]=trial<6 ? values[(trial+j)%6] : random64();
            memcpy(before,x,sizeof(x));
            uint64_t result=t->fn(step_alu_reg(x,t->rd),step_alu_reg(x,t->rn),step_alu_reg(x,t->rm),(uint64_t)flags<<28,&native_flags);
            CHECK(native_flags==((uint64_t)flags<<28));
            CHECK(step_alu_one(w,(uintptr_t)t->pc,x));
            if(t->rd!=31) CHECK(x[t->rd]==result);
            for(unsigned j=0;j<31;j++)if(j!=t->rd)CHECK(x[j]==before[j]);
        }
    }
    /* Memory, exclusive pairs, branches, calls, system/PAC, NZCV setters,
     * SP forms, reserved move-wide/shift encodings: reject without effects. */
    uint32_t refused[]={0xf9400020,0xf9000020,0xc85f7c20,0xc8027c20,
        0x14000000,0x94000000,0xd65f03c0,0x54000000,0xb4000000,
        0xd503207f,0xd503233f,0xd503245f,0xd53bd040,0xd4000001,
        0x00201420,0xd4e00000,0xb1000020,0xeb020020,0xea020020,
        0x910003e0,0x9100003f,0x32800000,0x12c00000,0x0a028020,
        0x0bc20020,0x0b028020,0x11000000 | (1u<<23)};
    for(idx=0;idx<sizeof(refused)/sizeof(*refused);idx++) {
        uint64_t x[31],before[31];w=refused[idx];
        for(unsigned j=0;j<31;j++)x[j]=random64();memcpy(before,x,sizeof(x));
        CHECK(!step_alu_one(w,0xfffffe000c22a000ULL,x));CHECK(!memcmp(x,before,sizeof(x)));
    }
    /* ADR arithmetic must wrap at 64 bits, independent of signed C overflow. */
    uint64_t x[31]={0};w=0x10000020;CHECK(step_alu_one(w,UINT64_MAX-2,x));CHECK(x[0]==1);
    uint32_t words[32];for(unsigned j=0;j<32;j++)words[j]=0x91000400; /* add x0,x0,#1 */
    uint64_t pc=0xfffffe000c22a000ULL;x[0]=0;
    CHECK(step_alu_batch(words,&pc,x)==16);CHECK(x[0]==16);CHECK(pc==0xfffffe000c22a040ULL);
    pc=0xfffffe000c22aff8ULL;x[0]=0;
    CHECK(step_alu_batch(words,&pc,x)==1);CHECK(x[0]==1);CHECK(pc==0xfffffe000c22affcULL);
    CHECK(step_alu_batch(words,&pc,x)==0);CHECK(x[0]==1);
    pc=0xfffffe000c22a001ULL;CHECK(step_alu_batch(words,&pc,x)==0);CHECK(x[0]==1);
    pc=0xfffffe000c22a000ULL;x[0]=0;words[3]=0xf9400020;
    CHECK(step_alu_batch(words,&pc,x)==3);CHECK(x[0]==3);CHECK(pc==0xfffffe000c22a00cULL);
    struct step_alu_state s={0}, other={0};pc=0xfffffe000c22a000ULL;
    CHECK(!step_alu_ready(&s,pc,7,5,1));
    step_alu_resume(&s,pc,7);step_alu_enter(&s,0x32);
    CHECK(step_alu_ready(&s,pc+4,7,5,1));CHECK(!step_alu_ready(&other,pc,7,5,1));
    CHECK(!step_alu_ready(&s,pc+4096,7,5,1));CHECK(!step_alu_ready(&s,pc,8,5,1));
    CHECK(!step_alu_ready(&s,pc,7,5|(1<<10),1));CHECK(!step_alu_ready(&s,pc,7,5|(1<<11),1));
    CHECK(!step_alu_ready(&s,pc,7,5|(1<<20),1));CHECK(!step_alu_ready(&s,pc,7,5,1|(1<<15)));
    step_alu_enter(&s,0x32);CHECK(!step_alu_ready(&s,pc,7,5,1));
    step_alu_resume(&s,pc,7);step_alu_enter(&s,0x18);CHECK(!step_alu_ready(&s,pc,7,5,1));
    step_alu_enter(&s,0x32);CHECK(!step_alu_ready(&s,pc,7,5,1));
    step_alu_resume(&s,pc,7);step_alu_enter(&s,64);CHECK(!step_alu_ready(&s,pc,7,5,1));
    printf("PASS %lu checks, %zu native AArch64 instruction cases\n",checks,sizeof(tests)/sizeof(*tests));
    return 0;
}
'''


def main():
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise SystemExit('Native qualification requires Apple Silicon macOS')
    declarations, rows, assembly = [], [], ['.text', '.p2align 2']
    for i, (word, native, rd, rn, rm) in enumerate(cases):
        declarations.append(f'extern uint64_t case_{i}(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t *); extern const char pc_{i}[];')
        rows.append(f'{{0x{word:08x},{rd},{rn},{rm},case_{i},pc_{i}}}')
        assembly += [f'.globl _case_{i}, _pc_{i}', f'_case_{i}:', 'msr nzcv, x3', 'mov x9, x0', 'mov x10, x1', 'mov x11, x2', f'_pc_{i}:', f'.long 0x{native:08x}', 'mov x0, x9', 'mrs x12, nzcv', 'str x12, [x4]', 'ret']
    with tempfile.TemporaryDirectory(prefix='snap-step-alu-') as td:
        p = Path(td)
        (p/'test.c').write_text(HARNESS.replace('DECLS', '\n'.join(declarations)).replace('ROWS', ',\n'.join(rows)))
        (p/'native.S').write_text('\n'.join(assembly)+'\n')
        flags = os.environ.get('STEP_ALU_TEST_FLAGS', '-O1 -fsanitize=address,undefined').split()
        subprocess.run(['clang', *flags, '-Wall', '-Wextra', '-Werror', '-I', str(ROOT/'compat'), str(p/'test.c'), str(p/'native.S'), '-o', str(p/'test')], check=True)
        subprocess.run([str(p/'test')], check=True)


if __name__ == '__main__':
    main()
