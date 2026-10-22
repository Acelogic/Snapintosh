#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""tools/perf_counters.py decodes bytes a real C writer produced.

A host program includes compat/perf-state.h, records traps through the same
census and fast-trap counters the monitor uses, fills the index/canonical
counters with distinct values and writes the raw struct. The decoder, using
the TARGET layout of xnuboot.c, must recover every value; truncated or
inconsistent captures must be refused, and every build (with or without the
perf defines) must place the state at the offset the define-free layout
readers compute.
"""
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
perf = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
DEFINES = ['-DSNAP_FAST_VCPU_TRAPS=1', '-DSNAP_SYSREG_CENSUS=1', '-DSNAP_INCREMENTAL_PUBLISH=1',
           '-DSNAP_ROOT_DIRTY_PUBLISH=1', '-DSNAP_TXN_DIRTY_PUBLISH=1',
           '-DSNAP_CANONICAL_VIEW_FAST=1']
BOUNDARY = ['-DSNAP_FAST_VCPU_TRAPS=1', '-DSNAP_VECTOR_BRANCH=1', '-DSNAP_FAST_CROSSINGS=1',
            '-DSNAP_NATIVE_WFE=1', '-DSNAP_NATIVE_CALLS=1',
            '-DSNAP_NATIVE_WRITER_ADMISSION=1', '-DSNAP_NATIVE_WRITER_BREAKPOINTS=1',
            '-DSNAP_ERET_SNAPSHOT=1', '-DSNAP_FAST_TIMER_WRITE=1', '-DSNAP_FAST_IDLE_POLL=1']
WRITER = r'''
#include <stdio.h>
#include <string.h>
#include "perf-state.h"
#include "fast-vector.h"
static struct perf_state p;
int main(int argc,char **argv)
{
    (void)argc;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        for(unsigned k=1;k<FAST_TRAP_CLASSES;k++)p.fast[cpu].handled[k]=cpu*100+k;
        p.fast[cpu].sysreg=cpu*1000+7;p.fast[cpu].declined=cpu+3;p.fast[cpu].first=cpu+1;
        p.fast[cpu].logged=0xff;   /* PACGA and the seven ignored registers */
        /* PACGA, then CONTEXTIDR writes and PMC0 reads through the census. */
        sysreg_census_note(&p.census[cpu],(UINT64_C(0x09)<<26));
        for(unsigned n=0;n<=cpu;n++)
            sysreg_census_note(&p.census[cpu],(UINT64_C(0x18)<<26)|FAST_TRAP_SYSREG(3,0,13,0,1)|(5u<<5));
        for(unsigned n=0;n<2*cpu+1;n++)
            sysreg_census_note(&p.census[cpu],(UINT64_C(0x18)<<26)|FAST_TRAP_SYSREG(3,2,15,0,0)|(9u<<5)|1);
    }
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        p.fast[cpu].branches=cpu*7+1;p.fast[cpu].entries=cpu*1000+11;p.fast[cpu].returns=cpu*1000+13;
        p.fast[cpu].logged|=fast_cross_log_bit(FAST_CROSS_TIMER)|fast_cross_log_bit(FAST_CROSS_USER_RETURN);
    }
    uint64_t *x=&p.root_index.count;for(unsigned i=0;i<14;i++)x[i]=500+i;
    p.canonical.mapped.calls=64;p.canonical.mapped.passed=63;p.canonical.mapped.leaves=61440;
    p.canonical.mapped.walks=15360;p.canonical.mapped.span_walks=60;
    p.canonical.sampled=1;p.canonical.mismatches=0;
    FILE *f=fopen(argv[1],"wb");fwrite(&p,sizeof p,1,f);fclose(f);
    printf("%zu\n",sizeof p);return 0;
}
'''


class PerfCounters(unittest.TestCase):
    def test_decode_real_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            (d / 'writer.c').write_text(WRITER)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-Icompat', '-Ishadow', str(d / 'writer.c'),
                            '-o', str(d / 'writer')], cwd=ROOT, check=True)
            size = int(subprocess.run([str(d / 'writer'), str(d / 'raw.bin')], check=True,
                                      capture_output=True, text=True).stdout)
            raw = (d / 'raw.bin').read_bytes()
        lay = perf['layout'](DEFINES)
        self.assertEqual(lay['size'], size)
        self.assertGreater(lay['context_offset'], 4_000_000)
        out = perf['decode'](raw, lay=lay)
        for cpu, row in enumerate(out['fast']):
            self.assertEqual(row['handled'], {k: cpu * 100 + i + 1 for i, k in
                                              enumerate(perf['CLASSES'][1:])})
            self.assertEqual((row['sysreg'], row['declined'], row['first'], row['logged']),
                             (cpu * 1000 + 7, cpu + 3, cpu + 1, 0xff | (1 << 10) | (1 << 13)))
            self.assertEqual((row['branches'], row['entries'], row['returns']),
                             (cpu * 7 + 1, cpu * 1000 + 11, cpu * 1000 + 13))
        for cpu, row in enumerate(out['census']):
            self.assertEqual((row['total'], row['other'], row['pacga']), (3 * cpu + 2, 0, 1))
            self.assertEqual(row['top'][0], dict(register='PMC0 read', count=2 * cpu + 1))
            self.assertIn(dict(register='CONTEXTIDR_EL1 write', count=cpu + 1), row['top'])
        self.assertEqual(out['summary']['vector_branches'], sum(c * 7 + 1 for c in range(6)))
        self.assertEqual((out['summary']['fast_entries'], out['summary']['fast_returns']),
                         (sum(c * 1000 + 11 for c in range(6)), sum(c * 1000 + 13 for c in range(6))))
        self.assertEqual(out['root_index']['count'], 500)
        self.assertEqual(out['root_index']['txn_scanned'], 513)
        self.assertEqual(out['canonical_view'], dict(calls=64, passed=63, leaves=61440,
                                                     walks=15360, span_walks=60, sampled=1,
                                                     mismatches=0))
        with self.assertRaises(ValueError):
            perf['decode'](raw[:-8], lay=lay)
        bad = bytearray(raw)
        bad[lay['census'] + lay['census_total']] ^= 1          # cpu0 census total
        with self.assertRaises(ValueError):
            perf['decode'](bytes(bad), lay=lay)
        # An occupied slot whose count was lost, and a wrong distinct-key word.
        occupied = next(i for i in range(lay['census_slots'])
                        if any(raw[lay['census'] + lay['census_key'] + 8 * i:][:8]))
        for at in (lay['census_count'] + 8 * occupied, lay['census_total'] + 24):
            bad = bytearray(raw)
            bad[lay['census'] + at:lay['census'] + at + 8] = (
                bytes(8) if at != lay['census_total'] + 24 else (99).to_bytes(8, 'little'))
            with self.assertRaises(ValueError):
                perf['decode'](bytes(bad), lay=lay)
        # class 0, a stray log bit, first > declined, the reserved word
        for at, flip in ((0, 1), (lay['fast_logged'] + 3, 0x08), (lay['fast_first'], 0xff),
                         (lay['fast_reserved'], 1)):
            bad = bytearray(raw)
            bad[lay['fast'] + lay['fast_stride'] + at] ^= flip
            with self.assertRaises(ValueError):
                perf['decode'](bytes(bad), lay=lay)

    def test_late_register_is_named(self):
        # Protects docs/SYSREG-CENSUS-20261016.md failure mode 1: a register
        # first trapped after many others must still get its own slot. The
        # 48-slot first-come list counted it only as `other` (31% of the
        # speed-test runs' system-register traps), so this fails against it.
        writer = r'''
#include <stdio.h>
#include "perf-state.h"
static struct perf_state p;
int main(int argc,char **argv)
{
    (void)argc;
    struct sysreg_census_cpu *s=&p.census[2];
    for(unsigned op1=0,n=0;op1<7;op1++)
        for(unsigned crm=0;crm<16 && n<100;crm++,n++)
            sysreg_census_note(s,(UINT64_C(0x18)<<26)|FAST_TRAP_SYSREG(3,op1,11,crm,2)|(3u<<5)|1);
    for(unsigned n=0;n<5000;n++)   /* CNTV_TVAL_ALIAS write, first seen last */
        sysreg_census_note(s,(UINT64_C(0x18)<<26)|FAST_TRAP_SYSREG(3,1,15,15,4)|((n%31)<<5));
    FILE *f=fopen(argv[1],"wb");fwrite(&p,sizeof p,1,f);fclose(f);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            (d / 'late.c').write_text(writer)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-Icompat', '-Ishadow', str(d / 'late.c'),
                            '-o', str(d / 'late')], cwd=ROOT, check=True)
            subprocess.run([str(d / 'late'), str(d / 'raw.bin')], check=True)
            raw = (d / 'raw.bin').read_bytes()
        row = perf['decode'](raw, lay=perf['layout'](DEFINES))['census'][2]
        self.assertEqual((row['total'], row['other']), (5100, 0))
        self.assertEqual(row['top'][0], dict(register='CNTV_TVAL_ALIAS write', count=5000))
        self.assertEqual(len(row['top']), 101)

    def test_one_layout_for_every_build(self):
        # Layout readers compute struct context without build defines; the
        # appended state must sit at the same place in every build.
        plain = perf['layout']([])
        for defines in ([], DEFINES, ['-DSNAP_SYSREG_CENSUS=1'], ['-DSNAP_CANONICAL_VIEW_FAST=1'],
                        BOUNDARY):
            lay = perf['layout'](defines)
            self.assertEqual((lay['context_offset'], lay['size']),
                             (plain['context_offset'], plain['size']))
        layout = runpy.run_path(str(ROOT / 'tools/monitor_layout.py'))['MonitorLayout']()
        self.assertEqual(layout.offset('context', 'perf'), plain['context_offset'])
        self.assertLessEqual(plain['context_offset'] + plain['size'], layout.size('context'))
        # The next append, the SKS request capture, follows it directly.
        self.assertEqual(layout.offset('context', 'sep_sks_request'),
                         plain['context_offset'] + plain['size'])


if __name__ == '__main__':
    unittest.main()
