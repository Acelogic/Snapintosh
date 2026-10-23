#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_BOOT_RELOCATE: bind compat/boot-relocate.h's decisions to the monitor,
its entry and exit assembly, the host configuration and the record layout.

    python3 tools/test-boot-relocate.py
    python3 tools/test-boot-relocate.py --build [--out DIR]
        [--expect control=SHA256 --expect fast=SHA256 --expect fast-wfi=SHA256]

Offline: no hardware and no proxy. It builds and runs tools/test-boot-relocate.c
(address/undefined and thread sanitizers: the layout check, the ID comparison,
q1n1's CPU's wait decision against an oracle over its whole grid, the relay
between two threads including a caller that gives up), then requires weakened
headers to FAIL it. It checks that probes/xnuboot.c and probes/xnuboot.S
default the define to 0 and keep every relocation line inside #if
SNAP_BOOT_RELOCATE; that _start relocates only after a successful preparation
and before its own watchdog and ERET; that the exit path sends the relocated
CPU, on its own stack, to xnuboot_relocated_stop before it could unwind as
q1n1; that the report settles first; that q1n1's call service is relayed and
the #else path is the unchanged line; that the Adreno SPI follows vCPU 0; that
q1n1's CPU captures exactly the registers vcpu_arch_prepare saves and the
report restores, and hands back each into the field it came from; the target's
boot order; and the record offsets the host and the assembly read, against
Clang's layout. Every system register the relocation code names must be in
ARCH, an allowlist of architecturally allocated encodings checked against
LLVM's register table, and BOOT_RELOCATE_ID_REGS may hold only allocated ID
registers (v48 read the whole ID group and faulted on S3_0_C0_C0_1). A run
that stopped before any vCPU took the service lock must still decode (v48's
decode raised on an empty profile).

--build compiles xnuboot with cycle.py's control, fast and fast+WFI flag sets
with the define absent, =0 and =1: -Werror, the code budget, absent == =0
byte for byte, =1 differs and carries the relocation symbols, absent carries
none. Every MRS/MSR encoding =1 adds over the default build must be in ARCH,
and boot_relocation_ids must read exactly the table's registers plus CTR_EL0
and DCZID_EL0, with no call out. --expect NAME=SHA256 requires the default build to equal a pre-change
monitor.

Failure inventory (compat/boot-relocate.h has the monitor's): a default build
that changed; relocation code outside its #if; a relocation started before
the shared preparation succeeded or after q1n1's CPU armed its own watchdog;
the relocated CPU unwinding as q1n1 or on q1n1's stack; the report running
before the target is OFF; the call service called from the target; q1n1's
registers not all captured or handed back into the wrong field; a weakened
decider passing the C test; host and monitor disagreeing on offsets; an
unallocated, IMPLEMENTATION DEFINED or unlisted system register read or written
on either CPU; a decoder that cannot summarize a run with no locked trap.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
VECTORS = (ROOT / 'probes/xnuboot.S').read_text()
SECONDARY = (ROOT / 'probes/secondary.S').read_text()
HEADER = (ROOT / 'compat/boot-relocate.h').read_text()
RUNTIME = runpy.run_path(str(ROOT / 'tools/secondary-runtime.py'))
SYMBOLS = ('xnuboot_boot_relocate', 'xnuboot_relocated_stop', 'boot_guest_enter')


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256',
                    help='control, fast or fast-wfi: the default build must have this SHA-256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, out=None, expect=[]), [])


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin)]


def ordered(region, tokens):
    at = 0
    for token in tokens:
        found = region.find(token, at)
        if found < 0:
            raise AssertionError(f'{token!r} missing or out of order')
        at = found + len(token)


def function(name, text=SOURCE):
    """The body of a top-level C function, from its definition line to the closing brace."""
    match = re.search(r'^[^\n;]*\b' + re.escape(name) + r'\([^;{]*\)\n\{\n', text, re.M)
    if not match:
        raise AssertionError(f'{name} definition missing')
    return text[match.start():text.index('\n}\n', match.end()) + 3]


def guarded_regions(text):
    """Line ranges inside #if SNAP_BOOT_RELOCATE ... #endif (and its #else, flagged)."""
    lines, stack, inside = text.split('\n'), [], []
    for number, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#if'):
            stack.append(['SNAP_BOOT_RELOCATE' in stripped and not stripped.startswith('#ifndef'), True])
        elif stripped.startswith('#else') and stack:
            stack[-1][1] = False
        elif stripped.startswith('#endif') and stack:
            stack.pop()
        inside.append(any(on and branch for on, branch in stack))
    return lines, inside


def compile_test(directory, header_dir=None, sanitizer='address,undefined'):
    exe = Path(directory) / f'test-boot-relocate-{sanitizer.replace(",", "-")}'
    include = [f'-I{header_dir}'] if header_dir else []
    recover = ['-fno-sanitize-recover=all'] if 'undefined' in sanitizer else []
    subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    f'-fsanitize={sanitizer}', *recover, *include, '-Icompat',
                    'tools/test-boot-relocate.c', 'compat/cpu-release.c', '-o', str(exe), '-lpthread'],
                   cwd=ROOT, check=True, timeout=180, capture_output=True)
    return exe


def layout(defines=()):
    text = subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding',
                           '-mgeneral-regs-only', '-Ishadow', '-Icompat', *defines,
                           '-Xclang', '-fdump-record-layouts', '-fsyntax-only', 'probes/xnuboot.c'],
                          cwd=ROOT, capture_output=True, text=True, check=True).stdout
    records = {}
    for block in text.split('*** Dumping AST Record Layout'):
        match = re.search(r'^\s*0 \| struct (\w+)\n', block, re.M)
        if match:
            records[match[1]] = block
    return records


def offset(records, kind, field):
    found = re.findall(r'^\s*(\d+) \|   \S.* ' + re.escape(field) + r'$', records[kind], re.M)
    if len(found) != 1:
        raise AssertionError(f'ambiguous {kind}.{field}')
    return int(found[0])


# Each weakening of compat/boot-relocate.h must make the C test fail.
MUTANTS = {
    'phase 4 trusted without OFF': ('return w->off == 1 ? BOOT_WAIT_HANDBACK : BOOT_WAIT_SERVE;',
                                    'return BOOT_WAIT_HANDBACK;'),
    'CPU_OFF failure not quarantined': ('if (w->phase >= 5) return BOOT_WAIT_QUARANTINE;',
                                        'if (w->phase >= 6) return BOOT_WAIT_QUARANTINE;'),
    'no arrival window': ('if (elapsed < w->arrival) return BOOT_WAIT_SERVE;', ''),
    'unarrived but ON handed back': ('if (w->off == 1) return BOOT_WAIT_HANDBACK;',
                                     'if (w->off >= 0) return BOOT_WAIT_HANDBACK;'),
    'running CPU trusted OFF': ('if (elapsed >= w->session && !w->stopped) return BOOT_WAIT_STOP;',
                                'if (w->off == 1) return BOOT_WAIT_HANDBACK;\n'
                                '    if (elapsed >= w->session && !w->stopped) return BOOT_WAIT_STOP;'),
    'stuck CPU never asked to stop': ('if (elapsed >= w->session && !w->stopped) return BOOT_WAIT_STOP;', ''),
    'target may be q1n1': ('target == boot ||', 'target == ~boot ||'),
    'cross-cluster accepted': (' ||\n            (affinity[i] & BOOT_RELOCATE_CLUSTER) != (target & BOOT_RELOCATE_CLUSTER)', ''),
    'shared redistributor': ('redistributor[i] == redistributor[0] ||', ''),
    'GICR unchecked': ('!boot_relocate_gicr_valid(redistributor[0])', '0'),
    'malformed affinity': ('(target & ~BOOT_RELOCATE_AFFINITY) || ', ''),
    'PFR1 not compared': ('X(ID_AA64PFR1_EL1,  0, 0, 4, 1, 1)', 'X(ID_AA64PFR1_EL1,  0, 0, 4, 1, 0)'),
    'MMFR0 not compared': ('X(ID_AA64MMFR0_EL1, 0, 0, 7, 0, 1)', 'X(ID_AA64MMFR0_EL1, 0, 0, 7, 0, 0)'),
    'ISAR2 not compared': ('X(ID_AA64ISAR2_EL1, 0, 0, 6, 2, 1)', 'X(ID_AA64ISAR2_EL1, 0, 0, 6, 2, 0)'),
    'release keeps bit 0': ('return mask & ~(uint64_t)BOOT_RELOCATE_MASK;', 'return mask;'),
    'MIDR compared': ('X(MIDR_EL1,         0, 0, 0, 0, 0)', 'X(MIDR_EL1,         0, 0, 0, 0, 1)'),
    'abandonment ignored': ('return !__atomic_load_n(&r->abandoned, __ATOMIC_RELAXED) &&', 'return'),
    'any answer accepted': ('if (__atomic_load_n(&r->done, __ATOMIC_ACQUIRE) != ticket) return 0;',
                            'if (__atomic_load_n(&r->done, __ATOMIC_ACQUIRE) < ticket - 1) return 0;'),
}


class Decision(unittest.TestCase):
    def test_c_test_passes_under_sanitizers(self):
        for sanitizer in ('address,undefined', 'thread'):
            with self.subTest(sanitizer), tempfile.TemporaryDirectory() as d:
                result = subprocess.run([str(compile_test(d, sanitizer=sanitizer))],
                                        capture_output=True, text=True, timeout=600)
                self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr[-3000:])
                self.assertTrue(result.stdout.rstrip().endswith('PASS'), result.stdout[-2000:])
                print(sanitizer, '|', ' | '.join(result.stdout.strip().splitlines()[-3:-1]), file=sys.stderr)

    def test_weakened_headers_fail(self):
        for name, (old, new) in MUTANTS.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                self.assertEqual(HEADER.count(old), 1, name)
                (Path(d) / 'boot-relocate.h').write_text(HEADER.replace(old, new))
                exe = compile_test(d, d)
                result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=600)
                self.assertNotEqual(result.returncode, 0, name)


class Source(unittest.TestCase):
    def test_default_off_everywhere(self):
        for text in (SOURCE, VECTORS):
            self.assertIn('#ifndef SNAP_BOOT_RELOCATE\n#define SNAP_BOOT_RELOCATE 0\n#endif\n'
                          '#if SNAP_BOOT_RELOCATE\n#include "../compat/boot-relocate.h"\n#endif', text)

    def test_every_relocation_line_is_guarded(self):
        names = re.compile(r'boot_reloc|relocated_stop|boot_relocated|relocated->|boot_relay|boot_guest_enter|'
                           r'BOOT_RELOCATE|CONTEXT_SECONDARY_BASE|BOOT_HOST_WORDS|xnuboot_boot_relocate')
        for label, text in (('xnuboot.c', SOURCE), ('xnuboot.S', VECTORS), ('secondary.S', SECONDARY)):
            lines, inside = guarded_regions(text)
            stray = [f'{label}:{n + 1}: {line}' for n, line in enumerate(lines)
                     if names.search(line) and not inside[n] and not line.lstrip().startswith(('#if', '#endif'))
                     and 'SNAP_BOOT_RELOCATE' not in line]
            self.assertEqual(stray, [], '\n'.join(stray))
        self.assertIn('#if SNAP_BOOT_RELOCATE\n/* vCPU 0 on a relocated CPU', SECONDARY)

    def test_start_relocates_after_preparation_before_its_own_entry(self):
        start = between(VECTORS, '_start:', '\nexit:')
        ordered(start, ['bl xnuboot_prepare', 'str x0, [x19, #OUT_STATUS]', 'cbnz x0, exit',
                        '#if SNAP_BOOT_RELOCATE', 'bl xnuboot_boot_relocate', 'cbnz x0, exit', '#endif',
                        'bl xnuboot_watchdog', 'orr x8, x8, #(1 << 4)', 'str x14, [x19, #OUT_ENTERED]', 'eret'])

    def test_exit_routes_the_relocated_cpu_before_any_unwind(self):
        exit_path = between(VECTORS, '\nexit:', 'bl xnuboot_report')
        ordered(exit_path, ['bl pauth_switch_leave', 'mrs x9, tpidr_el2', '#if SNAP_BOOT_RELOCATE',
                            'ldr x10, [x9, #40]', 'cbnz x10, 1f', 'ldr x11, [x9, #32]',
                            'movz x12, #(CONTEXT_SECONDARY_BASE & 65535)',
                            'movk x12, #(CONTEXT_SECONDARY_BASE >> 16), lsl #16', 'ldr x11, [x11, x12]',
                            'cbz x11, 1f', 'ldr x12, [x11, #BOOT_RELOCATE_ARMED]', 'cbz x12, 1f',
                            'mrs x13, mpidr_el1', 'and x13, x13, x14', 'ldr x12, [x11, #48]', 'cmp x13, x12',
                            'b.ne 1f', 'ldr x10, [x11, #40]', 'mov sp, x10', 'b xnuboot_relocated_stop', '1:',
                            '#endif', 'ldr x10, [x9, #0]', 'mov sp, x10', 'cbnz x10, xnuboot_secondary_stop'])
        # secondary_entry's record ABI: stack at 40 and affinity at 48.
        self.assertIn('_Static_assert(__builtin_offsetof(struct secondary,stack)==40', (ROOT / 'probes/secondary.h').read_text())
        self.assertIn('ldr x2, [x19, #48]', SECONDARY)

    def test_report_settles_first(self):
        report = function('xnuboot_report')
        ordered(report, ['struct vcpu *v = vcpu_of(c);', '#if SNAP_BOOT_RELOCATE', 'boot_relocation_settle(c);',
                         '#endif', 'watchdog_off(c);', 'guest_service_finish(&c->services, v->slot);'])

    def test_call_service_is_relayed_and_the_else_path_unchanged(self):
        call = function('early_stop_host_call')
        self.assertIn('#else\n    uint64_t result = call(op, a1, a2, a3);\n#endif', call)
        ordered(call, ['s->host_in_call = 1;', 'boot_relocation_of(c)', '!boot_relocation_on_boot_cpu(c)',
                       'boot_relay_call(c, relocated, op, a1, a2, a3)', 'call(op, a1, a2, a3)',
                       's->host_in_call = 0;'])
        relay = function('boot_relay_call')
        ordered(relay, ['!boot_relay_idle(q)', 'buffer[n] = caller[n]', 'boot_relay_post(q, op, latch ? (uintptr_t)q->buffer : a1',
                        'boot_relay_answered(q, ticket, &result)', 'q->abandoned, 1', 'caller[n] = buffer[n]'])
        serve = function('boot_relay_serve')
        ordered(serve, ['if (!live', 'BOOT_RELAY_FAILED', 'q->in_call=1;', 'call(q->op,q->a1,q->a2,q->a3)',
                        'q->in_call=0;', 'boot_relay_answer(q,ticket,result)'])

    def test_adreno_spi_follows_vcpu0(self):
        gpu = function('gpu_prepare')
        ordered(gpu, ['g.affinity=(mpidr&0xffffff)|((mpidr>>32)&0xff)<<32;', '#if SNAP_BOOT_RELOCATE',
                      'if (relocated) g.affinity=relocated->record.affinity;', '#endif', 'adreno_gic_route(&o,&g,&c->gpu)'])
        prepare = function('xnuboot_prepare')
        ordered(prepare, ['secondary_prepare_records(c)', 'gpu_prepare(c)', 'ans_window_prepare(c)',
                          '#if SNAP_BOOT_RELOCATE', 'if (relocated) return boot_relocation_capture(relocated);',
                          '#endif', 'return vcpu_arch_prepare(c);'])

    def test_capture_and_handback_cover_what_the_report_restores(self):
        arch = function('vcpu_arch_prepare')
        saved = dict(re.findall(r'mrs %0, (\w+)"\s*:\s*"=r"\(vcpu_of\(c\)->(save_\w+|dbg_oslsr)\)', arch))
        self.assertEqual(len(saved), 11, saved)
        capture = function('boot_relocation_capture')
        captured = {register: int(index) for register, index in re.findall(r'mrs %0, (\w+)":"=r"\(h\[(\d+)\]\)', capture)}
        self.assertEqual(set(captured), set(saved))
        handback = function('boot_relocation_handback')
        restored = {field: int(index) for field, index in re.findall(r'v->(save_\w+|dbg_oslsr)=h\[(\d+)\]', handback)}
        self.assertEqual(restored, {saved[register]: index for register, index in captured.items()})
        self.assertIn('#define BOOT_HOST_WORDS 11', SOURCE)
        # Everything else the report restores was captured by _start on q1n1's CPU.
        report = function('xnuboot_report')
        for field in re.findall(r'"r"\(vcpu_of\(c\)->(save_\w+)\)', report):
            self.assertTrue(field in restored or field in ('save_vbar', 'save_sctlr', 'save_tcr', 'save_hcr',
                                                           'save_daif', 'save_tpidr'), field)
        ordered(handback, ['if (r->captured)', 'if (r->relay.in_call) c->early_stop.host_in_call=1;',
                           'if (!out[0] && !out[1])', '__atomic_store_n(&r->handed_back,1,__ATOMIC_RELEASE);'])

    def test_target_boot_order(self):
        run = function('boot_relocated_run')
        ordered(run, ['__atomic_store_n(&s->phase,1,__ATOMIC_RELEASE);', 'boot_relocation_ids(r->target_id',
                      'boot_relocate_id_mismatch(r->boot_id,r->target_id)', 'mrs %0, cntvoff_el2',
                      'r->target_cntvoff!=r->boot_cntvoff || r->target_cntfrq!=r->boot_cntfrq',
                      'r->target_cntfrq!=c->params->clock_host_hz', 'BOOT_RELOCATE_ERROR_CLOCK', 'secondary_gic_start(s)',
                      '__atomic_store_n(&s->phase,2,__ATOMIC_RELEASE);', 'msr hcr_el2', 'msr cpacr_el1, %0; msr cptr_el2, %1',
                      's->prepare_result=(uint64_t)vcpu_arch_prepare(c);', 's->active_vttbr!=vcpu_vttbr(v)',
                      'xnuboot_watchdog(c->params->watchdog_seconds);', 'hcr|24', 's->entered=1;',
                      '__atomic_store_n(&s->phase,3,__ATOMIC_RELEASE);',
                      'boot_guest_enter(c->params->entry,v->out_ptr,c->params->x1,c->params->x2);'])
        self.assertNotIn('runtime_enter', run)   # no other executor yet: as on the boot path
        hcr = re.search(r'uint64_t hcr=(\(UINT64_C.*?\|1);', function('secondary_run'), re.S)[1]
        self.assertIn('uint64_t hcr=' + hcr + ';', run)
        enter = between(SECONDARY, 'boot_guest_enter:', 'eret')
        ordered(enter, ['msr elr_el2, x0', 'mov x4, #0x3c5', 'msr spsr_el2, x4', 'str x4, [x1, #8]',
                        'mov x0, #0', 'mov x1, x2', 'mov x2, x3', 'isb'])
        stop = function('xnuboot_relocated_stop')
        ordered(stop, ['if (v->slot || !r || boot_relocation_on_boot_cpu(c))', 'watchdog_off(c);', 'guards_close(c);',
                       'native_writer_debug_restore(&c->writer_debug[0]', 'c->writer_debug[0].saved=0;',
                       'secondary_gic_stop(s)', 's->finish_result=guest_service_finish(&c->services,0);',
                       '__atomic_store_n(&s->phase,4,__ATOMIC_RELEASE);', 'secondary_power_off(s);'])

    def test_q1n1_cpu_waits_for_off_before_returning(self):
        boot = function('xnuboot_boot_relocate')
        ordered(boot, ['if (!r) return 0;', 'secondary_psci(0xc4000004,s->affinity,0,0)', 'if (s->affinity_result==1)',
                       'r->launched=1;', 'publish(c->work_start,c->next_table);',
                       'secondary_psci(0xc4000003,s->affinity,(uint64_t)secondary_entry,(uint64_t)s)',
                       'boot_relocation_wait(c,r,1);', 'boot_relocation_handback(c,r);', 'return 1;'])
        wait = function('boot_relocation_wait')
        ordered(wait, ['boot_relay_take(&r->relay,&ticket)', 'record.phase,__ATOMIC_ACQUIRE', 'guest_service_stopped',
                       'secondary_psci(0xc4000004,r->record.affinity,0,0)', 'boot_relocate_wait(&w)',
                       'case BOOT_WAIT_HANDBACK:', 'return;', 'case BOOT_WAIT_STOP:', 'SERVICE_STOP_FAULT',
                       'case BOOT_WAIT_QUARANTINE:', 'for (;;)'])
        settle = function('boot_relocation_settle')
        ordered(settle, ['r->handed_back', 'if (!boot_relocation_on_boot_cpu(c)) xnuboot_relocated_stop();',
                         'if (r->launched)', 'SERVICE_STOP_FAULT', 'boot_relocation_wait(c,r,0);',
                         'boot_relocation_handback(c,r);'])

    def test_bit0_never_reaches_a_secondary_mask_consumer(self):
        """v51: the CPU-release allowance carried bit 0, so XNU's first CPU-start write was refused."""
        allowed = (re.compile(r'->mask&\(1U<<(slot|i|j)\)'),           # one secondary's bit, slots 1-5
                   re.compile(r'!h->mask \|\| h->mask&~UINT64_C\(0x3[ef]\)'),   # the records' validation
                   re.compile(r'h->mask&BOOT_RELOCATE_MASK'),
                   re.compile(r'boot_relocate_layout_valid\(h->boot_affinity,h->mask,'),
                   re.compile(r'boot_relocate_release_mask\(c->host_cpus->mask\)'))
        lines, inside = guarded_regions(SOURCE)
        stray = []
        for n, line in enumerate(lines):
            if not re.search(r'(host_cpus|\bh)->mask', line):
                continue
            rest = line
            for pattern in allowed:
                rest = pattern.sub('', rest)
            if re.search(r'(host_cpus|\bh)->mask', rest):
                # The default build's release call keeps its bare mask, only in the #else branch.
                if (line.strip() == 'c->host_cpus->mask,ipa-UINT64_C(0x300734000),a.size,value,' and
                        lines[n - 1].strip() == '#else'):
                    continue
                stray.append(f'xnuboot.c:{n + 1}: {line.strip()}')
        self.assertEqual(stray, [])
        release = SOURCE[SOURCE.index('guest_cpu_release_write(&c->cpu_release,'):][:400]
        ordered(release, ['#if SNAP_BOOT_RELOCATE', 'boot_relocate_release_mask(c->host_cpus->mask),',
                          '#else', 'c->host_cpus->mask,ipa-UINT64_C(0x300734000)', '#endif', 'secondary_release,&request'])
        self.assertIn('return mask & ~(uint64_t)BOOT_RELOCATE_MASK;', HEADER)

    def test_records_refuse_bit0_without_the_define(self):
        records = function('secondary_prepare_records')
        self.assertIn('#else\n    if (h->magic!=SECONDARY_MAGIC || h->size!=sizeof(*h) ||\n'
                      '        (mpidr&UINT64_C(0xff00ffffff))!=h->boot_affinity ||\n'
                      '        !h->mask || h->mask&~UINT64_C(0x3e) ||\n'
                      '        c->work_end-c->next_table<6*4096) return 0;\n#endif', records)
        ordered(records, ['h->mask&~UINT64_C(0x3f)', 'boot_relocate_layout_valid(h->boot_affinity,h->mask,h->affinity,h->redistributor)',
                          '6*4096+relocate', 'c->next_table+=6*4096;', 'if (relocate)', 'c->next_table+=relocate;',
                          'r->record.cpu=(uint64_t)&c->vcpus[0];r->record.stack=c->next_table;',
                          'r->record.callback=(uint64_t)boot_relocated_run;', 'r->armed=1;'])


class Layout(unittest.TestCase):
    def test_offsets_host_assembly_and_monitor_agree(self):
        plain, relocated = layout(), layout(['-DSNAP_BOOT_RELOCATE=1'])
        header = dict(re.findall(r'#define (BOOT_RELOCATE_ARMED|CONTEXT_SECONDARY_BASE) (\d+)', HEADER))
        for records in (plain, relocated):
            self.assertEqual(offset(records, 'context', 'secondary_base'), int(header['CONTEXT_SECONDARY_BASE']))
        self.assertEqual(offset(relocated, 'boot_relocation', 'armed'), int(header['BOOT_RELOCATE_ARMED']))
        for field, word in RUNTIME['RELOCATION_WORDS'].items():
            self.assertEqual(offset(relocated, 'boot_relocation', field), word * 8, field)
        for n, field in enumerate(RUNTIME['RELAY_FIELDS']):
            self.assertEqual(offset(relocated, 'boot_relay', field), n * 8, field)
        size = int(re.search(r'\[sizeof=(\d+),', relocated['boot_relocation'])[1])
        self.assertLessEqual(size, 4096)
        self.assertNotIn('boot_relocation', plain)
        # The default layout is untouched: the private CPU stride and context size are the same.
        for kind in ('vcpu', 'context'):
            self.assertEqual(re.search(r'\[sizeof=(\d+),', plain[kind])[1], re.search(r'\[sizeof=(\d+),', relocated[kind])[1])

    def test_decode_relocation(self):
        words = [0] * RUNTIME['RELOCATION_SIZE']
        self.assertIsNone(RUNTIME['decode_relocation'](words))
        w = RUNTIME['RELOCATION_WORDS']
        words[4] = 0x1000; words[6] = 0x10000; words[11] = 4; words[w['armed']] = 1; words[w['handed_back']] = 1
        words[w['boot_id']] = 0x511f0010; words[w['target_id']] = 0x511f0011
        words[w['boot_id'] + 2] = words[w['target_id'] + 2] = 7
        words[w['target_cache']] = 0x8444c004; words[w['relay'] + 9] = 12
        row = RUNTIME['decode_relocation'](words)
        self.assertEqual((row['cpu'], row['affinity'], row['phase'], row['handed_back']), (0x1000, 0x10000, 4, 1))
        self.assertEqual(row['id_differences'], {'MIDR_EL1': [0x511f0010, 0x511f0011]})
        self.assertEqual((row['target_cache']['ctr'], row['relay']['served']), (0x8444c004, 12))


# Every system register the relocation path may access: (op0, op1, CRn, CRm, op2) from the Arm ARM (DDI 0487,
# the System register index), and how it is accessed. Each is architecturally allocated and either mandatory with
# EL2 (the Generic Timer's CNTVOFF_EL2, the EL2 translation, trap and exception registers) or already accessed
# natively by this monitor on the A16 (the ID registers, VNCR_EL2 for FEAT_NV2, the debug and FP controls).
# Registers.test_allowlist_matches_llvm checks every encoding against LLVM's own register table.
ARCH = {
    'MIDR_EL1': ((3, 0, 0, 0, 0), 'r'), 'MPIDR_EL1': ((3, 0, 0, 0, 5), 'r'),
    'ID_AA64PFR0_EL1': ((3, 0, 0, 4, 0), 'r'), 'ID_AA64PFR1_EL1': ((3, 0, 0, 4, 1), 'r'),
    'ID_AA64DFR0_EL1': ((3, 0, 0, 5, 0), 'r'),
    'ID_AA64ISAR0_EL1': ((3, 0, 0, 6, 0), 'r'), 'ID_AA64ISAR1_EL1': ((3, 0, 0, 6, 1), 'r'),
    'ID_AA64ISAR2_EL1': ((3, 0, 0, 6, 2), 'r'),
    'ID_AA64MMFR0_EL1': ((3, 0, 0, 7, 0), 'r'), 'ID_AA64MMFR1_EL1': ((3, 0, 0, 7, 1), 'r'),
    'ID_AA64MMFR2_EL1': ((3, 0, 0, 7, 2), 'r'),
    'CTR_EL0': ((3, 3, 0, 0, 1), 'r'), 'DCZID_EL0': ((3, 3, 0, 0, 7), 'r'),
    'CNTFRQ_EL0': ((3, 3, 14, 0, 0), 'r'), 'CNTPCT_EL0': ((3, 3, 14, 0, 1), 'r'),
    'CNTVOFF_EL2': ((3, 4, 14, 0, 3), 'r'),
    'CNTKCTL_EL1': ((3, 0, 14, 1, 0), 'r'), 'CNTHCTL_EL2': ((3, 4, 14, 1, 0), 'r'),
    'VTTBR_EL2': ((3, 4, 2, 1, 0), 'r'), 'VTCR_EL2': ((3, 4, 2, 1, 2), 'r'), 'VNCR_EL2': ((3, 4, 2, 2, 0), 'r'),
    'VMPIDR_EL2': ((3, 4, 0, 0, 5), 'r'),
    'HCR_EL2': ((3, 4, 1, 1, 0), 'rw'), 'MDCR_EL2': ((3, 4, 1, 1, 1), 'rw'), 'CPTR_EL2': ((3, 4, 1, 1, 2), 'rw'),
    'CPACR_EL1': ((3, 0, 1, 0, 2), 'rw'),
    'MDSCR_EL1': ((2, 0, 0, 2, 2), 'rw'), 'OSLAR_EL1': ((2, 0, 1, 0, 4), 'w'), 'OSLSR_EL1': ((2, 0, 1, 1, 4), 'r'),
    'TTBR0_EL1': ((3, 0, 2, 0, 0), 'r'), 'TTBR1_EL1': ((3, 0, 2, 0, 1), 'r'), 'MAIR_EL1': ((3, 0, 10, 2, 0), 'r'),
    'TPIDR_EL2': ((3, 4, 13, 0, 2), 'r'),
    'ELR_EL2': ((3, 4, 4, 0, 1), 'w'), 'SPSR_EL2': ((3, 4, 4, 0, 0), 'w'),
}
BY_ENCODING = {encoding: name for name, (encoding, _) in ARCH.items()}
# The allocated ID registers of op0=3, op1=0, CRn=0 (Arm ARM): CRm=0's op2 1-4 and 7 are unallocated and
# UNDEFINED (with FEAT_IDST the A16 traps the read: v48); CRm 1-7's gaps are reserved.
ID_ALLOCATED = {(0, 0), (0, 5), (0, 6), *((1, n) for n in range(8)), *((2, n) for n in range(8)),
                (3, 0), (3, 1), (3, 2), (3, 4), (3, 5), (3, 6), (4, 0), (4, 1), (4, 2), (4, 4), (4, 5), (4, 7),
                (5, 0), (5, 1), (5, 2), (5, 4), (5, 5), (6, 0), (6, 1), (6, 2), (6, 3),
                (7, 0), (7, 1), (7, 2), (7, 3), (7, 4)}
ID_ROW = re.compile(r'^\s*X\((\w+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*([01])\)', re.M)


def system_moves(blob, start=0, end=None):
    """{(L, op0, op1, CRn, CRm, op2)}: every MRS (L=1) and MSR (register) word in blob[start:end]."""
    found = set()
    end = len(blob) if end is None else end
    for at in range(start - start % 4, end - 3, 4):
        w = int.from_bytes(blob[at:at + 4], 'little')
        if w & 0xffd00000 == 0xd5100000:
            found.add(((w >> 21) & 1, 2 + ((w >> 19) & 1), (w >> 16) & 7, (w >> 12) & 15, (w >> 8) & 15,
                       (w >> 5) & 7))
    return found


def id_row_problems(header):
    """Why a BOOT_RELOCATE_ID_REGS table would read something it must not; [] when every row is allowed."""
    problems, rows = [], ID_ROW.findall(between(header, '#define BOOT_RELOCATE_ID_REGS(X)', 'enum boot_relocate_id'))
    for name, op1, crn, crm, op2, _ in rows:
        encoding = (3, int(op1), int(crn), int(crm), int(op2))
        if ARCH.get(name, (None,))[0] != encoding:
            problems.append(f'{name}: {encoding} is not its allowlisted encoding')
        if encoding[1:3] != (0, 0) or (encoding[3], encoding[4]) not in ID_ALLOCATED:
            problems.append(f'{name}: {encoding} is not an allocated ID register')
    if not rows:
        problems.append('no rows')
    return problems


def source_accesses(text):
    """{(name, 'r'|'w')} of every MRS/MSR operand on lines guarded by #if SNAP_BOOT_RELOCATE."""
    lines, inside = guarded_regions(text)
    found = set()
    for number, line in enumerate(lines):
        if not inside[number]:
            continue
        for op, a, b in re.findall(r'\b(mrs|msr)\s+([%\w]+)\s*,\s*([%\w]+)', line):
            name = b if op == 'mrs' else a
            if re.fullmatch(r's3_', name, re.I):
                continue   # BOOT_ID_READ's template: its rows are checked by id_row_problems
            if name.startswith(('%', 'x')) and op == 'msr' and re.fullmatch(r'x\d+|xzr', a):
                continue
            found.add((name.upper(), 'r' if op == 'mrs' else 'w'))
    return found


def s3_encoding(name):
    match = re.fullmatch(r'S(\d)_(\d)_C(\d+)_C(\d+)_(\d)', name)
    return tuple(int(g) for g in match.groups()) if match else None


class Registers(unittest.TestCase):
    def test_allowlist_matches_llvm(self):
        names = sorted(ARCH)
        text = ''.join(f'mrs x0, {n}\n' if 'r' in ARCH[n][1] else f'msr {n}, x0\n' for n in names)
        out = subprocess.run(['/opt/homebrew/opt/llvm/bin/llvm-mc', '--triple=aarch64', '-mattr=+v9.4a',
                              '-show-encoding'], input=text, capture_output=True, text=True, check=True).stdout
        words = [int.from_bytes(bytes(int(b, 16) for b in m.split(',')), 'little')
                 for m in re.findall(r'encoding: \[([^\]]+)\]', out)]
        self.assertEqual(len(words), len(names), out)
        for name, w in zip(names, words):
            decoded = (2 + ((w >> 19) & 1), (w >> 16) & 7, (w >> 12) & 15, (w >> 8) & 15, (w >> 5) & 7)
            self.assertEqual(decoded, ARCH[name][0], name)
            self.assertNotIn(decoded[3], (11, 15) if decoded[0] == 3 else (), f'{name} is IMPLEMENTATION DEFINED')

    def test_id_table_reads_only_allocated_registers(self):
        self.assertEqual(id_row_problems(HEADER), [])
        rows = ID_ROW.findall(between(HEADER, '#define BOOT_RELOCATE_ID_REGS(X)', 'enum boot_relocate_id'))
        self.assertEqual(tuple(r[0] for r in rows), RUNTIME['BOOT_ID_NAMES'])
        shared = {r[0] for r in rows if r[5] == '1'}
        self.assertEqual(shared, {'ID_AA64PFR0_EL1', 'ID_AA64PFR1_EL1', 'ID_AA64ISAR0_EL1', 'ID_AA64ISAR1_EL1',
                                  'ID_AA64ISAR2_EL1', 'ID_AA64MMFR0_EL1'})
        # The checker refuses v48's mistake and its relatives.
        first = 'X(MIDR_EL1,         0, 0, 0, 0, 0)'
        self.assertEqual(HEADER.count(first), 1)
        for bad in ('X(MIDR_EL1,         0, 0, 0, 1, 0)', 'X(MIDR_EL1,         0, 0, 0, 7, 0)',
                    first + ' \\\n    X(ID_AA64MMFR3_EL1, 0, 0, 7, 5, 0)', first + ' \\\n    X(ID_AA64ISAR0_EL1, 0, 0, 6, 3, 1)',
                    first + ' \\\n    X(ID_AA64MMFR0_EL1, 0, 0, 7, 6, 0)', first + ' \\\n    X(SYS_APL, 0, 15, 2, 0, 0)'):
            with self.subTest(bad):
                self.assertNotEqual(id_row_problems(HEADER.replace(first, bad)), [])

    def test_guarded_source_accesses_are_allowlisted(self):
        seen = set()
        for label, text in (('xnuboot.c', SOURCE), ('xnuboot.S', VECTORS), ('secondary.S', SECONDARY)):
            lines, inside = guarded_regions(text)
            group = [f'{label}:{n + 1}: {line.strip()}' for n, line in enumerate(lines)
                     if inside[n] and 'id_register(' in line]
            self.assertEqual(group, [], 'the relocation path must not read the ID group through id_register')
            for name, mode in source_accesses(text):
                encoding = s3_encoding(name)
                resolved = BY_ENCODING.get(encoding) if encoding else name
                self.assertIn(resolved, ARCH, f'{label}: {name} is not allowlisted')
                self.assertIn(mode, ARCH[resolved][1], f'{label}: {name} accessed as {mode}')
                seen.add(resolved)
        # The table's reads are generated: BOOT_ID_READ is the only MRS template, and it uses only the row's fields.
        self.assertIn('"mrs %0, s3_" #op1 "_c" #crn "_c" #crm "_" #op2 : "=r"(id[BOOT_ID_##name])', SOURCE)
        self.assertLessEqual({'CNTVOFF_EL2', 'CTR_EL0', 'DCZID_EL0', 'ELR_EL2', 'SPSR_EL2', 'MPIDR_EL1'}, seen)


class Decode(unittest.TestCase):
    def test_a_run_that_never_took_the_lock_decodes(self):
        """installed-fresh-20261018-v48 stopped in preparation; its decode raised 'max() arg is an empty sequence'."""
        import struct
        import types
        sys.path.insert(0, str(ROOT / 'tools'))
        sys.path.insert(0, str(ROOT / 'probes'))
        from cycle_lib import speed_test
        from monitor_layout import MonitorLayout
        layout = MonitorLayout()
        sets, _ = runpy.run_path(str(ROOT / 'tools/test-wfi-resume.py'), run_name='flag_sets')['flag_sets']()
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / 'run'
            dest.mkdir()
            (dest / 'context.bin').write_bytes(bytes(layout.size('context')))
            params = bytearray(layout.size('params'))
            struct.pack_into('<Q', params, layout.offset('params', 'clock_host_hz'), 19200000)
            (dest / 'params.bin').write_bytes(bytes(params))
            (dest / 'report.bin').write_bytes(bytes(4096))
            summary = speed_test.decode(types.SimpleNamespace(root=ROOT), dest,
                                        dict(source_sha256={}, flags=sets['control'], variant='control',
                                             exit_code=4, exit_name='EL2 fault'))
            self.assertEqual((summary['cpus_active'], summary['wall_seconds'], summary['traps_total']), (0, 0.0, 0))
            self.assertIsNone(summary['lock_busy_fraction'])
            self.assertIsNone(summary['traps_per_second'])
            self.assertTrue((dest / 'summary.json').is_file() and (dest / 'decoded.json').is_file())


class Host(unittest.TestCase):
    def test_prime_flag_adds_the_monitor_define(self):
        import types
        sys.path.insert(0, str(ROOT / 'tools'))
        from cycle_lib import installed_fresh
        fresh = vars(installed_fresh)
        sets = {'control': ['-DBASE'], 'fast': ['-DBASE', '-DFAST']}
        for variant in sets:
            plain = types.SimpleNamespace(variant=variant)
            prime = types.SimpleNamespace(variant=variant, prime_secondaries=True)
            self.assertNotIn('-DSNAP_BOOT_RELOCATE=1', fresh['variant_flags'](sets, plain))
            self.assertEqual(fresh['variant_flags'](sets, prime)[-1], '-DSNAP_BOOT_RELOCATE=1')
            self.assertEqual(fresh['environment'](prime).get('SNAP_SMP_PRIME'), '1')
            self.assertNotIn('SNAP_SMP_PRIME', fresh['environment'](plain))


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (about two minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        sys.path.insert(0, str(ROOT.parent / 'q1n1' / 'tools'))
        import run  # noqa: E402  (import only: build() needs no hardware)
        sets, _ = runpy.run_path(str(ROOT / 'tools/test-wfi-resume.py'), run_name='flag_sets')['flag_sets']()
        sets = {'control': sets['control'], 'fast': sets['fast'], 'fast-wfi': sets['fast'] + ['-DSNAP_WFI_RESUME=1']}
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        self.assertLessEqual(set(expect), set(sets))
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='boot-relocate-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results = {}
        nm = Path(run.LLVM) / 'llvm-nm'
        try:
            for name, flags in sets.items():
                self.assertFalse(any('SNAP_BOOT_RELOCATE' in f for f in flags), name)
                blobs = {}
                for label, extra in (('default', []), ('off', ['-DSNAP_BOOT_RELOCATE=0']),
                                     ('on', ['-DSNAP_BOOT_RELOCATE=1'])):
                    run.FLAGS[:] = flags + extra
                    blob = run.build('xnuboot', out / f'{name}-{label}')
                    blobs[label] = blob
                    symbols = subprocess.run([str(nm), str(out / f'{name}-{label}' / 'xnuboot.elf')],
                                             capture_output=True, text=True, check=True).stdout
                    present = [s for s in SYMBOLS if re.search(r'\s' + s + r'$', symbols, re.M)]
                    results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                      sha256=hashlib.sha256(blob).hexdigest(), symbols=present)
                    self.assertGreater(budget - len(blob), 0, f'{name}-{label}')
                    self.assertEqual(present, list(SYMBOLS) if label == 'on' else [], f'{name}-{label}')
                self.assertEqual(blobs['default'], blobs['off'], name)
                self.assertNotEqual(blobs['default'], blobs['on'], name)
                # Every MRS/MSR encoding the define adds is an allowlisted register, accessed as allowed.
                added = system_moves(blobs['on']) - system_moves(blobs['default'])
                results[f'{name}-on']['added_system_registers'] = sorted(
                    f"{'mrs' if l else 'msr'} {BY_ENCODING.get(tuple(e), e)}" for l, *e in added)
                for read, *encoding in added:
                    register = BY_ENCODING.get(tuple(encoding))
                    self.assertIsNotNone(register, f'{name}: unlisted system register {encoding}')
                    self.assertIn('r' if read else 'w', ARCH[register][1], f'{name}: {register}')
                # The ID reader: exactly the table's registers and the two cache ones, and no call out of it.
                listing = subprocess.run([str(nm), '-S', str(out / f'{name}-on' / 'xnuboot.elf')],
                                         capture_output=True, text=True, check=True).stdout
                start, size = next((int(a, 16), int(s, 16)) for a, s, _, sym in
                                   (line.split() for line in listing.splitlines() if len(line.split()) == 4)
                                   if sym == 'boot_relocation_ids')
                reader = system_moves(blobs['on'], start, start + size)
                expected = {(1, *ARCH[n][0]) for n in (*RUNTIME['BOOT_ID_NAMES'], 'CTR_EL0', 'DCZID_EL0')}
                self.assertEqual(reader, expected, name)
                words = [int.from_bytes(blobs['on'][a:a + 4], 'little') for a in range(start, start + size, 4)]
                self.assertFalse([w for w in words if w & 0xfc000000 in (0x94000000, 0x14000000) or
                                  w & 0xfffffc1f == 0xd63f0000], f'{name}: boot_relocation_ids branches out')
                if name in expect:
                    self.assertEqual(results[f'{name}-default']['sha256'], expect[name], name)
        finally:
            run.FLAGS[:] = saved
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
