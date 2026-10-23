#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_FAST_EL0_SYSREG and SNAP_SERVICE_SUBCLASS: bind the lock-free EL0
emulation and the exit profile to the locked path, the vectors, the context
layout and the host decoder.

    python3 tools/test-fast-el0-sysreg.py
    python3 tools/test-fast-el0-sysreg.py --build [--out DIR]
                        [--expect NAME=SHA256 ...]

Offline, no hardware and no proxy. tools/test-fast-el0-sysreg.c (failure
modes F1-F13 in its header) runs compat/fast-vector.h's fast_el0_sysreg
through fast_cross_entry against a transcription of xnuboot_trap_locked's
vector branch and user_sysreg_access, sanitized and thread-sanitized; this
file checks that transcription and the monitor hooks against
probes/xnuboot.c and probes/xnuboot.S, requires every source mutant of the
deciders to FAIL the C test, runs tools/test-fast-vector.c with the class
compiled in (hooks absent), checks that every define combination keeps the
define-free context offsets and table-arena base, that the report record sits
where the decoder reads it, and decodes a C-written record.

--build compiles xnuboot with cycle.py's flag sets (control and fast, each
with and without -DSNAP_WFI_RESUME=1) with the defines absent, =0 and =1:
-Werror, the code budget, absent == =0, =1 differs. --expect NAME=SHA256
(NAME one of control, fast, control-wfi, fast-wfi) requires the default build
to equal a pre-change monitor byte for byte.

Failure inventory (beyond the C test's): the transcription drifting from
user_sysreg_access; the fast record differing from the locked one; the class
placed after the crash-class check or selecting the kernel regime; an EL0
return that skips the EL0 key reload; a sub-class tag outside its branch or
a charge after the release; the timing stamp missing from sync_lower or
consumed outside xnuboot_pauth_resume; an appended block that moves a
define-free offset or the arena; a decoder reading the wrong report bytes;
a default build that changed.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import os
import re
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
VECTORS = (ROOT / 'probes/xnuboot.S').read_text()
HEADER = (ROOT / 'compat/fast-vector.h').read_text()
PROFILE = (ROOT / 'compat/service-profile.h').read_text()
PERF = (ROOT / 'compat/perf-state.h').read_text()
ORACLE = (ROOT / 'tools/test-fast-el0-sysreg.c').read_text()
EL0 = '-DSNAP_FAST_EL0_SYSREG=1'
SUB = '-DSNAP_SERVICE_SUBCLASS=1'
WFI = '-DSNAP_WFI_RESUME=1'


def arguments():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--out', help='fresh directory for the monitor builds (default: a temporary one)')
    ap.add_argument('--expect', action='append', default=[], metavar='NAME=SHA256',
                    help='control, fast, control-wfi or fast-wfi: the default build must have this SHA-256')
    args, rest = ap.parse_known_args()
    if args.out and Path(args.out).exists():
        ap.error(f'--out {args.out} exists: use a fresh directory')
    return args, rest


ARGS, REST = arguments() if __name__ == '__main__' else (
    argparse.Namespace(build=False, out=None, expect=[]), [])


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin + len(start))]


def ordered(region, tokens):
    at = 0
    for token in tokens:
        found = region.find(token, at)
        if found < 0:
            raise AssertionError(f'{token!r} missing or out of order')
        at = found + len(token)
    return True


def flag_sets():
    """cycle_lib/speed_test.py flag_sets(): config/monitor-flags.json + ADDED (+FAST) + CENSUS."""
    tree = ast.parse((ROOT / 'tools/build-fast-traps-monitor.py').read_text())
    lists = {t.id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
             for t in n.targets if isinstance(t, ast.Name) and t.id in ('ADDED', 'FAST')}
    census = [ast.literal_eval(n.value) for n in ast.parse((ROOT / 'tools/cycle_lib/speed_test.py')
              .read_text()).body if isinstance(n, ast.Assign) and
              any(isinstance(t, ast.Name) and t.id == 'CENSUS' for t in n.targets)][0]
    base = json.loads((ROOT / 'config/monitor-flags.json').read_text())['flags']
    return dict(control=[*base, *lists['ADDED'], census],
                fast=[*base, *lists['ADDED'], *lists['FAST'], census]), lists['FAST']


def statements(block):
    return [s.strip() for s in re.split(r';\s*', block) if s.strip()]


class Source(unittest.TestCase):
    def test_defines_default_off(self):
        self.assertIn('#ifndef SNAP_FAST_EL0_SYSREG\n#define SNAP_FAST_EL0_SYSREG 0\n#endif\n'
                      '_Static_assert(!SNAP_FAST_EL0_SYSREG || (SNAP_FAST_CROSSINGS && SNAP_NATIVE_TABLES),', SOURCE)
        self.assertIn('#ifndef SNAP_SERVICE_SUBCLASS\n#define SNAP_SERVICE_SUBCLASS 0\n#endif\n'
                      '_Static_assert(!SNAP_SERVICE_SUBCLASS || SNAP_SERVICE_PROFILE,', SOURCE)
        self.assertLess(SOURCE.index('#define FAST_CROSS_EL0_SYSREG SNAP_FAST_EL0_SYSREG'),
                        SOURCE.index('#include "../compat/fast-vector.h"'))
        self.assertIn('#ifndef FAST_CROSS_EL0_SYSREG\n#define FAST_CROSS_EL0_SYSREG 0\n#endif', HEADER)
        self.assertIn('#ifndef SNAP_SERVICE_SUBCLASS\n#define SNAP_SERVICE_SUBCLASS 0\n#endif', VECTORS)
        # Without the define every hook is a no-op expression.
        for macro in ('SERVICE_SUB_TAG(c,tag)', 'FAST_EXIT_MARK(frame,slot)', 'FAST_EXIT_END(c,v,frame)'):
            self.assertIn(f'#define {macro} ((void)0)', SOURCE)

    def test_emulation_matches_user_sysreg_access(self):
        locked = between(SOURCE, 'static int user_sysreg_access(', '\n}\n')
        self.assertTrue(ordered(locked, [
            'if(vector!=0x400 || esr!=0x02000000 || pc>=(1UL<<47)-4)return 0;',
            'vncr_va+0x78', 'exception_user_return(0xd69f03e0,vhcr,pc+4,saved,&translated)',
            'user_return_root(c)', 'user_instruction_read(c,root,pc,&source,&hardware,&word)',
            'struct clock_backend backend={c,clock_counter,clock_control};',
            'struct sprr_state *sprr=&c->user_roots.sprr[v->slot];',
            'guest_clock_user_read(&v->clock,&backend,word,frame)', 'clock_result==CLOCK_OK',
            '(word&~31U)==0xd51ef1a0U', 'user_write_uperm(c,frame,pc,saved,word)',
            'sprr_user_read(sprr,word,frame)==SPRR_OK', 'else return 0;',
            'step_arm(c,0);guards_close(c);', 'msr spsr_el2, %0"::"r"(translated)', '*elr=pc+4;']))
        fast = between(HEADER, 'static inline unsigned fast_el0_sysreg(', '\n}\n')
        self.assertTrue(ordered(fast, [
            'if(vector!=0x400 || esr!=FAST_EL0_SYSREG_ESR)return FAST_EL0_NONE;',
            'pc<(UINT64_C(1)<<47)-4 && exception_user_return(FAST_EL0_ERET,vhcr,pc+4,saved,&translated)',
            'hw->fetch(hw->ctx,pc,&a)', 'fast_el0_word_kind(a.word)',
            '!v->clock || !hw->clock || !hw->clock->counter || !(v->clock->cntkctl&2)',
            '!sprr_fixed_state_valid(v->sprr)', 'hw->fetch(hw->ctx,pc,&b)',
            'a.source!=b.source || a.hardware!=b.hardware', 'a.pa!=b.pa || a.root!=b.root || a.word!=b.word',
            'guest_clock_user_read(v->clock,hw->clock,a.word,v->regs)!=CLOCK_OK',
            'sprr_user_read(v->sprr,a.word,v->regs)!=SPRR_OK', 'v->outcomes[result-1]++;',
            'hw->note(hw->ctx,result,pc,a.word,saved,a.root);', '*v->spsr_el2=translated;*elr=pc+4;']))
        # The accepted words are exactly the two functions' own.
        clock = (ROOT / 'compat/clock.c').read_text()
        sprr = (ROOT / 'compat/sprr.h').read_text()
        self.assertIn('if((instruction&~31U)!=0xd53cfac0U)return CLOCK_UNHANDLED;', clock)
        self.assertIn('if((instruction&~31U)!=0xd53ef1a0U)return SPRR_UNHANDLED;', sprr)
        self.assertIn('#define FAST_EL0_CLOCK_WORD 0xd53cfac0u', HEADER)
        self.assertIn('#define FAST_EL0_UPERM_WORD 0xd53ef1a0u', HEADER)
        self.assertIn('#define FAST_EL0_SYSREG_ESR UINT64_C(0x02000000)', HEADER)
        # The C oracle transcribes the same order.
        oracle = between(ORACLE, 'static int locked_sysreg_access(', '\n}\n')
        self.assertTrue(ordered(oracle, [
            'if(vector!=0x400 || esr!=0x02000000 || pc>=(UINT64_C(1)<<47)-4)return 0;',
            'exception_user_return(0xd69f03e0,vhcr,pc+4,saved,&translated)',
            'if(!w->root_ok || !w->read_ok)return 0;',
            'guest_clock_user_read(&c->clock,&backend,word,c->regs)', 'clock_result==CLOCK_OK',
            '(word&~31U)==0xd51ef1a0U', 'sprr_user_write(sprr,word,c->regs,model_change,0)',
            'sprr_user_read(sprr,word,c->regs)==SPRR_OK', 'else return 0;', '*spsr_el2=translated;',
            '*elr=pc+4;']))
        vector = between(SOURCE, 'if (p->vbar && (ipa & ~0xfffUL) == p->vbar) {', '/* A monitor call page.')
        entry = between(ORACLE, 'static int locked_entry(', '\n}\n')
        self.assertTrue(ordered(vector, ['pan->user_vectors++', 'pan->protected_vectors+=!!(physical_spsr&(1UL<<22));',
                                         'pan->vector=vector;pan->saved_spsr=saved;', 'pan->entry_spsr=physical_spsr;',
                                         'mrs %0, sctlr_el1":"=r"(pan->entry_sctlr)', 'user->pending',
                                         'exception_step_suspend(', 'user_sysreg_access(c,frame,g_elr,saved,g_esr,vector,elr)']))
        self.assertTrue(ordered(entry, ['vector>=0x400 && vector<=0x580 && !(saved&31)', 'c->user_vectors++',
                                        'c->protected_vectors+=!!(w->physical_spsr&(UINT64_C(1)<<22));',
                                        'c->vector=vector;c->saved_spsr=saved;c->entry_spsr=w->physical_spsr;',
                                        'c->entry_sctlr=w->sctlr;', 'locked_sysreg_access(']))
        block = between(HEADER, 'if(vector==0x400 && r.esr==FAST_EL0_SYSREG_ESR) {', '#endif')
        self.assertTrue(ordered(block, ['fast_el0_sysreg(hw->el0,v->el0,vector,r.esr,r.elr,r.spsr,',
                                        'hw->vhcr(hw->ctx),elr)', '(*v->user_vectors)++;',
                                        '*v->protected_vectors+=!!(physical_spsr&(UINT64_C(1)<<22));',
                                        '*v->vector=vector;*v->saved_spsr=r.spsr;',
                                        '*v->entry_spsr=physical_spsr;*v->entry_sctlr=r.sctlr;',
                                        'return FAST_CROSS_EL0_SYSREG_CLASS;']))
        # No regime selection, capture or first-occurrence mark for the class.
        for token in ('hw->cross(', 'hw->capture(', 'fast_cross_first(', 'fault_esr'):
            self.assertNotIn(token, block)

    def test_class_precedes_the_crash_check(self):
        entry = between(HEADER, 'static inline unsigned fast_cross_entry(', '\n}\n')
        self.assertTrue(ordered(entry, ['if(vector>=0x600 || (vector&0x7f) || (el0 && !hw->cross))return FAST_CROSS_NONE;',
                                        'if(mode!=(el0 ? 0u : vector>=0x200 ? 9u : 8u) || (r.spsr>>32))return FAST_CROSS_NONE;',
                                        '#if FAST_CROSS_EL0_SYSREG',
                                        'if(vector==0x400 && r.esr==FAST_EL0_SYSREG_ESR) {', '#endif',
                                        'if(!el0 && r.esr==(UINT64_C(1)<<25))return FAST_CROSS_NONE;',
                                        'user_crash_classify(r.esr,r.far,frame[16],frame[1])',
                                        'fast_cross_first(v,cls)', 'hw->cross(hw->ctx,0)']))
        self.assertIn('#define FAST_CROSS_EL0_SYSREG_CLASS FAST_CROSS_CLASSES', HEADER)

    def test_records_equal_the_locked_records(self):
        locked = between(SOURCE, 'static int user_sysreg_access(', '\n}\n')
        note = between(SOURCE, 'static void fast_el0_note(', '\n}\n')
        clock_l = between(locked, 'struct user_clock_state *u=&c->user_clock[v->slot];', 'SERVICE_SUB_TAG')
        clock_f = between(note, 'struct user_clock_state *u=&c->user_clock[v->slot];', '} else {')
        self.assertEqual(statements(clock_l.replace('root->root', 'root')), statements(clock_f))
        sprr_l = between(locked, 'struct user_sprr_state *u=&c->user_sprr[v->slot];', 'SERVICE_SUB_TAG')
        sprr_f = between(note, 'struct user_sprr_state *u=&c->user_sprr[v->slot];', '\n    }')
        self.assertEqual(statements(sprr_l.replace('root->root', 'root')), statements(sprr_f))
        self.assertIn('struct sprr_state *sprr=&c->user_roots.sprr[v->slot];', note)
        word = between(SOURCE, 'static int fast_el0_word(', '\n}\n')
        self.assertTrue(ordered(word, ['user_return_root(c)',
                                       'if(!root || !user_instruction_read(c,root,pc,&source,&hardware,&word))return 0;',
                                       '(struct fast_el0_fetch){source.descriptor,hardware.descriptor,source.pa,root->root,word}']))

    def test_monitor_hook_returns_through_the_key_reload(self):
        crossing = between(SOURCE, 'static int fast_crossing(', '\n}\n')
        self.assertTrue(ordered(crossing, [
            '#if SNAP_FAST_EL0_SYSREG', 'const struct clock_backend clock={c,clock_counter,clock_control};',
            '.fetch=fast_el0_word', '.note=fast_el0_note',
            '{&v->clock,&c->user_roots.sprr[v->slot],frame,', 'c->exit_profile.cpu[v->slot].el0,&el0_spsr};',
            '.el0=&el0_hw,', '&el0_state,', 'fast_cross_entry(&hw,&state,spsr,frame,elr)',
            'if(done==FAST_CROSS_NONE) {f->declined++;return 0;}',
            'if(ec==0x1a)__asm__ volatile("msr spsr_el2, %0"::"r"(next));',
            'else if(done==FAST_CROSS_EL0_SYSREG_CLASS)__asm__ volatile("msr spsr_el2, %0"::"r"(el0_spsr));',
            'else f->branches++;', 'native_exception_snapshot(c)', 'step_translation_clear(',
            'f->entries++', 'FAST_EXIT_MARK(frame,FAST_EXIT_CROSS_SLOT(done));', 'return 1;']))
        # The fast crossing's declines (lines synced, no step/guard/probe) are
        # what lets the class skip user_sysreg_access's step_arm/guards_close.
        for token in ('v->stepping.active || v->open_guards || c->user_execution[v->slot].pending',
                      '!(hcr&(1UL<<6))!=!fiq', '!(hcr&(1UL<<7))!=!v->model_irq_pending'):
            self.assertIn(token, crossing)
        # A 0 return resumes through xnuboot_pauth_resume, which installs the
        # EL0 keys when SPSR_EL2 names EL0, before the ERET.
        self.assertTrue(ordered(VECTORS, ['sync_lower:', 'bl xnuboot_trap', 'resume_lower:',
                                          'bl xnuboot_pauth_resume', 'msr elr_el2, x2', 'eret']))
        resume = between(SOURCE, 'int xnuboot_pauth_resume(const uint64_t *frame)\n{', '\n}\n')
        self.assertTrue(ordered(resume, ['mrs %0,spsr_el2', 'if(spsr&31) {FAST_EXIT_END(c,v,frame);return 0;}',
                                         'pauth_domain_user_cached(', 'pauth_switch_enter(bank)',
                                         'FAST_EXIT_END(c,v,frame);\n    return 0;']))
        trap = between(SOURCE, 'int xnuboot_trap(uint64_t *frame, uint64_t esr, uint64_t *elr)\n{', '\n}\n')
        self.assertTrue(ordered(trap, ['fast_vcpu_trap(', 'fast_crossing(c, frame, esr, elr)) return 0;',
                                       'runtime_enter(']))

    def test_subclass_hooks(self):
        locked = between(SOURCE, 'static int user_sysreg_access(', '\n}\n')
        self.assertTrue(ordered(locked, ['u->host_hz=v->clock_rate.host_hz;u->guest_hz=v->clock_rate.guest_hz;',
                                         'SERVICE_SUB_TAG(c,SERVICE_SUB_EL0_CLOCK);',
                                         'if(user_write_uperm(c,frame,pc,saved,word)!=SPRR_OK)return 0;',
                                         'SERVICE_SUB_TAG(c,SERVICE_SUB_EL0_UPERM_WRITE);',
                                         'u->root=root->root;u->umprr=sprr->umprr;',
                                         'SERVICE_SUB_TAG(c,SERVICE_SUB_EL0_UPERM);', 'else return 0;']))
        vector = between(SOURCE, 'if (p->vbar && (ipa & ~0xfffUL) == p->vbar) {', '/* A monitor call page.')
        self.assertIn('if (native_call_word(word)) {\n                        '
                      'SERVICE_SUB_TAG(c,service_sub_call(frame[16],SPTM_CMD_ENDPOINT));', vector)
        self.assertIn('if(user_sysreg_access(c,frame,g_elr,saved,g_esr,vector,elr))return 0;\n'
                      '                SERVICE_SUB_TAG(c,SERVICE_SUB_VECTOR);', vector)
        self.assertEqual(len(re.findall(r'SERVICE_SUB_TAG\(c,(?:SERVICE_SUB_|service_sub_call)', SOURCE)), 5)
        leave = between(SOURCE, 'static int runtime_leave(struct context *c, int stop)', '\n}\n')
        self.assertTrue(ordered(leave, ['int completed = c->service_profile[v->slot].stage == 2;',
                                        'service_profile_end(&c->service_profile[v->slot], service_profile_clock());',
                                        'service_sub_charge(&c->exit_profile.sub, (unsigned)v->slot,',
                                        'guest_service_release(&c->services, v->slot);']))
        # monitor_call_impl's endpoint split is the tag's.
        impl = between(SOURCE, 'static int monitor_call_impl(', '\n}\n')
        self.assertTrue(ordered(impl, ['uint32_t cmd = (uint32_t)((x16 >> 56) & 0xff);',
                                       'uint32_t domain = (uint32_t)((x16 >> 48) & 0xff);',
                                       'uint32_t table = (uint32_t)((x16 >> 32) & 0xffff);',
                                       'uint32_t endpoint = (uint32_t)x16;',
                                       'if (cmd == SPTM_CMD_ENDPOINT && domain == 0 && table == 0 &&',
                                       'endpoint < ENDPOINT_BUCKETS)']))
        self.assertIn('#define SPTM_CMD_ENDPOINT       0', SOURCE)
        tag = between(PROFILE, 'static inline unsigned service_sub_call(', '\n}\n')
        for token in ('(x16 >> 56) & 0xff', '(x16 >> 48) & 0xff', '(x16 >> 32) & 0xffff', '(uint32_t)x16',
                      'cmd == endpoint_command && !domain && !table && endpoint < SERVICE_SUB_ENDPOINTS'):
            self.assertIn(token, tag)

    def test_exit_timing_hooks(self):
        sync = between(VECTORS, 'sync_lower:', 'resume_lower:')
        self.assertTrue(ordered(sync, ['str x30, [sp, #(30 * 8)]', '#if SNAP_SERVICE_SUBCLASS',
                                       'mrs x9, cntpct_el0', 'str x9, [sp, #(31 * 8)]', '#endif',
                                       'pauth_bank_pointer', 'bl pauth_switch_leave', 'bl xnuboot_trap']))
        # The asynchronous path keeps its vector kind (1..3: class 0) in slot 31.
        self.assertIn('str x1,[sp,#(31 * 8)]', between(VECTORS, 'async_lower:', 'pauth_failed:'))
        vcpu = between(SOURCE, 'static int fast_vcpu_trap(', '\n}\n')
        self.assertTrue(ordered(vcpu, ['f->handled[done]++;', 'FAST_EXIT_MARK(frame,FAST_EXIT_TRAP_SLOT(done));',
                                       'return 1;']))
        idle = between(SOURCE, 'static int fast_idle_poll(', '\n}\n')
        self.assertTrue(ordered(idle, ['f->handled[FAST_TRAP_IDLE_POLL]++;',
                                       'FAST_EXIT_MARK(frame,FAST_EXIT_TRAP_SLOT(FAST_TRAP_IDLE_POLL));',
                                       '*elr+=4;return 1;']))
        self.assertEqual(SOURCE.count('FAST_EXIT_MARK(frame,FAST_EXIT_'), 3)
        self.assertEqual(SOURCE.count('FAST_EXIT_END(c,v,frame);'), 2)
        helper = between(SOURCE, 'static void fast_exit_end(', '\n}\n')
        self.assertIn('fast_exit_charge(&c->exit_profile.cpu[v->slot],frame[31],now);', helper)
        report = between(SOURCE, 'uint64_t xnuboot_report(uint64_t *out)\n{', '\n}\n')
        self.assertTrue(ordered(report, ['secondary_collect(c);', 'out[OUT_EARLY_STOP + n]',
                                         '#if SNAP_FAST_EL0_SYSREG || SNAP_SERVICE_SUBCLASS',
                                         'out[OUT_EXIT_PROFILE] = EXIT_PROFILE_MAGIC;',
                                         'out[OUT_EXIT_PROFILE + 2 + n] = ((const uint64_t *)&c->exit_profile)[n];',
                                         '#endif']))
        self.assertIn('#define OUT_EXIT_PROFILE (OUT_EARLY_STOP + EARLY_STOP_STATE_WORDS)', SOURCE)
        self.assertIn('struct exit_profile exit_profile;\n#endif\n};', SOURCE)


class Layout(unittest.TestCase):
    def test_define_free_offsets_and_arena_hold(self):
        perf = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
        sets, _ = flag_sets()
        base = [f for f in sets['fast'] if f.startswith('-D')] + [WFI]
        plain = perf['_records'](ROOT / 'probes/xnuboot.c', [])
        self.assertNotIn('exit_profile', plain['context'])
        fields = re.findall(r'^\s*(\d+) \|   (\S.*)$', plain['context'], re.M)
        size = perf['_size'](plain['context'])
        for extra in ([EL0], [SUB], [EL0, SUB]):
            records = perf['_records'](ROOT / 'probes/xnuboot.c', base + extra)
            context = records['context']
            self.assertEqual(re.findall(r'^\s*(\d+) \|   (\S.*)$', context, re.M)[:len(fields)], fields)
            lay = perf['exit_layout'](base + extra)
            self.assertEqual(lay['context_offset'], size)
            self.assertEqual((lay['context_size'] + 4095) // 4096, (size + 4095) // 4096)
            self.assertEqual((lay['size'], lay['cpu_stride'], lay['buckets'], lay['classes']), (2112, 192, 38, 18))
            self.assertEqual(perf['_size'](records['service_profile']), perf['_size'](plain['service_profile']))
            self.assertEqual(perf['_size'](records['perf_state']), perf['_size'](plain['perf_state']))
        print(f'exit profile at context+{size:#x}, {(-size) % 4096} bytes before the arena page; '
              f'report.bin+{perf["exit_profile_spec"](base + [SUB])[0]}', file=sys.stderr)

    def test_report_offset_is_the_monitors(self):
        perf = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
        sets, _ = flag_sets()
        flags = [f for f in sets['fast'] if f.startswith('-D')] + [WFI, EL0, SUB]
        offset, size = perf['exit_profile_spec'](flags)
        with tempfile.TemporaryDirectory() as d:
            probe = Path(d) / 'probe.c'
            probe.write_text(f'#include "{ROOT}/probes/xnuboot.c"\n'
                             f'_Static_assert(16 + 8*OUT_EXIT_PROFILE == {offset}, "report offset");\n'
                             f'_Static_assert(16 + 8*EXIT_PROFILE_WORDS == {size}, "record size");\n')
            subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only',
                            '-fsyntax-only', f'-I{ROOT / "shadow"}', f'-I{ROOT / "compat"}',
                            f'-I{ROOT.parent / "q1n1/platform/uefi"}', *flags, str(probe)],
                           cwd=ROOT, check=True, capture_output=True)


WRITER = r'''
#include <stdio.h>
#include <string.h>
#include "perf-state.h"
static struct exit_profile p;
int main(int argc,char **argv)
{
    (void)argc;
    uint64_t head[2]={UINT64_C(0x31464f5250544958),3|(uint64_t)sizeof p<<32};
    p.sub.buckets[SERVICE_SUB_VECTOR]=(struct service_profile_bucket){40,400,4000};
    p.sub.buckets[SERVICE_SUB_EL0_UPERM]=(struct service_profile_bucket){7,70,140};
    p.sub.buckets[SERVICE_SUB_ENDPOINT+6]=(struct service_profile_bucket){3,30,900};
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        struct fast_exit_cpu *c=&p.cpu[cpu];
        c->el0[0]=10+cpu;c->el0[1]=20+cpu;c->el0[2]=1;c->el0[3]=cpu;
        for(unsigned n=0;n<=cpu;n++) {
            fast_exit_charge(c,fast_exit_mark(1000,FAST_EXIT_TRAP_SLOT(1)),1030);
            fast_exit_charge(c,fast_exit_mark(5000,FAST_EXIT_CROSS_SLOT(7)),5050);
        }
    }
    FILE *f=fopen(argv[1],"wb");fwrite(head,sizeof head,1,f);fwrite(&p,sizeof p,1,f);fclose(f);
    printf("%zu\n",sizeof head+sizeof p);return 0;
}
'''


class Decoder(unittest.TestCase):
    def test_decode_a_c_written_record(self):
        perf = runpy.run_path(str(ROOT / 'tools/perf_counters.py'))
        sets, _ = flag_sets()
        flags = [f for f in sets['fast'] if f.startswith('-D')] + [EL0, SUB]
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'w.c').write_text(WRITER)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-Icompat', '-Ishadow', str(Path(d) / 'w.c'),
                            '-o', str(Path(d) / 'w')], cwd=ROOT, check=True)
            size = int(subprocess.run([str(Path(d) / 'w'), str(Path(d) / 'r.bin')], check=True,
                                      capture_output=True, text=True).stdout)
            raw = (Path(d) / 'r.bin').read_bytes()
        lay = perf['exit_layout'](flags)
        self.assertEqual(size, 16 + lay['size'])
        cpus = [dict(slot=0, cancelled=1, buckets=[dict(category=0x20, entries=51, wait_ticks=500, hold_ticks=5040)])]
        out = perf['decode_exit_profile'](raw, lay=lay, cpus=cpus, hz=19.2e6)
        s = out['summary']
        self.assertEqual((s['sub_entries'], s['sub_hold_ticks'], s['sub_wait_ticks']), (50, 5040, 500))
        self.assertEqual(out['sub'][0]['name'], 'vector')
        self.assertTrue(out['sub'][1]['name'].startswith('endpoint 0x06 UPDATE_DISJOINT'))
        self.assertEqual(s['el0'], dict(counter=75, uperm=135, declined_word=6, declined_guard=15))
        self.assertEqual(s['timing']['pacga'], dict(exits=21, ticks=630, mean_ticks=30.0,
                                                   mean_ns=30 / 19.2e6 * 1e9))
        self.assertEqual(s['timing']['el0_sysreg']['exits'], 21)
        self.assertEqual(s['max_ticks'], 50)
        # Refusals: no record, a wrong size word, time without entries, ticks
        # beyond exits x max, a broken refinement of EC 0x20.
        for at, value in ((0, 0), (8, 3 | (lay['size'] + 8) << 32),
                          (16 + lay['sub'] + 24 * 9 + 8, 5),
                          (16 + lay['cpu'] + lay['timing'], (1 << 36) | 999)):
            bad = bytearray(raw)
            struct.pack_into('<Q', bad, at, value)
            with self.assertRaises(ValueError):
                perf['decode_exit_profile'](bytes(bad), lay=lay)
        with self.assertRaises(ValueError):
            perf['decode_exit_profile'](raw, lay=lay, cpus=[dict(cpus[0], buckets=[dict(cpus[0]['buckets'][0],
                                                                                         hold_ticks=5041)])])
        with self.assertRaises(ValueError):
            perf['decode_exit_profile'](raw[:-8], lay=lay)
        # A build without the sub-class define must hold no timing.
        bad = bytearray(raw)
        struct.pack_into('<Q', bad, 8, 1 | lay['size'] << 32)
        with self.assertRaises(ValueError):
            perf['decode_exit_profile'](bytes(bad), lay=lay)
        # The command line reads the record out of a whole report.bin.
        offset, length = perf['exit_profile_spec'](flags)
        run = runpy.run_path(str(ROOT / 'probes/run.py'), run_name='exit_cli')
        report = bytearray(run['OUT_HEADROOM'])
        report[offset:offset + length] = raw
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'report.bin').write_bytes(report)
            text = subprocess.run([sys.executable, str(ROOT / 'tools/perf_counters.py'), '--report',
                                   str(Path(d) / 'report.bin'), '--hz', '19200000', '--defines', *flags],
                                  check=True, capture_output=True, text=True).stdout
        self.assertEqual(json.loads(text)['summary']['el0'], s['el0'])


def cc(out, sources, extra, include=(), unit=('-DFAST_CROSS_EL0_SYSREG=1',)):
    flags = ['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', *unit,
             *[f'-I{p}' for p in include], '-Icompat', '-Ishadow']
    subprocess.run([*flags, *extra, *sources, '-o', str(out)], cwd=ROOT, check=True, timeout=300,
                   capture_output=True)
    return out


SOURCES = ['tools/test-fast-el0-sysreg.c', 'compat/clock.c', 'compat/exception.c', 'compat/service-lock.c']


def build_test(directory, extra, include=()):
    """The test unit linked with its plain unit (the class compiled out)."""
    plain = cc(directory / 'plain.o', ['-c', 'tools/test-fast-el0-sysreg.c'], extra, include,
               unit=('-DFAST_EL0_PLAIN_UNIT=1', '-DFAST_CROSS_EL0_SYSREG=0'))
    return cc(directory / 'test', [*SOURCES, str(plain)], extra, include)
ASAN = ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']
# (file, original, mutant): each must make the C test fail. Not listed, because
# equivalent: dropping the PC-range test (exception_user_return already refuses
# pc+4 at 2^47 and any misaligned PC) or the clock/SPRR pre-guards
# (guest_clock_user_read and sprr_user_read refuse the same states unchanged).
MUTANTS = [
    ('fast-vector.h', '(!hw->fetch(hw->ctx,pc,&b) || a.source!=b.source || a.hardware!=b.hardware ||\n'
                      '                 a.pa!=b.pa || a.root!=b.root || a.word!=b.word)', '0'),
    ('fast-vector.h', 'if(vector==0x400 && r.esr==FAST_EL0_SYSREG_ESR) {', 'if(vector==0x400) {'),
    ('fast-vector.h', 'if(vector==0x400 && r.esr==FAST_EL0_SYSREG_ESR) {',
                      'if(vector==0x400 && r.esr==FAST_EL0_SYSREG_ESR && !hw->crash_ring) {'),
    ('fast-vector.h', '*v->spsr_el2=translated;*elr=pc+4;', '*v->spsr_el2=translated;*elr=pc;'),
    ('fast-vector.h', '*v->spsr_el2=translated;', '*v->spsr_el2=translated|(UINT64_C(1)<<22);'),
    ('fast-vector.h', 'if((word&~31u)==FAST_EL0_UPERM_WORD)return FAST_EL0_UPERM;',
                      'if((word&~31u)==FAST_EL0_UPERM_WORD || (word&~31u)==0xd51ef1a0u)return FAST_EL0_UPERM;'),
    ('fast-vector.h', '*v->entry_spsr=physical_spsr;*v->entry_sctlr=r.sctlr;\n        return FAST_CROSS_EL0_SYSREG_CLASS;',
                      'return FAST_CROSS_EL0_SYSREG_CLASS;'),
    ('fast-vector.h', 'hw->note(hw->ctx,result,pc,a.word,saved,a.root);', ''),
    ('fast-vector.h', 'v->outcomes[result-1]++;', ''),
    ('fast-vector.h', 'return FAST_CROSS_EL0_SYSREG_CLASS;', 'hw->cross(hw->ctx,0);return FAST_CROSS_EL0_SYSREG_CLASS;'),
    ('service-profile.h', 'if (!completed || p->category', 'if (p->category'),
    ('service-profile.h', 's->current[cpu] = SERVICE_SUB_OTHER;\n', ''),
    ('service-profile.h', 'b->wait_ticks += p->acquire_tick - p->enter_tick;',
                          'b->wait_ticks += p->last_tick - p->enter_tick;'),
    ('service-profile.h', 'endpoint < SERVICE_SUB_ENDPOINTS ?', 'endpoint < 64 ?'),
    ('perf-state.h', 'if (!slot || slot > FAST_EXIT_CLASSES) return;', 'if (slot > FAST_EXIT_CLASSES) return;'),
    ('perf-state.h', '{ p->slow++; return; }', '{ p->slow++; }'),
]


class Native(unittest.TestCase):
    def test_sanitized_and_thread_sanitized(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / 'a').mkdir()
            (d / 't').mkdir()
            asan = build_test(d / 'a', ASAN)
            tsan = build_test(d / 't', ['-fsanitize=thread', '-pthread', '-DFAST_EL0_THREADS=1'])
            env = dict(os.environ, TSAN_OPTIONS='halt_on_error=1:exitcode=66')
            for binary in (asan, tsan):
                result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=600, env=env)
                self.assertEqual(result.returncode, 0, result.stderr[-2000:])
                self.assertIn('PASS:', result.stdout)
                print(result.stdout.strip().splitlines()[0], file=sys.stderr)

    def test_fast_vector_suite_with_the_class_compiled_in(self):
        with tempfile.TemporaryDirectory() as d:
            binary = cc(Path(d) / 'fv', ['tools/test-fast-vector.c', 'compat/exception.c',
                                          'compat/service-lock.c', 'compat/clock.c'],
                        [*ASAN, '-Wno-missing-field-initializers'])
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=600)
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            self.assertIn('PASS:', result.stdout)

    def test_mutants_fail(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            survived = []
            for n, (name, original, mutant) in enumerate(MUTANTS):
                text = (ROOT / 'compat' / name).read_text()
                self.assertEqual(text.count(original), 1, (name, original))
                tree = d / f'm{n}'
                tree.mkdir()
                # Every compat header beside the mutant, so a header that
                # includes it from its own directory sees the mutant too.
                for header in (ROOT / 'compat').glob('*.h'):
                    (tree / header.name).write_bytes(header.read_bytes())
                (tree / name).write_text(text.replace(original, mutant))
                try:
                    binary = build_test(tree, ASAN, include=[tree])
                except subprocess.CalledProcessError:
                    continue      # a mutant that does not compile is killed too
                result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=600)
                if result.returncode == 0:
                    survived.append((name, original[:60]))
            self.assertEqual(survived, [])
            print(f'{len(MUTANTS)} decider mutants, all killed', file=sys.stderr)


@unittest.skipUnless(ARGS.build, 'pass --build to compile the monitor (a few minutes)')
class Build(unittest.TestCase):
    def test_monitor_builds(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        import run  # noqa: E402  (import only: build() needs no hardware)
        sets, _ = flag_sets()
        for flags in sets.values():
            self.assertFalse(any(f.startswith(('-DSNAP_FAST_EL0_SYSREG', '-DSNAP_SERVICE_SUBCLASS')) for f in flags))
        expect = dict(e.split('=', 1) for e in ARGS.expect)
        out = Path(ARGS.out) if ARGS.out else Path(tempfile.mkdtemp(prefix='fast-el0-sysreg-build-'))
        budget = run.OUT_AT - run.CODE_AT
        saved = list(run.FLAGS)
        results = {}
        variants = (('default', []), ('off', ['-DSNAP_FAST_EL0_SYSREG=0', '-DSNAP_SERVICE_SUBCLASS=0']),
                    ('el0', [EL0]), ('sub', [SUB]), ('both', [EL0, SUB]))
        try:
            for set_name, base in sets.items():
                for wfi in ([], [WFI]):
                    name = set_name + ('-wfi' if wfi else '')
                    blobs = {}
                    for label, extra in variants:
                        if set_name == 'control' and EL0 in extra:
                            continue      # the class needs the fast crossings (static assert)
                        run.FLAGS[:] = base + wfi + extra
                        blob = run.build('xnuboot', out / f'{name}-{label}')
                        blobs[label] = blob
                        results[f'{name}-{label}'] = dict(bytes=len(blob), headroom=budget - len(blob),
                                                          sha256=hashlib.sha256(blob).hexdigest())
                        self.assertGreater(budget - len(blob), 0, f'{name}-{label}')
                    self.assertEqual(blobs['default'], blobs['off'], name)
                    for label in blobs.keys() - {'default', 'off'}:
                        self.assertNotEqual(blobs['default'], blobs[label], f'{name}-{label}')
                    if name in expect:
                        self.assertEqual(results[f'{name}-default']['sha256'], expect[name],
                                         f'{name}: the default build changed')
        finally:
            run.FLAGS[:] = saved
        (out / 'result.json').write_text(json.dumps(results, indent=1) + '\n')
        print(json.dumps(results, indent=1), file=sys.stderr)


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(argv=[sys.argv[0], *REST])
