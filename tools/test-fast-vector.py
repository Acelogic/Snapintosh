#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_VECTOR_BRANCH, SNAP_ERET_SNAPSHOT and SNAP_FAST_CROSSINGS: bind the
lock-free exception boundary to the actual locked branches and the pinned kernel.

tools/test-fast-vector.c runs compat/fast-vector.h against a transcription of
xnuboot_trap_locked's vector-page and ERET branches. This test reads
probes/xnuboot.c and fails if that transcription no longer matches: a new or
reordered step in either branch means the fast classes must be re-derived
before the fast path may stay enabled. It also checks that every
open-and-step site of the vector branch tries the slot branch first, that the
lock-free wrapper declines what the fast-trap wrapper declines, and that an
ERET refreshes the native-call snapshot. Against the pinned kernelcache it
checks that every AArch64 vector slot is a B out of the vector page (the
AArch32 slots are NOPs, which keep the step) and runs the C window proof on
exception_return's words, which must lie in the const prefix. Finally it
builds and runs the C test (sanitized, thread-sanitized) and checks that the
pre-change trap-entry model fails the lock regression.
"""
from pathlib import Path
import importlib
import os
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = read_source(ROOT / 'probes/xnuboot.c')
ORACLE = (ROOT / 'tools/test-fast-vector.c').read_text()
HEADER = (ROOT / 'compat/fast-vector.h').read_text()
KERNELCACHE = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
VBAR_VA = 0xfffffe000b86c000
SITE5, ERET_VA = 0xfffffe000b86fe88, 0xfffffe000b870048


def between(text, start, end, after=0):
    begin = text.index(start, after)
    return text[begin:text.index(end, begin)]


def ordered(region, tokens):
    positions = [region.index(token) for token in tokens]
    return positions == sorted(positions)


def locked():
    body = between(SOURCE, 'static int xnuboot_trap_locked(', '\nint xnuboot_trap(')
    vector = between(body, 'if (p->vbar && (ipa & ~0xfffUL) == p->vbar) {', '/* A monitor call page.')
    eret = between(body, 'if (ec == 0x1a) {', 'if (ec == 0x09 && generic_pauth_supported())')
    return body, vector, eret


class FastVectorSource(unittest.TestCase):
    def test_vector_branch_matches_the_oracle(self):
        _, vector, _ = locked()
        source = ['g_esr==(1UL<<25)', 'native_call_word(word)', 'pan->user_vectors++',
                  'user_sysreg_access(', 'user_enter_mode(c,0)', 'vector == 0x100',
                  'timer_vectors++', 'vector == 0x80', 'model_irq_vectors++', 'c->skip_undef',
                  'capture_regs(', 'exception_user_sync(', 'uec==0x3c', 'user_crash_classify(',
                  'exception_kernel_page_fault(g_esr) || user_sync || p->permissive || p->let_panic']
        self.assertTrue(ordered(vector, source))
        oracle = between(ORACLE, 'static enum route locked_entry(', 'static enum route locked_return(')
        mirror = ['g_esr==(UINT64_C(1)<<25)', 'native_call_word(word)', 'c->user_vectors++',
                  'w->sysreg_ok', 'locked_cross(c,w,0)', 'vector==0x100', 'c->timer_vectors++',
                  'vector==0x80', 'c->model_irq_vectors++', 'w->skip_undef', 'model_capture(',
                  'exception_user_sync(', 'uec==0x3c', 'user_crash_classify(',
                  'exception_kernel_page_fault(g_esr) || user_sync || w->permissive || w->let_panic']
        self.assertTrue(ordered(oracle, mirror))
        # The same user-sync, signal and crash classes, in both.
        for text in (vector, oracle):
            self.assertIn('uec==0x3c || uec==0x00 || uec==0x0e || uec==0x1c || uec==0x22 || uec==0x26', text)
        # Every open-and-step continuation of the vector page tries the slot
        # branch first, and nothing else opens the vector guard.
        opens = [m.start() for m in re.finditer(r'guard_open\(c, g\);', vector)]
        self.assertEqual(len(opens), 3)
        for at in opens:
            self.assertTrue(vector[:at].rstrip().endswith(
                '#if SNAP_VECTOR_BRANCH\n                    if (vector_branch(c, elr)) return 0;\n#endif'))
        helper = between(SOURCE, 'static int vector_branch(', '\n}\n')
        for token in ('fast_vector_branch(', 'p->vbar | (*elr & 0xfff)', 'step_arm(c, 0);',
                      'guards_close(c);', '*elr = target;'):
            self.assertIn(token, helper)

    def test_eret_branch_matches_the_oracle(self):
        _, _, eret = locked()
        source = ['guest_pa(*elr)', 'mrs %0, elr_el1', 'mrs %0, spsr_el1',
                  'pa >= p->mem_low && pa <= p->mem_high - 4', 'vncr_va + 0x78', 'guest_pa(target)',
                  'target_pa >= p->mem_low && target_pa <= p->mem_high - 4',
                  'exception_kernel_return(word, vhcr, target, spsr, &translated)',
                  'kernel_returns++', 'last_kernel_return = target',
                  'exception_monitor_origin(*elr,physical_spsr)',
                  'exception_user_return(word,vhcr,target,spsr,&translated)', 'user_return_root(c)',
                  'user_enter_mode(c,1)', '!user->returns && user_entry_snapshot', 'user->returns++',
                  'user->pending=1', 'EV_RETURN_REFUSED']
        self.assertTrue(ordered(eret, source))
        oracle = between(ORACLE, 'static enum route locked_return(', '\n}\n')
        mirror = ['w->eret_pa', 'pa>=MEM_LOW && pa<=MEM_HIGH-4', 'w->vhcr', 'w->elr1_pa',
                  'target_pa>=MEM_LOW && target_pa<=MEM_HIGH-4',
                  'exception_kernel_return(word,vhcr,target,spsr,&translated)', 'c->kernel_returns++',
                  'c->last_kernel_return=target', 'exception_monitor_origin(*elr,physical_spsr)',
                  'exception_user_return(word,vhcr,target,spsr,&translated)', 'w->root_ok',
                  'locked_cross(c,w,1)', '!c->returns && w->probe_ok', 'c->returns++', 'c->pending=1',
                  'R_REFUSED']
        self.assertTrue(ordered(oracle, mirror))
        # The fast return reads the same words through the same helpers.
        fast = between(HEADER, 'static inline unsigned fast_cross_return(', '\n}\n')
        for token in ('pa>=hw->mem_low && pa<=hw->mem_high-4', 'exception_kernel_return(',
                      'exception_monitor_origin(*elr,physical_spsr)', 'exception_user_return(',
                      '!*v->returns', 'hw->user_root(', 'hw->cross(hw->ctx,1)'):
            self.assertIn(token, fast)

    def test_wrapper_and_snapshot(self):
        trap = between(SOURCE, 'int xnuboot_trap(uint64_t *frame, uint64_t esr, uint64_t *elr)\n{',
                       '\n}\n')
        self.assertTrue(ordered(trap, ['fast_vcpu_trap(', 'fast_crossing(', 'runtime_enter(',
                                       'xnuboot_trap_locked(', '(SNAP_ERET_SNAPSHOT && (esr>>26)==0x1a)',
                                       'native_exception_snapshot(c)', 'runtime_leave(']))
        crossing = between(SOURCE, 'static int fast_crossing(', '\n}\n')
        vcpu = between(SOURCE, 'static int fast_vcpu_trap(', '\n}\n')
        declines = ['guest_service_admitted(&c->services,(unsigned)v->slot)',
                    '__atomic_load_n(&c->kernel_view_failed,__ATOMIC_RELAXED)',
                    '__atomic_load_n(&c->user_view_failed,__ATOMIC_RELAXED)',
                    '__atomic_load_n(&c->root_install_failures,__ATOMIC_RELAXED)',
                    'v->stepping.active || v->open_guards || c->user_execution[v->slot].pending',
                    '(!v->slot && fast_secondary_pending(c))']
        # fast_vcpu_trap and the idle poll take the same declines through
        # fast_admitted (docs/FAST-TRAP-BATCH2-20261016.md).
        admitted = between(SOURCE, 'static int fast_admitted(', '\n}\n')
        idle = between(SOURCE, 'static int fast_idle_poll(', '\n}\n')
        for token in declines:
            self.assertIn(token, crossing)
            self.assertIn(token.replace('v->stepping.active || v->open_guards || ',
                                        '!v->stepping.active && !v->open_guards && !'), admitted)
        self.assertIn('fast_admitted(c,v,esr)', vcpu)
        self.assertIn('fast_admitted(c,v,esr)', idle)
        self.assertIn('native_call_snapshot_required(esr,0)', admitted)
        for token in ("far!=*elr", "(esr&(1UL<<7))", "(guest_pa(far)&~0xfffUL)!=p->vbar",
                      "(spsr&31)!=4 && (spsr&31)!=5", 'msr spsr_el2', 'native_exception_snapshot(c)',
                      'step_translation_clear(', '.cross=FAST_SELECT', '.user_root=fast_user_root',
                      # The locked boundary's step_arm(c, 0) re-derives the virtual
                      # lines (guest_interrupt_sync): only a synced line may skip it.
                      'v->timer_pending || __atomic_load_n(&v->ipi.pending,__ATOMIC_RELAXED)',
                      '!(hcr&(1UL<<6))!=!fiq', '!(hcr&(1UL<<7))!=!v->model_irq_pending'):
            self.assertIn(token, crossing)
        sync = between(SOURCE, 'static void guest_interrupt_sync(', '\n}\n')
        for token in ('guest_ipi_fiq(&vcpu_of(c)->ipi,vcpu_of(c)->timer_pending)',
                      'vcpu_of(c)->model_irq_pending', '(1UL << 6)', '(1UL << 7)'):
            self.assertIn(token, sync)
        # EL0 crossings select through native tables only; otherwise decline.
        select = between(SOURCE, '/* EL0 crossings select through native tables', '#define FAST_SELECT 0\n#endif')
        self.assertTrue(ordered(select, ['#if SNAP_NATIVE_TABLES', 'static int fast_select(',
                                         'user_cached(c,c->user_roots.active[cpu])',
                                         'native_cross(c,cpu,el0)', 'user_hw_root(c,e,cpu)',
                                         '__atomic_store_n(&c->user_view_failed,1,__ATOMIC_RELAXED)',
                                         '#define FAST_SELECT fast_select', '#else']))
        if 'static int native_cross(' in SOURCE:
            # Merged with native tables: the lock-free selection keeps exactly
            # the locked crossing's checks (native_cross, then the variant root).
            enter = between(SOURCE, 'static int user_enter_mode(struct context *c,int el0)', '\n}\n')
            self.assertIn('if(!native_cross(c,cpu,el0) || u->shadow!=user_hw_root(c,e,cpu))', enter)
        # Without a selection no EL0 crossing is fast, before any other read.
        self.assertIn('if(vector>=0x600 || (vector&0x7f) || (el0 && !hw->cross))return FAST_CROSS_NONE;', HEADER)
        self.assertIn('!hw->cross || !*v->returns || !hw->user_root(hw->ctx) ||', HEADER)
        self.assertIn('return user_return_root(ctx)!=0;', SOURCE)
        prepare = between(SOURCE, 'static int64_t vcpu_arch_prepare(struct context *c)\n{', '\n}\n')
        self.assertTrue(ordered(prepare, ['guest_pa(site->va)!=expected', 'eret_window_proof(c)',
                                          'native_writer_debug_install_armed(']))
        self.assertIn('NATIVE_WRITER_ARMED_ALL&~(1u<<NATIVE_WRITER_RETURN_SITE)', prepare)
        proof = between(SOURCE, 'static int eret_window_proof(', '\n}\n')
        for token in ('native_writer_sites[NATIVE_WRITER_RETURN_SITE].va', 'guest_pa(va+4*i)',
                      'pa<p->const_begin || pa+4>p->const_end',
                      'native_writer_return_window(words,i+1)==i'):
            self.assertIn(token, proof)
        # SNAP_NATIVE_WFE: TWE cleared per CPU; the guest's stream rescaled.
        self.assertTrue(ordered(prepare, ['if (SNAP_NATIVE_WFE) {', 'hcr & ~(1UL << 14)']))
        control = between(SOURCE, 'static int clock_control(void *ctx, uint64_t value)', '\n}\n')
        self.assertTrue(ordered(control, ['#if SNAP_NATIVE_WFE', 'clock_event_host_control(value,',
                                          '#else', 'value & ~4UL', '#endif', 'msr cntkctl_el1']))


def kernel_word(image, data, va):
    for _, vmaddr, vmsize, fileoff, filesize in image.segments:
        if vmaddr <= va < vmaddr + min(vmsize, filesize):
            return struct.unpack_from('<I', data, fileoff + va - vmaddr)[0]
    raise ValueError(hex(va))


@unittest.skipUnless(KERNELCACHE.exists(), 'pinned kernelcache not extracted')
class PinnedKernel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / 'tools'))
        kc_load = importlib.import_module('kc-load')
        cls.data = KERNELCACHE.read_bytes()
        cls.image = kc_load.Image(cls.data)

    def test_vector_slots_branch_out_of_the_page(self):
        for slot in range(16):
            va = VBAR_VA + slot * 0x80
            word = kernel_word(self.image, self.data, va)
            if slot >= 12:
                self.assertEqual(word, 0xd503201f, hex(va))       # AArch32: NOP, keeps the step
                continue
            self.assertEqual(word >> 26, 0x05, hex(va))            # B imm26
            offset = (word & 0x3ffffff) - ((word & 0x2000000) << 1)
            target = va + 4 * offset
            self.assertNotEqual(target >> 12, va >> 12, hex(va))
            self.assertGreaterEqual(target, 0xffff800000000000)

    def test_return_window_proof(self):
        sys.path.insert(0, str(ROOT / 'probes'))
        begin_va = self.image.vmin
        loader = (ROOT / 'probes/xnuboot.py').read_text()
        self.assertIn('def const_region_contract(image, image_pa):', loader)
        # The const prefix, as const_region_contract derives it (VA form).
        end = self.image.vmin
        for name, va, size, maxprot, initprot in sorted(self.image.segment_protections,
                                                          key=lambda s: s[1]):
            if not size:
                continue
            if (maxprot | initprot) & 2:
                break
            end = va + size
        self.assertTrue(begin_va <= SITE5 and ERET_VA + 4 <= end)
        words = [kernel_word(self.image, self.data, SITE5 + 4 * i)
                 for i in range((ERET_VA - SITE5) // 4 + 1)]
        self.assertEqual(words[0], 0xd5184002)
        self.assertEqual(words[-1], 0xd69f03e0)
        self.assertEqual(words.index(0xd69f03e0), len(words) - 1)
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            binary = build(d, 'window', [])
            for label, dump, want in (('live', words, len(words) - 1),
                                      ('call', words[:40] + [0x94000000] + words[41:], 0),
                                      ('call word', words[:50] + [0x00201420] + words[51:], 0)):
                (d / 'window.bin').write_bytes(struct.pack(f'<{len(dump)}I', *dump))
                out = subprocess.run([str(binary), '--window', str(d / 'window.bin')],
                                     capture_output=True, text=True, timeout=60, check=True)
                self.assertEqual(int(out.stdout), want, label)


def build(directory, name, extra):
    flags = ['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Icompat', '-Ishadow']
    sources = ['tools/test-fast-vector.c', 'compat/exception.c', 'compat/service-lock.c']
    sanitize = extra or ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']
    subprocess.run([*flags, *sanitize, *sources, '-o', str(directory / name)],
                   cwd=ROOT, check=True, timeout=120)
    return directory / name


class FastVectorNative(unittest.TestCase):
    def test_native_behaviour(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            builds = {'asan': [], 'tsan': ['-fsanitize=thread', '-pthread', '-DFAST_VECTOR_THREADS=1'],
                      'pre': ['-fsanitize=address,undefined', '-DFAST_VECTOR_PRE_CHANGE=1']}
            binaries = {name: build(d, name, extra) for name, extra in builds.items()}
            env = dict(os.environ, TSAN_OPTIONS='halt_on_error=1:exitcode=66')
            for name in ('asan', 'tsan'):
                result = subprocess.run([str(binaries[name])], capture_output=True, text=True,
                                        timeout=600, env=env)
                self.assertEqual(result.returncode, 0, result.stderr[-2000:])
                self.assertIn('PASS:', result.stdout)
            pre = subprocess.run([str(binaries['pre'])], capture_output=True, text=True, timeout=600)
            self.assertNotEqual(pre.returncode, 0)
            self.assertIn('e.acquisitions<=FAST_CROSS_CLASSES', pre.stderr)


if __name__ == '__main__':
    unittest.main()
