#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SNAP_PAUTH_EL0_LIVE: the EL0 reads fast_el0_sysreg answers return to EL0 with
the process's PAC bank still installed (no pauth_switch_leave, no
pauth_switch_enter). Offline; no hardware, no proxy, nothing written under build/.

    PYTHONPATH=DEPS python3 tools/test-pauth-el0-live.py [--elf MONITOR.elf ...]

DEPS holds unicorn and capstone (as for tools/test-pauth-switch.py; build/test-python-deps
is also searched). Failure modes, written before the code (numbers as in the design note):
  1  wrong bank live at EL1: a live entry handled as a class that resumes EL1;
  2  a PAC instruction or key/SCTLR_EL1/HCR_EL2 write at EL2 while the process bank is live;
  3  HCR_EL2 rewritten by C before the restore (lost on restore);
  4  a declined live attempt counted or emulated twice;
  5  entry_sctlr evidence carrying the process's enables;
  6  a restore path missed (every non-candidate must be exactly pauth_switch_leave);
  12 the exit not charged, or charged elsewhere;
  13 a default build that changed (checked by the offline builds, not here).

  replay  compat/pauth-switch.S assembled with the define (and with SNAP_NATIVE_PACGA too) runs
          in unicorn with modeled system registers: after pauth_switch_enter, the candidate
          (EC 0x20 from a lower EL, ESR_EL1 0x02000000, SPSR_EL1 EL0t, slot offset 0x400)
          returns 0 with no register write and the bank unchanged; every other entry,
          including an inactive bank, a latched failure and a corrupted readback, is byte
          for byte pauth_switch_leave (return value, register writes, final registers, bank).
  hooks   probes/xnuboot.S and probes/xnuboot.c call sites under the define.
  --elf   binary audit of a monitor built with the define: el0_live_trap and everything it can
          reach (direct calls and branches, and every function whose address it materializes
          with ADR, i.e. the callbacks its indirect calls take; pauth_switch_leave, the restore,
          excepted) holds no PAC-class instruction, no key-register access and no
          SCTLR_EL1/SCTLR_EL2/HCR_EL2/TCR_EL2 write; el0_live_trap restores exactly once;
          sync_lower calls pauth_switch_live and nothing else calls it. The closure
          over-approximates the live path (it includes the other crossing classes).
"""
from pathlib import Path
import argparse
import json
import re
import struct
import subprocess
import sys
import tempfile
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path('/opt/homebrew/opt/llvm/bin')
LLD = '/opt/homebrew/opt/lld/bin/ld.lld' if Path('/opt/homebrew/opt/lld/bin/ld.lld').exists() else str(LLVM / 'ld.lld')
sys.path.append(str(ROOT / 'build/test-python-deps'))
KEYS = [k + 'key' + half + '_el1' for k in ('apia', 'apib', 'apda', 'apdb', 'apga') for half in ('lo', 'hi')]
BASE = 0x1000000
BUFFER = BASE + 0x10000
RETURN = BASE + 0x1f000
VBAR = 0xfffffe000b86c000
EL2_EC = 0x20 << 26
CANDIDATE = dict(esr_el2=EL2_EC | (1 << 25) | 0x0f, esr_el1=0x02000000, spsr_el1=0, elr_el2=VBAR + 0x400)
STATE = 256
OFF_ACTIVE, OFF_FAILURES = 184, 208


def assemble(tmp, defines):
    """Assemble and link at BASE: pauth_switch_live branches to the global pauth_switch_leave through a
    relocation, which the monitor's link resolves the same way."""
    obj, elf, out = tmp / 'pauth-switch.o', tmp / 'pauth-switch.elf', tmp / 'pauth-switch.bin'
    subprocess.run([str(LLVM / 'clang'), '--target=aarch64-none-elf', *defines, '-c',
                    str(ROOT / 'compat/pauth-switch.S'), '-o', str(obj)], check=True)
    subprocess.run([LLD, '-e', '0', f'-Ttext={BASE:#x}', '-o', str(elf), str(obj)], check=True)
    subprocess.run([str(LLVM / 'llvm-objcopy'), '-O', 'binary', '--only-section=.text', str(elf), str(out)],
                   check=True)
    nm = subprocess.check_output([str(LLVM / 'llvm-nm'), '--defined-only', str(elf)], text=True)
    symbols = {n: int(a, 16) - BASE for a, kind, n in (l.split() for l in nm.splitlines()) if kind in 'Tt'}
    return out.read_bytes(), symbols


def replay(blob, symbols, native_pacga):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    import unicorn.arm64_const as reg
    ins = {i.address: i for i in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(blob, BASE)}
    host_hcr = 0x88000019 | ((1 << 41) if native_pacga else 0)

    def run(syndrome, entry, enter=True, failures=0, corrupt=None):
        """Install the process bank (pauth_switch_enter), then call entry; returns everything
        the entry changed."""
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(BASE, 0x20000)
        uc.mem_write(BASE, blob)
        regs = dict(currentel=8, daif=0x3c0, hcr_el2=host_hcr, sctlr_el1=0x30501805)
        regs.update({k: 0xfef0000 + i for i, k in enumerate(KEYS)})
        regs.update(syndrome)
        state = bytearray(STATE)
        state[:80] = struct.pack('<10Q', *(0x1234000 + i for i in range(10)))
        struct.pack_into('<Q', state, 176, 0xc8002000)
        uc.mem_write(BUFFER - 16, b'\xa5' * 16 + bytes(state) + b'\xa5' * 16)
        writes, phase = [], ['enter']

        def get(n):
            return 0 if n == 'xzr' else uc.reg_read(getattr(reg, 'UC_ARM64_REG_' + n.upper()))

        def put(n, v):
            uc.reg_write(getattr(reg, 'UC_ARM64_REG_' + n.upper()), v)

        def hook(u, address, size, _):
            a = ins[address]
            parts = a.op_str.split(', ')
            if a.mnemonic == 'mrs':
                dest, name = parts
                value = regs[name]
                if phase[0] == 'entry' and name == corrupt:
                    value ^= 1
                put(dest, value)
            elif a.mnemonic == 'msr':
                name, src = parts
                regs[name] = get(src)
                writes.append((phase[0], name, regs[name]))
            else:
                return
            put('pc', address + size)
        uc.hook_add(UC_HOOK_CODE, hook)

        def call(name):
            put('sp', BASE + 0x18000)
            put('x30', RETURN)
            put('x0', BUFFER)
            for i in range(19, 30):
                put('x' + str(i), 0xabc000 + i)
            uc.emu_start(BASE + symbols[name], RETURN, count=1000)
            assert get('pc') == RETURN and get('sp') == BASE + 0x18000, name
            assert all(get('x' + str(i)) == 0xabc000 + i for i in range(19, 30)), name
            return get('x0')
        if enter:
            assert call('pauth_switch_enter') == 0
            assert tuple(regs[k] for k in KEYS) == tuple(0x1234000 + i for i in range(10))
        if failures:
            uc.mem_write(BUFFER + OFF_FAILURES, struct.pack('<Q', failures))
        before = (dict(regs), bytes(uc.mem_read(BUFFER, STATE)))
        phase[0] = 'entry'
        result = call(entry)
        assert bytes(uc.mem_read(BUFFER - 16, 16)) == b'\xa5' * 16
        assert bytes(uc.mem_read(BUFFER + STATE, 16)) == b'\xa5' * 16
        after = (dict(regs), bytes(uc.mem_read(BUFFER, STATE)))
        return dict(result=result, writes=[w for w in writes if w[0] == 'entry'], before=before, after=after)

    cases = 0
    # The candidate, with the PSTATE bits the filter ignores and the slot in another 2K
    # block (the C pre-check, not the filter, requires the exact vector base).
    positives = [{}, dict(spsr_el1=0x80000000), dict(spsr_el1=0x200003c0), dict(spsr_el1=1 << 22),
                 dict(esr_el2=EL2_EC | (1 << 25) | 0x07), dict(esr_el2=EL2_EC), dict(elr_el2=VBAR + 0xc00)]
    for change in positives:
        syndrome = dict(CANDIDATE, **change)
        got = run(syndrome, 'pauth_switch_live')
        assert got['result'] == 0 and not got['writes'], change
        assert got['after'] == got['before'], change          # keys, enables, API, bank: still live
        assert struct.unpack_from('<Q', got['after'][1], OFF_ACTIVE)[0] == 1
        cases += 1
    negatives = [dict(esr_el2=0x24 << 26 | 1 << 25 | 0x46), dict(esr_el2=0x21 << 26 | 1 << 25 | 0x0f),
                 dict(esr_el2=0x18 << 26 | 1 << 25), dict(esr_el2=0x01 << 26 | 1 << 25), dict(esr_el2=0),
                 dict(esr_el1=0x56000000), dict(esr_el1=0x92000046), dict(esr_el1=0),
                 dict(esr_el1=0x02000001), dict(esr_el1=0x00000001), dict(esr_el1=0x22000000),
                 dict(spsr_el1=4), dict(spsr_el1=5), dict(spsr_el1=0x10), dict(spsr_el1=0x1f), dict(spsr_el1=1),
                 dict(spsr_el1=1 << 32), dict(spsr_el1=1 << 63),
                 dict(elr_el2=VBAR), dict(elr_el2=VBAR + 0x080), dict(elr_el2=VBAR + 0x200),
                 dict(elr_el2=VBAR + 0x480), dict(elr_el2=VBAR + 0x500), dict(elr_el2=VBAR + 0x580),
                 dict(elr_el2=VBAR + 0x600), dict(elr_el2=VBAR + 0x404), dict(elr_el2=VBAR + 0x3fc)]
    for change in negatives:
        for corrupt in (None, 'apiakeylo_el1', 'apgakeyhi_el1', 'hcr_el2', 'sctlr_el1'):
            syndrome = dict(CANDIDATE, **change)
            live, leave = run(syndrome, 'pauth_switch_live', corrupt=corrupt), \
                run(syndrome, 'pauth_switch_leave', corrupt=corrupt)
            assert live == leave, (change, corrupt)
            assert live['result'] == int(bool(corrupt)) and live['writes'], (change, corrupt)
            cases += 1
    # The candidate's syndrome but no live bank (EL1 bank installed), or a latched failure.
    for kwargs in (dict(enter=False), dict(failures=1), dict(failures=1, corrupt='apdbkeylo_el1')):
        live, leave = run(CANDIDATE, 'pauth_switch_live', **kwargs), run(CANDIDATE, 'pauth_switch_leave', **kwargs)
        assert live == leave, kwargs
        cases += 1
    inactive = run(CANDIDATE, 'pauth_switch_live', enter=False)
    assert inactive['result'] == 0 and not inactive['writes'] and inactive['after'] == inactive['before']
    return cases


def between(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin + len(start))]


def hooks():
    asm = (ROOT / 'probes/xnuboot.S').read_text()
    src = read_source(ROOT / 'probes/xnuboot.c')
    switch = (ROOT / 'compat/pauth-switch.S').read_text()
    header = (ROOT / 'compat/pauth-switch.h').read_text()
    checks = 0
    # The assembly: only sync_lower's leave becomes pauth_switch_live, under the define.
    assert '#ifndef SNAP_PAUTH_EL0_LIVE\n#define SNAP_PAUTH_EL0_LIVE 0\n#endif' in asm
    sync = between(asm, '\nsync_lower:', '\nresume_lower:')
    assert ('    pauth_bank_pointer\n#if SNAP_PAUTH_EL0_LIVE\n    bl pauth_switch_live\n#else\n'
            '    bl pauth_switch_leave\n#endif\n    cbnz x0,pauth_failed\n') in sync
    assert asm.count('pauth_switch_live') == 1 and asm.count('bl pauth_switch_leave') == 3
    for label, end in (('\nasync_lower:', '\npauth_failed:'), ('\nexit:', '\n.balign 2048')):
        assert 'bl pauth_switch_leave' in between(asm, label, end) and 'pauth_switch_live' not in between(asm, label, end)
    checks += 4
    live = between(switch, '.global pauth_switch_live', '#endif')
    assert switch.index('#if defined(SNAP_PAUTH_EL0_LIVE) && SNAP_PAUTH_EL0_LIVE') < switch.index('.global pauth_switch_live')
    mnemonics = [l.split('//')[0].split()[0] for l in live.splitlines()[2:] if l.split('//')[0].strip()]
    assert set(mnemonics) <= {'ldr', 'cmp', 'b.ne', 'cbnz', 'mrs', 'lsr', 'mov', 'tst', 'and', 'ret'}, mnemonics
    assert mnemonics.count('b.ne') + mnemonics.count('cbnz') == 6 and mnemonics[-2:] == ['mov', 'ret']
    assert 'int pauth_switch_live(struct pauth_switch *);' in header
    checks += 4
    # The C side.
    assert '#ifndef SNAP_PAUTH_EL0_LIVE\n#define SNAP_PAUTH_EL0_LIVE 0\n#endif' in src
    assert re.search(r'#if SNAP_PAUTH_EL0_LIVE && !\(SNAP_FAST_CROSSINGS && SNAP_FAST_EL0_SYSREG\)\n#error', src)
    assert re.search(r'#if SNAP_PAUTH_EL0_LIVE && defined\(SNAP_PAUTH_FIXED_KEYS\) && SNAP_PAUTH_FIXED_KEYS\n#error', src)
    trap = between(src, 'int xnuboot_trap(uint64_t *frame, uint64_t esr, uint64_t *elr)\n{', '\n}\n')
    hook = trap.index('if ((esr >> 26) == 0x20 && c->pauth_bank[vcpu_of(c)->slot].active == 1) {\n'
                      '        int live = el0_live_trap(c, frame, esr, elr, &crossed);\n'
                      '        if (live > 0) return 0;\n'
                      '        if (live < 0) return xnuboot_pauth_failed(frame);\n    }')
    assert hook < trap.index('sysreg_census_note') and hook < trap.index('fast_vcpu_trap(')
    assert '#if SNAP_PAUTH_EL0_LIVE\n    if (!crossed && fast_crossing(c, frame, esr, elr)) return 0;\n#else\n' \
           '    if (fast_crossing(c, frame, esr, elr)) return 0;\n#endif' in trap
    checks += 4
    fn = between(src, 'static __attribute__((noinline)) int el0_live_trap(', '\n}\n')
    order = [fn.index(s) for s in ('if(bank->active!=1)return 0;', '(esr>>26)==0x20', '*elr-p->vbar_va==0x400',
                                   'esr1==FAST_EL0_SYSREG_ESR && !(spsr1&31) && !(spsr1>>32)',
                                   'if(fast_crossing(c,frame,esr,elr)) {',
                                   'c->pan_entry[v->slot].entry_sctlr=bank->saved_sctlr;', 'return 1;',
                                   '*crossed=1;', 'return pauth_switch_leave(bank) ? -1 : 0;')]
    assert order == sorted(order)
    assert 'xnuboot_pauth_failed' not in fn and fn.count('pauth_switch_leave') == 1
    checks += 2
    resume = between(src, 'int xnuboot_pauth_resume(const uint64_t *frame)\n{', '\n}\n')
    order = [resume.index(s) for s in (
        'int live=bank->active==1 && !bank->failures;',
        'if(!live && (bank->failures || bank->active))return xnuboot_pauth_failed(frame);',
        '#else\n    if(bank->failures || bank->active)return xnuboot_pauth_failed(frame);\n#endif',
        '__asm__ volatile("mrs %0,spsr_el2":"=r"(spsr));\n#if SNAP_PAUTH_EL0_LIVE\n'
        '    if(live && (spsr&31))return xnuboot_pauth_failed(frame);\n#endif',
        'if(spsr&31) {FAST_EXIT_END(c,v,frame);return 0;}', '#if SNAP_PAUTH_EL0_LIVE\n    if(!live) {\n#endif',
        'pauth_domain_user_cached(', 'if(pauth_switch_enter(bank))return xnuboot_pauth_failed(frame);',
        '#if SNAP_PAUTH_EL0_LIVE\n    }\n#endif\n    FAST_EXIT_END(c,v,frame);\n    return 0;')]
    assert order == sorted(order)
    assert src.count('FAST_EXIT_END(c,v,frame);') == 2   # the live return is charged where every EL0 return is
    checks += 2
    # No other C path reads or relies on a live bank: pauth_switch_live is never called from C.
    assert not re.search(r'pauth_switch_live\s*\(', src)
    checks += 1
    return checks


PAC = re.compile(r'^(pac|aut|xpac|reta[ab]|bra[ab]|blra[ab]|ldra[ab]|ereta[ab])')
KEYREG = re.compile(r'^(s3_0_c2_c[123]_\d|ap[id][ab]key(lo|hi)_el1|apgakey(lo|hi)_el1)$', re.I)
CONTROL = {'sctlr_el1', 'sctlr_el2', 'hcr_el2', 'tcr_el2'}


def audit(elf):
    text = subprocess.run([str(LLVM / 'llvm-objdump'), '-d', '--no-show-raw-insn', str(elf)],
                          capture_output=True, text=True, check=True).stdout
    functions, current = {}, None
    for line in text.splitlines():
        m = re.match(r'^([0-9a-f]+) <(.+)>:', line)
        if m:
            current = m[2]
            functions.setdefault(current, [])
            continue
        m = re.match(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$', line)
        if m and current:
            functions[current].append((int(m[1], 16), m[2], m[3]))

    def sensitive(mn, ops):
        regs = [p.strip().lower() for p in ops.split(',')]
        if PAC.match(mn) or mn == 'hint':
            return True
        if mn == 'msr' and (KEYREG.match(regs[0]) or regs[0] in CONTROL):
            return True
        return mn == 'mrs' and len(regs) > 1 and bool(KEYREG.match(regs[1]))
    need = ['el0_live_trap', 'pauth_switch_live', 'pauth_switch_leave', 'sync_lower']
    missing = [n for n in need if n not in functions]
    assert not missing, f'{elf}: missing symbols {missing}'
    # The closure: direct calls and branches to other functions, and every function whose address a
    # closure function materializes (ADR: the fast_cross_hw/fast_el0_hw/clock callbacks), so each
    # indirect call's possible targets are in it. Only the restore itself is excluded. A memory-loaded
    # pointer (no ADR in the closure) would escape this; the indirect calls are listed for review.
    seen, todo, bad, indirect = set(), ['el0_live_trap'], [], []
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for address, mn, ops in functions[name]:
            if sensitive(mn, ops):
                bad.append((name, hex(address), mn, ops))
            if mn in ('blr', 'br') and not ops.startswith('x30'):
                indirect.append((name, hex(address), mn, ops))
            m = re.search(r'<([^>+]+)(?:\+0x[0-9a-f]+)?>$', ops)
            branch = mn in ('bl', 'b', 'cbz', 'cbnz', 'tbz', 'tbnz', 'adr') or mn.startswith('b.')
            if branch and m and m[1] != name and m[1] in functions and m[1] != 'pauth_switch_leave':
                todo.append(m[1])
    assert not bad, f'{elf}: live path reaches {bad}'
    # The EL0 read's own callbacks must be in the closure, or the ADR tracking found nothing.
    callbacks = {'fast_crossing', 'fast_cross_entry', 'fast_el1', 'fast_el0_word', 'fast_el0_note',
                 'clock_counter', 'guest_clock_user_read', 'user_return_root', 'user_instruction_read'}
    assert callbacks <= seen, f'{elf}: closure lacks {sorted(callbacks - seen)}'
    leaves = [ops for _, mn, ops in functions['el0_live_trap'] if mn == 'bl' and '<pauth_switch_leave>' in ops]
    assert len(leaves) == 1, f'{elf}: el0_live_trap restores the bank {len(leaves)} times'
    callers = sorted(n for n, body in functions.items()
                     for _, mn, ops in body if mn in ('bl', 'b') and '<pauth_switch_live>' in ops)
    assert callers == ['sync_lower'], f'{elf}: pauth_switch_live called from {callers}'
    # sync_lower's first call is the live entry (the census stamp and register saves come before it).
    first = next(ops for _, mn, ops in functions['sync_lower'] if mn == 'bl')
    assert '<pauth_switch_live>' in first, first
    holders = sorted({n for n, body in functions.items() for _, mn, ops in body if sensitive(mn, ops)})
    return dict(elf=str(elf), live_closure=len(seen), indirect_calls=len(indirect),
                functions_with_pac_key_or_control_writes=holders)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--elf', action='append', default=[], help='a monitor ELF built with -DSNAP_PAUTH_EL0_LIVE=1')
    args = ap.parse_args()
    report = dict(hook_checks=hooks())
    with tempfile.TemporaryDirectory(prefix='pauth-el0-live-') as tmp:
        for name, defines in (('live', ['-DSNAP_PAUTH_EL0_LIVE=1']),
                              ('live+native-pacga', ['-DSNAP_PAUTH_EL0_LIVE=1', '-DSNAP_NATIVE_PACGA=1'])):
            blob, symbols = assemble(Path(tmp), defines)
            report[f'replay_{name}'] = replay(blob, symbols, 'native' in name)
        # Without the define the symbol does not exist.
        _, symbols = assemble(Path(tmp), [])
        assert 'pauth_switch_live' not in symbols
    report['audits'] = [audit(Path(e)) for e in args.elf]
    print(json.dumps(report, indent=1))


if __name__ == '__main__':
    main()
