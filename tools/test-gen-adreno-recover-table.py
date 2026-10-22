#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Checks of compat/adreno-recover-table.h, the register program the monitor's CP soft reset replays
(agents/gpu-recovery FAILURE-MODES.md R9-R11):
  1. regenerating it from q1n1's sources gives the checked-in file (drift: q1n1's hw_init changed);
  2. every entry is a write/read/read-back inside the monitor's GX passthrough windows, or the one CP aperture SMC,
     whose arguments are the monitor's allow-list entry (compat/adreno.c adreno_smc_allowed);
  3. it holds q1n1's 52 CP_PROTECT_GLOBAL entries, both pipes' CP_PROTECT_CNTL_PIPE, the SQE/ring bases and RB_CNTL that
     probes/adreno.py adopts (BUFSZ 12), and the C4 words are CP_THREAD_CONTROL + CP_ME_INIT(7);
  4. the reset registers compat/adreno-ib.h names have Mesa's A8XX offsets (a6xx.xml), when the Mesa tree is present.
Run from the Snapintosh root: python3 tools/test-gen-adreno-recover-table.py"""
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('gen_table', ROOT / 'tools' / 'gen-adreno-recover-table.py')
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)
checks = failures = 0


def check(ok, what):
    global checks, failures
    checks += 1
    if not ok:
        failures += 1
        print(f'FAIL: {what}')


header = ROOT / 'compat' / 'adreno-recover-table.h'
tools = ROOT.parent / 'q1n1' / 'tools'
hw, sqe, me_init, secvid, skipped, inputs = gen.generate(tools, False)
check(gen.render(hw, sqe, me_init, secvid, skipped, inputs, False) == header.read_text(),
      'compat/adreno-recover-table.h differs from the generator output (regenerate it)')
R, S3 = gen.load_q1n1(tools)
for kind, pa, value, what in hw + sqe + secvid:
    if kind == 'SMC_APERTURE':
        continue
    check(gen.passthrough(pa) and not pa & 3, f'{what} at {pa:#x} outside the GX passthrough windows')
check([o[0] for o in hw].count('SMC_APERTURE') == 1, 'exactly one CP aperture SMC in hw_init')
check(tuple(S3.SMC_CP_APERTURE) == gen.MONITOR_SMC_CP_APERTURE, 'SMC arguments equal the monitor allow-list')
names = [o[3] for o in hw]
check(sum(n.startswith('CP_PROTECT_GLOBAL[') for n in names) == 52, '52 CP_PROTECT_GLOBAL writes')
check(names.count('CP_PROTECT_CNTL_PIPE') == 2, 'CP_PROTECT_CNTL_PIPE on BR and BV')
want = {'CP_SQE_INSTR_BASE': R.CP_SQE_VA & 0xffffffff, 'CP_RB_BASE': R.CP_RB_VA & 0xffffffff,
        'CP_RB_CNTL': R.RB_CNTL_DEFAULT, 'CP_RB_RPTR_ADDR': (R.CP_MEMPTRS_VA + R.CP_RPTR_SHADOW_OFF) & 0xffffffff}
last = {o[3]: o[2] for o in hw if o[0] == 'WRITE'}
for name, value in want.items():
    check(last.get(name) == value, f'{name} = {value:#x} (got {last.get(name)})')
check(R.RB_CNTL_DEFAULT & 0x3f == 12, 'RB_CNTL BUFSZ 12: the 8192-dword ring the monitor adopts')
check(me_init[0] == R.pkt7(R.CP_THREAD_CONTROL, 1) and me_init[2] == R.pkt7(R.CP_ME_INIT, 7) and len(me_init) == 10,
      'C4 words: CP_THREAD_CONTROL, CP_ME_INIT(7)')
check([o[0] for o in secvid] == ['WRITE', 'READBACK', 'WRITE', 'WRITE', 'WRITE'] and secvid[0][2] == 0,
      'C5: SECVID 0 with read-back, aperture BR, GMEM protect, aperture clear')
check(all(not gen.passthrough(pa) for _k, pa, _v, _n in skipped if pa), 'skipped writes are all CX-side')

# Mesa's offsets for the registers the reset itself uses (compat/adreno-ib.h; also _Static_assert-ed in adreno-ib.c).
mesa = Path(__file__).resolve().parents[1] / ('gpu/air2ir3/third_party/mesa/src/freedreno/'
            'registers/adreno/a6xx.xml')
if mesa.exists():
    xml = mesa.read_text()
    def offset(name, variant):
        for m in re.finditer(r'<reg(?:32|64) offset="(0x[0-9a-fA-F]+)" name="%s"(?: [^>]*?)?variants="([^"]+)"' % name, xml):
            if m.group(2).startswith(variant):
                return int(m.group(1), 16)
        m = re.search(r'<reg(?:32|64) offset="(0x[0-9a-fA-F]+)" name="%s"' % name, xml)
        return int(m.group(1), 16) if m else None
    h = (ROOT / 'compat' / 'adreno-ib.h').read_text()
    for name, macro, variant in (('RBBM_SW_RESET_CMD', 'ADRENO_RBBM_SW_RESET_CMD', 'A8XX'),
                                 ('RBBM_INT_CLEAR_CMD', 'ADRENO_RBBM_INT_CLEAR_CMD', 'A8XX'),
                                 ('GBIF_HALT', 'ADRENO_GBIF_HALT', 'A6XX'), ('GBIF_HALT_ACK', 'ADRENO_GBIF_HALT_ACK', 'A6XX')):
        pa = int(re.search(r'#define %s (0x[0-9a-fA-F]+)UL' % macro, h).group(1), 16)
        off = offset(name, variant)
        check(off is not None and pa == 0x03d00000 + 4 * off, f'{macro} {pa:#x} vs a6xx.xml {name} {off}')
    print(f'Mesa a6xx.xml: {mesa}')
else:
    print('Mesa a6xx.xml not present: offsets checked only by the _Static_asserts')
if failures:
    print(f'FAIL: {failures} of {checks} table checks')
    sys.exit(1)
print(f'PASS: {checks} table checks: {len(hw)} hw_init ops (52 CP_PROTECT_GLOBAL, 1 SMC), {len(sqe)} SQE start, '
      f'{len(me_init)} C4 words, {len(secvid)} C5 ops, {len(skipped)} CX-side writes not replayed; inputs {inputs[:60]}...')
