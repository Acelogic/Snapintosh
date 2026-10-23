#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify design S1 (ring wrap) and S2 (ADRENO_GUEST_IB) on the host: no hardware client, no proxy.

  python3 tools/qualify-adreno-ring-ib.py --output <new dir>

1. tools/test-adreno-ring.c under ASan/UBSan against this tree (must PASS) and, S1 part, against the pinned
   pre-change compat/ code (-DADRENO_RING_TEST_PRE_CHANGE: must FAIL, the ring never wrapped); the full test there
   must not even build (no ADRENO_GUEST_IB).
2. The evidence it saves, checked with q1n1's own Python rather than the C that produced it: the 35 ring words
   equal a16gpu_p6p7.ring_words for the recorded IB/fence addresses and marker; the rebased draw-plan-v2 IB
   differs from the original only in the 12 dwords q1n1's register database (a8xx_regs) marks as address
   fields (PKT4/CRB/NCRB address registers, the LOAD_STATE6 UBO descriptor), each moved by its window's offset;
   the readback holds the model's paint on the 37x23 scissor and the seed on every other byte.
3. The existing suites (test-adreno 1969, fill transport, fill command) still pass.
4. compat/adreno.c, adreno-fill.c and adreno-ib.c compile for the monitor (aarch64-unknown-none-elf, the
   probes/run.py flags); their text sizes are recorded (the monitor's code reservation, probes/run.py OUT_AT-CODE_AT, is tight).
Writes <output>/qualification.json with every input and artifact hash.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tarfile
import io
from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
Q1N1 = ROOT.parent / 'q1n1' / 'tools'
PLAN = ROOT / 'build/adreno-pipeline-compiler-20260927/draw-plan-v2'
LLVM = Path('/opt/homebrew/opt/llvm/bin')
FLAGS = ['-std=gnu11', '-Icompat', '-Ishadow', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra',
         '-Werror']
BASE = ['compat/adreno-fill.c', 'compat/adreno-submit.c', 'compat/adreno-resource.c', 'compat/adreno.c',
        'compat/irq-forward.c', 'shadow/stage2.c', 'shadow/shadow.c', 'shadow/mmu.c']
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--pre-change-ref', default='2cdbae5af3c7ac7d608a9d4ca7609fda3817163b',
                    help='commit before ring wrap and guest IB support (never assume current HEAD)')
    args = ap.parse_args()
    pre_change_ref = subprocess.check_output(
        ['git', 'rev-parse', '--verify', args.pre_change_ref + '^{commit}'], cwd=ROOT, text=True).strip()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands, record = [], {'status': 'RUNNING', 'a16_access': False}

    def run(name, argv, cwd=ROOT, env=None, ok=(0,)):
        commands.append({'name': name, 'argv': [str(a) for a in argv], 'cwd': str(cwd)})
        result = subprocess.run(argv, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (out / f'{name}.log').write_text(result.stdout)
        assert result.returncode in ok, (name, result.returncode, str(out / f'{name}.log'))
        return result

    run('compiler', ['clang', '--version'])
    # --- 1. post (this tree) ---------------------------------------------------------------------------------
    art = out / 'artifacts'
    art.mkdir()
    binary = out / 'test-adreno-ring'
    run('post-build', ['clang', *FLAGS, 'tools/test-adreno-ring.c', 'compat/adreno-ib.c', *BASE, '-o', binary])
    env = dict(os.environ, SNAP_RING_ARTIFACT_DIR=str(art), SNAP_DRAW_PLAN=str(PLAN))
    post = run('post-run', [binary], env=env).stdout
    assert re.search(r'^PASS: \d+ ring/IB checks', post, re.M) and 'FAIL' not in post and 'runtime error' not in post
    s1 = re.search(r'^RING_S1 fences=(\d+)/5000 fills=(\d+)/20 model_wraps=(\d+)', post, re.M)
    assert s1 and s1.group(1) == '5000' and s1.group(2) == '20' and int(s1.group(3)) >= 3, s1
    assert re.search(r'^RING_S2_REFUSALS (\d+)/\1$', post, re.M)
    # --- 1b. pre-change source with the current fixture in its S1-only mode ----------------------------------
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, capture_output=True, check=True).stdout.strip()
    pre = out / 'pre-change'
    pre.mkdir()
    tar = subprocess.run(['git', 'archive', pre_change_ref, 'compat', 'shadow', 'tools/test-adreno.c'], cwd=ROOT,
                         capture_output=True, check=True).stdout
    tarfile.open(fileobj=io.BytesIO(tar)).extractall(pre)
    (pre / 'tools/test-adreno-ring.c').write_bytes((ROOT / 'tools/test-adreno-ring.c').read_bytes())
    run('pre-build', ['clang', *FLAGS, '-DADRENO_RING_TEST_PRE_CHANGE', 'tools/test-adreno-ring.c', *BASE,
                      '-o', out / 'test-adreno-ring-pre'], cwd=pre)
    before = run('pre-run', [out / 'test-adreno-ring-pre'], cwd=pre, env=env, ok=(1,)).stdout
    assert re.search(r'^FAIL: \d+ of \d+ ring/IB checks', before, re.M)
    pre_s1 = re.search(r'^RING_S1 fences=(\d+)/5000 fills=(\d+)/20 model_wraps=(\d+) .* first_failure=(-?\d+) '
                       r'kind=(\w+) error=(-?\d+)', before, re.M)
    assert pre_s1 and int(pre_s1.group(1)) < 5000 and pre_s1.group(3) == '0' and pre_s1.group(6) == '-66', pre_s1
    no_ib = run('pre-build-s2', ['clang', *FLAGS, 'tools/test-adreno-ring.c', *BASE, '-o', out / 'never'],
                cwd=pre, ok=(1,)).stdout
    assert "'adreno-ib.h' file not found" in no_ib
    # --- 2. the evidence against q1n1's Python ----------------------------------------------------------------
    sys.path.insert(0, str(Q1N1))
    import adreno_x2 as R
    import a8xx_regs as X
    import a16gpu_p6p7 as P
    walk = json.loads((art / 'ib-walk.json').read_text())
    words = list(struct.unpack('<35I', (art / 'ib-ring-words.bin').read_bytes()))
    want = P.ring_words(walk['ib_va'], walk['ib_dwords'], walk['br_va'], walk['bv_va'], walk['marker'])
    assert words == want, [(i, hex(a), hex(b)) for i, (a, b) in enumerate(zip(words, want)) if a != b][:4]
    assert walk['br'] == walk['bv'] == walk['marker'] and walk['violations'] == 0 and walk['refs_walked'] == 7
    original = struct.unpack('<1005I', (PLAN / 'draw.ib.bin').read_bytes())
    rebased = struct.unpack('<1005I', (art / 'ib-rebased.bin').read_bytes())
    moved = {i for i, (a, b) in enumerate(zip(original, rebased)) if a != b}
    address = set()
    known = {}
    for name, (off, bits, fields, stride, length) in X.REGS.items():
        if bits == 64 and any(f[4] in ('address', 'waddress') for f in fields):
            for e in range(length):
                known[off + e * stride] = name
    at = 0
    while at < len(original):
        h = original[at]
        if h >> 28 == 4:
            count, reg = h & 0x7f, h >> 8 & 0x3ffff
            address |= {at + 1 + k for k in range(count) if reg + k in known}
            at += 1 + count
            continue
        count, op = h & 0x3fff, h >> 16 & 0x7f
        body = original[at + 1:at + 1 + count]
        if op in (R.CP_CONTEXT_REG_BUNCH, R.CP_NON_CONTEXT_REG_BUNCH):
            first = 2 if op == R.CP_NON_CONTEXT_REG_BUNCH else 0
            address |= {at + 2 + k for k in range(first, count - 1, 2) if body[k] in known and body[k + 1]}
        if op in (R.CP_LOAD_STATE6_GEOM, R.CP_LOAD_STATE6_FRAG) and (body[0] >> 16 & 3) == 0 and (body[0] >> 14 & 3) == 2:
            address |= {at + 4 + 2 * u for u in range(body[0] >> 22) if body[3 + 2 * u]}
        at += 1 + count
    assert moved == address and len(moved) == 12, (sorted(moved ^ address), len(moved))
    windows = walk['windows']                    # {q1n1 region: [q1n1 VA, model VA]}; sizes are q1n1's
    for i in moved:
        v = original[i] & ~0x3
        shifted = [m - q for name, (q, m) in windows.items() if q <= v < q + R.ARENA_LAYOUT[name][1]]
        assert len(shifted) == 1 and rebased[i] == original[i] + shifted[0], (i, hex(original[i]), hex(rebased[i]))
    rt, seed = (art / 'rt-readback.bin').read_bytes(), (PLAN / 'target.before.bin').read_bytes()
    paint = struct.pack('<I', 0xc0ffee42)
    for off in range(0, len(rt), 4):
        image = off - 0x1000
        inside = 0 <= image and image // 1024 < 23 and image % 1024 < 37 * 4
        assert rt[off:off + 4] == (paint if inside else seed[off:off + 4]), off
    # --- 3. the existing suites ------------------------------------------------------------------------------
    suites = {}
    for name, extra in (('test-adreno', []), ('test-adreno-fill', ['compat/adreno-fill.c']),
                        ('test-adreno-fill-command', ['compat/adreno-fill-command.c', 'compat/adreno-fill.c',
                                                      'compat/adreno-resource-list.c'])):
        srcs = [f'tools/{name}.c', *extra, *[b for b in BASE if b not in extra and b != 'compat/adreno-fill.c']]
        run(f'{name}-build', ['clang', *FLAGS, *srcs, '-o', out / name])
        log = run(f'{name}-run', [out / name]).stdout
        suites[name] = [l for l in log.splitlines() if l.startswith(('PASS', 'FAIL'))]
        assert 'PASS: 1969 Adreno' in log and 'FAIL' not in log, name
    # --- 4. the monitor objects --------------------------------------------------------------------------------
    sizes = {}
    for src in ('compat/adreno.c', 'compat/adreno-fill.c', 'compat/adreno-ib.c'):
        obj = out / (Path(src).stem + '-aarch64.o')
        run(f'monitor-{Path(src).stem}', [LLVM / 'clang', '--target=aarch64-unknown-none-elf', '-ffreestanding',
            '-fno-pic', '-mgeneral-regs-only', '-O1', '-Wall', '-Wextra', '-Werror', '-fno-stack-protector',
            '-mcmodel=tiny', '-Ishadow', '-c', src, '-o', obj])
        text = run(f'size-{Path(src).stem}', [LLVM / 'llvm-size', obj]).stdout.splitlines()[1].split()[0]
        sizes[src] = int(text)
    inputs = ['tools/test-adreno-ring.c', 'tools/test-adreno.c', 'tools/test-adreno-fill.c', 'compat/adreno.c',
              'compat/adreno.h', 'compat/adreno-fill.c', 'compat/adreno-fill.h', 'compat/adreno-ib.c',
              'compat/adreno-ib.h', 'compat/adreno-guest.h', 'gpu/adreno-kext/include/AdrenoA8xxRegs.h',
              *[str(p.relative_to(ROOT)) for p in source_files(ROOT / 'probes/xnuboot.c')],
              'probes/run.py', 'probes/adreno.py', 'tools/adreno_counters.py',
              str(Path(__file__).relative_to(ROOT))]
    record.update(status='RING_WRAP_AND_GUEST_IB_HOST_QUALIFIED', head=head,
        pre_change_ref=pre_change_ref, commands=commands,
        sources_sha256={n: sha(ROOT / n) for n in inputs},
        draw_plan_sha256={p.name: sha(p) for p in sorted(PLAN.iterdir()) if p.is_file()},
        q1n1_sha256={m: sha(Q1N1 / m) for m in ('adreno_x2.py', 'a8xx_regs.py', 'a16gpu_p6p7.py')},
        post=[l for l in post.splitlines() if l.startswith(('RING_', 'PASS', 'FAIL'))],
        pre_change=[l for l in before.splitlines() if l.startswith(('RING_', 'FAIL'))][:30],
        pre_change_s2_build='adreno-ib.h not found (no ADRENO_GUEST_IB before this change)',
        ring_words_equal_q1n1=True, rebased_address_dwords=sorted(moved), existing_suites=suites,
        monitor_text_bytes=sizes, walk=walk,
        artifacts_sha256={p.name: sha(p) for p in sorted(art.iterdir())},
        boundary='Host model only (non-coherent RAM, CB0 walk, CP ring/IB interpreter, DART leaves). The model '
                 'cannot execute ir3: the painted scissor is its stand-in, pixels are the A16\'s experiment. '
                 'No monitor boot, no kext, no A16.')
    (out / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record[k] for k in ('status', 'post', 'monitor_text_bytes')}, indent=1))


if __name__ == '__main__':
    main()
