#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact-image loader and published capability replay for --hide-amx.

Failure modes precede implementation in docs/SME-GUEST-CONTRACT-20261020.md.
This test uses the real guest image and an independent instruction decoder;
it does not run XNU or claim that every application selects a safe routine.
"""
import argparse
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / 'probes'), str(ROOT / 'tools')]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def rows(items):
    return [{'pa': pa, 'bytes': len(data), 'sha256': digest(data)}
            for pa, data in sorted(items.items())]


def loader(log, option=None):
    import xnuboot as xb
    with contextlib.redirect_stdout(log):
        xb.configure_guest('j700ap-26A428', ROOT / 'downloads/extracted/j700ap')
        return xb, xb.build(xb.DEFAULT_KERNELCACHE, **({} if option is None else {'hide_amx': option}))


def fingerprint(xb, built):
    return {'chunks': rows(built['chunks']), 'tables': rows(built['tables'].pages),
            'params_sha256': digest(xb.params_blob(built)),
            'image_sha256': digest(built['image'].data)}


def replay(blob, start, end, initial, version, alias):
    import capstone
    from capstone.arm64_const import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    instructions = {i.address: i for i in decoder.disasm(blob, start)}
    assert len(instructions) * 4 == len(blob)
    registers = {i: 0 for i in range(31)}
    registers[8] = initial
    registers[21], registers[22] = 0x200000, 0x300000
    memory, written = {}, []
    def width(name):
        return 4 if name.startswith('w') else 8
    def get(name):
        if name in ('xzr', 'wzr'):
            return 0
        return registers[int(name[1:])] & ((1 << (8 * width(name))) - 1)
    def put(name, value):
        if name not in ('xzr', 'wzr'):
            registers[int(name[1:])] = value & ((1 << (8 * width(name))) - 1)
    def read(address, count):
        assert all(address + n in memory for n in range(count)), hex(address)
        return int.from_bytes(bytes(memory[address + n] for n in range(count)), 'little')
    def store(address, value, count, record=True):
        for n, b in enumerate(value.to_bytes(count, 'little')):
            memory[address + n] = b
        if record:
            written.append((address, count, value))
    # Decode addresses from the actual ADRP/load instructions, not the patch's metadata.
    seq = list(instructions.values())
    version_address = (seq[0].operands[1].imm + seq[1].operands[1].mem.disp) & ((1 << 64) - 1)
    store(version_address, version, 4, False)
    for insn in seq:
        if insn.mnemonic == 'ldr' and insn.operands[1].type == ARM64_OP_MEM:
            operand = insn.operands[1].mem
            base = insn.reg_name(operand.base)
            if base == 'x22':
                store(get(base) + operand.disp, 0x400000, 8, False)
            elif base == 'x21':
                store(get(base) + operand.disp, 0x500000 if alias else 0, 8, False)
    pc, trace = start, []
    while pc < end:
        assert len(trace) < 32 and pc in instructions
        insn = instructions[pc]; ops = insn.operands; mnemonic = insn.mnemonic
        trace.append({'va': hex(pc), 'word': insn.bytes.hex(), 'instruction': insn.mnemonic + ' ' + insn.op_str})
        nxt = pc + 4
        def reg(op):
            return insn.reg_name(op.reg)
        def value(op):
            assert op.type in (ARM64_OP_REG, ARM64_OP_IMM)
            return get(reg(op)) if op.type == ARM64_OP_REG else op.imm
        if mnemonic in ('adrp', 'mov'):
            put(reg(ops[0]), value(ops[1]))
        elif mnemonic in ('and', 'orr', 'lsl'):
            left, right = value(ops[1]), value(ops[2])
            put(reg(ops[0]), {'and': lambda: left & right,
                             'orr': lambda: left | right,
                             'lsl': lambda: left << right}[mnemonic]())
        elif mnemonic in ('ldr', 'str'):
            assert ops[1].type == ARM64_OP_MEM and not ops[1].mem.index
            at = get(insn.reg_name(ops[1].mem.base)) + ops[1].mem.disp
            n = width(reg(ops[0]))
            if mnemonic == 'ldr':
                put(reg(ops[0]), read(at, n))
            else:
                store(at, get(reg(ops[0])), n)
        elif mnemonic == 'cbz':
            if value(ops[0]) == 0:
                nxt = value(ops[1]) & ((1 << 64) - 1)
        else:
            raise AssertionError('unqualified binary instruction ' + insn.mnemonic)
        pc = nxt
    assert pc == end
    return written, trace


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--capture-before', action='store_true')
    ap.add_argument('--before', type=Path)
    a = ap.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    for name in list(os.environ):
        if name.startswith('SNAP_'):
            os.environ.pop(name)
    os.environ['SNAP_SEED'] = 'hide-amx-offline-loader-v1'
    log = io.StringIO()
    xb, off = loader(log)
    baseline = fingerprint(xb, off)
    if a.capture_before:
        (a.output / 'receipt.json').write_text(json.dumps(baseline, indent=2) + '\n')
        (a.output / 'build.log').write_text(log.getvalue())
        print('CAPTURED_BEFORE')
        return
    assert a.before and baseline == json.loads(a.before.read_text()), 'default output changed'
    kc = importlib.import_module('kc-load')
    assert hasattr(kc, 'hide_amx'), 'loader has no opt-in AMX publication patch'
    _, on = loader(log, True)
    contract = on['hide_amx']
    assert contract and on['image'].data == off['image'].data
    assert set(on['chunks']) == set(off['chunks'])
    expected = {on['image_pa'] + s['va'] - on['image'].vmin: s for s in contract['sites']}
    actual = {}
    for pa, before in off['chunks'].items():
        after = on['chunks'][pa]
        assert len(before) == len(after)
        if before == after:
            continue
        for i in range(0, len(before), 4):
            if before[i:i + 4] != after[i:i + 4]:
                actual[pa + i] = (int.from_bytes(before[i:i + 4], 'little'),
                                  int.from_bytes(after[i:i + 4], 'little'))
    assert set(actual) == set(expected)
    for pa, (before, after) in actual.items():
        assert before == 0xaa090108 and after == 0x9261ed08
    assert rows(on['tables'].pages) == rows(off['tables'].pages)
    assert xb.params_blob(on) == xb.params_blob(off)
    assert 'pauth_fixed_keys' not in on
    published, cases = [], []
    image = off['image']
    source = bytearray(image.data)
    repeated = bytearray(source)
    kc.hide_amx(image, repeated)
    try:
        kc.hide_amx(image, repeated)
        raise AssertionError('repeated application accepted')
    except ValueError:
        cases.append('repeat-refused')
    for site in contract['sites']:
        start, length = site['sequence_va'], site['sequence_bytes']
        at = site['sequence_file_offset']
        before = source[at:at + length]
        after = repeated[at:at + length]
        for version in range(1, 7):
            for initial in (0, 0x1800000000000000, 0xffffffffffffffff, 0x123456789abcdef0):
                for alias in (False, True):
                    old, _ = replay(before, start, start + length, initial, version, alias)
                    new, trace = replay(after, start, start + length, initial, version, alias)
                    assert [(p, n) for p, n, _ in new] == [(p, n) for p, n, _ in old]
                    for (p, n, a1), (_, _, b1) in zip(old, new):
                        if n == 4 and a1 == 1 and b1 == 1:
                            continue  # Uncacheable-normal-memory feature boolean.
                        assert b1 == (a1 & ~0x78000000)
                        assert b1 & 0x78000000 == 0
                    published.append({'version': version, 'input_capabilities': hex(initial),
                                      'x86_alias': alias, 'writes': new})
        (a.output / 'publication-trace.json').write_text(json.dumps(trace, indent=2) + '\n')
    bad = bytearray(source)
    bad[contract['sites'][0]['file_offset']] ^= 1
    snapshot = bytes(bad)
    try:
        kc.hide_amx(image, bad)
        raise AssertionError('changed preimage accepted')
    except ValueError:
        assert bytes(bad) == snapshot
        cases.append('preimage-refused-before-mutation')
    os.environ['SNAP_HIDE_AMX'] = '1'
    _, env_on = loader(log)
    assert fingerprint(xb, env_on) == fingerprint(xb, on)
    _, explicit_off = loader(log, False)
    assert fingerprint(xb, explicit_off) == baseline
    os.environ['SNAP_HIDE_AMX'] = '2'
    try:
        loader(log)
        raise AssertionError('invalid environment accepted')
    except ValueError:
        cases.append('invalid-environment-refused')
    os.environ['SNAP_HIDE_AMX'] = '0'
    try:
        loader(log, 1)
        raise AssertionError('non-boolean option accepted')
    except ValueError:
        cases.append('non-boolean-option-refused')
    import cycle
    from cycle_lib import installed_fresh
    cli = ['installed-fresh', '--prefix', 'offline-hide-amx', '--prepare', '--variant', 'control']
    plain, hidden = cycle.parse(cli), cycle.parse(cli + ['--hide-amx'])
    assert not plain.hide_amx and hidden.hide_amx
    env1, env2 = installed_fresh.environment(plain), installed_fresh.environment(hidden)
    assert env2.pop('SNAP_HIDE_AMX') == '1' and env2 == env1
    assert (installed_fresh.variant_flags({'control': []}, plain, 'control') ==
            installed_fresh.variant_flags({'control': []}, hidden, 'control'))
    receipt = {'status': 'PASS_OFFLINE_E2E', 'default_byte_identical': True,
               'changed_words': len(actual), 'published_store_replays': len(published),
               'cases': cases + ['actual-parser-and-environment-routing', 'explicit-false-overrides-environment'],
               'patch': contract, 'default': baseline, 'published': published,
               'hardware': False, 'native_sme_qualified': False}
    (a.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (a.output / 'build.log').write_text(log.getvalue())
    print(json.dumps({k: v for k, v in receipt.items() if k not in ('patch', 'default', 'published')}, indent=2))


if __name__ == '__main__':
    main()
