#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify sign-only PAC on idle generation44 using public synthetic keys.

Bind existing model probes, verify the resident stage, preserve temporary RAM,
and compare valid pointers with the canonical PAC/AUT primitive. Raw operands
are never authenticated. This is primitive evidence, not a new guest boot.
"""
from pathlib import Path
import argparse
import hashlib
import itertools
import json
import os
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
Q1N1 = ROOT.parent/'q1n1'
sys.path[:0] = [str(ROOT/'probes'), str(Q1N1/'tools')]
import run
import q1n1proxy

sha = lambda b: hashlib.sha256(b).hexdigest()
KEYS = ((0x0123456789abcdef, 0xfedcba9876543210),
        (0x13579bdf2468ace0, 0x0eca8642fdb97531))
POINTERS = (0, 0x1cf5382f0, (1 << 47)-1, 1 << 47, 1 << 55,
            1 << 56, (1 << 64)-1, 0x123456789abcdef0, 0xe0fc8b839d03516b)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--device', default='udp://en5')
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args()
    out = args.output.resolve()
    assert not out.exists(), 'preserve prior physical records'
    retirement_path = ROOT/'build/installed-metal-progress-3600s-20260927-retirement-v1.json'
    assert sha(retirement_path.read_bytes()) == '774e4b399af0ab482f1c3a9f0398907e485c56eec6b091b701b26ad1f2c39270'
    retirement = json.loads(retirement_path.read_text())
    assert retirement['status'] == 'GENERATION44_IDLE'
    snapshot_path = ROOT/'build/installed-metal-20260926/progress-report-snapshot-v1/snapshot.json'
    snapshot = json.loads(snapshot_path.read_text())
    assert snapshot['result'] == 'PASS' and snapshot['generation'] == 44
    assert snapshot['completed_bytes'] == snapshot['container_bytes'] == 62826479616
    assert not any(snapshot['serror'].values())
    assert snapshot['edges_unchanged'] and snapshot['checkpoints_unchanged']
    assert snapshot['shutdown'] == ['normal shutdown, CSTS 0x9', 'CC.EN 0, CSTS 0x0']
    names = ['compat/pauth-native.S', 'compat/pauth-native-sign.S',
             'probes/pauth-address.S', 'probes/pauth-sign-address.S', 'probes/run.py',
             'tools/qualify-pauth-raw-native.py', 'tools/test-pauth-native.py',
             'tools/test-pauth-native-sign.py']
    sources = {n: sha((ROOT/n).read_bytes()) for n in names}
    if args.check:
        print('PASS: idle generation44 and completed snapshot inputs; no target access')
        return
    out.mkdir(parents=True)
    os.chdir(ROOT)
    raw = run.build('pauth-sign-address', out/'raw')
    canonical = run.build('pauth-address', out/'canonical')
    assert sha(raw) == '8ef7306ff0c27a7e7ce3155ab3f683f349ff56d0d7e36fcfdd2e440ac9cbfc05'
    assert sha(canonical) == 'e47d54871b38efc4452960e18c4df221dd25ba557e2cc8fc9fa0a0cc2357ce5e'
    assert len(raw) < 0x1000 and len(canonical) < 0x1000
    record = dict(result='INCOMPLETE', started=time.time(), source_sha256=sources,
        transport_sha256=sha((Q1N1/'tools/q1n1proxy.py').read_bytes()),
        retirement_sha256=sha(retirement_path.read_bytes()), snapshot_sha256=sha(snapshot_path.read_bytes()),
        raw_probe_sha256=sha(raw), canonical_probe_sha256=sha(canonical), rows=[],
        boundary='Physical synthetic-key sign-only primitive; canonical comparison only on valid pointers. No guest progress or rendering claim.')
    p = None
    guard = None
    saved = None
    try:
        p = q1n1proxy.connect(args.device)
        p.resume_skip = False
        info = p.bootinfo()
        record['bootinfo'] = info
        assert info['current_el'] == 2 and info['stage_generation'] == 44
        assert info['image_base'] == 0xb0800000 and p.stage_features() & 1
        for name in ('heap_base', 'heap_size', 'image_base', 'stage_base', 'stage_size'):
            assert info[name] == snapshot['bootinfo'][name]
        elf = (Q1N1/'build/uefi/stage/hardware-alt.elf').read_bytes()
        assert elf[:6] == b'\x7fELF\x02\x01'
        shoff = struct.unpack_from('<Q', elf, 40)[0]
        entsize, count, strings_index = struct.unpack_from('<3H', elf, 58)
        sections = [struct.unpack_from('<IIQQQQIIQQ', elf, shoff+i*entsize) for i in range(count)]
        strings_section = sections[strings_index]
        strings = elf[strings_section[4]:strings_section[4]+strings_section[5]]
        named = {strings[s[0]:].split(b'\0', 1)[0].decode(): s for s in sections}
        text = named['.text']
        resident = p.readmem(text[3], text[5])
        expected = bytearray(elf[text[4]:text[4]+text[5]])
        expected[24:32] = resident[24:32]
        assert text[3] == info['image_base'] and resident == expected
        record['stage_elf_sha256'] = sha(elf)
        record['stage_text_sha256'] = sha(resident)
        work = (info['heap_base']+0x100000+0x3fff) & ~0x3fff
        assert work+0x3000 < info['heap_base']+info['heap_size']-0x1000000
        for s in sections:
            if s[2] & 2:
                assert work+0x3000 <= s[3] or work >= s[3]+s[5]
        raw_code, canonical_code, buf = work, work+0x1000, work+0x2000
        record['workspace'] = dict(base=hex(work), bytes=0x3000)
        guard = p.serror_state()
        assert not any(guard[k] for k in ('before', 'during', 'unconsumed'))
        assert p.get_exc_count() == 0
        p.serror_strict(True)
        saved = p.readmem(work, 0x3000)
        record['workspace_before_sha256'] = sha(saved)
        p.writemem(raw_code, raw)
        p.flush_code(raw_code, len(raw))
        p.writemem(canonical_code, canonical)
        p.flush_code(canonical_code, len(canonical))
        assert p.readmem(raw_code, len(raw)) == raw
        assert p.readmem(canonical_code, len(canonical)) == canonical
        assert p.call(raw_code, buf, 0) == 0
        config = p.readmem(buf, 80)
        record['configuration'] = [hex(v) for v in struct.unpack('<10Q', config)]

        def trial(code, request, authenticated):
            before = bytearray(b'\xa5'*0x200)
            before[0x100:0x138] = request
            p.writemem(buf, before)
            assert p.call(code, buf, 1) == 0
            after = p.readmem(buf, 0x200)
            signed, actual_auth, restored = struct.unpack_from('<3Q', after, 0x180)
            assert actual_auth == authenticated and restored == 15
            expected = bytearray(before)
            expected[:80] = config
            expected[0x180:0x198] = struct.pack('<3Q', signed, authenticated, 15)
            assert after == expected, 'request or output canary changed'
            return signed

        comparisons = 0
        for key, tbi, tbid in itertools.product(range(4), range(2), range(2)):
            for pointer, key_index, modifier in itertools.product(POINTERS, range(2), (0xb743, 0xb744)):
                lo, hi = KEYS[key_index]
                request = struct.pack('<7Q', pointer, modifier, lo, hi, key, tbi, tbid)
                signed = trial(raw_code, request, 0)
                assert trial(raw_code, request, 0) == signed, 'nondeterministic PAC'
                matched = None
                if pointer < 1 << 47:
                    matched = trial(canonical_code, request, pointer) == signed
                    assert matched, 'raw/canonical signature mismatch'
                    comparisons += 1
                record['rows'].append(dict(pointer=hex(pointer), key=key, tbi=tbi, tbid=tbid,
                    synthetic_key_index=key_index, modifier=hex(modifier), signed_pointer=hex(signed),
                    authenticated=0, restored=15, canonical_match=matched))
            assert p.call(raw_code, buf, 0) == 0 and p.readmem(buf, 80) == config
            print(f'Physical raw-sign cases: {len(record["rows"])}/576', flush=True)
        for key, tbi, tbid in itertools.product(range(4), range(2), range(2)):
            selected = [r for r in record['rows'] if (r['key'], r['tbi'], r['tbid']) == (key, tbi, tbid)]
            assert any(r['pointer'] != r['signed_pointer'] for r in selected)
            for varying in ('synthetic_key_index', 'modifier'):
                groups = {}
                for row in selected:
                    group = tuple(row[k] for k in ('pointer', 'synthetic_key_index', 'modifier') if k != varying)
                    groups.setdefault(group, set()).add(row['signed_pointer'])
                assert any(len(v) > 1 for v in groups.values()), varying
        record['canonical_comparisons'] = comparisons
        assert p.readmem(text[3], text[5]) == resident
        after_info = p.bootinfo()
        assert all(after_info[n] == info[n] for n in ('stage_generation', 'image_base', 'heap_base'))
        assert all(sha((ROOT/n).read_bytes()) == h for n, h in sources.items())
        record['result'] = 'PASS'
    except BaseException as error:
        record['result'] = 'FAIL'
        record['error'] = repr(error)
        raise
    finally:
        if p:
            try:
                if saved is not None:
                    p.writemem(work, saved)
                    p.flush_code(work, len(saved))
                    restored = p.readmem(work, len(saved))
                    record['workspace_after_sha256'] = sha(restored)
                    record['workspace_restored'] = restored == saved
                    if restored != saved:
                        record['result'] = 'FAIL'
                state = p.serror_state()
                record['serror'] = {k: state[k] for k in ('before', 'during', 'unconsumed')}
                record['exceptions'] = p.get_exc_count()
                if any(record['serror'].values()) or record['exceptions']:
                    record['result'] = 'FAIL'
                if guard:
                    p.serror_strict(bool(guard['flags'] & q1n1proxy.SERROR_STRICT))
            except BaseException as error:
                record['result'] = 'FAIL'
                record['cleanup_error'] = repr(error)
                raise
            finally:
                p.link.close()
                record['finished'] = time.time()
                (out/'physical.json').write_text(json.dumps(record, indent=2)+'\n')
        else:
            record['finished'] = time.time()
            (out/'physical.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(dict(result=record['result'], cases=len(record['rows']), output=str(out/'physical.json'))))
    assert record['result'] == 'PASS' and record['workspace_restored']

if __name__ == '__main__':
    main()
