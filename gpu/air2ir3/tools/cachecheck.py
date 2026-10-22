#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""cachecheck.py - integrity check of a precompiled cache (CACHE-FORMAT.md).

  python3 tools/cachecheck.py [cache] [--reload N]
For every entry (format 3; entries/<k>/<key>.json is the library's sidecar byte for byte and
<key>.src.json its provenance): the file name equals the key, the key recomputes from key_inputs and
the reflection's function constants (cachekey.py), the stage/entry in key_inputs match the
reflection, variant_id is the key's first 8 bytes, the blob exists and has the recorded SHA-256/size,
the constant-sampler bitmask/set_id match the sampler list, the pvtmem requirement is inside the
budget, a safe_constlen entry has constlen <= max_const_safe and every entry whose constlen exceeds
it has its safe_constlen sibling in the cache, every entry carries the manifest's compiler_id / abi /
format version, and no entry is a runtime-template entry (those live only in evidence/).  --reload N additionally reloads N blobs (spread over the cache) with Mesa's
ir3_retrieve_variant and disassembles them (air2ir3 --verify-variant).
"""
import hashlib, json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cachekey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    cache = os.path.abspath(args[0] if args else os.path.join(ROOT, 'cache'))
    reload_n = int(sys.argv[sys.argv.index('--reload') + 1]) if '--reload' in sys.argv else 0
    man = json.load(open(os.path.join(cache, 'manifest.json')))
    errors, n, blobs, chip = [], 0, {}, int(man['chip_id'], 16)
    need_safe, have = [], set()
    for d in sorted(os.listdir(os.path.join(cache, 'entries'))):
        for f in sorted(os.listdir(os.path.join(cache, 'entries', d))):
            if f.endswith('.src.json'): continue
            e = json.load(open(os.path.join(cache, 'entries', d, f))); n += 1
            k = e['key']; ki = e['key_inputs']; have.add(k)
            def err(m): errors.append(f'{k[:16]} {e["reflection"].get("function")}: {m}')
            if f != k + '.json' or d != k[:2]: err('file name does not match key')
            srcp = os.path.join(cache, 'entries', d, k + '.src.json')
            if not os.path.exists(srcp) or json.load(open(srcp))['key'] != k: err('provenance file missing or wrong')
            cb, pv = e['ir3']['const_budget'], e['ir3']['pvtmem']
            if ki['safe_constlen'] != cb['safe_constlen']: err('safe_constlen key bit != const_budget')
            if cb['safe_constlen'] and cb['constlen'] > cb['max_const_safe']: err('safe_constlen variant over max_const_safe')
            if not cb['safe_constlen'] and cb['exceeds_safe_constlen']:
                ki2 = dict(ki, safe_constlen=True)
                need_safe.append((k, cachekey.key_of_sidecar(dict(e, key_inputs=ki2), chip)))
            if pv['total_size'] > pv['budget']: err('pvtmem over budget')
            if cachekey.key_of_sidecar(e, chip) != k: err('key does not recompute from key_inputs')
            if ki['stage'] != e['reflection']['stage'] or ki['entry'] != e['reflection']['function']: err('stage/entry differ from the reflection')
            if e.get('lookup') is False or e.get('library') == 'SkyLight-runtime': err('runtime-template entry in entries/')
            if e['format_version'] != cachekey.CACHE_FORMAT_VERSION or e['abi_version'] != cachekey.ABI_VERSION: err('format/abi version')
            if e['variant_id'] != '0x' + k[:16]: err('variant_id')
            if e['blob']['path'] != 'blobs/' + e['blob']['sha256'] + '.ir3v': err('blob path')
            for fld in ('compiler_id', 'abi_version', 'format_version', 'chip_id'):
                if e[fld] != man[fld]: err(f'{fld} {e[fld]} != manifest {man[fld]}')
            bp = os.path.join(cache, e['blob']['path'])
            if bp not in blobs:
                b = open(bp, 'rb').read() if os.path.exists(bp) else None
                blobs[bp] = (hashlib.sha256(b).hexdigest(), len(b)) if b is not None else None
            if blobs[bp] is None: err('blob missing')
            elif blobs[bp] != (e['blob']['sha256'], e['blob']['size']): err('blob hash/size mismatch')
            cs = e['constant_samplers']
            mask = sum(1 << s['slot'] for s in cs['samplers'])
            if int(cs['bitmask'], 16) != mask or int(e['reflection']['constexpr_sampler_mask'], 16) != mask: err('constexpr sampler bitmask')
            sid = hashlib.sha256(b''.join(bytes.fromhex(s['unique_id'][2:]) + bytes([s['slot']]) for s in sorted(cs['samplers'], key=lambda s: s['slot']))).hexdigest()[:16]
            if cs['set_id'] != '0x' + sid: err('constexpr sampler set_id')
    for k, sk in need_safe:
        if sk not in have: errors.append(f'{k[:16]}: exceeds max_const_safe but its safe_constlen variant {sk[:16]} is not cached')
    ok_reload = 0
    if reload_n:
        paths = sorted(blobs)
        for bp in paths[::max(1, len(paths) // reload_n)][:reload_n]:
            r = subprocess.run([os.path.join(ROOT, 'build', 'air2ir3'), '--quiet', '--verify-variant', bp], capture_output=True, text=True)
            if r.returncode == 0: ok_reload += 1
            else: errors.append(f'reload {os.path.basename(bp)}: {r.stderr.strip()[-200:]}')
    ev = os.path.join(cache, 'evidence')
    evidence = {f[:-6]: sum(1 for _ in open(os.path.join(ev, f))) for f in sorted(os.listdir(ev))} if os.path.isdir(ev) else {}
    print(json.dumps(dict(entries=n, blobs=len(blobs), safe_constlen_pairs=len(need_safe), compiler_id=man['compiler_id'], reloaded_ok=f'{ok_reload}/{reload_n}',
                          evidence_only=evidence, errors=len(errors), first_errors=errors[:10]), indent=1))
    sys.exit(1 if errors else 0)

if __name__ == '__main__':
    main()
