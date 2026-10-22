#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify the stock-image -> HVC-image -> paired monitor build pipeline offline.

Failure inventory: docs/SPTM-CALL-ENTRY-20260930.md. This exercises the real
348-site firmware contract and produces a repeatable patch manifest and build
records. It does not execute XNU or establish hardware ABI/performance results.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from nativecalls import (CALL_WORDS, FLAG, HVC_FLAG, HVC_IMMEDIATE, HVC_WORD,
                         KERNEL_SHA256, contract, count_word, patch_hvc_calls)


def load_image_api():
    spec = importlib.util.spec_from_file_location('sptm_entry_kc_load', ROOT / 'tools/kc-load.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def refuses(action):
    try:
        action()
    except ValueError:
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--kernelcache', type=Path,
                    default=ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p')
    ap.add_argument('--output', type=Path, required=True, help='fresh artifact directory')
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    kc = load_image_api()
    source = args.kernelcache.read_bytes()
    image = kc.Image(source)
    loaded = bytearray(source)
    for offset, value in kc.chained_fixups(image, 0):
        struct.pack_into('<Q', loaded, offset, value)
    control = bytes(loaded)
    # Placement is arbitrary for this offline contract: offsets and virtual
    # addresses are invariant; the live loader uses its actual IMAGE_PA.
    image_pa = 0x90000000
    stock = contract(image, loaded, image_pa)
    patched = patch_hvc_calls(image, loaded, image_pa)
    changes = []
    actual = []
    for _, va, _, off, size in image.executable_segments:
        for delta in range(0, size, 4):
            before = struct.unpack_from('<I', control, off + delta)[0]
            after = struct.unpack_from('<I', loaded, off + delta)[0]
            if before != after:
                require(before in CALL_WORDS and after == HVC_WORD,
                        'executable change outside prescribed private-call replacement')
                changes.append(dict(va=hex(va + delta), file_offset=off + delta,
                                    before=hex(before), after=hex(after)))
                actual.append(va + delta)
    require(len(changes) == 348 and sorted(actual) == sorted(stock['call_sites']),
            'changed-site list differs from the complete stock call inventory')
    restored = bytearray(loaded)
    for change in changes:
        struct.pack_into('<I', restored, change['file_offset'], int(change['before'], 16))
    require(restored == control, 'non-call bytes changed in the loaded image')
    require(stock['pages'] == patched['pages'], 'call/writer physical geometry changed')
    require(count_word(stock['pages'], True) == FLAG | 7, 'stock parameter ABI changed')
    require(count_word(patched['pages'], True, True) == FLAG | HVC_FLAG | 7,
            'HVC parameter ABI mismatch')
    require(refuses(lambda: contract(image, loaded, image_pa)),
            'stock admission accepted the patched executable')
    require(refuses(lambda: contract(image, control, image_pa, hvc=True)),
            'HVC admission accepted unpatched executable')
    incomplete = bytearray(loaded)
    first = changes[0]
    struct.pack_into('<I', incomplete, first['file_offset'], int(first['before'], 16))
    require(refuses(lambda: contract(image, incomplete, image_pa, hvc=True)),
            'HVC admission accepted a missing replacement')
    # Exercise the real loader and serialized monitor parameters, not just the
    # patch helper. The default audited profile needs no SSD or AuxKC input.
    import xnuboot as xb
    loader_records = {}
    saved_env = {name: os.environ.get(name)
                 for name in ('SNAP_NATIVE_CALLS', 'SNAP_SPTM_HVC_CALLS')}
    try:
        xb.configure_guest('j700ap-26A428', args.kernelcache.parent)
        for name, enabled in [('control', False), ('hvc', True)]:
            os.environ['SNAP_NATIVE_CALLS'] = '1'
            os.environ['SNAP_SPTM_HVC_CALLS'] = '1' if enabled else '0'
            with (out / (name + '-loader.log')).open('w') as log, contextlib.redirect_stdout(log):
                built = xb.build(args.kernelcache)
            params = xb.params_blob(built)
            require(struct.unpack_from('<Q', params, 7 * 8)[0] ==
                    count_word(built['stub_pa'], True, enabled),
                    'real loader parameter mode does not match patched image')
            admitted = built['native_call_contract']
            require(built['sptm_hvc_calls'] is enabled and
                    admitted['mode'] == ('hvc' if enabled else 'private'),
                    'real loader lost the explicit call-entry mode')
            for address, original in admitted['call_sites'].items():
                pa = xb.IMAGE_PA + address - built['vmin']
                values = [struct.unpack_from('<I', chunk, pa - base)[0]
                          for base, chunk in built['chunks'].items()
                          if base <= pa and pa + 4 <= base + len(chunk)]
                require(values == [HVC_WORD if enabled else original],
                        'uploaded chunk call word differs from admitted image')
            (out / (name + '-params.bin')).write_bytes(params)
            loader_records[name] = dict(params_sha256=digest(params),
                image_pa=hex(xb.IMAGE_PA), chunks=len(built['chunks']),
                uploaded_bytes=sum(map(len, built['chunks'].values())),
                loaded_data_sha256=admitted['loaded_data_sha256'],
                verified_upload_call_sites=len(admitted['call_sites']))
            del built
    finally:
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    build_records = {}
    for name, extra in [('control', []), ('hvc', ['--sptm-hvc-calls'])]:
        command = [sys.executable, str(ROOT / 'tools/build-fast-traps-monitor.py'),
                   '--out', str(out / name), *extra]
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        (out / (name + '-build.log')).write_text(result.stdout + result.stderr)
        require(result.returncode == 0, f'{name} monitor build failed; see build log')
        record = json.loads((out / name / 'build.json').read_text())
        for artifact in ['bin', 'elf']:
            require(digest((out / name / ('xnuboot.' + artifact)).read_bytes()) ==
                    record[artifact + '_sha256'], f'{name} monitor {artifact} digest mismatch')
        require(record['bytes'] <= record['reserved'], f'{name} code reservation overflow')
        build_records[name] = record
    require(build_records['hvc']['flags'] ==
            build_records['control']['flags'] + ['-DSNAP_SPTM_HVC_CALLS=1'],
            'paired monitor flags differ beyond the requested call-entry experiment')
    patch = dict(stock_kernel_sha256=KERNEL_SHA256,
                 loaded_control_sha256=digest(control), loaded_hvc_sha256=digest(loaded),
                 immediate=hex(HVC_IMMEDIATE), word=hex(HVC_WORD), changes=changes)
    patch_path = out / 'patch.json'
    patch_path.write_text(json.dumps(patch, indent=2) + '\n')
    result = dict(status='OFFLINE_IMAGE_AND_PAIRED_BUILDS_QUALIFIED',
                  boundary='No native execution, XNU boot, or speedup is established.',
                  kernelcache=str(args.kernelcache.resolve()), kernel_sha256=digest(source),
                  call_sites=len(changes), call_pages=len(stock['call_pages']),
                  writer_sites=len(stock['writer_sites']), writer_pages=len(stock['writer_pages']),
                  stock_count_word=hex(count_word(stock['pages'], True)),
                  hvc_count_word=hex(count_word(stock['pages'], True, True)),
                  patch_manifest_sha256=digest(patch_path.read_bytes()),
                  loaders=loader_records,
                  builds=build_records,
                  reproduce=[sys.executable, str(Path(__file__).resolve()),
                             '--kernelcache', str(args.kernelcache.resolve()),
                             '--output', 'NEW_ARTIFACT_DIRECTORY'])
    (out / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], call_sites=len(changes),
                         artifact=str(out / 'qualification.json'))))


if __name__ == '__main__':
    main()
