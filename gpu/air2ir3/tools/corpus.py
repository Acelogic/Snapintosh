#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""corpus.py - extract every function of the WindowServer metallibs into corpus/<lib>/<fn>.bc and
write corpus/index.json (library sha256, function name/type, AIR HASH tag, bitcode sha256).

The HASH tag (32 bytes) is the SHA-256 of the function's bitcode as stored in the metallib
(PROVEN below: we recompute it) and is the first component of the precompiled-cache key.
"""
import hashlib, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import metallib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import scrdir
WS = os.path.join(scrdir.scratchpad(), 'adreno', 'windowserver-metal-usage', 'libs')
LIBS = {
    'SkyLight': [os.path.join(WS, 'SkyLight.metallib'),
                 '/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/SkyLightShaders.air64.metallib'],
    'CoreDisplay': [os.path.join(WS, 'CoreDisplay.metallib'),
                    '/System/Library/Frameworks/CoreDisplay.framework/Versions/A/Resources/default.metallib'],
    'QuartzCore': [os.path.join(WS, 'QuartzCore.air64_v29.metallib'),
                   '(air64_v29 slice of) /System/Library/Frameworks/QuartzCore.framework/Versions/A/Resources/default.metallib'],
}

def extract(lib, path, origin, outroot, index):
    d, hdr, funcs = metallib.parse(path)
    od = os.path.join(outroot, lib); os.makedirs(od, exist_ok=True)
    lsha = hashlib.sha256(d).hexdigest()
    for f in funcs:
        s = hdr['bitcode'][0] + f['bc_off']
        bc = d[s:s + f['bc_size']]
        p = os.path.join(od, f['name'] + '.bc')
        open(p, 'wb').write(bc)
        bsha = hashlib.sha256(bc).hexdigest()
        index.append(dict(lib=lib, lib_sha256=lsha, lib_origin=origin, function=f['name'], type=f.get('type'),
                          air_hash=f.get('hash'), bc_sha256=bsha, hash_is_bc_sha256=(f.get('hash') == bsha),
                          air_version=f.get('air_version'), msl_version=f.get('lang_version'),
                          bc=os.path.relpath(p, ROOT)))

if __name__ == '__main__':
    outroot = os.path.join(ROOT, 'corpus')
    index = []
    for lib, (p, origin) in LIBS.items():
        extract(lib, p, origin, outroot, index)
    extra = sys.argv[1:]            # additional metallibs: name=path
    for e in extra:
        n, p = e.split('=', 1); extract(n, p, p, outroot, index)
    json.dump(index, open(os.path.join(outroot, 'index.json'), 'w'), indent=1)
    by = {}
    for e in index: by.setdefault(e['lib'], []).append(e)
    for lib, es in by.items():
        print(f"{lib}: {len(es)} functions, HASH==sha256(bitcode) for {sum(e['hash_is_bc_sha256'] for e in es)}")
