#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the shader-cache plug-in/probe to the corrected network/display collection.

Same checks as bind-composite-metal-components.py (kext 3c10369c, AuxKC 1f22aed6,
network personality, display source, compiler closure, probe identity, native
pipelines, four composite CA captures with kernel replays and extents), bound to
this candidate's evidence. Additionally the plug-in must carry, as its linked
__ADRENO,__shadercache section, exactly the qualified pack of 22 real
CoreAnimation shader records. Failure inventory: mixed compiler/probe
identities, a pack other than the qualified one, stale captured commands, and
host evidence mistaken for physical execution. Host files only; installation
requires a fresh stopped-guest SSD snapshot. Doc: docs/SHADER-COMPILE-PATH-20260928.md.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/bind-composite-metal-components.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == 'ccb370c23b40b619c0c6701f72ae662ac0036927b7a53041e7e4eb6880736c38'
PACK = 'build/shader-cache-deploy-20260928/AdrenoShaderCache-real-ca-v2.amsp'
PACK_SHA = '01df66b14341f63b6f2e58ed942f18777770dcb39e052adfd83bbdae2b7c5a18'
source = base.read_text()
changes = {
    "    native_path = ROOT / 'build/qc-pipelines-composite-20260928-v1.json'\n    native = read(native_path,\n        'e21bc5f0e164a5d230630ccb014ccdd32cb07c41b702ae35bffdba8eda917d58')":
        "    native_path = ROOT / 'build/qc-pipelines-shader-cache-20260928-v2.json'\n    native = read(native_path,\n        '81e295ad72fd0b6a9d776ce42d12b63c1ae37fa7d0a0ad26a04e82bf3d8369f4')",
    "    probe_path = ROOT / 'build/ca-composite-guest-probe-20260928-v1/build.json'\n    probe = read(probe_path,\n        '676f35ab479a93f4e3fb812ffff2e610cc1dcce4aaeeea9c64edaed3c067be08')":
        "    probe_path = ROOT / 'build/shader-cache-guest-probe-20260928-v2/build.json'\n    probe = read(probe_path,\n        '8be6e5b9cb015afd78b6e1b007e3329b7c123f2cb1d990a5518d2a114806bbdc')",
    "    capture_path = ROOT / 'build/ca-composite-private-20260928-v1/capture.json'\n    capture = read(capture_path,\n        'd77cee4c9f8d907804ce7f95cf12cb3dd246c268c9ff1dd217b9143481a54efd')":
        "    capture_path = ROOT / 'build/ca-shader-cache-private-20260928-v2/capture.json'\n    capture = read(capture_path,\n        '978126935a3ea0dc6876bff39761f6fadf2e2f28afe51b042490f2c22cf1794c')",
    "        extent_path = ROOT / f'build/ca-composite-extents-{scene}-20260928-v2.json'":
        "        extent_path = ROOT / f'build/ca-shader-cache-extents-{scene}-20260928-v1.json'",
    "    for tree in (bundle, kext, ROOT / 'gpu/adreno-kext/plugin', ROOT / 'gpu/adreno-kext/kext'):":
        "    pack = bind(ROOT / PACK, PACK_SHA)\n"
        "    import sys\n"
        "    sys.path.insert(0, str(ROOT / 'gpu/adreno-kext/plugin'))\n"
        "    import shader_cache_pack\n"
        "    ident, records = shader_cache_pack.read_pack((ROOT / PACK).read_bytes())\n"
        "    assert len(records) == 22 and ident.startswith(b'air2ir3-src-c5c4da8159de827e+')\n"
        "    import re\n"
        "    plugin = bundle / 'Contents/MacOS/AdrenoMetal'\n"
        "    commands = subprocess.run(['otool', '-l', str(plugin)], capture_output=True, text=True, check=True).stdout\n"
        "    (size, offset), = re.findall(r'sectname __shadercache\\n\\s+segname __ADRENO\\n\\s+addr \\S+\\n\\s+size (0x[0-9a-f]+)\\n\\s+offset (\\d+)', commands)\n"
        "    section = plugin.read_bytes()[int(offset):int(offset) + int(size, 16)]\n"
        "    assert section == (ROOT / PACK).read_bytes(), 'plug-in does not carry the qualified pack'\n"
        "    for tree in (bundle, kext, ROOT / 'gpu/adreno-kext/plugin', ROOT / 'gpu/adreno-kext/kext'):",
    "        boundary='New composite plug-in/probe with corrected network/display kext.":
        "        shader_pack=str(ROOT / PACK), shader_pack_sha256=pack, shader_pack_records=len(records),\n"
        "        boundary='Shader-cache plug-in (linked real-CoreAnimation pack, early-stop report) and its probe with corrected network/display kext.",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__', PACK=PACK, PACK_SHA=PACK_SHA))
