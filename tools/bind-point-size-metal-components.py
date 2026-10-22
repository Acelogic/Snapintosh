#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the point-size plug-in/probe to the corrected network/display collection.

Same checks as bind-composite-metal-components.py (kext 3c10369c, AuxKC 1f22aed6,
network personality, display source, compiler closure, probe identity, native
pipelines, four composite CA captures with kernel replays and extents), bound to
this candidate's evidence, with the compiler closure of the new compiler (2aca7392:
the opt_jump legalize fix and no disassembly text, outputs byte-identical to 7d0e1491
over the whole corpus). Additionally the plug-in must carry, as its linked
__ADRENO,__shadercache section, exactly the pack of 25 real CoreAnimation records,
including the generic pipeline (VfxXg, Xgc and its safe_constlen variant); the host
cache qualification must pass; every generic draw in the captures must carry the
point-size state; and the generic draws must match Metal on the host. Failure
inventory: mixed compiler/probe identities, a pack other than the qualified one, a
pack without the generic pipeline, stale captured commands, and host evidence
mistaken for physical execution. Host files only; installation requires a fresh
stopped-guest SSD snapshot. Doc: docs/SHADER-COMPILE-PATH-20260928.md.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/bind-composite-metal-components.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == 'ccb370c23b40b619c0c6701f72ae662ac0036927b7a53041e7e4eb6880736c38'
PACK = 'build/psize-deploy/AdrenoShaderCache-real-ca-v1.amsp'
PACK_SHA = 'e60c9ba022e366c9f764b0c7b1f58f182b5feae08c0c89201b09b650795e86ec'
GENERIC = {  # CoreAnimation's generic pipeline, com.apple.coreanimation.PBGRA_Xgc
    'a2e41f9e838fd91e4f2e966a4034e3445b7ae0f59106568cbc91acad6faae11d': 'VfxXg',
    '8a6afe275869cdaa6ebf498a7ecdd48f0f419ca3a348ea4d851a9205ef90cf52': 'Xgc',
    'f2528f65c440ee2b3d87446550895fac4aab0bfadefdddfd60b096d640f00cee': 'Xgc safe_constlen',
}
source = base.read_text()
changes = {
    "    native_path = ROOT / 'build/qc-pipelines-composite-20260928-v1.json'\n    native = read(native_path,\n        'e21bc5f0e164a5d230630ccb014ccdd32cb07c41b702ae35bffdba8eda917d58')":
        "    native_path = ROOT / 'build/qc-pipelines-psize-20260928-v2.json'\n    native = read(native_path,\n        '7d9724713e182b56029b2b668155d6de78794c930ba1773abb485ab3ed775f68')",
    "    compiler = read(PIPELINE / 'build/ca-compiler-vpc-20260928-v1/qualification.json',\n        '67e95cc74486121b68ff8a5e6577f589f382277dd1b83366ddbd83bceae1631d', PIPELINE)":
        "    compiler = read(ROOT / 'build/psize-compiler-runtime-v1/qualification.json',\n        'cd6b4459a9c651a1f4d932388b235766e8b6298aa1b66dd094943dbfbd2cce92', ROOT)",
    "    assert compiler['artifacts_sha256']['runtime/libAdrenoCompiler.dylib'] == native['compiler_sha256']\n":
        "    assert compiler['artifacts_sha256']['runtime/libAdrenoCompiler.dylib'] == native['compiler_sha256']\n"
        "    assert compiler['compiler_id'].startswith('air2ir3-src-585ddc20ba0499bf+')\n"
        "    corpus = read(ROOT / 'build/psize-compare-corpus-v1/report.json',\n"
        "        'aff3242ea888d75ae9dc0b968e09f8fa409d506c08fc1002c6a2781db6f52da3')\n"
        "    assert corpus['status'] == 'COMPILER_OUTPUTS_IDENTICAL' and corpus['difference_count'] == 0\n"
        "    assert corpus['results'] == 35597 and corpus['ca_air_jobs'] == 24\n"
        "    assert corpus['new']['sha256'] == native['compiler_sha256']\n"
        "    assert corpus['old']['sha256'] == '7d0e1491c9de4c15214ef82054b696acb7c6503229ed3a747ea08cf792bfbfa6'\n"
        "    for side in ('old', 'new'):\n"
        "        bind(corpus[side]['path'], corpus[side]['sha256'])\n"
        "    host = read(ROOT / 'build/psize-qualification-v2/summary.json',\n"
        "        'f1cf8e99cfcc20171e42fa44999228afe818615f1b1f567678e7842abac0eb49')\n"
        "    assert host['status'] == 'PASS' and len(host['checks']) == 23 and all(c['ok'] for c in host['checks'].values())\n"
        "    assert native['compiler_sha256'] in host['inputs_sha256'].values()\n",
    "    probe_path = ROOT / 'build/ca-composite-guest-probe-20260928-v1/build.json'\n    probe = read(probe_path,\n        '676f35ab479a93f4e3fb812ffff2e610cc1dcce4aaeeea9c64edaed3c067be08')":
        "    probe_path = ROOT / 'build/psize-guest-probe-20260928-v1/build.json'\n    probe = read(probe_path,\n        'f2f22a975750e1319ec36e417f99e2d7c9f07708a28a63e254c5dea6eabe1f6a')",
    "    capture_path = ROOT / 'build/ca-composite-private-20260928-v1/capture.json'\n    capture = read(capture_path,\n        'd77cee4c9f8d907804ce7f95cf12cb3dd246c268c9ff1dd217b9143481a54efd')":
        "    capture_path = ROOT / 'build/ca-psize-private-20260928-v1/capture.json'\n    capture = read(capture_path,\n        '3fe53c40fc64727ccff3ac5a18d3b84c600fa079072f00e81262735057aa8f63')",
    "        extent_path = ROOT / f'build/ca-composite-extents-{scene}-20260928-v2.json'":
        "        extent_path = ROOT / f'build/ca-psize-extents-{scene}-20260928-v1.json'",
    "    for tree in (bundle, kext, ROOT / 'gpu/adreno-kext/plugin', ROOT / 'gpu/adreno-kext/kext'):":
        "    pack = bind(ROOT / PACK, PACK_SHA)\n"
        "    import sys\n"
        "    sys.path.insert(0, str(ROOT / 'gpu/adreno-kext/plugin'))\n"
        "    import shader_cache_pack\n"
        "    ident, records = shader_cache_pack.read_pack((ROOT / PACK).read_bytes())\n"
        "    assert len(records) == 25 and ident == compiler['compiler_id'].encode()\n"
        "    assert set(GENERIC) <= {key.decode() for key in records}, 'pack lacks the generic pipeline'\n"
        "    import re\n"
        "    plugin = bundle / 'Contents/MacOS/AdrenoMetal'\n"
        "    commands = subprocess.run(['otool', '-l', str(plugin)], capture_output=True, text=True, check=True).stdout\n"
        "    (size, offset), = re.findall(r'sectname __shadercache\\n\\s+segname __ADRENO\\n\\s+addr \\S+\\n\\s+size (0x[0-9a-f]+)\\n\\s+offset (\\d+)', commands)\n"
        "    section = plugin.read_bytes()[int(offset):int(offset) + int(size, 16)]\n"
        "    assert section == (ROOT / PACK).read_bytes(), 'plug-in does not carry the qualified pack'\n"
        "    draws = read(ROOT / 'build/ca-psize-draws-20260928-v1.json',\n"
        "        'b88706382d7349f028adfdb3e4d6db253406a014949eb7065601d9967041d068')\n"
        "    assert draws['status'] == 'CA_POINT_SIZE_DRAWS_DECODED_AND_CHECKED' and not draws['gpu_execution']\n"
        "    bind(ROOT / 'tools/inspect-ca-point-draws.py', draws['source_sha256'])\n"
        "    adreno = {case['sha256'] for case in capture['cases'] if case['mode'] == 'adreno'}\n"
        "    assert {scene['capture_sha256'] for scene in draws['scenes']} == adreno and len(adreno) == 4\n"
        "    for scene in draws['scenes']:\n"
        "        bind(ROOT / scene['capture'], scene['capture_sha256'])\n"
        "    generic_draws = sum(scene['point_size_draws'] for scene in draws['scenes'])\n"
        "    conformance = read(ROOT / 'build/ca-psize-generic-conformance-folded-20260928-v1/report.json',\n"
        "        '9896f33150c0d1d97f6acccb0e40af49c04a7c1bc67ef392349bc7ae2fdd43e3')\n"
        "    assert conformance['status'] == 'CA_GENERIC_DRAWS_LLVMPIPE_MATCH_METAL' and not conformance['gpu_execution_of_adreno_commands']\n"
        "    assert conformance['summary']['draws'] == conformance['summary']['within_tolerance'] == generic_draws == 29\n"
        "    bind(ROOT / 'tools/conform-ca-generic-draws.py', conformance['source_sha256'])\n"
        "    for tree in (bundle, kext, ROOT / 'gpu/adreno-kext/plugin', ROOT / 'gpu/adreno-kext/kext'):",
    "        boundary='New composite plug-in/probe with corrected network/display kext.":
        "        shader_pack=str(ROOT / PACK), shader_pack_sha256=pack, shader_pack_records=len(records),\n"
        "        generic_pipeline_records=GENERIC, compiler_id=compiler['compiler_id'],\n"
        "        generic_point_size_draws=generic_draws, generic_draws_matching_metal=conformance['summary']['within_tolerance'],\n"
        "        boundary='Point-size plug-in (CoreAnimation generic pipeline: point size and point coordinate, one-slice 3D textures; linked 25-record real-CoreAnimation pack with the generic pipeline; per-user records on; early-stop report), new compiler and its probe with corrected network/display kext.",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__', PACK=PACK, PACK_SHA=PACK_SHA, GENERIC=GENERIC))
