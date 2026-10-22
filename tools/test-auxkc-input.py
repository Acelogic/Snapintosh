#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The --input AuxKC (installed_fresh.INPUT_AUXKC), offline.

    python3 tools/test-auxkc-input.py                          (the present collection, INPUT_AUXKC)
    SNAP_INPUT_AUXKC=cursor python3 tools/test-auxkc-input.py   (its rollback, INPUT_AUXKC_CURSOR)
    SNAP_INPUT_AUXKC=tpd2 python3 tools/test-auxkc-input.py     (its rollback, INPUT_AUXKC_TPD2)
    SNAP_INPUT_AUXKC=resident python3 tools/test-auxkc-input.py (INPUT_AUXKC_RESIDENT)
    SNAP_INPUT_AUXKC=ptp python3 tools/test-auxkc-input.py      (INPUT_AUXKC_PTP, --input-ptp)
    SNAP_INPUT_AUXKC=ptp-dartpool python3 tools/test-auxkc-input.py (INPUT_AUXKC_PTP_DARTPOOL)

No hardware, no sudo. docs/A16-INPUT-INSTALLED-20261017.md. Failure inventory: an asset that is not
the pinned one; a collection without both bundles or with either still explicit-load (XNU then omits
its personalities and, with no kernelmanagerd on this route, the kext never starts: v33); an AdrenoX2
that is not the default route's driver; a SnapI2CHID personality that differs from its source; a
packaging step that changed anything but the two flags; a multi-bundle autoload that weakened the
single-bundle form the default asset was made with.

 1. Every file of the asset by hash: the kc equals installed_fresh.INPUT_AUXKC_SHA, its pin and the
    autoload record's output; the raw link equals the record's source and the build record's
    collection; both kext inputs are the files in the asset (as recorded where the link ran), AdrenoX2's
    binary the expected one: the cursor kext (docs/ADRENO-DISPLAY-CURSOR-20261018.md) beside the tpd2
    collection's SnapI2CHID and AdrenoX2 Info.plist, else the comparison collection's own binary.
 2. The loader admits it (probes/auxkc.py load and the pinned kernelcache through
    xnuboot.linked_auxkc) with exactly AdrenoX2 and SnapI2CHID.
 3. Prelink metadata: both explicit-load flags false; AdrenoX2's dictionary equals the default
    AuxKC's but for the temporary staging path; SnapI2CHID's personality is its Info.plist's.
 4. tools/auxkc-autoload.py reproduces the asset from the raw link byte for byte, and reproduces
    the default asset (284f052f) and its retained record in the single-bundle form.
 5. The autoload refusals: a missing, extra, duplicate or non-Snapintosh bundle, a wrong source
    hash, or an already transformed input.
 6. tools/test-snap-i2c-hid-kext.py --kext on the asset's SnapI2CHID.kext.
"""
from pathlib import Path
import copy
import hashlib
import json
import os
import plistlib
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
sys.path.insert(0, str(ROOT / 'tools'))
sys.dont_write_bytecode = True
from auxkc import Collection  # noqa: E402
import auxkc  # noqa: E402

# Which --input collection: installed_fresh.INPUT_AUXKC (cursor), SNAP_INPUT_AUXKC=tpd2 for INPUT_AUXKC_TPD2,
# or SNAP_INPUT_AUXKC=resident for INPUT_AUXKC_RESIDENT.
from cycle_lib import installed_fresh as _f  # noqa: E402
RUN = os.environ.get('SNAP_INPUT_AUXKC', 'maint')
RESIDENT_RUN = RUN == 'resident'
# The present collection (2026-10-19) is built exactly like the cursor one: 7ec040b4's objects with a rebuilt
# AdrenoDisplay.o (composed-row cursor publication), so it takes the cursor checks.
# The ci collection (v81) is the present one with adreno-ib-command.o rebuilt: the same checks.
# The pacing collection (speed batch) is the ci one with AdrenoDisplay.o rebuilt again: the same checks.
# The damage collection (2026-10-20, --present-damage) is the maint one with AdrenoDisplay.o rebuilt again.
# The cachedread collection (--present-cached-read) is the damage one with AdrenoDisplay.o built with
# -DADRENO_PRESENT_CACHED_READ=1.
# The gpumap collection (--present-gpumap, kext batch 8) is the cachedread one with AdrenoX2.o, AdrenoMemoryMap.o,
# adreno-resource.o and AdrenoDisplay.o rebuilt (pacing, VA release order, the empty-reservation pool).
# The vsync60 collection (--present-vsync60) is the gpumap one with AdrenoDisplay.o built with -DADRENO_VSYNC60=1.
# The dartpool collection (--present-dartpool, kext batch 9) is the vsync60 one with AdrenoMemoryMap.o and
# adreno-resource.o built with -DADRENO_POOL_ARENA=1 (the pool's 1 MiB arena class).
# The ptp collection (--input-ptp, docs/A16-INPUT-PTP-20261020.md) carries the vsync60 collection's AdrenoX2.kext
# byte for byte beside a new SnapI2CHID (Precision Touchpad mode): it is compared with the vsync60 collection.
# The ptp-dartpool collection (--input-ptp --present-dartpool) carries the dartpool collection's AdrenoX2.kext and
# the ptp collection's SnapI2CHID.kext, both byte for byte: it is compared with the dartpool collection.
CURSOR_RUN = RUN in ('cursor', 'present', 'ci', 'pacing', 'maint', 'damage', 'cachedread', 'gpumap', 'vsync60',
                     'dartpool')
KC_PATH, KC_SHA = {'resident': (_f.INPUT_AUXKC_RESIDENT, _f.INPUT_AUXKC_RESIDENT_SHA),
                   'tpd2': (_f.INPUT_AUXKC_TPD2, _f.INPUT_AUXKC_TPD2_SHA),
                   'cursor': (_f.INPUT_AUXKC_CURSOR, _f.INPUT_AUXKC_CURSOR_SHA),
                   'present': (_f.INPUT_AUXKC_PRESENT, _f.INPUT_AUXKC_PRESENT_SHA),
                   'ci': (_f.INPUT_AUXKC_CI, _f.INPUT_AUXKC_CI_SHA),
                   'pacing': (_f.INPUT_AUXKC_PACING, _f.INPUT_AUXKC_PACING_SHA),
                   'maint': (_f.INPUT_AUXKC, _f.INPUT_AUXKC_SHA),
                   'damage': (_f.INPUT_AUXKC_DAMAGE, _f.INPUT_AUXKC_DAMAGE_SHA),
                   'cachedread': (_f.INPUT_AUXKC_CACHED_READ, _f.INPUT_AUXKC_CACHED_READ_SHA),
                   'gpumap': (_f.INPUT_AUXKC_GPUMAP, _f.INPUT_AUXKC_GPUMAP_SHA),
                   'vsync60': (_f.INPUT_AUXKC_VSYNC60, _f.INPUT_AUXKC_VSYNC60_SHA),
                   'dartpool': (_f.INPUT_AUXKC_DARTPOOL, _f.INPUT_AUXKC_DARTPOOL_SHA),
                   'ptp': (_f.INPUT_AUXKC_PTP, _f.INPUT_AUXKC_PTP_SHA),
                   'ptp-dartpool': (_f.INPUT_AUXKC_PTP_DARTPOOL, _f.INPUT_AUXKC_PTP_DARTPOOL_SHA)}[RUN]
ASSET = (ROOT / KC_PATH).parent.resolve()
# A two-kext collection that already carries the AdrenoX2 this one must (same metadata). The cursor
# collection's AdrenoX2 is new: it is compared with the tpd2 collection it replaces, whose SnapI2CHID
# it must carry unchanged and whose AdrenoX2 (7ec040b4) supplied every object but AdrenoDisplay.o.
RESIDENT = ROOT / {'resident': 'build/current-assets/auxkc-input-resident-20261017',
                   'tpd2': 'build/current-assets/auxkc-input-recover-20261017',
                   'cursor': 'build/current-assets/auxkc-input-tpd2-20261018',
                   'present': 'build/current-assets/auxkc-input-tpd2-20261018',
                   'ci': 'build/current-assets/auxkc-input-tpd2-20261018',
                   'pacing': 'build/current-assets/auxkc-input-tpd2-20261018',
                   'maint': 'build/current-assets/auxkc-input-tpd2-20261018',
                   'damage': 'build/current-assets/auxkc-input-tpd2-20261018',
                   'cachedread': 'build/current-assets/auxkc-input-tpd2-20261018',
                   'gpumap': 'build/current-assets/auxkc-input-tpd2-20261018',
                   'vsync60': 'build/current-assets/auxkc-input-tpd2-20261018',
                   'dartpool': 'build/current-assets/auxkc-input-tpd2-20261018',
                   'ptp': 'build/current-assets/auxkc-input-vsync60-20261020',
                   'ptp-dartpool': 'build/current-assets/auxkc-input-dartpool-20261020'}[RUN]
DEFAULT_RAW = ROOT / 'build/current-assets/auxkc-resident-20261017/adreno.raw.kc'
DEFAULT_KC = ROOT / 'build/current-assets/auxkc-resident-20261017/adreno.kc'
KERNEL = ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
ADRENO, HID = 'org.snapintosh.driver.AdrenoX2', 'org.snapintosh.driver.SnapI2CHID'
READONLY_BINARY_SHA = '7ec040b4e8b3807ec0fe2e214985e8ff10afd0c0287142242d209942870190ca'
ADRENO_BINARY_SHA = {'resident': '604216d0e8fe7aa8354bf7b44ac1dd462aca03b19d7bce97609307a833f2fc01',
                     'tpd2': READONLY_BINARY_SHA,
                     'cursor': '851b9900ae89119146ef538782089bfb490bd92dec73ac04c91c0cce563a3b04',
                     'present': 'dacfed34c5af304e8d8f11114da8af14bf21e95da615a8212a4f9db63a896446',
                     'ci': 'a6c273fc722f57647cea38a4a8ebf86ec5679af4affe924449800dd826bc61d4',
                     'pacing': '41eaae71348a5e38a491c2f59d721aed830875bc902b17e41665e6288c79a52f',
                     'maint': 'e6dab2e71def328c91fe9459ef7ab606d210bd6fdc75ad18583865f786974364',
                     'damage': '7bddbf6e8679c7e488d4af2a5870f584f4a14dc7e4824e0cf7e29c16b7b13e81',
                     'cachedread': '6077798702ed4502aac59b5d983a1300396f7657a46e0239b2918243c84580a5',
                     'gpumap': '435a7649e763929faae2da599d1f9e1d829121e220abb04e2b362e0ef54022ce',
                     'vsync60': '9822b9182fc931f49ab7570a6efa6ff243d62c72d3bf796748d57bfd1fa8ca95',
                     'dartpool': 'd8fe13633a84d2e7d6647e75cb1169e116bac6c8d87520c14c5e5250e32da4dd',
                     'ptp': '9822b9182fc931f49ab7570a6efa6ff243d62c72d3bf796748d57bfd1fa8ca95',
                     'ptp-dartpool': 'd8fe13633a84d2e7d6647e75cb1169e116bac6c8d87520c14c5e5250e32da4dd'}[RUN]
# The --input-ptp SnapI2CHID (UUID F9EF3A10-030A-3F23-8964-2BBA9CD02751), built by drivers/snap-i2c-hid/build.sh.
PTP_SNAPI2CHID_SHA = '0850513db4b376a7d0c2623b11688ee6458a9eaa9db28e9be28687495f90f4c3'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def autoload():
    import importlib.util
    spec = importlib.util.spec_from_file_location('autoload', ROOT / 'tools/auxkc-autoload.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def entries(path):
    return {e['CFBundleIdentifier']: e for e in Collection(Path(path).read_bytes()).prelink_info()['_PrelinkInfoDictionary']}


class Asset(unittest.TestCase):
    def test_1_files(self):
        from cycle_lib import installed_fresh as f
        kc, raw = ASSET / 'adreno-input.kc', ASSET / 'adreno-input.raw.kc'
        self.assertEqual((ROOT / KC_PATH).resolve(), kc)
        pin = json.loads((ASSET / 'adreno-input.kc.json').read_text())
        packaging = json.loads((ASSET / 'packaging.json').read_text())
        build = json.loads((ASSET / 'adreno-input.raw.kc.build.json').read_text())
        self.assertEqual(sha(kc), KC_SHA)
        self.assertEqual(pin['sha256'], KC_SHA)
        self.assertEqual(pin['bundles'], f.INPUT_BUNDLES)
        self.assertEqual(packaging['output_sha256'], KC_SHA)
        self.assertEqual((packaging['source_sha256'], build['collection_sha256']), (sha(raw), sha(raw)))
        self.assertEqual(build['status'], 'PASSWORDLESS_AUXKC_BUILT')
        self.assertEqual(build['bundle_identifiers'], [ADRENO, HID])
        # The inputs as recorded where the link ran (the asset may have been built elsewhere and copied).
        built = Path(build['output']).parent
        inputs = {Path(k).relative_to(built).as_posix(): v for k, v in build['inputs_sha256'].items()
                  if Path(k).is_relative_to(built)}
        expected = {p.relative_to(ASSET).as_posix(): sha(p) for k in ('AdrenoX2.kext', 'SnapI2CHID.kext')
                    for p in (ASSET / k).rglob('*') if p.is_file()}
        self.assertEqual(inputs, expected)
        self.assertEqual(sha(ASSET / 'AdrenoX2.kext/Contents/MacOS/AdrenoX2'), ADRENO_BINARY_SHA)
        if CURSOR_RUN:
            self.assertEqual(sha(RESIDENT / 'AdrenoX2.kext/Contents/MacOS/AdrenoX2'), READONLY_BINARY_SHA)
            self.assertEqual((ASSET / 'AdrenoX2.kext/Contents/Info.plist').read_bytes(),
                             (RESIDENT / 'AdrenoX2.kext/Contents/Info.plist').read_bytes())
            same = {p.relative_to(RESIDENT).as_posix(): sha(p) for p in (RESIDENT / 'SnapI2CHID.kext').rglob('*')
                    if p.is_file()}
            self.assertEqual({k: v for k, v in expected.items() if k.startswith('SnapI2CHID.kext/')}, same)
        else:
            self.assertEqual(sha(RESIDENT / 'AdrenoX2.kext/Contents/MacOS/AdrenoX2'), ADRENO_BINARY_SHA)
        if RUN in ('ptp', 'ptp-dartpool'):   # the comparison collection's AdrenoX2.kext, every file; the PTP SnapI2CHID
            self.assertEqual({k: v for k, v in expected.items() if k.startswith('AdrenoX2.kext/')},
                             {p.relative_to(RESIDENT).as_posix(): sha(p) for p in (RESIDENT / 'AdrenoX2.kext').rglob('*')
                              if p.is_file()})
            self.assertEqual(sha(ASSET / 'SnapI2CHID.kext/Contents/MacOS/SnapI2CHID'), PTP_SNAPI2CHID_SHA)
        if RUN == 'ptp-dartpool':   # SnapI2CHID.kext is the ptp collection's, every file
            ptp = (ROOT / _f.INPUT_AUXKC_PTP).parent.resolve() / 'SnapI2CHID.kext'
            self.assertEqual({k: v for k, v in expected.items() if k.startswith('SnapI2CHID.kext/')},
                             {('SnapI2CHID.kext' / p.relative_to(ptp)).as_posix(): sha(p) for p in ptp.rglob('*')
                              if p.is_file()})
        self.assertEqual((ASSET / 'SnapI2CHID.kext/Contents/Info.plist').read_bytes(),
                         (ROOT / 'drivers/snap-i2c-hid/Info.plist').read_bytes())

    def test_2_loader_admits(self):
        import importlib.util
        kernel_sha = sha(KERNEL)
        _, manifest = auxkc.load(ASSET / 'adreno-input.kc', kernel_sha)
        self.assertEqual(manifest['bundles'], [ADRENO, HID])
        spec = importlib.util.spec_from_file_location('xb_auxkc_input', ROOT / 'probes/xnuboot.py')
        xb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(xb)
        from cycle_lib import installed_fresh as f
        xb.configure_guest(f.INPUT_PROFILE, ROOT / f.FIRMWARE)
        xb.linked_auxkc(xb.kc_load.Image(KERNEL.read_bytes()), ASSET / 'adreno-input.kc')

    def test_3_metadata(self):
        combined, default = entries(ASSET / 'adreno-input.kc'), entries(RESIDENT / 'adreno-input.kc')
        self.assertEqual(set(combined), {ADRENO, HID})
        self.assertTrue(all(e['OSBundleRequireExplicitLoad'] is False for e in combined.values()))
        a, b = dict(combined[ADRENO]), dict(default[ADRENO])
        self.assertNotEqual(a.pop('_PrelinkBundlePath'), b.pop('_PrelinkBundlePath'))
        if CURSOR_RUN:      # another executable, the same driver metadata
            for key in ('OSBundleUUID', '_PrelinkExecutableSize'):
                self.assertNotEqual(a.pop(key), b.pop(key), key)
        self.assertEqual(a, b, 'AdrenoX2 is not the expected driver')
        source = plistlib.loads((ROOT / 'drivers/snap-i2c-hid/Info.plist').read_bytes())
        got = copy.deepcopy(combined[HID]['IOKitPersonalities'])
        for personality in got.values():
            self.assertEqual(personality.pop('IOPersonalityPublisher', HID), HID)
        self.assertEqual(got, source['IOKitPersonalities'])
        self.assertEqual(combined[HID]['OSBundleLibraries'], source['OSBundleLibraries'])

    def test_4_autoload_reproduces(self):
        tool = autoload()
        raw = (ASSET / 'adreno-input.raw.kc').read_bytes()
        out, record = tool.prepare(raw, sha(ASSET / 'adreno-input.raw.kc'), [ADRENO, HID])
        self.assertEqual(out, (ASSET / 'adreno-input.kc').read_bytes())
        retained = json.loads((ASSET / 'packaging.json').read_text())
        for key in ('source', 'output', 'tool_sha256'):
            retained.pop(key)
        self.assertEqual(record, retained)
        self.assertEqual(record['changed_byte_count'], 10)
        # The single-bundle form, as the default asset was made.
        out, record = tool.prepare(DEFAULT_RAW.read_bytes(), sha(DEFAULT_RAW), ADRENO)
        self.assertEqual(hashlib.sha256(out).hexdigest(), sha(DEFAULT_KC))
        retained = json.loads((DEFAULT_KC.parent / 'packaging.json').read_text())
        for key in ('source', 'output', 'tool_sha256'):
            retained.pop(key)
        self.assertEqual(record, retained)

    def test_5_autoload_refusals(self):
        tool = autoload()
        raw = (ASSET / 'adreno-input.raw.kc').read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        done = (ASSET / 'adreno-input.kc').read_bytes()
        for args, why in (((raw, digest, [ADRENO]), 'one bundle missing'),
                          ((raw, digest, ADRENO), 'single form on a two-kext collection'),
                          ((raw, digest, [ADRENO, HID, 'org.snapintosh.driver.Other']), 'extra bundle'),
                          ((raw, digest, [ADRENO, ADRENO]), 'duplicate bundle'),
                          ((raw, digest, [ADRENO, 'com.apple.iokit.IOHIDFamily']), 'not Snapintosh-owned'),
                          ((raw, '0' * 64, [ADRENO, HID]), 'wrong source hash'),
                          ((done, hashlib.sha256(done).hexdigest(), [ADRENO, HID]), 'already transformed')):
            with self.assertRaises(ValueError, msg=why):
                tool.prepare(*args)

    def test_6_kext(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tools/test-snap-i2c-hid-kext.py'), '--kext',
                                 str(ASSET / 'SnapI2CHID.kext')], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr[-3000:])


if __name__ == '__main__':
    os.chdir(ROOT)
    unittest.main(verbosity=2)
