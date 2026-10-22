#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the full guest image of the -sks-quiet profile from an -sks stage.

Generation63's image was qualified by ../Snapintosh-adreno-composite/tools/
qualify-qc-metal-image.py: the unchanged base qualifier tools/qualify-adreno-gui-image.py
run against the Snapintosh-adreno-sks probes. This runs the same base qualifier
against this checkout's probes (23c583f plus the quiet profile), with the guest
profile chosen here instead of read from the stage record. The stage was prepared
for -sks; the base qualifier still requires its trust cache to reproduce byte for
byte under the chosen profile. The only changed expectation is the display slot:
disp0 for -sks, /arm-io/adreno-display for -sks-quiet.

    python3 tools/qualify-qc-metal-quiet-image.py --deployment STAGE/deployment.json \\
        --root-hash ROOT_HASH --output NEW_DIR [--profile sks|quiet] \\
        [--auxkc COLLECTION --auxkc-qualification QUALIFICATION]

--profile sks rebuilds the generation63 image from this checkout (a control that
the patch leaves -sks unchanged); the default is quiet.

--auxkc builds the image with a relinked collection in place of the stage's
deployed one (the AuxKC is loaded from RAM, not installed on the SSD, so the stage
and its trust cache are unchanged). Its kext qualification must name exactly this
collection, replace the stage's own collection and kext (booted_*), and keep the
booted classes, Info.plist and linked personalities. The record keeps the staged
collection as staged_auxkc_sha256 and binds the collection and qualification.
"""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'tools/qualify-adreno-gui-image.py'
BASE_SHA256 = '2d37fce355f650f1b360b9e7faf751e835989cc973f6c08b9b823f000c6e379e'
SKS = 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks'
SLOTS = {SKS: '/device-tree/arm-io/disp0', SKS + '-quiet': '/device-tree/arm-io/adreno-display'}


def option(argv, name):
    if name not in argv:
        return None
    i = argv.index(name)
    value = argv[i + 1]
    del argv[i:i + 2]
    return value


def explicit_collection(collection, qualification):
    """The relinked collection and its kext qualification, checked against each
    other; the stage-side checks run inside the base qualifier."""
    collection, qualification = Path(collection).resolve(), Path(qualification).resolve()
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    q = json.loads(qualification.read_text())
    assert Path(q['collection']).resolve() == collection, q['collection']
    assert digest(collection) == q['collection_sha256'], collection
    assert q['hardware_access'] is False
    for key in ('classes_equal_to_booted', 'info_plist_identical_to_booted',
                'linked_collection_personalities_equal_to_booted'):
        assert q[key] is True, key
    return collection, qualification, q


argv = sys.argv[1:]
choice = option(argv, '--profile') or 'quiet'
AUXKC = option(argv, '--auxkc')
AUXKC_QUALIFICATION = option(argv, '--auxkc-qualification')
assert bool(AUXKC) == bool(AUXKC_QUALIFICATION), '--auxkc needs --auxkc-qualification'
AUXKC_RECORD = None
if AUXKC:
    AUXKC, AUXKC_QUALIFICATION, AUXKC_RECORD = explicit_collection(AUXKC, AUXKC_QUALIFICATION)
PROFILE = {'sks': SKS, 'quiet': SKS + '-quiet'}[choice]
sys.argv = [sys.argv[0]] + argv
assert hashlib.sha256(BASE.read_bytes()).hexdigest() == BASE_SHA256, BASE
source = BASE.read_text()
changes = {
    "    for p in (Path(__file__), helper_path): sources[str(p.relative_to(ROOT))] = sha(p)":
        "    for p in (Path(__file__), helper_path, BASE): sources[str(p.relative_to(ROOT))] = sha(p)",
    "    profile = deployment['guest_profile']\n"
    "    assert profile == 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display'":
        "    assert deployment['guest_profile'] == SKS, deployment['guest_profile']\n"
        "    profile = PROFILE",
    "    assert slots == ['/device-tree/arm-io/disp0']":
        "    assert slots == [SLOTS[profile]], slots",
    "guest_profile=profile,":
        "guest_profile=profile, staged_guest_profile=deployment['guest_profile'],",
}
if AUXKC:
    changes.update({
        "    collection = Path(deployment['deployed_collection'])\n"
        "    assert sha(collection) == deployment['deployed_collection_sha256']":
            "    staged = Path(deployment['deployed_collection'])\n"
            "    assert sha(staged) == deployment['deployed_collection_sha256']\n"
            "    assert AUXKC_RECORD['booted_collection_sha256'] == deployment['deployed_collection_sha256']\n"
            "    assert AUXKC_RECORD['booted_kext_sha256'] == components['kext_sha256']\n"
            "    assert AUXKC_RECORD['guest_profile'] == deployment['guest_profile']\n"
            "    collection = AUXKC",
        "auxkc_sha256=sha(collection),":
            "auxkc_sha256=sha(collection), auxkc=str(collection), staged_auxkc_sha256=sha(staged), "
            "auxkc_qualification=str(AUXKC_QUALIFICATION), auxkc_qualification_sha256=sha(AUXKC_QUALIFICATION), "
            "kext_sha256=AUXKC_RECORD['kext_sha256'], staged_kext_sha256=components['kext_sha256'],",
    })
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(BASE), 'exec'),
     dict(__file__=str(Path(__file__).resolve()), __name__='__main__', BASE=BASE, SKS=SKS, PROFILE=PROFILE, SLOTS=SLOTS,
          AUXKC=AUXKC, AUXKC_QUALIFICATION=AUXKC_QUALIFICATION, AUXKC_RECORD=AUXKC_RECORD))
