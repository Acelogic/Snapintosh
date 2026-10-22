#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Boot the corrected combined kernel driver with the installed CA plug-in.

Failure inventory: changed image/monitor/trust, a missing network personality,
wrong generation, a still-active standalone GPU, concurrent owner, a stale disk
header, or claiming offline construction proves a desktop. No SSD rewrite.
"""
from pathlib import Path
import hashlib
import json
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT.parent/'Snapintosh-adreno-sks'
WORK = ROOT.parent/'Snapintosh-adreno-buffer-textures'
Q = ROOT.parent/'q1n1'
BASE = ROOT/'tools/run-sks-transport-candidate.py'
IMAGE = WORK/'build/ca-network-guest-20260928-v1/qualification.json'
IMAGE_SHA = '2d0342ee4ff3347ed8913befff55f8cf06ae5f475e9074e4fcc94e71fac909b2'
PREFIX = 'installed-metal-ca-network-3600s-20260928'
PREDECESSOR = 'installed-metal-ca-3600s-20260928'
RETIREMENT = ROOT/'build/ca-network-boot-20260928/retirement-gen60-v1.json'
RETIREMENT_SHA = 'e0a01203d35d500610a598ee35e7a7f5881196b2b7b3311a1ce8e54788e75a98'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text())
assert sha(BASE) == '52fe215a9a4779ebc50f01ecaafb4a4210d2b506b09e6ee10a5fbb089a5cc6b8'
source = BASE.read_text()
changes = {
    "PREFIX='installed-metal-sks-transport-2100s-20260928'":f'PREFIX={PREFIX!r}',
    "PREDECESSOR='installed-metal-sks-2100s-20260928'":f'PREDECESSOR={PREDECESSOR!r}',
    "SNAP_WATCHDOG='2100'":"SNAP_WATCHDOG='3600'",
    "context_fields=old['context_fields']+1":"context_fields=old['context_fields']",
    "('.c','.h','.py','.S','.ld')":"('.c','.h','.py','.S','.ld','.cpp','.m','.sh','.plist')",
    "comparison='Generation54: correct native SKS query command/sequence decoding after the reproduced generation53 startup panic. Same installed image and GPU/clock baseline; verify SKS startup, HID cleanup and WindowServer.'":
        "comparison='Generation61: restore the omitted virtual-network class/personality/dependency in the combined copy/display AuxKC. Retain installed CA plug-in/compiler/probe, SSD contents and SKS monitor. Verify ClockManager publication, WindowServer graphics and actual presentation.'",
    "    def save():path('-launch.json').write_text":
        "    record['network_correction'] = network_binding\n    record['compiler_deployment'] = old['compiler_deployment']\n    def save():path('-launch.json').write_text",
}
for old,new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old,new)
scope = dict(__file__=__file__,__name__='ca_network_launcher')
exec(compile(source,str(BASE),'exec'),scope)
scope['QUAL_SHA'] = IMAGE_SHA


def validate():
    assert sha(IMAGE) == IMAGE_SHA
    image = read(IMAGE)
    assert image['status'] == 'CA_NETWORK_FULL_GUEST_IMAGE_BUILT_NOT_BOOTED'
    assert image['runtime_root'] == str(RUNTIME)
    for name,digest in image['inputs_sha256'].items(): assert sha(name) == digest, name
    for name,digest in image['artifacts_sha256'].items(): assert sha(IMAGE.parent/name) == digest, name
    old_path = Path(image['prior_launch'])
    assert sha(old_path) == '4930edb3f6156957d326058369760b4fb2ba629d8422326c4728bd5eee6acd21'
    old = read(old_path)
    assert old['exit_code'] == 9 and old['finished'] > old['started']
    assert old['adreno_record']['stage_generation'] == 59
    assert (old['context_fields'],old['context_bytes']) == (image['context_fields'],image['context_bytes']) == (217,5124736)
    assert sha(ROOT/'build/metal-ca-gen59-preserved-20260928-v1/preservation.json') == 'ea8f5323a5e50e02379d51361a170e7bb0b43eb346c63bd97cb3cf15c5cf730e'
    assert sha(RETIREMENT) == RETIREMENT_SHA
    retired = read(RETIREMENT)
    assert retired['status'] == 'GENERATION61_IDLE' and retired['finished'] > retired['started']
    assert retired['source_sha256'] == sha(ROOT/'tools/retire-gen60-gradient.py')
    assert not retired['ssd_writes'] and retired['after']['stage_generation'] == 61
    sys.path[:0] = [str(RUNTIME/'probes'),str(Q/'tools')]
    import auxkc
    from guestprofile import get_profile
    from trustcache import load_additions
    profile = get_profile(image['guest_profile'])
    runpy.run_path(str(RUNTIME/'tools/secondary-runtime.py'))['validate_guest_profile'](profile.name)
    assert profile.apfs_without_sep and profile.sep_asc.sks_startup
    assert profile.sep_asc.pnon_refusal and profile.sep_asc.xars_refusal and not profile.sep_asc.pnon_recovery
    assert profile.chip_id_boot.board_id == 0x64 and profile.chip_id_boot.security_domain == 1
    assert profile.chip_id_boot.certificate_production_status and profile.sip_lp_sip0 == 2
    arguments = list(image['arguments'])
    expected = list(old['arguments'])
    expected[expected.index('--auxkc')+1] = image['collection']
    assert arguments == expected and '--ans-writable' in arguments
    assert arguments[arguments.index('--console')+1] == 'serial'
    firmware = Path(arguments[arguments.index('--firmware-dir')+1])
    additions = Path(arguments[arguments.index('--trust-additions')+1])
    assert sha(old['root_hash']) == profile.installed_root.payload_sha256
    assert sha(additions) == old['trust_additions_sha256'] == image['trust_additions_sha256']
    trust = profile.trust_cache.bind(load_additions(additions)).load(firmware)
    assert hashlib.sha256(trust).hexdigest() == image['trust_cache_sha256']
    _,pin = auxkc.load(Path(image['collection']),sha(firmware/'kernelcache.release.mac17p'))
    assert pin['sha256'] == image['collection_sha256'] and pin['bundles'] == ['org.snapintosh.driver.AdrenoX2']
    assert sha(image['monitor']['path']) == image['monitor']['sha256'] == old['monitor_sha256']
    applied = read(old['ssd_apply_record'])
    assert sha(old['ssd_apply_record']) == old['ssd_apply_record_sha256']
    assert applied['result'] == 'PASS' and applied['header_after'] == old['expected_window_header_sha256']
    assert applied['edges_unchanged'] and not any(applied['serror'].values())
    settings = dict(old['environment'],SNAP_SMP_REPORT_PREFIX=PREFIX,SNAP_WATCHDOG='3600',
                    SNAP_ADRENO_ADOPT=str(ROOT/'build'/(PREFIX+'-adopt.json')))
    old = dict(old,auxkc=image['collection'],auxkc_sha256=image['collection_sha256'],kext_sha256=image['kext_sha256'])
    observers = [ROOT/'build'/name for name in [
        'collect-ca-network-20260928.py', 'capture-ca-network-ring-20260928.py',
        'capture-native-startup-gen61-20260928.py', 'capture-crash-retention-gen61-20260928.py']]
    candidate = dict(image,inputs_sha256={**image['inputs_sha256'],
        **{str(p):sha(p) for p in observers},str(__file__):sha(__file__),
        str(BASE):sha(BASE),str(IMAGE):IMAGE_SHA,str(RETIREMENT):RETIREMENT_SHA,
        str(ROOT/'tools/retire-gen60-gradient.py'):sha(ROOT/'tools/retire-gen60-gradient.py')})
    scope['network_binding'] = dict(image=str(IMAGE),image_sha256=IMAGE_SHA,
        qualification=image['network_qualification'],qualification_sha256=sha(image['network_qualification']),
        collection_sha256=image['collection_sha256'],kext_sha256=image['kext_sha256'],
        retirement_sha256=RETIREMENT_SHA,ssd_rewritten=False)
    return candidate,old,arguments,settings


def idle():
    assert sha(RETIREMENT) == RETIREMENT_SHA
    record = read(RETIREMENT)
    assert record['status'] == 'GENERATION61_IDLE' and record['after']['stage_generation'] == 61
    import q1n1proxy
    proxy = q1n1proxy.connect('udp://en5',wait=10)
    try:
        info = proxy.bootinfo()
        assert info['current_el'] == 2 and info['stage_generation'] == 61 and info['image_base'] == 0xb0000000
        guard = proxy.serror_state()
        assert not any(guard[k] for k in ['before','during','unconsumed'])
        status,battery = proxy.live_battery()
        assert status == 0 and battery['plausible'] and (battery['ac'] or battery['percent'] >= 80)
        return info,battery
    finally: proxy.link.close()


scope['validate'],scope['idle'] = validate,idle
if __name__ == '__main__': raise SystemExit(scope['main']())
