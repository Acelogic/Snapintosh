#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Boot generation65: bisect generation64's early exception with the OLD monitor.

Derived from run-ca-quiet-memo-candidate.py (full adapter over the pinned
run-sks-transport-candidate.py). Generation64 stopped with exit 6 in XNU early
boot after adding two things to generation63: the quiet -sks profile and the
SWITCH_ROOT memo monitor. This boot keeps only the quiet profile:

- runtime root ../Snapintosh-quiet (a3e36a6 = 23c583f + quiet patch only);
- monitor 340bae8f (ELF 87f8b7fd), generation61/63's qualified flags without
  SNAP_ROOT_VALIDATE_MEMO, context 5124736 bytes / 217 fields, identical to
  generation63 field by field;
- guest profile ...-sks-quiet, bound by that checkout's own full-image
  qualification 08eb85e2 (device tree f76897a0);
- watchdog 1800 seconds, prefix installed-metal-ca-quiet-bisect-1800s-20260928.

Everything else is generation63's: SSD (package 9f9f91cf applied at generation62,
header 0cc9d8b1), plug-in 78b6b161, kext 3c10369c, AuxKC 1f22aed6, trust additions
c384cb00, TXM native image, SMP, 8 GiB, seed and all other arguments/environment.
The runtime root's downloads/extracted/j700ap must resolve to the qualified
firmware with all five pinned hashes before any hardware step.

--check-inputs performs no hardware access and does not require the retirement;
idle() (used by --prepare and --boot) requires the actual generation64->65
retirement, its graceful quiescence and the preserved generation64 evidence.
SNAP_BATTERY_MINIMUM behaves exactly as in run-ca-quiet-memo-candidate.py.
Never interrupt an in-flight P_CALL.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT.parent / 'Snapintosh-quiet'
PRIOR_RUNTIME = ROOT.parent / 'Snapintosh-adreno-sks'
PIPE = ROOT.parent / 'Snapintosh-adreno-composite'
Q = ROOT.parent / 'q1n1'
BASE = ROOT / 'tools/run-sks-transport-candidate.py'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text())
PREFIX = 'installed-metal-ca-quiet-bisect-1800s-20260928'
PREDECESSOR = 'installed-metal-ca-quiet-memo-1800s-20260928'
BASELINE = 'installed-metal-ca-composite-2400s-20260928'
WATCHDOG = '1800'
DEPLOY = PIPE / 'build/ca-composite-deploy-20260928'
STORAGE = ROOT / 'build/ca-composite-deploy-gen62-20260928'
IMAGE = RUNTIME / 'build/ca-composite-quiet-image-20260928-v1/qualification.json'
IMAGE_SHA = '08eb85e21b98101c6976d82a6c675186d0e0a1383ce51b0758a3bf5fdc28a6ae'
QUIET = 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks-quiet'
QUIET_TREE_SHA = 'f76897a06e2753fb31bcfb6a13d07f8faea1f688a582fa39ef97ff33212c85b7'
MONITOR_SHA = '340bae8fa6cdfc26f65d96003551e79298698ff98b256c25b316f32f3c0ec934'
MONITOR_ELF_SHA = '87f8b7fd9f7f16d07303fb95741c9f6e998484f057fa8dfd2a883f448b002d14'
FLAGS_QUALIFICATION = ROOT / 'build/sks-transport-candidate-20260928-v2/qualification.json'
PRESERVATION = ROOT / 'build/metal-ca-quiet-memo-gen64-preserved-20260928-v1/preservation.json'
OBSERVERS = ['collect-ca-quiet-bisect-20260928.py', 'capture-ca-quiet-bisect-ring-20260928.py',
             'capture-native-startup-gen65-20260928.py', 'capture-crash-retention-gen65-20260928.py']
assert sha(BASE) == '52fe215a9a4779ebc50f01ecaafb4a4210d2b506b09e6ee10a5fbb089a5cc6b8'
source = BASE.read_text()
changes = {
    "RUNTIME=ROOT.parent/'Snapintosh-adreno-sks'": f"RUNTIME=ROOT.parent/{RUNTIME.name!r}",
    "PREFIX='installed-metal-sks-transport-2100s-20260928'": f'PREFIX={PREFIX!r}',
    "PREDECESSOR='installed-metal-sks-2100s-20260928'": f'PREDECESSOR={PREDECESSOR!r}',
    "SNAP_WATCHDOG='2100'": f'SNAP_WATCHDOG={WATCHDOG!r}',
    "context_fields=old['context_fields']+1": "context_fields=candidate['context_fields']",
    "('.c','.h','.py','.S','.ld')": "('.c','.h','.py','.S','.ld','.cpp','.m','.sh','.plist')",
    "comparison='Generation54: correct native SKS query command/sequence decoding after the reproduced generation53 startup panic. Same installed image and GPU/clock baseline; verify SKS startup, HID cleanup and WindowServer.'":
        "comparison='Generation65 bisect: quiet -sks profile with the old monitor340bae8f (no SWITCH_ROOT memo) after generation64 (quiet + memo) stopped with exit6 in XNU early boot. Same SSD, plug-in78b6b161, kext3c10369c, AuxKC1f22aed6, trust and GPU/clock baseline as generation63; 1800-second watchdog.'",
    "    def save():path('-launch.json').write_text":
        "    record['compiler_deployment'] = deployment_binding\n    def save():path('-launch.json').write_text",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
scope = dict(__file__=__file__, __name__='quiet_bisect_launcher')
exec(compile(source, str(BASE), 'exec'), scope)
scope['QUAL_SHA'] = IMAGE_SHA
assert scope['RUNTIME'] == RUNTIME and scope['PREFIX'] == PREFIX


def context_layout(root):
    layout = runpy.run_path(str(root / 'tools/monitor_layout.py'))['MonitorLayout']()
    fields = re.findall(r'^\s*(\d+) \|   \S.* (\w+)$', layout.records['context'], re.M)
    named = {name: int(offset) for offset, name in fields}
    assert len(named) == len(fields)
    return layout, named


def firmware_pinned(image):
    """The runtime root's downloads link must resolve to the qualified firmware."""
    firmware = RUNTIME / 'downloads/extracted/j700ap'
    assert firmware.resolve() == Path(image['firmware']).resolve(), firmware.resolve()
    assert len(image['firmware_sha256']) == 5
    for name, digest in image['firmware_sha256'].items():
        assert sha(firmware / name) == digest, name
    return firmware


def validate():
    assert sha(IMAGE) == IMAGE_SHA
    image = read(IMAGE)
    assert image['status'] == 'COMPLETE_SHADER_DISPLAY_IMAGE_BUILT_NOT_INSTALLED'
    assert image['guest_profile'] == QUIET and image['staged_guest_profile'] == QUIET[:-len('-quiet')]
    assert image['framebuffer_slots'] == ['/device-tree/arm-io/adreno-display']
    assert image['artifacts_sha256']['device-tree.bin'] == QUIET_TREE_SHA
    for group, directory in [('sources_sha256', RUNTIME), ('inputs_sha256', PIPE), ('artifacts_sha256', IMAGE.parent)]:
        for name, digest in image[group].items():
            assert sha(directory / name) == digest, name
    runtime_firmware = firmware_pinned(image)
    deployment_path = Path(image['deployment'])
    assert sha(deployment_path) == image['deployment_sha256']
    deployment = read(deployment_path)
    components_path = Path(deployment['components'])
    assert sha(components_path) == deployment['components_sha256'] == image['components_sha256']
    components = read(components_path)
    for name, digest in deployment['artifacts_sha256'].items():
        assert sha(deployment_path.parent / name) == digest, name
    for name, digest in deployment['sources_sha256'].items():
        assert sha(PIPE / name) == digest, name
    old_path = ROOT / 'build' / (BASELINE + '-launch.json')
    assert sha(old_path) == '2f0456ec3010c9a9bd809d6973c78e302a29427f7d5abd0d8550aede3ba191e2'
    old = read(old_path)
    for name, digest in old['source_sha256'].items():
        assert sha(name) == digest, name
    assert old['adreno_record']['stage_generation'] == 63 and old['exit_code'] == 9
    assert old['runtime_root'] == old['observer_root'] == str(PRIOR_RUNTIME)
    assert old['context_fields'] == 217 and old['context_bytes'] == components['context_bytes'] == 5124736
    assert image['monitor_sha256'] == old['monitor_sha256'] == sha(old['monitor_path']) == MONITOR_SHA
    assert sha(Path(old['monitor_path']).with_suffix('.elf')) == MONITOR_ELF_SHA
    assert image['auxkc_sha256'] == old['auxkc_sha256'] == components['deployed_collection_sha256'] == sha(components['deployed_collection'])
    assert old['kext_sha256'] == components['kext_sha256'] == '3c10369cef3d0c3dd446e1822569df346340c93599147a29d38fe28f4a0a4b62'
    assert old['auxkc'] == components['deployed_collection']
    # Monitor: exactly generation63's binary and qualified flags, no memo.
    qualified = read(FLAGS_QUALIFICATION)
    assert old['build_defines'] == qualified['flags'] and qualified['monitor']['sha256'] == MONITOR_SHA
    assert not any('SNAP_ROOT_VALIDATE_MEMO' in flag for flag in old['build_defines'])
    # Context: the quiet runtime's layout equals generation63's field for field.
    old_layout, old_fields = context_layout(PRIOR_RUNTIME)
    layout, fields = context_layout(RUNTIME)
    assert old_layout.size('context') == layout.size('context') == old['context_bytes'] == 5124736
    assert fields == old_fields and len(fields) == old['context_fields'] == 217
    # No SSD apply: generation63's installed package and header stay authoritative.
    package_path = DEPLOY / 'delta-v1/package.json'
    package = read(package_path)
    applied_path = STORAGE / 'apply-v1.json'
    applied = read(applied_path)
    assert applied['result'] == 'PASS' and applied['mode'] == 'apply'
    assert applied['package_sha256'] == sha(package_path) == old['compiler_deployment']['package_sha256']
    assert applied['header_after'] == package['header_after_sha256'] == old['expected_window_header_sha256']
    assert applied['edges_unchanged'] and not any(applied['serror'].values())
    assert applied['bootinfo']['stage_generation'] == 62
    assert old['ssd_apply_record'] == str(applied_path) and old['ssd_apply_record_sha256'] == sha(applied_path)
    assert old['storage_snapshot_generation'] == 62
    assert package['source_sha256'] == sha(PIPE / 'tools/package-qc-metal.py')
    for name, digest in package['binding_inputs_sha256'].items():
        assert sha(name) == digest, name
    sys.path[:0] = [str(RUNTIME / 'probes'), str(Q / 'tools')]
    from guestprofile import get_profile
    from trustcache import load_additions
    import auxkc
    import guestprofile
    assert Path(guestprofile.__file__).resolve() == RUNTIME / 'probes/guestprofile.py'
    profile = get_profile(QUIET)
    runpy.run_path(str(RUNTIME / 'tools/secondary-runtime.py'))['validate_guest_profile'](profile.name)
    assert profile.name == QUIET
    assert profile.apfs_without_sep and profile.sep_asc.sks_startup
    assert profile.sep_asc.pnon_refusal and profile.sep_asc.xars_refusal and not profile.sep_asc.pnon_recovery
    assert profile.chip_id_boot.board_id == 0x64 and profile.chip_id_boot.security_domain == 1
    assert profile.chip_id_boot.certificate_production_status and profile.sip_lp_sip0 == 2
    assert profile.adreno is not None and profile.adreno.display_slot
    assert profile.hashes(runtime_firmware) == image['firmware_sha256']
    arguments = list(old['arguments'])
    arguments[arguments.index('--guest-profile') + 1] = profile.name
    additions = deployment_path.parent / 'trust-additions.json'
    assert arguments[arguments.index('--trust-additions') + 1] == str(additions)
    assert arguments[arguments.index('--auxkc') + 1] == old['auxkc']
    assert [i for i, (a, b) in enumerate(zip(arguments, old['arguments'])) if a != b] == [arguments.index('--guest-profile') + 1]
    firmware = Path(arguments[arguments.index('--firmware-dir') + 1])
    assert firmware.resolve() == runtime_firmware.resolve()
    assert sha(old['root_hash']) == profile.installed_root.payload_sha256
    assert sha(additions) == image['trust_additions_sha256'] == old['trust_additions_sha256']
    trust = profile.trust_cache.bind(load_additions(additions)).load(firmware)
    assert hashlib.sha256(trust).hexdigest() == image['trust_cache_sha256']
    _, pin = auxkc.load(Path(old['auxkc']), sha(firmware / 'kernelcache.release.mac17p'))
    assert pin['sha256'] == old['auxkc_sha256'] and pin['bundles'] == ['org.snapintosh.driver.AdrenoX2']
    raw = read(ROOT / 'build/pauth-native-sign-20260927/launch-qualification-v1.json')
    image4 = Path(old['environment']['SNAP_TXM_NATIVE'])
    assert sha(image4) == raw['artifacts_sha256'][str(image4.relative_to(ROOT))]
    assert '--ans-writable' in arguments and arguments[arguments.index('--console') + 1] == 'serial'
    settings = dict(old['environment'], SNAP_SMP_REPORT_PREFIX=PREFIX, SNAP_WATCHDOG=WATCHDOG,
        SNAP_ADRENO_ADOPT=str(ROOT / 'build' / (PREFIX + '-adopt.json')))
    assert {k for k in settings if settings[k] != old['environment'][k]} == {
        'SNAP_SMP_REPORT_PREFIX', 'SNAP_WATCHDOG', 'SNAP_ADRENO_ADOPT'}
    inputs = {**components['inputs_sha256'], str(__file__): sha(__file__), str(BASE): sha(BASE),
        str(IMAGE): IMAGE_SHA, str(old_path): sha(old_path),
        str(package_path): sha(package_path), str(applied_path): sha(applied_path),
        str(ROOT / 'tools/preserve-gen64-quiet-memo.py'): sha(ROOT / 'tools/preserve-gen64-quiet-memo.py'),
        str(ROOT / 'tools/retire-gen64-quiet-memo.py'): sha(ROOT / 'tools/retire-gen64-quiet-memo.py'),
        **{str(RUNTIME / name): digest for name, digest in image['sources_sha256'].items()},
        **{str(ROOT / 'build' / name): sha(ROOT / 'build' / name) for name in OBSERVERS}}
    candidate = dict(inputs_sha256=inputs, guest_profile=profile.name,
        monitor=dict(path=old['monitor_path'], sha256=MONITOR_SHA),
        context_bytes=layout.size('context'), context_fields=len(fields), flags=old['build_defines'])
    scope['deployment_binding'] = dict(image=str(IMAGE), image_sha256=IMAGE_SHA,
        device_tree_sha256=QUIET_TREE_SHA, guest_profile=profile.name,
        deployment=str(deployment_path), deployment_sha256=sha(deployment_path),
        components_sha256=sha(components_path), package_sha256=sha(package_path),
        applied_sha256=sha(applied_path), ssd_rewritten=False, plugin_sha256=components['plugin_sha256'],
        compiler_sha256=components['compiler_sha256'], guest_probe_sha256=components['guest_probe_sha256'],
        kext_sha256=components['kext_sha256'], collection_sha256=components['deployed_collection_sha256'],
        network_qualification_sha256=components['network_qualification_sha256'],
        native_pipeline_evidence=components['native_compiler_evidence'],
        native_pipeline_sha256=components['native_compiler_sha256'],
        runtime_root=str(RUNTIME), prior_runtime_root=str(PRIOR_RUNTIME),
        runtime_firmware=str(runtime_firmware.resolve()),
        monitor_sha256=MONITOR_SHA, monitor_elf_sha256=MONITOR_ELF_SHA, root_validate_memo=False,
        baseline_launch_sha256=sha(old_path), bisects=PREDECESSOR, watchdog_seconds=int(WATCHDOG))
    old = dict(old, trust_additions_sha256=sha(additions))
    return candidate, old, arguments, settings


def idle():
    preserved = read(PRESERVATION)
    assert preserved['status'] == 'GEN64_STOPPED_EVIDENCE_PRESERVED' and preserved['generation'] == 64
    assert preserved['exit_code'] == 6
    retired = ROOT / 'build' / (PREDECESSOR + '-retirement-v1.json')
    record = read(retired)
    assert record['status'] == 'GENERATION65_IDLE' and not record['ssd_writes']
    assert record['finished'] > record['started']
    assert record['source_sha256'] == sha(ROOT / 'tools/retire-gen64-quiet-memo.py')
    assert record['verification_sha256'] == sha(PRESERVATION) == sha(ROOT / 'build' / (PREDECESSOR + '-pre-reset-verification.json'))
    assert record['before']['bootinfo']['stage_generation'] == 64
    quiet_path = ROOT / 'build' / (PREDECESSOR + '-quiesce-v1.json')
    assert record['quiesce_sha256'] == sha(quiet_path)
    quiet = read(quiet_path)
    assert quiet.get('quiesce') == 'graceful' and not quiet.get('stopped')
    assert not any(quiet['serror_guard']['after'][k] for k in ['before', 'during', 'unconsumed'])
    assert record['after']['stage_generation'] == 65 and record['after']['image_base'] == 0xb0000000
    assert not any(record['after_serror'][k] for k in ['before', 'during', 'unconsumed'])
    scope['deployment_binding'].update(retirement=str(retired), retirement_sha256=sha(retired),
                                       quiesce_sha256=sha(quiet_path), preservation_sha256=sha(PRESERVATION))
    import q1n1proxy
    proxy = q1n1proxy.connect('udp://en5', wait=10)
    try:
        info = proxy.bootinfo()
        assert info['current_el'] == 2 and info['stage_generation'] == 65 and info['image_base'] == 0xb0000000
        guard = proxy.serror_state()
        assert not any(guard[k] for k in ['before', 'during', 'unconsumed'])
        status, battery = proxy.live_battery()
        # 80% without AC is the standing rule. SNAP_BATTERY_MINIMUM lowers it for
        # one run only when the user asks (2026-09-28: gen64 on battery at 72%).
        minimum = int(os.environ.get('SNAP_BATTERY_MINIMUM', '80'))
        assert 50 <= minimum <= 100, minimum
        assert status == 0 and battery['plausible'] and (battery['ac'] or battery['percent'] >= minimum), battery.get('text')
        battery['required_minimum_without_ac'] = minimum
        return info, battery
    finally:
        proxy.link.close()


scope['validate'], scope['idle'] = validate, idle
if __name__ == '__main__':
    raise SystemExit(scope['main']())
