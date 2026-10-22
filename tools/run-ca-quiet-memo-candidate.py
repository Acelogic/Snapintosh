#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Boot generation64: quiet -sks profile and SWITCH_ROOT memo monitor, no SSD apply.

Derived from run-ca-composite-candidate.py (itself run-qc-metal-candidate.py
with generation63 changes) as a full adapter over the same pinned
run-sks-transport-candidate.py. What changes against generation63:

- runtime root ../Snapintosh-gen64 (23c583f + quiet profile + memo + monitor build);
- monitor build/gen64-monitor-v1 (0149a8e9, ELF 5fb806e6): generation61's qualified
  flags plus -DSNAP_ROOT_VALIDATE_MEMO=1, recorded as the launch build defines so
  the kernel-ops-perf decoder receives SNAP_ROOT_VALIDATE_MEMO;
- context 5124736 -> 5190400 bytes, 217 -> 218 fields: every generation63 field
  keeps its offset and the only new field is root_memo at 5124736;
- guest profile ...-sks-quiet, bound by the full-image qualification regenerated
  in the runtime root (device tree f76897a0, same tree/params/trust/chunks as
  ../Snapintosh-quiet's 08eb85e2 except the random handoff page);
- watchdog 1800 seconds, prefix installed-metal-ca-quiet-memo-1800s-20260928.

Unchanged: the SSD (composite package 9f9f91cf applied at generation62, header
0cc9d8b1), plug-in 78b6b161, kext 3c10369c, AuxKC 1f22aed6, trust additions
c384cb00 (trust cache da8e9fad), TXM native image, SMP, 8 GiB, seed and every
other argument and environment value of generation63.

--check-inputs performs no hardware access and does not require the retirement;
idle() (used by --prepare and --boot) requires the actual generation63->64
retirement, graceful quiescence and the preserved generation63 evidence before
any hardware step. Never interrupt an in-flight P_CALL.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT.parent / 'Snapintosh-gen64'
PRIOR_RUNTIME = ROOT.parent / 'Snapintosh-adreno-sks'
PIPE = ROOT.parent / 'Snapintosh-adreno-composite'
Q = ROOT.parent / 'q1n1'
BASE = ROOT / 'tools/run-sks-transport-candidate.py'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text())
PREFIX = 'installed-metal-ca-quiet-memo-1800s-20260928'
PREDECESSOR = 'installed-metal-ca-composite-2400s-20260928'
WATCHDOG = '1800'
DEPLOY = PIPE / 'build/ca-composite-deploy-20260928'
STORAGE = ROOT / 'build/ca-composite-deploy-gen62-20260928'
IMAGE = RUNTIME / 'build/ca-composite-quiet-image-20260928-v1/qualification.json'
IMAGE_SHA = '87b6743a50422366d9e4c34533c4a715ec9c3315c332d0742a63ad60ca3079c6'
REFERENCE = ROOT.parent / 'Snapintosh-quiet/build/ca-composite-quiet-image-20260928-v1/qualification.json'
REFERENCE_SHA = '08eb85e21b98101c6976d82a6c675186d0e0a1383ce51b0758a3bf5fdc28a6ae'
QUIET = 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks-quiet'
QUIET_TREE_SHA = 'f76897a06e2753fb31bcfb6a13d07f8faea1f688a582fa39ef97ff33212c85b7'
MONITOR = RUNTIME / 'build/gen64-monitor-v1'
MONITOR_SHA = '0149a8e9f95dd3889f608c85046e36ab0160b987542a9d25e330e3269a0ada8c'
MONITOR_ELF_SHA = '5fb806e67a77789055a19434f5ec20a3ac77931b6f3c0e77180374f0ab030376'
FLAGS_QUALIFICATION = ROOT / 'build/sks-transport-candidate-20260928-v2/qualification.json'
PRESERVATION = ROOT / 'build/metal-ca-composite-gen63-preserved-20260928-v1/preservation.json'
PRESERVATION_SHA = '228fe4cc359fae93a6b48401cb5a778924b7cec6987beab1924775a7db61d7ac'
OBSERVERS = ['collect-ca-quiet-memo-20260928.py', 'capture-ca-quiet-memo-ring-20260928.py',
             'capture-native-startup-gen64-20260928.py', 'capture-crash-retention-gen64-20260928.py']
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
        "comparison='Generation64: quiet -sks profile (absent-hardware subtrees withdrawn, adreno-display slot) and SWITCH_ROOT level-3 memo monitor0149a8e9. Same SSD, plug-in78b6b161, kext3c10369c, AuxKC1f22aed6, trust and GPU/clock baseline as generation63; 1800-second watchdog. Verify configd quiet, WindowServer Metal pipeline compilation and actual presentation.'",
    "    def save():path('-launch.json').write_text":
        "    record['compiler_deployment'] = deployment_binding\n    def save():path('-launch.json').write_text",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
scope = dict(__file__=__file__, __name__='quiet_memo_launcher')
exec(compile(source, str(BASE), 'exec'), scope)
scope['QUAL_SHA'] = IMAGE_SHA
assert scope['RUNTIME'] == RUNTIME and scope['PREFIX'] == PREFIX


def context_layout(root):
    layout = runpy.run_path(str(root / 'tools/monitor_layout.py'))['MonitorLayout']()
    fields = re.findall(r'^\s*(\d+) \|   \S.* (\w+)$', layout.records['context'], re.M)
    named = {name: int(offset) for offset, name in fields}
    assert len(named) == len(fields)
    return layout, named


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
    assert sha(REFERENCE) == REFERENCE_SHA
    reference = read(REFERENCE)
    for key in ('status', 'guest_profile', 'staged_guest_profile', 'inputs_sha256', 'deployment_sha256',
                'components_sha256', 'root_hash_sha256', 'firmware_sha256', 'framebuffer_slots', 'auxkc_sha256',
                'trust_additions_sha256', 'trust_cache_sha256', 'upload_bytes', 'artifacts_sha256'):
        assert image[key] == reference[key], key
    assert [c['address'] for c in image['chunks']] == [r['address'] for r in reference['chunks']]
    assert len(image['chunks']) == 598
    # Only the handoff page (random seed) may differ between two builds.
    assert {c['address'] for c, r in zip(image['chunks'], reference['chunks']) if c != r} <= {'0x8c0000000'}
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
    old_path = ROOT / 'build' / (PREDECESSOR + '-launch.json')
    assert sha(old_path) == '2f0456ec3010c9a9bd809d6973c78e302a29427f7d5abd0d8550aede3ba191e2'
    old = read(old_path)
    for name, digest in old['source_sha256'].items():
        assert sha(name) == digest, name
    assert old['adreno_record']['stage_generation'] == 63 and old['exit_code'] == 9
    assert old['runtime_root'] == old['observer_root'] == str(PRIOR_RUNTIME)
    assert old['context_fields'] == 217 and old['context_bytes'] == components['context_bytes'] == 5124736
    assert image['monitor_sha256'] == old['monitor_sha256'] == sha(old['monitor_path'])
    assert image['auxkc_sha256'] == old['auxkc_sha256'] == components['deployed_collection_sha256'] == sha(components['deployed_collection'])
    assert old['kext_sha256'] == components['kext_sha256'] == '3c10369cef3d0c3dd446e1822569df346340c93599147a29d38fe28f4a0a4b62'
    assert old['auxkc'] == components['deployed_collection']
    # Monitor: generation61's qualified flags plus the memo flag, reproducibly built.
    qualified = read(FLAGS_QUALIFICATION)
    assert old['build_defines'] == qualified['flags']
    build = read(MONITOR / 'build.json')
    assert build['qualification_sha256'] == sha(FLAGS_QUALIFICATION)
    assert build['flags'] == qualified['flags'] + ['-DSNAP_ROOT_VALIDATE_MEMO=1']
    assert '-DSNAP_ROOT_VALIDATE_WORDS=1' in build['flags']
    assert sha(MONITOR / 'xnuboot.bin') == build['bin_sha256'] == MONITOR_SHA
    assert sha(MONITOR / 'xnuboot.elf') == build['elf_sha256'] == MONITOR_ELF_SHA
    assert (MONITOR / 'xnuboot.bin').stat().st_size == build['bytes']
    # Context: every generation63 field keeps its offset; only root_memo is appended.
    old_layout, old_fields = context_layout(PRIOR_RUNTIME)
    layout, fields = context_layout(RUNTIME)
    assert old_layout.size('context') == old['context_bytes'] and len(old_fields) == old['context_fields']
    assert {name: fields.get(name) for name in old_fields} == old_fields
    assert set(fields) - set(old_fields) == {'root_memo'} and fields['root_memo'] == old['context_bytes']
    assert layout.size('context') == 5190400 and len(fields) == 218
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
    arguments = list(old['arguments'])
    arguments[arguments.index('--guest-profile') + 1] = profile.name
    additions = deployment_path.parent / 'trust-additions.json'
    assert arguments[arguments.index('--trust-additions') + 1] == str(additions)
    assert arguments[arguments.index('--auxkc') + 1] == old['auxkc']
    assert [i for i, (a, b) in enumerate(zip(arguments, old['arguments'])) if a != b] == [arguments.index('--guest-profile') + 1]
    firmware = Path(arguments[arguments.index('--firmware-dir') + 1])
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
        str(IMAGE): IMAGE_SHA, str(REFERENCE): REFERENCE_SHA, str(old_path): sha(old_path),
        str(package_path): sha(package_path), str(applied_path): sha(applied_path),
        str(PRESERVATION): sha(PRESERVATION),
        str(ROOT / 'tools/preserve-gen63-composite.py'): sha(ROOT / 'tools/preserve-gen63-composite.py'),
        str(ROOT / 'tools/retire-gen63-composite.py'): sha(ROOT / 'tools/retire-gen63-composite.py'),
        str(MONITOR / 'build.json'): sha(MONITOR / 'build.json'),
        str(RUNTIME / 'tools/build-gen64-monitor.py'): sha(RUNTIME / 'tools/build-gen64-monitor.py'),
        **{str(RUNTIME / name): digest for name, digest in image['sources_sha256'].items()},
        **{str(ROOT / 'build' / name): sha(ROOT / 'build' / name) for name in OBSERVERS}}
    candidate = dict(inputs_sha256=inputs, guest_profile=profile.name,
        monitor=dict(path=str(MONITOR / 'xnuboot.bin'), sha256=MONITOR_SHA),
        context_bytes=layout.size('context'), context_fields=len(fields), flags=build['flags'])
    scope['deployment_binding'] = dict(image=str(IMAGE), image_sha256=IMAGE_SHA,
        quiet_reference=str(REFERENCE), quiet_reference_sha256=REFERENCE_SHA,
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
        monitor_build=str(MONITOR / 'build.json'), monitor_build_sha256=sha(MONITOR / 'build.json'),
        monitor_sha256=MONITOR_SHA, monitor_elf_sha256=MONITOR_ELF_SHA,
        added_build_defines=['-DSNAP_ROOT_VALIDATE_MEMO=1'], root_memo_offset=fields['root_memo'],
        previous_launch_sha256=sha(old_path), preservation_sha256=sha(PRESERVATION), watchdog_seconds=int(WATCHDOG))
    old = dict(old, trust_additions_sha256=sha(additions))
    return candidate, old, arguments, settings


def idle():
    assert sha(PRESERVATION) == PRESERVATION_SHA
    preserved = read(PRESERVATION)
    assert preserved['status'] == 'GEN63_STOPPED_EVIDENCE_PRESERVED' and preserved['generation'] == 63
    retired = ROOT / 'build' / (PREDECESSOR + '-retirement-v1.json')
    record = read(retired)
    assert record['status'] == 'GENERATION64_IDLE' and not record['ssd_writes']
    assert record['finished'] > record['started']
    assert record['source_sha256'] == sha(ROOT / 'tools/retire-gen63-composite.py')
    assert record['verification_sha256'] == PRESERVATION_SHA == sha(ROOT / 'build' / (PREDECESSOR + '-pre-reset-verification.json'))
    assert record['before']['bootinfo']['stage_generation'] == 63
    quiet_path = ROOT / 'build' / (PREDECESSOR + '-quiesce-v1.json')
    assert record['quiesce_sha256'] == sha(quiet_path)
    quiet = read(quiet_path)
    assert quiet.get('quiesce') == 'graceful' and not quiet.get('stopped')
    assert not any(quiet['serror_guard']['after'][k] for k in ['before', 'during', 'unconsumed'])
    assert record['after']['stage_generation'] == 64 and record['after']['image_base'] == 0xb0800000
    assert not any(record['after_serror'][k] for k in ['before', 'during', 'unconsumed'])
    scope['deployment_binding'].update(retirement=str(retired), retirement_sha256=sha(retired),
                                       quiesce_sha256=sha(quiet_path))
    import q1n1proxy
    proxy = q1n1proxy.connect('udp://en5', wait=10)
    try:
        info = proxy.bootinfo()
        assert info['current_el'] == 2 and info['stage_generation'] == 64 and info['image_base'] == 0xb0800000
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
