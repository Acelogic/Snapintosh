#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Boot the applied compiler fix with the accepted gen56 monitor and display.

Failure inventory: stale source/trust/disk header; wrong generation or device;
changed monitor/driver; mixed compiler bundle; duplicate owner; false host exit.
The established GPU preparation, adoption, native policy and bounded watchdog
remain unchanged. This run has a3600-second watchdog; never interrupt P_CALL.
"""
from pathlib import Path
import hashlib
import json
import os
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT.parent / 'Snapintosh-adreno-sks'
PIPE = ROOT.parent / 'Snapintosh-adreno-pipeline'
Q = ROOT.parent / 'q1n1'
BASE = ROOT / 'tools/run-sks-transport-candidate.py'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text())
PREFIX = 'installed-metal-qc-pipeline-3600s-20260928'
PREDECESSOR = 'installed-metal-panel-arguments-3600s-20260928'
DEPLOY = PIPE / 'build/qc-metal-deploy-20260928'
STORAGE = ROOT / 'build/metal-pipeline-deploy-20260928'
IMAGE = DEPLOY / 'image-v1/qualification.json'
IMAGE_SHA = 'fbd902010b506ab4dcc055f23c40e345eb55a6d85c6da61c72175f250c60ffbb'
assert sha(BASE) == '52fe215a9a4779ebc50f01ecaafb4a4210d2b506b09e6ee10a5fbb089a5cc6b8'
source = BASE.read_text()
changes = {
    "PREFIX='installed-metal-sks-transport-2100s-20260928'": f'PREFIX={PREFIX!r}',
    "PREDECESSOR='installed-metal-sks-2100s-20260928'": f'PREDECESSOR={PREDECESSOR!r}',
    "SNAP_WATCHDOG='2100'": "SNAP_WATCHDOG='3600'",
    "context_fields=old['context_fields']+1": "context_fields=old['context_fields']",
    "reused_installed_image=True,fresh_filesystem_report=False": "reused_installed_image=False,fresh_filesystem_report=False",
    "comparison='Generation54: correct native SKS query command/sequence decoding after the reproduced generation53 startup panic. Same installed image and GPU/clock baseline; verify SKS startup, HID cleanup and WindowServer.'":
        "comparison='Generation57: deploy native vertex-fetch and scalar-sampler compiler fixes plus the corrected triangle wait probe. Retain gen56 SKS monitor/display AuxKC. Verify actual WindowServer pipelines and presentation; host18/18 does not prove a desktop.'",
    "    def save():path('-launch.json').write_text":
        "    record['compiler_deployment'] = deployment_binding\n    def save():path('-launch.json').write_text",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
scope = dict(__file__=__file__, __name__='qc_metal_launcher')
exec(compile(source, str(BASE), 'exec'), scope)
scope['QUAL_SHA'] = IMAGE_SHA


def validate():
    assert sha(IMAGE) == IMAGE_SHA
    image = read(IMAGE)
    assert image['status'] == 'COMPLETE_SHADER_DISPLAY_IMAGE_BUILT_NOT_INSTALLED'
    for group, directory in [('sources_sha256', PIPE), ('inputs_sha256', PIPE), ('artifacts_sha256', IMAGE.parent)]:
        for name, digest in image[group].items():
            assert sha(directory / name) == digest, name
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
    assert sha(old_path) == 'cd076f19519151cf2073e7871153d8beb4a9cd1c0744c25ad915941f3dca4cfe'
    old = read(old_path)
    for name, digest in old['source_sha256'].items():
        assert sha(name) == digest, name
    assert old['adreno_record']['stage_generation'] == 56
    assert old['context_fields'] == 217 and old['context_bytes'] == components['context_bytes'] == 5124736
    assert image['monitor_sha256'] == old['monitor_sha256'] == sha(old['monitor_path'])
    assert image['auxkc_sha256'] == old['auxkc_sha256'] == sha(old['auxkc'])
    package_path = DEPLOY / 'delta-v1/package.json'
    package = read(package_path)
    applied_path = STORAGE / 'apply-v1.json'
    applied = read(applied_path)
    assert applied['result'] == 'PASS' and applied['mode'] == 'apply'
    assert applied['package_sha256'] == sha(package_path)
    assert applied['header_after'] == package['header_after_sha256']
    assert applied['edges_unchanged'] and not any(applied['serror'].values())
    assert applied['bootinfo']['stage_generation'] == 57
    assert package['source_sha256'] == sha(PIPE / 'tools/package-qc-metal.py')
    for name, digest in package['binding_inputs_sha256'].items():
        assert sha(name) == digest, name
    sys.path[:0] = [str(RUNTIME / 'probes'), str(Q / 'tools')]
    from guestprofile import get_profile
    from trustcache import load_additions
    import auxkc
    profile = get_profile(image['guest_profile'])
    runpy.run_path(str(RUNTIME / 'tools/secondary-runtime.py'))['validate_guest_profile'](profile.name)
    assert profile.apfs_without_sep and profile.sep_asc.sks_startup
    assert profile.sep_asc.pnon_refusal and profile.sep_asc.xars_refusal and not profile.sep_asc.pnon_recovery
    assert profile.chip_id_boot.board_id == 0x64 and profile.chip_id_boot.security_domain == 1
    assert profile.chip_id_boot.certificate_production_status and profile.sip_lp_sip0 == 2
    arguments = list(old['arguments'])
    additions = deployment_path.parent / 'trust-additions.json'
    arguments[arguments.index('--trust-additions') + 1] = str(additions)
    firmware = Path(arguments[arguments.index('--firmware-dir') + 1])
    assert sha(old['root_hash']) == profile.installed_root.payload_sha256
    assert sha(additions) == image['trust_additions_sha256']
    trust = profile.trust_cache.bind(load_additions(additions)).load(firmware)
    assert hashlib.sha256(trust).hexdigest() == image['trust_cache_sha256']
    _, pin = auxkc.load(Path(old['auxkc']), sha(firmware / 'kernelcache.release.mac17p'))
    assert pin['sha256'] == old['auxkc_sha256'] and pin['bundles'] == ['org.snapintosh.driver.AdrenoX2']
    raw = read(ROOT / 'build/pauth-native-sign-20260927/launch-qualification-v1.json')
    image4 = Path(old['environment']['SNAP_TXM_NATIVE'])
    assert sha(image4) == raw['artifacts_sha256'][str(image4.relative_to(ROOT))]
    assert '--ans-writable' in arguments and arguments[arguments.index('--console') + 1] == 'serial'
    settings = dict(old['environment'], SNAP_SMP_REPORT_PREFIX=PREFIX, SNAP_WATCHDOG='3600',
        SNAP_ADRENO_ADOPT=str(ROOT / 'build' / (PREFIX + '-adopt.json')))
    old = dict(old, trust_additions_sha256=sha(additions),
        expected_window_header_sha256=package['header_after_sha256'],
        ssd_apply_record=str(applied_path), ssd_apply_record_sha256=sha(applied_path),
        storage_snapshot_generation=57)
    inputs = {**components['inputs_sha256'], str(__file__): sha(__file__), str(BASE): sha(BASE),
        str(IMAGE): IMAGE_SHA, str(package_path): sha(package_path), str(applied_path): sha(applied_path)}
    candidate = dict(inputs_sha256=inputs, guest_profile=profile.name,
        monitor=dict(path=old['monitor_path'], sha256=old['monitor_sha256']),
        context_bytes=old['context_bytes'], flags=old['build_defines'])
    scope['deployment_binding'] = dict(image=str(IMAGE), image_sha256=IMAGE_SHA,
        deployment=str(deployment_path), deployment_sha256=sha(deployment_path),
        components_sha256=sha(components_path), package_sha256=sha(package_path),
        applied_sha256=sha(applied_path), plugin_sha256=components['plugin_sha256'],
        compiler_sha256=components['compiler_sha256'], guest_probe_sha256=components['guest_probe_sha256'],
        native_pipeline_evidence=components['native_compiler_evidence'],
        native_pipeline_sha256=components['native_compiler_sha256'])
    return candidate, old, arguments, settings


def idle():
    retired = ROOT / 'build' / (PREDECESSOR + '-retirement-v1.json')
    assert sha(retired) == '9c6a7fb09e344050880ebcf4fe9e0c33d62722b937aa534dba2935f3e6052d09'
    record = read(retired)
    assert record['status'] == 'GENERATION57_IDLE' and record['quiesce'] == 'graceful'
    import q1n1proxy
    proxy = q1n1proxy.connect('udp://en5', wait=10)
    try:
        info = proxy.bootinfo()
        assert info['current_el'] == 2 and info['stage_generation'] == 57 and info['image_base'] == 0xb0000000
        status, battery = proxy.live_battery()
        assert status == 0 and battery['plausible'] and (battery['ac'] or battery['percent'] >= 80)
        return info, battery
    finally:
        proxy.link.close()


scope['validate'], scope['idle'] = validate, idle
if __name__ == '__main__':
    raise SystemExit(scope['main']())
