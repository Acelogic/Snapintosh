# SPDX-License-Identifier: MIT
"""Boot a candidate manifest through the pinned tools/run-sks-transport-candidate.py.

This is the per-generation run-*-candidate.py adapter made generic. The base launcher
text gets the same eight substitutions every adapter made (runtime root, prefix,
predecessor, watchdog, context fields, source-pin suffixes, comparison, deployment
binding) and its validate()/idle() are replaced by the manifest-driven ones below,
which perform the union of the checks run-ca-memo-candidate.py (generation66) and
run-ca-quiet-memo-candidate.py (generation64) made, with every value taken from the
manifest and verified against the files it names.

--check-inputs: no hardware access, no retirement required. --prepare and --boot call
the admission check (idle) first: the predecessor retirement, its graceful quiescence
(own or inherited), the preserved predecessor evidence, then a live bootinfo/SError/
battery read. --boot runs the launcher as a child process writing PREFIX-boot.log,
then runs `cycle.py capture` for the actual exit. Never interrupt an in-flight P_CALL.
"""
from pathlib import Path
import json
import runpy
import subprocess
import sys

from .common import (PINS, Refused, need, sha, sha_bytes, matches, read, image_base, serror_clear, downloads_pinned,
                     context_layout, battery_minimum, battery_ok, require_exclusive, load_proxy)
from .observers import substitute, pinned

SCHEMA = 'snapintosh-cycle-candidate-v1'
COMPARISON_OLD = ("comparison='Generation54: correct native SKS query command/sequence decoding after the reproduced "
                  "generation53 startup panic. Same installed image and GPU/clock baseline; verify SKS startup, HID "
                  "cleanup and WindowServer.'")
SOURCE_SUFFIXES = ('.c', '.h', '.py', '.S', '.ld', '.cpp', '.m', '.sh', '.plist')
ADAPTER_KEYS = {'SNAP_SMP_REPORT_PREFIX', 'SNAP_WATCHDOG', 'SNAP_ADRENO_ADOPT'}


class Manifest:
    """A candidate: everything a per-generation adapter used to pin in its source."""

    def __init__(self, ws, path):
        self.ws, self.path = ws, Path(path).resolve()
        need(self.path.is_file(), f'{path} does not exist')
        self.sha256 = sha(self.path)
        d = self.data = read(self.path)
        need(d.get('schema') == SCHEMA, f'{path}: schema is not {SCHEMA}')
        for key in ('prefix', 'generation', 'runtime_root', 'watchdog_seconds', 'comparison', 'predecessor',
                    'baseline_launch', 'guest_profile', 'image', 'monitor', 'context', 'kext_sha256', 'ssd'):
            need(key in d, f'{path}: missing {key}')
        self.prefix = d['prefix']
        need(all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in self.prefix), 'bad prefix')
        self.generation = d['generation']
        self.runtime = ws.path(d['runtime_root'])
        need(self.runtime.parent == ws.parent and self.runtime.is_dir(), f'runtime root {self.runtime} is not beside {ws.root}')
        self.watchdog = str(int(d['watchdog_seconds']))
        self.comparison = d['comparison']
        self.predecessor, self.baseline = d['predecessor'], d['baseline_launch']
        self.guest_profile, self.image, self.monitor, self.context = d['guest_profile'], d['image'], d['monitor'], d['context']
        self.kext_sha256, self.ssd = d['kext_sha256'], d['ssd']
        self.arguments = d.get('arguments', {})
        self.environment = d.get('environment', {})
        need(not ADAPTER_KEYS & set(self.environment), f'{sorted(ADAPTER_KEYS)} are set by the launcher, not the manifest')
        self.observers = d.get('observers', {})
        self.stages = d.get('stages')
        self.profile_checks = d.get('profile_checks', {})
        self.extra_inputs = d.get('extra_inputs', [])
        # Optional: a relinked AuxKC in place of the baseline's (explicit_auxkc), and an
        # SSD package applied after the baseline launch (ssd.after_baseline).
        self.auxkc = d.get('auxkc')
        if self.auxkc:
            for key in ('path', 'sha256', 'manifest', 'manifest_sha256', 'qualification', 'qualification_sha256',
                        'kext_sha256'):
                need(key in self.auxkc, f'{path}: auxkc lacks {key}')
        after = self.ssd.get('after_baseline')
        if after:
            need('snapshot' in after and 'local_stage' in after, f'{path}: ssd.after_baseline needs snapshot and local_stage')
        need(self.predecessor['prefix'] != self.prefix, 'a candidate cannot be its own predecessor')


def join(ws, root, name):
    """A record's file name: absolute names are local paths, relative ones are under root."""
    return ws.local(name) if str(name).startswith('/') else Path(root) / name


def verify_group(ws, record, group, root, what):
    for name, digest in record[group].items():
        need(matches(join(ws, root, name), digest), f'{what}: {group} {name} changed or missing')


def explicit_auxkc(ws, M, image, deployment, components):
    """The manifest's relinked AuxKC, which replaces exactly the stage's collection
    and kext (its kext qualification says which, and that the classes, Info.plist
    and linked personalities are the booted ones). The image must have been built
    with it. Returns (path, kext qualification record)."""
    a = M.auxkc
    path, manifest, qualification = ws.path(a['path']), ws.path(a['manifest']), ws.path(a['qualification'])
    need(matches(path, a['sha256']), f'{path} is missing or not {a["sha256"]}')
    need(matches(manifest, a['manifest_sha256']), f'{manifest} is missing or changed')
    need(matches(qualification, a['qualification_sha256']), f'{qualification} is missing or changed')
    q, pin = read(qualification), read(manifest)
    need(ws.local(q['collection']) == path and q['collection_sha256'] == pin['sha256'] == a['sha256'],
         'the AuxKC qualification and manifest name another collection')
    need(q['manifest_sha256'] == a['manifest_sha256'], 'the AuxKC qualification names another manifest')
    need(q['kext_sha256'] == a['kext_sha256'] == M.kext_sha256, 'kext differs from the AuxKC qualification')
    need(q['booted_collection_sha256'] == components['deployed_collection_sha256'] and
         q['booted_kext_sha256'] == components['kext_sha256'],
         'the AuxKC does not replace the stage\'s collection and kext')
    need(all(q[k] is True for k in ('classes_equal_to_booted', 'info_plist_identical_to_booted',
                                    'linked_collection_personalities_equal_to_booted')),
         'the AuxKC changes classes, Info.plist or personalities')
    need(q['hardware_access'] is False and q['guest_profile'] == pin['guest_profile'] == deployment['guest_profile'],
         'the AuxKC was qualified for another guest profile')
    need(pin['bundles'] == ['org.snapintosh.driver.AdrenoX2'], 'AuxKC bundles')
    for name, digest in q['inputs_sha256'].items():
        need(matches(ws.local(name), digest), f'AuxKC qualification input changed or missing: {name}')
    need(image['auxkc_sha256'] == a['sha256'] and ws.local(image['auxkc']) == path and
         image['auxkc_qualification_sha256'] == a['qualification_sha256'] and
         image['staged_auxkc_sha256'] == components['deployed_collection_sha256'],
         'the image was not built with this AuxKC in place of the staged one')
    return path, q


def installed_after_baseline(ws, M, old, image, package, package_path, applied):
    """An SSD package applied after the baseline launch. It must start from the SSD
    the baseline booted (header), be packaged from the named snapshot of it and the
    named local stage of this image's deployment, and its apply must have produced
    the package's header."""
    after = M.ssd['after_baseline']
    need(applied['package_sha256'] == sha(package_path), 'the SSD apply record names another package')
    need(applied['header_after'] == package['header_after_sha256'], 'SSD header after the apply')
    need(package['header_before_sha256'] == old['expected_window_header_sha256'],
         'the SSD package does not start from the SSD the baseline launch booted')
    need(package['ssd_writes'] is False, 'the SSD package record wrote the SSD')
    snapshot_path, stage_path = ws.path(after['snapshot']), ws.path(after['local_stage'])
    bound = {ws.local(name) for name in package['binding_inputs_sha256']}
    need(snapshot_path in bound and stage_path in bound, 'the package was not built from the named snapshot and stage')
    snapshot, stage = read(snapshot_path), read(stage_path)
    need(snapshot['result'] == 'PASS' and snapshot['generation'] == M.ssd['snapshot_generation'] and
         snapshot['header_sha256'] == package['header_before_sha256'] and
         snapshot['container_sha256'] == package['container_before_sha256'], 'SSD snapshot')
    need(stage['generation'] == M.ssd['snapshot_generation'] and stage['ssd_writes'] is False and
         stage['deployment_sha256'] == image['deployment_sha256'], 'the package installs another stage than the image\'s')
    need(M.ssd['apply_generation'] >= M.ssd['snapshot_generation'], 'SSD applied before its snapshot')
    return [snapshot_path, stage_path]


def validate(ws, M, scope):
    """(candidate, old, arguments, settings) for the base launcher; no hardware access."""
    RUNTIME, PREFIX = M.runtime, M.prefix
    PIPE = ws.path(M.image['pipeline_root'])
    PRIOR = ws.path(M.baseline['runtime_root'])
    BASE = pinned_launcher(ws)
    IMAGE = ws.path(M.image['qualification'])
    need(matches(IMAGE, M.image['sha256']), f'{IMAGE} is missing or not {M.image["sha256"]}')
    image = read(IMAGE)
    need(image['status'] == 'COMPLETE_SHADER_DISPLAY_IMAGE_BUILT_NOT_INSTALLED', 'image is not a complete built image')
    need(image['guest_profile'] == M.guest_profile, 'image was built for another guest profile')
    if 'staged_guest_profile' in M.image:
        need(image['staged_guest_profile'] == M.image['staged_guest_profile'], 'image staged another profile')
    need(image['framebuffer_slots'] == M.image['framebuffer_slots'], 'image framebuffer slots differ')
    need(image['artifacts_sha256']['device-tree.bin'] == M.image['device_tree_sha256'], 'image device tree differs')
    sources_root = ws.path(M.image['sources_root'])
    for group, root in (('sources_sha256', sources_root), ('inputs_sha256', PIPE), ('artifacts_sha256', IMAGE.parent)):
        verify_group(ws, image, group, root, 'image')
    runtime_sources = dict(image['sources_sha256']) if sources_root == RUNTIME else {}
    equivalent = M.image.get('equivalent')
    EQ = None
    if equivalent:
        EQ = ws.path(equivalent['qualification'])
        need(matches(EQ, equivalent['sha256']), f'{EQ} is missing or changed')
        other = read(EQ)
        for group, root in equivalent.get('verify_files', {}).items():
            root = EQ.parent if root == 'record_dir' else ws.path(root)
            verify_group(ws, other, group, root, equivalent['role'])
            if group == 'sources_sha256' and root == RUNTIME:
                runtime_sources = dict(other['sources_sha256'])
        if equivalent.get('tool'):
            tool = ws.path(equivalent['tool'])
            need(other['sources_sha256'].get(str(tool)) == sha(tool), f'{equivalent["role"]} was not built by {tool}')
        for key in equivalent['keys']:
            need(other[key] == image[key], f'{equivalent["role"]} differs from the image in {key}')
        need([c['address'] for c in other['chunks']] == [c['address'] for c in image['chunks']], 'chunk addresses differ')
        need({c['address'] for c, r in zip(other['chunks'], image['chunks']) if c != r} <= set(equivalent['differing_chunks']),
             'chunks other than the handoff page differ')
    need(len(image['chunks']) == M.image['chunks'], f'image has {len(image["chunks"])} chunks')
    runtime_firmware = downloads_pinned(ws, RUNTIME, image)
    deployment_path = ws.local(image['deployment'])
    need(matches(deployment_path, image['deployment_sha256']), 'deployment record changed')
    deployment = read(deployment_path)
    components_path = ws.local(deployment['components'])
    need(sha(components_path) == deployment['components_sha256'] == image['components_sha256'], 'components changed')
    components = read(components_path)
    verify_group(ws, deployment, 'artifacts_sha256', deployment_path.parent, 'deployment')
    verify_group(ws, deployment, 'sources_sha256', PIPE, 'deployment')
    old_path = ws.prefixed(M.baseline['prefix'], '-launch.json')
    need(matches(old_path, M.baseline['sha256']), f'baseline launch {old_path.name} is missing or changed')
    old = read(old_path)
    from . import unqualified
    need(not unqualified.recorded(ws, M.baseline['prefix']),
         f'baseline {M.baseline["prefix"]} was recorded as an unqualified stop; it can never be a baseline')
    for name, digest in old['source_sha256'].items():
        need(matches(ws.local(name), digest), f'baseline source pin changed: {name}')
    need(old['adreno_record']['stage_generation'] == M.baseline['generation'] and old['exit_code'] == M.baseline['exit_code'],
         'baseline launch generation or exit differs')
    need(ws.local(old['runtime_root']) == ws.local(old['observer_root']) == PRIOR, 'baseline runtime root differs')
    need(old['context_fields'] == M.baseline['context_fields'] and old['context_bytes'] == M.baseline['context_bytes'],
         'baseline context differs')
    need(components['context_bytes'] == M.image.get('deployment_context_bytes', M.baseline['context_bytes']),
         'deployment staged another context size')
    if M.image.get('same_as_baseline'):
        need(old['qualification_sha256'] == M.image['sha256'], 'baseline booted another image')
    if '--guest-profile' not in M.arguments:
        need(old['guest_profile'] == M.guest_profile, 'baseline booted another guest profile')
    need(old['monitor_sha256'] == sha(ws.local(old['monitor_path'])), 'baseline monitor binary changed')
    need(old['monitor_sha256'] == M.baseline.get('monitor_sha256', image['monitor_sha256']),
         'baseline booted another monitor than the manifest says (default: the image\'s staged monitor)')
    if M.auxkc:
        auxkc_path, _ = explicit_auxkc(ws, M, image, deployment, components)
        auxkc_sha256 = M.auxkc['sha256']
    else:
        need(image['auxkc_sha256'] == old['auxkc_sha256'] == components['deployed_collection_sha256'] ==
             sha(ws.local(components['deployed_collection'])), 'AuxKC differs')
        need(old['kext_sha256'] == components['kext_sha256'] == M.kext_sha256, 'kext differs')
        need(old['auxkc'] == components['deployed_collection'], 'AuxKC path differs')
        auxkc_path, auxkc_sha256 = ws.local(old['auxkc']), old['auxkc_sha256']
    # Monitor: the baseline's qualified flags plus the manifest's additions, reproducibly built.
    flags_qualification = ws.path(M.monitor['flags_qualification'])
    qualified = read(flags_qualification)
    need(old['build_defines'] == qualified['flags'] + M.baseline.get('added_build_defines', []),
         'baseline build defines are not the qualified flags (plus the baseline\'s own additions)')
    monitor_bin = ws.path(M.monitor['binary'])
    added = M.monitor.get('added_build_defines', [])
    if M.monitor.get('build_record'):
        build = read(ws.path(M.monitor['build_record']))
        need(build['qualification_sha256'] == sha(flags_qualification), 'monitor built from other qualified flags')
        need(build['flags'] == qualified['flags'] + added, 'monitor flags are not qualified flags + added defines')
        for define in M.monitor.get('required_build_defines', []):
            need(define in build['flags'], f'monitor lacks {define}')
        need(sha(monitor_bin) == build['bin_sha256'] == M.monitor['sha256'], 'monitor binary differs from its build record')
        need(sha(monitor_bin.with_suffix('.elf')) == build['elf_sha256'] == M.monitor['elf_sha256'], 'monitor ELF differs')
        need(monitor_bin.stat().st_size == build['bytes'], 'monitor size differs')
        flags = build['flags']
    else:
        need(not added and sha(monitor_bin) == M.monitor['sha256'] == old['monitor_sha256'],
             'without a build record the monitor must be the baseline monitor')
        flags = old['build_defines']
    # Context: every baseline field keeps its offset; only the manifest's fields are added.
    old_layout, old_fields = context_layout(PRIOR)
    layout, fields = context_layout(RUNTIME)
    need(old_layout.size('context') == old['context_bytes'] and len(old_fields) == old['context_fields'], 'baseline layout')
    need({name: fields.get(name) for name in old_fields} == old_fields, 'a baseline context field moved')
    need({k: fields[k] for k in set(fields) - set(old_fields)} == M.context['added_fields'], 'unexpected context fields')
    need(layout.size('context') == M.context['bytes'] and len(fields) == M.context['fields'], 'context size differs')
    # No SSD apply: the installed package and header stay authoritative.
    need(not M.ssd.get('rewrite'), 'launches do not rewrite the SSD')
    package_path, applied_path = ws.path(M.ssd['package']), ws.path(M.ssd['apply_record'])
    package, applied = read(package_path), read(applied_path)
    need(applied['result'] == 'PASS' and applied['mode'] == 'apply', 'SSD apply record did not pass')
    ssd_records = []
    if M.ssd.get('after_baseline'):
        ssd_records = installed_after_baseline(ws, M, old, image, package, package_path, applied)
    else:
        need(applied['package_sha256'] == sha(package_path) == old['compiler_deployment']['package_sha256'],
             'SSD package differs')
        need(applied['header_after'] == package['header_after_sha256'] == old['expected_window_header_sha256'],
             'SSD header')
    need(applied['edges_unchanged'] and not any(applied['serror'].values()), 'SSD apply edges or SError')
    need(applied['bootinfo']['stage_generation'] == M.ssd['apply_generation'], 'SSD apply generation')
    if not M.ssd.get('after_baseline'):
        need(ws.local(old['ssd_apply_record']) == applied_path and old['ssd_apply_record_sha256'] == sha(applied_path),
             'baseline booted another SSD apply')
        need(old['storage_snapshot_generation'] == M.ssd['snapshot_generation'], 'storage snapshot generation')
    need(package['source_sha256'] == sha(ws.path(M.ssd['package_tool'])), 'SSD packager changed')
    for name, digest in package['binding_inputs_sha256'].items():
        need(matches(ws.local(name), digest), f'SSD package input changed: {name}')
    sys.path[:0] = [str(RUNTIME / 'probes'), str(ws.q / 'tools')]
    from guestprofile import get_profile
    from trustcache import load_additions
    import auxkc
    import guestprofile
    need(Path(guestprofile.__file__).resolve() == (RUNTIME / 'probes/guestprofile.py').resolve(),
         'guestprofile imported from another runtime root')
    profile = get_profile(M.guest_profile)
    runpy.run_path(str(RUNTIME / 'tools/secondary-runtime.py'))['validate_guest_profile'](profile.name)
    need(profile.name == M.guest_profile, 'profile name')
    need(profile.apfs_without_sep and profile.sep_asc.sks_startup, 'profile SKS startup')
    need(profile.sep_asc.pnon_refusal and profile.sep_asc.xars_refusal and not profile.sep_asc.pnon_recovery, 'profile SEP')
    need(profile.chip_id_boot.board_id == 0x64 and profile.chip_id_boot.security_domain == 1, 'profile chip id')
    need(profile.chip_id_boot.certificate_production_status and profile.sip_lp_sip0 == 2, 'profile production/SIP')
    if M.profile_checks.get('adreno_display_slot'):
        need(profile.adreno is not None and profile.adreno.display_slot, 'profile has no adreno display slot')
    need(profile.hashes(runtime_firmware) == image['firmware_sha256'], 'profile firmware hashes differ')
    arguments = list(old['arguments'])
    for option, value in M.arguments.items():
        arguments[arguments.index(option) + 1] = value
    changed = sorted(i for i, (a, b) in enumerate(zip(arguments, old['arguments'])) if a != b)
    need(changed == sorted(arguments.index(o) + 1 for o, v in M.arguments.items()
                           if old['arguments'][old['arguments'].index(o) + 1] != v), 'arguments changed beyond the manifest')
    additions = deployment_path.parent / 'trust-additions.json'
    need(arguments[arguments.index('--guest-profile') + 1] == profile.name, 'argument guest profile')
    need(ws.local(arguments[arguments.index('--trust-additions') + 1]) == additions, 'argument trust additions')
    need(ws.local(arguments[arguments.index('--auxkc') + 1]) == auxkc_path, 'argument AuxKC')
    firmware = ws.local(arguments[arguments.index('--firmware-dir') + 1])
    need(firmware.resolve() == runtime_firmware.resolve(), 'argument firmware directory')
    need(sha(ws.local(old['root_hash'])) == profile.installed_root.payload_sha256, 'installed root hash')
    # Trust additions are the baseline's, or with a later SSD install the ones of
    # the stage that install carried (installed_after_baseline checked the stage).
    staged_additions = deployment['artifacts_sha256']['trust-additions.json'] if M.ssd.get('after_baseline') \
        else old['trust_additions_sha256']
    need(sha(additions) == image['trust_additions_sha256'] == staged_additions, 'trust additions')
    trust = profile.trust_cache.bind(load_additions(additions)).load(firmware)
    need(sha_bytes(trust) == image['trust_cache_sha256'], 'trust cache')
    _, pin = auxkc.load(auxkc_path, sha(firmware / 'kernelcache.release.mac17p'))
    need(pin['sha256'] == auxkc_sha256 and pin['bundles'] == ['org.snapintosh.driver.AdrenoX2'], 'AuxKC pin')
    raw = read(ws.path(PINS['txm_qualification']))
    image4 = ws.local(old['environment']['SNAP_TXM_NATIVE'])
    need(sha(image4) == raw['artifacts_sha256'][str(image4.relative_to(ws.root))], 'TXM native image')
    need('--ans-writable' in arguments and arguments[arguments.index('--console') + 1] == 'serial', 'ANS/console arguments')
    settings = dict(old['environment'], SNAP_SMP_REPORT_PREFIX=PREFIX, SNAP_WATCHDOG=M.watchdog,
                    SNAP_ADRENO_ADOPT=str(ws.prefixed(PREFIX, '-adopt.json')))
    settings.update(M.environment)
    need(set(settings) == set(old['environment']) | set(M.environment), 'environment keys dropped')
    need({k for k in settings if settings[k] != old['environment'].get(k)} <= ADAPTER_KEYS | set(M.environment),
         'environment changed beyond the manifest')
    inputs = {**components['inputs_sha256'], str(BASE): sha(BASE), str(IMAGE): sha(IMAGE), str(old_path): sha(old_path),
              str(package_path): sha(package_path), str(applied_path): sha(applied_path)}
    if EQ:
        inputs[str(EQ)] = sha(EQ)
    for record in ssd_records:
        inputs[str(record)] = sha(record)
    auxkc_files = [M.auxkc['path'], M.auxkc['manifest'], M.auxkc['qualification']] if M.auxkc else []
    for relative in [equivalent and equivalent.get('tool'), M.monitor.get('build_record'), M.monitor.get('build_tool'),
                     M.predecessor.get('preservation_tool'), M.predecessor.get('retirement_tool'), *auxkc_files,
                     *M.extra_inputs]:
        if relative:
            inputs[str(ws.path(relative))] = sha(ws.path(relative))
    inputs.update({str(join(ws, RUNTIME, name)): digest for name, digest in runtime_sources.items()})
    for kind in ('collector', 'gui_collector', 'ring', 'native', 'crash'):
        inputs[str(pinned(ws, kind))] = sha(pinned(ws, kind))
    candidate = dict(inputs_sha256=inputs, guest_profile=profile.name,
                     monitor=dict(path=str(monitor_bin), sha256=M.monitor['sha256']),
                     context_bytes=layout.size('context'), context_fields=len(fields), flags=flags)
    binding = dict(image=str(IMAGE), image_sha256=M.image['sha256'], device_tree_sha256=M.image['device_tree_sha256'],
                   guest_profile=profile.name, deployment=str(deployment_path), deployment_sha256=sha(deployment_path),
                   components_sha256=sha(components_path), package=str(package_path), package_sha256=sha(package_path),
                   applied_sha256=sha(applied_path), ssd_rewritten=False, plugin_sha256=components['plugin_sha256'],
                   compiler_sha256=components['compiler_sha256'], guest_probe_sha256=components['guest_probe_sha256'],
                   kext_sha256=components['kext_sha256'], collection_sha256=components['deployed_collection_sha256'],
                   network_qualification_sha256=components['network_qualification_sha256'],
                   native_pipeline_evidence=components['native_compiler_evidence'],
                   native_pipeline_sha256=components['native_compiler_sha256'],
                   runtime_root=str(RUNTIME), prior_runtime_root=str(PRIOR),
                   runtime_firmware=str(runtime_firmware.resolve()), monitor_sha256=M.monitor['sha256'],
                   added_build_defines=added, added_context_fields=M.context['added_fields'],
                   baseline_launch_sha256=sha(old_path), predecessor=M.predecessor['prefix'],
                   watchdog_seconds=int(M.watchdog),
                   cycle=dict(manifest=str(M.path), manifest_sha256=M.sha256, tool_sha256=ws.tool_sources(),
                              observers=M.observers, stages=M.stages))
    if EQ:
        binding.update({equivalent['role']: str(EQ), equivalent['role'] + '_sha256': sha(EQ)})
    if M.monitor.get('build_record'):
        record = ws.path(M.monitor['build_record'])
        binding.update(monitor_build=str(record), monitor_build_sha256=sha(record), monitor_elf_sha256=M.monitor['elf_sha256'])
    # The launch record names what this boot loads and expects, not what the
    # baseline did: the relinked AuxKC and kext, the SSD header after a later apply.
    patch = dict(trust_additions_sha256=sha(additions))
    if M.auxkc:
        binding.update(kext_sha256=M.auxkc['kext_sha256'], collection_sha256=M.auxkc['sha256'],
                       network_qualification_sha256=M.auxkc['qualification_sha256'],
                       auxkc=str(auxkc_path), auxkc_manifest_sha256=M.auxkc['manifest_sha256'],
                       staged_kext_sha256=components['kext_sha256'],
                       staged_collection_sha256=components['deployed_collection_sha256'],
                       staged_network_qualification_sha256=components['network_qualification_sha256'])
        patch.update(auxkc=str(auxkc_path), auxkc_sha256=M.auxkc['sha256'], kext_sha256=M.auxkc['kext_sha256'])
    if M.ssd.get('after_baseline'):
        binding.update(ssd_after_baseline={str(p): sha(p) for p in ssd_records},
                       baseline_window_header_sha256=old['expected_window_header_sha256'])
        patch.update(expected_window_header_sha256=package['header_after_sha256'], ssd_apply_record=str(applied_path),
                     ssd_apply_record_sha256=sha(applied_path), storage_snapshot_generation=M.ssd['snapshot_generation'])
    scope['deployment_binding'] = binding
    old = dict(old, **patch)
    return candidate, old, arguments, settings


def admit(ws, M, scope, minimum):
    """The predecessor retirement and a live read of the idle A16, before any hardware write."""
    N = admit_records(ws, M, scope)
    require_exclusive(ws)
    q = load_proxy(ws)
    proxy = q.connect(ws.device, wait=10)
    try:
        info = proxy.bootinfo()
        need(info['current_el'] == 2 and info['stage_generation'] == N and info['image_base'] == image_base(N),
             f'A16 is at generation {info["stage_generation"]}/{info["image_base"]:#x}, expected {N}/{image_base(N):#x}')
        guard = proxy.serror_state()
        need(serror_clear(guard), 'SError at the idle generation')
        status, battery = proxy.live_battery()
        need(battery_ok(status, battery, minimum),
             f'battery below {minimum}% without AC: {battery.get("text")} (status {status})')
        battery['required_minimum_without_ac'] = minimum
        return info, battery
    finally:
        proxy.link.close()


def admit_records(ws, M, scope):
    """The offline half of admission: the predecessor's retirement, quiescence and
    preservation. Returns the generation the A16 must be idle at."""
    pred, N = M.predecessor, M.generation
    retired = ws.path(pred['retirement'])
    need(retired.is_file(), f'{retired} does not exist: retire the predecessor first')
    record = read(retired)
    need(record['status'] == f'GENERATION{N}_IDLE' and not record['ssd_writes'], f'{retired.name}: status {record["status"]}')
    need(record['finished'] > record['started'], f'{retired.name}: timing')
    need(record['after']['stage_generation'] == N and record['after']['image_base'] == image_base(N),
         f'{retired.name} left generation {record["after"]["stage_generation"]} at {record["after"]["image_base"]:#x}')
    need(serror_clear(record['after_serror']), f'{retired.name}: SError after chainload')
    if 'tool_copies' in record:
        for source, entry in record['tool_copies'].items():
            need(matches(ws.local(entry['copy']), entry['sha256']), f'retirement tool copy of {source} changed')
    else:
        need(pred.get('retirement_tool') and record['source_sha256'] == sha(ws.path(pred['retirement_tool'])),
             'retirement was not written by the named retirement tool')
    from .retire import quiesce_record
    quiet_path, _ = quiesce_record(ws, retired, record)
    binding = dict(retirement=str(retired), retirement_sha256=sha(retired), quiesce_sha256=sha(quiet_path))
    if record.get('kind', 'stopped-run') == 'stopped-run':
        preservation = ws.path(pred['preservation'])
        need(record['verification_sha256'] == sha(preservation) ==
             sha(ws.prefixed(pred['prefix'], '-pre-reset-verification.json')), 'predecessor preservation differs')
        preserved = read(preservation)
        from . import unqualified
        if unqualified.recorded(ws, pred['prefix']):
            # A stop whose audit correctly refused was preserved with its evidence and
            # retired: it may precede a launch, never serve as a baseline (checked above).
            need(preserved['status'] == f'GEN{N - 1}_UNQUALIFIED_STOP_PRESERVED' and preserved['generation'] == N - 1
                 and preserved.get('qualified') is False and record.get('qualified') is False,
                 'predecessor unqualified preservation is for another generation')
        else:
            need(preserved['status'] == f'GEN{N - 1}_STOPPED_EVIDENCE_PRESERVED' and preserved['generation'] == N - 1,
                 'predecessor preservation is for another generation')
        need(preserved['exit_code'] == read(ws.prefixed(pred['prefix'], '-launch.json'))['exit_code'],
             'predecessor preservation exit code')
        need(record['before']['bootinfo']['stage_generation'] == N - 1, 'retirement started from another generation')
        binding['preservation_sha256'] = sha(preservation)
    else:
        need(record['before']['bootinfo']['stage_generation'] == N - 1, 'idle retirement started from another generation')
    if M.stages:
        need(record.get('chosen_stage', {}).get('sha256') in M.stages.values(),
             'the predecessor retirement did not chainload this candidate\'s stage pair')
    if M.ssd.get('after_baseline'):
        # The SSD changed after the baseline launch: the generation this boot starts
        # from must have been reached after that apply, and say so.
        applied = ws.path(M.ssd['apply_record'])
        need(M.ssd['apply_generation'] < N, 'the SSD apply is not before the idle generation')
        need(sha(applied) in record.get('bound_sha256', {}).values(),
             f'{retired.name} does not bind the SSD apply record {applied.name}')
    scope['deployment_binding'].update(binding)
    return N


def pinned_launcher(ws):
    base = ws.path(PINS['base_launcher']['path'])
    need(matches(base, PINS['base_launcher']['sha256']), f'{base} changed')
    return base


def adapter(ws, M, minimum):
    """The base launcher's namespace with the manifest's substitutions and checks."""
    base = pinned_launcher(ws)
    source = substitute(base.read_text(), {
        "RUNTIME=ROOT.parent/'Snapintosh-adreno-sks'": f'RUNTIME=ROOT.parent/{M.runtime.name!r}',
        "PREFIX='installed-metal-sks-transport-2100s-20260928'": f'PREFIX={M.prefix!r}',
        "PREDECESSOR='installed-metal-sks-2100s-20260928'": f'PREDECESSOR={M.predecessor["prefix"]!r}',
        "SNAP_WATCHDOG='2100'": f'SNAP_WATCHDOG={M.watchdog!r}',
        "context_fields=old['context_fields']+1": "context_fields=candidate['context_fields']",
        "('.c','.h','.py','.S','.ld')": repr(SOURCE_SUFFIXES).replace(' ', ''),
        COMPARISON_OLD: f'comparison={M.comparison!r}',
        "    def save():path('-launch.json').write_text":
            "    record['compiler_deployment'] = deployment_binding\n    def save():path('-launch.json').write_text",
    })
    scope = dict(__file__=str(ws.tool), __name__='cycle_launcher')
    exec(compile(source, str(base), 'exec'), scope)
    scope['QUAL_SHA'] = M.image['sha256']
    need(scope['RUNTIME'] == M.runtime and scope['PREFIX'] == M.prefix, 'launcher substitution failed')
    scope['validate'] = lambda: validate(ws, M, scope)
    scope['idle'] = lambda: admit(ws, M, scope, minimum)
    return scope, source


def compare_adapter(ws, M, scope, source, adapter_path):
    """What an existing per-generation adapter would pass to the base launcher, next to
    what this manifest passes. Offline: runs both validate() functions."""
    theirs = runpy.run_path(str(adapter_path), run_name='cycle_compare')
    mine = scope['validate']()
    other = theirs['validate']()
    names = ('candidate', 'old', 'arguments', 'environment')
    a, b = dict(zip(names, mine)), dict(zip(names, other))
    report = dict(adapter=str(adapter_path), adapter_sha256=sha(adapter_path),
                  transformed_launcher_identical=source == theirs['source'],
                  arguments_identical=a['arguments'] == b['arguments'],
                  environment_identical=a['environment'] == b['environment'] and
                  list(a['environment']) == list(b['environment']),
                  monitor_identical=a['candidate']['monitor'] == b['candidate']['monitor'],
                  runtime_root_identical=str(M.runtime) == str(theirs['RUNTIME']),
                  guest_profile_identical=a['candidate']['guest_profile'] == b['candidate']['guest_profile'],
                  context_identical=(a['candidate']['context_bytes'], a['candidate']['context_fields']) ==
                  (b['candidate']['context_bytes'], b['candidate']['context_fields']),
                  flags_identical=a['candidate']['flags'] == b['candidate']['flags'],
                  qual_sha_identical=scope['QUAL_SHA'] == theirs['scope']['QUAL_SHA'],
                  old_identical=a['old'] == b['old'],
                  inputs_only_here=sorted(set(a['candidate']['inputs_sha256']) - set(b['candidate']['inputs_sha256'])),
                  inputs_only_in_adapter=sorted(set(b['candidate']['inputs_sha256']) - set(a['candidate']['inputs_sha256'])),
                  inputs_digest_mismatch=sorted(k for k in set(a['candidate']['inputs_sha256']) & set(b['candidate']['inputs_sha256'])
                                                if a['candidate']['inputs_sha256'][k] != b['candidate']['inputs_sha256'][k]))
    launch = ws.prefixed(M.prefix, '-launch.json')
    if launch.is_file():
        record = read(launch)
        report.update(launch_record_arguments_identical=record['arguments'] == a['arguments'],
                      launch_record_environment_identical=record['environment'] == a['environment'])
    keys = ('transformed_launcher_identical', 'arguments_identical', 'environment_identical', 'monitor_identical',
            'runtime_root_identical', 'guest_profile_identical', 'context_identical', 'flags_identical',
            'qual_sha_identical', 'old_identical')
    report['status'] = 'EQUIVALENT' if all(report[k] for k in keys) and \
        report.get('launch_record_arguments_identical', True) and report.get('launch_record_environment_identical', True) \
        else 'DIFFERENT'
    return report


def main(ws, args):
    M = Manifest(ws, args.candidate)
    minimum = battery_minimum(args.battery_minimum)
    scope, source = adapter(ws, M, minimum)
    if args.compare_adapter:
        report = compare_adapter(ws, M, scope, source, Path(args.compare_adapter).resolve())
        print(json.dumps(report, indent=2), flush=True)
        return 0 if report['status'] == 'EQUIVALENT' else 1
    if not args.boot:
        mode = '--check-inputs' if args.check_inputs else '--prepare' if args.prepare else '--boot'
        sys.argv = [str(ws.tool), mode]
        rc = scope['main']() or 0
        if args.check_inputs:
            # Offline preview of the admission --prepare/--boot will run (stderr, so the
            # launcher's own --check-inputs line on stdout stays exactly the adapters').
            try:
                preview = dict(admission_records='OK', idle_generation=admit_records(ws, M, scope),
                               battery_minimum_without_ac=minimum)
            except Refused as refusal:
                preview = dict(admission_records='NOT YET', reason=str(refusal))
            print(json.dumps(preview), file=sys.stderr, flush=True)
        return rc
    # --boot: validate offline, run the launcher as a child writing PREFIX-boot.log, then capture.
    scope['validate']()
    boot_log = ws.prefixed(M.prefix, '-boot.log')
    need(not boot_log.exists() and not ws.prefixed(M.prefix, '-launch.json').exists(), 'this prefix has already booted')
    require_exclusive(ws)
    command = [sys.executable, str(ws.tool), 'launch', '--candidate', str(M.path), '--boot-child',
               '--battery-minimum', str(minimum)]
    with boot_log.open('x') as stream:
        rc = subprocess.run(command, cwd=ws.root, stdout=stream, stderr=subprocess.STDOUT).returncode
    print(json.dumps(dict(status='LAUNCHER_EXITED', exit_code=rc, boot_log=str(boot_log))), flush=True)
    launch = ws.prefixed(M.prefix, '-launch.json')
    if not launch.is_file() or not read(launch).get('finished'):
        print(json.dumps(dict(status='NO_FINISHED_LAUNCH', note='nothing to capture; inspect the boot log')), flush=True)
        return rc or 1
    log = ws.prefixed(M.prefix, '-cycle-capture-auto.log')
    with log.open('x') as stream:
        crc = subprocess.run([sys.executable, str(ws.tool), 'capture', '--prefix', M.prefix, '--candidate', str(M.path)],
                             cwd=ws.root, stdout=stream, stderr=subprocess.STDOUT).returncode
    print(json.dumps(dict(status='CAPTURE_EXITED', exit_code=crc, log=str(log),
                          next=f'python3 tools/cycle.py preserve --prefix {M.prefix}' if crc == 0 else
                          f'inspect {log.name}, then python3 tools/cycle.py capture --prefix {M.prefix} '
                          f'--candidate {M.path.relative_to(ws.root)} --check')), flush=True)
    return rc
