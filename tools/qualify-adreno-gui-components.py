#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the shader/display candidate and retained PA evidence. No A16 access."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import time
from source_text import read_source

from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--integration-dir', type=Path, required=True)
    ap.add_argument('--pa-components', type=Path, required=True)
    ap.add_argument('--pa-root', type=Path, required=True)
    ap.add_argument('--original-root', type=Path, required=True)
    ap.add_argument('--display-copy', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    base, original, pa_root = [p.resolve() for p in (args.integration_dir, args.original_root, args.pa_root)]
    inputs, records, paths = {}, {}, {}
    def bind(path, digest=None):
        path = path.resolve()
        actual = sha(path)
        assert digest is None or actual == digest, str(path)
        assert str(path) not in inputs or inputs[str(path)] == actual, str(path)
        inputs[str(path)] = actual
        return actual
    def verify(path, root=ROOT, artifact_root=None):
        bind(path)
        record = json.loads(path.read_text())
        for key, directory in [('sources_sha256', root), ('source_sha256', root),
                ('inputs_sha256', root), ('external_sha256', root),
                ('q1n1_sha256', ROOT.parent/'q1n1/tools'), ('artifacts_sha256', artifact_root or path.parent)]:
            if isinstance(record.get(key), dict):
                for name, digest in record[key].items():
                    bind(directory/name, digest)
        return record
    expected = {
        'integration': ('integration-v1/qualification.json', 'FILL_COMMAND_MONITOR_KEXT_HOST_QUALIFIED_NOT_INSTALLED'),
        'mixed': ('mixed-replay-v2/qualification.json', 'PASS'),
        'compiler': ('native-compiler-v1/qualification.json', 'NATIVE_CALLBACK_BYTES_CAPTURED'),
        'draw': ('draw-package-v1/qualification.json', 'ADRENO_DRAW_PACKAGES_MATCH_PLAN_AND_MODEL'),
        'ring': ('ring-ib-v1/qualification.json', 'RING_WRAP_AND_GUEST_IB_HOST_QUALIFIED'),
        'driver': ('kext-ib-v1/qualification.json', 'KEXT_IB_PATH_HOST_QUALIFIED_NOT_INSTALLED'),
        'submission': ('native-submission-v1/qualification.json', 'NATIVE_METAL_TRIANGLE_DRIVER_CORE_REPLAY_PASS_NOT_A16'),
        'probe': ('triangle-probe-v2/build.json', 'GUEST_TRIANGLE_BUILT_HOST_REFERENCE_MATCHED_NOT_EXECUTED_ON_A16'),
        'link': ('auxkc-v1/link.json', 'FILL_AUXKC_LINKED_PINNED_NOT_INSTALLED'),
    }
    for name, (relative, status) in expected.items():
        paths[name] = base/relative
        records[name] = verify(paths[name], artifact_root=(paths[name].parent/'artifacts' if name == 'ring' else None))
        assert records[name]['status'] == status, (name, records[name]['status'])
    for name, digest in records['ring']['draw_plan_sha256'].items():
        bind(ROOT/'build/adreno-pipeline-compiler-20260927/draw-plan-v2'/name, digest)
    integration, mixed, compiler, draw, probe, link = [records[n] for n in
        ('integration', 'mixed', 'compiler', 'draw', 'probe', 'link')]
    assert mixed['build_exit'] == mixed['replay_exit'] == 0
    assert mixed['regressions'] == {'test-sptm-update': 0, 'test-user-update': 0}
    bind(Path(mixed['capture']), mixed['capture_sha256'])
    assert mixed['request']['count'] == 2 and int(mixed['request']['options'], 0) == 0x10a
    assert Path(link['plan']['qualification']) == paths['integration']
    assert link['plan']['qualification_sha256'] == sha(paths['integration'])
    for name, digest in link['plan']['original_sources_sha256'].items():
        bind(original/name, digest)
    assert link['plan']['kext_sha256'] == integration['kext_sha256']
    assert Path(probe['draw_qualification']) == paths['draw']
    assert probe['draw_qualification_sha256'] == sha(paths['draw'])
    assert probe['plugin_sha256'] == draw['bundle_executable_sha256']
    assert Path(records['submission']['draw']) == paths['draw']
    assert Path(records['submission']['driver']) == paths['driver']
    runtime_path = Path(compiler['runtime_qualification'])
    bind(runtime_path, compiler['runtime_qualification_sha256'])
    runtime = verify(runtime_path)
    assert runtime['status'] == 'PACKAGED_COMPILER_ARM64E_C_API_VERIFIED'
    bundle = Path(draw['bundle'])
    bind(bundle/'Contents/MacOS/AdrenoMetal', draw['bundle_executable_sha256'])
    bind(bundle/'Contents/Frameworks/libAdrenoCompiler.dylib',
        runtime['artifacts_sha256']['runtime/libAdrenoCompiler.dylib'])
    for p in bundle.rglob('*'):
        if p.is_file(): bind(p)
    monitor = paths['integration'].parent/'monitor/xnuboot.bin'
    kext = paths['integration'].parent/'kext/AdrenoX2.kext/Contents/MacOS/AdrenoX2'
    collection, executable = paths['link'].parent/'AdrenoX2.kc', paths['probe'].parent/'metal-triangle-probe'
    for path, digest in [(monitor, integration['monitor_sha256']), (kext, integration['kext_sha256']),
            (collection, link['collection_sha256']), (executable, probe['binary_sha256'])]: bind(path, digest)

    # The retained PA evidence is deliberately scoped to identical helpers and context.
    pa_path = args.pa_components.resolve()
    pa = verify(pa_path, pa_root)
    assert pa['status'] == 'CLEAR_COMPONENTS_BOUND_NOT_INSTALLED'
    physical_path = Path(pa['physical_record'])
    bind(physical_path, pa['physical_record_sha256'])
    assert pa['physical_record_sha256'] == '60adf8f269f935e32d7a27b7c9e64096da802145efff69e0156bdfe95eadd9b1'
    physical = verify(physical_path, original)
    assert physical['result'] == 'PASS' and len(physical['rows']) == 576
    assert physical['canonical_comparisons'] == 192 and physical['workspace_restored']
    assert physical['workspace_before_sha256'] == physical['workspace_after_sha256']
    assert not physical['exceptions'] and not any(physical['serror'].values())
    for name, digest in physical['source_sha256'].items():
        if name not in ('probes/run.py', 'tools/qualify-pauth-raw-native.py'): bind(ROOT/name, digest)
    for directory in ('compat', 'probes'):
        for p in (ROOT/directory).glob('pauth-*'):
            if p.is_file():
                bind(p, bind(pa_root/directory/p.name))
    raw_path = original/'build/pauth-native-sign-20260927/monitor-v1/build.json'
    bind(raw_path, pa['raw_build_sha256'])
    assert integration['build_defines'] == json.loads(raw_path.read_text())['build_defines']
    helper_path = ROOT/'tools/qualify-adreno-clear-components.py'
    bind(helper_path)
    spec = importlib.util.spec_from_file_location('component_layout', helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    context = helper.layout(read_source(ROOT/'probes/xnuboot.c'), ROOT)
    previous = json.loads((pa_path.parent/'context-layout.json').read_text())
    assert len(previous['fields']) == 215 and previous['context_bytes'] == 5094208
    assert {k: context['fields'].get(k) for k in previous['fields']} == previous['fields']
    assert set(context['fields'])-set(previous['fields']) == {'perf'}
    assert context['fields']['perf'] == previous['context_bytes']
    assert len(context['fields']) == 216 and context['context_bytes'] == 5108352
    current_source, previous_source = [read_source(r/'probes/xnuboot.c') for r in (ROOT, pa_root)]
    for callback in ('pauth_batch_native_sign', 'pauth_pointer_native_sign'):
        pattern = r'^static int '+callback+r'\(.*?^\}'
        assert re.search(pattern, current_source, re.M | re.S)[0] == re.search(pattern, previous_source, re.M | re.S)[0]
    for switch in ('SNAP_FAST_VCPU_TRAPS', 'SNAP_SYSREG_CENSUS', 'SNAP_INCREMENTAL_PUBLISH',
                   'SNAP_INCREMENTAL_PUBLISH_VERIFY', 'SNAP_CANONICAL_VIEW_FAST'):
        assert '#define '+switch+' 0' in current_source
        assert not any(x.startswith('-D'+switch+'=') for x in integration['build_defines'])

    copy_path = args.display_copy.resolve()
    copy = verify(copy_path)
    assert copy['verdict'] == 'PASS'
    abi_path = base/'display-abi-v1/iomfb-vtable-check.json'
    abi = verify(abi_path)
    assert abi['verdict'] == 'PASS' and not abi['errors'] and not abi['undefined_not_exported']
    bind(ROOT/'gpu/adreno-kext/kext/include/IOMobileGraphicsFamily26A428.h', abi['header_sha256'])
    bind(abi_path.parent/'IOMFBCheck', abi['bundle_sha256'])
    bind(Path(abi['kernelcache']))
    for name in ['tools/check-iomfb-vtable.py', 'tools/test-display-profile.py',
            'gpu/adreno-kext/kext/src/AdrenoDisplay.cpp', 'gpu/adreno-kext/kext/src/AdrenoDisplay.h']:
        for path in source_files(ROOT/name):              # a split unit binds its ordered parts too
            bind(path)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, 'tools/test-display-profile.py', '--firmware', str(original/'downloads/extracted/j700ap')]
    run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    (out/'display-profile.log').write_text(run.stdout+run.stderr)
    assert run.returncode == 0 and 'Ran 6 tests' in run.stderr and run.stderr.rstrip().endswith('OK')
    (out/'context-layout.json').write_text(json.dumps(context, indent=2)+'\n')
    bind(Path(__file__))
    for name, digest in inputs.items(): assert sha(Path(name)) == digest, name
    result = dict(status='SHADER_DISPLAY_COMPONENTS_BOUND_NOT_INSTALLED', finished=time.time(),
        a16_access=False, guest_executed=False, screen_presented=False,
        components={n: dict(path=str(p), sha256=sha(p)) for n, p in paths.items()},
        inputs_sha256=inputs, display_profile='j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display',
        monitor=str(monitor), monitor_sha256=sha(monitor), kext=str(kext), kext_sha256=sha(kext),
        deployed_collection=str(collection), deployed_collection_sha256=sha(collection),
        plugin_bundle=str(bundle), plugin_sha256=probe['plugin_sha256'],
        guest_probe=str(executable), guest_probe_sha256=sha(executable),
        pa_components=str(pa_path), physical_record=str(physical_path),
        context_fields=len(context['fields']), context_bytes=context['context_bytes'],
        preserved_context_fields=len(previous['fields']), appended_perf_bytes=context['context_bytes']-previous['context_bytes'],
        commands=[dict(argv=command, exit_code=run.returncode)],
        artifacts_sha256={str(p.relative_to(out)): sha(p) for p in out.rglob('*') if p.is_file()},
        boundary='Bound current shader and display source/build/host evidence; retained physical PA helper proof only. No A16 shader draw, swap or desktop has run.')
    (out/'components.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(status=result['status'], bindings=len(inputs), monitor=result['monitor_sha256'])))


if __name__ == '__main__':
    main()
