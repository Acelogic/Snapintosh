#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage bound Metal clear components and trust entries; no mount or SSD access."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import plistlib
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--components', type=Path, required=True)
    ap.add_argument('--fill-root', type=Path, required=True)
    ap.add_argument('--firmware', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    module_path = ROOT / 'tools/qualify-adreno-clear-components.py'
    spec = importlib.util.spec_from_file_location('clear_components', module_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    components_path = args.components.resolve()
    components = helper.verify(components_path, ROOT)
    assert components['status'] == 'CLEAR_COMPONENTS_BOUND_NOT_INSTALLED'
    paths, records = {}, {}
    for name, entry in components['components'].items():
        path = Path(entry['path'])
        assert sha(path) == entry['sha256'], name
        paths[name] = path
        records[name] = helper.verify(path, args.fill_root.resolve() if name == 'link' else ROOT)
    for name, digest in components['unchanged_kext_inputs_sha256'].items():
        assert sha(ROOT / name) == digest
        assert sha(args.fill_root.resolve() / name) == digest
    for name in ('deployed_kext', 'deployed_collection', 'monitor'):
        assert sha(Path(components[name])) == components[name + '_sha256']
    assert helper.compare_kext(Path(components['deployed_kext']),
        paths['monitor'].parent / 'kext/AdrenoX2.kext/Contents/MacOS/AdrenoX2') == components['kext_comparison']
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = {str(p.relative_to(ROOT)): sha(p) for p in
        (Path(__file__), module_path, ROOT / 'probes/trustcache.py', ROOT / 'probes/guestprofile.py')}
    bundle = paths['clear'].parent / 'plugin/AdrenoMetal.bundle'
    executable = paths['probe'].parent / 'metal-clear-probe'
    assert sha(bundle / 'Contents/MacOS/AdrenoMetal') == components['plugin_sha256']
    assert sha(executable) == components['guest_probe_sha256']
    shutil.copytree(bundle, out / 'AdrenoMetal.bundle')
    shutil.copy2(executable, out / 'metal-clear-probe')
    rows, commands = [], []
    for name, path in [('AdrenoMetal', out / 'AdrenoMetal.bundle'),
                       ('metal-clear-probe', out / 'metal-clear-probe')]:
        for kind, argv in [('verify', ['codesign', '--verify', '--strict', str(path)]),
                           ('identity', ['codesign', '-dvvv', str(path)])]:
            commands.append(argv)
            result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (out / (name + '-' + kind + '.log')).write_text(result.stdout)
            assert result.returncode == 0, (name, kind)
        cdhash, = re.findall(r'^CDHash=([0-9a-f]{40})$', result.stdout, re.M)
        if name == 'metal-clear-probe':
            assert cdhash == records['probe']['cdhash']
        rows.append(dict(name=name, cdhash=cdhash, category=2, flags=0))
    additions = out / 'trust-additions.json'
    additions.write_text(json.dumps(rows, indent=2) + '\n')
    sys.path.insert(0, str(ROOT / 'probes'))
    import xnuboot as xb
    from trustcache import parse_v2
    firmware = args.firmware.resolve()
    xb.configure_guest('j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal', directory=firmware)
    trust = xb.trust_cache_spec(additions)
    payload = trust.load(firmware)
    assert trust.verify(payload) == payload
    (out / 'trustcache.payload').write_bytes(payload)
    job = dict(Label='org.snapintosh.metal-probe',
        ProgramArguments=['/Library/Snapintosh/metal-clear-probe', '--report-base',
                          '/var/db/Snapintosh/metal-clear-probe', '--wait', '600'],
        RunAtLoad=True, StandardOutPath='/var/log/snapintosh-metal-clear-probe.log',
        StandardErrorPath='/var/log/snapintosh-metal-clear-probe.log')
    job_path = out / 'org.snapintosh.metal-probe.plist'
    with job_path.open('xb') as stream:
        plistlib.dump(job, stream, sort_keys=True)
    installs = []
    for file in sorted((out / 'AdrenoMetal.bundle').rglob('*')):
        if file.is_file():
            destination = '/Library/GPUBundles/AdrenoMetal.bundle/' + str(file.relative_to(out / 'AdrenoMetal.bundle'))
            installs.append(dict(source=str(file.relative_to(out)), destination=destination, sha256=sha(file)))
    installs.extend([
        dict(source='metal-clear-probe', destination='/Library/Snapintosh/metal-clear-probe', sha256=sha(out / 'metal-clear-probe')),
        dict(source=job_path.name, destination='/private/var/db/ManagedConfigurationFiles/BackgroundTaskServices/LaunchDaemons/' + job_path.name, sha256=sha(job_path))])
    helper.verify(components_path, ROOT)
    for name, digest in sources.items():
        assert sha(ROOT / name) == digest
    result = dict(status='CLEAR_DEPLOYMENT_STAGED_NOT_INSTALLED', components=str(components_path),
        components_sha256=sha(components_path), sources_sha256=sources, commands=commands,
        installs=installs, trust_rows=rows, trust_cache_sha256=sha(out / 'trustcache.payload'),
        trust_entries=parse_v2(payload)['count'], firmware=str(firmware),
        firmware_base_trust_sha256=sha(firmware / trust.filename),
        monitor=components['monitor'], monitor_sha256=components['monitor_sha256'],
        deployed_collection=components['deployed_collection'],
        deployed_collection_sha256=components['deployed_collection_sha256'],
        artifacts_sha256={str(p.relative_to(out)): sha(p) for p in sorted(out.rglob('*')) if p.is_file()},
        boundary=__doc__ + ' Apply only against a fresh post-boot main-container snapshot. Offscreen GPU readback and panel presentation remain unproven.')
    report = out / 'deployment.json'
    report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], report=str(report), files=len(installs), trust_entries=result['trust_entries'])))


if __name__ == '__main__':
    main()
