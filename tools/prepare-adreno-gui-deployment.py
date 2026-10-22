#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the bound Metal triangle/display candidate and all code trust entries.

Offline only. Failure inventory: docs/ADRENO-GUI-INTEGRATION-20260927.md.
"""
from pathlib import Path
import argparse
import hashlib
import json
import plistlib
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def verify(path):
    record = json.loads(path.read_text())
    for key, base in [('inputs_sha256', ROOT), ('sources_sha256', ROOT), ('artifacts_sha256', path.parent)]:
        for name, digest in record.get(key, {}).items():
            assert sha(base/name) == digest, (path, name)
    return record


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--components', type=Path, required=True)
    ap.add_argument('--firmware', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    components_path = args.components.resolve()
    components = verify(components_path)
    assert components['status'] == 'SHADER_DISPLAY_COMPONENTS_BOUND_NOT_INSTALLED'
    for name in ('monitor', 'deployed_collection', 'guest_probe'):
        assert sha(Path(components[name])) == components[name+'_sha256']
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = {str(p.relative_to(ROOT)): sha(p) for p in
        (Path(__file__), ROOT/'probes/trustcache.py', ROOT/'probes/guestprofile.py')}
    bundle = out/'AdrenoMetal.bundle'
    executable = out/'metal-triangle-probe'
    shutil.copytree(Path(components['plugin_bundle']), bundle)
    shutil.copy2(Path(components['guest_probe']), executable)
    assert sha(bundle/'Contents/MacOS/AdrenoMetal') == components['plugin_sha256']
    assert sha(executable) == components['guest_probe_sha256']
    # Every embedded Mach-O needs its own trust entry, including the compiler.
    machos = [p for p in bundle.rglob('*') if p.is_file() and p.read_bytes()[:4] == b'\xcf\xfa\xed\xfe']
    assert {str(p.relative_to(bundle)) for p in machos} == {
        'Contents/MacOS/AdrenoMetal', 'Contents/Frameworks/libAdrenoCompiler.dylib'}
    rows, commands = [], []
    for path in machos+[executable]:
        name = path.name
        for kind, argv in [('verify', ['codesign', '--verify', '--strict', str(path)]),
                           ('identity', ['codesign', '-dvvv', str(path)])]:
            proc = subprocess.run(argv, capture_output=True, text=True)
            output = proc.stdout+proc.stderr
            (out/(name+'-'+kind+'.log')).write_text(output)
            commands.append(dict(argv=argv, exit_code=proc.returncode))
            assert proc.returncode == 0, (name, kind)
        cdhash, = re.findall(r'^CDHash=([0-9a-f]{40})$', output, re.M)
        rows.append(dict(name=name, cdhash=cdhash, category=2, flags=0))
    proc = subprocess.run(['codesign', '--verify', '--strict', str(bundle)], capture_output=True, text=True)
    (out/'bundle-verify.log').write_text(proc.stdout+proc.stderr)
    assert proc.returncode == 0
    assert len(rows) == len({r['cdhash'] for r in rows}) == 3
    additions = out/'trust-additions.json'
    additions.write_text(json.dumps(rows, indent=2)+'\n')
    sys.path.insert(0, str(ROOT/'probes'))
    import xnuboot as xb
    from trustcache import parse_v2
    firmware = args.firmware.resolve()
    xb.configure_guest(components['display_profile'], directory=firmware)
    trust = xb.trust_cache_spec(additions)
    payload = trust.load(firmware)
    assert trust.verify(payload) == payload
    (out/'trustcache.payload').write_bytes(payload)
    job = dict(Label='org.snapintosh.metal-probe', RunAtLoad=True,
        ProgramArguments=['/Library/Snapintosh/metal-triangle-probe', '--report-base',
            '/var/db/Snapintosh/metal-triangle-probe', '--wait', '600', '--present', '--hold', '3600'],
        StandardOutPath='/var/log/snapintosh-metal-triangle-probe.log',
        StandardErrorPath='/var/log/snapintosh-metal-triangle-probe.log')
    job_path = out/'org.snapintosh.metal-probe.plist'
    job_path.write_bytes(plistlib.dumps(job, sort_keys=True))
    installs = [dict(source=str(p.relative_to(out)),
        destination='/Library/GPUBundles/AdrenoMetal.bundle/'+str(p.relative_to(bundle)), sha256=sha(p))
        for p in sorted(bundle.rglob('*')) if p.is_file()]
    installs += [dict(source=executable.name, destination='/Library/Snapintosh/'+executable.name, sha256=sha(executable)),
        dict(source=job_path.name, destination='/private/var/db/ManagedConfigurationFiles/BackgroundTaskServices/LaunchDaemons/'+job_path.name,
             sha256=sha(job_path))]
    verify(components_path)
    for name, digest in sources.items(): assert sha(ROOT/name) == digest
    result = dict(status='SHADER_DISPLAY_DEPLOYMENT_STAGED_NOT_INSTALLED',
        a16_access=False, guest_executed=False, screen_presented=False,
        components=str(components_path), components_sha256=sha(components_path),
        inputs_sha256=components['inputs_sha256'], sources_sha256=sources, commands=commands,
        installs=installs, trust_rows=rows, trust_entries=parse_v2(payload)['count'],
        trust_cache_sha256=sha(out/'trustcache.payload'), firmware=str(firmware),
        firmware_base_trust_sha256=sha(firmware/trust.filename), guest_profile=components['display_profile'],
        monitor=components['monitor'], monitor_sha256=components['monitor_sha256'],
        deployed_collection=components['deployed_collection'], deployed_collection_sha256=components['deployed_collection_sha256'],
        context_bytes=components['context_bytes'],
        artifacts_sha256={str(p.relative_to(out)): sha(p) for p in out.rglob('*') if p.is_file()},
        boundary='Offline shader/compiler/probe and native display job staging only. Apply against a fresh stopped-guest snapshot; reject competing display jobs. No A16 draw, swap or desktop.')
    (out/'deployment.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(status=result['status'], files=len(installs), new_trust_entries=len(rows))))


if __name__ == '__main__':
    main()
