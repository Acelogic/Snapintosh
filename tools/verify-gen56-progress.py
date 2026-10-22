#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the resumed captures and derive generation56's actual GUI blocker.

Failure inventory: incomplete recovery, source drift, missing resumed stage,
conflicting copied capture, unbound native state, stale mode properties, and
mistaking a compiler abort or pipeline build for GPU presentation. Host only.
The failed primary collector remains failed; this is a separate completion
manifest for its successfully resumed capture stages.
"""
from pathlib import Path
import collections
import hashlib
import json
import runpy
import shutil
import struct

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT.parent / 'Snapintosh-adreno-sks'
PREFIX = 'installed-metal-panel-arguments-3600s-20260928'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    path = lambda suffix: ROOT / 'build' / (PREFIX + suffix)
    output = path('-capture-completion-v1.json')
    assert not output.exists(), 'preserve prior completion evidence'
    launch = json.loads(path('-launch.json').read_text())
    adapter = runpy.run_path(str(ROOT / 'tools/collect-recovered-gen56.py'))
    recovery = adapter['native_recovery'](launch)
    recovery_hash = sha(path('-host-recovery-v1.json'))
    records = {}
    for p in (ROOT / 'build').glob(PREFIX + '-recovery-adapter-*.json'):
        row = json.loads(p.read_text())
        if row['status'] != 'RECOVERED_COLLECTOR_COMPLETED':
            continue
        assert row['recovery_sha256'] == recovery_hash
        assert row['launch_sha256'] == sha(path('-launch.json'))
        records[p] = row
    required = ['audit-secondary-runtime.py', 'capture-secondary-stop.py',
        'capture-service-profile.py', 'capture-kernel-waits.py',
        'capture-console-tail.py', 'capture-panel-arguments-ring-20260928.py',
        'capture-native-startup-gen56-20260928.py']
    for name in required:
        assert any(Path(r['script']).name == name or
            any(Path(arg).name == name for arg in r['command']) for r in records.values()), name
    for suffix in ['console-tail.bin', 'console-tail.txt', 'console-tail.json']:
        source = RUNTIME / 'build' / (PREFIX + '-' + suffix)
        target = path('-' + suffix)
        if not target.exists():
            with source.open('rb') as inp, target.open('xb') as out:
                shutil.copyfileobj(inp, out)
        assert sha(source) == sha(target)
    suffixes = ['-launch.json', '-host-recovery-v1.json', '-audit.json', '-cpu0-stop.json',
        '-service-profile.json', '-kernel-waits.json', '-mounts.json', '-metal-probe.json',
        '-panel.png', '-console-tail.bin', '-console-tail.txt', '-console-tail.json',
        '-gpu-ring.json', '-gpu-ring.bin', '-gpu-fence.bin',
        '-native-startup-state-v1.json', '-native-startup-state-v1-binding.json',
        '-native-startup-state-waits-v1.json', '-native-startup-state-waits-v1-binding.json',
        '-crash-retention-v1.json', '-crash-retention-v1-binding.json',
        '-recovery-adapter-primary-50854.json']
    artifacts = {str(path(s)): sha(path(s)) for s in suffixes}
    audit = json.loads(path('-audit.json').read_text())
    assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
    assert audit['service'] == recovery['service']
    assert audit['monitor_sha256'] == launch['monitor_sha256']
    for stem in ['native-startup-state-v1', 'native-startup-state-waits-v1', 'crash-retention-v1']:
        bound = json.loads(path('-' + stem + '-binding.json').read_text())
        assert bound['generation'] == 56 and not bound['writes'] and not bound['guest_resumed']
        assert bound['output_sha256'] == sha(path('-' + stem + '.json'))
        assert bound['verification_sha256'] == sha(path('-audit.json'))
    native = json.loads(path('-native-startup-state-v1.json').read_text())
    display = next(e for e in native['ioreg_state']['detail_entries'] if e['class_name'] == 'AdrenoDisplay')
    modes = {}
    for name in ['DisplayWidth', 'DisplayHeight', 'DPTimingModeId']:
        prop = display['property_objects'][name]
        assert prop['class_name'] == 'OSNumber'
        raw = bytes.fromhex(prop['raw_hex'])
        modes[name] = struct.unpack_from('<Q', raw, 16)[0]
    assert modes == dict(DisplayWidth=2880, DisplayHeight=1800, DPTimingModeId=1000)
    crashes = audit['el0_crashes']['user_crashes']
    assert not any(crashes['lost'])
    reasons = collections.Counter(r['reason'] for r in crashes['rows'] if r.get('reason'))
    assert reasons['Metal failed to build render pipeline'] == 7
    prior = json.loads(path('-recovery-adapter-primary-50854.json').read_text())
    assert prior['status'] == 'FAILED'
    result = dict(status='GEN56_STOPPED_CAPTURES_AND_MODE_VERIFIED', generation=56,
        hardware_access=False, primary_capture_complete=True, native_capture_complete=True,
        original_primary_status=prior['status'], original_host_exit_available=False,
        recovery_sha256=recovery_hash, launch_sha256=sha(path('-launch.json')),
        artifacts_sha256=artifacts, completed_adapter_records_sha256={str(p): sha(p) for p in records},
        mode_properties=modes, display_presents=display['display_swap_snapshot']['presents'],
        crash_reasons=dict(reasons), desktop_verified=False,
        source_sha256=sha(Path(__file__)),
        boundary='Captured hardware mode-setting success and native pipeline abort reasons; no desktop or current-run shader pixels.')
    with output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(status=result['status'], mode=modes, aborts=dict(reasons), output=str(output))))


if __name__ == '__main__':
    main()
