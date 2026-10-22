#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read previously inaccessible crash logs from the verified local SSD snapshot.

Failure inventory: modifying the image, selecting a host volume, symlink escape,
unbounded logs, incomplete detach, or attributing an old report to this boot.
Mount only this snapshot's Data volume read-only with ownership disabled, as
already used for local image staging. No root process or hardware connection.
"""
from pathlib import Path
import hashlib
import json
import os
import plistlib
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/ca-metal-deploy-20260928'
SNAP = BASE / 'snapshot-v1/snapshot.json'
OUT = BASE / 'crash-log-inspection-v1'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
assert sha(SNAP) == 'a2f2e983857d8137b23979633158b423d634699242fe348cf092999a11a8cd97'
snapshot = json.loads(SNAP.read_text())
assert snapshot['result'] == 'PASS' and snapshot['generation'] == 58
image = Path(snapshot['image']).resolve()
assert image.stat().st_size == 64 << 30
signature = lambda p: [p.stat().st_dev, p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ctime_ns]
before = signature(image)
plist = lambda *argv: plistlib.loads(subprocess.check_output(argv))
assert not any(Path(v.get('image-path', '/')).resolve() == image for v in plist('hdiutil', 'info', '-plist').get('images', []))
OUT.mkdir(exist_ok=False)
mount = OUT / 'data'
mount.mkdir()
record = dict(status='RUNNING', started=time.time(), source_sha256=sha(__file__),
    snapshot_sha256=sha(SNAP), image=str(image), image_stat=before,
    hardware_access=False, image_writes=False, files=[], directories=[])
device = None
try:
    raw = subprocess.check_output(['hdiutil', 'attach', '-nomount', '-readonly', '-plist', str(image)])
    (OUT / 'attach.plist').write_bytes(raw)
    entities = plistlib.loads(raw)['system-entities']
    device = next(e['dev-entry'] for e in entities if e.get('dev-entry'))
    nodes = {e.get('dev-entry') for e in entities}
    container, = [c for c in plist('diskutil', 'apfs', 'list', '-plist')['Containers']
        if c['APFSContainerUUID'] == '3404F471-EA91-4F23-B2A5-B21455330A5F'
        and any('/dev/' + s['DeviceIdentifier'] in nodes for s in c['PhysicalStores'])]
    volume, = [v for v in container['Volumes'] if v['APFSVolumeUUID'] == '501065D4-E49E-4DDA-B4E7-056CA04D4B90']
    subprocess.run(['diskutil', 'mount', 'readOnly', 'nobrowse', '-mountOptions', 'noowners',
                    '-mountPoint', str(mount), volume['DeviceIdentifier']], check=True, capture_output=True)
    info = plist('diskutil', 'info', '-plist', str(mount))
    assert not info['WritableVolume'] and not info['GlobalPermissionsEnabled']
    assert info['VolumeUUID'] == '501065D4-E49E-4DDA-B4E7-056CA04D4B90'
    record['mount'] = dict(device=volume['DeviceIdentifier'], readonly=True, owners=False)
    directories = ['Library/Logs/DiagnosticReports', 'private/var/root/Library/Logs/DiagnosticReports',
                   'private/var/db/diagnostics', 'private/var/log']
    for relative in directories:
        directory = mount / relative
        assert directory.resolve().is_relative_to(mount.resolve())
        if not directory.is_dir():
            record['directories'].append(dict(path=relative, exists=False))
            continue
        entries = sorted(directory.iterdir())
        assert len(entries) < 10000
        record['directories'].append(dict(path=relative, exists=True, entries=[p.name for p in entries]))
        for path in entries:
            if path.is_symlink() or not path.is_file():
                continue
            selected = 'WindowServer' in path.name or 'loginwindow' in path.name or path.name in (
                'system.log', 'snapintosh-metal-triangle-probe.log')
            if not selected:
                continue
            assert path.stat().st_size <= 32 << 20, path
            data = path.read_bytes()
            dest = OUT / 'evidence' / relative / path.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            lines = data.decode(errors='replace').splitlines()
            matches = [line[:1500] for line in lines if re.search(
                'exception|unrecognized|reason|abort|Adreno|WindowServer|pipeline', line, re.I)]
            record['files'].append(dict(path=str(path.relative_to(mount)), bytes=len(data),
                mtime_ns=path.stat().st_mtime_ns, sha256=sha(dest), copy=str(dest), matches=matches[-60:]))
    record['status'] = 'READ_ONLY_CRASH_LOG_INSPECTION_COMPLETE'
except BaseException as error:
    record.update(status='FAILED', error=repr(error))
    raise
finally:
    if device:
        detached = subprocess.run(['hdiutil', 'detach', device], capture_output=True, text=True)
        record['detach'] = dict(exit_code=detached.returncode, output=detached.stdout + detached.stderr)
        if detached.returncode:
            record['status'] = 'FAILED_DETACH'
    record['image_stat_after'] = signature(image)
    assert record['image_stat_after'] == before
    record['finished'] = time.time()
    (OUT / 'inspection.json').write_text(json.dumps(record, indent=2) + '\n')
assert record['status'] == 'READ_ONLY_CRASH_LOG_INSPECTION_COMPLETE'
print(json.dumps(dict(status=record['status'], files=len(record['files']), output=str(OUT / 'inspection.json'))))
