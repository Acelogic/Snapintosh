#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy and decode generation61's crash reports and unified logs from the snapshot.

Failure inventory: wrong snapshot, writable mount, symlink traversal, unbounded
archive, altered raw logs, decoder failure hidden as no events, incomplete
detach, and old-boot events mistaken for generation61. Only host copies are
written. No A16 access and no change to the snapshot image.
"""
from pathlib import Path
import hashlib
import json
import plistlib
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/ca-network-deploy-20260928'
SNAP = BASE / 'snapshot-v1/snapshot.json'
OUT = BASE / 'gen61-logs-v1'
TOOL = ROOT / 'build/ca-logarchive-info-20260928'
LIMIT = 1 << 30
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
signature = lambda p: [p.stat().st_dev, p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ctime_ns]
plist = lambda *argv: plistlib.loads(subprocess.check_output(argv))

snapshot = json.loads(SNAP.read_text())
assert snapshot['result'] == 'PASS' and snapshot['generation'] == 62
image = Path(snapshot['image']).resolve()
assert image.stat().st_size == 64 << 30
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=TOOL, text=True).strip()
assert commit == 'ceebafe6df25bf70f288cff22bc226380c17a69f'
helper = TOOL / 'logarchive_info.py'
assert helper.read_bytes() == subprocess.check_output(['git', 'show', 'HEAD:logarchive_info.py'], cwd=TOOL)
before = signature(image)
assert not any(Path(v.get('image-path', '/')).resolve() == image for v in plist('hdiutil', 'info', '-plist').get('images', []))
OUT.mkdir(exist_ok=False)
mount = OUT / 'data'
mount.mkdir()
archive = OUT / 'guest.logarchive'
record = dict(status='RUNNING', started=time.time(), source_sha256=sha(__file__),
    snapshot_sha256=sha(SNAP), image=str(image), image_stat=before, helper_commit=commit,
    hardware_access=False, image_writes=False, reports=[], archive_files=[])
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
    for relative in ['Library/Logs/DiagnosticReports', 'private/var/root/Library/Logs/DiagnosticReports',
                     'private/var/log']:
        directory = mount / relative
        assert directory.resolve().is_relative_to(mount.resolve())
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 << 20:
                continue
            dest = OUT / 'reports' / relative / path.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            assert sha(path) == sha(dest)
            record['reports'].append(dict(path=str(path.relative_to(mount)), bytes=path.stat().st_size,
                                          mtime_ns=path.stat().st_mtime_ns, sha256=sha(dest)))
    total = 0
    for relative, destination in [('private/var/db/diagnostics', archive),
                                  ('private/var/db/uuidtext', archive)]:
        origin = mount / relative
        assert origin.is_dir() and origin.resolve().is_relative_to(mount.resolve()), relative
        for path in sorted(origin.rglob('*')):
            assert not path.is_symlink(), path
            if not path.is_file():
                continue
            total += path.stat().st_size
            assert total <= LIMIT and len(record['archive_files']) < 40000, 'bounded archive limit'
            dest = destination / path.relative_to(origin)
            assert not dest.exists(), dest
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            assert sha(path) == sha(dest)
            record['archive_files'].append(dict(path=str(dest.relative_to(archive)), sha256=sha(dest)))
    record['archive_bytes'] = total
    record['status'] = 'COPIED'
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
    (OUT / 'inspection.json').write_text(json.dumps(record, indent=2) + '\n')
assert record['status'] == 'COPIED'

try:
    for name in ('Persist', 'Special', 'Signpost', 'HighVolume', 'timesync'):
        (archive / name).mkdir(exist_ok=True)
    with (OUT / 'metadata.log').open('x') as log:
        built = subprocess.run([sys.executable, str(helper), str(archive)], stdout=log,
                               stderr=subprocess.STDOUT, timeout=300)
    record['metadata_exit'] = built.returncode
    assert built.returncode == 0, 'metadata reconstruction failed'
    command = ['/usr/bin/log', 'show', '--archive', str(archive), '--style', 'ndjson', '--info', '--debug']
    with (OUT / 'all.ndjson').open('x') as stdout, (OUT / 'decoder.log').open('x') as stderr:
        decoded = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=1800)
    record.update(decoder_exit=decoded.returncode, command=command,
                  output_sha256=sha(OUT / 'all.ndjson'), output_bytes=(OUT / 'all.ndjson').stat().st_size)
    assert decoded.returncode == 0, 'log decoder did not complete'
    for entry in record['archive_files']:
        assert sha(archive / entry['path']) == entry['sha256']
    record['status'] = 'GEN61_LOGS_DECODED'
except BaseException as error:
    record.update(status='FAILED_DECODE', error=repr(error))
    raise
finally:
    record['finished'] = time.time()
    (OUT / 'inspection.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(status=record['status'], reports=len(record['reports']),
                      archive_files=len(record['archive_files']), output=str(OUT / 'inspection.json'))))
