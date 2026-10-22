#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect graphics diagnostics from a read-only, verified guest SSD clone.

Failure inventory: docs/GEN57-OBJC-ABORT-20260928.md. This never connects to A16.
"""
from pathlib import Path
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(16 << 20), b''):
            result.update(block)
    return result.hexdigest()


def signature(path):
    stat = path.stat()
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]


ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--snapshot', type=Path, required=True)
ap.add_argument('--verified-inspection', type=Path)
ap.add_argument('--guest-generation', type=int, required=True)
ap.add_argument('--output', type=Path, required=True)
args = ap.parse_args()
args.snapshot = args.snapshot.resolve()
args.output = args.output.resolve()
if args.verified_inspection:
    args.verified_inspection = args.verified_inspection.resolve()
snapshot = json.loads(args.snapshot.read_text())
assert snapshot['result'] == 'PASS' and snapshot['finished']
assert snapshot['completed_bytes'] == snapshot['container_bytes'] == 62826479616
assert snapshot['edges_unchanged'] and snapshot['checkpoints_unchanged']
assert not any(snapshot['serror'].values())
assert snapshot['generation'] == args.guest_generation + 1
image = Path(snapshot['image'])
assert image.is_file() and not image.is_symlink()
identity = dict(snapshot_sha256=digest(args.snapshot), guest_generation=args.guest_generation,
                snapshot_generation=snapshot['generation'])
if args.verified_inspection:
    previous = json.loads(args.verified_inspection.read_text())
    assert previous['status'] == 'READ_ONLY_REPORT_INSPECTION_COMPLETE'
    assert previous['snapshot_sha256'] == identity['snapshot_sha256']
    assert previous['image'] == str(image)
    assert previous['image_stat_after'] == previous['image_stat'] == signature(image)
    assert previous['detach'] and all(x['exit_code'] == 0 for x in previous['detach'])
    identity['prior_inspection_sha256'] = digest(args.verified_inspection)
    identity['identity_method'] = 'unchanged verified clone identity and metadata'
else:
    value = hashlib.sha256()
    with image.open('rb') as stream:
        stream.seek(snapshot['image_offset'])
        remaining = snapshot['container_bytes']
        while remaining:
            block = stream.read(min(16 << 20, remaining))
            assert block
            value.update(block)
            remaining -= len(block)
    assert value.hexdigest() == snapshot['container_sha256']
    identity['identity_method'] = 'independent full main-container SHA256'

base = ROOT / 'build/inspect-metal-report-snapshot-20260926.py'
assert digest(base) == '6c9f3627e8889a69b45639593224aa1fa41ec5fff5efeaeae4afdc3c97e51558'
source = base.read_text()
changes = {
    "BASE = ROOT/'build/installed-metal-20260926'": 'BASE = OUTPUT_OVERRIDE.parent',
    "SNAP = BASE/'report-snapshot-v1'": 'SNAP = SNAPSHOT_OVERRIDE.parent',
    "OUT = BASE/'report-inspection-v1'": 'OUT = OUTPUT_OVERRIDE',
    "IMAGE = SNAP/'current.img'": 'IMAGE = IMAGE_OVERRIDE',
    "snapshot['generation'] == 41": "snapshot['generation'] == IDENTITY['snapshot_generation']",
    "'-readonly','-nobrowse',": "'-readonly','-nobrowse','-owners','off',",
    "staged = json.loads((BASE/'stage-v1/stage.json').read_text())": "staged = {'files': []}",
    "reports.glob('metal-probe*.json')": "reports.glob('metal-triangle-probe*.json')",
    "'private/var/log/snapintosh-firstboot.log')":
        "'private/var/log/snapintosh-firstboot.log','private/var/log/windowserver.log',"
        "'private/var/log/system.log','private/var/log/WindowServer.log')",
    "('Library/Logs/DiagnosticReports','private/var/root/Library/Logs/DiagnosticReports')":
        "('Library/Logs/DiagnosticReports','private/var/root/Library/Logs/DiagnosticReports',"
        "'private/var/log/WindowServer','private/var/log','private/var/db/diagnostics','private/var/db/uuidtext')",
    "'metal-probe' in path.name.lower()":
        "(any(term in path.name.lower() for term in ('windowserver','metal','quartz','coreanimation')) "
        "or path.parent.name.lower() == 'windowserver')",
    "destination = OUT/'evidence'/relative": "destination = OUT/'evidence'/data.name/relative",
    "entry = dict(path=str(relative),": "entry = dict(source_volume=str(data),path=str(relative),",
    "record = dict(status='RUNNING',": "record = dict(identity=IDENTITY,launch_plists=[],directory_inventory=[],inaccessible=[],status='RUNNING',",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
anchor = "    assert path.is_file() and path.stat().st_size <= 16<<20, str(path)"
assert source.count(anchor) == 1
source = source.replace(anchor, anchor + "\n    copies = record['reports'] + record['logs'] + record['launch_plists']\n"
    "    assert len(copies) < 256 and sum(x['bytes'] for x in copies) + path.stat().st_size <= 128<<20")
anchor = "    shutil.copyfile(path,destination)"
assert source.count(anchor) == 1
source = source.replace(anchor, "    if destination.exists():\n        assert sha(destination) == sha(path)\n    else:\n    " + anchor)
anchor = "        if info.get('VolumeUUID') == '501065D4-E49E-4DDA-B4E7-056CA04D4B90': data_points.append(point)"
assert source.count(anchor) == 1
source = source.replace(anchor, anchor + "\n        for name in ('com.apple.WindowServer','com.apple.logd','com.apple.syslogd'):\n"
    "            path = safe(point, 'System/Library/LaunchDaemons/' + name + '.plist')\n"
    "            if path.is_file(): preserve(path,'launch_plists',point)")
anchor = '        if directory.is_dir():\n            for path in directory.iterdir():'
assert source.count(anchor) == 1
source = source.replace(anchor, "        try:\n"
    "            is_directory = directory.is_dir()\n"
    "            entries = sorted(directory.iterdir()) if is_directory else []\n"
    "        except PermissionError as error:\n"
    "            record['inaccessible'].append(dict(path=relative,error=str(error)))\n"
    "            continue\n"
    "        if is_directory:\n"
    "            assert len(entries) <= 4096, relative\n"
    "            record['directory_inventory'].append(dict(path=relative,entries=[dict(name=p.name,bytes=p.lstat().st_size,symlink=p.is_symlink()) for p in entries]))\n"
    "            for path in entries:")
compile(source, '<verified-guest-log-inspection>', 'exec')
exec(compile(source, '<verified-guest-log-inspection>', 'exec'), dict(__file__=__file__, __name__='__main__',
    SNAPSHOT_OVERRIDE=args.snapshot, OUTPUT_OVERRIDE=args.output, IMAGE_OVERRIDE=image, IDENTITY=identity))
