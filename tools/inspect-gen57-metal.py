#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect the verified generation57 snapshot without altering its image."""
from pathlib import Path
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
SNAP = ROOT / 'build/metal-pipeline-deploy-20260928/snapshot-v1'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--snapshot-sha256', required=True)
args = ap.parse_args()
sp = SNAP / 'snapshot.json'
assert sha(sp) == args.snapshot_sha256
record = json.loads(sp.read_text())
assert record['result'] == 'PASS' and record['generation'] == 57
assert record['completed_bytes'] == record['container_bytes'] == 62826479616
assert record['edges_unchanged'] and record['checkpoints_unchanged']
assert not any(record['serror'].values())
assert record['shutdown'] == ['normal shutdown, CSTS 0x9', 'CC.EN 0, CSTS 0x0']
for name, digest in record['sources'].items():
    assert sha(ROOT.parent / 'q1n1' / name) == digest
digest = hashlib.sha256()
with Path(record['image']).open('rb') as f:
    f.seek(record['image_offset'])
    remaining = record['container_bytes']
    while remaining:
        block = f.read(min(16 << 20, remaining))
        assert block
        digest.update(block)
        remaining -= len(block)
assert digest.hexdigest() == record['container_sha256']
print('PASS: independent full main-container rehash', flush=True)
deployment_path = ROOT.parent / 'Snapintosh-adreno-pipeline/build/adreno-gui-integration-20260927/deployment-v1/deployment.json'
assert sha(deployment_path) == '53eac4ddc76738a1ea42dc97dda56f0d3515c936bb505458787ce9a91220247a'
deployment = json.loads(deployment_path.read_text())
staged = dict(files=[dict(path=i['destination'].lstrip('/'), sha256=i['sha256']) for i in deployment['installs']])
base = ROOT / 'build/inspect-metal-report-snapshot-20260926.py'
assert sha(base) == '6c9f3627e8889a69b45639593224aa1fa41ec5fff5efeaeae4afdc3c97e51558'
source = base.read_text()
changes = {
    "BASE = ROOT/'build/installed-metal-20260926'": "BASE = ROOT/'build/metal-pipeline-deploy-20260928'",
    "SNAP = BASE/'report-snapshot-v1'": "SNAP = BASE/'snapshot-v1'",
    "snapshot['generation'] == 41": "snapshot['generation'] == 57",
    "staged = json.loads((BASE/'stage-v1/stage.json').read_text())": 'staged = installed_files',
    'Library/LaunchDaemons/org.snapintosh.metal-probe.plist': 'private/var/db/ManagedConfigurationFiles/BackgroundTaskServices/LaunchDaemons/org.snapintosh.metal-probe.plist',
    "reports.glob('metal-probe*.json')": "reports.glob('metal-triangle-probe*')",
    "'metal-probe' in path.name.lower()": "'metal-triangle-pro' in path.name.lower()",
    "        directory = safe(data,relative)\n        if directory.is_dir():":
        "        directory = safe(data,relative)\n        if not __import__('os').access(directory.parent, 1):\n            record.setdefault('unreadable_directories',[]).append(relative); continue\n        if directory.is_dir():",
    '    assert path.is_file() and path.stat().st_size <= 16<<20, str(path)':
        "    presentation = __import__('re').fullmatch(r'metal-triangle-probe-[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}-presentation\\.bgra', path.name)\n    limit = (64 if presentation else 16) << 20\n    assert path.is_file() and path.stat().st_size <= limit, str(path)",
    "    plist_path = safe(data,'Library/LaunchDaemons/org.snapintosh.metal-probe.plist')":
        "    assert len(record['files']) == 6 and all(i.get('matches') for i in record['files'])\n    plist_path = safe(data,'Library/LaunchDaemons/org.snapintosh.metal-probe.plist')",
}
# Insert the file-count check before replacing its launch-job pathname.
last = "    plist_path = safe(data,'Library/LaunchDaemons/org.snapintosh.metal-probe.plist')"
assert source.count(last) == 1
source = source.replace(last, changes.pop(last))
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__', installed_files=staged))
