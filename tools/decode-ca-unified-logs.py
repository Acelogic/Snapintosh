#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the saved unified store with a separately reconstructed manifest.

Failure inventory: altered raw logs, lost UUID strings, invented timestamps,
decoder failures hidden as no events, and old events misattributed to gen57.
Only a new host copy is written. Metadata is derived by the reviewed MIT tool
https://github.com/Johann-PLW/logarchive_info at the pinned commit below.
"""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/ca-metal-deploy-20260928'
INPUT = BASE / 'unified-log-inspection-v1'
OUT = BASE / 'unified-log-decoded-v2'
TOOL = ROOT / 'build/ca-logarchive-info-20260928'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
record_path = INPUT / 'inspection.json'
captured = json.loads(record_path.read_text())
assert captured['status'] == 'READ_ONLY_CRASH_LOG_INSPECTION_COMPLETE'
assert captured['image_stat'] == captured['image_stat_after'] and captured['detach']['exit_code'] == 0
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=TOOL, text=True).strip()
assert commit == 'ceebafe6df25bf70f288cff22bc226380c17a69f'
helper = TOOL / 'logarchive_info.py'
assert helper.read_bytes() == subprocess.check_output(['git', 'show', 'HEAD:logarchive_info.py'], cwd=TOOL)
OUT.mkdir(exist_ok=False)
archive = OUT / 'guest.logarchive'
archive.mkdir()
record = dict(status='RUNNING', started=time.time(), source_sha256=sha(__file__),
    input_sha256=sha(record_path), helper_commit=commit, helper_sha256=sha(helper),
    hardware_access=False, raw_inputs_modified=False, copied=[])
try:
    for entry in captured['archive']['files']:
        relative = Path(entry['path'])
        origin = INPUT / 'guest.logarchive' / relative
        assert sha(origin) == entry['sha256'] and not origin.is_symlink()
        target_relative = relative.relative_to('uuidtext') if relative.parts[0] == 'uuidtext' else relative
        dest = archive / target_relative
        assert not dest.exists()
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, dest)
        assert sha(dest) == entry['sha256']
        record['copied'].append(dict(source=entry['path'], target=str(target_relative), sha256=entry['sha256']))
    # Empty stores have no entries in the captured file-hash manifest.
    for name in ('Persist', 'Special', 'Signpost', 'HighVolume', 'timesync'):
        (archive / name).mkdir(exist_ok=True)
    with (OUT / 'metadata.log').open('x') as log:
        built = subprocess.run([sys.executable, str(helper), str(archive)],
            stdout=log, stderr=subprocess.STDOUT, timeout=60)
    record['metadata_exit'] = built.returncode
    assert built.returncode == 0, 'metadata reconstruction failed'
    record['generated_info_sha256'] = sha(archive / 'Info.plist')
    command = ['/usr/bin/log', 'show', '--archive', str(archive), '--style', 'ndjson',
        '--info', '--debug', '--predicate',
        'process == "WindowServer" OR eventMessage CONTAINS[c] "WindowServer" OR eventMessage CONTAINS[c] "Adreno" OR eventMessage CONTAINS[c] "uncaught exception"']
    with (OUT / 'windowserver.ndjson').open('x') as stdout, (OUT / 'decoder.log').open('x') as stderr:
        decoded = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=90)
    record.update(decoder_exit=decoded.returncode, command=command,
        output_sha256=sha(OUT / 'windowserver.ndjson'), output_bytes=(OUT / 'windowserver.ndjson').stat().st_size)
    assert decoded.returncode == 0, 'log decoder did not complete'
    for entry in captured['archive']['files']:
        assert sha(INPUT / 'guest.logarchive' / entry['path']) == entry['sha256']
    record['status'] = 'SAVED_UNIFIED_LOG_DECODE_COMPLETE'
except BaseException as error:
    record.update(status='FAILED', error=repr(error))
    raise
finally:
    record['finished'] = time.time()
    (OUT / 'decode.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(status=record['status'], output=str(OUT / 'decode.json'), bytes=record['output_bytes'])))
