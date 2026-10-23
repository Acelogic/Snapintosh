#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the saved WindowServer exception to gen57 and the tested CA candidate.

Failure inventory: decoder failure, wrong boot or old plug-in UUID, timestamps
outside the launch, absent persisted events confused with no crash, changed
captured shaders, and calling the candidate fixed before another guest boot.
Produces evidence only; no hardware connection or source/binary changes.
"""
from pathlib import Path
from datetime import datetime
import argparse
import hashlib
import json
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_text import read_source, source_files

ROOT = Path(__file__).resolve().parents[1]
PIPE = ROOT.parent / 'Snapintosh-adreno-pipeline'
BASE = ROOT / 'build/ca-metal-deploy-20260928'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output', type=Path, required=True)
args = ap.parse_args()
inputs = {}


def bind(path, digest=None):
    path = Path(path).resolve()
    actual = sha(path)
    assert digest is None or actual == digest, path
    inputs[str(path)] = actual
    return path


launch_path = bind(ROOT / 'build/installed-metal-qc-pipeline-3600s-20260928-launch.json',
    '834fada225eb1a4809c84f307f41caff0c2387fac058a62045b8d0b90bd704e9')
launch = json.loads(launch_path.read_text())
assert launch['adreno_record']['stage_generation'] == 57 and launch['exit_code'] == 9
decoded_path = bind(BASE / 'unified-log-decoded-v2/decode.json',
    '226e1225010fa7e10333f1a63de8d65bab2e9775b2963c10ff20e2d7e6363507')
decoded = json.loads(decoded_path.read_text())
assert decoded['status'] == 'SAVED_UNIFIED_LOG_DECODE_COMPLETE' and decoded['decoder_exit'] == 0
bind(BASE / 'unified-log-inspection-v1/inspection.json', decoded['input_sha256'])
events_path = bind(decoded_path.parent / 'windowserver.ndjson', decoded['output_sha256'])
events = []
for line in events_path.read_text().splitlines():
    try:
        events.append(json.loads(line))
    except ValueError:
        assert not line.strip() or line.startswith('Filtering the log data'), line[:100]
boot = 'ADFCD134-7E8A-4B42-92D4-7A01EA63F2C2'
rows = [row for row in events if row.get('bootUUID') == boot]
old_binary = bind(PIPE / 'build/qc-plugin-sampler-20260928-v1/AdrenoMetal.bundle/Contents/MacOS/AdrenoMetal',
    '942d8f2c7261880da126838a62412a562fbd1f0f798eaa3f6263faa3743ea014')
uuid = 'B656B91D-BB73-30CF-9BB4-2D5353F89F27'
assert uuid in subprocess.check_output(['xcrun', 'dwarfdump', '--uuid', str(old_binary)], text=True)
plugin_events = [row for row in rows if row.get('senderImagePath') == '/Library/GPUBundles/AdrenoMetal.bundle/Contents/MacOS/AdrenoMetal']
assert plugin_events and {row['senderImageUUID'] for row in plugin_events} == {uuid}
reason = 'Adreno draw: varying generated(9color_linDv4_Dh): no_perspective/center interpolation is not built'
exceptions = [row for row in rows if row.get('processImagePath', '').endswith('/WindowServer')
    and 'Terminating app due to uncaught exception' in row.get('eventMessage', '')]
assert len(exceptions) == 6 and len({row['processID'] for row in exceptions}) == 6
for row in exceptions:
    timestamp = datetime.strptime(row['timestamp'], '%Y-%m-%d %H:%M:%S.%f%z').timestamp()
    assert launch['started'] <= timestamp <= launch['finished']
    assert "'NSInvalidArgumentException'" in row['eventMessage'] and reason in row['eventMessage']
capture_path = bind(PIPE / 'build/ca-renderer-image-vpc-20260928-v1.json',
    '65830b61f4e8e4288a520d07595b4d862576dfd4081cb1a0972a874727284cbf')
capture = json.loads(capture_path.read_text())
fragment = capture['programs'][0]['fragment']
fragment_path = bind(fragment['path'], fragment['sha256'])
assert 'no_perspective' in fragment_path.read_text() and 'color_lin' in fragment_path.read_text()
proof_path = bind(PIPE / 'build/ca-vpc-a16-verified-gen58-20260928-v1/verification.json',
    '8d95a910aedce77fb31710799e0882e0a1c8b0d32b1eacfbf709e0c5d0995c2e')
proof = json.loads(proof_path.read_text())
assert proof['status'] == 'A16_CA_FRAME_EXACT' and not proof['desktop_verified']
source = PIPE / 'gpu/adreno-kext/plugin/AdrenoMetal/AdrenoDrawCommands.m'
for part in source_files(source):
    bind(part)
assert '![var[@"interp"] isEqual:@"no_perspective"]' in read_source(source)
bind(__file__)
output = args.output.resolve()
assert not output.exists()
record = dict(status='GEN57_WINDOWSERVER_EXCEPTION_IDENTIFIED', inputs_sha256=inputs,
    generation=57, boot_uuid=boot, old_plugin_sha256=sha(old_binary), old_plugin_uuid=uuid,
    exception='NSInvalidArgumentException', reason=reason,
    persisted_exception_count=6, console_crash_count=7,
    events=[{k:row[k] for k in ('timestamp', 'bootUUID', 'processID', 'processImagePath', 'eventMessage')} for row in exceptions],
    candidate_plugin_sha256=capture['plugin_sha256'], candidate_compiler_sha256=capture['compiler_sha256'],
    candidate_support_present=True, physical_ca_pixels_exact=proof['pixels']['total'],
    guest_fix_verified=False, desktop_verified=False,
    boundary='Six persisted WindowServer exceptions match the gen57 launch period and exact installed plug-in UUID. One console crash lacks a persisted exception here. Candidate supports the rejected mode and has physical offscreen CA proof; guest fix awaits the new boot.')
output.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(status=record['status'], output=str(output), sha256=sha(output))))
