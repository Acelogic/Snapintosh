#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy one run's crash reports and unified logs from its SSD snapshot, decode
only that run's boot, and print its startup timeline.

    python3 tools/inspect-logs.py --prefix PREFIX [--all-boots]

Input is the snapshot `cycle.py storage --prefix PREFIX snapshot` wrote
(build/PREFIX-snapshot-v1/snapshot.json) and the run's build/PREFIX-launch.json.
Output goes to a new build/PREFIX-logs/logs-vN/: reports/, guest.logarchive/,
boot.ndjson (all.ndjson with --all-boots), timeline.json and inspection.json.
Minutes are counted from the boot's first kernel event on the guest's 24 MHz
timebase, which also dates kernel events logged before the wall clock was set.

Failure inventory: wrong snapshot, writable mount, symlink traversal, unbounded
archive, altered raw logs, decoder failure hidden as no events, incomplete
detach, a decoded boot that is not this run's (it must start inside the launch
window), and a timebase that disagrees with the wall clock. Only host copies are
written. No A16 access and no change to the snapshot image.
"""
from datetime import datetime
from pathlib import Path
import argparse
import hashlib
import json
import plistlib
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'build/ca-logarchive-info-20260928'
TOOL_COMMIT = 'ceebafe6df25bf70f288cff22bc226380c17a69f'
CONTAINER_UUID = '3404F471-EA91-4F23-B2A5-B21455330A5F'
DATA_VOLUME_UUID = '501065D4-E49E-4DDA-B4E7-056CA04D4B90'
LIMIT = 1 << 30
TIMEBASE = 24_000_000
CLOCK_TOLERANCE = 5.0     # seconds of wall-minus-timebase spread allowed across user events
LAUNCH_SLACK = 300        # the guest wall clock comes from our RTC model

# (label, process image basename or None for any, pattern). The first three
# matches of each are reported; order is the order of a normal boot.
MILESTONES = [
    ('kernel start', 'kernel', r'^Darwin Kernel Version'),
    ('userspace boot', 'kernel', r'^userspace boot'),
    ('WindowServer spawned', 'launchd', r'Successfully spawned WindowServer\['),
    ('loginwindow spawned', 'launchd', r'Successfully spawned loginwindow\['),
    ('kernelmanagerd starts', 'kernelmanagerd', r'Starting userland kernel management'),
    ('WindowServer asks for the TimeSync clock', 'WindowServer', r'name=com\.apple\.timesync\.expositor'),
    ('IOKit quiesce timeout', None, r'timed out waiting for IOKit to quiesce'),
    ('AuxKC activation', 'kernelmanagerd', r'performing auxiliary activation'),
    ('AuxKC loaded', 'kernel', r'Adding kexts from in-memory AuxKC'),
    ('IOGPU start', 'kernel', r'IOGPU::start'),
    ('en0 attached', 'kernel', r'^en0: attached'),
    ('clock available', 'clocksyncd', r'clock manager is available'),
    ('AdrenoMTLDevice up', None, r'AdrenoMTLDevice up'),
    ('early stop armed', None, r'early stop enabled'),
    ('first present', None, r'^(?!.*early stop enabled).*(first (successful )?present|AdrenoEarlyStopPresented)'),
    ('early stop requested', None, r'reported for early stop|early stop request'),
    ('sandbox blocked an early-stop report', 'kernel', r'deny\(1\) iokit-set-properties .*AdrenoEarlyStop'),
    ('uncaught exception', None, r'Terminating app due to uncaught exception'),
    ('kernel assert', 'kernel', r'^Assert: '),
    ('panic', 'kernel', r'\bpanic\('),
]

sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
signature = lambda p: [p.stat().st_dev, p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ctime_ns]
plist = lambda *argv: plistlib.loads(subprocess.check_output(argv))
wall = lambda e: datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S.%f%z').timestamp()


def copy_logs(image, out, record):
    """Attach the snapshot read-only, copy reports and the log store, detach."""
    mount, archive = out / 'data', out / 'guest.logarchive'
    mount.mkdir()
    device = None
    try:
        raw = subprocess.check_output(['hdiutil', 'attach', '-nomount', '-readonly', '-plist', str(image)])
        (out / 'attach.plist').write_bytes(raw)
        entities = plistlib.loads(raw)['system-entities']
        device = next(e['dev-entry'] for e in entities if e.get('dev-entry'))
        nodes = {e.get('dev-entry') for e in entities}
        container, = [c for c in plist('diskutil', 'apfs', 'list', '-plist')['Containers']
                      if c['APFSContainerUUID'] == CONTAINER_UUID
                      and any('/dev/' + s['DeviceIdentifier'] in nodes for s in c['PhysicalStores'])]
        volume, = [v for v in container['Volumes'] if v['APFSVolumeUUID'] == DATA_VOLUME_UUID]
        subprocess.run(['diskutil', 'mount', 'readOnly', 'nobrowse', '-mountOptions', 'noowners',
                        '-mountPoint', str(mount), volume['DeviceIdentifier']], check=True, capture_output=True)
        info = plist('diskutil', 'info', '-plist', str(mount))
        assert not info['WritableVolume'] and not info['GlobalPermissionsEnabled']
        assert info['VolumeUUID'] == DATA_VOLUME_UUID
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
                dest = out / 'reports' / relative / path.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dest)
                assert sha(path) == sha(dest)
                record['reports'].append(dict(path=str(path.relative_to(mount)), bytes=path.stat().st_size,
                                              mtime_ns=path.stat().st_mtime_ns, sha256=sha(dest)))
        total = 0
        for relative in ('private/var/db/diagnostics', 'private/var/db/uuidtext'):
            origin = mount / relative
            assert origin.is_dir() and origin.resolve().is_relative_to(mount.resolve()), relative
            for path in sorted(origin.rglob('*')):
                assert not path.is_symlink(), path
                if not path.is_file():
                    continue
                total += path.stat().st_size
                assert total <= LIMIT and len(record['archive_files']) < 40000, 'bounded archive limit'
                dest = archive / path.relative_to(origin)
                assert not dest.exists(), dest
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dest)
                assert sha(path) == sha(dest)
                record['archive_files'].append(dict(path=str(dest.relative_to(archive)), sha256=sha(dest)))
        record['archive_bytes'] = total
        record['status'] = 'COPIED'
    finally:
        if device:
            detached = subprocess.run(['hdiutil', 'detach', device], capture_output=True, text=True)
            record['detach'] = dict(exit_code=detached.returncode, output=detached.stdout + detached.stderr)
            if detached.returncode:
                record['status'] = 'FAILED_DETACH'
    return archive


def timeline(events, launch):
    """Milestones of one boot, in minutes after its first kernel event."""
    boots = {e.get('bootUUID') for e in events}
    assert len(boots) == 1, f'expected one boot, decoded {len(boots)}'
    marker = next((e for e in events if (e.get('eventMessage') or '').startswith('=== system boot:')), None)
    assert marker, 'no system boot marker in the decoded boot'
    booted = wall(marker)
    assert launch['started'] - LAUNCH_SLACK <= booted <= launch['finished'], \
        'the decoded boot did not start inside this run\'s launch window'
    k0 = min(e['machTimestamp'] for e in events if e.get('machTimestamp', 0) > 0)
    offsets = sorted(wall(e) - (e['machTimestamp'] - k0) / TIMEBASE for e in events
                     if e.get('machTimestamp', 0) > 0 and not (e.get('processImagePath') or '').endswith('/kernel'))
    spread = offsets[int(len(offsets) * 0.99)] - offsets[int(len(offsets) * 0.01)] if offsets else None
    assert spread is not None and spread <= CLOCK_TOLERANCE, f'timebase disagrees with the wall clock ({spread} s)'
    minutes = lambda e: round((e['machTimestamp'] - k0) / TIMEBASE / 60, 2) if e.get('machTimestamp', 0) > 0 else None
    compiled = [(label, process, re.compile(pattern)) for label, process, pattern in MILESTONES]
    counts = {label: 0 for label, _, _ in MILESTONES}
    firsts = {label: [] for label, _, _ in MILESTONES}
    for e in events:
        message = e.get('eventMessage') or ''
        image = (e.get('processImagePath') or '').rsplit('/', 1)[-1]
        for label, process, pattern in compiled:
            if (process is None or image == process) and pattern.search(message):
                counts[label] += 1
                if len(firsts[label]) < 3:
                    firsts[label].append(dict(minutes=minutes(e), process=image, pid=e.get('processID'),
                                              message=message[:200].replace('\n', ' ')))
    found = {label: dict(count=counts[label], first=firsts[label]) for label, _, _ in MILESTONES}
    stamps = [m for m in map(minutes, events) if m is not None]
    last = max(stamps) if stamps else None
    return dict(boot_uuid=boots.pop(), boot_marker_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(booted)),
                events=len(events), timebase_hz=TIMEBASE, wall_minus_timebase_spread_seconds=round(spread, 3),
                last_event_minutes=last, milestones=found)


def main():
    parser = argparse.ArgumentParser(description='Decode one run\'s own boot from its SSD snapshot.')
    parser.add_argument('--prefix', required=True, help='the stopped run whose snapshot holds its logs')
    parser.add_argument('--snapshot', help='default: build/PREFIX-snapshot-v1/snapshot.json')
    parser.add_argument('--all-boots', action='store_true', help='decode every boot in the archive (slow, large)')
    args = parser.parse_args()
    snap = Path(args.snapshot) if args.snapshot else ROOT / f'build/{args.prefix}-snapshot-v1/snapshot.json'
    launch_path = ROOT / f'build/{args.prefix}-launch.json'
    snapshot, launch = json.loads(snap.read_text()), json.loads(launch_path.read_text())
    assert snapshot['result'] == 'PASS', 'snapshot did not pass'
    assert launch.get('finished', 0) > launch.get('started', 0), 'the launch has not finished'
    image = Path(snapshot['image']).resolve()
    assert image.stat().st_size == 64 << 30
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=TOOL, text=True).strip()
    assert commit == TOOL_COMMIT
    helper = TOOL / 'logarchive_info.py'
    assert helper.read_bytes() == subprocess.check_output(['git', 'show', 'HEAD:logarchive_info.py'], cwd=TOOL)
    assert not any(Path(v.get('image-path', '/')).resolve() == image
                   for v in plist('hdiutil', 'info', '-plist').get('images', []))
    base = ROOT / f'build/{args.prefix}-logs'
    version = 1
    while (base / f'logs-v{version}').exists():
        version += 1
    out = base / f'logs-v{version}'
    out.mkdir(parents=True)
    before = signature(image)
    result = None
    record = dict(status='RUNNING', started=time.time(), source_sha256=sha(__file__), prefix=args.prefix,
                  snapshot=str(snap), snapshot_sha256=sha(snap), snapshot_generation=snapshot.get('generation'),
                  launch_sha256=sha(launch_path), image=str(image), image_stat=before, helper_commit=commit,
                  hardware_access=False, image_writes=False, all_boots=args.all_boots, reports=[], archive_files=[])
    try:
        try:
            archive = copy_logs(image, out, record)
        finally:
            record['image_stat_after'] = signature(image)
            assert record['image_stat_after'] == before
        assert record['status'] == 'COPIED', record['status']
        for name in ('Persist', 'Special', 'Signpost', 'HighVolume', 'timesync'):
            (archive / name).mkdir(exist_ok=True)
        with (out / 'metadata.log').open('x') as log:
            built = subprocess.run([sys.executable, str(helper), str(archive)], stdout=log,
                                   stderr=subprocess.STDOUT, timeout=300)
        record['metadata_exit'] = built.returncode
        assert built.returncode == 0, 'metadata reconstruction failed'
        decoded_path = out / ('all.ndjson' if args.all_boots else 'boot.ndjson')
        command = ['/usr/bin/log', 'show', '--archive', str(archive), '--style', 'ndjson', '--info', '--debug']
        if not args.all_boots:
            command += ['--last', 'boot']
        with decoded_path.open('x') as stdout, (out / 'decoder.log').open('x') as stderr:
            decoded = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=1800)
        record.update(decoder_exit=decoded.returncode, command=command, output=str(decoded_path),
                      output_sha256=sha(decoded_path), output_bytes=decoded_path.stat().st_size)
        assert decoded.returncode == 0, 'log decoder did not complete'
        for entry in record['archive_files']:
            assert sha(archive / entry['path']) == entry['sha256']
        if not args.all_boots:
            events, trailer = [], None
            with decoded_path.open() as lines:
                for line in lines:
                    if line.startswith('{'):
                        item = json.loads(line)
                        if 'finished' in item and 'eventMessage' not in item:
                            trailer = item      # log show's closing {"count": N, "finished": 1}
                        else:
                            events.append(item)
            assert events, 'decoder produced no events'
            assert trailer and trailer.get('finished') == 1 and trailer.get('count') == len(events), \
                f'decoder trailer {trailer} does not confirm {len(events)} complete events'
            result = timeline(events, launch)
            (out / 'timeline.json').write_text(json.dumps(result, indent=2) + '\n')
            record['timeline_sha256'] = sha(out / 'timeline.json')
        record['status'] = 'LOGS_DECODED'
    except BaseException as error:
        record.update(status='FAILED' if record['status'] == 'RUNNING' else record['status'], error=repr(error))
        raise
    finally:
        record['finished'] = time.time()
        (out / 'inspection.json').write_text(json.dumps(record, indent=2) + '\n')
    if result:
        print(f"boot {result['boot_uuid']} at {result['boot_marker_utc']}, {result['events']} events, "
              f"last at {result['last_event_minutes']} min")
        seen = [(entry['first'][0], label, entry) for label, entry in result['milestones'].items() if entry['count']]
        for first, label, entry in sorted(seen, key=lambda row: (row[0]['minutes'] is None, row[0]['minutes'] or 0)):
            more = f" (x{entry['count']})" if entry['count'] > 1 else ''
            print(f"{first['minutes']:>7} min  {label}{more}: {first['process']}[{first['pid']}] {first['message'][:110]}")
    print(json.dumps(dict(status=record['status'], reports=len(record['reports']),
                          archive_files=len(record['archive_files']), output=str(out / 'inspection.json'))))


if __name__ == '__main__':
    main()
