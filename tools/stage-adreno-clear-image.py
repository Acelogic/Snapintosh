#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the bound clear deployment in an inspected local COW clone, never SSD."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import plistlib
import shutil
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
JOB = 'private/var/db/ManagedConfigurationFiles/BackgroundTaskServices/LaunchDaemons/org.snapintosh.metal-probe.plist'
UUID = '501065D4-E49E-4DDA-B4E7-056CA04D4B90'


def signature(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def plist(*argv):
    return plistlib.loads(subprocess.check_output(argv))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--deployment', type=Path, required=True)
    ap.add_argument('--snapshot', type=Path, required=True)
    ap.add_argument('--inspection', type=Path, required=True)
    ap.add_argument('--generation', type=int, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args()
    helper_path = ROOT / 'tools/qualify-adreno-clear-components.py'
    spec = importlib.util.spec_from_file_location('components', helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    deployment_path = args.deployment.resolve()
    deployment = helper.verify(deployment_path, ROOT)
    assert deployment['status'] == 'CLEAR_DEPLOYMENT_STAGED_NOT_INSTALLED'
    snapshot_path, inspection_path = args.snapshot.resolve(), args.inspection.resolve()
    snapshot = json.loads(snapshot_path.read_text())
    inspection = json.loads(inspection_path.read_text())
    assert snapshot['result'] == 'PASS' and snapshot['generation'] == args.generation
    assert snapshot['completed_bytes'] == snapshot['container_bytes'] == 62826479616
    assert snapshot['image_offset'] == 524308480
    assert snapshot['edges_unchanged'] and snapshot['checkpoints_unchanged']
    assert not any(snapshot['serror'].values())
    assert inspection['status'] == 'READ_ONLY_REPORT_INSPECTION_COMPLETE'
    assert inspection['snapshot_sha256'] == sha(snapshot_path)
    assert inspection['image_stat'] == inspection['image_stat_after']
    assert inspection['detach'] and all(x['exit_code'] == 0 for x in inspection['detach'])
    seed = Path(snapshot['image']).resolve()
    assert seed == Path(inspection['image']).resolve()
    assert signature(seed) == inspection['image_stat_after'] and seed.stat().st_size == 64 << 30
    out = args.output.resolve()
    assert not out.exists()
    assert not any(Path(x.get('image-path', '/')).resolve() == seed
                   for x in plist('hdiutil', 'info', '-plist').get('images', []))
    old_files = {x['path']: x for x in inspection['files'] if 'sha256' in x}
    assert old_files and all(x['matches'] for x in old_files.values())
    assert inspection['launch_job']['Label'] == 'org.snapintosh.metal-probe'
    job = plistlib.loads((deployment_path.parent / 'org.snapintosh.metal-probe.plist').read_bytes())
    assert job['Label'] == 'org.snapintosh.metal-probe' and job['RunAtLoad'] and not job.get('KeepAlive')
    assert job['ProgramArguments'] == ['/Library/Snapintosh/metal-clear-probe', '--report-base',
                                     '/var/db/Snapintosh/metal-clear-probe', '--wait', '600']
    installs = deployment['installs']
    expected = {'Library/GPUBundles/AdrenoMetal.bundle/Contents/' + n for n in
                ('Info.plist', 'MacOS/AdrenoMetal', '_CodeSignature/CodeResources')}
    expected |= {'Library/Snapintosh/metal-clear-probe', JOB}
    assert len(installs) == 5 and {x['destination'].lstrip('/') for x in installs} == expected
    for item in installs:
        src = deployment_path.parent / item['source']
        assert src.is_file() and not src.is_symlink() and sha(src) == item['sha256']
    inputs = {str(p): sha(p) for p in (Path(__file__), helper_path, deployment_path, snapshot_path, inspection_path)}
    record = dict(status='READY', started=time.time(), generation=args.generation,
        source_sha256=sha(Path(__file__)), inputs_sha256=inputs,
        snapshot_sha256=sha(snapshot_path), inspection_sha256=sha(inspection_path),
        deployment_sha256=sha(deployment_path), seed=str(seed), seed_stat=signature(seed),
        image=str(out / 'staged.img'), ssd_writes=False, mounts=[], files=[], detach=[])
    if args.check:
        print(json.dumps(dict(status='LOCAL_STAGE_INPUTS_VALIDATED', generation=args.generation,
                              snapshot_sha256=sha(snapshot_path), ssd_writes=False)))
        return
    assert os.geteuid() == 0, 'administrator authentication required for actual guest ownership'
    out.mkdir(parents=True)
    image, mountroot = out / 'staged.img', out / 'mounted'
    subprocess.run(['cp', '-c', str(seed), str(image)], check=True)
    os.chmod(image, 0o644)
    mountroot.mkdir()
    devices = []
    try:
        raw = subprocess.check_output(['hdiutil', 'attach', '-nobrowse', '-owners', 'on',
                                      '-mountroot', str(mountroot), '-plist', str(image)])
        (out / 'attach.plist').write_bytes(raw)
        entities = plistlib.loads(raw)['system-entities']
        devices.append(next(e['dev-entry'] for e in entities if e.get('dev-entry')))
        candidates = []
        nodes = {e.get('dev-entry') for e in entities}
        for e in entities:
            if 'mount-point' not in e:
                continue
            point = Path(e['mount-point'])
            assert point.is_relative_to(mountroot)
            info = plist('diskutil', 'info', '-plist', str(point))
            record['mounts'].append(dict(path=str(point), device=e['dev-entry'], uuid=info.get('VolumeUUID')))
            if info.get('VolumeUUID') == UUID:
                assert info['WritableVolume'] and info['GlobalPermissionsEnabled']
                assert info['DeviceNode'] in nodes
                candidates.append((point, info))
        assert len(candidates) == 1
        data, info = candidates[0]
        containers = plist('diskutil', 'apfs', 'list', '-plist')['Containers']
        container, = [x for x in containers if x['ContainerReference'] == info['APFSContainerReference']]
        assert container['APFSContainerUUID'] == '3404F471-EA91-4F23-B2A5-B21455330A5F'
        assert container['CapacityCeiling'] == snapshot['container_bytes']
        store, = container['PhysicalStores']
        assert '/dev/' + store['DeviceIdentifier'] in nodes
        assert store['DiskUUID'] == '1760DD8E-36AB-4591-B606-F92D75FF4115'
        def safe(relative):
            path = data
            for part in Path(relative).parts:
                assert part not in ('/', '.', '..')
                path /= part
                assert not path.is_symlink(), relative
            assert path.resolve().is_relative_to(data.resolve())
            return path
        for name, old in old_files.items():
            file = safe(name)
            assert file.is_file() and sha(file) == old['sha256'], name
        assert plistlib.loads(safe(JOB).read_bytes()) == inspection['launch_job']
        assert not safe('Library/Snapintosh/metal-clear-probe').exists()
        for item in installs:
            relative = item['destination'].lstrip('/')
            target = safe(relative)
            for parent in [target.parent, *target.parent.parents]:
                if parent == data:
                    break
                assert parent.is_dir() and not parent.is_symlink()
                identity = (parent.stat().st_uid, parent.stat().st_gid, stat.S_IMODE(parent.stat().st_mode))
                expected_owner = (277, 277, 0o755) if str(parent.relative_to(data)) == 'private/var/db/ManagedConfigurationFiles' else (0, 0, 0o755)
                assert identity == expected_owner, (parent, identity, expected_owner)
            mode = 0o755 if target.name in ('AdrenoMetal', 'metal-clear-probe') else 0o644
            before = dict(sha256=sha(target), mode=oct(stat.S_IMODE(target.stat().st_mode)),
                          uid=target.stat().st_uid, gid=target.stat().st_gid) if target.exists() else None
            with (deployment_path.parent / item['source']).open('rb') as src, target.open('wb' if before else 'xb') as dst:
                shutil.copyfileobj(src, dst)
                dst.flush()
                os.fsync(dst.fileno())
            os.chown(target, 0, 0)
            os.chmod(target, mode)
            assert sha(target) == item['sha256']
            assert (target.stat().st_uid, target.stat().st_gid, stat.S_IMODE(target.stat().st_mode)) == (0, 0, mode)
            record['files'].append(dict(path=relative, before=before, sha256=sha(target), uid=0, gid=0, mode=oct(mode)))
        for row in deployment['trust_rows']:
            path = safe('Library/GPUBundles/AdrenoMetal.bundle' if row['name'] == 'AdrenoMetal' else 'Library/Snapintosh/metal-clear-probe')
            subprocess.run(['codesign', '--verify', '--strict', str(path)], check=True)
            signed = subprocess.run(['codesign', '-dvvv', str(path)], capture_output=True, text=True, check=True)
            assert 'CDHash=' + row['cdhash'] + '\n' in signed.stderr
        assert plistlib.loads(safe(JOB).read_bytes()) == job
        assert sha(safe('Library/Snapintosh/metal-probe')) == old_files['Library/Snapintosh/metal-probe']['sha256']
        for name, digest in inputs.items(): assert sha(Path(name)) == digest
        helper.verify(deployment_path, ROOT)
        subprocess.run(['sync'], check=True)
        record['status'] = 'CLEAR_FILES_STAGED_LOCAL_ONLY'
    except BaseException as error:
        record.update(status='FAIL', exception=repr(error))
        raise
    finally:
        for device in reversed(devices):
            result = subprocess.run(['hdiutil', 'detach', device], capture_output=True, text=True)
            record['detach'].append(dict(device=device, exit_code=result.returncode, output=result.stdout + result.stderr))
            if result.returncode: record['status'] = 'FAIL'
        record['seed_stat_after'] = signature(seed)
        if record['seed_stat'] != record['seed_stat_after']: record['status'] = 'FAIL'
        for path in (image, out / 'attach.plist', mountroot, out):
            if path.exists(): os.chown(path, ROOT.stat().st_uid, ROOT.stat().st_gid)
        record.update(image_stat=signature(image), finished=time.time())
        report = out / 'stage.json'
        report.write_text(json.dumps(record, indent=2) + '\n')
        os.chown(report, ROOT.stat().st_uid, ROOT.stat().st_gid)
    assert record['status'] == 'CLEAR_FILES_STAGED_LOCAL_ONLY'
    print(json.dumps(dict(status=record['status'], files=len(record['files']), report=str(out / 'stage.json'))))


if __name__ == '__main__':
    main()
