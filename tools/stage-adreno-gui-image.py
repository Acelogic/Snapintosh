#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the shader/display deployment in a verified local COW clone, never SSD."""
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
BUNDLE = 'Library/GPUBundles/AdrenoMetal.bundle'
FRAMEWORKS = BUNDLE+'/Contents/Frameworks'
TRIANGLE = 'Library/Snapintosh/metal-triangle-probe'
UUID = '501065D4-E49E-4DDA-B4E7-056CA04D4B90'


def signature(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def identity(path):
    s = path.stat()
    return dict(uid=s.st_uid, gid=s.st_gid, mode=oct(stat.S_IMODE(s.st_mode)), inode=s.st_ino, links=s.st_nlink)


def plist(*argv):
    return plistlib.loads(subprocess.check_output(argv))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('deployment', 'snapshot', 'inspection', 'output'):
        ap.add_argument('--'+name, type=Path, required=True)
    ap.add_argument('--generation', type=int, required=True)
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args()
    helper_path = ROOT/'tools/prepare-adreno-gui-deployment.py'
    spec = importlib.util.spec_from_file_location('deployment', helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    deployment_path, snapshot_path, inspection_path = [p.resolve() for p in
        (args.deployment, args.snapshot, args.inspection)]
    deployment = helper.verify(deployment_path)
    assert deployment['status'] == 'SHADER_DISPLAY_DEPLOYMENT_STAGED_NOT_INSTALLED'
    snapshot, inspection = [json.loads(p.read_text()) for p in (snapshot_path, inspection_path)]
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
    job = plistlib.loads((deployment_path.parent/'org.snapintosh.metal-probe.plist').read_bytes())
    assert job['Label'] == inspection['launch_job']['Label'] == 'org.snapintosh.metal-probe'
    assert job['RunAtLoad'] and not job.get('KeepAlive')
    assert job['ProgramArguments'] == ['/'+TRIANGLE, '--report-base',
        '/var/db/Snapintosh/metal-triangle-probe', '--wait', '600', '--present', '--hold', '3600']
    installs = deployment['installs']
    expected = {BUNDLE+'/Contents/'+n for n in ('Info.plist', 'MacOS/AdrenoMetal',
        '_CodeSignature/CodeResources', 'Frameworks/libAdrenoCompiler.dylib')} | {TRIANGLE, JOB}
    assert len(installs) == 6 and {i['destination'].lstrip('/') for i in installs} == expected
    for item in installs:
        src = deployment_path.parent/item['source']
        assert src.is_file() and not src.is_symlink() and sha(src) == item['sha256']
    inputs = {str(p): sha(p) for p in (Path(__file__), helper_path, deployment_path, snapshot_path, inspection_path)}
    if args.check:
        print(json.dumps(dict(status='GUI_LOCAL_STAGE_INPUTS_VALIDATED', inputs_sha256=inputs, ssd_writes=False)))
        return
    assert os.geteuid() == 0, 'local image staging requires administrator authentication for new root-owned files'
    out.mkdir(parents=True)
    image, mountroot = out/'staged.img', out/'mounted'
    subprocess.run(['cp', '-c', str(seed), str(image)], check=True)
    os.chmod(image, 0o644)
    mountroot.mkdir()
    record = dict(status='RUNNING', started=time.time(), generation=args.generation,
        inputs_sha256=inputs, source_sha256=sha(Path(__file__)), snapshot_sha256=sha(snapshot_path),
        inspection_sha256=sha(inspection_path), deployment_sha256=sha(deployment_path),
        seed=str(seed), seed_stat=signature(seed), image=str(image), ssd_writes=False,
        mounts=[], files=[], detach=[], created_directories=[], checked_jobs=[])
    devices = []
    try:
        raw = subprocess.check_output(['hdiutil', 'attach', '-nobrowse', '-owners', 'on',
                                      '-mountroot', str(mountroot), '-plist', str(image)])
        (out/'attach.plist').write_bytes(raw)
        entities = plistlib.loads(raw)['system-entities']
        devices.append(next(e['dev-entry'] for e in entities if e.get('dev-entry')))
        nodes = {e.get('dev-entry') for e in entities}
        candidates = []
        for e in entities:
            if 'mount-point' not in e: continue
            point = Path(e['mount-point'])
            assert point.is_relative_to(mountroot)
            info = plist('diskutil', 'info', '-plist', str(point))
            record['mounts'].append(dict(path=str(point), device=e['dev-entry'], uuid=info.get('VolumeUUID')))
            if info.get('VolumeUUID') == UUID:
                assert info['WritableVolume'] and info['GlobalPermissionsEnabled'] and info['DeviceNode'] in nodes
                candidates.append((point, info))
        data, info = candidates[0] if len(candidates) == 1 else (None, None)
        assert data is not None
        container, = [x for x in plist('diskutil', 'apfs', 'list', '-plist')['Containers']
            if x['ContainerReference'] == info['APFSContainerReference']]
        assert container['APFSContainerUUID'] == '3404F471-EA91-4F23-B2A5-B21455330A5F'
        assert container['CapacityCeiling'] == snapshot['container_bytes']
        store, = container['PhysicalStores']
        assert '/dev/'+store['DeviceIdentifier'] in nodes and store['DiskUUID'] == '1760DD8E-36AB-4591-B606-F92D75FF4115'
        def safe(relative):
            p = data
            for part in Path(relative).parts:
                assert part not in ('/', '.', '..')
                p /= part
                assert not p.is_symlink(), relative
            assert p.resolve().is_relative_to(data.resolve())
            return p
        for name, old in old_files.items(): assert sha(safe(name)) == old['sha256'], name
        assert plistlib.loads(safe(JOB).read_bytes()) == inspection['launch_job']
        assert not safe(TRIANGLE).exists() and not safe(FRAMEWORKS).exists()
        for directory in ('Library/LaunchDaemons', str(Path(JOB).parent)):
            d = safe(directory)
            if not d.exists(): continue
            for p in d.glob('*.plist'):
                assert not p.is_symlink()
                if str(p.relative_to(data)) == JOB: continue
                values = plistlib.loads(p.read_bytes())
                argv = [values.get('Program', ''), *values.get('ProgramArguments', [])]
                assert not any('display-probe' in str(x) or 'metal-triangle-probe' in str(x)
                               or 'metal-clear-probe' in str(x) for x in argv), str(p)
                record['checked_jobs'].append(str(p.relative_to(data)))
        newdir = safe(FRAMEWORKS)
        newdir.mkdir(mode=0o755)
        os.chown(newdir, 0, 0)
        record['created_directories'].append(dict(path=FRAMEWORKS, **identity(newdir)))
        for item in installs:
            name = item['destination'].lstrip('/')
            target = safe(name)
            for parent in target.parents:
                if parent == data: break
                assert parent.is_dir() and not parent.is_symlink()
                ident = identity(parent)
                owner = (277, 277) if str(parent.relative_to(data)) == 'private/var/db/ManagedConfigurationFiles' else (0, 0)
                assert (ident['uid'], ident['gid'], ident['mode']) == (*owner, '0o755'), str(parent)
            mode = 0o755 if target.name in ('AdrenoMetal', 'metal-triangle-probe', 'libAdrenoCompiler.dylib') else 0o644
            before = dict(**identity(target), sha256=sha(target)) if target.exists() else None
            if before: assert before['links'] == 1 and before['uid'] == before['gid'] == 0
            with (deployment_path.parent/item['source']).open('rb') as src, target.open('wb' if before else 'xb') as dst:
                shutil.copyfileobj(src, dst)
                dst.flush()
                os.fsync(dst.fileno())
            os.chown(target, 0, 0)
            os.chmod(target, mode)
            assert sha(target) == item['sha256']
            ident = identity(target)
            assert (ident['uid'], ident['gid'], ident['mode'], ident['links']) == (0, 0, oct(mode), 1)
            if before: assert ident['inode'] == before['inode']
            record['files'].append(dict(path=name, before=before, sha256=sha(target), **ident))
        trust_paths = {'AdrenoMetal': BUNDLE, 'metal-triangle-probe': TRIANGLE,
                       'libAdrenoCompiler.dylib': FRAMEWORKS+'/libAdrenoCompiler.dylib'}
        assert {r['name'] for r in deployment['trust_rows']} == set(trust_paths)
        for row in deployment['trust_rows']:
            p = safe(trust_paths[row['name']])
            subprocess.run(['codesign', '--verify', '--strict', str(p)], check=True)
            signed = subprocess.run(['codesign', '-dvvv', str(p)], capture_output=True, text=True, check=True)
            assert 'CDHash='+row['cdhash']+'\n' in signed.stderr
        assert plistlib.loads(safe(JOB).read_bytes()) == job
        for name, old in old_files.items():
            if name not in expected: assert sha(safe(name)) == old['sha256']
        for name, value in inputs.items(): assert sha(Path(name)) == value
        helper.verify(deployment_path)
        subprocess.run(['sync'], check=True)
        record['status'] = 'SHADER_DISPLAY_FILES_STAGED_LOCAL_ONLY'
    except BaseException as error:
        record.update(status='FAIL', exception=repr(error))
        raise
    finally:
        for device in reversed(devices):
            proc = subprocess.run(['hdiutil', 'detach', device], capture_output=True, text=True)
            record['detach'].append(dict(device=device, exit_code=proc.returncode, output=proc.stdout+proc.stderr))
            if proc.returncode: record['status'] = 'FAIL'
        record['seed_stat_after'] = signature(seed)
        if record['seed_stat_after'] != record['seed_stat']: record['status'] = 'FAIL'
        for p in (image, out/'attach.plist', mountroot, out):
            if p.exists(): os.chown(p, ROOT.stat().st_uid, ROOT.stat().st_gid)
        record.update(image_stat=signature(image), finished=time.time())
        report = out/'stage.json'
        report.write_text(json.dumps(record, indent=2)+'\n')
        os.chown(report, ROOT.stat().st_uid, ROOT.stat().st_gid)
    assert record['status'] == 'SHADER_DISPLAY_FILES_STAGED_LOCAL_ONLY'
    print(json.dumps(dict(status=record['status'], files=len(record['files']), report=str(report))))


if __name__ == '__main__':
    main()
