#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the installed plug-in tree and WindowServer's cache folders from an SSD snapshot.

Answers two deployment questions for the shader-cache plug-in
(docs/SHADER-COMPILE-PATH-20260928.md): does
/Library/GPUBundles/AdrenoMetal.bundle/Contents/Resources exist, and who owns
_windowserver's (uid 88) per-user cache folders and Metal's cache files.

Same guards as the main checkout's tools/inspect-gen61-logs.py: refuse an image
that is already attached, attach it -readonly -nomount, mount only the Data
volume read-only and nobrowse, never follow symlinks, detach, and require the
image's stat to be unchanged. Ownership is enforced on this read-only mount
(like restage's read-only verify mount) so uid/gid are the guest's. Host
records only; no A16 access and no write to the image.
"""
from pathlib import Path
import argparse
import hashlib
import json
import plistlib
import stat
import subprocess
import time

CONTAINER = '3404F471-EA91-4F23-B2A5-B21455330A5F'
DATA = '501065D4-E49E-4DDA-B4E7-056CA04D4B90'
WINDOWSERVER = 'private/var/folders/zz/zyxvpxvq6csfxvn_n00000b000002r'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
signature = lambda p: [p.stat().st_dev, p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ctime_ns]
plist = lambda *argv: plistlib.loads(subprocess.check_output(argv))


def entry(root, path, digest=True, head=0):
    s = path.lstat()
    kind = 'link' if stat.S_ISLNK(s.st_mode) else 'dir' if stat.S_ISDIR(s.st_mode) else 'file' if stat.S_ISREG(s.st_mode) else 'other'
    row = dict(path=str(path.relative_to(root)), kind=kind, uid=s.st_uid, gid=s.st_gid, mode=oct(stat.S_IMODE(s.st_mode)))
    if kind == 'file':
        row['bytes'] = s.st_size
        if digest and s.st_size <= 256 << 20:
            row['sha256'] = sha(path)
        if head:
            with path.open('rb') as f:
                row['head_hex'] = f.read(head).hex()
    return row


def walk(root, top, depth, **kw):
    rows = []
    try:
        if not top.exists() and not top.is_symlink():
            return rows
        rows.append(entry(root, top, **kw))
        if depth and top.is_dir() and not top.is_symlink():
            for child in sorted(top.iterdir()):
                rows += walk(root, child, depth - 1, **kw)
    except PermissionError as error:      # a guest folder this host user may not enter
        rows.append(dict(path=str(top.relative_to(root)), unreadable=error.strerror))
    return rows


def mounted(image, mount, owners, work):
    """Attach read-only, mount the Data volume read-only (owners on or off), run work(mount), detach."""
    device, result = None, {}
    try:
        raw = subprocess.check_output(['hdiutil', 'attach', '-nomount', '-readonly', '-plist', str(image)])
        entities = plistlib.loads(raw)['system-entities']
        device = next(e['dev-entry'] for e in entities if e.get('dev-entry'))
        nodes = {e.get('dev-entry') for e in entities}
        container, = [c for c in plist('diskutil', 'apfs', 'list', '-plist')['Containers']
                      if c['APFSContainerUUID'] == CONTAINER
                      and any('/dev/' + s['DeviceIdentifier'] in nodes for s in c['PhysicalStores'])]
        volume, = [v for v in container['Volumes'] if v['APFSVolumeUUID'] == DATA]
        mount.mkdir()
        subprocess.run(['diskutil', 'mount', 'readOnly', 'nobrowse', '-mountOptions', 'owners' if owners else 'noowners',
                        '-mountPoint', str(mount), volume['DeviceIdentifier']], check=True, capture_output=True)
        info = plist('diskutil', 'info', '-plist', str(mount))
        assert not info['WritableVolume'] and info['GlobalPermissionsEnabled'] == owners
        assert info['VolumeUUID'] == DATA
        result = dict(device=volume['DeviceIdentifier'], readonly=True, owners=owners, **work(mount))
    finally:
        if device:
            detached = subprocess.run(['hdiutil', 'detach', device], capture_output=True, text=True)
            result['detach'] = dict(exit_code=detached.returncode, output=detached.stdout + detached.stderr)
            assert detached.returncode == 0, 'detach failed'
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--image', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    image = args.image.resolve()
    assert image.stat().st_size == 64 << 30
    assert not any(Path(v.get('image-path', '/')).resolve() == image for v in plist('hdiutil', 'info', '-plist').get('images', []))
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    before = signature(image)
    record = dict(status='RUNNING', started=time.time(), source_sha256=sha(__file__), image=str(image),
                  image_stat=before, hardware_access=False, image_writes=False)

    def owned(mount):
        """Owners enforced: the guest's uid/gid/mode, where this host user may look."""
        bundle = mount / 'Library/GPUBundles/AdrenoMetal.bundle'
        ws = mount / WINDOWSERVER
        return dict(bundle=walk(mount, bundle, 4), bundle_resources_exists=(bundle / 'Contents/Resources').is_dir(),
                    gpubundles=walk(mount, mount / 'Library/GPUBundles', 1, digest=False),
                    windowserver_folders=walk(mount, ws, 1, digest=False),
                    folders_zz=walk(mount, mount / 'private/var/folders/zz', 1, digest=False))

    def listed(mount):
        """Ownership ignored (as inspect-gen61-logs.py mounts): names, sizes and file headers inside
        _windowserver's 0700 folders; uid/gid read here are not the guest's."""
        ws = mount / WINDOWSERVER / 'C'
        return dict(windowserver_cache_exists=ws.is_dir(),
                    windowserver_cache=walk(mount, ws, 1, digest=False),
                    windowserver_metal_cache=walk(mount, ws / 'com.apple.metal', 3, head=40),
                    windowserver_metalfe_cache=walk(mount, ws / 'com.apple.metalfe', 2, digest=False),
                    windowserver_adreno_cache_exists=(ws / 'org.snapintosh.AdrenoMetal').exists())
    try:
        record['owners_pass'] = mounted(image, out / 'owners', True, owned)
        record['contents_pass'] = mounted(image, out / 'contents', False, listed)
        record['status'] = 'INSPECTED'
    except BaseException as error:
        record.update(status='FAILED', error=repr(error))
        raise
    finally:
        record['image_stat_after'] = signature(image)
        record['image_unchanged'] = record['image_stat_after'] == before
        record['finished'] = time.time()
        (out / 'inspection.json').write_text(json.dumps(record, indent=2) + '\n')
    assert record['status'] == 'INSPECTED' and record['image_unchanged']
    print(json.dumps(dict(status=record['status'], resources=record['owners_pass']['bundle_resources_exists'],
                          windowserver_cache=record['contents_pass']['windowserver_cache_exists'],
                          output=str(out / 'inspection.json'), sha256=sha(out / 'inspection.json'))))


if __name__ == '__main__':
    main()
