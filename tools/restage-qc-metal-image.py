#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replace six installed files in a clone using verified ownership preservation.

No password or root process: update existing inodes with ownership disabled on
the local clone, then remount read-only with ownership enforced and recheck
every inode, owner, mode, parent, signed payload and CDHash. Never creates files.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT.parent / 'Snapintosh-adreno-resource-map/tools/restage-adreno-clear-image.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == 'f1a78ca0ae15eb52f5047b7eebfd38965808d83dc4149f3d62b29325cf884311'
source = base.read_text()
changes = {
    "helper_path=ROOT/'tools/qualify-adreno-clear-components.py'": "helper_path=ROOT/'tools/prepare-adreno-gui-deployment.py'",
    'helper.verify(deployment_path,ROOT)': 'helper.verify(deployment_path)',
    'CLEAR_DEPLOYMENT_STAGED_NOT_INSTALLED': 'SHADER_DISPLAY_DEPLOYMENT_STAGED_NOT_INSTALLED',
    'CLEAR_FILES_STAGED_LOCAL_ONLY': 'SHADER_DISPLAY_FILES_STAGED_LOCAL_ONLY',
    'len(items)==5': 'len(items)==6',
    "('AdrenoMetal','metal-clear-probe')": "('AdrenoMetal','metal-triangle-probe','libAdrenoCompiler.dylib')",
    "name='Library/GPUBundles/AdrenoMetal.bundle' if row['name']=='AdrenoMetal' else 'Library/Snapintosh/metal-clear-probe'":
        "name={'AdrenoMetal':'Library/GPUBundles/AdrenoMetal.bundle','metal-triangle-probe':'Library/Snapintosh/metal-triangle-probe','libAdrenoCompiler.dylib':'Library/GPUBundles/AdrenoMetal.bundle/Contents/Frameworks/libAdrenoCompiler.dylib'}[row['name']]",
    "        with mounted('update','off',False) as data:":
        "        assert plistlib.loads((deployment_path.parent/'org.snapintosh.metal-probe.plist').read_bytes()) == inspection['launch_job']\n        with mounted('update','off',False) as data:",
}
for old, new in changes.items():
    assert source.count(old) == (2 if old == 'helper.verify(deployment_path,ROOT)' else 1), old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
