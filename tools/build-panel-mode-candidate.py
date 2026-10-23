#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rebuild only AdrenoDisplay against the installed native-link object baseline."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / 'build/virtual-ethernet-clock-20260927/native-link-v3'
SOURCE = ROOT.parent / 'Snapintosh-adreno-clear'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve()
    assert not out.exists(), 'preserve previous candidate'
    baseline = json.loads((BASELINE / 'qualification.json').read_text())
    old_kext = BASELINE / 'AdrenoX2.kext'
    binary = 'Contents/MacOS/AdrenoX2'
    assert sha(old_kext / binary) == baseline['kext_sha256']
    objects = {k: v for k, v in baseline['artifacts_sha256'].items() if k.startswith('obj/') and k.endswith('.o')}
    assert len(objects) == 11, objects.keys()
    for name, expected in objects.items():
        assert sha(BASELINE / name) == expected, name
    source = SOURCE / 'gpu/adreno-kext/kext/src/AdrenoDisplay.cpp'
    inputs = {str(f): sha(f) for f in source_files(source)}      # the unit: AdrenoDisplay.cpp and its parts
    inputs[str(BASELINE / 'qualification.json')] = sha(BASELINE / 'qualification.json')
    for folder in ['gpu/adreno-kext/kext/src', 'gpu/adreno-kext/kext/include', 'gpu/adreno-kext/include']:
        for f in (SOURCE / folder).glob('*.h'):
            inputs[str(f)] = sha(f)
    out.mkdir(parents=True)
    (out / 'obj').mkdir()
    bundle = out / 'AdrenoX2.kext'
    shutil.copytree(old_kext, bundle)
    commands = []

    def run(cmd, log):
        commands.append(cmd)
        with (out / log).open('w') as stream:
            subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT, check=True)

    compile_cmd = list(next(c for c in baseline['commands'] if '-c' in c and 'clang++' in c))
    compile_cmd[compile_cmd.index('-c') + 1] = str(source)
    compile_cmd[compile_cmd.index('-o') + 1] = str(out / 'obj/AdrenoDisplay.o')
    compile_cmd += ['-I' + str(SOURCE / folder) for folder in
                    ['gpu/adreno-kext/kext/include', 'gpu/adreno-kext/include']]
    run(compile_cmd, 'compile.log')
    link = list(next(c for c in baseline['commands'] if '-kext' in c and 'clang++' in c))
    link[link.index('-o') + 1] = str(bundle / binary)
    link = [str(out / 'obj/AdrenoDisplay.o') if x == str(BASELINE / 'obj/AdrenoDisplay.o') else x for x in link]
    run(link, 'link.log')
    run(['codesign', '--force', '--sign', '-', '--timestamp=none', str(bundle)], 'sign.log')
    run(['codesign', '--verify', '--strict', str(bundle)], 'verify-sign.log')
    for name, expected in objects.items():
        assert sha(BASELINE / name) == expected, name
    for name, expected in inputs.items():
        assert sha(Path(name)) == expected, name
    result = dict(status='PANEL_MODE_KEXT_BUILT_NOT_INSTALLED', hardware_access=False,
        source_root=str(SOURCE), sources_sha256=inputs, baseline_objects=objects,
        replaced_objects=['AdrenoDisplay.o'], commands=commands,
        kext_sha256=sha(bundle / binary), info_sha256=sha(bundle / 'Contents/Info.plist'),
        new_object_sha256=sha(out / 'obj/AdrenoDisplay.o'), builder_sha256=sha(Path(__file__)),
        boundary='Native kext compile/link/sign only; no AuxKC, install, runtime or desktop qualification')
    (out / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(output=str(out), status=result['status'], kext_sha256=result['kext_sha256'])))


if __name__ == '__main__':
    main()
