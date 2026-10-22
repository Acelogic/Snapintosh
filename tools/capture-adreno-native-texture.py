# SPDX-License-Identifier: MIT
"""Capture native texture allocation with the unchanged deployed plug-in."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--bundle', type=Path, required=True)
parser.add_argument('--expected-sha256', required=True)
parser.add_argument('--plugin-root', type=Path, default=ROOT)
parser.add_argument('--incompatible', action='store_true')
parser.add_argument('--draw', action='store_true')
args = parser.parse_args()
assert not (args.incompatible and args.draw)
OUT = args.output.resolve()
BUNDLE = args.bundle.resolve()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(BUNDLE / 'Contents/MacOS/AdrenoMetal') == args.expected_sha256
assert not OUT.exists()
OUT.mkdir(parents=True)
record = dict(status='RUNNING', started=time.time(), a16_access=False, gpu_submission=False,
    expected_incompatible=args.incompatible,
    draw_requested=args.draw,
    plugin_source_root=str(args.plugin_root.resolve()),
    source_sha256=sha(ROOT / 'gpu/adreno-kext/plugin/harness/native-texture.m'),
    wrapper_sha256=sha(Path(__file__)),
    plugin_sources_sha256={str(p.relative_to(args.plugin_root.resolve())):sha(p) for p in (args.plugin_root.resolve() / 'gpu/adreno-kext/plugin').rglob('*')
        if p.is_file() and p.suffix in ('.m','.h','.sh','.plist','.tbd')},
    bundle_sha256={str(p.relative_to(BUNDLE)):sha(p) for p in BUNDLE.rglob('*') if p.is_file()})
try:
    probe = OUT / 'native-texture'
    with (OUT / 'build.log').open('x') as log:
        subprocess.run(['xcrun','clang','-arch','arm64e','-mmacosx-version-min=27.0',
            '-fobjc-arc','-fobjc-arc-exceptions','-O1','-g','-Wall','-Werror',
            str(ROOT / 'gpu/adreno-kext/plugin/harness/native-texture.m'),
            '-framework','Foundation','-framework','Metal','-framework','IOSurface',
            '-framework','IOKit','-o',str(probe)],stdout=log,stderr=subprocess.STDOUT,check=True)
    for label, command in [('sign', ['codesign', '-f', '-s', '-', str(probe)]),
                        ('verify', ['codesign', '--verify', '--strict', str(BUNDLE)])]:
        with (OUT / (label + '.log')).open('x') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    with (OUT / 'native.log').open('x') as log:
        result = subprocess.run([str(probe), str(BUNDLE), str(OUT / 'capture.json'),
            *(['--incompatible'] if args.incompatible else []), *(['--draw'] if args.draw else [])],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=90)
    record['exit_code'] = result.returncode
    if (OUT / 'capture.json').exists():
        record['capture'] = json.loads((OUT / 'capture.json').read_text())
    expected = 'NATIVE_TEXTURE_EXCEPTION' if args.incompatible else ('NATIVE_DRAW_ENCODED_NOT_SUBMITTED' if args.draw else 'NATIVE_CLEAR_ENCODED_NOT_SUBMITTED')
    assert result.returncode == (2 if args.incompatible else 0)
    assert record['capture']['status'] == expected
    if args.incompatible:
        assert record['capture']['exception']['reason'] == 'Adreno clear requires a recorded linear2D texture'
    assert record['capture']['native_texture_properties']['usage'] == (1 if args.incompatible else 4)
    record['status'] = 'NATIVE_DRAW_PREFLIGHT_VERIFIED' if args.draw else 'NATIVE_CLEAR_PREFLIGHT_VERIFIED'
except BaseException as error:
    record.update(status='FAILED', error=repr(error))
    raise
finally:
    record['finished'] = time.time()
    record['artifacts_sha256'] = {str(p.relative_to(OUT)):sha(p) for p in OUT.rglob('*') if p.is_file()}
    (OUT / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({k:record.get(k) for k in ['status','exit_code','capture']}))
