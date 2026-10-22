#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise real CA desktop layer operations with the pinned guest candidate.

Failure inventory: docs/ADRENO-CA-DESKTOP-SCENES-20260928.md.
Host rendering/capture only. No A16 access or changes to installed boot inputs.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'gpu/adreno-kext/plugin/harness/ca-renderer.m'
BASE_SHA = '2752042b0ae242b7dfccea4dc70bb71483f3e3efe95fc4a0ee10ae4410538e1e'
BUNDLE = ROOT / 'build/ca-buffer-plugin-20260928-v2/AdrenoMetal.bundle'
PLUGIN_SHA = 'a7f631041750178745e3665a3a8fb6c76e7ad3f8a01d69d406826d21ebc53215'
COMPILER_SHA = '7d0e1491c9de4c15214ef82054b696acb7c6503229ed3a747ea08cf792bfbfa6'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()

SCENES = r'''
            if ([scene isEqualToString:@"opacity"]) {
                child.opaque = NO; child.opacity = 0.5;
            } else if ([scene isEqualToString:@"rounded"]) {
                child.opaque = NO; child.cornerRadius = 18; child.masksToBounds = YES;
            } else if ([scene isEqualToString:@"text"]) {
                [child removeFromSuperlayer];
                CATextLayer *text = [CATextLayer layer];
                text.frame = CGRectMake(16, 48, 224, 64);
                text.string = @"Snapintosh"; text.fontSize = 28; text.contentsScale = 1;
                text.alignmentMode = kCAAlignmentCenter;
                CGColorRef white = CGColorCreateGenericRGB(1, 1, 1, 1);
                text.foregroundColor = white; CGColorRelease(white);
                [root addSublayer:text];
            } else if ([scene isEqualToString:@"gradient"]) {
                [child removeFromSuperlayer];
                CAGradientLayer *gradient = [CAGradientLayer layer];
                gradient.frame = CGRectMake(32, 24, 192, 112);
                gradient.colors = @[(__bridge id)blue, (__bridge id)orange];
                gradient.startPoint = CGPointMake(0, 0);
                gradient.endPoint = CGPointMake(1, 1);
                [root addSublayer:gradient];
            }
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    assert sha(BASE) == BASE_SHA
    assert sha(BUNDLE / 'Contents/MacOS/AdrenoMetal') == PLUGIN_SHA
    assert sha(BUNDLE / 'Contents/Frameworks/libAdrenoCompiler.dylib') == COMPILER_SHA
    out = args.output.resolve()
    out.mkdir(exist_ok=False, parents=True)
    record = dict(status='RUNNING', started=time.time(), a16_access=False,
        source_sha256=sha(__file__), base_sha256=BASE_SHA, plugin_sha256=PLUGIN_SHA,
        compiler_sha256=COMPILER_SHA, cases=[], desktop_verified=False,
        boundary='Native CA host references and first Adreno commits only; no physical replay or guest proof')

    def save():
        (out / 'capture.json').write_text(json.dumps(record, indent=2) + '\n')

    save()
    try:
        source = BASE.read_text()
        replacements = {
            '                const void *cpu = [resource virtualAddress];':
                '                const void *cpu = [resource virtualAddress];\n'
                '                if ([resource conformsToProtocol:@protocol(MTLTexture)] && [(id<MTLTexture>)resource buffer]) {\n'
                '                    id<MTLBuffer> backing = [(id<MTLTexture>)resource buffer];\n'
                '                    require([(id)backing resourceID] == rid, @"Texture alias changed resource identity");\n'
                '                    cpu = [(id)backing virtualAddress];\n'
                '                }',
            '        if (argc == 5 && !imageScene) return 64;':
                '        NSString *scene = argc == 5 ? @(argv[4]) : @"solid";\n'
                '        if (![@[@"opacity", @"rounded", @"text", @"gradient"] containsObject:scene]) return 64;',
            '@"scene":imageScene ? @"blue root with checkerboard image child" : @"blue root with orange child rectangle",':
                '@"scene":scene,',
            '            CGColorRelease(blue); CGColorRelease(orange);':
                SCENES + '\n            CGColorRelease(blue); CGColorRelease(orange);',
        }
        for old, new in replacements.items():
            assert source.count(old) == 1, old
            source = source.replace(old, new)
        generated = out / 'ca-desktop-scenes.m'
        generated.write_text(source)
        binary = out / 'ca-desktop-scenes'
        command = ['xcrun', 'clang', '-arch', 'arm64e', '-mmacosx-version-min=27.0',
            '-fobjc-arc', '-fobjc-arc-exceptions', '-O1', '-g', '-Wall', '-Werror',
            '-Wno-deprecated-declarations', str(generated)]
        for framework in ['Foundation', 'Metal', 'QuartzCore', 'CoreGraphics', 'IOSurface', 'IOKit']:
            command += ['-framework', framework]
        command += ['-o', str(binary)]
        record['build_command'] = command
        with (out / 'build.log').open('x') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
            subprocess.run(['codesign', '-f', '-s', '-', str(binary)],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        record.update(generated_sha256=sha(generated), executable_sha256=sha(binary))
        save()
        for scene in ['opacity', 'rounded', 'text', 'gradient']:
            for mode in ['host', 'adreno']:
                path = out / f'{scene}-{mode}.json'
                case = dict(scene=scene, mode=mode, path=str(path), started=time.time())
                record['cases'].append(case)
                save()
                with (out / f'{scene}-{mode}.log').open('x') as log:
                    try:
                        result = subprocess.run([str(binary), '--' + mode, str(BUNDLE), str(path), scene],
                            stdout=log, stderr=subprocess.STDOUT, timeout=90)
                        case['exit_code'] = result.returncode
                    except subprocess.TimeoutExpired:
                        case['timeout'] = True
                case['finished'] = time.time()
                if path.exists():
                    data = json.loads(path.read_text())
                    case.update(status=data['status'], sha256=sha(path),
                        stage=data.get('stage'), exception=data.get('exception'),
                        programs=len(data.get('programs', [])), commits=len(data.get('commits', [])))
                save()
        assert sha(BASE) == BASE_SHA
        assert sha(BUNDLE / 'Contents/MacOS/AdrenoMetal') == PLUGIN_SHA
        assert sha(BUNDLE / 'Contents/Frameworks/libAdrenoCompiler.dylib') == COMPILER_SHA
        completed = {'host': 'HOST_CA_RENDER_COMPLETED', 'adreno': 'ADRENO_CA_COMMANDS_CAPTURED_NOT_SUBMITTED'}
        record['native_paths_completed'] = all(case.get('exit_code') == 0
            and case.get('status') == completed[case['mode']] for case in record['cases'])
        record['status'] = 'NATIVE_CA_SCENES_CAPTURED' if record['native_paths_completed'] else 'NATIVE_CA_SCENES_REVEAL_MISSING_PATHS'
    except BaseException as error:
        record.update(status='FAILED', error=repr(error))
        raise
    finally:
        record['finished'] = time.time()
        save()
    print(json.dumps(dict(status=record['status'], output=str(out / 'capture.json'),
                          native_paths_completed=record['native_paths_completed'])))


if __name__ == '__main__':
    main()
