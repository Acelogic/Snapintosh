#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture commands with explicit replay seeds for initially undefined private targets.

Failure inventory: private bytes mistaken for a memory snapshot; read-before-write
textures seeded silently; mismatched resource identity; shader reads before the
first producing pass; or a replay seed mistaken for physically verified output.
All seeded allocations are labelled, and GPU execution still stops at commit.
"""
from pathlib import Path
import hashlib
import runpy

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def capture_scope(seed):
    assert isinstance(seed, int) and 0 <= seed <= 255
    adapter = ROOT / 'tools/capture-ca-composite-layouts.py'
    assert sha(adapter) == 'ff6175450a6fef82b736bdc039b691fba7fbda856b70c2d315259c9a02802462'
    baseline = runpy.run_path(str(adapter))
    source = baseline['source']
    old_snapshot = '''                require(cpu != NULL, @"Captured resource has no CPU mapping");
                NSData *snapshot = [NSData dataWithBytes:cpu length:(NSUInteger)size];'''
    new_snapshot = r'''
                BOOL seeded = cpu == NULL;
                NSData *snapshot;
                if (seeded) {
                    require([resource conformsToProtocol:@protocol(MTLTexture)], @"Unmapped non-texture resource");
                    id<MTLTexture> t = resource; CaptureLinearLayout l = {0};
                    require(t.storageMode == MTLStorageModePrivate && !t.buffer && !t.iosurface &&
                        t.textureType == MTLTextureType2D && t.pixelFormat == MTLPixelFormatBGRA8Unorm &&
                        [resource adrenoGetLinearLayout:&l] && l.allocationBytes == size && (access & 2),
                        @"Only known private BGRA8 render allocations may use an explicit replay seed");
                    NSUInteger producer = NSNotFound;
                    for (NSUInteger i = 0; i < passRows.count; i++) {
                        NSDictionary *p = passRows[i];
                        if ([p[@"resource_id"] unsignedIntValue] == rid) { producer = i; break; }
                    }
                    require(producer != NSNotFound && [passRows[producer][@"load"] unsignedIntegerValue] != MTLLoadActionLoad,
                        @"Private target initially loads undefined bytes or has no producing pass");
                    for (NSDictionary *binding in Report[@"fragment_bindings"]) {
                        for (NSDictionary *trow in binding[@"textures"]) if ([trow[@"resource_id"] unsignedIntValue] == rid)
                            require([binding[@"render_pass_count"] unsignedIntegerValue] > producer + 1,
                                @"Private texture is sampled before its first producing pass ends");
                    }
                    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)size];
                    memset(data.mutableBytes, PRIVATE_SEED, data.length); snapshot = data;
                } else snapshot = [NSData dataWithBytes:cpu length:(NSUInteger)size];'''.replace('PRIVATE_SEED', str(seed))
    replacements = {
        old_snapshot: new_snapshot,
        '@"path":resourcePath, @"sha256":digest(snapshot), @"class":NSStringFromClass([resource class])}':
            '@"path":resourcePath, @"sha256":digest(snapshot), @"class":NSStringFromClass([resource class]), '
            '@"snapshot_kind":seeded ? @"undefined-private-replay-seed" : @"cpu-memory", '
            '@"replay_seed":seeded ? @(' + str(seed) + ') : (id)[NSNull null]}',
        '[bindingsReport addObject:@{@"textures":ts, @"samplers":ss}]':
            '[bindingsReport addObject:@{@"textures":ts, @"samplers":ss, '
            '@"render_pass_count":@([Report[@"render_passes"] count])}]',
        'Report[@"boundary"] = @"Stopped at first native commit; completion and endFrame were not simulated.";':
            'Report[@"boundary"] = @"Stopped at first native commit; completion and endFrame were not simulated. '
            'Unmapped private targets carry labelled deterministic replay seeds, not captured memory bytes.";',
    }
    anchor = '        replacements = {'
    assert source.count(anchor) == 1
    injected = '\n'.join('            ' + repr(k) + ': ' + repr(v) + ',' for k, v in replacements.items())
    source = source.replace(anchor, anchor + '\n' + injected)
    scope = dict(__file__=__file__, __name__='private_capture', HOOK=baseline['hook'])
    exec(compile(source, str(adapter), 'exec'), scope)
    scope['SCENES'] = baseline['scope']['SCENES']
    return scope
