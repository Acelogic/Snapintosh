#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Record the native textures refused by composite CA scenes, without changing them.

Failure inventory: logging a requested layout instead of the actual allocation;
calling a private selector with the wrong ABI; perturbing a constructor or
render pass; and interpreting a captured descriptor as physical format support.
The hooks call the original methods exactly once and never change arguments.
"""
from pathlib import Path
import hashlib
import runpy

ROOT = Path(__file__).resolve().parents[1]
SCENES = ROOT / 'tools/capture-ca-composite-scenes.py'
BASE = ROOT / 'tools/capture-ca-desktop-scenes.py'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(SCENES) == '41701a9167870e364d3154dd01f1bbdcbf0dd79ac12090937949b5a40c7131f1'
assert sha(BASE) == '953e4f8fda60197602eec95e1b759eab39e5245c32c243e8e18638b0899e57d7'
scene_scope = runpy.run_path(str(SCENES))['scope']
source = BASE.read_text()
hook = r'''
    NSMutableArray *layoutRows = [NSMutableArray array], *passRows = [NSMutableArray array];
    Report[@"layout_publications"] = layoutRows; Report[@"render_passes"] = passRows;
    SEL layoutSel = NSSelectorFromString(@"adrenoSetLinearDescriptor:rowBytes:offset:available:");
    Method layoutMethod = class_getInstanceMethod(NSClassFromString(@"AdrenoTexture"), layoutSel);
    require(layoutMethod != NULL, @"Missing exact layout publication method");
    IMP layoutImp = method_getImplementation(layoutMethod);
    method_setImplementation(layoutMethod, imp_implementationWithBlock(^(id texture, MTLTextureDescriptor *d,
        NSUInteger rowBytes, NSUInteger offset, NSUInteger available) {
        ((void (*)(id, SEL, MTLTextureDescriptor *, NSUInteger, NSUInteger, NSUInteger))layoutImp)
            (texture, layoutSel, d, rowBytes, offset, available);
        CaptureLinearLayout l = {0}; BOOL known = [texture adrenoGetLinearLayout:&l];
        [layoutRows addObject:@{@"resource_id":@([texture resourceID]), @"format":@(d.pixelFormat),
            @"width":@(d.width), @"height":@(d.height), @"depth":@(d.depth), @"type":@(d.textureType),
            @"levels":@(d.mipmapLevelCount), @"samples":@(d.sampleCount), @"layers":@(d.arrayLength),
            @"storage":@(d.storageMode), @"usage":@(d.usage), @"row_bytes":@(rowBytes),
            @"offset":@(offset), @"available":@(available), @"known":@(known),
            @"allocation_bytes":@([texture resourceSize])}];
        save(nil);
    }));
    SEL passSel = @selector(renderCommandEncoderWithDescriptor:);
    Method passMethod = class_getInstanceMethod(NSClassFromString(@"AdrenoCommandBuffer"), passSel);
    require(passMethod != NULL, @"Missing render-pass constructor");
    IMP passImp = method_getImplementation(passMethod);
    method_setImplementation(passMethod, imp_implementationWithBlock(^id(id command, MTLRenderPassDescriptor *pass) {
        MTLRenderPassColorAttachmentDescriptor *a = pass.colorAttachments[0]; id<MTLTexture> t = a.texture;
        CaptureLinearLayout l = {0}; BOOL known = [(id)t adrenoGetLinearLayout:&l];
        [passRows addObject:@{@"resource_id":@([(id)t resourceID]), @"format":@(t.pixelFormat),
            @"width":@(t.width), @"height":@(t.height), @"depth":@(t.depth), @"type":@(t.textureType),
            @"levels":@(t.mipmapLevelCount), @"samples":@(t.sampleCount), @"layers":@(t.arrayLength),
            @"usage":@(t.usage), @"storage":@(t.storageMode), @"known":@(known),
            @"offset":@(l.offset), @"pitch":@(l.rowBytes), @"allocation_bytes":@([(id)t resourceSize]),
            @"load":@(a.loadAction), @"store":@(a.storeAction), @"level":@(a.level), @"slice":@(a.slice),
            @"pass_width":@(pass.renderTargetWidth), @"pass_height":@(pass.renderTargetHeight)}];
        save(nil);
        return ((id (*)(id, SEL, MTLRenderPassDescriptor *))passImp)(command, passSel, pass);
    }));
'''
changes = {
    '@[@"opacity", @"rounded", @"text", @"gradient"]': '@[@"desktop", @"shadow", @"mask", @"transform"]',
    "for scene in ['opacity', 'rounded', 'text', 'gradient']:": "for scene in ['desktop', 'shadow', 'mask', 'transform']:",
    '        replacements = {': '        replacements = {\n'
        + '            "- (uint32_t)resourceID;": "- (uint32_t)resourceID;\\n- (uint64_t)resourceSize;",\n'
        + '            "static void installCapture(void) {": "static void installCapture(void) {" + HOOK,',
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
scope = dict(__file__=__file__, __name__='composite_layout_capture', HOOK=hook)
exec(compile(source, str(BASE), 'exec'), scope)
scope['SCENES'] = scene_scope['SCENES']
if __name__ == '__main__':
    scope['main']()
