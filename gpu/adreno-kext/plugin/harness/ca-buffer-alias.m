/* SPDX-License-Identifier: MIT */
// Real CoreAnimation through the production buffer-texture method.
// CA_SCENE_CAPTURE names the separately built, hash-bound desktop scene harness.
// SNAP_CA_ALIAS_OFFSET optionally relocates image bytes into a fresh native
// buffer, exercising allocation-relative texture offsets without changing CA.
#ifndef CA_SCENE_CAPTURE
#error Define CA_SCENE_CAPTURE to the captured desktop scene source
#endif
#define main ca_scene_main
#include CA_SCENE_CAPTURE
#undef main

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc != 5 || strcmp(argv[1], "--adreno")) return 64;
        NSError *error = nil;
        NSBundle *bundle = [NSBundle bundleWithPath:@(argv[2])];
        if (![bundle loadAndReturnError:&error]) return 65;
        Class buffer = NSClassFromString(@"AdrenoBuffer");
        SEL selector = @selector(newTextureWithDescriptor:offset:bytesPerRow:);
        Method method = class_getInstanceMethod(buffer, selector);
        if (!method) return 66;
        IMP original = method_getImplementation(method);
        const char *offsetText = getenv("SNAP_CA_ALIAS_OFFSET");
        NSUInteger extra = offsetText ? strtoull(offsetText, NULL, 0) : 0;
        if (extra != 0 && extra != 256) return 67;
        method_setImplementation(method, imp_implementationWithBlock(^id(id<MTLBuffer> originalBuffer,
            MTLTextureDescriptor *d, NSUInteger offset, NSUInteger rowBytes) {
            id<MTLBuffer> b = originalBuffer;
            if (extra) {
                require(b.contents && b.storageMode == MTLStorageModeShared && b.length < (1 << 20),
                        @"Alias-offset scenario needs a bounded shared buffer");
                b = [b.device newBufferWithLength:b.length + extra options:MTLResourceStorageModeShared];
                require(b != nil && b.contents != NULL, @"Offset backing allocation failed");
                memset(b.contents, 0xa5, b.length);
                memcpy((char *)b.contents + extra, originalBuffer.contents, originalBuffer.length);
                offset += extra;
            }
            id<MTLTexture> texture = ((id (*)(id, SEL, id, NSUInteger, NSUInteger))original)
                (b, selector, d, offset, rowBytes);
            CaptureLinearLayout layout = {0};
            BOOL known = [(id)texture respondsToSelector:@selector(adrenoGetLinearLayout:)] &&
                         [(id)texture adrenoGetLinearLayout:&layout];
            require(texture != nil && known, @"Native buffer alias did not expose a verified linear layout");
            NSMutableArray *rows = Report[@"buffer_aliases"];
            if (!rows) { rows = [NSMutableArray array]; Report[@"buffer_aliases"] = rows; }
            [rows addObject:@{@"format":@(d.pixelFormat), @"width":@(d.width), @"height":@(d.height),
                @"requested_offset":@(offset), @"layout_offset":@(layout.offset), @"row_bytes":@(layout.rowBytes),
                @"allocation_bytes":@(layout.allocationBytes), @"buffer_length":@(b.length),
                @"buffer_id":@([(id)b resourceID]), @"texture_id":@([(id)texture resourceID]),
                @"buffer_retained":@(texture.buffer == b), @"buffer_offset":@(texture.bufferOffset),
                @"texture_cpu_delta":@((intptr_t)[(id)texture virtualAddress] - (intptr_t)b.contents),
                @"relocated_by":@(extra)}];
            save(@"native-buffer-alias-verified");
            return texture;
        }));
        return ca_scene_main(argc, argv);
    }
}
