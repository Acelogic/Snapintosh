/* SPDX-License-Identifier: MIT */
// Observe the actual CA gradient buffer-texture request before implementing it.
// The included harness keeps native Adreno submission intercepted on the host.
#define main ca_scene_main
#include CA_DESKTOP_SCENES  /* -DCA_DESKTOP_SCENES='"<build dir>/ca-desktop-scenes.m"' (the scene harness build output) */
#undef main

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc != 5 || strcmp(argv[1], "--adreno")) return 64;
        NSError *error = nil;
        NSBundle *bundle = [NSBundle bundleWithPath:@(argv[2])];
        if (![bundle loadAndReturnError:&error]) return 65;
        Class buffer = NSClassFromString(@"AdrenoBuffer");
        SEL selector = @selector(newTextureWithDescriptor:offset:bytesPerRow:);
        if (class_getInstanceMethod(buffer, selector)) return 66;
        IMP capture = imp_implementationWithBlock(^id(id<MTLBuffer> b, MTLTextureDescriptor *d, NSUInteger o, NSUInteger rb) {
            Report[@"buffer_texture_request"] = @{@"format":@(d.pixelFormat), @"type":@(d.textureType),
                @"width":@(d.width), @"height":@(d.height), @"depth":@(d.depth),
                @"levels":@(d.mipmapLevelCount), @"samples":@(d.sampleCount), @"array_length":@(d.arrayLength),
                @"usage":@(d.usage), @"storage":@(d.storageMode), @"options":@(d.resourceOptions),
                @"offset":@(o), @"row_bytes":@(rb), @"buffer_length":@(b.length)};
            save(@"buffer-texture-request-captured");
            require(NO, @"Observed missing buffer texture constructor; no texture fabricated");
            return nil;
        });
        if (!class_addMethod(buffer, selector, capture, "@@:@QQ")) return 67;
        return ca_scene_main(argc, argv);
    }
}
