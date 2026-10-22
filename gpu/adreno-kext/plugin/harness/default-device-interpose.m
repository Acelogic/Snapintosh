/* SPDX-License-Identifier: MIT */
// Inserted with DYLD_INSERT_LIBRARIES by icon-render.m: MTLCreateSystemDefaultDevice and MTLCopyAllDevices answer the
// device AdrenoSetDefaultDevice names, so frameworks that pick the system default device (IconServices, IconRendering,
// RenderBox) run on the Adreno plug-in device, as they do in the guest where it is the only GPU. Manual retain/release:
//   clang -dynamiclib -arch arm64e default-device-interpose.m -o default-device-interpose.dylib -framework Foundation -framework Metal
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
static id gDevice;
__attribute__((visibility("default"))) void AdrenoSetDefaultDevice(id device) { [gDevice release]; gDevice = [device retain]; }
static id<MTLDevice> AdrenoCreateDefault(void) { return gDevice ? [gDevice retain] : MTLCreateSystemDefaultDevice(); }
static NSArray *AdrenoCopyAll(void) { return gDevice ? [[NSArray alloc] initWithObjects:gDevice, nil] : MTLCopyAllDevices(); }
__attribute__((used)) static const struct { const void *replacement, *original; } interposers[]
    __attribute__((section("__DATA,__interpose"))) = {
    {(const void *)AdrenoCreateDefault, (const void *)MTLCreateSystemDefaultDevice},
    {(const void *)AdrenoCopyAll, (const void *)MTLCopyAllDevices},
};
