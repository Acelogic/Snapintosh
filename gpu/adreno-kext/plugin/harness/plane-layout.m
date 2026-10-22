/* SPDX-License-Identifier: MIT */
/* Real IOSurface -> native Metal texture -> production linear layout.
 * Failure inventory: docs/GRAPHICS-CORRECTNESS-20261018.md. No GPU submission. */
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#import "../AdrenoMetal/AdrenoLinearTexture.h"
extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (PlaneCheck)
- (id)initWithAcceleratorPort:(unsigned)port;
@end
int main(int argc,const char **argv) {
 @autoreleasepool {
  if(argc!=3)return 64;
  NSMutableDictionary *report=[NSMutableDictionary dictionary];IOSurfaceRef surface=NULL;
  @try {
   (void)MTLCopyAllDevices();NSError *error=nil;NSBundle *b=[NSBundle bundleWithPath:@(argv[1])];
   if(![b loadAndReturnError:&error])@throw [NSException exceptionWithName:@"Load" reason:error.description userInfo:nil];
   io_service_t port=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("IOAccelerator"));
   id<MTLDevice> device=[[[b classNamed:@"AdrenoMTLDevice"] alloc] initWithAcceleratorPort:port];IOObjectRelease(port);MTLAddDevice(device);
   /* Two 10-bit bi-planar x420 views: R16 luma and RG16 interleaved chroma. */
   NSDictionary *properties=@{(id)kIOSurfaceWidth:@64,(id)kIOSurfaceHeight:@32,
    (id)kIOSurfacePixelFormat:@0x78343230,(id)kIOSurfaceAllocSize:@16384,
    (id)kIOSurfacePlaneInfo:@[
      @{(id)kIOSurfacePlaneWidth:@64,(id)kIOSurfacePlaneHeight:@32,(id)kIOSurfacePlaneBytesPerElement:@2,
        (id)kIOSurfacePlaneBytesPerRow:@128,(id)kIOSurfacePlaneOffset:@0,(id)kIOSurfacePlaneSize:@4096},
      @{(id)kIOSurfacePlaneWidth:@32,(id)kIOSurfacePlaneHeight:@16,(id)kIOSurfacePlaneBytesPerElement:@4,
        (id)kIOSurfacePlaneBytesPerRow:@128,(id)kIOSurfacePlaneOffset:@4096,(id)kIOSurfacePlaneSize:@2048}]};
   surface=IOSurfaceCreate((__bridge CFDictionaryRef)properties);
   if(!surface)@throw [NSException exceptionWithName:@"Surface" reason:@"no planar IOSurface" userInfo:nil];
   NSMutableArray *planes=[NSMutableArray array];report[@"planes"]=planes;
   for(unsigned plane=0;plane<2;plane++) {
    MTLTextureDescriptor *d=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:plane?MTLPixelFormatRG16Unorm:MTLPixelFormatR16Unorm width:plane?32:64 height:plane?16:32 mipmapped:NO];
    d.usage=MTLTextureUsageShaderRead;d.storageMode=MTLStorageModeShared;
    id<MTLTexture> t=[device newTextureWithDescriptor:d iosurface:surface plane:plane];
    AdrenoLinearTextureLayout l={0};BOOL known=[(id<AdrenoLinearTexture>)t adrenoGetLinearLayout:&l];
    [planes addObject:@{@"plane":@(plane),@"known":@(known),@"offset":@(l.offset),@"row":@(l.rowBytes),
       @"width":@(l.width),@"height":@(l.height),@"format":@(l.format),@"texture":t.description ?: @"nil"}];
    if(!known||l.offset!=(plane?4096:0)||l.rowBytes!=128||l.width!=d.width||l.height!=d.height||l.format!=d.pixelFormat)
     @throw [NSException exceptionWithName:@"Check" reason:@"selected plane layout unavailable or incorrect" userInfo:nil];
   }
   // A plane cannot be reinterpreted with the wrong element size or dimensions.
   for(unsigned fault=0;fault<2;fault++) {
    MTLTextureDescriptor *d=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:fault?MTLPixelFormatRG16Unorm:MTLPixelFormatR16Unorm width:fault?64:32 height:16 mipmapped:NO];
    d.storageMode=MTLStorageModeShared;d.usage=MTLTextureUsageShaderRead;
    id<MTLTexture> t=[device newTextureWithDescriptor:d iosurface:surface plane:1];
    AdrenoLinearTextureLayout l={0};
    if([(id<AdrenoLinearTexture>)t adrenoGetLinearLayout:&l])
     @throw [NSException exceptionWithName:@"Check" reason:@"invalid plane element/extent accepted" userInfo:nil];
   }
   CFRelease(surface);
   surface=IOSurfaceCreate((__bridge CFDictionaryRef)@{(id)kIOSurfaceWidth:@16,(id)kIOSurfaceHeight:@16,
    (id)kIOSurfaceBytesPerElement:@4,(id)kIOSurfaceBytesPerRow:@64,(id)kIOSurfaceAllocSize:@16384,
    (id)kIOSurfacePixelFormat:@0x42475241});
   MTLTextureDescriptor *d=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:16 height:16 mipmapped:NO];
   d.storageMode=MTLStorageModeShared;d.usage=MTLTextureUsageShaderRead;
   id<MTLTexture> t=[device newTextureWithDescriptor:d iosurface:surface plane:0];AdrenoLinearTextureLayout l={0};
   if(![(id<AdrenoLinearTexture>)t adrenoGetLinearLayout:&l] || l.offset || l.rowBytes!=64)
    @throw [NSException exceptionWithName:@"Check" reason:@"nonplanar BGRA layout regressed" userInfo:nil];
   report[@"invalid_plane_layouts_refused"]=@2;report[@"nonplanar_bgra"]=@"PASS";
   report[@"status"]=@"PASS";
  } @catch(NSException *e){report[@"status"]=@"FAIL";report[@"exception"]=e.reason?:e.name;}
  if(surface)CFRelease(surface);report[@"gpu_submission"]=@NO;
  [[NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:NULL] writeToFile:@(argv[2]) atomically:YES];
  puts([report[@"status"] UTF8String]);return [report[@"status"] isEqual:@"PASS"]?0:1;
 }
}
