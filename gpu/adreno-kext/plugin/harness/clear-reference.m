/* SPDX-License-Identifier: MIT */
// Measured Metal clear-color reference on the host's real Apple GPU.
// This is reference data, never evidence of an Adreno render or guest GUI.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <assert.h>
#include <math.h>

int main(int argc,const char **argv) {
    @autoreleasepool {
        assert(argc==2);
        NSString *directory=@(argv[1]);
        assert(![[NSFileManager defaultManager] fileExistsAtPath:directory]);
        assert([[NSFileManager defaultManager] createDirectoryAtPath:directory
            withIntermediateDirectories:YES attributes:nil error:nil]);
        id<MTLDevice> device=MTLCreateSystemDefaultDevice();
        assert(device && [device.name containsString:@"Apple"]);
        id<MTLCommandQueue> queue=[device newCommandQueue];
        assert(queue);
        const double colors[][4]={
            {1,0,0,1},{0,1,0,1},{0,0,1,1},{0.25,0.5,0.75,1},
            {-0.1,1.1,0.123,0.875},{0,0,0,0},{1,1,1,1},
            {0.5/255,1.5/255,2.5/255,3.5/255},
            {32.5/255,63.5/255,126.5/255,127.5/255},
            {0.1,0.2,0.3,0.4},
        };
        NSMutableArray *cases=[NSMutableArray array];
        const NSUInteger width=37,height=23,rowBytes=width*4;
        for (NSUInteger format=0;format<2;format++) {
            MTLPixelFormat pf=format ? MTLPixelFormatBGRA8Unorm : MTLPixelFormatRGBA8Unorm;
            for (NSUInteger index=0;index<sizeof(colors)/sizeof(colors[0]);index++) {
                MTLTextureDescriptor *desc=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:pf
                    width:width height:height mipmapped:NO];
                desc.storageMode=MTLStorageModeShared;
                desc.usage=MTLTextureUsageRenderTarget;
                id<MTLTexture> texture=[device newTextureWithDescriptor:desc];
                assert(texture);
                // Seed every byte to a different value from typical clears.
                NSMutableData *seed=[NSMutableData dataWithLength:rowBytes*height];
                memset(seed.mutableBytes,0x69,seed.length);
                [texture replaceRegion:MTLRegionMake2D(0,0,width,height) mipmapLevel:0
                    withBytes:seed.bytes bytesPerRow:rowBytes];
                MTLRenderPassDescriptor *pass=[MTLRenderPassDescriptor renderPassDescriptor];
                pass.colorAttachments[0].texture=texture;
                pass.colorAttachments[0].loadAction=MTLLoadActionClear;
                pass.colorAttachments[0].storeAction=MTLStoreActionStore;
                const double *c=colors[index];
                pass.colorAttachments[0].clearColor=MTLClearColorMake(c[0],c[1],c[2],c[3]);
                id<MTLCommandBuffer> cb=[queue commandBuffer];
                id<MTLRenderCommandEncoder> encoder=[cb renderCommandEncoderWithDescriptor:pass];
                assert(encoder);
                [encoder endEncoding];[cb commit];[cb waitUntilCompleted];
                assert(cb.status==MTLCommandBufferStatusCompleted && !cb.error);
                NSMutableData *pixels=[NSMutableData dataWithLength:rowBytes*height];
                [texture getBytes:pixels.mutableBytes bytesPerRow:rowBytes
                    fromRegion:MTLRegionMake2D(0,0,width,height) mipmapLevel:0];
                uint32_t first=0;
                memcpy(&first,pixels.bytes,4);
                for(NSUInteger p=0;p<pixels.length;p+=4)
                    assert(!memcmp((const char *)pixels.bytes+p,&first,4));
                NSString *name=[NSString stringWithFormat:@"format-%lu-color-%lu.rgba",
                    (unsigned long)pf,(unsigned long)index];
                assert([pixels writeToFile:[directory stringByAppendingPathComponent:name] atomically:YES]);
                [cases addObject:@{@"format":@(pf),@"color":@[@(c[0]),@(c[1]),@(c[2]),@(c[3])],
                    @"width":@(width),@"height":@(height),@"readback_row_bytes":@(rowBytes),
                    @"pixel_word":@(first),@"readback":name,@"command_status":@(cb.status)}];
            }
        }
        NSDictionary *record=@{@"status":@"APPLE_GPU_CLEAR_REFERENCE_COMPLETE",@"device":device.name,
            @"registry_id":@(device.registryID),@"cases":cases,
            @"boundary":@"Actual host Apple-GPU Metal render-pass-clear reference; no Adreno or guest execution."};
        NSData *json=[NSJSONSerialization dataWithJSONObject:record options:NSJSONWritingPrettyPrinted error:nil];
        assert(json && [json writeToFile:[directory stringByAppendingPathComponent:@"reference.json"] atomically:YES]);
        printf("Apple GPU clear reference: %lu cases, %s\n",(unsigned long)cases.count,device.name.UTF8String);
    }
    return 0;
}
