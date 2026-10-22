/* SPDX-License-Identifier: MIT */
// Real plug-in Metal entry points; native submission is intercepted, never sent.
// Failure inventory: docs/GRAPHICS-CORRECTNESS-20261018.md.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>
#include <stdio.h>
#include <unistd.h>
extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (WorkCheck)
- (id)initWithAcceleratorPort:(unsigned)port;
- (NSDictionary *)adrenoWorkReport;
@end
static BOOL available(id self,SEL sel){(void)self;(void)sel;return YES;}
static unsigned NativeCommits;
static void capture(id self,SEL sel) {(void)self;(void)sel;NativeCommits++;}
int main(int argc,const char **argv) {
 @autoreleasepool {
  if(argc!=4)return 64;
  BOOL lenient=atoi(argv[3]);NSMutableDictionary *report=[NSMutableDictionary dictionary];
  @try {
   (void)MTLCopyAllDevices();NSError *error=nil;NSBundle *bundle=[NSBundle bundleWithPath:@(argv[1])];
   if(![bundle loadAndReturnError:&error])@throw [NSException exceptionWithName:@"Load" reason:error.description userInfo:nil];
   method_setImplementation(class_getInstanceMethod(NSClassFromString(@"IOGPUMetalCommandBuffer"),@selector(commit)),(IMP)capture);
   io_service_t provider=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("IOAccelerator"));
   id<MTLDevice> device=[[[bundle classNamed:@"AdrenoMTLDevice"] alloc] initWithAcceleratorPort:provider];
   IOObjectRelease(provider);if(!device)@throw [NSException exceptionWithName:@"Device" reason:@"no device" userInfo:nil];MTLAddDevice(device);
   id<MTLCommandQueue> queue=[device newCommandQueue];NSMutableArray *cases=[NSMutableArray array];
   for(unsigned which=0;which<5;which++) {
    id<MTLCommandBuffer> cb=[queue commandBuffer];id encoder=nil;BOOL refused=NO,commitRefused=NO;
    if(which==2 || which==3) {
     MTLTextureDescriptor *td=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:16 height:16 mipmapped:NO];td.usage=MTLTextureUsageRenderTarget;td.storageMode=MTLStorageModeShared;
     MTLRenderPassDescriptor *rp=[MTLRenderPassDescriptor renderPassDescriptor];rp.colorAttachments[0].texture=[device newTextureWithDescriptor:td];rp.colorAttachments[0].loadAction=MTLLoadActionLoad;rp.colorAttachments[0].storeAction=MTLStoreActionStore;
     encoder=[cb renderCommandEncoderWithDescriptor:rp];
    } else {
     encoder=[cb computeCommandEncoder];uint32_t bytes[4]={1,2,3,4};
     [encoder setBytes:bytes length:sizeof bytes atIndex:0];
     [encoder setBuffer:[device newBufferWithLength:64 options:MTLResourceStorageModeShared] offset:4 atIndex:1];
     [encoder setThreadgroupMemoryLength:16 atIndex:0];
      id<MTLBuffer> ranged[2]={[device newBufferWithLength:128 options:MTLResourceStorageModeShared],nil};
      NSUInteger offsets[2]={12,0};[encoder setBuffers:ranged offsets:offsets withRange:NSMakeRange(3,2)];
    }
    @try {
     for(unsigned n=0;n<3;n++) {
      if(which==0)[encoder dispatchThreads:MTLSizeMake(32,1,1) threadsPerThreadgroup:MTLSizeMake(8,1,1)];
      if(which==1)[encoder dispatchThreadgroups:MTLSizeMake(4,1,1) threadsPerThreadgroup:MTLSizeMake(8,1,1)];
      if(which==2)[encoder dispatchThreadsPerTile:MTLSizeMake(8,8,1)];
       if(which==3)[encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
       if(which==4)[encoder dispatchThreadgroupsWithIndirectBuffer:[device newBufferWithLength:32 options:MTLResourceStorageModeShared] indirectBufferOffset:4 threadsPerThreadgroup:MTLSizeMake(8,1,1)];
     }
    } @catch(NSException *e) {refused=YES;report[@"last_refusal"]=e.reason;}
    [encoder endEncoding];
    @try {[cb commit];} @catch(NSException *e){commitRefused=YES;}
    NSDictionary *ledger=[(id)cb respondsToSelector:@selector(adrenoWorkReport)]?[(id)cb adrenoWorkReport]:@{};
    [cases addObject:@{@"case":@(which),@"refused":@(refused),@"commit_refused":@(commitRefused),@"ledger":ledger}];
    if(which!=2 && which!=3 && [ledger[@"omissions"][0][@"details"][@"bindings"][@"buffer:3"][@"offset"] unsignedIntegerValue]!=12)
      @throw [NSException exceptionWithName:@"Check" reason:@"ranged compute bindings lost" userInfo:@{@"cases":cases}];
     if(refused==lenient || commitRefused==lenient || [ledger[@"omitted"] unsignedIntegerValue]!=(lenient?3:1))
     @throw [NSException exceptionWithName:@"Check" reason:@"omissions are not counted/refused at the public entry point" userInfo:@{@"cases":cases}];
   }
   if(NativeCommits!=(lenient?5:0))@throw [NSException exceptionWithName:@"Check" reason:@"native submission boundary" userInfo:nil];
    // A real render pass rejected by both the IB builder and clear fallback.
    Method availability=class_getInstanceMethod(NSClassFromString(@"AdrenoCommandBuffer"),NSSelectorFromString(@"adrenoDrawAvailable"));
    IMP prior=method_setImplementation(availability,(IMP)available);
    id cbPass=[queue commandBuffer];BOOL passRefused=NO,passCommitRefused=NO;
    MTLTextureDescriptor *bad=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatR8Sint width:16 height:16 mipmapped:NO];
    bad.usage=MTLTextureUsageRenderTarget;bad.storageMode=MTLStorageModeShared;
    MTLRenderPassDescriptor *rp=[MTLRenderPassDescriptor renderPassDescriptor];
    rp.colorAttachments[0].texture=[device newTextureWithDescriptor:bad];rp.colorAttachments[0].loadAction=MTLLoadActionClear;
    @try {id e=[cbPass renderCommandEncoderWithDescriptor:rp];[e endEncoding];} @catch(NSException *e){passRefused=YES;}
    method_setImplementation(availability,prior);
    @try {[cbPass commit];} @catch(NSException *e){passCommitRefused=YES;}
    NSDictionary *passLedger=[cbPass adrenoWorkReport];
    if(passRefused==lenient || passCommitRefused==lenient || [passLedger[@"omitted"] unsignedIntegerValue]!=1)
     @throw [NSException exceptionWithName:@"Check" reason:@"unrepresentable render pass not accounted" userInfo:passLedger];
    report[@"refused_pass"]=passLedger;
    if(lenient) {
     id cb=[queue commandBuffer];id encoder=[cb computeCommandEncoder];
     for(unsigned i=0;i<300;i++)[encoder dispatchThreads:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
     [encoder endEncoding];NSDictionary *ledger=[cb adrenoWorkReport];
     if([ledger[@"omitted"] unsignedIntegerValue]!=300 || ![ledger[@"trace_incomplete"] boolValue] || [ledger[@"omissions"] count]!=256)
      @throw [NSException exceptionWithName:@"Check" reason:@"bounded trace loses aggregate count" userInfo:nil];
     report[@"bounded_trace"]=@{@"omitted":ledger[@"omitted"],@"trace_incomplete":ledger[@"trace_incomplete"],@"stored":@([ledger[@"omissions"] count])};
    }
    report[@"cases"]=cases;report[@"status"]=@"PASS";
  } @catch(NSException *e) {report[@"status"]=@"FAIL";report[@"exception"]=e.reason?:e.name;report[@"evidence"]=e.userInfo?:@{};}
  report[@"native_commits_intercepted"]=@(NativeCommits);report[@"gpu_submission"]=@NO;report[@"lenient"]=@(lenient);
   NSString *tracePath=[NSString stringWithFormat:@"/private/var/tmp/adreno-%s-%d.log",getprogname(),getpid()];
   NSData *trace=[NSData dataWithContentsOfFile:tracePath];
   if(!trace || ![trace writeToFile:[@(argv[2]) stringByAppendingString:@".trace.log"] atomically:YES]) {
    report[@"status"]=@"FAIL";report[@"exception"]=@"work trace was not retained";
   }
   report[@"trace_bytes"]=@(trace.length);
   [[NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:NULL] writeToFile:@(argv[2]) atomically:YES];
  puts([report[@"status"] UTF8String]);return [report[@"status"] isEqual:@"PASS"]?0:1;
 }
}
