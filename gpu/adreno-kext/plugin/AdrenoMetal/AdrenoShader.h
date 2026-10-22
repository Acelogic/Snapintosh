/* SPDX-License-Identifier: MIT */
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import "AdrenoCompilerInput.h"

// Owned serialized Adreno code and its compiler binding description.
@interface AdrenoShader : NSObject
@property (nonatomic, readonly, strong) NSData *code;
// code is the Mesa cache serialization; only machineCode is shader upload data.
@property (nonatomic, readonly, strong) NSData *machineCode;
@property (nonatomic, readonly, strong) NSData *programData;
@property (nonatomic, readonly, strong) NSDictionary *program;
@property (nonatomic, readonly, strong) NSData *sidecarData;
@property (nonatomic, readonly, strong) NSDictionary *sidecar;
@property (nonatomic, readonly, strong) NSString *key;
// Returns a verified cached result for the same air2ir3 cache key when one exists (process memory,
// the bundle's AdrenoShaderCache.amsp, the per-user cache directory); otherwise compiles and stores.
+ (instancetype)compileInput:(AdrenoCompilerInput *)input
                  descriptor:(MTLRenderPipelineDescriptor *)descriptor
                safeConstlen:(BOOL)safe error:(NSString **)error;
// Hit/miss/reject/write counters of the compile-result cache in this process.
+ (NSDictionary *)cacheStatistics;
+ (NSUInteger)trimVertex:(AdrenoShader *)vertex fragment:(AdrenoShader *)fragment;
+ (NSDictionary *)linkVertex:(AdrenoShader *)vertex fragment:(AdrenoShader *)fragment error:(NSString **)error;
@end
