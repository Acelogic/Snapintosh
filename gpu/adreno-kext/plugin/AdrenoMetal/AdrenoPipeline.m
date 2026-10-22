/* SPDX-License-Identifier: MIT */
// AdrenoPipeline.m - shader/pipeline side of the plug-in.
//
// _MTLDevice's public pipeline entry points (newRenderPipelineStateWithDescriptor:error:, ...:options:reflection:error:,
// newComputePipelineStateWithDescriptor:...) are implemented in Metal. They run the MTLCompiler returned by
// -compiler (XPC to MTLCompilerService), then call back into these device hooks with the service output:
//   -newVertexVariantWithCompilerOutput:pipelineStatisticsOutput:          (same for Fragment/Compute/Tile)
//   -newRenderPipelineWithDescriptor:vertexVariant:fragmentVariant:errorMessage:
//   -newComputePipelineWithDescriptor:variant:errorMessage:
// AppleParavirtDevice implements exactly these (pv-hooks-called-by-frameworks.txt), which is our template.
//
// Which metallib slice Metal hands the compiler: -targetDeviceArchitecture. AppleParavirtDevice reports
// cpuType 0x01000017 (the AIR slice type in fat metallibs; AGX slices are 0x01000013 + GPU subtype), so it
// always gets AIR. QuartzCore default.metallib (26A428): slice 0 = 0x01000017/0xd "MTLB", 20 AGX slices.
#import "AdrenoMTLDevice.h"
#import "AdrenoMTLObjects.h"
#import "AdrenoCompilerInput.h"
#import "AdrenoShader.h"

typedef struct { unsigned short major; unsigned char minor, patch; } AdrenoArchVersion;   // MTLTargetDeviceArchVersion
@interface MTLTargetDeviceArchitecture : NSObject
@property (nonatomic) unsigned int cpuType;
@property (nonatomic) unsigned int subType;
@property (nonatomic) AdrenoArchVersion version;
@property (nonatomic) unsigned long long driverVersion;
@end
@interface MTLFunctionVariant : NSObject
- (instancetype)initWithCompilerOutput:(id)output;
@end
@interface _MTLRenderPipelineState : NSObject
- (instancetype)initWithDevice:(id)d pipelineStateDescriptor:(id)desc;
@end
@interface _MTLComputePipelineState : NSObject
- (instancetype)initWithDevice:(id)d pipelineStateDescriptor:(id)desc;
@end

// ---- variant: what the compiler service returned for one stage (AIR in simulatorDummyPlugin mode).
@interface AdrenoFunctionVariant : MTLFunctionVariant
@property (nonatomic, readonly) id compilerOutput;    // dispatch_data / NSData from MTLCompilerService
@property (nonatomic, readonly) NSUInteger stage;     // 0 vertex, 1 fragment, 2 compute, 3 tile
@property (nonatomic, readonly, strong) AdrenoCompilerInput *input;
@property (nonatomic, readonly, strong) NSString *inputError;
@end
@implementation AdrenoFunctionVariant
- (instancetype)initWithCompilerOutput:(id)o stage:(NSUInteger)s {
    if ((self = [super initWithCompilerOutput:o])) {
        _compilerOutput = o;
        _stage = s;
        NSString *error = nil;
        _input = [AdrenoCompilerInput inputWithCompilerOutput:o stage:s entry:nil error:&error];
        _inputError = error;
    }
    // The native callback is a metallib container. _input retains its verified
    // AIR module; translation and binding to GPU shader state remain unfinished.
    return self;
}
@end

@interface AdrenoRenderPipelineState : _MTLRenderPipelineState <MTLRenderPipelineState>
@property (nonatomic, strong) AdrenoFunctionVariant *vertex, *fragment;
@property (nonatomic, strong) AdrenoShader *vertexCode, *fragmentCode;
@property (nonatomic, copy) NSDictionary *programLinkage;
@end
@implementation AdrenoRenderPipelineState
- (NSUInteger)maxTotalThreadsPerThreadgroup { return 1024; }
@end

@interface AdrenoComputePipelineState : _MTLComputePipelineState <MTLComputePipelineState>
@property (nonatomic, strong) AdrenoFunctionVariant *kernel;
@property (nonatomic, strong) AdrenoShader *kernelCode;
@end
@implementation AdrenoComputePipelineState
- (NSDictionary *)adrenoWorkDescriptor {
    return @{@"entry":self.kernel.input.entry ?: @"unknown",@"shader_key":self.kernelCode.key ?: @"unknown",
             @"label":self.label ?: @""};
}
- (NSUInteger)maxTotalThreadsPerThreadgroup { return 1024; }
- (NSUInteger)threadExecutionWidth { return 64; }     // Adreno wave64 (a7xx/a8xx "full" waves are 64, double 128)
@end

@implementation AdrenoMTLDevice (Pipeline)
// Shader-toolchain identity.
- (int)llvmVersion { return 32023; }                   // same value AppleParavirtDevice returns (0x7d17)
- (MTLTargetDeviceArchitecture *)targetDeviceArchitecture {
    MTLTargetDeviceArchitecture *a = [MTLTargetDeviceArchitecture new];
    a.cpuType = 0x01000017;                            // AIR (pick the air64 slice of fat metallibs)
    a.subType = 0xd;                                   // matches QuartzCore/SkyLight slice 0 subtype
    a.driverVersion = 1;
    a.version = (AdrenoArchVersion){1, 0, 0};
    return a;
}

// Compiler-service outputs -> variants.
- (id)newVertexVariantWithCompilerOutput:(id)o pipelineStatisticsOutput:(id)s {
    return [[AdrenoFunctionVariant alloc] initWithCompilerOutput:o stage:0];
}
- (id)newFragmentVariantWithCompilerOutput:(id)o pipelineStatisticsOutput:(id)s {
    return [[AdrenoFunctionVariant alloc] initWithCompilerOutput:o stage:1];
}
- (id)newComputeVariantWithCompilerOutput:(id)o pipelineStatisticsOutput:(id)s {
    return [[AdrenoFunctionVariant alloc] initWithCompilerOutput:o stage:2];
}
- (id)newTileVariantWithCompilerOutput:(id)o pipelineStatisticsOutput:(id)s functionType:(unsigned long long)t {
    return nil;                                        // no tile shaders
}

// Variants -> pipeline state objects.
- (id)newRenderPipelineWithDescriptor:(MTLRenderPipelineDescriptor *)d vertexVariant:(AdrenoFunctionVariant *)v
                      fragmentVariant:(AdrenoFunctionVariant *)f errorMessage:(NSString **)err {
    // Metal lowers the descriptor's vertex fetch into a generated entry. The
    // native CoreAnimation callback names it air.vertexFetchFunction; its AIR
    // calls the requested shader after loading the declared vertex attributes.
    // Compile that verified callback entry, preserving the fetch instructions.
    BOOL vertexEntryMatches = [v.input.entry isEqualToString:d.vertexFunction.name] ||
        (d.vertexDescriptor && v.input.stage == 0 &&
         [v.input.entry isEqualToString:@"air.vertexFetchFunction"]);
    if (!v.input || (d.fragmentFunction && !f.input) ||
        !vertexEntryMatches ||
        (d.fragmentFunction && ![f.input.entry isEqualToString:d.fragmentFunction.name])) {
        if (err) *err = v.inputError ?: f.inputError ?: @"Compiler variant does not match the render pipeline entry";
        return nil;
    }
    AdrenoRenderPipelineState *p = [[AdrenoRenderPipelineState alloc] initWithDevice:self pipelineStateDescriptor:d];
    p.vertexCode = [AdrenoShader compileInput:v.input descriptor:d safeConstlen:NO error:err];
    if (!p.vertexCode) return nil;
    // No fragment function (RenderBox's stencil-only path_edges): the built-in empty fragment stage, with every colour
    // write disabled by the captured fixed state (AdrenoDrawCommands.m), as Metal draws such a pipeline.
    AdrenoCompilerInput *fragmentInput = d.fragmentFunction ? f.input : [AdrenoCompilerInput emptyFragmentInput:err];
    if (!fragmentInput) return nil;
    p.fragmentCode = [AdrenoShader compileInput:fragmentInput descriptor:d safeConstlen:NO error:err];
    if (!p.fragmentCode) return nil;
    NSUInteger trim = [AdrenoShader trimVertex:p.vertexCode fragment:p.fragmentCode];
    if (trim == NSUIntegerMax) { if (err) *err = @"Missing shader constant budget"; return nil; }
    if (trim & 1) p.vertexCode = [AdrenoShader compileInput:v.input descriptor:d safeConstlen:YES error:err];
    if (trim & 2) p.fragmentCode = [AdrenoShader compileInput:fragmentInput descriptor:d safeConstlen:YES error:err];
    if (!p.vertexCode || !p.fragmentCode) return nil;
    p.programLinkage = [AdrenoShader linkVertex:p.vertexCode fragment:p.fragmentCode error:err];
    if (!p.programLinkage) return nil;
    p.vertex = v; p.fragment = f;
    return p;
}
- (id)newComputePipelineWithDescriptor:(MTLComputePipelineDescriptor *)d variant:(AdrenoFunctionVariant *)v
                          errorMessage:(NSString **)err {
    if (!v.input || ![v.input.entry isEqualToString:d.computeFunction.name]) {
        if (err) *err = v.inputError ?: @"Compiler variant does not match the compute pipeline entry";
        return nil;
    }
    AdrenoComputePipelineState *p = [[AdrenoComputePipelineState alloc] initWithDevice:self pipelineStateDescriptor:d];
    p.kernelCode = [AdrenoShader compileInput:v.input descriptor:nil safeConstlen:NO error:err];
    if (!p.kernelCode) return nil;
    p.kernel = v;
    return p;
}
- (id)newRenderPipelineWithTileDescriptor:(id)d tileVariant:(id)v errorMessage:(NSString **)err { return nil; }
@end
