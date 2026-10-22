/* SPDX-License-Identifier: MIT */
// Capture real Metal compiler callbacks without command queues or GPU submission.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>
#include <unistd.h>
#include <string.h>

extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (CompilerCapture)
- (id)initWithAcceleratorPort:(unsigned int)port;
@end

static NSString *digest(NSData *data) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
    NSMutableString *text = [NSMutableString string];
    for (unsigned i = 0; i < sizeof(hash); i++) [text appendFormat:@"%02x", hash[i]];
    return text;
}

static BOOL save(NSDictionary *report, NSString *path) {
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:&error];
    BOOL result = data && [data writeToFile:path options:NSDataWritingAtomic error:&error];
    if (!result) fprintf(stderr, "report: %s\n", error.description.UTF8String);
    return result;
}

static BOOL capture(id pipeline, NSString *key, NSString *entry, NSString *directory,
                    NSMutableArray *variants) {
    id variant = [pipeline valueForKey:key];
    id output = [variant valueForKey:@"compilerOutput"];
    NSMutableDictionary *row = [@{@"stage":key, @"entry":entry,
        @"variant_class":variant ? @(object_getClassName(variant)) : @"nil",
        @"output_class":output ? @(object_getClassName(output)) : @"nil"} mutableCopy];
    NSData *bytes = nil;
    if ([output isKindOfClass:[NSData class]]) {
        if ([output length] <= (16u << 20)) bytes = [output copy];
    } else {
        Class dispatchClass = NSClassFromString(@"OS_dispatch_data");
        if (dispatchClass && [output isKindOfClass:dispatchClass]) {
            dispatch_data_t data = (dispatch_data_t)output;
            if (dispatch_data_get_size(data) <= (16u << 20)) {
                const void *mappedBytes = NULL;
                size_t count = 0;
                dispatch_data_t mapped = dispatch_data_create_map(data, &mappedBytes, &count);
                if (mapped && count <= (16u << 20)) bytes = [NSData dataWithBytes:mappedBytes length:count];
            }
        }
    }
    row[@"bytes"] = @(bytes.length);
    if (bytes.length) {
        NSString *filename = [key stringByAppendingString:@".bin"];
        NSError *error = nil;
        if (![bytes writeToFile:[directory stringByAppendingPathComponent:filename]
                      options:NSDataWritingAtomic error:&error]) {
            row[@"error"] = error.description ?: @"write failed";
            [variants addObject:row];
            return NO;
        }
        row[@"file"] = filename;
        row[@"sha256"] = digest(bytes);
        row[@"first_bytes"] = [[bytes subdataWithRange:NSMakeRange(0, MIN(16, bytes.length))] description];
    }
    id input = [variant valueForKey:@"input"];
    NSData *air = [input valueForKey:@"airModule"];
    NSString *airEntry = [input valueForKey:@"entry"];
    NSString *airHash = [input valueForKey:@"airSHA256"];
    if (![air isKindOfClass:[NSData class]] || !air.length || air.length > (16u << 20) ||
        ![airEntry isEqualToString:entry] || ![airHash isEqualToString:digest(air)]) {
        row[@"error"] = @"No matching verified AIR module from production variant";
        [variants addObject:row];
        return NO;
    }
    NSString *airFile = [key stringByAppendingString:@".bc"];
    NSError *airError = nil;
    if (![air writeToFile:[directory stringByAppendingPathComponent:airFile]
                 options:NSDataWritingAtomic error:&airError]) {
        row[@"error"] = airError.description ?: @"AIR artifact write failed";
        [variants addObject:row];
        return NO;
    }
    row[@"air_file"] = airFile;
    row[@"air_bytes"] = @(air.length);
    row[@"air_sha256"] = airHash;
    row[@"air_entry"] = airEntry;
    id compiled = [pipeline valueForKey:[key stringByAppendingString:@"Code"]];
    NSData *code = [compiled valueForKey:@"code"];
    NSData *sidecar = [compiled valueForKey:@"sidecarData"];
    NSString *cacheKey = [compiled valueForKey:@"key"];
    if (![code isKindOfClass:[NSData class]] || !code.length ||
        ![sidecar isKindOfClass:[NSData class]] || !sidecar.length || cacheKey.length != 64) {
        row[@"error"] = @"Native pipeline has no owned compiled Adreno shader";
        [variants addObject:row];
        return NO;
    }
    NSString *codeFile = [key stringByAppendingString:@".ir3v"];
    NSString *sidecarFile = [key stringByAppendingString:@".sidecar.json"];
    if (![code writeToFile:[directory stringByAppendingPathComponent:codeFile] options:NSDataWritingAtomic error:&airError] ||
        ![sidecar writeToFile:[directory stringByAppendingPathComponent:sidecarFile] options:NSDataWritingAtomic error:&airError]) {
        row[@"error"] = airError.description ?: @"Compiled shader artifact write failed";
        [variants addObject:row];
        return NO;
    }
    row[@"compiled_file"] = codeFile;
    row[@"compiled_sha256"] = digest(code);
    row[@"sidecar_file"] = sidecarFile;
    row[@"sidecar_sha256"] = digest(sidecar);
    row[@"compiled_key"] = cacheKey;
    NSData *machine = [compiled respondsToSelector:@selector(machineCode)] ? [compiled valueForKey:@"machineCode"] : nil;
    NSData *program = [compiled respondsToSelector:@selector(programData)] ? [compiled valueForKey:@"programData"] : nil;
    if (![machine isKindOfClass:[NSData class]] || !machine.length || machine.length > (16u << 20) ||
        ![program isKindOfClass:[NSData class]] || !program.length || program.length > (32u << 20) ||
        [machine isEqualToData:code]) {
        row[@"error"] = @"Native pipeline has no owned GPU instructions and program metadata";
        [variants addObject:row];
        return NO;
    }
    NSString *gpuFile = [key stringByAppendingString:@".gpu.bin"];
    NSString *programFile = [key stringByAppendingString:@".program.json"];
    if (![machine writeToFile:[directory stringByAppendingPathComponent:gpuFile] options:NSDataWritingAtomic error:&airError] ||
        ![program writeToFile:[directory stringByAppendingPathComponent:programFile] options:NSDataWritingAtomic error:&airError]) {
        row[@"error"] = airError.description ?: @"GPU program artifact write failed";
        [variants addObject:row];
        return NO;
    }
    row[@"gpu_file"] = gpuFile; row[@"gpu_sha256"] = digest(machine); row[@"gpu_bytes"] = @(machine.length);
    row[@"program_file"] = programFile; row[@"program_sha256"] = digest(program);
    [variants addObject:row];
    return bytes.length > 0;
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc < 3 || argc > 5) return 64;
        BOOL constants = NO, varyings = NO;
        for (int i=3; i<argc; ++i) {
            if (!strcmp(argv[i], "--constants") && !constants) constants = YES;
            else if (!strcmp(argv[i], "--varyings") && !varyings) varyings = YES;
            else return 64;
        }
        if (varyings && !constants) return 64;
        NSString *bundlePath = [NSString stringWithUTF8String:argv[1]];
        NSString *directory = [NSString stringWithUTF8String:argv[2]];
        if (!bundlePath.isAbsolutePath || !directory.isAbsolutePath ||
            [[NSFileManager defaultManager] fileExistsAtPath:directory]) return 64;
        NSError *error = nil;
        if (![[NSFileManager defaultManager] createDirectoryAtPath:directory
             withIntermediateDirectories:YES attributes:nil error:&error]) return 73;
        NSString *reportPath = [directory stringByAppendingPathComponent:@"capture.json"];
        NSMutableDictionary *report = [@{@"schema":@"snapintosh-native-compiler-output/1",
            @"result":@"RUNNING", @"stage":@"register-device", @"pid":@(getpid()),
            @"host_version":[NSProcessInfo processInfo].operatingSystemVersionString,
            @"bundle":bundlePath, @"command_buffers_submitted":@0,
            @"boundary":@"Real host Metal compiler service and Adreno plug-in callbacks. Host AGX registration provider only; no Adreno execution or pixel proof."} mutableCopy];
        if (!save(report, reportPath)) return 73;
        report[@"function_constant_capture"] = @(constants);
        report[@"varying_capture"] = @(varyings);
        io_service_t accelerator = 0;
        int result = 1;
        @try {
            (void)MTLCopyAllDevices();
            NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
            if (![bundle loadAndReturnError:&error]) @throw [NSException exceptionWithName:@"BundleLoad" reason:error.description userInfo:nil];
            Class deviceClass = [bundle classNamed:@"AdrenoMTLDevice"];
            if (!deviceClass || ![deviceClass isSubclassOfClass:NSClassFromString(@"_MTLDevice")])
                @throw [NSException exceptionWithName:@"DeviceClass" reason:@"missing Adreno _MTLDevice subclass" userInfo:nil];
            accelerator = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
            if (!accelerator) @throw [NSException exceptionWithName:@"HostProvider" reason:@"no host IOAccelerator" userInfo:nil];
            id<MTLDevice> device = [[deviceClass alloc] initWithAcceleratorPort:accelerator];
            if (!device) @throw [NSException exceptionWithName:@"DeviceInit" reason:@"Adreno device init failed" userInfo:nil];
            MTLAddDevice(device);
            report[@"device_class"] = @(object_getClassName(device));
            report[@"stage"] = @"compile-library";
            save(report, reportPath);
            NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\n"
                "vertex float4 vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-1,-1),float2(1,-1),float2(0,1)}; return float4(p[i],0,1); }\n"
                "fragment float4 fs() { return float4(0.25,0.5,0.75,1); }\n"
                "kernel void cs(device uint *out [[buffer(0)]], uint i [[thread_position_in_grid]]) { out[i]=i+7; }\n";
            if (constants) source = @"#include <metal_stdlib>\nusing namespace metal;\n"
                "constant float scale [[function_constant(0)]];\n"
                "constant uint indexBias [[function_constant(1)]];\n"
                "vertex float4 vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-1,-1),float2(1,-1),float2(0,1)}; return float4(p[i]*scale,0,1); }\n"
                "fragment float4 fs() { return float4(scale,0.5,0.75,1); }\n"
                "kernel void cs(device uint *out [[buffer(0)]], uint i [[thread_position_in_grid]]) { out[i]=i+indexBias; }\n";
            if (varyings) source = @"#include <metal_stdlib>\nusing namespace metal;\n"
                "constant float scale [[function_constant(0)]];\n"
                "constant uint indexBias [[function_constant(1)]];\n"
                "struct V { float4 position [[position]]; float3 rgb; float2 uv; uint id [[flat]]; };\n"
                "vertex V vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-1,-1),float2(1,-1),float2(0,1)}; V o; o.position=float4(p[i]*scale,0,1); o.rgb=float3(float(i)*0.25,scale,0.75); o.uv=p[i]; o.id=i; return o; }\n"
                "fragment float4 fs(V i [[stage_in]]) { return float4(i.rgb+float3(i.uv*0.125,float(i.id)*scale),1); }\n"
                "kernel void cs(device uint *out [[buffer(0)]], uint i [[thread_position_in_grid]]) { out[i]=i+indexBias; }\n";
            if (![source writeToFile:[directory stringByAppendingPathComponent:@"input.metal"] atomically:YES encoding:NSUTF8StringEncoding error:&error])
                @throw [NSException exceptionWithName:@"SourceArtifact" reason:error.description userInfo:nil];
            report[@"source_sha256"] = digest([source dataUsingEncoding:NSUTF8StringEncoding]);
            id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
            if (!library) @throw [NSException exceptionWithName:@"LibraryCompile" reason:error.description userInfo:nil];
            report[@"function_names"] = library.functionNames;
            MTLFunctionConstantValues *values = [MTLFunctionConstantValues new];
            if (constants) {
                float scale = 0.5f;
                uint32_t bias = 13;
                [values setConstantValue:&scale type:MTLDataTypeFloat atIndex:0];
                [values setConstantValue:&bias type:MTLDataTypeUInt atIndex:1];
                report[@"requested_function_constants"] = @{@"0":@0.5, @"1":@13};
            }
            NSMutableDictionary *functions = [NSMutableDictionary dictionary];
            NSMutableDictionary *declarations = [NSMutableDictionary dictionary];
            report[@"function_constant_declarations"] = declarations;
            for (NSString *name in @[@"vs", @"fs", @"cs"]) {
                id<MTLFunction> plain = [library newFunctionWithName:name];
                id<MTLFunction> function = constants ? [library newFunctionWithName:name constantValues:values error:&error] : plain;
                if (!function) @throw [NSException exceptionWithName:@"FunctionSpecialization" reason:error.description userInfo:nil];
                functions[name] = function;
                NSMutableDictionary *stages = [NSMutableDictionary dictionary];
                for (NSString *label in @[@"original", @"specialized"]) {
                    id<MTLFunction> selected = [label isEqualToString:@"original"] ? plain : function;
                    NSMutableDictionary *fields = [NSMutableDictionary dictionary];
                    for (NSString *key in selected.functionConstantsDictionary) {
                        MTLFunctionConstant *fc = selected.functionConstantsDictionary[key];
                        fields[key] = @{@"index":@(fc.index), @"type":@(fc.type), @"required":@(fc.required)};
                    }
                    stages[label] = fields;
                }
                declarations[name] = stages;
            }
            report[@"stage"] = @"compile-render-pipeline";
            save(report, reportPath);
            MTLRenderPipelineDescriptor *descriptor = [MTLRenderPipelineDescriptor new];
            descriptor.vertexFunction = functions[@"vs"];
            descriptor.fragmentFunction = functions[@"fs"];
            descriptor.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
            id<MTLRenderPipelineState> render = [device newRenderPipelineStateWithDescriptor:descriptor error:&error];
            if (!render) @throw [NSException exceptionWithName:@"RenderPipelineCompile" reason:error.description userInfo:nil];
            NSMutableArray *variants = [NSMutableArray array];
            report[@"variants"] = variants;
            BOOL vertex = capture(render, @"vertex", @"vs", directory, variants);
            BOOL fragment = capture(render, @"fragment", @"fs", directory, variants);
            report[@"render_pipeline_class"] = @(object_getClassName(render));
            report[@"stage"] = @"compile-compute-pipeline";
            save(report, reportPath);
            id<MTLComputePipelineState> compute = [device newComputePipelineStateWithFunction:functions[@"cs"] error:&error];
            if (!compute) @throw [NSException exceptionWithName:@"ComputePipelineCompile" reason:error.description userInfo:nil];
            BOOL kernel = capture(compute, @"kernel", @"cs", directory, variants);
            report[@"compute_pipeline_class"] = @(object_getClassName(compute));
            if (![render respondsToSelector:NSSelectorFromString(@"programLinkage")])
                @throw [NSException exceptionWithName:@"MissingProgramLinkage" reason:@"Native render pipeline has no owned a8xx program linkage" userInfo:nil];
            report[@"program_linkage"] = [(id)render valueForKey:@"programLinkage"];
            if (![report[@"program_linkage"] isKindOfClass:[NSDictionary class]])
                @throw [NSException exceptionWithName:@"MissingProgramLinkage" reason:@"Native render pipeline returned invalid linkage" userInfo:nil];
            report[@"result"] = vertex && fragment && kernel ? @"NATIVE_COMPILER_OUTPUTS_CAPTURED" : @"EMPTY_OR_UNSUPPORTED_COMPILER_OUTPUT";
            report[@"stage"] = @"finished";
            result = vertex && fragment && kernel ? 0 : 2;
        } @catch (NSException *exception) {
            report[@"result"] = @"NATIVE_COMPILER_CAPTURE_FAILED";
            report[@"exception"] = @{@"name":exception.name ?: @"", @"reason":exception.reason ?: @""};
            result = 3;
        } @finally {
            if (accelerator) IOObjectRelease(accelerator);
            if (!save(report, reportPath)) result = 73;
        }
        printf("%s\n", [report[@"result"] UTF8String]);
        return result;
    }
}
