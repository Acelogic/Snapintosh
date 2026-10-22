/* SPDX-License-Identifier: MIT */
// Host timing of the WindowServer/CoreAnimation pipeline compile path through the Adreno plug-in.
// Same 18 recorded CoreAnimation descriptors and public Metal calls as qc-pipelines.m, plus:
//  - MTLSetShaderCachePath(<cache>) before any Metal use, so Metal's per-user function cache
//    (<cache>/com.apple.metal/16777239_13/functions.*) starts empty or is reused on purpose;
//  - wall time per stage: function specialisation, pipeline creation, and the plug-in's own
//    in-process part (air2ir3 + linkage, timed by wrapping the device callback);
//  - CPU time and faults of the MTLCompilerService instance(s) this process started.
// No command queue, no command buffer, no GPU work. Doc: docs/SHADER-COMPILE-PATH-20260928.md.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <mach/mach_time.h>
#import <libproc.h>
#import <sys/resource.h>
#import <dlfcn.h>

extern void MTLAddDevice(id<MTLDevice>);
extern void MTLSetShaderCachePath(NSString *);
@interface NSObject (CompileTimingDevice)
- (id)initWithAcceleratorPort:(unsigned int)port;
@end

static void require(BOOL ok, NSString *message) {
    if (!ok) @throw [NSException exceptionWithName:@"CompileTiming" reason:message userInfo:nil];
}
static double nowMs(void) {
    static mach_timebase_info_data_t tb;
    if (!tb.denom) mach_timebase_info(&tb);
    return (double)mach_absolute_time() * tb.numer / tb.denom / 1e6;
}
static double ticksMs(uint64_t ticks) {
    static mach_timebase_info_data_t tb;
    if (!tb.denom) mach_timebase_info(&tb);
    return (double)ticks * tb.numer / tb.denom / 1e6;
}
static NSString *digest(NSData *data) {
    require(data != nil, @"Missing hash input");
    unsigned char value[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, value);
    NSMutableString *text = [NSMutableString string];
    for (unsigned i = 0; i < sizeof(value); ++i) [text appendFormat:@"%02x", value[i]];
    return text;
}
static NSDictionary *selfUsage(void) {
    struct rusage u; getrusage(RUSAGE_SELF, &u);
    return @{@"user_ms":@(u.ru_utime.tv_sec * 1e3 + u.ru_utime.tv_usec / 1e3),
             @"system_ms":@(u.ru_stime.tv_sec * 1e3 + u.ru_stime.tv_usec / 1e3),
             @"minor_faults":@(u.ru_minflt), @"major_faults":@(u.ru_majflt)};
}
static NSSet<NSNumber *> *servicePids(void) {
    int n = proc_listallpids(NULL, 0);
    NSMutableSet *out = [NSMutableSet set];
    if (n <= 0) return out;
    pid_t *pids = calloc((size_t)n + 64, sizeof(pid_t));
    n = proc_listallpids(pids, (int)(((size_t)n + 64) * sizeof(pid_t)));
    for (int i = 0; i < n; ++i) {
        char name[2 * MAXCOMLEN + 1] = {0};
        if (proc_name(pids[i], name, sizeof name) > 0 && !strcmp(name, "MTLCompilerService")) [out addObject:@(pids[i])];
    }
    free(pids);
    return out;
}
static NSDictionary *serviceUsage(pid_t pid) {
    struct proc_taskinfo ti;
    if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof ti) != sizeof ti) return @{@"pid":@(pid), @"error":@"proc_pidinfo"};
    return @{@"pid":@(pid), @"user_ms":@(ticksMs(ti.pti_total_user)), @"system_ms":@(ticksMs(ti.pti_total_system)),
             @"faults":@(ti.pti_faults), @"pageins":@(ti.pti_pageins), @"cow_faults":@(ti.pti_cow_faults),
             @"resident_bytes":@(ti.pti_resident_size), @"threads":@(ti.pti_threadnum)};
}
static void save(NSDictionary *record, NSString *path) {
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:record options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
    require(data && [data writeToFile:path options:NSDataWritingAtomic error:&error], error.description ?: @"Report write failed");
}

// The row being compiled: thread-local for concurrent runs; serial runs also set the global, because
// Metal may call the device back on one of its own threads. Rows are owned by the record.
static __thread __unsafe_unretained NSMutableDictionary *activeRow;
static __unsafe_unretained NSMutableDictionary *serialRow;
static IMP originalPipeline;
static void timePluginCallback(Class deviceClass) {
    SEL selector = NSSelectorFromString(@"newRenderPipelineWithDescriptor:vertexVariant:fragmentVariant:errorMessage:");
    Method method = class_getInstanceMethod(deviceClass, selector);
    require(method != NULL, @"Missing Adreno pipeline callback");
    originalPipeline = method_getImplementation(method);
    IMP wrapper = imp_implementationWithBlock(^id(id device, MTLRenderPipelineDescriptor *desc, id vertex, id fragment, NSString **error) {
        double start = nowMs();
        id result = ((id (*)(id, SEL, MTLRenderPipelineDescriptor *, id, id, NSString **))originalPipeline)(device, selector, desc, vertex, fragment, error);
        double spent = nowMs() - start;
        NSMutableDictionary *row = activeRow ?: serialRow;
        row[@"plugin_ms"] = @([row[@"plugin_ms"] doubleValue] + spent);
        row[@"plugin_calls"] = @([row[@"plugin_calls"] unsignedIntegerValue] + 1);
        return result;
    });
    method_setImplementation(method, wrapper);
}

static id<MTLFunction> function(id<MTLLibrary> library, NSDictionary *spec, NSError **error) {
    require([spec[@"library"] isEqual:@"quartzcore"], @"Unexpected library");
    id<MTLFunction> plain = [library newFunctionWithName:spec[@"name"]];
    require(plain != nil, @"Missing function");
    NSArray *constants = spec[@"constants"];
    if (!constants.count) return plain;
    MTLFunctionConstantValues *values = [MTLFunctionConstantValues new];
    NSDictionary *types = @{@"bool":@(MTLDataTypeBool), @"uchar":@(MTLDataTypeUChar),
        @"uchar2":@(MTLDataTypeUChar2), @"uchar4":@(MTLDataTypeUChar4)};
    NSDictionary *counts = @{@"bool":@1, @"uchar":@1, @"uchar2":@2, @"uchar4":@4};
    for (NSDictionary *row in constants) {
        NSString *type = row[@"type"], *name = row[@"name"];
        MTLFunctionConstant *decl = plain.functionConstantsDictionary[name];
        require(types[type] && decl && decl.type == [types[type] unsignedIntegerValue], @"Unknown or mismatched constant");
        NSArray *elements = row[@"values"];
        require(elements.count == [counts[type] unsignedIntegerValue], @"Wrong constant width");
        uint8_t bytes[4] = {0};
        for (NSUInteger i = 0; i < elements.count; ++i) bytes[i] = (uint8_t)[elements[i] unsignedIntValue];
        [values setConstantValue:bytes type:decl.type withName:name];
    }
    return [library newFunctionWithName:spec[@"name"] constantValues:values error:error];
}

static MTLRenderPipelineDescriptor *descriptor(NSDictionary *item, id<MTLFunction> vertex, id<MTLFunction> fragment) {
    NSDictionary *spec = item[@"pipeline"];
    MTLRenderPipelineDescriptor *desc = [MTLRenderPipelineDescriptor new];
    desc.label = item[@"label"]; desc.vertexFunction = vertex; desc.fragmentFunction = fragment;
    desc.rasterSampleCount = [spec[@"sampleCount"] unsignedIntegerValue];
    require(desc.rasterSampleCount == 1, @"Unreviewed sample count");
    NSArray *attachments = spec[@"colorAttachments"];
    require(attachments.count == 1, @"Unreviewed attachment count");
    NSDictionary *attachment = attachments[0], *blend = attachment[@"blend"];
    require([attachment[@"format"] isEqual:@"bgra8Unorm"], @"Unreviewed attachment format");
    NSDictionary *factors = @{@"zero":@(MTLBlendFactorZero), @"one":@(MTLBlendFactorOne),
        @"oneMinusSourceAlpha":@(MTLBlendFactorOneMinusSourceAlpha)};
    require(factors[blend[@"srcRGB"]] && factors[blend[@"srcAlpha"]] && factors[blend[@"dstRGB"]] && factors[blend[@"dstAlpha"]] &&
        [blend[@"rgbOp"] isEqual:@"add"] && [blend[@"alphaOp"] isEqual:@"add"], @"Unreviewed blend state");
    MTLRenderPipelineColorAttachmentDescriptor *color = desc.colorAttachments[0];
    color.pixelFormat = MTLPixelFormatBGRA8Unorm; color.blendingEnabled = [blend[@"enabled"] boolValue];
    color.sourceRGBBlendFactor = [factors[blend[@"srcRGB"]] unsignedIntegerValue];
    color.sourceAlphaBlendFactor = [factors[blend[@"srcAlpha"]] unsignedIntegerValue];
    color.destinationRGBBlendFactor = [factors[blend[@"dstRGB"]] unsignedIntegerValue];
    color.destinationAlphaBlendFactor = [factors[blend[@"dstAlpha"]] unsignedIntegerValue];
    color.writeMask = [blend[@"writeMask"] unsignedIntegerValue];
    MTLVertexDescriptor *vd = [MTLVertexDescriptor vertexDescriptor];
    NSDictionary *formats = @{@"float2":@(MTLVertexFormatFloat2), @"float4":@(MTLVertexFormatFloat4), @"uchar4Normalized":@(MTLVertexFormatUChar4Normalized)};
    for (NSDictionary *a in spec[@"vertexAttributes"]) {
        NSUInteger index = [a[@"index"] unsignedIntegerValue], buffer = [a[@"buffer"] unsignedIntegerValue];
        require(index < 31 && buffer < 31 && formats[a[@"format"]], @"Unreviewed vertex attribute");
        vd.attributes[index].format = [formats[a[@"format"]] unsignedIntegerValue];
        vd.attributes[index].bufferIndex = buffer; vd.attributes[index].offset = [a[@"offset"] unsignedIntegerValue];
    }
    for (NSDictionary *a in spec[@"vertexLayouts"]) {
        NSUInteger buffer = [a[@"buffer"] unsignedIntegerValue];
        require(buffer < 31 && [a[@"step"] isEqual:@"perVertex"], @"Unreviewed vertex layout");
        vd.layouts[buffer].stepFunction = MTLVertexStepFunctionPerVertex;
        vd.layouts[buffer].stride = [a[@"stride"] unsignedIntegerValue];
    }
    if ([spec[@"vertexAttributes"] count]) desc.vertexDescriptor = vd;
    return desc;
}

// SHA-256 of what the draw path consumes, so cached and freshly compiled pipelines can be compared.
static NSDictionary *outputHashes(id pipeline) {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    for (NSString *stage in @[@"vertexCode", @"fragmentCode"]) {
        id shader = [pipeline valueForKey:stage];
        if (!shader) continue;
        for (NSString *field in @[@"machineCode", @"programData", @"sidecarData", @"code"]) {
            NSData *data = [shader valueForKey:field];
            if (data) out[[NSString stringWithFormat:@"%@.%@", stage, field]] = digest(data);
        }
    }
    NSDictionary *linkage = [pipeline valueForKey:@"programLinkage"];
    if (linkage) out[@"programLinkage"] = digest([NSJSONSerialization dataWithJSONObject:linkage options:NSJSONWritingSortedKeys error:NULL]);
    return out;
}

static NSArray *cacheFiles(NSString *root) {
    NSMutableArray *rows = [NSMutableArray array];
    NSDirectoryEnumerator *e = [[NSFileManager defaultManager] enumeratorAtPath:root];
    for (NSString *relative in e) {
        NSDictionary *a = e.fileAttributes;
        if ([a.fileType isEqual:NSFileTypeRegular]) [rows addObject:@{@"path":relative, @"bytes":@(a.fileSize)}];
    }
    return rows;
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc < 5 || argc > 7) {
            fprintf(stderr, "usage: %s BUNDLE SPEC.json OUTPUT.json CACHE_DIR [REPEAT] [THREADS]\n", argv[0]);
            return 64;
        }
        NSString *bundlePath = @(argv[1]), *specPath = @(argv[2]), *output = @(argv[3]), *cacheDir = @(argv[4]);
        NSUInteger repeat = argc >= 6 ? (NSUInteger)strtoul(argv[5], NULL, 10) : 1;
        NSUInteger threads = argc == 7 ? (NSUInteger)strtoul(argv[6], NULL, 10) : 1;
        if (!repeat || !threads || threads > 16) return 64;
        if ([[NSFileManager defaultManager] fileExistsAtPath:output]) return 73;
        // Must precede every Metal call: Metal ignores a later override once any cache folder was resolved.
        [[NSFileManager defaultManager] createDirectoryAtPath:cacheDir withIntermediateDirectories:YES attributes:nil error:NULL];
        NSArray *cacheBefore = cacheFiles(cacheDir);
        MTLSetShaderCachePath(cacheDir);
        NSString *libraryPath = @"/System/Library/Frameworks/QuartzCore.framework/Versions/A/Resources/default.metallib";
        NSMutableArray *rows = [NSMutableArray array];
        NSMutableDictionary *record = [@{@"status":@"RUNNING", @"rows":rows, @"bundle":bundlePath, @"specification":specPath,
            @"library":libraryPath, @"cache_dir":cacheDir, @"cache_files_before":cacheBefore, @"repeat":@(repeat), @"threads":@(threads),
            @"shader_cache_env":@{@"ADRENO_SHADER_CACHE":@(getenv("ADRENO_SHADER_CACHE") ?: ""),
                                  @"ADRENO_SHADER_CACHE_DIR":@(getenv("ADRENO_SHADER_CACHE_DIR") ?: "")},
            @"command_buffers_submitted":@0, @"a16_access":@NO,
            @"boundary":@"Host wall/CPU time of public Metal pipeline creation through the Adreno plug-in; no GPU work."} mutableCopy];
        io_service_t service = 0;
        int result = 1;
        @try {
            NSData *specData = [NSData dataWithContentsOfFile:specPath];
            record[@"spec_sha256"] = digest(specData);
            record[@"plugin_sha256"] = digest([NSData dataWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Contents/MacOS/AdrenoMetal"]]);
            NSString *compilerPath = [bundlePath stringByAppendingPathComponent:@"Contents/Frameworks/libAdrenoCompiler.dylib"];
            record[@"compiler_sha256"] = digest([NSData dataWithContentsOfFile:compilerPath]);
            NSArray *specs = [NSJSONSerialization JSONObjectWithData:specData options:0 error:NULL];
            require([specs isKindOfClass:[NSArray class]] && specs.count, @"Missing pipeline specifications");
            NSSet *pidsBefore = servicePids();
            record[@"usage_start"] = selfUsage();
            double t0 = nowMs();
            (void)MTLCopyAllDevices();
            record[@"copy_all_devices_ms"] = @(nowMs() - t0);
            // The plug-in dlopen()s this same file on its first compile; loading it here first times the
            // loader cost on its own (same image, reference counted).
            NSDictionary *u0 = selfUsage(); t0 = nowMs();
            void *handle = dlopen(compilerPath.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
            NSDictionary *u1 = selfUsage();
            require(handle != NULL, @"Compiler runtime dlopen failed");
            record[@"compiler_dlopen"] = @{@"ms":@(nowMs() - t0),
                @"minor_faults":@([u1[@"minor_faults"] longLongValue] - [u0[@"minor_faults"] longLongValue]),
                @"major_faults":@([u1[@"major_faults"] longLongValue] - [u0[@"major_faults"] longLongValue])};
            NSError *error = nil;
            NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
            require([bundle loadAndReturnError:&error], error.description ?: @"Bundle load failed");
            Class deviceClass = [bundle classNamed:@"AdrenoMTLDevice"];
            require(deviceClass && [deviceClass isSubclassOfClass:NSClassFromString(@"_MTLDevice")], @"Wrong device class");
            timePluginCallback(deviceClass);
            service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
            require(service != 0, @"Missing host registration provider");
            t0 = nowMs();
            id<MTLDevice> device = [[deviceClass alloc] initWithAcceleratorPort:service];
            require(device != nil, @"Device initialization failed");
            MTLAddDevice(device);
            record[@"device_init_ms"] = @(nowMs() - t0);
            t0 = nowMs();
            id<MTLLibrary> library = [device newLibraryWithURL:[NSURL fileURLWithPath:libraryPath] error:&error];
            require(library != nil, error.description ?: @"Library load failed");
            record[@"library_ms"] = @(nowMs() - t0);
            // Rows exist before any compile, so concurrent workers only fill their own row.
            for (NSUInteger round = 0; round < repeat; ++round)
                for (NSDictionary *item in specs)
                    [rows addObject:[@{@"label":item[@"label"], @"round":@(round), @"plugin_ms":@0, @"plugin_calls":@0} mutableCopy]];
            __block NSUInteger passed = 0;
            NSObject *printLock = [NSObject new];
            void (^run)(size_t) = ^(size_t index) {
                NSDictionary *item = specs[index % specs.count];
                NSDictionary *spec = item[@"pipeline"];
                NSMutableDictionary *row = rows[index];
                activeRow = row;
                @try {
                    NSError *stageError = nil;
                    double a = nowMs();
                    id<MTLFunction> vertex = function(library, spec[@"vertex"], &stageError);
                    require(vertex != nil, stageError.description ?: @"Vertex specialization failed");
                    double b = nowMs();
                    id<MTLFunction> fragment = function(library, spec[@"fragment"], &stageError);
                    require(fragment != nil, stageError.description ?: @"Fragment specialization failed");
                    double c = nowMs();
                    MTLRenderPipelineDescriptor *desc = descriptor(item, vertex, fragment);
                    id<MTLRenderPipelineState> pipeline = [device newRenderPipelineStateWithDescriptor:desc error:&stageError];
                    double d = nowMs();
                    require(pipeline != nil, stageError.description ?: @"Pipeline creation failed without NSError");
                    row[@"vertex_function_ms"] = @(b - a);
                    row[@"fragment_function_ms"] = @(c - b);
                    row[@"pipeline_ms"] = @(d - c);
                    row[@"metal_side_ms"] = @(d - c - [row[@"plugin_ms"] doubleValue]);
                    row[@"outputs"] = outputHashes(pipeline);
                    row[@"status"] = @"COMPILED";
                } @catch (NSException *exception) {
                    row[@"status"] = @"FAILED"; row[@"error"] = exception.reason ?: @"";
                }
                activeRow = nil;
                @synchronized (printLock) {
                    if ([row[@"status"] isEqual:@"COMPILED"]) ++passed;
                    printf("%s r%lu %-60s fn %.1f+%.1f ms pipe %.1f ms (plug-in %.1f ms)\n", [row[@"status"] UTF8String],
                        [row[@"round"] unsignedLongValue], [row[@"label"] UTF8String], [row[@"vertex_function_ms"] doubleValue],
                        [row[@"fragment_function_ms"] doubleValue], [row[@"pipeline_ms"] doubleValue], [row[@"plugin_ms"] doubleValue]);
                    fflush(stdout);
                }
            };
            double runStart = nowMs();
            if (threads == 1) {
                for (NSUInteger index = 0; index < rows.count; ++index) { serialRow = rows[index]; run(index); }
                serialRow = nil;
            } else {
                dispatch_queue_t queue = dispatch_queue_create("compile-timing", DISPATCH_QUEUE_CONCURRENT);
                dispatch_semaphore_t slots = dispatch_semaphore_create((long)threads);
                dispatch_group_t group = dispatch_group_create();
                for (NSUInteger index = 0; index < rows.count; ++index) {
                    dispatch_semaphore_wait(slots, DISPATCH_TIME_FOREVER);
                    dispatch_group_async(group, queue, ^{ run(index); dispatch_semaphore_signal(slots); });
                }
                dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
            }
            record[@"pipelines_wall_ms"] = @(nowMs() - runStart);
            Class shaderClass = [bundle classNamed:@"AdrenoShader"];
            if ([shaderClass respondsToSelector:NSSelectorFromString(@"cacheStatistics")])
                record[@"shader_cache"] = [shaderClass valueForKey:@"cacheStatistics"];
            record[@"usage_end"] = selfUsage();
            NSMutableSet *fresh = [servicePids() mutableCopy];
            [fresh minusSet:pidsBefore];
            NSMutableArray *services = [NSMutableArray array];
            for (NSNumber *pid in fresh) [services addObject:serviceUsage(pid.intValue)];
            record[@"compiler_services_started"] = services;
            record[@"cache_files_after"] = cacheFiles(cacheDir);
            record[@"passed"] = @(passed); record[@"attempted"] = @(rows.count);
            record[@"status"] = passed == rows.count ? @"TIMED" : @"FAILURES";
            result = passed == rows.count ? 0 : 2;
        } @catch (NSException *exception) {
            record[@"status"] = @"HARNESS_FAILED"; record[@"error"] = exception.reason ?: @"";
        } @finally {
            if (service) IOObjectRelease(service);
            save(record, output);
        }
        return result;
    }
}
