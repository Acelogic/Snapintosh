/* SPDX-License-Identifier: MIT */
// Native CoreAnimation descriptors through the Adreno public compiler path.
// Failure inventory and qualification boundary: docs/ADRENO-QC-PIPELINES-20260928.md.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>

extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (QCCompilerCapture)
- (id)initWithAcceleratorPort:(unsigned int)port;
@end

static void require(BOOL ok, NSString *message) {
    if (!ok) @throw [NSException exceptionWithName:@"QCReproduction" reason:message userInfo:nil];
}
static NSString *digest(NSData *data) {
    require(data != nil, @"Missing hash input");
    unsigned char value[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, value);
    NSMutableString *text = [NSMutableString string];
    for (unsigned i = 0; i < sizeof(value); ++i) [text appendFormat:@"%02x", value[i]];
    return text;
}
static void save(NSDictionary *record, NSString *path) {
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:record options:NSJSONWritingPrettyPrinted error:&error];
    require(data && [data writeToFile:path options:NSDataWritingAtomic error:&error], error.description ?: @"Report write failed");
}
static NSMutableDictionary *activeRow;
static NSString *artifactPrefix;
static NSUInteger artifactIndex;
static IMP originalPipeline;
static void observePipeline(Class deviceClass) {
    SEL selector = NSSelectorFromString(@"newRenderPipelineWithDescriptor:vertexVariant:fragmentVariant:errorMessage:");
    Method method = class_getInstanceMethod(deviceClass, selector);
    require(method != NULL, @"Missing Adreno pipeline callback");
    originalPipeline = method_getImplementation(method);
    IMP observer = imp_implementationWithBlock(^id(id device, MTLRenderPipelineDescriptor *desc, id vertex, id fragment, NSString **error) {
        NSMutableArray *stages = [NSMutableArray array];
        for (NSString *stage in @[@"vertex", @"fragment"]) {
            id variant = [stage isEqual:@"vertex"] ? vertex : fragment;
            id input = [variant valueForKey:@"input"];
            NSData *air = [input valueForKey:@"airModule"];
            NSString *file = [NSString stringWithFormat:@"%@-%lu-%@.bc", artifactPrefix, (unsigned long)artifactIndex, stage];
            NSMutableDictionary *row = [@{@"stage":stage,
                @"requested_entry":[stage isEqual:@"vertex"] ? (desc.vertexFunction.name ?: @"") : (desc.fragmentFunction.name ?: @""),
                @"compiler_entry":[input valueForKey:@"entry"] ?: @"",
                @"input_error":[variant valueForKey:@"inputError"] ?: @""} mutableCopy];
            if (air) {
                require([air writeToFile:file options:NSDataWritingWithoutOverwriting error:NULL], @"AIR capture write failed");
                row[@"air_file"] = file; row[@"air_sha256"] = digest(air);
            }
            [stages addObject:row];
        }
        activeRow[@"native_variants"] = stages;
        return ((id (*)(id, SEL, MTLRenderPipelineDescriptor *, id, id, NSString **))originalPipeline)(device, selector, desc, vertex, fragment, error);
    });
    method_setImplementation(method, observer);
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
        require(types[type] && decl && decl.type == [types[type] unsignedIntegerValue],
            [@"Unknown or mismatched constant: " stringByAppendingString:name]);
        NSArray *elements = row[@"values"];
        require(elements.count == [counts[type] unsignedIntegerValue], @"Wrong constant width");
        uint8_t bytes[4] = {0};
        for (NSUInteger i=0; i<elements.count; ++i) {
            double value = [elements[i] doubleValue];
            require(value >= 0 && value <= ([type isEqual:@"bool"] ? 1 : 255) && value == (int)value,
                @"Constant outside byte range");
            bytes[i] = (uint8_t)value;
        }
        [values setConstantValue:bytes type:decl.type withName:name];
    }
    return [library newFunctionWithName:spec[@"name"] constantValues:values error:error];
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc != 4) return 64;
        NSString *bundlePath = @(argv[1]), *specPath = @(argv[2]), *output = @(argv[3]);
        if ([[NSFileManager defaultManager] fileExistsAtPath:output]) return 73;
        NSString *libraryPath = @"/System/Library/Frameworks/QuartzCore.framework/Versions/A/Resources/default.metallib";
        NSMutableArray *rows = [NSMutableArray array];
        NSMutableDictionary *record = [@{@"status":@"RUNNING", @"rows":rows,
            @"bundle":bundlePath, @"specification":specPath, @"library":libraryPath,
            @"command_buffers_submitted":@0, @"a16_access":@NO,
            @"boundary":@"Native host compiler and Adreno callbacks for recorded CoreAnimation descriptors; no GPU execution or exact guest-request identity."} mutableCopy];
        io_service_t service = 0;
        int result = 1;
        @try {
            NSData *specData = [NSData dataWithContentsOfFile:specPath];
            record[@"spec_sha256"] = digest(specData);
            record[@"metallib_sha256"] = digest([NSData dataWithContentsOfFile:libraryPath]);
            record[@"plugin_sha256"] = digest([NSData dataWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Contents/MacOS/AdrenoMetal"]]);
            record[@"compiler_sha256"] = digest([NSData dataWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Contents/Frameworks/libAdrenoCompiler.dylib"]]);
            NSError *error = nil;
            NSArray *specs = [NSJSONSerialization JSONObjectWithData:specData options:0 error:&error];
            require([specs isKindOfClass:[NSArray class]] && specs.count == 18, @"Expected18 recorded CoreAnimation pipelines");
            save(record, output);
            (void)MTLCopyAllDevices();
            NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
            require([bundle loadAndReturnError:&error], error.description ?: @"Bundle load failed");
            Class deviceClass = [bundle classNamed:@"AdrenoMTLDevice"];
            require(deviceClass && [deviceClass isSubclassOfClass:NSClassFromString(@"_MTLDevice")], @"Wrong device class");
            artifactPrefix = [output stringByDeletingPathExtension];
            observePipeline(deviceClass);
            service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
            require(service != 0, @"Missing host registration provider");
            id<MTLDevice> device = [[deviceClass alloc] initWithAcceleratorPort:service];
            require(device != nil, @"Device initialization failed");
            MTLAddDevice(device);
            record[@"device_class"] = @(object_getClassName(device));
            id<MTLLibrary> library = [device newLibraryWithURL:[NSURL fileURLWithPath:libraryPath] error:&error];
            require(library != nil, error.description ?: @"Library load failed");
            NSUInteger passed = 0;
            for (NSDictionary *item in specs) {
                NSDictionary *spec = item[@"pipeline"];
                NSMutableDictionary *row = [@{@"label":item[@"label"], @"descriptor":spec, @"stage":@"vertex-function"} mutableCopy];
                activeRow = row; artifactIndex = rows.count;
                [rows addObject:row]; save(record, output);
                @try {
                    error = nil;
                    id<MTLFunction> vertex = function(library, spec[@"vertex"], &error);
                    require(vertex != nil, error.description ?: @"Vertex specialization failed");
                    row[@"stage"] = @"fragment-function"; save(record, output);
                    error = nil;
                    id<MTLFunction> fragment = function(library, spec[@"fragment"], &error);
                    require(fragment != nil, error.description ?: @"Fragment specialization failed");
                    MTLRenderPipelineDescriptor *desc = [MTLRenderPipelineDescriptor new];
                    desc.label = item[@"label"]; desc.vertexFunction = vertex; desc.fragmentFunction = fragment;
                    desc.rasterSampleCount = [spec[@"sampleCount"] unsignedIntegerValue];
                    require(desc.rasterSampleCount == 1, @"Unreviewed sample count");
                    NSArray *attachments = spec[@"colorAttachments"];
                    require(attachments.count == 1, @"Unreviewed attachment count");
                    NSDictionary *attachment = attachments[0], *blend = attachment[@"blend"];
                    require([attachment[@"format"] isEqual:@"bgra8Unorm"] && [blend[@"rgbOp"] isEqual:@"add"] &&
                        [blend[@"alphaOp"] isEqual:@"add"] && [blend[@"srcRGB"] isEqual:@"one"] && [blend[@"srcAlpha"] isEqual:@"one"], @"Unreviewed attachment state");
                    NSDictionary *factors = @{@"zero":@(MTLBlendFactorZero), @"oneMinusSourceAlpha":@(MTLBlendFactorOneMinusSourceAlpha)};
                    require(factors[blend[@"dstRGB"]] && factors[blend[@"dstAlpha"]], @"Unreviewed blend factors");
                    MTLRenderPipelineColorAttachmentDescriptor *color = desc.colorAttachments[0];
                    color.pixelFormat = MTLPixelFormatBGRA8Unorm; color.blendingEnabled = [blend[@"enabled"] boolValue];
                    color.sourceRGBBlendFactor = color.sourceAlphaBlendFactor = MTLBlendFactorOne;
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
                    row[@"stage"] = @"render-pipeline"; save(record, output);
                    error = nil;
                    id<MTLRenderPipelineState> pipeline = [device newRenderPipelineStateWithDescriptor:desc error:&error];
                    require(pipeline != nil, error.description ?: @"Pipeline creation failed without NSError");
                    row[@"pipeline_class"] = @(object_getClassName(pipeline)); row[@"status"] = @"COMPILED";
                    ++passed;
                } @catch (NSException *exception) {
                    row[@"status"] = @"FAILED"; row[@"error"] = exception.reason ?: @"";
                }
                save(record, output);
                printf("%s %s\n", [row[@"status"] UTF8String], [row[@"label"] UTF8String]); fflush(stdout);
            }
            record[@"passed"] = @(passed); record[@"failed"] = @(specs.count-passed);
            record[@"status"] = passed == specs.count ? @"NATIVE_QC_PIPELINES_COMPILED" : @"NATIVE_QC_PIPELINES_REJECTED";
            result = passed == specs.count ? 0 : 2;
        } @catch (NSException *exception) {
            record[@"status"] = @"CAPTURE_FAILED"; record[@"error"] = exception.reason ?: @"";
        } @finally {
            if (service) IOObjectRelease(service);
            save(record, output);
        }
        return result;
    }
}
