/* SPDX-License-Identifier: MIT */
// Runtime metadata only: no Metal device creation or GPU command execution.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <sys/sysctl.h>
#import <ptrauth.h>

static NSDictionary *imageInfo(const char *path) {
    if (!path) return @{};
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        if (strcmp(_dyld_get_image_name(i), path)) continue;
        const struct mach_header_64 *h = (const void *)_dyld_get_image_header(i);
        if (h->magic != MH_MAGIC_64) break;
        const struct load_command *c = (const void *)(h + 1);
        for (uint32_t n = 0; n < h->ncmds; n++) {
            if (c->cmd == LC_UUID) {
                const struct uuid_command *u = (const void *)c;
                NSUUID *uuid = [[NSUUID alloc] initWithUUIDBytes:u->uuid];
                return @{ @"path": @(path), @"uuid": uuid.UUIDString };
            }
            c = (const void *)((const char *)c + c->cmdsize);
        }
    }
    return @{ @"path": @(path) };
}

static NSArray *methods(Class cls) {
    unsigned count = 0;
    Method *list = class_copyMethodList(cls, &count);
    NSMutableArray *result = [NSMutableArray array];
    for (unsigned i = 0; i < count; i++) {
        Method m = list[i];
        const void *code = ptrauth_strip(method_getImplementation(m), ptrauth_key_function_pointer);
        Dl_info info = {0};
        dladdr(code, &info);
        NSMutableDictionary *entry = [@{
            @"selector": @(sel_getName(method_getName(m))),
            @"encoding": @(method_getTypeEncoding(m)),
        } mutableCopy];
        if (info.dli_fbase && info.dli_fname) {
            entry[@"image"] = imageInfo(info.dli_fname);
            entry[@"offset"] = @((uintptr_t)code - (uintptr_t)info.dli_fbase);
            NSString *selector = entry[@"selector"];
            if ([selector isEqualToString:@"_reserveKernelCommandBufferSpace:"] ||
                [selector isEqualToString:@"kernelCommandCollectTimeStamp"] ||
                [selector isEqualToString:@"beginSegment:"] ||
                [selector isEqualToString:@"endCurrentSegment"] ||
                [selector isEqualToString:@"commitAndReset"] || [selector isEqualToString:@"commit"]) {
                const struct mach_header_64 *h = info.dli_fbase;
                if (h->magic == MH_MAGIC_64) {
                    const struct load_command *c = (const void *)(h+1);
                    intptr_t slide = 0;
                    for (uint32_t n = 0; n < h->ncmds; n++) {
                        if (c->cmd == LC_SEGMENT_64) {
                            const struct segment_command_64 *s = (const void *)c;
                            if (!strcmp(s->segname, "__TEXT")) slide = (uintptr_t)h-s->vmaddr;
                        }
                        c = (const void *)((const char *)c+c->cmdsize);
                    }
                    c = (const void *)(h+1);
                    for (uint32_t n = 0; n < h->ncmds; n++) {
                        if (c->cmd == LC_SEGMENT_64) {
                            const struct segment_command_64 *s = (const void *)c;
                            uintptr_t start = s->vmaddr+slide, pc = (uintptr_t)code;
                            if ((s->initprot & VM_PROT_EXECUTE) && pc >= start && pc-start < s->vmsize) {
                                size_t bytes = MIN((uint64_t)256, s->vmsize-(pc-start));
                                NSMutableString *hex = [NSMutableString string];
                                for (size_t j = 0; j < bytes; j++) [hex appendFormat:@"%02x", ((const uint8_t *)code)[j]];
                                entry[@"code_address"] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)pc];
                                entry[@"code_hex"] = hex;
                                // Capture direct branch targets for the segment wrappers. Each
                                // read stays in this image's executable segment; no code runs.
                                if ([selector isEqualToString:@"beginSegment:"] ||
                                    [selector isEqualToString:@"endCurrentSegment"]) {
                                    NSMutableArray *targets = [NSMutableArray array];
                                    for (size_t j = 0; j+4 <= MIN(bytes, (size_t)64); j += 4) {
                                        uint32_t insn; memcpy(&insn, (const char *)code+j, 4);
                                        if ((insn & 0x7c000000) != 0x14000000) continue;
                                        int64_t displacement = ((int64_t)(int32_t)(insn << 6) >> 6) * 4;
                                        uintptr_t target = pc+j+displacement;
                                        if (target < start || target-start >= s->vmsize) continue;
                                        size_t length = MIN((uint64_t)512, s->vmsize-(target-start));
                                        NSMutableString *targetHex = [NSMutableString string];
                                        for (size_t k = 0; k < length; k++)
                                            [targetHex appendFormat:@"%02x", ((const uint8_t *)target)[k]];
                                        [targets addObject:@{ @"address": [NSString stringWithFormat:@"0x%llx", (unsigned long long)target],
                                            @"offset": @(target-(uintptr_t)h), @"code_hex": targetHex }];
                                        // These tiny wrappers end in a tail branch. Stop here
                                        // rather than interpreting the next method's bytes.
                                        if (!(insn & 0x80000000)) break;
                                    }
                                    entry[@"direct_targets"] = targets;
                                }
                            }
                        }
                        c = (const void *)((const char *)c+c->cmdsize);
                    }
                }
            }
        }
        [result addObject:entry];
    }
    free(list);
    [result sortUsingDescriptors:@[[NSSortDescriptor sortDescriptorWithKey:@"selector" ascending:YES]]];
    return result;
}

int main(void) {
    @autoreleasepool {
        const char *path = "/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU";
        if (!dlopen(path, RTLD_NOW | RTLD_LOCAL)) {
            fprintf(stderr, "IOGPU load failed: %s\n", dlerror()); return 1;
        }
        char build[128] = {0}; size_t size = sizeof(build);
        if (sysctlbyname("kern.osversion", build, &size, NULL, 0) || strcmp(build, "26A428")) {
            fprintf(stderr, "Requires host build 26A428; found %s\n", build); return 2;
        }
        int count = 0;
        Class *classes = objc_copyClassList((unsigned *)&count);
        NSMutableArray *records = [NSMutableArray array];
        for (int i = 0; i < count; i++) {
            Class cls = classes[i];
            NSString *name = @(class_getName(cls));
            if (![name hasPrefix:@"IOGPU"] ||
                !([name containsString:@"CommandBuffer"] || [name containsString:@"CommandEncoder"] ||
                  [name isEqualToString:@"IOGPUMetalResource"] || [name isEqualToString:@"IOGPUMetalBuffer"])) continue;
            unsigned n = 0;
            Ivar *ivars = class_copyIvarList(cls, &n);
            NSMutableArray *fields = [NSMutableArray array];
            for (unsigned j = 0; j < n; j++) {
                [fields addObject:@{ @"name": @(ivar_getName(ivars[j])),
                    @"offset": @(ivar_getOffset(ivars[j])), @"encoding": @(ivar_getTypeEncoding(ivars[j])) }];
            }
            free(ivars);
            Class parent = class_getSuperclass(cls);
            [records addObject:@{ @"class": name, @"size": @(class_getInstanceSize(cls)),
                @"superclass": parent ? @(class_getName(parent)) : @"",
                @"image": imageInfo(class_getImageName(cls)), @"ivars": fields,
                @"methods": methods(cls), @"class_methods": methods(object_getClass(cls)) }];
        }
        free(classes);
        [records sortUsingDescriptors:@[[NSSortDescriptor sortDescriptorWithKey:@"class" ascending:YES]]];
        NSDictionary *record = @{ @"host_build": @(build), @"classes": records,
            @"boundary": @"Host runtime metadata only; no guest framework identity or GPU execution proof." };
        NSError *error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:record options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
        if (!json) { fprintf(stderr, "%s\n", error.description.UTF8String); return 3; }
        fwrite(json.bytes, 1, json.length, stdout); putchar('\n');
    }
    return 0;
}
