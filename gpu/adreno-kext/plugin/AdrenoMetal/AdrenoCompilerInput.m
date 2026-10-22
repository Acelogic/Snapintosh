/* SPDX-License-Identifier: MIT */
#import "AdrenoCompilerInput.h"
#import <CommonCrypto/CommonDigest.h>
#import <dispatch/dispatch.h>
#include <dlfcn.h>
#include <mach-o/getsect.h>
#include <string.h>

static uint16_t u16(const unsigned char *p) {
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)u16(p) | (uint32_t)u16(p + 2) << 16;
}
static uint64_t u64(const unsigned char *p) {
    return (uint64_t)u32(p) | (uint64_t)u32(p + 4) << 32;
}
static BOOL within(uint64_t offset, uint64_t size, uint64_t total) {
    return offset <= total && size <= total - offset;
}
static id reject(NSString **error, NSString *message) {
    if (error) *error = message;
    return nil;
}

@implementation AdrenoCompilerInput
+ (instancetype)inputWithCompilerOutput:(id)output stage:(NSUInteger)stage
                                 entry:(NSString *)entry error:(NSString **)error {
    if (error) *error = nil;
    if (stage > 2) return reject(error, @"Unsupported Adreno shader stage");
    const NSUInteger limit = 16u << 20;
    NSData *data = nil;
    if ([output isKindOfClass:[NSData class]]) {
        if ([output length] > limit) return reject(error, @"Compiler output exceeds bound");
        data = [output copy];
    } else {
        Class dispatchClass = NSClassFromString(@"OS_dispatch_data");
        if (!dispatchClass || ![output isKindOfClass:dispatchClass])
            return reject(error, @"Unsupported compiler output object");
        dispatch_data_t raw = (dispatch_data_t)output;
        if (dispatch_data_get_size(raw) > limit) return reject(error, @"Compiler output exceeds bound");
        const void *bytes = NULL;
        size_t size = 0;
        dispatch_data_t mapped = dispatch_data_create_map(raw, &bytes, &size);
        if (!mapped || size > limit) return reject(error, @"Compiler output cannot be mapped");
        data = [NSData dataWithBytes:bytes length:size];
    }
    const unsigned char *bytes = data.bytes;
    uint64_t total = data.length;
    if (total < 88 || memcmp(bytes, "MTLB", 4) || u16(bytes + 6) != 2 || u16(bytes + 8) != 4)
        return reject(error, @"Expected native MTLB2.4 compiler output");
    if (u64(bytes + 16) != total) return reject(error, @"Metallib length mismatch");
    uint64_t offsets[4], sizes[4];
    for (unsigned i = 0; i < 4; i++) {
        offsets[i] = u64(bytes + 24 + i * 16);
        sizes[i] = u64(bytes + 32 + i * 16);
        // The function table's four-byte count is outside its declared size.
        uint64_t extra = i == 0 ? 4 : 0;
        if (offsets[i] < 88 || !within(offsets[i], extra, total) ||
            !within(offsets[i] + extra, sizes[i], total))
            return reject(error, @"Metallib section outside container");
        if (i && offsets[i] < offsets[i - 1] + sizes[i - 1] + (i == 1 ? 4 : 0))
            return reject(error, @"Overlapping metallib sections");
    }
    uint64_t at = offsets[0] + 4, end = at + sizes[0];
    uint32_t count = u32(bytes + offsets[0]);
    if (!count || count > 4096 || count > sizes[0] / 8)
        return reject(error, @"Invalid metallib function count");
    NSData *selected = nil;
    NSString *selectedName = nil;
    unsigned char selectedHash[CC_SHA256_DIGEST_LENGTH];
    for (uint32_t index = 0; index < count; index++) {
        if (!within(at, 4, end)) return reject(error, @"Short function entry");
        uint64_t entrySize = u32(bytes + at);
        if (entrySize < 8 || !within(at, entrySize, end))
            return reject(error, @"Function entry exceeds table");
        uint64_t stop = at + entrySize, tag = at + 4;
        NSData *hash = nil;
        NSString *name = nil;
        uint64_t moduleOffset = 0, moduleSize = 0;
        NSUInteger type = NSUIntegerMax;
        unsigned seen = 0;
        BOOL ended = NO;
        while (within(tag, 4, stop)) {
            const unsigned char *kind = bytes + tag;
            tag += 4;
            if (!memcmp(kind, "ENDT", 4)) { ended = YES; break; }
            if (!within(tag, 2, stop)) return reject(error, @"Short function tag");
            uint16_t length = u16(bytes + tag);
            tag += 2;
            if (!within(tag, length, stop)) return reject(error, @"Function tag exceeds entry");
            const unsigned char *value = bytes + tag;
            unsigned flag = 0;
            if (!memcmp(kind, "NAME", 4)) {
                flag = 1;
                if (length < 2 || value[length - 1] || memchr(value, 0, length - 1))
                    return reject(error, @"Malformed shader entry name");
                name = [[NSString alloc] initWithBytes:value length:length - 1 encoding:NSUTF8StringEncoding];
                if (!name.length) return reject(error, @"Invalid shader entry encoding");
            } else if (!memcmp(kind, "TYPE", 4)) {
                flag = 2;
                if (length != 1) return reject(error, @"Malformed shader stage tag");
                type = value[0];
            } else if (!memcmp(kind, "HASH", 4)) {
                flag = 4;
                if (length != CC_SHA256_DIGEST_LENGTH) return reject(error, @"Malformed shader hash");
                hash = [NSData dataWithBytes:value length:length];
            } else if (!memcmp(kind, "MDSZ", 4)) {
                flag = 8;
                if (length != 8) return reject(error, @"Malformed module size tag");
                moduleSize = u64(value);
            } else if (!memcmp(kind, "OFFT", 4)) {
                flag = 16;
                if (length != 24 || u64(value) >= sizes[1] || u64(value + 8) >= sizes[2])
                    return reject(error, @"Malformed module offsets");
                moduleOffset = u64(value + 16);
            }
            if (flag && (seen & flag)) return reject(error, @"Duplicate shader identity tag");
            seen |= flag;
            tag += length;
        }
        if (!ended || tag != stop || seen != 31 || moduleSize < 4 ||
            !within(moduleOffset, moduleSize, sizes[3]))
            return reject(error, @"Incomplete shader entry or module range");
        if (type == stage && (!entry || [entry isEqualToString:name])) {
            if (selected) return reject(error, @"Ambiguous compiler output entry");
            selected = [data subdataWithRange:NSMakeRange((NSUInteger)(offsets[3] + moduleOffset), (NSUInteger)moduleSize)];
            selectedName = name;
            memcpy(selectedHash, hash.bytes, sizeof(selectedHash));
        }
        at = stop;
    }
    if (at != end || !selected) return reject(error, @"No unique matching shader stage and entry");
    unsigned char actual[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(selected.bytes, (CC_LONG)selected.length, actual);
    if (memcmp(actual, selectedHash, sizeof(actual))) return reject(error, @"Shader module hash mismatch");
    const unsigned char *air = selected.bytes;
    uint64_t n = selected.length;
    if (u32(air) == 0x0b17c0de) {
        if (n < 20 || u32(air + 4) != 0 || u32(air + 8) < 20 || u32(air + 12) < 4 ||
            !within(u32(air + 8), u32(air + 12), n) || u32(air + u32(air + 8)) != 0xdec04342)
            return reject(error, @"Malformed LLVM bitcode wrapper");
    } else if (u32(air) != 0xdec04342) return reject(error, @"Compiler module is not LLVM bitcode");
    AdrenoCompilerInput *input = [AdrenoCompilerInput new];
    input->_airModule = selected;
    input->_entry = selectedName;
    input->_stage = stage;
    NSMutableString *hex = [NSMutableString string];
    for (unsigned i = 0; i < sizeof(actual); i++) [hex appendFormat:@"%02x", actual[i]];
    input->_airSHA256 = [hex copy];
    return input;
}
+ (instancetype)emptyFragmentInput:(NSString **)error {
    static AdrenoCompilerInput *cached;
    static NSString *failure;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Dl_info image;
        unsigned long size = 0;
        const unsigned char *air = dladdr((const void *)&reject, &image) && image.dli_fbase
            ? getsectiondata((const struct mach_header_64 *)image.dli_fbase, "__ADRENO", "__emptyfrag", &size) : NULL;
        if (!air || size < 20 || u32(air) != 0x0b17c0de || u32(air + 8) < 20 || !within(u32(air + 8), u32(air + 12), size) ||
            u32(air + u32(air + 8)) != 0xdec04342) { failure = @"The built-in empty fragment stage is missing or malformed"; return; }
        AdrenoCompilerInput *input = [AdrenoCompilerInput new];
        input->_airModule = [NSData dataWithBytes:air length:size];
        input->_entry = @"adreno_empty_fragment";
        input->_stage = 1;
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(air, (CC_LONG)size, digest);
        NSMutableString *hex = [NSMutableString string];
        for (unsigned i = 0; i < sizeof(digest); i++) [hex appendFormat:@"%02x", digest[i]];
        input->_airSHA256 = [hex copy];
        cached = input;
    });
    if (error) *error = cached ? nil : failure;
    return cached;
}
@end
