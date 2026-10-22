/* SPDX-License-Identifier: MIT */
#import "AdrenoShader.h"
#include "../../../air2ir3/src/air2ir3_api.h"
#import <CommonCrypto/CommonDigest.h>
extern void AdrenoDiagLine(NSString *line);   // AdrenoCommandBuffer.m: the lenient build's diagnostics file
#include <dlfcn.h>
#include <limits.h>
#include <mach-o/getsect.h>
#include <os/lock.h>
#include <os/log.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

static void *runtime;
static air2ir3_compiler *compiler;
static NSString *runtimeError;
#define DECLARE(name) static __typeof__(&name) p_##name
DECLARE(air2ir3_api_version);
DECLARE(air2ir3_abi_version);
DECLARE(air2ir3_cache_format_version);
DECLARE(air2ir3_compiler_create);
DECLARE(air2ir3_compile);
DECLARE(air2ir3_compile_program);
DECLARE(air2ir3_program_result_free);
DECLARE(air2ir3_result_free);
DECLARE(air2ir3_free);
DECLARE(air2ir3_trim_constlen);
DECLARE(air2ir3_cache_key);                            // optional: the result cache only
DECLARE(air2ir3_compiler_id);                          // optional: the result cache only
#undef DECLARE

static id reject(NSString **error, NSString *message) {
    if (error) *error = message;
    return nil;
}

static BOOL boundedField(NSDictionary *row, NSString *key, NSUInteger maximum, NSUInteger *value) {
    if (![row isKindOfClass:[NSDictionary class]] || ![row[key] isKindOfClass:[NSNumber class]]) return NO;
    double number = [row[key] doubleValue];
    if (!isfinite(number) || number < 0 || number > maximum || floor(number) != number) return NO;
    *value = (NSUInteger)number;
    return YES;
}

static BOOL prepare(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSBundle *bundle = [NSBundle bundleForClass:[AdrenoShader class]];
        NSString *path = [bundle.privateFrameworksPath stringByAppendingPathComponent:@"libAdrenoCompiler.dylib"];
        if (!path || ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
            runtimeError = @"Adreno compiler runtime is missing from the Metal bundle";
            return;
        }
        runtime = dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
        if (!runtime) { runtimeError = [NSString stringWithUTF8String:dlerror()] ?: @"Adreno compiler load failed"; return; }
#define LOAD(name) do { p_##name = (__typeof__(&name))dlsym(runtime, #name); \
    if (!p_##name) { runtimeError = @"Adreno compiler is missing " @#name; return; } } while (0)
        LOAD(air2ir3_api_version);
        LOAD(air2ir3_abi_version);
        LOAD(air2ir3_cache_format_version);
        LOAD(air2ir3_compiler_create);
        LOAD(air2ir3_compile);
        LOAD(air2ir3_compile_program);
        LOAD(air2ir3_program_result_free);
        LOAD(air2ir3_result_free);
        LOAD(air2ir3_free);
        LOAD(air2ir3_trim_constlen);
#undef LOAD
        p_air2ir3_cache_key = (__typeof__(&air2ir3_cache_key))dlsym(runtime, "air2ir3_cache_key");
        p_air2ir3_compiler_id = (__typeof__(&air2ir3_compiler_id))dlsym(runtime, "air2ir3_compiler_id");
        if (p_air2ir3_api_version() != AIR2IR3_API_VERSION || p_air2ir3_abi_version() != 6 ||
            p_air2ir3_cache_format_version() != 5) {
            runtimeError = @"Unsupported Adreno compiler API, binding ABI or cache format";
            return;
        }
        char *message = NULL;
        compiler = p_air2ir3_compiler_create(0, &message);
        if (!compiler) runtimeError = message ? [NSString stringWithUTF8String:message] : @"Adreno compiler initialization failed";
        p_air2ir3_free(message);
        // The compiler and dylib stay alive for all concurrent pipeline calls.
    });
    return compiler != NULL;
}

// ---- Compile-result cache (docs/SHADER-COMPILE-PATH-20260928.md).
// air2ir3_cache_key() names one compile exactly (CACHE-FORMAT.md 2: AIR hash, stage, entry, constants,
// colour format classes, lowered blend state, texture classes, safe_constlen). It leaves the compiler
// identity out, so every record carries that identity and the directory is namespaced by it.
// Lookup order: process memory, the read-only pack linked into this image (section __ADRENO,__shadercache,
// build.sh ADRENO_SHADER_CACHE_PACK; inside the signed Mach-O, so installing it adds no file), then the
// writable per-user directory ($DARWIN_USER_CACHE_DIR/org.snapintosh.AdrenoMetal/shader-cache/<namespace>/
// <kk>/<key>.amse; only with ADRENO_SHADER_CACHE_PERSIST, see below, or ADRENO_SHADER_CACHE_DIR on the host).
// A record must pass its length, SHA-256 and identity checks and then the same checks as a fresh compile
// result; anything else is a miss and the shader compiles online, exactly as without the cache.
// Record (little endian): "AMSE" u32 version=1 u32 id_length u32 0 | key[64] | u64 size[4] (sidecar,
// blob, code, program) | SHA-256 over bytes [0,112) + id + payloads | id | payloads.
// Pack: "AMSP" u32 version=1 u32 count u32 id_length | id | pad to 8 | count x (key[64] u64 offset
// u64 length), sorted by key | records.
enum { kRecordHeader = 144, kRecordDigest = 112, kPackHeader = 16, kPackIndexEntry = 80, kMaxIdLength = 1024 };
// Per-user records outside host runs (ADRENO_SHADER_CACHE_DIR): on unless built with
// ADRENO_SHADER_CACHE_PERSIST=0. (They were off while the draw path refused CoreAnimation's generic pipeline,
// whose vertex function writes point size, not clip distances: a persisted generic pipeline is ready at the next
// start's first frame and CA then draws with it. AdrenoDrawCommands.m now builds that path.)
#ifndef ADRENO_SHADER_CACHE_PERSIST
#define ADRENO_SHADER_CACHE_PERSIST 1
#endif
static const uint64_t kPayloadLimit[4] = {8u << 20, 16u << 20, 16u << 20, 32u << 20};

static BOOL cacheReady;
static NSString *cacheCompilerID;
static NSString *cacheDirectory;              // writable namespace directory; nil: no disk reads or writes
static NSData *cachePack;                     // mapped read-only pack; nil: none or rejected
static uint32_t cachePackCount;
static uint64_t cachePackIndex;
static NSCache<NSString *, AdrenoShader *> *cacheMemory;
static NSMutableDictionary<NSString *, dispatch_group_t> *cacheInflight;   // key -> compile in progress
static os_unfair_lock cacheInflightLock = OS_UNFAIR_LOCK_INIT;
static os_unfair_lock cacheStatsLock = OS_UNFAIR_LOCK_INIT;
static NSUInteger cacheHits[3], cacheMisses, cacheRejects, cacheWrites, cacheWriteErrors, cacheWaits;
static double cacheCompileMs;

static os_log_t cache_log(void) {
    static os_log_t log; static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("org.snapintosh.adreno", "shader-cache"); });
    return log;
}
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32; }
static void wr32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void wr64(uint8_t *p, uint64_t v) { wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32)); }
static void countStat(NSUInteger *counter, double compileMs) {
    os_unfair_lock_lock(&cacheStatsLock);
    if (counter) ++*counter;
    cacheCompileMs += compileMs;
    os_unfair_lock_unlock(&cacheStatsLock);
}

// Verified payloads of one record (sidecar, blob, code, program), or NO.
static BOOL parseRecord(NSData *record, NSString *key, NSData *__strong parts[4]) {
    const uint8_t *b = record.bytes;
    uint64_t n = record.length;
    const char *id = cacheCompilerID.UTF8String;
    size_t idLength = strlen(id);
    if (n < kRecordHeader || memcmp(b, "AMSE", 4) || rd32(b + 4) != 1 || rd32(b + 12) != 0 ||
        rd32(b + 8) != idLength || memcmp(b + 16, key.UTF8String, 64))
        return NO;
    uint64_t total = kRecordHeader + idLength, size[4];
    for (unsigned i = 0; i < 4; i++) {
        size[i] = rd64(b + 80 + 8 * i);
        if (!size[i] || size[i] > kPayloadLimit[i]) return NO;
        total += size[i];
    }
    if (total != n || memcmp(b + kRecordHeader, id, idLength)) return NO;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, b, kRecordDigest);
    CC_SHA256_Update(&ctx, b + kRecordHeader, (CC_LONG)(n - kRecordHeader));
    CC_SHA256_Final(digest, &ctx);
    if (memcmp(digest, b + kRecordDigest, sizeof digest)) return NO;
    uint64_t at = kRecordHeader + idLength;
    for (unsigned i = 0; i < 4; i++) {
        parts[i] = [record subdataWithRange:NSMakeRange((NSUInteger)at, (NSUInteger)size[i])];
        at += size[i];
    }
    return YES;
}

static NSData *buildRecord(NSString *key, NSData *__strong parts[4]) {
    const char *id = cacheCompilerID.UTF8String;
    size_t idLength = strlen(id);
    uint64_t total = kRecordHeader + idLength;
    for (unsigned i = 0; i < 4; i++) total += parts[i].length;
    NSMutableData *record = [NSMutableData dataWithLength:(NSUInteger)total];
    uint8_t *b = record.mutableBytes;
    memcpy(b, "AMSE", 4);
    wr32(b + 4, 1);
    wr32(b + 8, (uint32_t)idLength);
    memcpy(b + 16, key.UTF8String, 64);
    uint64_t at = kRecordHeader;
    memcpy(b + at, id, idLength);
    at += idLength;
    for (unsigned i = 0; i < 4; i++) {
        wr64(b + 80 + 8 * i, parts[i].length);
        memcpy(b + at, parts[i].bytes, parts[i].length);
        at += parts[i].length;
    }
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, b, kRecordDigest);
    CC_SHA256_Update(&ctx, b + kRecordHeader, (CC_LONG)(total - kRecordHeader));
    CC_SHA256_Final(b + kRecordDigest, &ctx);
    return record;
}

// The pack linked into this image, or nil.
static NSData *embeddedPack(void) {
    Dl_info image;
    if (!dladdr((const void *)&embeddedPack, &image) || !image.dli_fbase) return nil;
    unsigned long size = 0;
    uint8_t *bytes = getsectiondata((const struct mach_header_64 *)image.dli_fbase, "__ADRENO", "__shadercache", &size);
    return bytes && size ? [NSData dataWithBytesNoCopy:bytes length:size freeWhenDone:NO] : nil;
}

static NSString *openPack(NSData *pack) {
    if (!pack) return @"absent";
    const uint8_t *b = pack.bytes;
    uint64_t n = pack.length;
    if (n < kPackHeader || memcmp(b, "AMSP", 4) || rd32(b + 4) != 1) return @"not an AMSP version 1 pack";
    uint32_t count = rd32(b + 8), idLength = rd32(b + 12);
    const char *id = cacheCompilerID.UTF8String;
    if (idLength != strlen(id) || idLength > kMaxIdLength || kPackHeader + (uint64_t)idLength > n ||
        memcmp(b + kPackHeader, id, idLength))
        return @"built by a different compiler";
    uint64_t index = (kPackHeader + (uint64_t)idLength + 7) & ~7ull;
    if (count > (1u << 20) || index + (uint64_t)count * kPackIndexEntry > n) return @"index outside the pack";
    cachePack = pack; cachePackCount = count; cachePackIndex = index;
    return nil;
}

static NSData *packRecord(NSString *key) {
    if (!cachePack) return nil;
    const uint8_t *b = cachePack.bytes;
    const char *k = key.UTF8String;
    uint32_t lo = 0, hi = cachePackCount;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const uint8_t *e = b + cachePackIndex + (uint64_t)mid * kPackIndexEntry;
        int order = memcmp(e, k, 64);
        if (!order) {
            uint64_t offset = rd64(e + 64), length = rd64(e + 72), end = cachePackIndex + (uint64_t)cachePackCount * kPackIndexEntry;
            if (offset < end || length > cachePack.length || offset > cachePack.length - length) return nil;
            return [cachePack subdataWithRange:NSMakeRange((NSUInteger)offset, (NSUInteger)length)];
        }
        if (order < 0) lo = mid + 1; else hi = mid;
    }
    return nil;
}

static NSString *recordPath(NSString *key) {
    return [[cacheDirectory stringByAppendingPathComponent:[key substringToIndex:2]]
            stringByAppendingPathComponent:[key stringByAppendingPathExtension:@"amse"]];
}

static void prepareCache(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        const char *switchValue = getenv("ADRENO_SHADER_CACHE");      // "0": off (host A/B runs)
        if ((switchValue && !strcmp(switchValue, "0")) || !p_air2ir3_cache_key || !p_air2ir3_compiler_id) return;
        const char *id = p_air2ir3_compiler_id();
        if (!id || !*id || strlen(id) > kMaxIdLength) return;
        cacheCompilerID = @(id);
        cacheMemory = [NSCache new];
        cacheMemory.totalCostLimit = 64u << 20;
        cacheInflight = [NSMutableDictionary dictionary];
        NSString *identity = [NSString stringWithFormat:@"adreno-shader-cache record 1\n%s\napi %u abi %u format %u\n", id,
            p_air2ir3_api_version(), p_air2ir3_abi_version(), p_air2ir3_cache_format_version()];
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(identity.UTF8String, (CC_LONG)strlen(identity.UTF8String), digest);
        NSMutableString *space = [NSMutableString string];
        for (unsigned i = 0; i < 8; i++) [space appendFormat:@"%02x", digest[i]];
        NSString *base = nil;
        const char *override = getenv("ADRENO_SHADER_CACHE_DIR");     // host precompute and tests
        if (override && *override) base = @(override);
        else if (ADRENO_SHADER_CACHE_PERSIST) {
            char user[PATH_MAX];
            size_t n = confstr(_CS_DARWIN_USER_CACHE_DIR, user, sizeof user);
            if (n > 1 && n <= sizeof user) base = [@(user) stringByAppendingPathComponent:@"org.snapintosh.AdrenoMetal/shader-cache"];
        }
        cacheDirectory = [base stringByAppendingPathComponent:space];
        NSString *packError = openPack(embeddedPack());
        os_log(cache_log(), "shader cache ready: compiler %{public}s pack %{public}@ (%u records) directory %{public}@",
               id, packError ?: @"accepted", cachePack ? cachePackCount : 0, cacheDirectory ?: @"none");
        cacheReady = YES;
    });
}
static NSUInteger shaderCost(AdrenoShader *s) {
    return s.code.length + s.machineCode.length + s.programData.length + s.sidecarData.length;
}

@implementation AdrenoShader
// The checks every result passes, whether freshly compiled or read back from the cache.
+ (instancetype)shaderWithInput:(AdrenoCompilerInput *)input key:(NSString *)key sidecar:(NSData *)sidecar
                           blob:(NSData *)blob machineCode:(NSData *)machineCode programData:(NSData *)programData
                          error:(NSString **)error {
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:sidecar options:0 error:NULL];
    NSString *stage = @[@"vertex", @"fragment", @"kernel"][input.stage];
    NSDictionary *inputs = [json isKindOfClass:[NSDictionary class]] ? json[@"key_inputs"] : nil;
    if (![inputs isKindOfClass:[NSDictionary class]] ||
        ![inputs[@"air_hash"] isEqual:input.airSHA256] ||
        ![inputs[@"entry"] isEqual:input.entry] ||
        ![inputs[@"stage"] isEqual:stage] ||
        ![json[@"key"] isEqual:key])
        return reject(error, @"Adreno compiler result does not match the requested shader");
    NSDictionary *programJSON = [NSJSONSerialization JSONObjectWithData:programData options:0 error:NULL];
    NSDictionary *info = [programJSON isKindOfClass:[NSDictionary class]] ? programJSON[@"info"] : nil;
    if (![info isKindOfClass:[NSDictionary class]] ||
        ![programJSON[@"sidecar"] isEqual:json] ||
        ![info[@"size"] isKindOfClass:[NSNumber class]] ||
        [info[@"size"] unsignedLongLongValue] != machineCode.length)
        return reject(error, @"Adreno GPU program does not match the compiled variant");
    AdrenoShader *shader = [AdrenoShader new];
    shader->_code = blob;
    shader->_sidecarData = sidecar;
    shader->_sidecar = json;
    shader->_key = key;
    shader->_machineCode = machineCode;
    shader->_programData = programData;
    shader->_program = programJSON;
    return shader;
}

+ (AdrenoShader *)cachedShaderForKey:(NSString *)key input:(AdrenoCompilerInput *)input {
    AdrenoShader *shader = [cacheMemory objectForKey:key];
    if ([shader.key isEqualToString:key]) { countStat(&cacheHits[0], 0); return shader; }
    for (unsigned from = 0; from < 2; from++) {
        // Records in the writable directory are read, not mapped: a file cut short by anything but our
        // atomic writer must fail the checks, never fault the WindowServer process.
        NSData *record = from == 0 ? packRecord(key) : cacheDirectory ?
            [NSData dataWithContentsOfFile:recordPath(key) options:0 error:NULL] : nil;
        if (!record) continue;
        NSData *parts[4] = {nil};
        NSString *reason = nil;
        shader = parseRecord(record, key, parts) ?
            [self shaderWithInput:input key:key sidecar:parts[0] blob:parts[1] machineCode:parts[2] programData:parts[3] error:&reason] : nil;
        if (!shader) {
            countStat(&cacheRejects, 0);
            os_log_error(cache_log(), "shader cache %{public}s record %{public}@ rejected: %{public}@",
                         from ? "disk" : "pack", key, reason ?: @"length, digest or identity check");
            continue;
        }
        countStat(&cacheHits[1 + from], 0);
        [cacheMemory setObject:shader forKey:key cost:shaderCost(shader)];
        return shader;
    }
    return nil;
}

+ (void)storeShader:(AdrenoShader *)shader key:(NSString *)key compileMs:(double)ms {
    [cacheMemory setObject:shader forKey:key cost:shaderCost(shader)];
    countStat(&cacheMisses, ms);
    os_log(cache_log(), "shader cache miss %{public}@ %{public}@ compiled in %.1f ms", key, shader.sidecar[@"key_inputs"][@"entry"], ms);
    AdrenoDiagLine([NSString stringWithFormat:@"compile %@ %.0f ms key %@", shader.sidecar[@"key_inputs"][@"entry"], ms,
                    [key substringToIndex:MIN((NSUInteger)16, key.length)]]);
    if (!cacheDirectory) return;
    NSData *parts[4] = {shader.sidecarData, shader.code, shader.machineCode, shader.programData};
    NSString *path = recordPath(key);
    NSError *error = nil;
    BOOL written = [[NSFileManager defaultManager] createDirectoryAtPath:path.stringByDeletingLastPathComponent
        withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0755} error:&error] &&
        [buildRecord(key, parts) writeToFile:path options:NSDataWritingAtomic error:&error];
    countStat(written ? &cacheWrites : &cacheWriteErrors, 0);
    if (!written) os_log_error(cache_log(), "shader cache write %{public}@ failed: %{public}@", path, error.localizedDescription);
}

+ (NSDictionary *)cacheStatistics {
    // Read-only: the cache initialises on the first compile, once the compiler runtime is loaded. Doing it
    // here, before that, would find no runtime symbols and leave the cache off for the whole process.
    os_unfair_lock_lock(&cacheInflightLock);
    NSUInteger inflight = cacheInflight.count;
    os_unfair_lock_unlock(&cacheInflightLock);
    os_unfair_lock_lock(&cacheStatsLock);
    NSDictionary *stats = @{@"ready":@(cacheReady), @"compiler_id":cacheCompilerID ?: @"", @"directory":cacheDirectory ?: @"",
        @"pack_records":@(cachePack ? cachePackCount : 0), @"hits_memory":@(cacheHits[0]), @"hits_pack":@(cacheHits[1]),
        @"hits_disk":@(cacheHits[2]), @"misses":@(cacheMisses), @"rejects":@(cacheRejects), @"writes":@(cacheWrites),
        @"write_errors":@(cacheWriteErrors), @"waits":@(cacheWaits), @"inflight":@(inflight),
        @"miss_compile_ms":@(cacheCompileMs)};
    os_unfair_lock_unlock(&cacheStatsLock);
    return stats;
}

+ (instancetype)compileInput:(AdrenoCompilerInput *)input
                  descriptor:(MTLRenderPipelineDescriptor *)descriptor
                safeConstlen:(BOOL)safe error:(NSString **)error {
    if (error) *error = nil;
    if (!input || input.stage > 2) return reject(error, @"Missing verified compiler input");
    if (!prepare()) return reject(error, runtimeError ?: @"Adreno compiler unavailable");
    air2ir3_compile_info info = {0};
    info.struct_size = sizeof(info);
    info.air = input.airModule.bytes;
    info.air_size = input.airModule.length;
    info.entry = input.entry.UTF8String;
    info.stage = (uint32_t)input.stage + 1;
    info.safe_constlen = safe;
    info.raster_sample_count = descriptor ? (uint32_t)descriptor.rasterSampleCount : 1;
    if (input.stage == 1 && descriptor) {
        for (unsigned i = 0; i < 8; i++) {
            MTLRenderPipelineColorAttachmentDescriptor *a = descriptor.colorAttachments[i];
            if (a.pixelFormat > UINT32_MAX) return reject(error, @"Invalid color attachment format");
            info.color_pixel_format[i] = (uint32_t)a.pixelFormat;
            info.blend[i] = (air2ir3_blend){a.blendingEnabled, (uint8_t)a.rgbBlendOperation,
                (uint8_t)a.alphaBlendOperation, (uint8_t)a.sourceRGBBlendFactor,
                (uint8_t)a.destinationRGBBlendFactor, (uint8_t)a.sourceAlphaBlendFactor,
                (uint8_t)a.destinationAlphaBlendFactor, 0};
        }
    }
    // The compiler's own key names exactly this compile; a verified earlier result replaces it.
    prepareCache();
    NSString *key = nil;
    dispatch_group_t owner = nil, running = nil;
    if (cacheReady) {
        char keyHex[65] = {0};
        char *message = NULL;
        if (!p_air2ir3_cache_key(compiler, &info, keyHex, &message) && strnlen(keyHex, sizeof keyHex) == 64)
            key = @(keyHex);
        else
            os_log_error(cache_log(), "shader cache key failed for %{public}@: %{public}s", input.entry, message ?: "no key");
        p_air2ir3_free(message);
        AdrenoShader *cached = key ? [self cachedShaderForKey:key input:input] : nil;
        if (cached) return cached;
        if (key) {
            // One compile per key: a second request for the same shader (CoreAnimation's async pipeline
            // queue and a draw on the render thread) waits for the first instead of compiling again.
            os_unfair_lock_lock(&cacheInflightLock);
            running = cacheInflight[key];
            if (!running) {
                owner = dispatch_group_create();
                dispatch_group_enter(owner);
                cacheInflight[key] = owner;
            }
            os_unfair_lock_unlock(&cacheInflightLock);
            if (running) {
                countStat(&cacheWaits, 0);
                dispatch_group_wait(running, DISPATCH_TIME_FOREVER);
                cached = [self cachedShaderForKey:key input:input];
                if (cached) return cached;              // otherwise that compile failed: repeat it for its error
            }
        }
    }
    air2ir3_result result = {0};
    air2ir3_program_result program = {0};
    AdrenoShader *shader = nil;
    @try {
        if (p_air2ir3_compile_program(compiler, &info, &result, &program))
            return reject(error, result.error ? [NSString stringWithUTF8String:result.error] : @"Adreno shader compilation failed");
        if (!result.blob || !result.blob_size || result.blob_size > (16u << 20) ||
            !result.sidecar_json || !result.sidecar_size || result.sidecar_size > (8u << 20) ||
            strnlen(result.key_hex, sizeof(result.key_hex)) != 64)
            return reject(error, @"Invalid Adreno compiler result");
        if (!program.code || !program.code_size || program.code_size > (16u << 20) ||
            !program.program_json || !program.program_size || program.program_size > (32u << 20))
            return reject(error, @"Invalid Adreno GPU program export");
        NSString *resultKey = @(result.key_hex);
        shader = [self shaderWithInput:input key:resultKey
                               sidecar:[NSData dataWithBytes:result.sidecar_json length:result.sidecar_size]
                                  blob:[NSData dataWithBytes:result.blob length:result.blob_size]
                           machineCode:[NSData dataWithBytes:program.code length:program.code_size]
                           programData:[NSData dataWithBytes:program.program_json length:program.program_size]
                                 error:error];
        if (shader && key) {
            if ([key isEqualToString:resultKey]) [self storeShader:shader key:key compileMs:result.compile_ms];
            else os_log_error(cache_log(), "shader cache key %{public}@ differs from the compiled key %{public}@; not stored", key, resultKey);
        }
    } @finally {
        p_air2ir3_result_free(&result);
        p_air2ir3_program_result_free(&program);
        if (owner) {
            os_unfair_lock_lock(&cacheInflightLock);
            [cacheInflight removeObjectForKey:key];
            os_unfair_lock_unlock(&cacheInflightLock);
            dispatch_group_leave(owner);
        }
    }
    return shader;
}
+ (NSUInteger)trimVertex:(AdrenoShader *)vertex fragment:(AdrenoShader *)fragment {
    NSNumber *vs = vertex.sidecar[@"ir3"][@"const_budget"][@"constlen"];
    NSNumber *fs = fragment.sidecar[@"ir3"][@"const_budget"][@"constlen"];
    if (![vs isKindOfClass:[NSNumber class]] || (fragment && ![fs isKindOfClass:[NSNumber class]])) return NSUIntegerMax;
    return p_air2ir3_trim_constlen(compiler, vs.unsignedIntValue, fs.unsignedIntValue);
}
+ (NSDictionary *)linkVertex:(AdrenoShader *)vertex fragment:(AdrenoShader *)fragment error:(NSString **)error {
    // Mesa ir3_link_shaders(pack_vs_out=true), using our owned variant export.
    // Slot numbers are shader_enums.h from the pinned Mesa revision/ABI6.
    if (![vertex.program[@"type"] isEqual:@"VS"] ||
        (fragment && ![fragment.program[@"type"] isEqual:@"FS"]))
        return reject(error, @"Invalid Adreno shader stages for linkage");
    NSArray *outputs = vertex.program[@"outputs"];
    NSArray *inputs = fragment ? fragment.program[@"inputs"] : @[];
    NSUInteger total = 0;
    if (![outputs isKindOfClass:[NSArray class]] || outputs.count > 64 ||
        ![inputs isKindOfClass:[NSArray class]] || inputs.count > 64 ||
        (fragment && !boundedField(fragment.program, @"total_in", 128, &total)))
        return reject(error, @"Invalid Adreno shader linkage arrays");
    NSMutableDictionary<NSNumber *, NSNumber *> *registers = [NSMutableDictionary dictionary];
    for (NSDictionary *output in outputs) {
        NSUInteger slot, regid;
        if (!boundedField(output, @"slot", 255, &slot) || !boundedField(output, @"regid", 255, &regid) || registers[@(slot)])
            return reject(error, @"Invalid or duplicate Adreno vertex output");
        registers[@(slot)] = @(regid);
    }
    NSMutableArray *varyings = [NSMutableArray array];
    uint32_t mask[4] = {0};
    NSUInteger maxLocation = 0, primitive = 255, view = 255, clip0 = 255, clip1 = 255;
    for (NSDictionary *input in inputs) {
        NSUInteger slot, location, components, bary;
        if (!boundedField(input, @"slot", 255, &slot) || !boundedField(input, @"inloc", 255, &location) ||
            !boundedField(input, @"compmask", 15, &components) || !boundedField(input, @"bary", 1, &bary))
            return reject(error, @"Invalid Adreno fragment input");
        if (!components || !bary || location >= total) continue;
        NSUInteger length = 0;
        for (NSUInteger bits = components; bits; bits >>= 1) ++length;
        if (location + length > 128) return reject(error, @"Adreno varying locations overflow");
        NSNumber *output = registers[@(slot)];
        if (slot == 21) primitive = location;
        if (slot == 30) {
            if (output) return reject(error, @"Adreno view index must not be a vertex output");
            view = location;
        }
        if (slot == 17) clip0 = location;
        if (slot == 18) clip1 = location;
        for (NSUInteger j=0; j<length; ++j) {
            NSUInteger at = location + j;
            mask[at / 32] |= UINT32_C(1) << (at % 32);
        }
        maxLocation = MAX(maxLocation, location + length);
        NSUInteger regid = output ? output.unsignedIntegerValue : 252;
        if (regid != 252) {
            if (varyings.count == 32) return reject(error, @"Adreno varying exports exceed32");
            [varyings addObject:@{@"slot":@(slot), @"regid":@(regid), @"compmask":@(components), @"loc":@(location)}];
        }
    }
    return @{@"max_loc":@(maxLocation), @"cnt":@(varyings.count),
        @"varmask":@[@(mask[0]), @(mask[1]), @(mask[2]), @(mask[3])],
        @"primid_loc":@(primitive), @"viewid_loc":@(view), @"clip0_loc":@(clip0), @"clip1_loc":@(clip1),
        @"var":[varyings copy]};
}
@end
