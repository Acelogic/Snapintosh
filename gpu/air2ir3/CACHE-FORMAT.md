# air2ir3 precompiled cache, format version 5

This document describes the offline cache of compiled WindowServer pipelines, written with binding ABI 6 ([BINDING-ABI.md](BINDING-ABI.md)).

- `tools/sweep.py --cache <dir>` writes it; the Metal plug-in reads it.
- The key is computed three times, independently: by the C library (`air2ir3_compile`, the sidecar's `key`), by the reference implementation `tools/cachekey.py`, and from real `MTLRenderPipelineDescriptor` objects by `tools/pipelinekey.swift`.
- `tools/cachecheck.py` is the integrity checker.

## 1. Layout

```text
cache/
  manifest.json                       format_version, abi_version, compiler_id, chip_id, created
  entries/<key[0:2]>/<key>.json       one entry per key: the library's sidecar, byte for byte (section 3)
  entries/<key[0:2]>/<key>.src.json   provenance (sweep id, library, source, pipeline)
  blobs/<sha256>.ir3v                 ir3 variant blobs, content-addressed and shared between keys
  evidence/templates.jsonl            runtime-template compiles: evidence only, never looked up
```

- Every file is written to a temporary name and renamed, so a reader never sees a partial entry.
- Blobs are addressed by their own SHA-256; keys that compile to the same code share one blob (the full sweep produces about 35,000 keys and 15,000 blobs).
- **Runtime templates.** WindowServer builds SkyLight's five blur/shadow templates at run time from MSL text, so their AIR hash depends on the exact text WindowServer generates. Lookup entries for them would never hit. The plug-in compiles templates online through the library; the sweep keeps its template compiles only as evidence (`lookup: false`), and `cachecheck.py` fails if a template entry appears under `entries/`.

## 2. Key

```text
key = SHA-256( "AIR2IR3-CACHE-KEY\0"
             | u32 cache_format_version (5) | u32 abi_version (6) | u32 chip_id (0x44070041)
             | 32 bytes AIR hash
             | u32 stage (1 vertex, 2 fragment, 3 kernel)
             | u32 len | entry-point name (UTF-8, no NUL)
             | u32 n_fc | n_fc x { u16 index | u16 MTLDataType | u8 defined | u8 0 | u16 nbytes | value bytes }
             | u32 8    | 8 x u8 format class of colour attachments 0..7            (all 0 unless fragment)
             | for each attachment whose class is not 0, in order:
                 7 x u8 { enabled, rgbOp, alphaOp, srcRGB, dstRGB, srcAlpha, dstAlpha }   (all 0 if !enabled)
             | u32 16   | 16 x u8 draw-time format class of T# 0..15   (0 for a T# the function does not declare)
             | u8 safe_constlen                                  (1: ir3's safe_constlen variant) )
```

All integers are little-endian. The key is written as 64 lowercase hex characters.

### 2.1 Function and constants

- **AIR hash.** The SHA-256 of the bitcode module the compiler is given. For a function taken from a metallib this equals the function's `HASH` tag (`tools/corpus.py` recomputes it for every function, and the sweep checks it again), so the plug-in gets the same key whether it hashes the AIR or reads the tag.
- **Stage and entry.** A module can hold several functions (a runtime library holds `SimpleVertex` plus the blur), so stage (`MTLFunctionType`) and entry name (`MTLFunction.name`) keep their keys apart.
- **Function constants.** One record for every constant the function declares (`!air.function_constants`), sorted by index. `defined = 0` means the pipeline did not supply a value, and the record has no value bytes; "unset" and "set to 0" are different pipelines and get different keys. Values are stored in the constant's own type (bool/uchar/char 1 byte, short/ushort 2, int/uint 4, long/ulong 8, half binary16, float binary32, vectors n elements). `MTLDataType` uses the numbers from `Metal/MTLArgument.h`.
- **One canonical value.** The CLI (`--fc i=v`) and the C API (doubles) hand the compiler numbers; it converts each component once to the declared type: integers wrap to their width with C conversion toward zero (int `4294967295` is -1, char `200` is -56), bool is 1 for any non-zero value (NaN included), float and half round to nearest and keep NaN, inf and -0. A vector given one value repeats it. Key bytes, specialised code and sidecar all come from this value. (long / ulong values beyond 2^53 cannot pass through the C API's doubles.)
- **In the sidecar** (`reflection.function_constants[]`: `index`, `name`, `type`, `defined`, `value`, and `bits` for float / half): integer and bool values are JSON integers, exact over 64 bits; float and half values are the shortest decimal that reads back as the same value (always with `.` or an exponent, `-0.0` for negative zero) or the strings `"nan"`, `"-nan"`, `"inf"`, `"-inf"`; `bits` holds each component's IEEE pattern as hex (`"0x7fc00000"`, half `"0x7e00"`). The file is strict JSON, and the key recomputes from it for every value.

### 2.2 Format classes and blend

| Class | MTLPixelFormat | Code |
|---:|---|---|
| 0 | none, and every format the Adreno RB renders natively (bgra8Unorm 80, rgba16Float 115, r8Unorm 10, bgr10a2Unorm 94, ...) | independent of the format |
| 1 | BGR10_XR 554 | XR lowering: encode on write, decode on framebuffer fetch |
| 2 | BGRA10_XR 552 | XR lowering, dual-source blending where needed |
| 3 | 550, 551 (two-plane XR) | refused: conversion blit |
| 4 | 508, 510 (packed 10-bit YCbCr) | refused: conversion blit |
| 5 | 553, 555 (XR sRGB) | refused: conversion blit |

- For class 0 the key contains neither the format nor the blend state, so a real pipeline rendering into BGRA8, RGBA16Float or nothing gets the key the sweep wrote. For a lowered attachment the blend state changes the code and is part of the key.
- **Texture classes** use the same numbering and are draw-time key material (BINDING-ABI.md 3.3). All zero is the ordinary variant, used by a lookup at pipeline creation. Only T# the function declares as `texture(n)` arguments keep their class; the others are 0 in the key and never reach the translator.

### 2.3 What the key leaves out

- **Compiler identity.** It lives in `manifest.compiler_id` and every entry. A reader must discard the whole cache when the compiler id, format version or ABI version differs from its own. The id is `air2ir3-src-<16 hex>+mesa-<rev>-p<8 hex>-o<8 hex>+llvm-<version>` (`tools/compiler_id.py`, baked in by `src/build.sh`): sources, Mesa revision, Mesa patches, the options Mesa was configured with, and LLVM. The blob is a raw dump of Mesa's variant structure, so the reader must be built from the same Mesa with the same options.
- **Vertex descriptor, blend state of native attachments, depth/stencil, write masks, texture and sampler objects.** None changes the ir3 code; the command stream programs them.
- **The ir3 shader key**, which is all zero except `safe_constlen`. Any other non-zero bit must be added to the key material and bumps the format version.

### 2.4 Safe constlen, sample count, self-test

- `safe_constlen` is 1 for ir3's safe_constlen variant of a stage (BINDING-ABI.md 5.2), whose const file is capped at 100 vec4.
- The raster sample count is not key material: nothing in the compile reads it (ir3 consults `key.msaa` only below a6xx). MSAA pipelines use the single-sample entries.
- **Self-test vector.** `python3 tools/cachekey.py` computes the key for chip 0x44070041, an all-zero hash, fragment entry `f`; constants `{0: bool 1, 3: uchar4 (1,2,3,4), 5: float unset}`; RT0 = BGR10_XR (class 1) with premultiplied source-over, RT1 = bgra8Unorm; texture 2 of class 2 (declared) and texture 3 of class 1 (not declared, masked to 0); the safe_constlen variant. The result must be `84d0e040476266a13d34c957018ff089e40e642ce6963f79367156f8aa3881c1`.

## 3. Entry (`entries/<kk>/<key>.json`)

An entry file is exactly the bytes `air2ir3_compile` returns as `sidecar_json` for that key; `tools/apitest.py` recompiles a spread of entries through the C API and checks byte identity.

| Field | Meaning |
|---|---|
| `format_version`, `abi_version`, `compiler_id`, `chip_id` | must equal `manifest.json` |
| `key` | the key; also the file name |
| `variant_id` | `0x` + the first 16 hex characters of the key: a stable 64-bit id of the variant |
| `key_inputs` | `air_hash`, `stage`, `entry`, `rt_classes[8]`, `blend` (lowered attachments only), `texture_classes[16]` (masked), `safe_constlen`; with `reflection.function_constants` the key recomputes from these |
| `reflection` | bindings (with `present` and `used`), varyings, vertex attributes, render targets, `rt_lowering`, texture classes, system values, function constants, flags, `threadgroup_bytes`, `requires_no_attachment`, `warnings` |
| `constant_samplers` | `bitmask`, `set_id`, and `samplers[]` of `{slot, unique_id, air_word, a8xx_tex_samp[4], state}` |
| `blob` | `sha256`, `size`, `path`, `format` = Mesa `ir3_store_variant` (includes the binning VS) |
| `ir3` | `chip_id`, `gen`, `stats` (instructions, registers, constlen, `ntex`, `nsamp`, `num_samp`, `need_pixlod`, `per_sample_shading_if_msaa`, `pvtmem_size`, `max_ubo_index`, `ubo_slots`, `driver_table_ubo`, `driver_ubo_base`, `dual_src_blend`, ...), `const_budget`, `pvtmem`, `driver_ubos[]`, `sample_shading`, `inputs[]` / `outputs[]` |

`constant_samplers`: each sampler's `unique_id` is the first 8 bytes of `SHA-256("AIRSAMP1" || w0 || w1)`, big-endian; `set_id` is the first 8 bytes of SHA-256 over (`unique_id` as 8 bytes, then the slot byte) for each sampler in slot order; `a8xx_tex_samp` is the finished descriptor with the compare function in Adreno order.

## 4. Reader contract

1. Open `manifest.json`. If `format_version`, `abi_version`, `chip_id` or `compiler_id` differ from the reader's, ignore the whole cache and compile online.
2. Compute the key from the pipeline: AIR hash, `MTLFunctionType` and name; every declared constant with its value or `defined = 0`; for a fragment function the format class of each colour attachment and the blend state of lowered ones; the texture classes of the declared T# (all zero at pipeline creation, the bound textures' at draw time); `safe_constlen` 0, then 1 for each stage `air2ir3_trim_constlen` trims. `air2ir3_cache_key()` does this without compiling; `tools/pipelinekey.swift` shows the computation from a real descriptor.
3. Load `entries/<k[0:2]>/<k>.json`. Optionally check that the key recomputes from `key_inputs` and `reflection.function_constants` (float / half bytes from `bits`).
4. Load `blobs/<blob.sha256>.ir3v`, check its SHA-256, and call `ir3_retrieve_variant()`.
5. On a miss, compile online with `air2ir3_compile` (same library, same key) and optionally add the result.
6. Bind as BINDING-ABI.md says. Bindings with `present: false, used: true` are bound through, not a miss. If `reflection.requires_no_attachment` lists an index at which the pipeline has a colour attachment, refuse the pipeline (an online compile gives the same entry).

## 5. What is verified

- **Real pipelines hit.** `tests/pipelinekeys.py` builds real `MTLRenderPipelineDescriptor`s (CoreAnimation's 18 pipelines with exact constants; 28 SkyLight VS/FS pairs into R8, BGRA8 and RGBA16Float with blending off and on; CoreDisplay into formats 80, 90, 94 and 115 with `GPUPass` masks; 4x MSAA pairs; SkyLight into the XR formats) and derives keys from the descriptor objects: all 536 VS and FS keys from 268 descriptors hit. The runtime-template descriptors miss by design. One pipeline (`02_PBGRA_Xgfc`) needs a safe FS, whose key also hits.
- **CoreDisplay `GPUPass`.** It is specialised with two uint masks of which only bits 0-4 are tested, so the sweep compiles all 1,024 pairs of values in 0..31; a mask with a higher bit compiles online.
- **Three implementations agree.** The sweep checks the library against `cachekey.py` for every entry; the descriptor test checks Swift against the cache; `air2ir3_cache_key` equals the compile's key on every recompiled entry.
- **Integrity.** `tools/cachecheck.py cache --reload N` checks that every key recomputes; file name, `variant_id`, stage and entry agree; manifest fields match; blob hash, size and path match; sampler bitmask and `set_id` are consistent; every entry above `max_const_safe` has its safe sibling and every safe entry fits; private memory is within budget; no template entries exist. It then reloads N blobs through `ir3_retrieve_variant` and disassembles them.
- **No missing key inputs.** A real risk is an input that changes the code but is missing from the key; the sweep checks that identical keys always produced identical blobs.

## History

| Format | Change |
|---|---|
| 5 | Function-constant values exact in their declared type; strict JSON with `bits` (with ABI 6) |
| 4 | Same layout, new version words (ABI 4, then 5); `ntex`, `nsamp`, `sample_shading`, `requires_no_attachment` in the sidecar |
| 3 | `safe_constlen` byte; texture classes masked to declared T#; raster sample count removed; entry file = library sidecar byte for byte; `air2ir3_cache_key()` |
| 2 | Stage and entry name in the key; format classes instead of raw formats; blend state of lowered attachments; texture classes; templates moved to evidence; Mesa build options in the compiler id |
