# air2ir3 coverage: the WindowServer shader set

This document summarises what air2ir3 compiles, what it refuses, and how its output is checked. The numbers were measured with binding ABI 6 / cache format 5 on an Apple-silicon Mac running macOS 27 (26A428), target Adreno X2-90 (`chip_id 0x44070041`), Mesa `bbeb2dca9fee` with `patches/`, Homebrew LLVM 22. `tools/runall.sh` regenerates every number; each check writes its log and JSON into `results/`, and `tools/coverage.py` regenerates the sweep tables. The shader set is extracted locally from the host's SkyLight, CoreDisplay and QuartzCore metallibs (README.md, "Inputs").

"Compiles" means AIR -> NIR (validated) -> ir3 (RA-validated) -> encoded variant with no `UNSUPPORTED/ERROR`. Correctness evidence is in sections 3 to 6.

## 1. Headline

| Check | Result |
|---|---|
| Coverage targets (WindowServer's real set) | 32,125 of 32,136 compile; the 11 others are refused by design (base variants compiled with no constants set, whose unset constants decide their body) |
| CoreAnimation pipelines | 18/18 (36/36 stages) |
| Runtime templates | 183/183 |
| All 240 QuartzCore functions | 187 compile; 46 imageblock kernels and 7 unset-constant base variants refused |
| Real pipeline descriptors -> cache | 536/536 VS+FS keys from 268 `MTLRenderPipelineDescriptor`s hit |
| Online compile == cached entry | 518/518 sidecars byte-identical; `air2ir3_cache_key` == compile key |
| llvmpipe vs Metal | 9 WindowServer scenes + 24 XR scenes pass; 281 XR blend scenes and an 834-state XR grid within 1 code |
| NIR vs Mesa's SPIR-V front end | 10/11 NIR identical, 8/11 ir3 binaries identical, 8/8 renders bit-identical |
| Bindings vs Metal reflection | 4,436/4,436 sampled variants; QuartzCore 36/36 stages |
| Unset function constants vs Metal (randomized) | every compiled case matches Metal (present set, buffers read, pixel); the rest refused |
| Cache | about 35,200 keys, 14,840 blobs, 0 keys with two blobs, 0 errors, blobs reload through `ir3_retrieve_variant` |
| Clean-tree rebuild (`tools/cleanroom.sh`) | (key, blob) pairs identical to the working tree, same compiler id |

## 2. Coverage sweep (`tools/sweep.py`)

| Group | What | Variants | Compile |
|---|---|---:|---:|
| skylight_base | 33 SkyLight functions, no constants set | 33 | 23 |
| coredisplay | 4 CoreDisplay functions, no constants set | 4 | 3 |
| qc_pipelines | the 18 pipelines CoreAnimation builds under the Adreno device profile, exact constants | 36 | 36 |
| templates | SkyLight's runtime MSL templates, all instantiations | 183 | 183 |
| skylight_fc410 | structured constant sets | 410 | 410 |
| skylight_exhaustive | every combination of the boolean constants | 17,106 | 17,106 |
| shadow_structured | shadow blur radius / rim / glow selectors | 14,364 | 14,364 |
| coredisplay_gpupass | `GPUPass` with both masks in 0..31 | 1,024 | 1,024 |
| xr_targets, xr_textures | every WindowServer fragment function with XR attachments / textures | 152 | 152 |
| qc_all | all QuartzCore functions, no constants set | 240 | 187 |

After each group, every compile whose constlen exceeds `max_const_safe` is compiled again as its safe_constlen variant (about 2,200). The sweep takes a few minutes with parallel jobs. Every key is re-derived by `tools/cachekey.py`, the AIR hash is checked against the metallib `HASH` tag, and the compiler id against the binary's.

### 2.1 Refusals

| Group | Refused | Why |
|---|---:|---|
| skylight_base | 10 | an unset constant decides the body: `is_radius_eq_0` (3 shadow blurs), `enable_cc` (2), `flattened_above`, `enable_rgba_shadow`, `enable_border`, `single_channel`, `enable_mesh` |
| coredisplay | 1 | `GPUPass`: `optionalFeatures` decides a branch (CoreDisplay always sets the masks; that group compiles) |
| qc_pipelines | 0 | `02_PBGRA_Xgfc` FS compiles with `requires_no_attachment: [1, 2]` |
| qc_all | 53 | 46 imageblock kernels; 7 base variants whose unset constant decides the body (`fc_has_attachment_0`, `fc_base_color`, `fc_generic`) |

### 2.2 Imageblocks

46 of the 240 QuartzCore functions take an `imageblock` argument (Apple-GPU tile memory), which has no Adreno equivalent: tile shaders (`tile_average_luma*`, `tile_downsample_*`, `tile_simd_blur_*`, `backdrop_capture_compute_tile_*`) and compute blur, downsample and backdrop kernels (`compute_clear`, `compute_simd_blur_*`, `blur_copy_compute`, `downsample_*_compute*`, `narrow_blur_*_compute*`, `variable_blur_*`). CoreAnimation stays off them when the device answers NO to `supportsFamily:` Apple1-9, `supportsTileShaders` and the SIMD-group queries; it then draws the same effects with fragment pipelines (`downsample_4_frag_lph`, `narrow_blur_19_frag_lph`, `narrow_blur_27_frag_lph`). The device report must keep these answers. The five threadgroup-buffer kernels (`compute_apl`, `compute_apl_fast`, `compute_average_luma`, `compute_sum_luma`, `sum_apl_and_compute_dimming_factor`) compile.

## 3. Regression tests (`tests/regress.py`)

One test per known bug or design rule, including: cache-key fields; real pipeline keys hitting the cache; online compile through the C API; constexpr compare functions against Metal's `sample_compare`; XR lowering, corners, min/max and alpha clamp; driver UBOs and their placement; unset-constant semantics against Metal on fixtures and random shaders; presence predicates; threadgroup arguments; rebuild hygiene; safe_constlen; private memory sizing; online sidecar == cache entry; descriptor counts and `nsamp`; per-sample shading; exact sidecar constant values; poison and IEEE static-initialiser handling; float-to-char/short truncation; integer clamp and conversion; UBO slots below 16; derivatives of 16-bit values taken at 32 bits. The tests run with Mesa's per-pass NIR validation on (`AIR2IR3_NIR_VALIDATE=1`).

## 4. Execution: llvmpipe vs Metal (`tools/exec.py`)

Both sides render three frames and frame 2 is compared.

| Scene | VS | FS | Max abs diff (of 255) |
|---|---|---|---:|
| cd_texture_copy | ViewportToNDC | TextureCopy | 1 |
| sl_alpha_texture | SimpleVertex | AlphaTextureFragment | 0 |
| sl_grayscale | SimpleVertex | SimpleGrayscale | 0 |
| sl_shadow_composite_fc | SimpleVertex | ShadowCompositeFragment | 0 |
| sl_shadow_hblur_r12_soft | SimpleVertexShadow | ShadowHorizontalBlurFragment | 0 |
| sl_simple_color | SimpleColorVertex | SimpleColorFragment | 0 |
| sl_simple_texture | SimpleVertex | SimpleTextureFragment | 1 |
| sl_texture_tint | SimpleVertex | SimpleTextureTintFragment | 2 |
| tmpl_hbb_r8 | SimpleVertex | HorizontalBackgroundBlur | 1 |

The 24 XR scenes (FORMATS.md section 5) are within 2 XR10 codes, most at 0 or 1. The broad generated-uniform differential (`vtools/diffscenes.py`, 261 variants) passes 223; the 37 failures are isolated edge pixels, and 1 scene lacks vertex data in `nirexec`.

## 5. Function constants against Metal

The randomized generators (`tests/fcrand.py`, `fcv4.py`, `fcv5.py`, `fc6.py`) create fragment functions over bool, integer, float and half constants (branches, selects, switches, loops, `is_function_constant_defined`, presence predicates gating buffers, conversions, NaN / inf / -0 / range edges) and compare each specialisation with Metal: the reflection's present set, the buffers Metal's code reads (buffer k adds 2^k to a 1x1 render), and the rendered pixel.

| Runs | Cases | Result |
|---|---:|---|
| fcrand seeds 1, 2, 17, 23 (400 shaders x 24 cases each) | 38,400 | about 12,260 compiled, all == Metal; the rest refused on an unset constant |
| fcv4 (7 runs) | about 7,600 | 0 mismatches |
| fcv5 (16 runs) | 38,400 | 11,141 == Metal; refusals only on unset constants or poison conversions; 0 failures |
| fc6 predicate / shadow modes (6 runs) | 9,000 | 0 presence and 0 pixel mismatches |

Before refusing, Metal's own undef choices were emulated: LLVM's classic rules matched 826 of 960 random cases and a JumpThreading-style rule 772; reductions showed Metal taking opposite branches for the same shape depending on unrelated code. That is why unknown cases are refused rather than guessed (BINDING-ABI.md 3.7).

In fc6's body mode some pixel differences remain; every one inspected is a value Metal's own code leaves undefined under its fast-math flags in the body (a half overflow, `uint(-7.5)`, NaN). The body keeps Metal's flags by design.

## 6. Cache and descriptors

- **Real descriptors** (`tests/pipelinekeys.py`): CoreAnimation 18, SkyLight 154, XR 52, CoreDisplay 24 (16 `GPUPass` with masks), MSAA 20: every VS and FS key hits; 12 template pipelines miss by design. One pipeline needs a safe FS; the largest final VS+FS constlen is 168.
- **Descriptor counts**: no swept variant needs 16 T# or 16 S#; the maximum is 15 T# (`02_PBGRA_Xgfc` FS) and 4 S#, mean 2.53 T# and 1.54 S# per draw.
- **Per-sample shading**: flagged only for framebuffer-fetch functions (`InPlace*`, some QuartzCore) and XR shader blending.
- **Private memory**: no SkyLight base, CoreDisplay, QuartzCore, fc410, exhaustive or XR variant needs it. About 5,000 of the 14,364 structured shadow variants spill (radius 192 and above), needing a private-memory BO of 16 to 512 MiB; the worst spills 11,264 bytes per fiber.

## 7. Online compile time (`tools/apitest.py`)

Each template function compiled through `air2ir3_compile` on one compiler handle, median of 5, on the Mac host:

| Template | Instantiations | Median of medians (ms) | Slowest median (ms) |
|---|---:|---:|---:|
| HorizontalBackgroundBlur | 8 | 2.8 | 28.9 (r128) |
| ShadowHorizontalBlur | 54 | 7.8 | 174.5 (r712) |
| ShadowVerticalBlur | 54 | 8.5 | 169.4 (r712) |
| ShadowVerticalBlurRGBA | 54 | 8.5 | 172.4 (r712) |
| VerticalBackgroundBlurComposite | 8 | 4.1 | 31.2 (r128) |

SimpleVertex takes under 1 ms. Apple's MSL -> AIR front end (`xcrun metal`, including process start) takes 190-300 ms for the same templates. Compiles from 8 threads on one handle produce identical blobs and keys.

## 8. Largest variants

The QuartzCore generic fragment function (`02_PBGRA_Xgfc`) has about 40,900 instructions and constlen 512 (its safe variant 100). Shadow blurs reach about 19,100 instructions. Their speed on the Adreno is part of the ongoing performance work.
