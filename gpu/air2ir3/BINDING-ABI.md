# air2ir3 binding ABI, version 6

This is the contract between the shader compiler (air2ir3: Apple AIR -> NIR -> Mesa ir3) and the command-stream builder of the Adreno X2-90 Metal driver. It says where each Metal resource of a compiled function must be placed so the ir3 code finds it, and what the command stream must program from the variant.

The compiler implements it in `src/air2ir3.cpp`. Every sidecar records `abi_version: 6`, and the version is hashed into every cache key ([CACHE-FORMAT.md](CACHE-FORMAT.md)). Any change to a field, slot, key word or command-stream rule raises the version, so no stale binary is picked up; a correction that changes none of these still replaces cached code, because the compiler id changes.

Target: `chip_id 0x44070041` (Adreno X2-90, Mesa `freedreno_devices.py`, ir3 gen 8 / a8xx), Mesa revision `bbeb2dca9fee` plus the patches in `patches/`.

## 1. What the compiler hands over

A variant is one combination of: function, function-constant values, attachment format classes, blend state of lowered attachments, draw-time texture classes of the declared `texture(n)` arguments, and the `safe_constlen` bit (5.2). The raster sample count is not part of it: no step of the compile reads it, so an MSAA pipeline uses the single-sample variant.

- **Blob.** The `ir3_store_variant()` output (Mesa `ir3_disk_cache.c`): code, constant data, const-state layout and, for a vertex shader, the binning-pass VS too. Reload it with `ir3_retrieve_variant()`; `air2ir3 --verify-variant blob` does exactly that.
- **Sidecar.** JSON with `key`, `variant_id`, `key_inputs`, `reflection` (this ABI's view of the function), `constant_samplers` (3.5), `blob` (SHA-256 and size) and `ir3` (stats, `const_budget`, `pvtmem`, driver UBOs, input/output registers). CACHE-FORMAT.md section 3 gives the schema.
- **Program export** (optional, `air2ir3_compile_program`): the executable code bytes and a JSON description of the a8xx state the command builder needs, taken from the freshly compiled variant.

The compiler is a library with a stable C API (`src/air2ir3_api.h`, `build/libair2ir3.a`): `air2ir3_compile(compiler, {AIR, entry, stage, constants, attachment formats, blend, texture classes, safe_constlen}) -> {blob, sidecar, key}`, `air2ir3_cache_key()` (the key without compiling) and `air2ir3_trim_constlen()` (5.2). The plug-in calls it for runtime-compiled libraries and on every cache miss. `build/air2ir3` is a CLI over the same entry point, so an online compile and a cache entry are byte-identical.

The command stream is built from the blob plus the reflection; it never parses AIR. Every variant is compiled with the all-zero `ir3_shader_key` except `safe_constlen`, which is key material. Any other non-zero key bit would have to be added to the cache key first.

## 2. Summary table

| Metal object | Constraint | ir3 / hardware slot | Reflection `kind` |
|---|---|---|---|
| `constant T& x [[buffer(n)]]` | n <= 15 | UBO n (the stage's non-bindless UBO table, 16 entries on a8xx) | `ubo` |
| `device T* x [[buffer(n)]]` | n <= 30 | 64-bit VA read from the driver table, UBO `driver_table_ubo`, at byte `8*n` | `device_buffer` |
| `threadgroup T* x [[threadgroup(n)]]` (kernels) | n <= 30 | shared memory at the u32 offset in the driver table at byte `256 + 4*n` | `threadgroup_buffer` |
| `texture*d<..> [[texture(n)]]`, sample or read | n < 16 | T# n | `texture` |
| `texture*d<..> [[texture(n)]]`, write | n < 16 | ir3 image (IBO) n | `storage_texture` |
| `sampler s [[sampler(n)]]` | n < 16 | S# n | `sampler` |
| `constexpr sampler s(...)` | API + constexpr <= 16 | the lowest S# no API sampler of the function uses | `constexpr_sampler` |
| `[[color(n)]]` input (framebuffer fetch) | n < 8 | bindless set 4, descriptor `55 + n` | `fb_fetch` |
| `[[color(n)]]` output | n < 8 | `FRAG_RESULT_DATA0 + n`; XR attachments lowered (4.5) | `render_targets[]`, `rt_lowering[]` |
| `[[attribute(n)]]` | - | `VERT_ATTRIB_GENERIC0 + n` (VFD) | `vertex_attributes[]` |
| `[[user(name)]]` / generated varyings | <= 32 | `VARYING_SLOT_VAR0 + rank(name)` | `varyings[]` |
| `[[position]]`, `[[point_size]]` | - | `VARYING_SLOT_POS`, `VARYING_SLOT_PSIZ` | `writes_point_size` |
| `[[depth(any)]]`, `[[sample_mask]]` | - | `FRAG_RESULT_DEPTH`, `FRAG_RESULT_SAMPLE_MASK` | `writes_depth` |
| `constant` globals (tables) | - | ir3 constant data; if not pushed, the `constant_data` driver UBO | `constant_data_bytes` |
| ir3 driver parameters | - | the `driver_params` driver UBO (3.9) | `ir3.driver_ubos[]` |

Refused on purpose: argument buffers (`air.indirect_buffer`), visible function tables, imageblocks (Apple-GPU tile memory, COVERAGE.md), threadgroup arguments in vertex or fragment functions, `access::read_write` textures, app-written dual-source blending, attachment and texture format classes 3, 4 and 5, XR blend states outside 4.5, a variant in which an unset function constant decides anything in the body (3.7), driver UBOs other than those in 3.9, any UBO index above 15, and private memory over the budget of 3.10.

## 3. Resources

### 3.1 Constant buffers -> UBO n

- a8xx is used with 16 non-bindless UBO descriptors per stage: every UBO index a variant uses (constant buffers, the driver table, ir3's driver UBOs) is 0..15. A constant buffer above 15 is a compile error. This matches Mesa: freedreno advertises `max_const_buffers` = 16 for ir3, and Turnip binds application UBOs bindless. (On hardware, a driver table placed at UBO 31 read zeros; whether indices above 15 work at all is not established, so the ABI stays below 16.)
- `buffer(n)` in the `constant` address space is UBO n, written with `CP_LOAD_STATE6` / `ST6_UBO` as Mesa `fd6_emit_ubos` does: the buffer VA plus the Metal offset, and the size in vec4 units, rounded up.
- `setVertexBytes` / `setFragmentBytes` data is copied into a ring and bound as UBO n.
- Metal allows smaller constant-buffer offsets than Adreno accepts (Turnip advertises 64-byte alignment on this family). A misaligned offset goes through the setBytes path.
- The code loads used UBO ranges into the const file from its preamble (`ldc.k`); the command stream programs the const length from `ir3.stats.constlen` (vec4 units).

### 3.2 Device buffers -> the driver table

- `buffer(n)` in the `device` address space is read with global loads. Its base address comes from the stage's driver table: one little-endian u64 per Metal buffer index at byte `8*n`, n = 0..30, the buffer VA plus the Metal offset.
- The table is bound at `driver_table_ubo` = 1 + the highest constant-buffer index the function declares (0 when it declares none), so it never shares an index with a buffer the app may bind; it must be below 16 or the compile fails. Every `device_buffer` / `threadgroup_buffer` binding carries it, and `ir3.stats.driver_table_ubo` repeats it (-1 when no table is read).
- The table also holds the threadgroup offsets (3.8) at bytes 256..379. Bind 384 bytes, and rewrite it whenever a bound device buffer, its offset or a threadgroup length changes.

### 3.3 Textures, storage textures, draw-time texture classes

- `texture(n)` with access `sample` or `read` is the non-bindless T# n, built from the MTLTexture (format, swizzle, dimensions, mip range, IOSurface plane).
- For native formats the code does not depend on the texture format. For the XR formats it does (FORMATS.md): a `BGR10_XR` (554) texture is bound as a `B10G10R10A2_UNORM` view (class 1), a `BGRA10_XR` (552) texture as `R16G16B16A16_UNORM` with the B,G,R,A swizzle (class 2), and the shader decodes after sampling.
- Texture formats are not pipeline state, so at draw time the command stream builds the class vector of T# 0..15 (all zero is the ordinary variant) and uses the variant compiled for it, as Mesa ir3 does with its draw-time `fsampler_swizzles`. Only the T# the function declares count; the others are zeroed before the key is computed.
- clamp_to_zero / clamp_to_border on a class 1 or 2 texture needs a custom border colour in the view's u-domain: (c, c, c, c) for transparent black.
- Classes 3, 4 and 5 never reach the compiler; the command stream converts those textures first (FORMATS.md 4).
- `access::write` textures are ir3 images (IBO n, `ST6_IBO` as freedreno `fd6_emit_ibos`).

### 3.4 API samplers and descriptor counts

`sampler(n)` is S# n, built from the MTLSamplerState as Mesa `fd6_sampler_state_create<A8XX>` does. The compiler runs `nir_shader_gather_info` before ir3, as Turnip does, and reports:

- `ntex` = 1 + the highest non-bindless T# a texture instruction names: program `NTEX` and load that many T# (holes get a default descriptor).
- `nsamp` = 1 + the highest S# any texture instruction names. Every cat5 instruction carries an s#, including `isam` (`read()`), `getsize` and `getinfo`, so a `read()`-only function has `nsamp` 1. Program `NSAMP` and fill every S# below it that nothing else fills with the driver's default sampler.
- `num_samp` is ir3's own count, informational only: it adds one per framebuffer-read instruction even though that read uses a bindless descriptor.
- `need_pixlod` (FS): program `RB_PS_CNTL.PIXLODENABLE`, and `LODPIXMASK` from `need_full_quad`, as Turnip `tu6_emit_xs` does.

Separate T# and S# counts, plus constexpr samplers in the lowest free slots, keep the per-draw state small: no swept variant needs 16 of either (at most 15 T# and 4 S#).

### 3.5 Constexpr samplers

- Constexpr samplers (`@__air_sampler_state*`) go into the lowest S# slots no API sampler of the function uses, in sorted name order. API and constexpr samplers together are limited to 16.
- Each is described in the sidecar's `constant_samplers` with `slot`, `air_word`, the decoded `state`, the finished `a8xx_tex_samp[4]` descriptor and `unique_id` (the first 8 bytes of `SHA-256("AIRSAMP1" || w0 || w1)`, big-endian). The object also carries `bitmask` (`1 << slot` per sampler, the value `getConstantSamplersBitmasks` returns) and `set_id`. The command stream writes each descriptor into its slot on every pipeline bind.
- Compare functions: AIR stores MSL enum order (1 less, 2 less_equal, 3 greater, 4 greater_equal, 5 equal, 6 not_equal, 7 always, 8 never; 8 also means "none"). Adreno's `COMPARE_FUNC` order is NEVER 0, LESS 1, EQUAL 2, LEQUAL 3, GREATER 4, NOTEQUAL 5, GEQUAL 6, ALWAYS 7. The compiler translates; AIR 8 becomes NEVER, which is what Metal's `sample_compare` does with such a sampler.
- Open point: `clamp_to_zero` on a texture without alpha returns opaque black in Metal; force alpha to 1 in the texture swizzle for such formats.

### 3.6 Framebuffer fetch

- A `[[color(n)]]` input is read through a bindless texture descriptor: set 4, index `32 + 32 - 1 - 8 + n` = `55 + n`, following Mesa gallium `ir3_screen_init` / `fd6_build_bindless_state`. The command stream points FS bindless base 4 at an array of at least 64 descriptors and writes a descriptor of colour attachment n at `55 + n` (the UNORM view for an XR attachment). These are sysmem semantics; GMEM rendering needs Mesa's `patch_fb_read_gmem` treatment.
- The read's coordinate includes the layer (`nir_lower_fb_read`), so the FS has a `VARYING_SLOT_LAYER` input. When the VS does not write the layer, program that input's location INTERP_ZERO, as Mesa `emit_interp_state` does; FLAT returns whatever the VPC holds and the fetch reads zeros.

### 3.7 Function-constant gating and unset constants

- An argument or output gated by `[[function_constant(x)]]` whose predicate is false after specialisation is absent (`present: false`); a render target switched off is not written.
- **Unset constants.** A constant the pipeline does not set is LLVM `undef` in Metal, and Metal's optimiser decides what it becomes, differently from one shader to the next. A randomized differential test against Metal found no local rule that reproduces those choices. air2ir3 therefore compiles a variant only where the result provably does not depend on the unset constants, and refuses the rest:
  - Every use of an unset constant may independently be any value of its type. A value is folded only when it is the same for every such value: exhaustively for small domains (at most 2^16 combinations: bool, 8- and 16-bit), with LLVM `ConstantRange` / KnownBits for wider integers, never through float arithmetic. Anything that may be poison (violated `nsw`/`nuw`/`exact` flags, over-wide shifts, division by a possible 0, fast-math flags on a possible NaN/inf) is never folded.
  - **Body.** If an undefined value decides a branch, switch or used select, or reaches a returned value, a store or a call, the variant is refused: `the value of unset function constant <name> (index i) decides a branch in the function body ...: set the constant`.
  - **Presence.** The static initialiser that computes the predicates (`__metal_implicit_fc_pred_N`), binding-index expressions and constant shadows is evaluated with the same model. A gating predicate is accepted only when it is a direct copy of an unset constant (the argument is absent, as Metal measures) or has the same value for every value of the unset constants. Every other one is refused where it gates an argument. A binding-index expression that depends on an unset constant is a compile error.
  - **Undecided predicates.** With every constant set, a predicate the evaluation cannot decide is refused, never guessed and never taken from an optimised copy. AIR conversions in the initialiser fold as Metal folds them (float to integer truncates toward zero; `bool(x)` is `x != 0`, NaN true; a NaN or out-of-range conversion is poison and is refused). The initialiser is evaluated with IEEE values; an operation that creates an inf or NaN from finite operands under Metal's fast-math flags is poison and refused. With every constant set, globals the initialiser stores get the evaluated values, so the body reads what decided presence. Other AIR calls (popcount, clamp, floor, ...) in an initialiser are refused, as Metal itself rejects them.
  - **Bit patterns.** A constant is built in its declared type and read as the type of the load, so `isnan`, `isinf`, `signbit` and `as_type` of a float constant see its bits.
  - **Colour outputs: `requires_no_attachment`.** When such a predicate gates a `[[color(k)]]` output, the write cannot be observed on a pipeline with no attachment k. The compiler leaves the output unwritten and lists k in `reflection.requires_no_attachment`; the plug-in must refuse a pipeline that has attachment k. This keeps CoreAnimation's `02_PBGRA_Xgfc` pipeline, which leaves `fc_dest_index` unset with one attachment.
  - In the WindowServer set this refuses only base variants compiled with no constants set (COVERAGE.md); every variant that sets its constants compiles. Whether WindowServer ever leaves such a constant unset is not known; if it does, pipeline creation fails with the message above.
- **Absent but read.** If specialised code still reads an argument whose predicate is false, the binding keeps its slot with `present: false, used: true` and a warning. The command stream binds the app's object at that index, or a zero buffer / null descriptor. This is not a refusal.

### 3.8 Threadgroup buffer arguments (kernels)

- Static threadgroup variables occupy `reflection.threadgroup_bytes` from offset 0; the command stream places argument buffers after them at 16-byte-aligned offsets, writes each offset as a u32 into the driver table at `256 + 4*n`, and programs the total shared size at dispatch (Turnip programs it from `v->shared_size`).
- ir3's `max_waves` was computed with the static size only; the command stream recomputes occupancy from the total.

### 3.9 Driver-owned UBOs

ir3 allocates its own UBOs from `num_ubos`, which the compiler sets to 1 + the highest constant buffer the function declares (used or not), or 1 + `driver_table_ubo` when the driver table is in use. `ir3.stats.driver_ubo_base` reports it, so a driver UBO never collides with an app binding. `ir3.driver_ubos[]` lists them and `ir3.stats.max_ubo_index` gives the highest index used:

| `kind` | What | How to bind (Mesa reference) |
|---|---|---|
| `constant_data` | constant tables not pushed to the const file | UBO = code IOVA + `constant_data_offset`, size `size_vec4` (Turnip `tu6_emit_xs`) |
| `driver_params` | ir3 driver parameters (a8xx loads them through the preamble) | a buffer holding Mesa's `ir3_driver_params_vs` / `_fs` / `_cs`, filled per draw or dispatch (Turnip `tu_emit_compute_driver_params`, freedreno `emit_driver_params`) |

Anything else (primitive map/param UBOs, driver params for another stage, any index above 15) fails the compile. WindowServer's own set (SkyLight, CoreDisplay, CoreAnimation's pipelines) uses UBO indices up to 7 and no driver UBO.

### 3.10 Private memory

ir3 spills registers and large local arrays to per-fiber private memory (`ldp`/`stp`). The large WindowServer shadow blurs need it: their AIR is already unrolled (up to 665 texture fetches), and they spill up to 11,264 bytes per fiber. `ir3.pvtmem` says what to allocate:

| Field | Meaning |
|---|---|
| `pvtmem_size` | bytes per fiber (max of the variant and its binning VS) |
| `pvtmem_per_wave` | per-wave layout (ir3 chooses it only for compute) |
| `per_fiber_size` | `next_pow2(align(pvtmem_size, 512))`, as Turnip `tu_setup_pvtmem` |
| `per_sp_size` | `align(per_fiber_size * fibers_per_sp, 4096)`; X2-90 `fibers_per_sp` = 4096 |
| `total_size` | `num_sp_cores * per_sp_size`; X2-90 `num_sp_cores` = 8 |
| `budget` | 512 MiB (16 KiB per fiber); a variant over it fails the compile |

The command stream follows Turnip: one lazily created BO per layout, grown in powers of two; for each stage with private memory, `SP_xS_PVT_MEM_PARAM.MEMSIZEPERITEM`, `SP_xS_PVT_MEM_BASE`, `SP_xS_PVT_MEM_SIZE` (`TOTALPVTMEMSIZE`, `PERWAVEMEMLAYOUT`) and `SP_xS_PVT_MEM_STACK_OFFSET`; zeros elsewhere.

## 4. Stage interface

### 4.1 Varyings

Each stage numbers its varyings by the rank of the name in sorted order: slot k is `VARYING_SLOT_VAR0 + k` (ir3 slot `32 + k`). The command stream links VS outputs to FS inputs by name; an FS input without a matching VS output is a pipeline-creation error, as in Metal. Interpolation (`perspective`, `no_perspective`, `flat`; `center`, `centroid`, `sample`) comes from the FS input. The limit is 32 varyings.

### 4.2 Vertex attributes

`[[attribute(n)]]` is `VERT_ATTRIB_GENERIC0 + n`; `vertex_attributes[]` gives the shader-side type. The VFD is programmed from the MTLVertexDescriptor, and format conversion happens in the fetch hardware.

### 4.3 System values

| AIR | NIR | Notes |
|---|---|---|
| `vertex_id` | `load_vertex_id` | includes `vertexStart` / `baseVertex`, as Metal's does |
| `instance_id` | `load_instance_id` | whether the hardware value includes `baseInstance` is unverified |
| `base_vertex`, `base_instance`, compute sizes | driver parameters (3.9) | |
| `position` (FS) | `load_frag_coord` | upper-left origin, pixel centres at .5 |
| `front_facing`, `sample_id`, `point_coord` | matching intrinsics | |

Conventions: clip-space z in [0, 1]; NDC +y up, viewport mapping it to row 0 at the top; flat varyings from the first vertex.

### 4.4 Outputs

- `[[color(n)]]` is `FRAG_RESULT_DATA0 + n`, base type in `render_targets[]`; a target that is only read is listed with `written: false`.
- App dual-source blending (`[[color(n), index(1)]]`) is a compile error; the compiler uses dual-source itself for XR lowering.
- **Constant output components** (a8xx `alias.rt`): ir3 writes compile-time-constant components of a colour output from the preamble, and the output's `aliased_components` says which. The command stream must set `SP_PS_OUTPUT_CONST_CNTL.ENABLED` and `SP_PS_OUTPUT_CONST_MASK` and count outputs with only aliased components, as Mesa `emit_fs_outputs` does; otherwise those components come from registers the code never writes.

### 4.5 Colour attachment format classes and XR lowering

The code depends on the attachment format for the XR formats. Format classes: 0 native (any format the RB renders, or none), 1 `BGR10_XR` (554), 2 `BGRA10_XR` (552), 3 two-plane XR (550), 4 packed 10-bit YCbCr, 5 XR sRGB. For classes 1 and 2 the variant has one `reflection.rt_lowering[]` entry per lowered attachment:

- `view_format`: bind the memory as `B10G10R10A2_UNORM` (class 1) or `R16G16B16A16_UNORM` with the B,G,R,A swap (class 2).
- `hw_blend`: the blend state to program. A zero source factor becomes one, SRC_* becomes SRC1_* with `dual_source`, and a min or max channel carries ONE/ONE (Metal ignores factors there).
- `dual_source`: the shader writes the raw colour to colour(0) index 1; set `DUAL_COLOR_IN_ENABLE`. Adreno dual-source drives colour(0) only, so it is never used on another attachment or while another attachment is written.
- `blend_in_shader`: program RB blending off and bind the attachment for framebuffer fetch (3.6). The shader reads and decodes the destination, blends exactly as Metal (source clamped to the XR range, source alpha clamped to [0, 1] wherever it is a factor and, on BGRA10_XR, as the alpha value too; BGRA10_XR alpha result clamped to [0, 1]) and stores the exact code. Used for premultiplied source-over, additive, subtract, reverse subtract, destination factors, source colour as an RGB factor, and any case that would need dual-source with another attachment written.
- `hw_write_mask_clear: "A"` (class 1): 554 stores no alpha.
- Clears of a lowered attachment are given in the u-domain: u = k·v + c per channel.

The shader clamps the source to [-384/510, 638/510] = [-0.752941, 1.25098] (codes 0..1022, the range Apple documents for XR10). Blend-colour and source-1 factors on an add/subtract channel are refused. Classes 3, 4 and 5 are refused; the command stream uses the conversion-blit paths of FORMATS.md section 4.

### 4.6 Per-sample shading on multisampled pipelines

On a pipeline with `rasterSampleCount > 1` the fragment shader must run once per sample when it reads `[[sample_id]]` or the sample position, has a sample-interpolated varying, or reads a colour attachment (including XR shader blending, which reads at the current sample). Metal does exactly this. ir3's own flag misses these cases for AIR input, so the sidecar carries `ir3.sample_shading` (`per_sample_if_msaa`, `reasons`, `ir3_sample_shading`) and `ir3.stats.per_sample_shading_if_msaa`. Program it as Turnip does for `fs->sample_shading` (`RB_PS_SAMPLEFREQ_CNTL`, `GRAS_LRZ_PS_SAMPLEFREQ_CNTL`, FRAGCOORD_SAMPLE, sample IJ, late Z).

## 5. Checklist for the command-stream builder

### 5.1 Per pipeline and draw

1. Write the UBO descriptors for every `ubo` binding, including bind-through bindings (3.7).
2. Write the driver table at `driver_table_ubo` when a `device_buffer` or `threadgroup_buffer` binding exists.
3. Bind every `ir3.driver_ubos[]` entry.
4. Write T#, IBO and S# at the bindings the reflection lists, and the constexpr descriptors at their slots on every pipeline bind. Program NTEX from `ntex` and NSAMP from `nsamp`, with default descriptors in unfilled slots below them; ignore `num_samp`. For the FS, program `PIXLODENABLE` / `LODPIXMASK`.
5. At draw time, compute the texture class vector over the declared T#; if it is not all zero, use the matching variant and u-domain border colours (3.3).
6. For a FS with framebuffer fetch, point bindless base 4 at the attachment descriptors at `55 + n`.
7. For a lowered attachment, bind the view format and program `hw_blend` (off when `blend_in_shader`), dual-source and the write mask. Convert class 3/4/5 attachments and textures.
8. Run the const budget (5.2) and use the safe variant of every stage it trims. Program const length, register footprint and wave size from that variant; for kernels, the total shared size.
9. Size and bind private memory from `ir3.pvtmem`.
10. Link varyings by name and program the VFD.
11. If the pipeline is multisampled and the FS reports `per_sample_if_msaa`, program per-sample shading.
12. A refused variant is a pipeline-creation error with the compiler's message. Also refuse a pipeline with a colour attachment at an index listed in `requires_no_attachment`.
13. Program `SP_PS_OUTPUT_CONST_CNTL/MASK` from `aliased_components`.
14. Program a FS layer (or viewport) input the VS does not write as INTERP_ZERO.
15. Refuse any variant whose `ir3.stats.ubo_slots` is not 16 (`--test-ubo-slots` is for hardware probes only).

### 5.2 Pipeline const budget (safe_constlen)

The VS and FS const files share one limit. On a6xx and later each stage may use up to 512 vec4, the pipeline up to `max_const_pipeline` = 512, and a "safe" stage up to `max_const_safe` = 100. CoreAnimation's `02_PBGRA_Xgfc` needs VS 16 + FS 512 = 528.

The compiler follows Turnip: every stage above `max_const_safe` reports `ir3.const_budget.exceeds_safe_constlen`, and its safe_constlen variant (CLI `--safe-constlen`, constlen at most 100) is key material, so the cache holds both. At pipeline creation the plug-in calls `air2ir3_trim_constlen(vs_constlen, fs_constlen)`, a copy of Mesa `ir3_trim_constlen`: bit 0 means use the VS's safe variant, bit 1 the FS's. For `02_PBGRA_Xgfc` the trim mask is 2 and the pipeline total becomes 116.

## History

| ABI | Change |
|---|---|
| 6 | Every UBO index below 16; the driver table moved from UBO 31 to `driver_table_ubo`; sidecar function-constant values exact (cache format 5); undecided predicates refused rather than taken from the optimiser; IEEE static-initialiser evaluation; float -> char/short truncation; integer `clamp` and integer `air.convert` fixed |
| 5 | Unset constants folded only when provably value-independent; presence predicates restricted, `requires_no_attachment` added; `nsamp` counts every texture instruction's s#; XR source alpha clamped |
| 4 | Unset constants may not decide anything in the body; separate NTEX / NSAMP; constexpr samplers in the lowest free S#; per-sample shading flag; XR min/max blending with ONE/ONE |
| 3 | Pipeline const budget and safe_constlen; private memory sizing and budget; driver UBOs above the highest declared constant buffer; descriptor counts from `nir_shader_gather_info`; XR shader blending |
| 2 | Shader code may depend on attachment and texture format (XR); `present` / bind-through; threadgroup buffers; driver UBOs specified; storage textures; compare functions translated |
