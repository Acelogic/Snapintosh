# air2ir3 changelog

Technically meaningful changes to the compiler, newest first. Interface versions: binding ABI ([BINDING-ABI.md](BINDING-ABI.md)), cache format ([CACHE-FORMAT.md](CACHE-FORMAT.md)), C API (`src/air2ir3_api.h`). Each rule change has a regression test in `tests/regress.py`.

## 2026-10-20: AIR 2.2 texture reads

- Metal's compiler service hands the plug-in AIR 2.2, where a texture read has 4 operands instead of AIR 2.9's 6. The translator read operand 4 and hit an LLVM assertion inside WindowServer (CoreAnimation's APL filter, `compute_apl`). Both layouts are now handled, and every operand read is bounds-checked.

## 2026-10-16 to 2026-10-20: desktop bring-up fixes and compile speed

- **Derivatives of 16-bit values** are taken at 32 bits and narrowed. On the X2-90, `dsx` / `dsy` on half registers returned derivatives tens of times too large, which erased the shape mask of CoreAnimation's glass background (`fwidth(half)`). Test `deriv16` checks that every `dsx`/`dsy` is f32.
- **Pointer phis and selects**: supported when all incoming pointers address the same object (a 32-bit offset from one base, or a 64-bit device address); refused with a specific message otherwise (loaded or integer-made pointers, different buffers or address spaces).
- **Dead resource-handle stores** into private memory that is never read back as a pointer are dropped (RenderBox custom effects); any other use still refuses.
- **`air.buffer_size`** metadata is read as the argument's declared minimum size.
- **Compile speed**: function constants are folded and dead feature branches pruned before inlining (inlining a whole ubershader first was most of a specialised CoreAnimation compile); Mesa's per-pass NIR validation is off in production compiles (`NIR_DEBUG` or `AIR2IR3_NIR_VALIDATE=1` turn it back on; the regression tests do).
- The program export gains compute state (local size, dispatch mode).

## 2026-09-30: Mesa patch and llvmpipe fixes

- `patches/0003`: ir3's jump optimisation built its flow-instruction lists on every pass, which was quadratic on very large shaders; the lists are now built once.
- Disassembly and its NIR text are produced only when a caller prints them (a tenth of a large fragment compile).
- `nirexec` widens 8- and 16-bit ALU operations, phis, half texture results and fp16 varyings to 32 bits for llvmpipe, whose code generator mis-selects or mis-evaluates them; narrow buffer loads become 32-bit loads plus extraction, as ir3 does.
- A packed i64 constexpr sampler state (as native Metal specialisation emits) is decoded like the two-word array.
- `tests/corpus_compile.c` and `tools/compare_compilers.py` compile the whole corpus through two compiler library builds and compare every output.

## 2026-09-27: program export and private allocations

- `air2ir3_compile_program()` (additive to C API 2) returns the executable code bytes and a JSON description of the a8xx state the command builder needs, from the freshly compiled variant (`src/ir3_program_export.h`).
- Static private `alloca`s are translated to NIR local arrays, up to 64 KiB per function; dynamic or non-private allocas are refused.
- `air.buffer` arguments are checked against the pointer's actual address space.

## September 2026: ABI 6, cache format 5

- **UBO indices below 16.** On the A16, a CoreDisplay vertex function read its device-buffer addresses from a driver table bound at UBO 31 and got zeros, so the vertex fetch faulted at VA 0. No Mesa driver uses a non-bindless UBO above 15. The driver table now sits at `driver_table_ubo` = 1 + the highest declared constant buffer, ir3's driver UBOs follow it, and any index above 15 is a compile error. 25 corpus functions changed (the ones that read the table); maximum UBO index 6.
- **Integer `clamp`** (`air.clamp.s` / `.u`) was matched by the float `clamp` and compiled as `max.f` / `min.f` on integer bits. Small integers are fp32 denormals, which Adreno flushes, so the clamp returned 0. It now compiles to integer min/max. This was the cause of a hardware UBO probe reading "the first slot in every slot"; that probe therefore said nothing about UBO indices above 15.
- **Integer `air.convert`** between integer types extended by the destination's signedness; it now extends by the source's (C semantics).
- **Exact function-constant values (cache format 5).** The sidecar printed values with `%.9g` (large integers rounded, bare `nan`/`inf` invalid JSON, `-0` read as integer 0), so keys did not recompute. Every value is now canonicalised once in its declared type; key bytes, code and sidecar use it; the sidecar is strict JSON with IEEE `bits` for float / half.
- **Undecided predicates** are never taken from LLVM's optimiser or its Evaluator: when air2ir3's own evaluation of the static initialiser fails, what it would decide is refused. (`(uint(F) == 7u) || A` with F = NaN had come out true; Metal has false.)
- **IEEE static initialisers.** The initialiser is evaluated without Metal's fast-math flags, and its stored values are given to the body, so the body reads what decided presence. An operation that creates inf / NaN from finite operands under those flags is poison with no reproducible Metal answer, and is refused.
- **Float -> char / short** of a constant truncates toward zero (`char(-128.5)` is -128); NIR's folding had called it poison.

## September 2026: ABI 5 (corrections)

- **XR source colour as an RGB blend factor** moved to shader blending: the RB clamps the dual-source colour to [0, 1] for the UNORM view where Metal clamps to the XR range (76 to 439 codes off).
- **Undecided presence predicates are refused**; they had defaulted to "present if read". AIR conversions in the static initialiser are evaluated as Metal folds them (measured), with NaN or out-of-range conversions treated as poison and refused.
- **Float constants loaded as integers** (`isnan`, `isinf`, `signbit`, `as_type`) keep their bit pattern; they had been converted by value.
- Metal rejects static initialisers that call popcount, clz, clamp, abs or floor; air2ir3 refuses them too.
- An active app `[[color(n), index(1)]]` output is a compile error (it had been stored as a second index-0 output).

## September 2026: ABI 5

- **Unset number constants** fold only when provably value-independent: exhaustive enumeration up to 2^16 combinations, LLVM `ConstantRange` / KnownBits beyond, never float arithmetic, every use independent, poison never folded. The previous rule decided independence from ten sample values and folded `N == 4` to false.
- **Presence predicates** on unset constants are accepted only as a direct copy (absent) or when value-independent. Gated colour outputs are left unwritten and listed in `reflection.requires_no_attachment`, which keeps CoreAnimation's `02_PBGRA_Xgfc` pipeline.
- **XR source alpha** is clamped to [0, 1] wherever it is a blend factor (and as the BGRA10_XR alpha value); alpha 1.2 had been up to 224 codes off.
- **`nsamp`** counts the s# of every texture instruction, so `read()`-only functions report 1.
- The diff tools print `SKIP:` without their baseline, and the clean-room run checks it.

## September 2026: ABI 4

- **Unset function constants** may not decide anything in the function body. A randomized differential test against Metal (generated shaders x set/unset combinations: present set, buffers read, pixel) showed no local rule reproduces Metal's undef choices, so such variants are refused.
- **Separate NTEX / NSAMP** in the sidecar, and **constexpr samplers in the lowest free S#** instead of S#15 downward: per-draw descriptors fell from 16 T# + 16 S# for most variants to at most 15 + 4.
- **Per-sample shading** flag for multisampled pipelines (sample id/position, sample interpolation, colour-attachment reads, XR shader blending), with Turnip's registers documented.
- **XR min/max** channels program ONE/ONE and never use dual-source; the XR source clamp moved to code 1022 (Apple's documented range), fitted against Metal's output.

## September 2026: ABI 3

- **Pipeline const budget**: ir3 safe_constlen variants as key material, `air2ir3_trim_constlen()` (Mesa `ir3_trim_constlen`), and a VS+FS check; `02_PBGRA_Xgfc` needs VS 16 + FS 512.
- **Private memory** reported in the sidecar and sized as Turnip does for the X2-90, with a 512 MiB budget.
- **Driver UBOs** start above the highest declared constant buffer (one had landed on a declared but unused `buffer(1)`).
- **The library writes the full sidecar**, so a cache entry is the online sidecar byte for byte; `air2ir3_cache_key()` computes a key without compiling.
- **`nir_shader_gather_info`** runs before ir3, as in Turnip, so `num_samp` and `need_pixlod` are real (they had read 0, and the first hardware draw had to program NTEX/NSAMP/PIXLODENABLE by hand). One bit of SimpleTextureFragment changed: the `(eq)` helper-lane end marker.
- **XR shader blending** through framebuffer fetch for every blend state the RB cannot do exactly, including premultiplied source-over.
- Texture classes masked to declared `texture(n)` arguments; the raster sample count left the key; CoreDisplay `GPUPass` swept over its mask bits.
- The Metal-side Swift tools are built from source, and `tools/cleanroom.sh` fails on any binary in the copy.

## September 2026: ABI 2, cache format 2

- **Cache key** includes stage and entry name, and uses format classes instead of raw formats (format 1 never hit for real pipelines).
- **C library** with a stable API, no global state, thread-safe; runtime templates compile online instead of being cached.
- **Constexpr compare functions** translated from MSL order to Adreno order (5 of 7 had been wrong).
- **XR formats**: shader lowering for 554 / 552, conversion-blit paths for 550, XR sRGB and packed YCbCr (FORMATS.md).
- **Driver UBOs** reported and specified; `access::read_write` textures refused; write-only textures are storage images.
- **Unset constants** follow Metal's presence rules with bind-through for absent but read arguments.
- **Threadgroup buffer arguments** supported through driver-table offsets; imageblock kernels refused with a stated reason.
- **Clean rebuild**: `tools/mesa-setup.sh`, library-only Mesa targets (`tools/mesa-ninja.sh`), Mesa build options in the compiler id, tree-relative scene paths.

## Earlier

The original prototype (`src/air2ir3.v0-prototype.cpp`) was hardened before the rounds above: 64-bit phis, gated render targets, the framebuffer-fetch slot, binding-index expressions, varyings linked by name, constexpr sampler slots, LLVM instcombine fixpoint aborts, dynamic `insertelement`, the Mesa ir3 predicate register-allocation fix (`patches/0001`), and blob round trips.
