# air2ir3

air2ir3 is the shader compiler of Snapintosh's own Adreno X2-90 Metal driver. It translates Apple AIR (Metal's LLVM-based intermediate representation, the bitcode inside a `.metallib` or produced by a runtime `newLibraryWithSource:` compile) into Mesa NIR, and compiles that with Mesa's ir3 back end for the Adreno X2-90 (a8xx, `chip_id 0x44070041`). The Metal plug-in calls it through a small C library; the same code is available as a command-line tool and produces an offline cache of precompiled WindowServer pipelines.

Current interface versions: binding ABI 6, cache format 5, C API 2.

| Document | Contents |
|---|---|
| [BINDING-ABI.md](BINDING-ABI.md) | Where each Metal resource of a compiled function goes, and what the command-stream builder must program |
| [CACHE-FORMAT.md](CACHE-FORMAT.md) | The precompiled cache: key, entry, blob and reader contract |
| [FORMATS.md](FORMATS.md) | The XR and packed-YCbCr pixel formats with no Adreno equivalent, and how each is handled |
| [COVERAGE.md](COVERAGE.md) | What compiles, what is refused, and how the output is checked against Metal |
| [CHANGES.md](CHANGES.md) | Changelog |

The rest of the GPU stack is described in the project [README](../../README.md) and [ARCHITECTURE](../../docs/ARCHITECTURE.md).

## How it works

1. **Front end.** Parse the AIR module with LLVM, specialise function constants, evaluate the static initialiser that decides which arguments are present, and translate the function to NIR. Resources are placed as the binding ABI says (UBOs, a driver table for device buffers, T#/S#, bindless framebuffer fetch).
2. **Lowering.** Pixel formats the Adreno render backend cannot store (BGR10_XR, BGRA10_XR) are lowered in the shader (FORMATS.md).
3. **Back end.** Run Mesa's NIR passes and ir3 for a8xx, then serialise the variant with `ir3_store_variant()`.
4. **Sidecar.** Emit a JSON description of the variant (reflection, descriptor counts, const budget, private memory, cache key), which is what the command stream needs besides the code.

The compiler refuses, with an `air2ir3: UNSUPPORTED/ERROR: ...` message, anything it cannot reproduce exactly (BINDING-ABI.md section 2). There is no silent fallback.

## Layout

| Path | What |
|---|---|
| `src/air2ir3.cpp`, `air2ir3.h`, `src/parts/` | The compiler: AIR front end, function-constant evaluation, XR lowering, ir3 back end, cache key, C API and CLI |
| `src/air2ir3_api.h` | The stable C API (`air2ir3_compile`, `air2ir3_compile_program`, `air2ir3_cache_key`, `air2ir3_trim_constlen`), built as `build/libair2ir3.a` |
| `src/ir3_program_export.h` | Exports the executable program bytes and a8xx state of a compiled variant for the command builder |
| `src/a8xx_sampler.c`, `.h` | Constexpr-sampler decoder and A8XX TEX_SAMP descriptor builder (follows Mesa `fd6_texture.cc`) |
| `src/nirexec.cpp` | Runs the AIR-derived NIR on Mesa llvmpipe, for comparison with Metal |
| `src/spvnir.cpp`, `src/nirdiff.cpp` | NIR differential against Mesa's own SPIR-V front end |
| `src/air2ir3.v0-prototype.cpp` | The original prototype, kept for before/after comparisons |
| `src/build.sh` | Builds everything against Homebrew LLVM and the local Mesa build |
| `patches/` | Patches applied to the pinned Mesa checkout, plus `ir3_parse_stub.c` / `ir3_parser.h` |
| `tests/regress.py`, `tests/fixtures/` | Regression tests, one per known bug |
| `tests/fcrand.py`, `fcv4.py`, `fcv5.py`, `fc6.py`, `fc6-runs.sh` | Randomized differential tests of function-constant handling against Metal |
| `tests/api_test.c`, `tests/pipelinekeys.py`, `tests/corpus_compile.c` | C API test, real-pipeline cache-key test, whole-corpus compile through the C API |
| `tools/` | Mesa setup, sweep, cache tools, render comparisons, clean-room rebuild (below) |
| `vtools/` | Reflection checks against Metal (`reflcmp.py`, `qcrefl.py`, `mtlrefl.swift`), generated-uniform renders (`diffscenes.py`), format evidence (`formats_evidence.sh`, `wsfmtscan.py`) |
| `xrscenes/`, `xr5scenes/`, `vscenes/`, `scenes/` | Render-test scene descriptions (JSON; they name Apple metallib functions, they contain no Apple code) |

Generated directories (not in the repository): `third_party/mesa`, `build/`, `corpus/`, `results/`, `cache/`, `scratch/`.

## Requirements

- macOS 27 (26A428 was used) with Xcode's Metal toolchain (`xcrun metal`, `swiftc`). The compiler itself is portable C++; the tests compare against Metal and need a Mac.
- Homebrew `llvm` 22, `meson`, `ninja`, `zstd`, `spirv-tools` and `shaderc` (for `glslc`).
- Python 3.
- macOS's own bison 2.3 is enough, because only Mesa library targets are built.

## Mesa

air2ir3 builds against Mesa (MIT; NIR, ir3 and the freedreno register database), pinned at revision `bbeb2dca9fee`. `tools/mesa-setup.sh` clones Mesa (from `MESA_URL`, default the freedesktop.org repository) into `third_party/mesa`, checks out the pinned revision, applies `patches/0*.patch`, copies the parser stub, and configures `build/mesa` with `tools/mesa-options.txt`. The patches:

| Patch | Purpose |
|---|---|
| `0000-build-nir-and-ir3-without-drivers-parser-stub.patch` | Build NIR and ir3 without the GL/Vulkan drivers (with `ir3_parse_stub.c`, `ir3_parser.h`) |
| `0001-ir3-ra-predicates-match-reloaded-def-in-live-in-merge.patch` | ir3 predicate register allocation fix |
| `0002-glsl-bison-2.3-compat.patch` | Builds with macOS's bison 2.3 |
| `0003-ir3-legalize-opt-jump-flow-lists-built-once.patch` | Makes ir3's jump optimisation linear instead of quadratic on very large shaders |

## Build

```sh
cd gpu/air2ir3
tools/mesa-setup.sh            # clone/patch/configure Mesa (MESA_URL may point at a local mirror)
tools/mesa-ninja.sh            # build only the Mesa libraries and generated headers src/build.sh links
src/build.sh all               # air2ir3, libair2ir3.a, api_test, nirexec, nirdiff, Swift Metal tools
src/build.sh v0                # optional: the prototype, for comparisons
```

`src/build.sh` with no argument builds only `build/air2ir3` and the library; `src/build.sh swift` builds only the Metal-side tools (`mtlgold`, `mtlrefl`, `pipelinekey`). The compiler identity baked into the binary (`build/air2ir3 --compiler-id`) covers the sources, the Mesa revision, the patches, the options Mesa was configured with, and the LLVM version; the cache is keyed to it.

## Inputs

The compiler needs only AIR. The test corpus is extracted locally from the macOS install the tests run on; nothing from Apple is shipped in the repository.

```sh
python3 tools/corpus.py        # corpus/ + index.json from the SkyLight, CoreDisplay and QuartzCore metallibs
python3 tools/templates.py     # build/templates/: SkyLight's runtime MSL templates, compiled with xcrun metal
python3 tools/scenes.py        # scenes/ for the llvmpipe-vs-Metal render checks
```

These and several checks (the sweep, `tests/pipelinekeys.py`, some regression tests, `vtools/`) read a local research directory holding copies of those metallibs, the runtime template sources and recorded CoreAnimation pipeline descriptions (`adreno/local-cts`, `adreno/windowserver-metal-usage`). It is not part of the repository. `tools/scrdir.py` finds it by walking up from this tree; `AIR2IR3_SCRATCH` points at it explicitly.

`tools/a16check.py` and `tools/p7check.py` compare against shader sets that ran on the A16 hardware. Those reference files contain Adreno code compiled from Apple shaders and are not published; generate them locally with q1n1's `tools/a16gpu-render/make-render-shaders.sh` and `tools/a16gpu-p7/make-p7-shaders.sh`.

## Run and test

```sh
build/air2ir3 --help                       # compile one function (constants, attachment formats, blend,
                                           #   texture classes, --safe-constlen, --json, --variant, --key-only)
build/air2ir3 --list-fcs f.bc              # declared function constants, without compiling
build/air2ir3 --verify-variant v.ir3v      # reload a blob with ir3_retrieve_variant and disassemble it

python3 tests/regress.py                   # regression tests (pipeline_keys_hit_cache needs cache/)
python3 tools/sweep.py --out results/fixed --cache cache   # full coverage sweep + cache (minutes, parallel)
python3 tools/cachecheck.py cache --reload 200             # cache integrity and blob reload
python3 tests/pipelinekeys.py              # real MTLRenderPipelineDescriptors -> keys -> cache hits
python3 tools/apitest.py                   # online compiles through the C API; online sidecar == cache entry
python3 tools/exec.py                      # llvmpipe vs Metal render scenes
python3 tools/xrrand.py; python3 tools/xr5.py   # XR blend states, llvmpipe vs Metal
python3 tools/nirdiff.py                   # NIR differential vs Mesa spirv_to_nir
python3 tests/fcrand.py --seed 1           # unset function constants: random shaders vs Metal
zsh tests/fixtures/v6/run_fixtures.sh      # function-constant fixtures vs Metal
zsh tests/fc6-runs.sh                      # randomized function-constant runs
python3 tools/coverage.py > results/coverage.md
tools/cleanroom.sh                         # rebuild from a clean copy and compare (key, blob) pairs
tools/runall.sh                            # all of the above in order (about an hour)
```

`tools/rounddiff.py`, `tools/fix2diff.py` and `tools/unsetdiff.py` compare against earlier sweeps in `results/`; without that baseline they print `SKIP:`.

## Licence

- air2ir3's own sources are MIT, like the rest of Snapintosh.
- The files in `patches/` modify Mesa and are under the MIT licence of the files they patch.
- `src/a8xx_sampler.c` follows Mesa's `fd6_texture.cc` (MIT).
- The register headers Mesa's build generates from its register database (`a8xx_descriptors.xml.h` and others) carry Mesa's notice.
- Binaries link Mesa (MIT) and LLVM (Apache-2.0 WITH LLVM-exception).
- The test corpus, the templates and the A16 reference shader sets are generated locally from Apple software and are not redistributed.
