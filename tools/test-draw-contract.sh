#!/bin/sh
# SPDX-License-Identifier: MIT
# Draw-submission contract check (design S0). Host only: no GPU, no guest, no hardware.
#
#   tools/test-draw-contract.sh                 # the checkout this script lives in
#   ROOT=<tree> tools/test-draw-contract.sh     # another tree's headers (e.g. a `git archive` of a commit)
#   OUT=<dir>  Q1N1_TOOLS=<q1n1/tools>  MESA_TREE=<mesa>  LLVM=<llvm bin>   (optional overrides)
#
# Proves, and records in $OUT/draw-contract.json (hashes of every input, per-step verdicts):
#   1 fresh      gpu/adreno-kext/include/AdrenoA8xxRegs.h is byte-identical to tools/gen-a8xx-regs.py's output
#   2 monitor    the headers compile as freestanding C with the monitor's flags (probes/run.py FLAGS)
#   3 kext-cxx   ... as C++ with the kext's flags (kext/build.sh CXXF, -mkernel, Kernel.framework)
#   4 kext-c     ... as C with the kext's compat flags (kext/build.sh COMMON)
#   5 plugin     ... as Objective-C with the plug-in's flags (plugin/build.sh CFL) plus -Werror
#   6 host       ... as strict host C11
#   7 q1n1       every register, field, packet dword, descriptor dword and enum value in q1n1's
#                tools/a8xx_regs.py, every opcode and monitor register in tools/adreno_x2.py, and the q1n1
#                masks the monitor copies resolve to the same numbers in the generated/contract headers
#                (compile-time asserts generated from the Python modules)
#   8 oracle     host run: the IB ring words built only from generated macros equal q1n1
#                a16gpu_p6p7.ring_words (the 35 words of every hardware-proven P7/render draw); pkt4/pkt7
#                headers equal q1n1's for every register/opcode; the draw table expands to exactly
#                q1n1's KNOWN_OFFSETS and its 64-bit/address set; the explicit CS extension is checked against
#                pinned Mesa's own generated C definitions; package/command sizes follow the wire layout
# Failure inventory for the CS extension: docs/ADRENO-COMPUTE-PACKETS-20261019.md.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=${ROOT:-$(cd "$HERE/.." && pwd)}
Q1N1=${Q1N1_TOOLS:-$(cd "$HERE/../../q1n1/tools" 2>/dev/null && pwd || echo /nonexistent)}
MESA=${MESA_TREE:-$HERE/../gpu/air2ir3/third_party/mesa}
LLVM=${LLVM:-/opt/homebrew/opt/llvm/bin}
OUT=${OUT:-$(mktemp -d "${TMPDIR:-/tmp}/draw-contract.XXXXXX")}
GEN=$HERE/gen-a8xx-regs.py
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$OUT"
C=$ROOT/compat
INC=$ROOT/gpu/adreno-kext/include
REGS=$INC/AdrenoA8xxRegs.h
STEPS=$OUT/steps.txt
: > "$STEPS"
FAILED=0
step() {   # step <name> <command...>: run, log to $OUT/<name>.log, record the verdict
    name=$1; shift
    if "$@" > "$OUT/$name.log" 2>&1; then
        echo "$name ok" >> "$STEPS"; echo "ok    $name"
    else
        echo "$name FAIL" >> "$STEPS"; echo "FAIL  $name (see $OUT/$name.log)"; tail -5 "$OUT/$name.log" | sed 's/^/      /'
        FAILED=1
    fi
}

# ---- the translation unit every dialect compiles --------------------------------------------------------------
cat > "$OUT/contract-tu.h" <<EOF
#include "$C/adreno-guest.h"
#include "$C/adreno-submit.h"
#include "$INC/AdrenoA8xxRegs.h"
/* ABI numbers that must never move (binary compatibility with the running monitor and kext). */
#if ADRENO_GUEST_HVC != 0xad16 || ADRENO_GUEST_ABI != 1 || ADRENO_GUEST_FENCE != 0x00010001 || \\
    ADRENO_GUEST_UNMAP != 0x00010002 || ADRENO_GUEST_CACHE != 0x00010003 || ADRENO_CACHE_TO_DEVICE != 1 || \\
    ADRENO_CACHE_FROM_DEVICE != 2 || ADRENO_KCMD_FENCE != 0x1000u || ADRENO_KCMD_VENDOR_BASE != 0x1000u
#error existing FENCE/UNMAP/CACHE numbers changed
#endif
#if ADRENO_GUEST_IB != 0x00010005 || ADRENO_KCMD_IB != 0x1002u || ADRENO_GUEST_IB_ABI != 1
#error IB numbers
#endif
/* New error codes may not collide with any existing refusal (-60..-74 monitor, -80..-93, -110..-118). */
#if ADRENO_IB_E_UNCERTAIN != -75 || ADRENO_IB_E_GPU_ERROR != -76 || ADRENO_IB_E_BUSY != -77 || ADRENO_IB_E_STICKY != -78
#error monitor IB codes
#endif
EOF
cat > "$OUT/monitor.c" <<EOF
#include "$C/adreno.h"
#include "$C/adreno-fill.h"
#include "$OUT/contract-tu.h"
/* compat/adreno.h reads registers by physical address; each must be the generated A8XX offset. */
_Static_assert(ADRENO_RBBM_STATUS == ADRENO_PA + 4 * A8XX_REG_RBBM_STATUS, "RBBM_STATUS");
_Static_assert(ADRENO_RBBM_GBIF_HALT == ADRENO_PA + 4 * A8XX_REG_RBBM_GBIF_HALT, "GBIF_HALT");
_Static_assert(ADRENO_RBBM_GBIF_HALT_ACK == ADRENO_PA + 4 * A8XX_REG_RBBM_GBIF_HALT_ACK, "GBIF_HALT_ACK");
_Static_assert(ADRENO_CP_RB_RPTR == ADRENO_PA + 4 * A8XX_REG_CP_RB_RPTR, "CP_RB_RPTR");
_Static_assert(ADRENO_CP_RB_WPTR == ADRENO_PA + 4 * A8XX_REG_CP_RB_WPTR, "CP_RB_WPTR");
_Static_assert(ADRENO_CP_SQE_CNTL == ADRENO_PA + 4 * A8XX_REG_CP_SQE_CNTL, "CP_SQE_CNTL");
_Static_assert(ADRENO_FILL32_E_UNCERTAIN == -74 && ADRENO_GUEST_FILL32 == 0x00010004, "FILL32 unchanged");
_Static_assert(ADRENO_IB_E_UNCERTAIN < ADRENO_FILL32_E_UNCERTAIN && ADRENO_E_DART > ADRENO_FILL32_E_UNCERTAIN,
               "IB codes follow the monitor's refusal range");
/* Every package page must be a window address: the high reloc half is then always 0. */
_Static_assert(ADRENO_WINDOW_END <= 0x100000000ull, "window below 4 GiB");
int contract_monitor_probe(void) { return ADRENO_GUEST_IB_ABI; }
EOF
cat > "$OUT/kext.cpp" <<EOF
#include "$INC/AdrenoContract.h"
#include "$C/adreno.h"
#include "$C/adreno-fill-command.h"
#include "$OUT/contract-tu.h"
static_assert(sizeof(adreno_ib_command) == 48 && sizeof(adreno_ib_reloc) == 32, "C++ layout");
extern "C" uint64_t contract_kext_probe(void) { return adreno_ib_command_bytes(1, 64, 1); }
EOF
cp "$OUT/kext.cpp" "$OUT/kext-c.c"; sed -i '' -e 's/^static_assert(sizeof(adreno_ib_command)/_Static_assert(sizeof(struct adreno_ib_command)/' \
    -e 's/sizeof(adreno_ib_reloc)/sizeof(struct adreno_ib_reloc)/' -e 's/^extern "C" //' "$OUT/kext-c.c"
cat > "$OUT/plugin.m" <<EOF
#import <Foundation/Foundation.h>
#include "$INC/AdrenoContract.h"
#include "$C/adreno-fill-command.h"
#include "$OUT/contract-tu.h"
uint64_t contract_plugin_probe(void) { return adreno_ib_package_bytes(3, 128) + (ADRENO_IB_REGISTRY_PROPERTY[0] == 'A'); }
EOF

# ---- 1 fresh ------------------------------------------------------------------------------------------------
fresh() {
    python3 "$GEN" --mesa "$MESA" --out "$OUT/AdrenoA8xxRegs.regen.h" &&
    cmp "$OUT/AdrenoA8xxRegs.regen.h" "$REGS" &&
    python3 "$HERE/gen-adreno-ib-tables.py" --q1n1 "$Q1N1" --mesa "$MESA" --out "$C/adreno-ib-tables.h" --check
}
step fresh fresh

# ---- 2..6 dialects --------------------------------------------------------------------------------------------
monitor() {
    "$LLVM/clang" --target=aarch64-unknown-none-elf -ffreestanding -fno-pic -mgeneral-regs-only -O1 -Wall -Wextra \
        -Werror -fno-stack-protector -mcmodel=tiny -I"$ROOT/shadow" -c "$OUT/monitor.c" -o "$OUT/monitor.o"
}
step monitor monitor
SDK=$(xcrun --show-sdk-path)
KH=$SDK/System/Library/Frameworks/Kernel.framework/Headers
KCOMMON="-target arm64e-apple-macos27.0 -isysroot $SDK -mkernel -nostdinc -I$KH -I$ROOT/gpu/adreno-kext/kext/include -I$INC -DKERNEL -DAPPLE -DNeXT -O2 -Wall -Werror -Wno-unused-private-field -fno-common"
# shellcheck disable=SC2086
kext_cxx() { xcrun clang++ $KCOMMON -std=gnu++17 -fapple-kext -fno-exceptions -fno-rtti -Wno-inconsistent-missing-override -c "$OUT/kext.cpp" -o "$OUT/kext.o"; }
step kext-cxx kext_cxx
# shellcheck disable=SC2086
kext_c() { xcrun clang $KCOMMON -c "$OUT/kext-c.c" -o "$OUT/kext-c.o"; }
step kext-c kext_c
plugin() {
    xcrun clang -arch arm64e -mmacosx-version-min=27.0 -fobjc-arc -fobjc-arc-exceptions -O2 -Wall -Werror \
        -Wno-objc-method-access -Wno-incomplete-implementation -Wno-protocol -Wno-objc-protocol-method-implementation \
        -Wno-objc-protocol-property-synthesis -Wno-deprecated-declarations -c "$OUT/plugin.m" -o "$OUT/plugin.o"
}
step plugin plugin
host() { xcrun clang -std=c11 -Wall -Wextra -Werror -Wpedantic -Wno-gnu-offsetof-extensions -c -x c "$OUT/kext-c.c" -o "$OUT/host.o"; }
step host host

# ---- 7 q1n1 constants -> compile-time asserts --------------------------------------------------------------
q1n1_asserts() {
    python3 - "$Q1N1" "$OUT/q1n1-asserts.c" "$INC" "$C" "$GEN" "$MESA" <<'PY'
import hashlib, importlib.util, json, pathlib, re, subprocess, sys
q1n1, out, inc, compat, gen, mesa = sys.argv[1:7]
sys.path.insert(0, q1n1)
import a8xx_regs as X, adreno_x2 as R, a16gpu_p6p7 as P
spec = importlib.util.spec_from_file_location('cs_gen', gen)
G = importlib.util.module_from_spec(spec); spec.loader.exec_module(G)
M = G.Mesa(mesa)
assert M.revision() == 'bbeb2dca9feed6ac88d71234a9dc5ae8aeed4275', 'unqualified Mesa revision'
assert set(G.DRAW_REG_NAMES) == set(X.REGS), 'draw baseline changed'
assert not set(G.CS_REG_NAMES) & set(X.REGS), 'compute extension overlaps draw'
cs_regs = {n: r for n, r in G.regs_of(M, M.load('a6xx.xml'), domains=G.CORE_DOMAINS).items()
           if n in G.CS_REG_NAMES}
assert set(cs_regs) == set(G.CS_REG_NAMES), 'missing compute register'
cs_packets = {n: r for n, r in G.regs_of(M, M.load('adreno_pm4.xml'), by_full=True).items()
              if r['domain'] == 'CP_EXEC_CS'}
assert set(cs_packets) == {'CP_EXEC_CS_0', 'CP_EXEC_CS_1', 'CP_EXEC_CS_2', 'CP_EXEC_CS_3'}
# Compare against Mesa's own C emitter, not only our parser-to-header emitter.
native = {}
native_paths = []
for xml in ('a6xx.xml', 'adreno_pm4.xml'):
    data = subprocess.check_output([sys.executable, str(pathlib.Path(M.regs_dir) / 'gen_header.py'),
        '--rnn', M.regs_dir, '--xml', str(pathlib.Path(M.regs_dir) / 'adreno' / xml), 'c-defines'], text=True)
    path = pathlib.Path(out).parent / (xml + '.native.h')
    path.write_text(data); native_paths.append(path)
    native.update({n: int(v, 0) for n, v in re.findall(
        r'^#define\s+(\w+)\s+(?:__FD_DEPRECATED\s+)?(0x[0-9a-fA-F]+|[0-9]+)(?:ull|u)?\s*$', data, re.M)})
native_fields = 0
for r in [*cs_regs.values(), *cs_packets.values()]:
    assert native['REG_' + r['mesa_name']] == r['offset'], r['mesa_name']
    for name, lo, hi, shr, typ, radix in r['fields']:
        if not name:  # Mesa emits scalar/address registers without a named mask.
            continue
        field = r['mesa_name'] + '_' + name
        mask = ((1 << (hi - lo + 1)) - 1) << lo
        if typ == 'boolean':
            assert native[field] == mask, field
        else:
            assert native[field + '__MASK'] == mask, field
            assert native[field + '__SHIFT'] == lo, field
        native_fields += 1
manifest = {'mesa_revision': M.revision(), 'compute_registers': cs_regs,
            'compute_packets': cs_packets, 'native_fields_checked': native_fields,
            'native_headers': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in native_paths},
            'xml_sha256': {x: M.xml_sha(x) for x in G.XML_FILES}}
pathlib.Path(out).with_name('compute-mesa.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
lines = [f'#include "{inc}/AdrenoContract.h"', f'#include "{compat}/adreno-guest.h"',
         '#define EQ(a, b) _Static_assert((unsigned long long)(a) == (unsigned long long)(b), #a " == " #b)']
n = {'regs': 0, 'fields': 0, 'pkt': 0, 'desc': 0, 'enums': 0, 'opcodes': 0, 'monitor': 0}
def fields(prefix, flds, bits):
    for name, lo, hi, shr, _t, _r in flds:
        f = f'{prefix}__{(name or "VALUE").upper()}'
        lines.append(f'EQ({f}__SHIFT, {lo}); EQ({f}__WIDTH, {hi - lo + 1});')
        lines.append(f'EQ({f}__SHR, {shr});' if shr else f'#ifdef {f}__SHR\n#error {f} has no shr in q1n1\n#endif')
        mask = ((1 << (hi - lo + 1)) - 1) << lo
        lines.append(f'EQ({f}__MASK, {mask:#x}ull);')
        n['fields'] += 1
for name, (off, bits, flds, stride, length) in X.REGS.items():
    p = f'A8XX_REG_{name}'
    lines.append(f'EQ({p}, {off:#x}); EQ({p}__BIT_SIZE, {bits}); EQ({p}__ARRAY_COUNT, {length}); EQ({p}__ARRAY_STRIDE, {stride});')
    fields(p, flds, bits); n['regs'] += 1
for name, r in cs_regs.items():
    p = f'A8XX_REG_{name}'
    lines.append(f'EQ({p}, {r["offset"]:#x}); EQ({p}__BIT_SIZE, {r["bits"]}); '
                 f'EQ({p}__ARRAY_COUNT, {r["length"]}); EQ({p}__ARRAY_STRIDE, {r["stride"]});')
    fields(p, r['fields'], r['bits'])
for name, r in cs_packets.items():
    p = f'A8XX_PKT_{name}'
    lines.append(f'EQ({p}, {r["offset"]}); EQ({p}__BIT_SIZE, {r["bits"]});')
    fields(p, r['fields'], r['bits'])
for name, (off, bits, flds) in X.PKT.items():
    p = f'A8XX_PKT_{name}'
    lines.append(f'EQ({p}, {off}); EQ({p}__BIT_SIZE, {bits});'); fields(p, flds, bits); n['pkt'] += 1
for name, (off, bits, flds) in X.DESC.items():
    p = f'A8XX_DESC_{name}'
    lines.append(f'EQ({p}, {off});'); fields(p, flds, bits); n['desc'] += 1
for ename, values in X.ENUMS.items():
    for vname, v in values.items():
        lines.append(f'EQ(A8XX_E_{vname.upper()}, {v:#x});'); n['enums'] += 1
for attr in dir(R):
    if attr.startswith('CP_') and isinstance(getattr(R, attr), int) and attr in X.ENUMS['adreno_pm4_type3_packets']:
        lines.append(f'EQ(A8XX_E_{attr}, {getattr(R, attr)});'); n['opcodes'] += 1
for name in ('RBBM_STATUS', 'RBBM_GBIF_HALT', 'RBBM_GBIF_HALT_ACK', 'RBBM_INT_0_STATUS', 'CP_INTERRUPT_STATUS_GLOBAL',
             'CP_RB_BASE', 'CP_RB_CNTL', 'CP_RB_RPTR', 'CP_RB_WPTR', 'CP_SQE_CNTL', 'CP_APRIV_CNTL_PIPE',
             'CP_PROTECT_CNTL_PIPE', 'RBBM_INT_0_MASK', 'CP_RB_RPTR_ADDR', 'CP_SQE_INSTR_BASE'):
    if name in R.REGS:
        lines.append(f'EQ(0x03d00000u + 4u * A8XX_REG_{name}, {R.REGS[name].addr:#x});'); n['monitor'] += 1
lines += [f'EQ(ADRENO_IB_RBBM_INT_ERRORS, {P.RBBM_INT_ERRORS:#x});',
          f'EQ(ADRENO_IB_CP_GLOBAL_FAULTS, {P.CP_GLOBAL_FAULTS:#x});',
          f'EQ(ADRENO_IB_RBBM_IDLE_IGNORE, {R.RBBM_STATUS_CX_MASTER:#x});',
          f'EQ(ADRENO_IB_BR_FENCE_OFF, {R.MONITOR_FENCE_OFF:#x});',
          f'EQ(A8XX_FIELDS_AXXX_CP_RB_CNTL__BUFSZ({R.RB_CNTL_DEFAULT & 0x3f}) | A8XX_FIELDS_AXXX_CP_RB_CNTL__BLKSZ(2), {R.RB_CNTL_DEFAULT:#x});',
          f'EQ(ADRENO_RING_BUFSZ, {R.RB_CNTL_DEFAULT & 0x3f});',
          f'EQ(A8XX_E_CP_TYPE7_PKT, 0x70000000); EQ(A8XX_E_CP_TYPE4_PKT, 0x40000000);',
          f'EQ(A8XX_REG_CP_APRIV_CNTL_PIPE__ICACHE__MASK | A8XX_REG_CP_APRIV_CNTL_PIPE__RBFETCH__MASK | '
          f'A8XX_REG_CP_APRIV_CNTL_PIPE__RBPRIVLEVEL__MASK | A8XX_REG_CP_APRIV_CNTL_PIPE__RBRPWB__MASK, {R.A8XX_APRIV_MASK:#x});',
          f'EQ(A8XX_REG_CP_PROTECT_CNTL_PIPE__HALT_SQE_RANGE(0xffff) | A8XX_REG_CP_PROTECT_CNTL_PIPE__LAST_SPAN_INF_RANGE(1) | '
          f'A8XX_REG_CP_PROTECT_CNTL_PIPE__ACCESS_FAULT_ON_VIOL_EN(1) | A8XX_REG_CP_PROTECT_CNTL_PIPE__ACCESS_PROT_EN(1), '
          f'{R.CP_PROTECT_CNTL:#x});',
          f'EQ(A8XX_REGS_DRAW_COUNT, {len(X.REGS)});',
          f'EQ(A8XX_REGS_CS_COUNT, {len(cs_regs)});',
          f'EQ(A8XX_REGS_IB_COUNT, {len(X.REGS) + len(cs_regs)});']
open(out, 'w').write('\n'.join(lines) + '\n')
print({**n, 'compute_regs': len(cs_regs), 'compute_packets': len(cs_packets), 'mesa_native_fields': native_fields})
PY
    xcrun clang -std=c11 -Wall -Werror -fsyntax-only "$OUT/q1n1-asserts.c"
}
step q1n1 q1n1_asserts

# ---- 8 oracle: host run vs q1n1's Python builders -----------------------------------------------------------
cat > "$OUT/oracle.c" <<EOF
#define A8XX_REGS_TABLES
#include <stdio.h>
#include "$INC/AdrenoContract.h"
#include "$C/adreno.h"

/* The ADRENO_GUEST_IB ring words, from generated fields only (the design-4.3 sequence). */
static unsigned ring_words(uint32_t *w, uint64_t ib, uint32_t dwords, uint64_t br, uint64_t bv, uint32_t marker)
{
    unsigned n = 0;
#define TC(t) A8XX_PKT_CP_THREAD_CONTROL_0__THREAD(t)
#define EV(e) A8XX_PKT_CP_EVENT_WRITE7_0__EVENT(e)
    const uint32_t clean = EV(A8XX_E_CACHE_CLEAN) | A8XX_PKT_CP_EVENT_WRITE7_0__WRITE_ENABLED(1);
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_THREAD_CONTROL, 1);
    w[n++] = TC(A8XX_E_CP_SET_THREAD_BR) | A8XX_PKT_CP_THREAD_CONTROL_0__SYNC_THREADS(1);
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_THREAD_CONTROL, 1); w[n++] = TC(A8XX_E_CP_SET_THREAD_BOTH);
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_INDIRECT_BUFFER, 3); w[n++] = (uint32_t)ib; w[n++] = (uint32_t)(ib >> 32);
    w[n++] = A8XX_PKT_A5XX_CP_INDIRECT_BUFFER_2__IB_SIZE(dwords);
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_THREAD_CONTROL, 1); w[n++] = TC(A8XX_E_CP_SET_THREAD_BR);
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_EVENT_WRITE7, 1); w[n++] = EV(A8XX_E_CCU_INVALIDATE_DEPTH);
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_EVENT_WRITE7, 1); w[n++] = EV(A8XX_E_CCU_INVALIDATE_COLOR);
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_THREAD_CONTROL, 1); w[n++] = TC(A8XX_E_CP_SET_THREAD_BV);
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_EVENT_WRITE7, 4); w[n++] = clean;
    w[n++] = (uint32_t)bv; w[n++] = (uint32_t)(bv >> 32); w[n++] = marker;
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_THREAD_CONTROL, 1); w[n++] = TC(A8XX_E_CP_SET_THREAD_BR);
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_WAIT_TIMESTAMP, 4); w[n++] = 0;
    w[n++] = (uint32_t)bv; w[n++] = (uint32_t)(bv >> 32); w[n++] = marker;
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_EVENT_WRITE7, 4); w[n++] = clean;
    w[n++] = (uint32_t)br; w[n++] = (uint32_t)(br >> 32); w[n++] = marker;
    w[n++] = a8xx_pkt7_hdr(A8XX_E_CP_THREAD_CONTROL, 1); w[n++] = TC(A8XX_E_CP_SET_THREAD_BOTH);
    return n;
}

int main(void)
{
    static const struct { uint64_t ib; uint32_t dwords; uint64_t br, bv; uint32_t marker; } cases[] = {
        {0x40010000ull, 1u, 0x10200080ull, 0x102000c0ull, ADRENO_IB_MARKER_BASE ^ 1u},
        {0xfffc0000ull, ADRENO_IB_MAX_DWORDS, 0x10200080ull, 0x102000c0ull, ADRENO_IB_MARKER_BASE ^ 0xabcdu},
        {0x1234567890ull, 1005u, 0x0000000110200080ull, 0x00000001102000c0ull, 0xfffffffeu},
    };
    uint32_t w[64];
    printf("{\"ring\": [");
    for (unsigned c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        unsigned n = ring_words(w, cases[c].ib, cases[c].dwords, cases[c].br, cases[c].bv, cases[c].marker);
        if (n != ADRENO_IB_RING_WORDS) return 2;
        printf("%s{\"ib\": %llu, \"dwords\": %u, \"br\": %llu, \"bv\": %llu, \"marker\": %u, \"words\": [",
               c ? ", " : "", (unsigned long long)cases[c].ib, cases[c].dwords, (unsigned long long)cases[c].br,
               (unsigned long long)cases[c].bv, cases[c].marker);
        for (unsigned i = 0; i < n; i++) printf("%s%u", i ? ", " : "", w[i]);
        printf("]}");
    }
    printf("], \"pkt7\": [");
    static const uint32_t counts7[] = {0, 1, 2, 3, 4, 7, 0x100, 0x3ffe, ADRENO_RING_NOP_MAX};
    int first = 1;
    for (uint32_t op = 0; op < 128; op++)
        for (unsigned k = 0; k < sizeof counts7 / sizeof counts7[0]; k++, first = 0)
            printf("%s[%u, %u, %u, %d]", first ? "" : ", ", op, counts7[k], a8xx_pkt7_hdr(op, counts7[k]),
                   a8xx_pkt_is_type7(a8xx_pkt7_hdr(op, counts7[k])));
    printf("], \"mem_write3\": [%u, %u], \"pkt4\": [", ADRENO_PKT7_MEM_WRITE3, a8xx_pkt7_hdr(A8XX_E_CP_MEM_WRITE, 3));
    first = 1;
    for (unsigned r = 0; r < sizeof a8xx_ib_regs / sizeof a8xx_ib_regs[0]; r++) {
        const struct a8xx_reg_info *g = &a8xx_ib_regs[r];
        for (unsigned i = 0; i < g->count; i++) {
            uint32_t off = g->offset + i * g->stride;
            for (uint32_t cnt = 1; cnt <= A8XX_PKT4_COUNT_MASK; cnt += 63, first = 0)
                printf("%s[%u, %u, %u, %d]", first ? "" : ", ", off, cnt, a8xx_pkt4_hdr(off, cnt),
                       a8xx_pkt_is_type4(a8xx_pkt4_hdr(off, cnt)));
        }
    }
    printf("], \"known\": [");
    first = 1;
    for (unsigned r = 0; r < sizeof a8xx_ib_regs / sizeof a8xx_ib_regs[0]; r++) {
        const struct a8xx_reg_info *g = &a8xx_ib_regs[r];
        for (unsigned i = 0; i < g->count; i++)
            for (unsigned h = 0; h < (g->bits == 64 ? 2u : 1u); h++, first = 0)
                printf("%s%u", first ? "" : ", ", g->offset + i * g->stride + h);
    }
    printf("], \"regs\": {");
    for (unsigned r = 0; r < sizeof a8xx_ib_regs / sizeof a8xx_ib_regs[0]; r++) {
        const struct a8xx_reg_info *g = &a8xx_ib_regs[r];
        printf("%s\"%s\": [%u, %u, %u, %u, %u]", r ? ", " : "", g->name, g->offset, g->bits, g->stride, g->count, g->flags);
    }
    printf("}, \"sizes\": [%llu, %llu, %llu, %llu, %llu], \"limits\": [%u, %u, %u, %u, %u]}\n",
           (unsigned long long)adreno_ib_command_bytes(1, 0, 0), (unsigned long long)adreno_ib_command_bytes(17, 64, 3),
           (unsigned long long)adreno_ib_data_offset(16), (unsigned long long)adreno_ib_data_offset(17),
           (unsigned long long)adreno_ib_command_bytes(ADRENO_IB_MAX_DWORDS, ADRENO_IB_MAX_DATA, ADRENO_IB_MAX_RELOCS),
           ADRENO_IB_MAX_DWORDS, ADRENO_IB_MAX_DATA, ADRENO_IB_MAX_RELOCS, ADRENO_IB_MAX_PACKAGE, ADRENO_IB_RING_WORDS);
    return 0;
}
EOF
oracle() {
    xcrun clang -std=c11 -Wall -Wextra -Werror -O1 -o "$OUT/oracle" "$OUT/oracle.c" &&
    "$OUT/oracle" > "$OUT/oracle.json" &&
    python3 - "$Q1N1" "$OUT/oracle.json" "$OUT/compute-mesa.json" <<'PY'
import json, struct, sys
q1n1, path, cs_path = sys.argv[1:4]
sys.path.insert(0, q1n1)
import a8xx_regs as X, adreno_x2 as R, a16gpu_p6p7 as P
d = json.load(open(path))
cs_regs = json.load(open(cs_path))['compute_registers']
bad = []
for c in d['ring']:
    want = P.ring_words(c['ib'], c['dwords'], c['br'], c['bv'], c['marker'])
    if want != c['words']:
        bad.append(('ring', c['ib'], [(i, hex(a), hex(b)) for i, (a, b) in enumerate(zip(c['words'], want)) if a != b][:4]))
for op, cnt, hdr, ok in d['pkt7']:
    if hdr != R.pkt7(op, cnt) or not ok:
        bad.append(('pkt7', op, cnt, hex(hdr), hex(R.pkt7(op, cnt))))
if d['mem_write3'][0] != d['mem_write3'][1] or d['mem_write3'][1] != R.pkt7(R.CP_MEM_WRITE, 3):
    bad.append(('ADRENO_PKT7_MEM_WRITE3', d['mem_write3']))
for off, cnt, hdr, ok in d['pkt4']:
    if hdr != P.pkt4_header(off, cnt) or not ok:
        bad.append(('pkt4', hex(off), cnt, hex(hdr), hex(P.pkt4_header(off, cnt))))
known = set()                    # test-a16gpu-p6p7.py KNOWN_OFFSETS, recomputed from the same module
for _n, (_off, _bits, _f, _stride, _len) in X.REGS.items():
    for _i in range(_len):
        for _s in range(2 if _bits == 64 else 1):
            known.add(_off + _i * _stride + _s)
cs_known = {r['offset'] + i * r['stride'] + h for r in cs_regs.values()
            for i in range(r['length']) for h in range(2 if r['bits'] == 64 else 1)}
if known & cs_known:
    bad.append(('compute offsets overlap draw', sorted(known & cs_known)))
all_known = known | cs_known
if set(d['known']) != all_known or len(d['known']) != len(all_known):
    bad.append(('known', len(d['known']), len(all_known), sorted(set(d['known']) ^ all_known)[:8]))
if set(d['regs']) != set(X.REGS) | set(cs_regs):
    bad.append(('regset', sorted(set(d['regs']) ^ (set(X.REGS) | set(cs_regs)))))
for name, (off, bits, stride, count, flags) in d['regs'].items():
    q = X.REGS.get(name)
    if q and (off, bits, stride, count) != (q[0], q[1], q[3], q[4]):
        bad.append(('reg', name, (off, bits, stride, count), (q[0], q[1], q[3], q[4])))
    addr = any(f[4] in ('address', 'waddress') for f in q[2]) if q else None
    if q and bool(flags & 2) != addr or q and bool(flags & 1) != (q[1] == 64):
        bad.append(('flags', name, flags))
    if name in cs_regs:
        r = cs_regs[name]
        want = [r['offset'], r['bits'], r['stride'], r['length'],
                int(r['bits'] == 64) | (2 * int(any(f[4] in ('address', 'waddress') for f in r['fields']))) |
                (4 * int(any(f[4] == 'waddress' for f in r['fields'])))]
        if [off, bits, stride, count, flags] != want:
            bad.append(('compute reg', name, [off, bits, stride, count, flags], want))
addr_regs = sorted(n for n, v in d['regs'].items() if v[4] & 2 and n not in cs_regs)
if addr_regs != sorted(n for n, v in X.REGS.items() if v[1] == 64) or len(addr_regs) != 18:
    bad.append(('address set', addr_regs))
# Wire layout (design 2.2): 48 + align64(4*ib) + data + 32*relocs.
al = lambda x: (x + 63) & ~63
want_sizes = [48 + al(4), 48 + al(68) + 64 + 96, al(64), al(68), 48 + al(4 * 0x40000) + 0x100000 + 32 * 16384]
if d['sizes'] != want_sizes:
    bad.append(('sizes', d['sizes'], want_sizes))
if d['limits'] != [0x40000, 0x100000, 16384, 0x200000, len(P.ring_words(0, 1, 0, 0, 0))]:
    bad.append(('limits', d['limits']))
print(json.dumps({'ring_cases': len(d['ring']), 'pkt7': len(d['pkt7']), 'pkt4': len(d['pkt4']),
                  'known_offsets': len(known), 'compute_offsets': len(cs_known),
                  'ib_regs': len(d['regs']), 'draw_address_regs': len(addr_regs),
                  'compute_regs': len(cs_regs),
                  'mismatches': bad[:20]}))
sys.exit(1 if bad else 0)
PY
}
step oracle oracle

# ---- artifact -------------------------------------------------------------------------------------------------
python3 - "$OUT" "$ROOT" "$Q1N1" "$MESA" "$GEN" "$STEPS" <<'PY'
import hashlib, json, os, subprocess, sys
out, root, q1n1, mesa, gen, steps = sys.argv[1:7]
def sha(p):
    try:
        return hashlib.sha256(open(p, 'rb').read()).hexdigest()
    except OSError:
        return None
def rev(p):
    try:
        return subprocess.run(['git', '-C', p, 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
files = ['compat/adreno-guest.h', 'compat/adreno-submit.h', 'compat/adreno-ib-tables.h',
         'tools/gen-adreno-ib-tables.py', 'gpu/adreno-kext/include/AdrenoContract.h',
         'gpu/adreno-kext/include/AdrenoA8xxRegs.h', 'compat/adreno.h', 'compat/adreno-fill.h']
res = {'test': 'tools/test-draw-contract.sh', 'root': root, 'root_head': rev(root),
       'inputs': {f: sha(os.path.join(root, f)) for f in files},
       'generator': {'path': gen, 'sha256': sha(gen)},
       'contract_source_sha256': sha(os.path.join(root, 'tools/test-draw-contract.sh')),
       'compute_mesa_manifest_sha256': sha(os.path.join(out, 'compute-mesa.json')),
       'mesa': {'path': os.path.realpath(mesa), 'revision': rev(mesa)},
       'q1n1': {'path': q1n1, 'head': rev(q1n1),
                **{m: sha(os.path.join(q1n1, m)) for m in ('a8xx_regs.py', 'adreno_x2.py', 'a16gpu_p6p7.py')}},
       'steps': dict(l.split() for l in open(steps) if l.strip())}
for name in ('q1n1', 'oracle'):
    try:
        res[name + '_log'] = open(os.path.join(out, name + '.log')).read().strip().splitlines()[-1]
    except (OSError, IndexError):
        pass
res['verdict'] = 'PASS' if res['steps'] and all(v == 'ok' for v in res['steps'].values()) else 'FAIL'
json.dump(res, open(os.path.join(out, 'draw-contract.json'), 'w'), indent=1, sort_keys=True)
print(f"artifact: {os.path.join(out, 'draw-contract.json')} verdict {res['verdict']}")
PY
exit $FAILED
