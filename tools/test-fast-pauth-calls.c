/* SPDX-License-Identifier: MIT */
/* SNAP_FAST_PAUTH_CALLS differential (tools/test-fine-locks.py Pauth).
 *
 * probes/xnuboot.c's converted pointer calls (fine_pauth_pointer,
 * fine_pauth_batch) against monitor_call_impl's SIGN/AUTH_USER_POINTER and
 * BATCH_SIGN_USER_POINTER cases, as the define-on build compiles them and as
 * the default build does (its inline original): test-fine-locks.py extracts
 * the cases, the helpers they share (user_pointer_call, user_pointer_batch),
 * the native sign callbacks and the converted functions from the monitor
 * source into pauth-extract.h, with TCR_EL1 read from this model, and builds
 * this file with the real engines (compat/pauth-pointer.c, pauth-batch.c,
 * pauth-domain.c, pauth-user.c, aes.c). Only the native helpers
 * (compat/pauth-native.S) are a deterministic model here.
 *
 * Random calls over this CPU's TCR_EL1 (regime, TBI0, TBID0, unrelated bits),
 * PAC bank, key operands and APCTL, the derivation cache, the domain, batch
 * input frames (type, lock, placement, count, records) and injected native
 * failures. Checked (the P numbers of the report's failure modes):
 *  P1  the default build's case and the define-on case agree on everything:
 *      answer, frame, records, publications, every signing record;
 *  P1  a converted call that answers returns the define-on case's frame and
 *      leaves the same signing state, records nothing itself;
 *  P2/P3 a converted call that declines changed nothing (no native call, no
 *      record, no publication) and the case refuses the same call with
 *      SPTM_BAD_CONFIG (the locked path's stop);
 *  P4  a converted failure carries the case's failure record and leaves the
 *      same state (the attempt counted once, by the one engine run);
 *  P5  the case publishes through the token path's memory, the converted
 *      batch through fine_memory, the same ranges in the same order;
 *  coverage: every outcome class below is reached, so no check is vacuous.
 *
 * Build (test-fine-locks.py writes pauth-extract.h into DIR):
 *  clang -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *    -Wall -Wextra -Werror -DSNAP_FINE_LOCKS=1 -DSNAP_FAST_PAUTH_CALLS=1 -Icompat -Ishadow -IDIR \
 *    tools/test-fast-pauth-calls.c compat/pauth-pointer.c compat/pauth-batch.c \
 *    compat/pauth-domain.c compat/pauth-user.c compat/aes.c
 * Arguments: [cases] [seed]. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "cpu.h"
#include "fine-lock.h"
#include "pauth-batch.h"
#include "pauth-domain.h"
#include "pauth-native.h"
#include "pauth-pointer.h"
#include "pauth-switch.h"
#include "pauth-user.h"
#include "sptm.h"
#if !SNAP_FAST_PAUTH_CALLS
#error "build with -DSNAP_FINE_LOCKS=1 -DSNAP_FAST_PAUTH_CALLS=1"
#endif

static unsigned long long checks;
static unsigned current_case;
#define CHECK(x) do { checks++; if(!(x)) { \
    fprintf(stderr,"case %u, line %d: %s\n",current_case,__LINE__,#x); exit(1); } } while(0)

#define FRAME UINT64_C(0x4000)
#define FRAMES 6u                          /* 0..4 batch inputs, 5 this CPU's scratch page */
#define LOW UINT64_C(0x80000000)
#define META UINT64_C(0x90000000)
#define SCRATCH (LOW+5*FRAME)
#define SCRATCH_VA UINT64_C(0xfffffe0100014000)
#define EV_TABLE_FAILED UINT64_C(0x7e1)    /* the monitor's event kind; only compared */

struct vcpu { unsigned slot; };
struct record { uint64_t kind, pc, a, b, c; };
struct publication { uint64_t pa, size, converted; };
struct context {
    /* What the extracted code reads and writes: compared byte for byte up
     * to vcpus (every copy is a memcpy of one zeroed base, so padding agrees). */
    struct pauth_switch pauth_bank[GUEST_CPU_COUNT];
    struct pauth_user_state user_pauth[GUEST_CPU_COUNT];
    struct pauth_derive_cache pauth_derive[GUEST_CPU_COUNT];
    struct pauth_pointer_state pauth_pointer[GUEST_CPU_COUNT];
    struct pauth_batch_state pauth_batch[GUEST_CPU_COUNT];
    struct pauth_domain pauth_domain;
    uint64_t aes_hardware;
    uint8_t ram[FRAMES*FRAME], fm[FRAMES*16];
    /* The model: the running CPU, its TCR_EL1, and what each path reported. */
    struct vcpu vcpus[GUEST_CPU_COUNT];
    unsigned current, records, publications;
    uint64_t tcr, calls;
    struct record record[4];
    struct publication publication[4];
};
#define STATE offsetof(struct context, vcpus)

static struct vcpu *vcpu_of(struct context *c) { return &c->vcpus[c->current]; }
static void record(struct context *c, uint64_t kind, uint64_t pc, uint64_t a, uint64_t b, uint64_t d)
{
    CHECK(c->records < 4);
    c->record[c->records++] = (struct record){kind, pc, a, b, d};
}
static volatile uint8_t *map(void *ctx, uint64_t pa, uint64_t size)
{
    struct context *c = ctx;
    if (pa >= LOW && pa - LOW < sizeof c->ram && size <= sizeof c->ram - (pa - LOW)) return c->ram + (pa - LOW);
    if (pa >= META && pa - META < sizeof c->fm && size <= sizeof c->fm - (pa - META)) return c->fm + (pa - META);
    return 0;
}
static void published(struct context *c, uint64_t pa, uint64_t size, uint64_t converted)
{
    CHECK(c->publications < 4);
    c->publication[c->publications++] = (struct publication){pa, size, converted};
}
static void token_publish(void *ctx, uint64_t pa, uint64_t size) { published(ctx, pa, size, 0); }
static void converted_publish(void *ctx, uint64_t pa, uint64_t size) { published(ctx, pa, size, 1); }
/* sptm_context_memory and fine_memory as far as pauth_batch_sign reads them:
 * the frame map, its geometry, map, and the token path's publisher
 * (sptm_publish) or the converted one (fine_sptm_publish). Either may be
 * unused by a weakened source (test-fine-locks.py's mutants). */
__attribute__((unused)) static struct sptm_memory sptm_context_memory(struct context *c)
{
    return (struct sptm_memory){.frame_map_pa = META, .frame_low = LOW, .frame_high = LOW + FRAMES * FRAME,
                                .map = map, .publish = token_publish, .ctx = c};
}
__attribute__((unused)) static struct sptm_memory fine_memory(struct context *c)
{
    struct sptm_memory m = sptm_context_memory(c);
    m.publish = converted_publish;
    return m;
}

/* compat/pauth-native.S, modeled: a keyed PAC over the pointer's non-PAC bits
 * (bits 54..47, and 63..56 unless TBI applies to the key's class), so a
 * signature authenticates; the injected native call fails, or claims an
 * incomplete restoration. */
static unsigned native_calls, native_fail_at = ~0u, native_unrestored_at = ~0u;
static uint64_t pac_field(const struct pauth_native_request *r)
{
    uint64_t f = UINT64_C(0xff) << 47;
    if (!(r->tbi && (r->key >= 2 || !r->tbid))) f |= UINT64_C(0xff) << 56;
    return f;
}
static int native_model(const struct pauth_native_request *r, struct pauth_native_result *out, int raw)
{
    unsigned n = native_calls++;
    if (!r || !out || r->key > 3 || r->tbi > 1 || r->tbid > 1 || n == native_fail_at) return 1;
    uint64_t field = pac_field(r), bits = r->pointer & ~field;
    uint64_t h = bits ^ r->modifier * UINT64_C(0x9e3779b97f4a7c15) ^ r->key_lo ^ (r->key_hi << 1) ^
                 r->key * 0x51 ^ r->tbi << 7 ^ r->tbid << 9;
    h ^= h >> 29; h *= UINT64_C(0xbf58476d1ce4e5b9); h ^= h >> 32;
    out->signed_pointer = bits | (h & field);
    out->authenticated = raw ? 0 : r->pointer;
    out->restored = n == native_unrestored_at ? 7 : 15;
    return out->restored != 15;
}
int pauth_native_user(const struct pauth_native_request *r, struct pauth_native_result *out)
{ return native_model(r, out, 0); }
int pauth_native_sign_user(const struct pauth_native_request *r, struct pauth_native_result *out)
{ return native_model(r, out, 1); }

/* The monitor's code: locked_off (the default build's cases), locked_on (the
 * define-on cases), fine_pauth_pointer and fine_pauth_batch. */
#include "pauth-extract.h"

static uint64_t seed_state;
static uint64_t rnd(void)
{
    seed_state ^= seed_state << 13; seed_state ^= seed_state >> 7; seed_state ^= seed_state << 17;
    return seed_state;
}
static unsigned below(unsigned n) { return (unsigned)(rnd() % n); }
static void put(struct context *c, uint64_t pa, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) c->ram[pa - LOW + i] = (uint8_t)(v >> (8 * i));
}

/* Outcome classes; each must be reached. */
enum cover {
    C_SIGN, C_AUTH_VALID, C_AUTH_INVALID, C_DECLINE_T0SZ, C_DECLINE_TG0, C_DECLINE_EPD0, C_DECLINE_BANK,
    C_DECLINE_APCTL, C_DECLINE_DOMAIN, C_FATAL_KEY, C_FATAL_UPPER, C_FATAL_NATIVE, C_FATAL_UNRESTORED,
    C_BATCH, C_BATCH_DECLINE, C_BATCH_COUNT, C_BATCH_OUTSIDE, C_BATCH_CROSSING, C_BATCH_TYPE, C_BATCH_LOCK,
    C_BATCH_KEY, C_BATCH_UPPER, C_BATCH_NATIVE, C_DERIVE_HIT, C_DERIVE_MISS, C_COVERS
};
static const char *const cover_name[C_COVERS] = {
    "sign", "auth valid", "auth invalid", "decline T0SZ", "decline TG0", "decline EPD0", "decline bank",
    "decline APCTL", "decline domain", "fatal key", "fatal upper", "fatal native", "fatal unrestored",
    "batch", "batch decline", "batch count", "batch outside", "batch crossing", "batch type", "batch lock",
    "batch key", "batch upper", "batch native", "derive hit", "derive miss"};
static unsigned long cover[C_COVERS];

static uint64_t good_tcr(void)
{
    /* T0SZ 17, TG0 16K-or-4K bits clear, EPD0 clear; TBI0/TBID0 and the
     * bits the check ignores random. */
    uint64_t noise = rnd() & ~(UINT64_C(63) | UINT64_C(1) << 7 | UINT64_C(3) << 14 | UINT64_C(1) << 37 |
                               UINT64_C(1) << 51);
    return noise | 17 | (rnd() & 1) << 37 | (rnd() & 1) << 51;
}

static void same_reports(const struct context *a, const struct context *b, int converted)
{
    CHECK(a->publications == b->publications);
    for (unsigned i = 0; i < a->publications; i++) {
        CHECK(a->publication[i].pa == b->publication[i].pa && a->publication[i].size == b->publication[i].size);
        CHECK(!a->publication[i].converted && b->publication[i].converted == (uint64_t)converted);
    }
}

int main(int argc, char **argv)
{
    unsigned cases = argc > 1 ? (unsigned)strtoul(argv[1], 0, 0) : 20000;
    seed_state = UINT64_C(0x9e3779b97f4a7c15) ^ (argc > 2 ? strtoull(argv[2], 0, 0) : 1);
    struct context *base = calloc(1, sizeof *base), *off = malloc(sizeof *base), *on = malloc(sizeof *base),
                   *fine = malloc(sizeof *base), *pre = malloc(sizeof *base);
    CHECK(base && off && on && fine && pre);
    uint8_t seed[32];
    for (unsigned i = 0; i < 32; i++) seed[i] = (uint8_t)(rnd() >> 13);
    CHECK(pauth_domain_init(&base->pauth_domain, seed));
    for (unsigned n = 0; n < GUEST_CPU_COUNT; n++) {
        base->vcpus[n].slot = n;
        pauth_user_init(&base->user_pauth[n]);
    }
    for (current_case = 0; current_case < cases; current_case++) {
        /* The running CPU and its state: new key operands now and then (a
         * derivation miss), else the cached ones. */
        unsigned slot = below(GUEST_CPU_COUNT);
        base->current = slot;
        struct pauth_user_state *u = &base->user_pauth[slot];
        if (!below(4))
            for (unsigned k = 0; k < PAUTH_KEYS; k++) u->key[k] = (struct pauth_key_pair){rnd(), rnd()};
        if (!below(8)) u->extra = (struct pauth_key_pair){rnd(), rnd()};
        u->apctl = 0x11;
        base->pauth_bank[slot].active = 0;
        base->pauth_domain.ready = 1;
        base->tcr = good_tcr();
        native_fail_at = native_unrestored_at = ~0u;
        unsigned roll = below(100), cause = C_COVERS;
        /* Refusals before anything runs: the converted call declines. */
        if (roll < 3) {base->tcr = (base->tcr & ~UINT64_C(63)) | (below(2) ? 16 : 18 + below(46)); cause = C_DECLINE_T0SZ;}
        else if (roll < 5) {base->tcr |= (UINT64_C(1) + below(3)) << 14; cause = C_DECLINE_TG0;}
        else if (roll < 7) {base->tcr |= UINT64_C(1) << 7; cause = C_DECLINE_EPD0;}
        else if (roll < 9) {base->pauth_bank[slot].active = 1; cause = C_DECLINE_BANK;}
        else if (roll < 11) {u->apctl = below(2) ? 0x10 : 0x1011; cause = C_DECLINE_APCTL;}
        else if (roll < 12) {base->pauth_domain.ready = 0; cause = C_DECLINE_DOMAIN;}
        int declining = cause != C_COVERS;
        uint64_t frame[17] = {0};
        unsigned what = below(10);   /* 0..5 SIGN, 6..7 AUTH, 8..9 BATCH */
        int batch = what >= 8, auth = what == 6 || what == 7;
        frame[16] = batch ? SPTM_FN_BATCH_SIGN_USER_POINTER : auth ? SPTM_FN_AUTH_USER_POINTER : SPTM_FN_SIGN_USER_POINTER;
        uint64_t key = below(2) ? 0 : 2;
        if (!batch) {
            /* SIGN forwards every bit; AUTH of a signature from this state
             * authenticates, of anything else does not. */
            uint64_t pointer = rnd() & ((UINT64_C(1) << 47) - 1);
            if (!below(4)) pointer |= rnd() & UINT64_C(0xff00000000000000);
            if (!auth && !below(8)) pointer = rnd();
            frame[0] = pointer;frame[1] = key | (below(8) ? 0 : UINT64_C(1) << 32);frame[2] = rnd();
            if (!declining && !below(12)) {frame[1] = below(2) ? 1 : 3; cause = C_FATAL_KEY;}
            else if (!declining && auth && !below(6)) {frame[0] |= UINT64_C(1) << 55; cause = C_FATAL_UPPER;}
            else if (!declining && !below(20)) {native_fail_at = 0; cause = C_FATAL_NATIVE;}
            else if (!declining && !below(20)) {native_unrestored_at = 0; cause = C_FATAL_UNRESTORED;}
            if (auth && cause == C_COVERS && below(2)) {
                /* The define-on case's own signature of this pointer. */
                memcpy(pre, base, sizeof *base);
                uint64_t sign[17];memcpy(sign, frame, sizeof sign);
                sign[16] = SPTM_FN_SIGN_USER_POINTER;
                uint64_t elr = 0;
                native_calls = 0;
                if (locked_on(pre, sign, &elr, (struct guest_cpu_buffer){SCRATCH, SCRATCH_VA}) == 1) frame[0] = sign[0];
            }
        } else {
            /* A batch: records in one of the input frames, its type and lock,
             * its placement, its count. */
            memset(base->ram, 0, sizeof base->ram);
            memset(base->fm, 0, sizeof base->fm);
            for (unsigned f = 0; f < FRAMES; f++) base->fm[16 * f + 2] = below(2) ? SPTM_MAC_DEFAULT : SPTM_MAC_KERNEL_RESTRICTED;
            unsigned count = 1 + below(64), f = below(5);
            uint64_t offset = below(4) ? 8 * below((unsigned)((FRAME - 24 * count) / 8 + 1)) :
                              below((unsigned)(FRAME - 24 * count + 1));
            uint64_t input = LOW + f * FRAME + offset;
            unsigned tbi = (unsigned)(base->tcr >> 37) & 1, tbid = (unsigned)(base->tcr >> 51) & 1;
            for (unsigned i = 0; i < count; i++) {
                uint64_t k = below(2) ? 0 : 2, p = rnd() & ((UINT64_C(1) << 47) - 1);
                if (tbi && (k == 2 || !tbid) && below(2)) p |= rnd() & UINT64_C(0xff00000000000000);
                put(base, input + 24 * i, p);put(base, input + 24 * i + 8, rnd());put(base, input + 24 * i + 16, k);
            }
            frame[0] = input;frame[1] = count;
            if (!declining) {
                unsigned shape = below(40);
                if (shape == 0) {frame[1] = below(2) ? 0 : 65; cause = C_BATCH_COUNT;}
                else if (shape == 1) {frame[0] = below(2) ? LOW - 24 : LOW + FRAMES * FRAME + 8 * below(64); cause = C_BATCH_OUTSIDE;}
                else if (shape == 2) {frame[0] = LOW + f * FRAME + FRAME - 8 * (1 + below(3 * count - 1)); cause = C_BATCH_CROSSING;}
                else if (shape == 3) {base->fm[16 * f + 2] = (uint8_t)(1 + below(10)); cause = C_BATCH_TYPE;}
                else if (shape == 4) {base->fm[16 * f] = below(2) ? 1 : 0xf3; base->fm[16 * f + 1] = 0xff * (base->fm[16 * f] == 0xf3); cause = C_BATCH_LOCK;}
                else if (shape == 5) {put(base, input + 24 * below(count) + 16, below(2) ? 1 : 3); cause = C_BATCH_KEY;}
                else if (shape == 6) {
                    uint64_t at = input + 24 * below(count);
                    put(base, at, (UINT64_C(1) << 47) | rnd());
                    cause = C_BATCH_UPPER;
                } else if (shape == 7) {
                    if (below(2)) native_fail_at = below(count); else native_unrestored_at = below(count);
                    cause = C_BATCH_NATIVE;
                }
            }
        }
        /* The three paths from one state. */
        memcpy(off, base, sizeof *base);memcpy(on, base, sizeof *base);memcpy(fine, base, sizeof *base);
        uint64_t f_off[17], f_on[17], f_fine[17];
        memcpy(f_off, frame, sizeof frame);memcpy(f_on, frame, sizeof frame);memcpy(f_fine, frame, sizeof frame);
        const uint64_t elr = UINT64_C(0xfffffe0007100000) + 4 * (uint64_t)current_case;
        uint64_t e_off = elr, e_on = elr;
        const struct guest_cpu_buffer scratch = {SCRATCH, SCRATCH_VA};
        uint64_t hits = base->pauth_derive[slot].hits;
        native_calls = 0;
        int r_off = locked_off(off, f_off, &e_off, scratch);
        unsigned n_off = native_calls;
        native_calls = 0;
        int r_on = locked_on(on, f_on, &e_on, scratch);
        unsigned n_on = native_calls;
        native_calls = 0;
        struct fine_call_state s = {.x16 = frame[16], .a0 = frame[0], .a1 = frame[1], .a2 = frame[2], .a3 = frame[3],
                                    .elr = elr, .kind = batch ? FINE_CALL_PAUTH_BATCH : FINE_CALL_PAUTH,
                                    .reason = FINE_NO_SHAPE};
        int r = batch ? fine_pauth_batch(fine, f_fine, &scratch, &s) : fine_pauth_pointer(fine, f_fine, &s);
        unsigned n_fine = native_calls;

        /* P1: the default build's case is the define-on case. */
        CHECK(r_off == r_on && (r_off == 0 || r_off == 1) && e_off == e_on && n_off == n_on);
        CHECK(!memcmp(f_off, f_on, sizeof f_on) && !memcmp(off, on, STATE) && off->calls == on->calls);
        CHECK(off->records == on->records && !memcmp(off->record, on->record, sizeof on->record));
        same_reports(off, on, 0);
        /* The converted call against the define-on case. */
        CHECK(!fine->records && fine->calls == base->calls);
        if (r == FINE_DONE) {
            CHECK(r_on == 1 && !on->records && e_on == elr + 4 && n_fine == n_on);
            CHECK(!memcmp(f_fine, f_on, sizeof f_on) && !memcmp(fine, on, STATE));
            same_reports(on, fine, 1);
            CHECK(!declining && cause == C_COVERS);
            if (batch) cover[C_BATCH]++;
            else if (!auth) cover[C_SIGN]++;
            else cover[f_on[0] == UINT64_MAX ? C_AUTH_INVALID : C_AUTH_VALID]++;
            if (!batch && fine->pauth_derive[slot].hits != hits) cover[C_DERIVE_HIT]++;
            else if (!batch) cover[C_DERIVE_MISS]++;
        } else if (r == FINE_DECLINE) {
            /* P2/P3: nothing changed; the case refuses it (and stops). */
            CHECK(s.reason == FINE_NO_ENGINE && !n_fine && !fine->publications);
            CHECK(!memcmp(fine, base, STATE) && !memcmp(f_fine, frame, sizeof frame));
            CHECK(r_on == 0 && on->records == 1 && !on->publications);
            CHECK(on->record[0].kind == EV_TABLE_FAILED && on->record[0].pc == elr &&
                  on->record[0].a == SPTM_BAD_CONFIG && on->record[0].b == frame[0] &&
                  on->record[0].c == (uint32_t)frame[16]);
            CHECK(declining);
            cover[batch ? C_BATCH_DECLINE : cause]++;
        } else {
            /* P4: the case's failure record; the same state. */
            CHECK(r == FINE_FATAL && !declining);
            CHECK(r_on == 0 && on->records == 1 && !on->publications && !fine->publications && n_fine == n_on);
            CHECK(s.fail_kind == on->record[0].kind && s.elr == on->record[0].pc && s.result == on->record[0].a &&
                  s.fail_a == on->record[0].b && s.fail_b == on->record[0].c);
            CHECK(!memcmp(fine, on, STATE) && !memcmp(f_fine, frame, sizeof frame) && !memcmp(f_on, frame, sizeof frame));
            CHECK(cause != C_COVERS);
            cover[cause]++;
        }
        /* The next case starts from the define-on case's state (caches,
         * counters and records accumulate as in a run). */
        memcpy(base, on, STATE);
    }
    for (unsigned k = 0; k < C_COVERS; k++)
        if (!cover[k]) {fprintf(stderr, "outcome never reached: %s\n", cover_name[k]); return 1;}
    printf("pauth differential: %u cases, %llu checks; outcomes:", cases, checks);
    for (unsigned k = 0; k < C_COVERS; k++) printf(" %s %lu%s", cover_name[k], cover[k], k + 1 < C_COVERS ? "," : "\n");
    return 0;
}
