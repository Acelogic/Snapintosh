/* SPDX-License-Identifier: MIT */
/* EL0 crash ring: classification of every recorded class and of the
 * look-alikes it must ignore, the ring's wrap and field ABI, the bounded
 * frame walk and the reason-string capture through a fake user memory. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user-crash.h"

static unsigned checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

#define SVC 0x56000080UL                 /* EC 0x15, imm16 0x80 */
#define EC(e) ((uint64_t)(e) << 26)

/* Fake user memory: sparse aligned words. */
struct word { uint64_t va, value; };
static struct word memory[64];
static unsigned words, reads, refuse_at = ~0u;

static void poke(uint64_t va, uint64_t value)
{
    memory[words].va = va; memory[words].value = value; words++;
}
static void poke_string(uint64_t va, const char *s)
{
    size_t n = strlen(s) + 1;
    uint64_t base = va & ~7UL, end = (va + n + 7) & ~7UL;
    for (uint64_t w = base; w < end; w += 8) {
        uint64_t value = 0;
        for (unsigned b = 0; b < 8; b++) {
            uint64_t a = w + b;
            if (a >= va && a < va + n) value |= (uint64_t)(unsigned char)s[a - va] << (8 * b);
        }
        poke(w, value);
    }
}
static int reader(void *ctx, uint64_t va, uint64_t *out)
{
    CHECK(ctx == memory);
    CHECK(!(va & 7));
    if (reads++ == refuse_at) return 0;
    for (unsigned i = 0; i < words; i++)
        if (memory[i].va == va) { *out = memory[i].value; return 1; }
    return 0;
}
static void reset(void) { words = reads = 0; refuse_at = ~0u; }

static void classification(void)
{
    /* Syscalls: only XNU's svc #0x80 and only the listed numbers. */
    for (uint64_t sig = 0; sig < 32; sig++) {
        int core = sig == 3 || sig == 4 || sig == 5 || sig == 6 || sig == 7 ||
                   sig == 8 || sig == 10 || sig == 11 || sig == 12;
        CHECK(user_crash_core_signal(sig) == core);
        CHECK(user_crash_classify(SVC, 0, 328, sig) == (core ? USER_CRASH_SELF_SIGNAL : 0));
        CHECK(user_crash_classify(SVC, 0, 37, sig) == (core ? USER_CRASH_KILL : 0));
    }
    CHECK(user_crash_classify(SVC, 0, 521, 0) == USER_CRASH_ABORT_PAYLOAD);
    CHECK(user_crash_classify(SVC, 0, 520, 0) == USER_CRASH_TERMINATE_PAYLOAD);
    CHECK(user_crash_classify(SVC, 0, 529, 0) == USER_CRASH_OS_FAULT);
    for (uint64_t n = 0; n < 1024; n++)
        if (n != 37 && n != 328 && n != 520 && n != 521 && n != 529)
            CHECK(user_crash_classify(SVC, 0, n, 6) == 0);
    CHECK(user_crash_classify(SVC, 0, (uint64_t)-31, 6) == 0);   /* mach_msg2 */
    CHECK(user_crash_classify(EC(0x15) | 0x81, 0, 328, 6) == 0);  /* other imm */
    /* Exception classes XNU turns into the task's own signal. */
    unsigned fatal[] = {0x3c, 0x00, 0x0e, 0x1c, 0x22, 0x26};
    for (unsigned i = 0; i < sizeof fatal / sizeof *fatal; i++)
        CHECK(user_crash_classify(EC(fatal[i]) | 1, 0, 0, 0) == USER_CRASH_EXCEPTION);
    unsigned benign[] = {0x01, 0x07, 0x11, 0x16, 0x17, 0x18, 0x2c, 0x30, 0x32, 0x34};
    for (unsigned i = 0; i < sizeof benign / sizeof *benign; i++)
        CHECK(user_crash_classify(EC(benign[i]), 0, 328, 6) == 0);
    /* Aborts: page zero and the non-user top are wild; the user range is not. */
    uint64_t data = EC(0x24) | 0x07, insn = EC(0x20) | 0x07;
    CHECK(user_crash_classify(data, 0, 0, 0) == USER_CRASH_WILD_ABORT);
    CHECK(user_crash_classify(insn, 0x10, 0, 0) == USER_CRASH_WILD_ABORT);
    CHECK(user_crash_classify(data, 0xffffffffUL, 0, 0) == USER_CRASH_WILD_ABORT);
    CHECK(user_crash_classify(data, 0x100000000UL, 0, 0) == 0);
    CHECK(user_crash_classify(data, 0x16af86bf0UL, 0, 0) == 0);
    CHECK(user_crash_classify(data, 0x7fffffffc000UL, 0, 0) == 0);
    CHECK(user_crash_classify(data, 1UL << 47, 0, 0) == USER_CRASH_WILD_ABORT);
    CHECK(user_crash_classify(data, 0x0020000193470000UL, 0, 0) == USER_CRASH_WILD_ABORT);
    CHECK(user_crash_classify(data, 0xab00000193470000UL, 0, 0) == 0);  /* tag */
    CHECK(user_crash_classify(data, 0xab00000000000010UL, 0, 0) == USER_CRASH_WILD_ABORT);
}

static void registers(uint64_t *x)
{
    for (unsigned i = 0; i < 31; i++) x[i] = 0x1000 + i;
}

static void abort_frames(void)
{
    struct user_crash_ring ring;
    memset(&ring, 0xa5, sizeof ring);
    ring.recorded = ring.walk_reads = ring.walk_refusals = ring.text_refusals = 0;
    uint64_t x[31];
    registers(x);
    /* abort() -> pthread_kill -> __pthread_kill: x29 is pthread_kill's
     * frame; the third record returns into the SkyLight Metal block. */
    uint64_t sp = 0x16af86b00;
    x[0] = 0x103; x[1] = 6; x[16] = 328; x[29] = 0x16af86b40; x[30] = 0x1934d9000;
    reset();
    poke(0x16af86b40, 0x16af86b80); poke(0x16af86b48, 0x19361e6f0);   /* pthread_kill */
    poke(0x16af86b80, 0x16af86c00); poke(0x16af86b88, 0x193490458);   /* abort */
    poke(0x16af86c00, 0x16af86c20); poke(0x16af86c08, 0x199e1b6e4);   /* SkyLight */
    poke(0x16af86c20, 0x16af86c40); poke(0x16af86c28, 0x19347659c);
    poke(0x16af86c40, 0x16af86c80); poke(0x16af86c48, 0x1111);        /* beyond 4 */
    unsigned kind = user_crash_classify(SVC, 0, x[16], x[1]);
    CHECK(kind == USER_CRASH_SELF_SIGNAL);
    user_crash_record(&ring, kind, 3, 82268660267UL, 65354316378UL, SVC, 0x1935db650,
                      0, x, sp, 0xa23308000UL | (0x1fUL << 48), 0xfffffe1e43a13740UL,
                      0x16af87000, reader, memory);
    struct user_crash_record *r = &ring.rows[0];
    CHECK(ring.recorded == 1 && r->seq == 1);
    CHECK((r->meta & 0xff) == USER_CRASH_SELF_SIGNAL && ((r->meta >> 8) & 0xff) == 3);
    CHECK(((r->meta >> 16) & 63) == 0x15 && ((r->meta >> 24) & 7) == 4);
    CHECK(((r->meta >> 28) & 15) == 0 && ((r->meta >> 32) & 7) == 0);
    CHECK(r->frames[0] == 0x19361e6f0 && r->frames[1] == 0x193490458);
    CHECK(r->frames[2] == 0x199e1b6e4 && r->frames[3] == 0x19347659c);
    CHECK(r->guest_count == 82268660267UL && r->raw_count == 65354316378UL);
    CHECK(r->elr == 0x1935db650 && r->x1 == 6 && r->x16 == 328 && r->sp == sp);
    CHECK(r->fp == 0x16af86b40 && r->lr == 0x1934d9000 && r->x0 == 0x103 && r->x2 == x[2]);
    CHECK(r->ttbr0 == (0xa23308000UL | (0x1fUL << 48)) && r->tpidr_el1 == 0xfffffe1e43a13740UL);
    CHECK(r->tpidrro_el0 == 0x16af87000 && r->text[0] == 0);
    CHECK(ring.walk_reads == 8 && ring.walk_refusals == 0);
    CHECK(ring.rows[1].seq == 0xa5a5a5a5a5a5a5a5UL);     /* untouched */
}

static void walk_bounds(void)
{
    struct user_crash_ring ring;
    uint64_t x[31];
    memset(&ring, 0, sizeof ring);
    registers(x);
    uint64_t sp = 0x16f000000;
    struct { uint64_t fp, next; unsigned frames; } cases[] = {
        {0, 0, 0},                                   /* no frame pointer */
        {0x16f000008, 0x16f000100, 0},               /* misaligned */
        {0x16efffff0, 0x16f000100, 0},               /* below SP */
        {0x16f000000 + (8UL << 20), 0, 0},           /* beyond the stack span */
        {0x16f000040, 0x16f000040, 1},               /* self loop stops */
        {0x16f000040, 0x16f000030, 1},               /* descending stops */
        {0x16f000040, 0x0, 1},                       /* null parent */
    };
    for (unsigned i = 0; i < sizeof cases / sizeof *cases; i++) {
        reset();
        x[29] = cases[i].fp;
        if (cases[i].fp) { poke(cases[i].fp, cases[i].next); poke(cases[i].fp + 8, 0x1800000a0 + i); }
        unsigned before = (unsigned)ring.walk_reads;
        user_crash_record(&ring, USER_CRASH_EXCEPTION, 0, 0, 0, EC(0x3c) | 1, 0x100, 0, x,
                          sp, 0, 0, 0, reader, memory);
        struct user_crash_record *r = &ring.rows[(ring.recorded - 1) % USER_CRASH_ROWS];
        CHECK(((r->meta >> 24) & 7) == cases[i].frames);
        CHECK(ring.walk_reads - before == 2 * cases[i].frames);
        if (cases[i].frames) CHECK(r->frames[0] == 0x1800000a0 + i);
        CHECK(r->frames[cases[i].frames < 4 ? cases[i].frames : 3] == 0 || cases[i].frames == 4);
    }
    /* A refused read stops the walk and is counted; no partial frame. */
    reset();
    x[29] = 0x16f000040;
    poke(0x16f000040, 0x16f000080); poke(0x16f000048, 0x180000111);
    refuse_at = 0;
    user_crash_record(&ring, USER_CRASH_EXCEPTION, 0, 0, 0, EC(0x3c) | 1, 0x100, 0, x, sp,
                      0, 0, 0, reader, memory);
    struct user_crash_record *r = &ring.rows[(ring.recorded - 1) % USER_CRASH_ROWS];
    CHECK(ring.walk_refusals == 1 && ((r->meta >> 24) & 7) == 0 && r->frames[0] == 0);
    /* No reader: nothing is walked, the registers are still kept. */
    user_crash_record(&ring, USER_CRASH_EXCEPTION, 0, 0, 0, EC(0x3c) | 1, 0x100, 0, x, sp,
                      0, 0, 0, 0, 0);
    r = &ring.rows[(ring.recorded - 1) % USER_CRASH_ROWS];
    CHECK(((r->meta >> 24) & 7) == 0 && r->fp == x[29]);
}

static void reason_text(void)
{
    struct user_crash_ring ring;
    uint64_t x[31];
    memset(&ring, 0, sizeof ring);
    registers(x);
    x[29] = 0;
    const char *msg = "No suitable Metal devices present after 30 seconds.";
    /* abort_with_payload: reason string in x4, deliberately unaligned. */
    reset();
    poke_string(0x100a3c013, msg);
    x[16] = 521; x[4] = 0x100a3c013;
    user_crash_record(&ring, user_crash_classify(SVC, 0, 521, 0), 1, 0, 0, SVC, 0x100, 0, x,
                      0x16f000000, 0, 0, 0, reader, memory);
    struct user_crash_record *r = &ring.rows[0];
    unsigned n = (unsigned)((r->meta >> 28) & 15), off = (unsigned)((r->meta >> 32) & 7);
    CHECK((r->meta & 0xff) == USER_CRASH_ABORT_PAYLOAD && off == 3);
    CHECK(n == 7);                  /* 51 bytes + NUL from offset 3: bytes 3..54 */
    char text[8 * USER_CRASH_TEXT_WORDS + 1];
    memcpy(text, r->text, sizeof r->text); text[sizeof text - 1] = 0;
    CHECK(!strcmp(text + off, msg) && r->text[7] == 0);
    /* A string longer than the text area is kept truncated, not refused. */
    reset();
    poke_string(0x100a3d000, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefXYZ");
    x[4] = 0x100a3d000;
    user_crash_record(&ring, USER_CRASH_ABORT_PAYLOAD, 1, 0, 0, SVC, 0x100, 0, x,
                      0x16f000000, 0, 0, 0, reader, memory);
    r = &ring.rows[1];
    CHECK(((r->meta >> 28) & 15) == USER_CRASH_TEXT_WORDS && ring.text_refusals == 0);
    CHECK(!memcmp(r->text, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 64));
    /* terminate_with_payload: x5; a short string stops at its NUL word. */
    reset();
    poke_string(0x100b00000, "launchd: exit");
    x[5] = 0x100b00000; x[4] = 0;
    user_crash_record(&ring, USER_CRASH_TERMINATE_PAYLOAD, 1, 0, 0, SVC, 0x100, 0, x,
                      0x16f000000, 0, 0, 0, reader, memory);
    r = &ring.rows[2];
    CHECK(((r->meta >> 28) & 15) == 2 && !strcmp((const char *)r->text, "launchd: exit"));
    /* os_fault_with_payload: x4; an unreadable string is counted. */
    reset();
    x[4] = 0x100c00000;
    user_crash_record(&ring, USER_CRASH_OS_FAULT, 1, 0, 0, SVC, 0x100, 0, x, 0x16f000000,
                      0, 0, 0, reader, memory);
    r = &ring.rows[3];
    CHECK(((r->meta >> 28) & 15) == 0 && ring.text_refusals == 1);
    /* Kinds without a reason argument never read x4/x5. */
    CHECK(user_crash_reason(USER_CRASH_SELF_SIGNAL, x) == 0);
    CHECK(user_crash_reason(USER_CRASH_EXCEPTION, x) == 0);
    CHECK(user_crash_reason(USER_CRASH_TERMINATE_PAYLOAD, x) == x[5]);
}

static void wrap(void)
{
    struct user_crash_ring ring;
    uint64_t x[31];
    memset(&ring, 0, sizeof ring);
    registers(x);
    for (unsigned i = 1; i <= 3 * USER_CRASH_ROWS + 5; i++) {
        x[0] = i;
        user_crash_record(&ring, USER_CRASH_KILL, 2, i, i, SVC, 0x100, 0, x, 0, 0, 0, 0, 0, 0);
    }
    CHECK(ring.recorded == 3 * USER_CRASH_ROWS + 5);
    for (unsigned s = 0; s < USER_CRASH_ROWS; s++) {
        uint64_t seq = ring.rows[s].seq;
        CHECK(seq > ring.recorded - USER_CRASH_ROWS && seq <= ring.recorded);
        CHECK((seq - 1) % USER_CRASH_ROWS == s && ring.rows[s].x0 == seq);
    }
    CHECK(sizeof(struct user_crash_record) == 232);
    CHECK(__builtin_offsetof(struct user_crash_record, frames) == 17 * 8);
    CHECK(__builtin_offsetof(struct user_crash_record, text) == 21 * 8);
    CHECK(__builtin_offsetof(struct user_crash_ring, rows) == 32);
}

int main(void)
{
    classification();
    abort_frames();
    walk_bounds();
    reason_text();
    wrap();
    printf("user crash ring: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
