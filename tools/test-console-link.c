/* SPDX-License-Identifier: MIT */
/* Offline stand-in for the two-way console (docs/GUEST-SHELL-DESIGN-20261016.md):
 * q1n1's real console and stop handlers (../q1n1/platform/uefi/call-service.c)
 * behind a localhost UDP socket, served only during polls the way the monitor
 * polls q1n1, with the monitor's real console link (compat/console-link.h) and
 * DockChannel receive model (shadow/dockchannel.c) behind them. The "guest"
 * reads the UART exactly as XNU's serial_keyboard_poll does (RX_COUNT, then
 * RX_8, every 16 ms) and runs XNU's "Automatic NMI" matcher over what it gets.
 * Optionally a real shell sits on a pty standing in for /dev/console: what the
 * guest receives is typed into it, and what it prints is the console.
 *
 * Not a unit test of these pieces: tools/test-console-link.py runs
 * tools/guest-console.py against this, with loss, duplication and reordering
 * injected here, and compares the streams byte for byte. One reply leaves per
 * poll, as q1n1's side path keeps one frame in flight; later ones are dropped.
 *
 *   clang -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *     -Wall -Wextra -Werror -I../q1n1/platform/uefi tools/test-console-link.c \
 *     shadow/dockchannel.c ../q1n1/platform/uefi/call-service.c -o build/test-console-link
 *
 * Usage: test-console-link --session HEX [--port N] [--poll-ms N] [--duration S]
 *   [--linger S] [--noise FILE --noise-rate BYTES [--quiet S] [--noise-lines]] [--shell COMMAND]
 *   [--loss P] [--reply-loss P] [--dup P] [--reorder P] [--seed N]
 *   [--produced FILE] [--delivered FILE] [--result FILE]
 * --noise-lines adds noise only as whole lines and only after a newline, so
 * it never splits a line of the shell's. --quiet stops the noise S seconds
 * before the end, so a tool can catch up
 * before the call ends. Prints "port N" once it is listening. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <util.h>
#include "call-service.h"
#include "../compat/console-link.h"

#define RING 65536u                      /* CONSOLE_TAIL_MAX */
#define GUEST_POLL_NS 16000000ull        /* serial_keyboard_poll's 16 ms */
#define REPLY_CAPACITY 1440u             /* NCM_SIDE_REPLY_MAX */

_Static_assert(sizeof(struct console_link_view) == sizeof(struct q1n1_console_view),
               "monitor and q1n1 views agree");
_Static_assert(CONSOLE_LINK_VIEW_MAGIC == Q1N1_CONSOLE_VIEW_MAGIC, "view magic");
_Static_assert(CONSOLE_LINK_STAGING >= Q1N1_CONSOLE_IN_MAX, "one request's input fits staging");

static struct {
    uint64_t requests, dropped_requests, dropped_replies, duplicated, reordered;
    uint64_t one_in_flight, guest_reads, guest_bytes, nmi_entries, shell_bytes, noise_bytes;
} h;

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static uint64_t now_ns(void) { return (uint64_t)(now_s() * 1e9); }

static int chance(double p) { return p > 0 && (double)random() / 2147483647.0 < p; }

static uint8_t ring[RING];
static uint64_t produced;
static FILE *produced_file, *delivered_file;

static void console_put(uint8_t byte)
{
    ring[produced % RING] = byte;
    produced++;
    if (produced_file) fputc(byte, produced_file);
}

int main(int argc, char **argv)
{
    uint64_t session = 0;
    unsigned port = 0, poll_ms = 20, noise_rate = 0, seed = 1, noise_lines = 0;
    double duration = 10, linger = 1, quiet = 0, loss = 0, reply_loss = 0, dup = 0, reorder = 0;
    const char *noise_path = NULL, *shell = NULL, *result_path = NULL;
    for (int n = 1; n < argc; n++) {
        const char *a = argv[n], *v = n + 1 < argc ? argv[n + 1] : NULL;
        if (!strcmp(a, "--noise-lines")) { noise_lines = 1; continue; }
        if (!v) { fprintf(stderr, "%s needs a value\n", a); return 1; }
        n++;
        if (!strcmp(a, "--session")) session = strtoull(v, NULL, 16);
        else if (!strcmp(a, "--port")) port = (unsigned)atoi(v);
        else if (!strcmp(a, "--poll-ms")) poll_ms = (unsigned)atoi(v);
        else if (!strcmp(a, "--duration")) duration = atof(v);
        else if (!strcmp(a, "--linger")) linger = atof(v);
        else if (!strcmp(a, "--quiet")) quiet = atof(v);
        else if (!strcmp(a, "--noise")) noise_path = v;
        else if (!strcmp(a, "--noise-rate")) noise_rate = (unsigned)atoi(v);
        else if (!strcmp(a, "--shell")) shell = v;
        else if (!strcmp(a, "--loss")) loss = atof(v);
        else if (!strcmp(a, "--reply-loss")) reply_loss = atof(v);
        else if (!strcmp(a, "--dup")) dup = atof(v);
        else if (!strcmp(a, "--reorder")) reorder = atof(v);
        else if (!strcmp(a, "--seed")) seed = (unsigned)atoi(v);
        else if (!strcmp(a, "--produced")) produced_file = fopen(v, "wb");
        else if (!strcmp(a, "--delivered")) delivered_file = fopen(v, "wb");
        else if (!strcmp(a, "--result")) result_path = v;
        else { fprintf(stderr, "unknown %s\n", a); return 1; }
    }
    if (!session || !poll_ms) { fprintf(stderr, "--session HEX (nonzero) and --poll-ms\n"); return 1; }
    srandom(seed);

    FILE *noise = noise_path ? fopen(noise_path, "rb") : NULL;
    if (noise_path && !noise) { perror(noise_path); return 1; }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in me = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t me_len = sizeof me;
    if (sock < 0 || bind(sock, (struct sockaddr *)&me, sizeof me) ||
        getsockname(sock, (struct sockaddr *)&me, &me_len) || fcntl(sock, F_SETFL, O_NONBLOCK)) {
        perror("socket");
        return 1;
    }

    int master = -1;
    pid_t child = -1;
    if (shell) {
        child = forkpty(&master, NULL, NULL, NULL);
        if (child < 0) { perror("forkpty"); return 1; }
        if (!child) {
            setenv("TERM", "vt100", 1);
            execl("/bin/sh", "sh", "-c", shell, (char *)NULL);
            _exit(127);
        }
        fcntl(master, F_SETFL, O_NONBLOCK);
    }
    printf("port %u\n", ntohs(me.sin_port));
    fflush(stdout);

    static struct q1n1_call_state state;
    static struct console_link link;
    static struct dockchannel uart;
    q1n1_call_init(&state);
    q1n1_call_arm(&state, session);

    static uint8_t held[REPLY_CAPACITY];
    uint32_t held_length = 0;
    struct sockaddr_in held_to;
    uint64_t nmi_match = 0;
    double start = now_s(), next_poll = start;
    uint64_t next_guest = now_ns();
    int armed = 1;
    for (;;) {
        double t = now_s();
        if (armed && t - start > duration) {
            q1n1_call_disarm(&state);
            armed = 0;
        }
        if (!armed && t - start > duration + linger) break;

        /* The shell's output is console output, as the guest's TX is. */
        if (master >= 0) {
            uint8_t buffer[4096];
            ssize_t got;
            while ((got = read(master, buffer, sizeof buffer)) > 0)
                for (ssize_t n = 0; n < got; n++) { console_put(buffer[n]); h.shell_bytes++; }
        }

        /* The guest: serial_keyboard_poll every 16 ms, a byte at a time. */
        if (now_ns() >= next_guest) {
            next_guest += GUEST_POLL_NS;
            for (;;) {
                uint64_t count = 0, data = 0;
                h.guest_reads++;
                if (dc_read_rx(&uart, armed ? &link.rx : NULL, DC_WINDOW_DATA,
                               DC_BLOCK + DC_DATA_RX_COUNT, &count) != DC_OK) return 2;
                if (!(count & 0x7f)) break;
                h.guest_reads++;
                if (dc_read_rx(&uart, &link.rx, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_RX8, &data) != DC_OK)
                    return 2;
                uint8_t c = (uint8_t)(data >> 8);
                if ((data & 0xff) != 1) return 3;
                h.guest_bytes++;
                /* XNU's own matcher: advance on a match, zero on anything else. */
                nmi_match = c == (uint8_t)CONSOLE_LINK_NMI[nmi_match] ? nmi_match + 1 : 0;
                if (nmi_match == CONSOLE_LINK_NMI_LENGTH) { h.nmi_entries++; nmi_match = 0; }
                if (delivered_file) fputc(c, delivered_file);
                if (master >= 0) { ssize_t w = write(master, &c, 1); (void)w; }
            }
        }

        if (t < next_poll) {
            usleep(1000);
            continue;
        }
        next_poll += poll_ms / 1000.0;

        /* Kernel and launchd logging, at a fixed rate per poll. */
        if (noise && armed && t - start < duration - quiet &&
            (!noise_lines || !produced || ring[(produced - 1) % RING] == '\n'))
            for (unsigned n = 0; n < noise_rate || noise_lines; n++) {
                int c = fgetc(noise);
                if (c == EOF) break;
                console_put((uint8_t)c);
                h.noise_bytes++;
                if (noise_lines && c == '\n' && n + 1 >= noise_rate) break;
            }

        /* One POLL, as main.c runs it: the view only for its duration. */
        struct q1n1_console_view *view = NULL;
        if (armed) {
            console_link_prepare(&link, ring, RING, produced);
            view = (struct q1n1_console_view *)&link.view;
        }
        if (state.polls != UINT64_MAX) state.polls++;
        if (view && view->magic == Q1N1_CONSOLE_VIEW_MAGIC) view->polls_seen++;
        int sent = 0;
        uint64_t before = now_ns();
        for (;;) {
            uint8_t datagram[2048], reply[REPLY_CAPACITY];
            struct sockaddr_in from;
            socklen_t from_len = sizeof from;
            ssize_t got = recvfrom(sock, datagram, sizeof datagram, 0, (struct sockaddr *)&from, &from_len);
            if (got < 0) break;
            h.requests++;
            if (chance(loss)) { h.dropped_requests++; continue; }
            uint32_t n = q1n1_console_request(datagram, (uint32_t)got)
                ? q1n1_console_datagram(&state, view, datagram, (uint32_t)got, reply, sizeof reply)
                : q1n1_stop_datagram(&state, datagram, (uint32_t)got, before, reply);
            if (!n) continue;
            if (sent) { h.one_in_flight++; continue; }
            if (chance(reply_loss)) { h.dropped_replies++; sent = 1; continue; }
            if (!held_length && chance(reorder)) {
                memcpy(held, reply, n);
                held_length = n;
                held_to = from;
                h.reordered++;
                sent = 1;
                continue;
            }
            sendto(sock, reply, n, 0, (struct sockaddr *)&from, from_len);
            if (chance(dup)) { sendto(sock, reply, n, 0, (struct sockaddr *)&from, from_len); h.duplicated++; }
            sent = 1;
            if (held_length) {
                /* The earlier reply, now behind a later one. */
                sendto(sock, held, held_length, 0, (struct sockaddr *)&held_to, sizeof held_to);
                held_length = 0;
            }
        }
        if (armed) {
            console_link_account(&link, now_ns() - before);
            console_link_drain(&link);
        }
    }

    if (child > 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); }
    if (produced_file) fclose(produced_file);
    if (delivered_file) fclose(delivered_file);
    FILE *out = result_path ? fopen(result_path, "w") : stdout;
    if (!out) { perror(result_path); return 1; }
    const struct console_link_view *v = &link.view;
    fprintf(out, "{\n  \"produced\": %llu, \"noise_bytes\": %llu, \"shell_bytes\": %llu,\n",
            (unsigned long long)produced, (unsigned long long)h.noise_bytes,
            (unsigned long long)h.shell_bytes);
    fprintf(out, "  \"guest_bytes\": %llu, \"guest_reads\": %llu, \"nmi_entries\": %llu,\n",
            (unsigned long long)h.guest_bytes, (unsigned long long)h.guest_reads,
            (unsigned long long)h.nmi_entries);
    fprintf(out, "  \"requests\": %llu, \"dropped_requests\": %llu, \"dropped_replies\": %llu, "
            "\"duplicated\": %llu, \"reordered\": %llu, \"one_in_flight\": %llu,\n",
            (unsigned long long)h.requests, (unsigned long long)h.dropped_requests,
            (unsigned long long)h.dropped_replies, (unsigned long long)h.duplicated,
            (unsigned long long)h.reordered, (unsigned long long)h.one_in_flight);
    fprintf(out, "  \"view\": {\"in_held\": %llu, \"owner_changes\": %llu, \"requests\": %llu, "
            "\"refused\": %llu, \"in_duplicate\": %llu, \"in_gaps\": %llu, \"in_overflow\": %llu, "
            "\"out_served\": %llu, \"out_gaps\": %llu, \"polls_seen\": %llu},\n",
            (unsigned long long)v->in_held, (unsigned long long)v->owner_changes,
            (unsigned long long)v->requests, (unsigned long long)v->refused,
            (unsigned long long)v->in_duplicate, (unsigned long long)v->in_gaps,
            (unsigned long long)v->in_overflow, (unsigned long long)v->out_served,
            (unsigned long long)v->out_gaps, (unsigned long long)v->polls_seen);
    fprintf(out, "  \"link\": {\"polls\": %llu, \"staged\": %llu, \"delivered\": %llu, "
            "\"nmi_dropped\": %llu, \"rx_refused\": %llu, \"rx_pushed\": %llu, \"rx_popped\": %llu, "
            "\"rx_waiting\": %u},\n",
            (unsigned long long)link.polls, (unsigned long long)link.staged,
            (unsigned long long)link.delivered, (unsigned long long)link.nmi_dropped,
            (unsigned long long)link.rx_refused, (unsigned long long)link.rx.pushed,
            (unsigned long long)link.rx.popped, link.rx.count);
    fprintf(out, "  \"q1n1\": {\"polls\": %llu, \"datagrams\": %llu, \"malformed\": %llu, "
            "\"refused\": %llu, \"last_status\": %lld}\n}\n",
            (unsigned long long)state.polls, (unsigned long long)state.datagrams,
            (unsigned long long)state.malformed, (unsigned long long)state.refused,
            (long long)(int64_t)state.last_status);
    if (out != stdout) fclose(out);
    return 0;
}
