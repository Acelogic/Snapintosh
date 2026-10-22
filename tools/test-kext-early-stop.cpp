// SPDX-License-Identifier: MIT
// Host harness for the kext's early-stop request (gpu/adreno-kext/kext/src/AdrenoEarlyStop.cpp).
//
// The real source is compiled for user space against minimal IOService/OSData/IOLog stand-ins that
// tools/test-kext-early-stop.py writes out. The monitor is played by a SIGILL handler: an HVC at EL0 traps,
// and the handler checks it is exactly the word the monitor admits (hvc #0xad16), records x0-x3, answers
// the way compat/early-stop.c does, and steps over it. One scenario per process, because the kext keeps its
// one-shot state in statics for the life of the boot:
//
//   inert     never configured: nothing reaches the monitor
//   refused   GPU nodes without a valid advertisement stay inert
//   present   the first present asks once; later presents and a plug-in report do not ask again
//   failure   a plug-in report asks first; the monitor's refusal comes back; a present does not ask again
//   died      WindowServer's GPU task ending asks once with reason 3; nothing asks after it
//   after     a present asked first: the later end of WindowServer's task does not ask again
//   race      many threads present and report at once: exactly one request reaches the monitor
#include "../gpu/adreno-kext/kext/src/AdrenoEarlyStop.h"
#include "../compat/adreno-guest.h"
#include "../compat/early-stop.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ucontext.h>

static int checks, failures;
static void check(bool condition, const char *label)
{
    if (condition) checks++;
    else {
        failures++;
        printf("FAIL: %s\n", label);
    }
}

static int calls;
static uint64_t seen[4];
static int64_t answer = EARLY_STOP_ACCEPTED;

static void monitor(int, siginfo_t *, void *context)
{
    ucontext_t *uc = (ucontext_t *)context;
    uint32_t word;
    memcpy(&word, (const void *)uc->uc_mcontext->__ss.__pc, sizeof(word));
    if (word != 0xd415a2c2u) abort();                      // anything but the admitted instruction
    __atomic_add_fetch(&calls, 1, __ATOMIC_SEQ_CST);
    for (int n = 0; n < 4; n++) seen[n] = uc->uc_mcontext->__ss.__x[n];
    uc->uc_mcontext->__ss.__x[0] = (uint64_t)answer;
    uc->uc_mcontext->__ss.__x[1] = answer == EARLY_STOP_ACCEPTED ? seen[2] : 0;   // accepted delay
    uc->uc_mcontext->__ss.__x[2] = 3;                                               // monitor phase
    uc->uc_mcontext->__ss.__x[3] = 120;                                             // the launch's bound
    uc->uc_mcontext->__ss.__pc += 4;
}

static OSData *word32(uint32_t value, unsigned length = 4)
{
    OSData *data = new OSData;
    data->bytes.assign(length, 0);
    memcpy(data->bytes.data(), &value, length < 4 ? length : 4);
    return data;
}

static IOService *node(OSData *abi, OSData *delay)
{
    IOService *gpu = new IOService;
    if (abi) gpu->properties[ADRENO_GUEST_STOP_PROPERTY] = abi;
    if (delay) gpu->properties[ADRENO_GUEST_STOP_DELAY_PROPERTY] = delay;
    return gpu;
}

static void inert()
{
    AdrenoEarlyStopConfigure(nullptr);
    AdrenoEarlyStopPresented(1);
    AdrenoEarlyStopClientDied(1);
    check(!AdrenoEarlyStopEnabled(), "not enabled without a configured node");
    check(AdrenoEarlyStopRequest(EARLY_STOP_REASON_PLUGIN_FAILURE, 7) == EARLY_STOP_E_DISABLED,
          "a request without the launch's opt-in is refused locally");
    check(calls == 0, "and nothing reaches the monitor");
}

static void refused()
{
    IOService *bad[] = {
        node(nullptr, nullptr),                                        // an ordinary launch
        node(word32(ADRENO_GUEST_STOP_ABI + 1), word32(20)),           // another ABI
        node(word32(ADRENO_GUEST_STOP_ABI), word32(EARLY_STOP_DELAY_LIMIT + 1)),
        node(word32(ADRENO_GUEST_STOP_ABI, 8), word32(20)),            // not a 32-bit cell
        node(word32(ADRENO_GUEST_STOP_ABI, 2), word32(20)),
    };
    for (IOService *gpu : bad) AdrenoEarlyStopConfigure(gpu);
    AdrenoEarlyStopPresented(1);
    check(!AdrenoEarlyStopEnabled() && calls == 0, "no malformed advertisement enables it");
    check(AdrenoEarlyStopRequest(EARLY_STOP_REASON_PRESENT, 1) == EARLY_STOP_E_DISABLED, "still refused locally");
}

static void present()
{
    AdrenoEarlyStopConfigure(node(word32(ADRENO_GUEST_STOP_ABI), word32(20)));
    check(AdrenoEarlyStopEnabled(), "a valid advertisement enables it");
    AdrenoEarlyStopPresented(42);
    check(calls == 1 && seen[0] == ADRENO_GUEST_STOP && seen[1] == EARLY_STOP_REASON_PRESENT && seen[2] == 20 &&
          seen[3] == 42, "the first present asks: x0 GUEST_STOP, x1 PRESENT, x2 the advertised delay, x3 presents");
    AdrenoEarlyStopPresented(43);
    check(calls == 1, "later presents do not ask again");
    check(AdrenoEarlyStopRequest(EARLY_STOP_REASON_PLUGIN_FAILURE, 5) == EARLY_STOP_DUPLICATE && calls == 1,
          "a later plug-in report is dropped by the kext itself");
}

static void failure()
{
    AdrenoEarlyStopConfigure(node(word32(ADRENO_GUEST_STOP_ABI), word32(0)));
    answer = EARLY_STOP_E_CALLER;
    int status = AdrenoEarlyStopRequest(EARLY_STOP_REASON_PLUGIN_FAILURE, 0x0000123400050067ull);
    check(status == EARLY_STOP_E_CALLER, "the monitor's refusal is the request's answer");
    check(calls == 1 && seen[1] == EARLY_STOP_REASON_PLUGIN_FAILURE && seen[2] == 0 &&
          seen[3] == 0x0000123400050067ull, "the report carries reason 2 and pid << 32 | site");
    AdrenoEarlyStopPresented(1);
    check(calls == 1, "one request per boot, whatever its answer");
}

static void died()
{
    AdrenoEarlyStopConfigure(node(word32(ADRENO_GUEST_STOP_ABI), word32(20)));
    AdrenoEarlyStopClientDied(0x0000000100000011ull);
    check(calls == 1 && seen[0] == ADRENO_GUEST_STOP && seen[1] == EARLY_STOP_REASON_CLIENT_DIED && seen[2] == 20 &&
          seen[3] == 0x0000000100000011ull, "WindowServer's task ending asks with reason 3 and its sequence/allocations");
    AdrenoEarlyStopClientDied(0x0000000200000001ull);
    AdrenoEarlyStopPresented(1);
    check(calls == 1, "a second ending, or a present, does not ask again");
}

static void after()
{
    AdrenoEarlyStopConfigure(node(word32(ADRENO_GUEST_STOP_ABI), word32(20)));
    AdrenoEarlyStopPresented(7);
    AdrenoEarlyStopClientDied(0x0000000100000003ull);
    check(calls == 1 && seen[1] == EARLY_STOP_REASON_PRESENT, "the first present keeps its request; the ending is dropped");
}

static void *worker(void *argument)
{
    uintptr_t n = (uintptr_t)argument;
    if (n & 1) AdrenoEarlyStopPresented(n);
    else AdrenoEarlyStopRequest(EARLY_STOP_REASON_PLUGIN_FAILURE, n);
    return nullptr;
}

static void race()
{
    AdrenoEarlyStopConfigure(node(word32(ADRENO_GUEST_STOP_ABI), word32(20)));
    pthread_t threads[16];
    for (uintptr_t n = 0; n < 16; n++) pthread_create(&threads[n], nullptr, worker, (void *)n);
    for (pthread_t thread : threads) pthread_join(thread, nullptr);
    check(calls == 1, "sixteen racing presents and reports: exactly one request");
}

int main(int argc, char **argv)
{
    struct sigaction action = {};
    action.sa_sigaction = monitor;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGILL, &action, nullptr);
    const struct { const char *name; void (*run)(); } scenarios[] = {
        {"inert", inert}, {"refused", refused}, {"present", present}, {"failure", failure}, {"died", died},
        {"after", after}, {"race", race}};
    for (auto &scenario : scenarios)
        if (argc == 2 && !strcmp(argv[1], scenario.name)) {
            scenario.run();
            if (failures) {
                printf("FAILED %s: %d of %d checks\n", scenario.name, failures, checks + failures);
                return 1;
            }
            printf("PASS %s: %d checks\n", scenario.name, checks);
            return 0;
        }
    fprintf(stderr, "usage: %s inert|refused|present|failure|died|after|race\n", argv[0]);
    return 2;
}
