/*
 * Minimal coroutine demo using ucontext on E2K.
 *
 * E2K quirk: plain makecontext() does not exist. glibc provides
 * makecontext_e2k() instead, which additionally allocates the hardware
 * procedure/chain stacks (and can therefore fail), and freecontext_e2k()
 * to release them. The ucontext_t must stay alive for the whole lifetime
 * of the coroutine.
 *
 * Cross-compile with:
 *   /opt/mcst/lcc-1.29.16.e2k-v4.linux-6.1/bin/lcc -O2 -static -o coroutine-e2k-demo coroutine-e2k-demo.c -lm
 */
#include <errno.h>
#include <fenv.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ucontext.h>

#define CO_STACK_SIZE (64 * 1024)

static ucontext_t main_ctx;
static ucontext_t co_ctx;   /* must outlive the coroutine: freecontext_e2k() needs it */
static void *co_stack;

static void coroutine_body(void)
{
    for (int i = 0; i < 3; i++) {
        printf("coroutine: step %d\n", i);
        /* yield back to main */
        if (swapcontext(&co_ctx, &main_ctx) < 0) {
            perror("swapcontext");
            exit(1);
        }
    }
    printf("coroutine: done\n");
    /* returning follows uc_link, i.e. resumes main */
}

static void check(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "FAIL: %s (errno=%d)\n", what, errno);
        exit(1);
    }
}

static ucontext_t saved_ctx;
static volatile int phase;

static __attribute__((noinline)) void restore_nested(int depth)
{
    volatile unsigned long keep = 0x12340000UL + depth;

    if (depth) {
        restore_nested(depth - 1);
    } else {
        setcontext(&saved_ctx);
    }
    check(keep == 0, "setcontext must not return");
    exit(1);
}

static void test_restore(void)
{
    sigset_t mask, original, observed;

    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    check(sigprocmask(SIG_BLOCK, &mask, &original) == 0, "block signal");
    phase = 0;
    check(getcontext(&saved_ctx) == 0, "getcontext");
    if (phase == 0) {
        phase = 1;
        check(sigprocmask(SIG_UNBLOCK, &mask, NULL) == 0, "unblock signal");
        restore_nested(12);
    }
    check(phase == 1, "second return");
    check(sigprocmask(SIG_SETMASK, NULL, &observed) == 0, "read signal mask");
    check(sigismember(&observed, SIGUSR1) == 1, "restore signal mask");
    check(sigprocmask(SIG_SETMASK, &original, NULL) == 0, "reset signal mask");
    puts("PASS: nested getcontext/setcontext and signal mask");
}

static volatile int args_seen;

static void argument_body(long a, long b, long c, long d, long e,
                          long f, long g, long h, long i, long j)
{
    check(a == 11 && b == 22 && c == 33 && d == 44 && e == 55 &&
          f == 66 && g == 77 && h == 88 && i == 99 && j == 110,
          "ten arguments");
    args_seen++;
}

static void test_arguments(void)
{
    check(getcontext(&co_ctx) == 0, "argument context");
    co_ctx.uc_stack.ss_sp = co_stack;
    co_ctx.uc_stack.ss_size = CO_STACK_SIZE;
    co_ctx.uc_link = NULL;
#ifdef __e2k__
    check(makecontext_e2k(&co_ctx, (void (*)(void))argument_body, 10,
                         11L, 22L, 33L, 44L, 55L, 66L, 77L, 88L, 99L, 110L)
          == 0, "make ten-argument context");
    /* The e2k trampoline must follow the live link, not a cached pointer. */
    co_ctx.uc_link = &main_ctx;
#else
    co_ctx.uc_link = &main_ctx;
    makecontext(&co_ctx, (void (*)(void))argument_body, 10,
                11L, 22L, 33L, 44L, 55L, 66L, 77L, 88L, 99L, 110L);
#endif
    check(swapcontext(&main_ctx, &co_ctx) == 0, "run argument context");
    check(args_seen == 1, "argument function ran");
#ifdef __e2k__
    check(freecontext_e2k(&co_ctx) == 0, "free argument context");
#endif
    puts("PASS: ten arguments and uc_link");
}

static void check_rounding(int mode)
{
    volatile double one = 1.0, small = 0x1p-54;
    volatile long double onel = 1.0L, smalll = 0x1p-65L;

    check(fegetround() == mode, "FPU rounding registers");
    check((one + small > one) == (mode == FE_UPWARD),
          "double arithmetic rounding");
    check((onel + smalll > onel) == (mode == FE_UPWARD),
          "long double arithmetic rounding");
}

static void fpu_body(void)
{
#ifdef __e2k__
    /* Unlike other ABIs, makecontext_e2k installs default FPU state. */
    check_rounding(FE_TONEAREST);
#endif
    check(fesetround(FE_DOWNWARD) == 0, "coroutine rounding mode");
    check(feclearexcept(FE_ALL_EXCEPT) == 0, "clear coroutine exceptions");
    check(feraiseexcept(FE_INVALID) == 0, "raise coroutine exception");
    for (int i = 0; i < 100; i++) {
        check((fetestexcept(FE_INVALID | FE_DIVBYZERO)) == FE_INVALID,
              "coroutine FPU exception flags");
        check_rounding(FE_DOWNWARD);
        check(swapcontext(&co_ctx, &main_ctx) == 0, "FPU yield");
    }
}

static void test_fpu(void)
{
    fenv_t original;

    check(fegetenv(&original) == 0, "save FPU environment");
    check(fesetround(FE_UPWARD) == 0, "saved rounding mode");
    phase = 0;
    check(getcontext(&saved_ctx) == 0, "FPU getcontext");
    if (phase == 0) {
        phase = 1;
        check(fesetround(FE_DOWNWARD) == 0, "changed rounding mode");
        restore_nested(3);
    }
    check_rounding(FE_UPWARD);

    check(getcontext(&co_ctx) == 0, "FPU context");
    co_ctx.uc_stack.ss_sp = co_stack;
    co_ctx.uc_stack.ss_size = CO_STACK_SIZE;
    co_ctx.uc_link = &main_ctx;
#ifdef __e2k__
    check(makecontext_e2k(&co_ctx, fpu_body, 0) == 0, "make FPU context");
#else
    makecontext(&co_ctx, fpu_body, 0);
#endif
    check(feclearexcept(FE_ALL_EXCEPT) == 0, "clear main exceptions");
    check(feraiseexcept(FE_DIVBYZERO) == 0, "raise main exception");
    for (int i = 0; i < 101; i++) {
        check(swapcontext(&main_ctx, &co_ctx) == 0, "FPU resume");
        check((fetestexcept(FE_INVALID | FE_DIVBYZERO)) == FE_DIVBYZERO,
              "main FPU exception flags");
        check_rounding(FE_UPWARD);
    }
#ifdef __e2k__
    check(freecontext_e2k(&co_ctx) == 0, "free FPU context");
#endif
    check(fesetenv(&original) == 0, "restore FPU environment");
    puts("PASS: FPU rounding, arithmetic and exception flags");
}

static void null_link_body(void)
{
    puts("PASS: null-link body");
}

#ifdef __e2k__
static void test_boundaries(void)
{
    size_t page = sysconf(_SC_PAGESIZE);
    size_t prefix = offsetof(ucontext_t, uc_extra.pfpfr) + sizeof(int);
    char *mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ucontext_t *uc;
    int fpcr;

    check(mapping != MAP_FAILED, "map context buffer");
    check(prefix <= page, "context prefix fits page");
    check(mprotect(mapping + page, page, PROT_NONE) == 0, "context guard page");
    uc = (ucontext_t *)(mapping + page - prefix);
    check(getcontext(uc) == 0, "getcontext writes only ABI prefix");
    check(swapcontext(uc, uc) == 0, "self-swap writes only ABI prefix");
    uc->uc_stack.ss_sp = co_stack;
    uc->uc_stack.ss_size = CO_STACK_SIZE;
    uc->uc_link = &main_ctx;
    check(makecontext_e2k(uc, null_link_body, 0) == 0,
          "makecontext writes only ABI prefix");
    fpcr = uc->uc_extra.fpcr;
    uc->uc_extra.fpcr = (fpcr & ~0x300) | 0x100;
    errno = 0;
    check(swapcontext(&main_ctx, uc) == -1 && errno == EINVAL,
          "reserved FPCR rejected");
    uc->uc_extra.fpcr = fpcr;
    check(swapcontext(&main_ctx, uc) == 0, "restore reads only ABI prefix");

    /* freecontext needs only the key, not even the rest of the prefix. */
    uc = (ucontext_t *)(mapping + page -
         offsetof(ucontext_t, uc_mcontext.nr_TIRs) - sizeof(unsigned long long));
    uc->uc_mcontext.nr_TIRs = ((ucontext_t *)(mapping + page - prefix))
                             ->uc_mcontext.nr_TIRs;
    check(freecontext_e2k(uc) == 0, "freecontext reads only key");
    errno = 0;
    check(freecontext_e2k(uc) == -1 && errno == ENOENT, "double free rejected");
    errno = 0;
    check(swapcontext(&main_ctx, (ucontext_t *)(mapping + page)) == -1 &&
          errno == EFAULT, "inaccessible context rejected");
    check(munmap(mapping, 2 * page) == 0, "unmap context buffer");
    puts("PASS: context buffer boundaries and errors");
}
#endif

static void test_null_link(void)
{
    int status;
    pid_t pid = fork();

    check(pid >= 0, "fork");
    if (pid == 0) {
        check(getcontext(&co_ctx) == 0, "null-link context");
        co_ctx.uc_stack.ss_sp = co_stack;
        co_ctx.uc_stack.ss_size = CO_STACK_SIZE;
        co_ctx.uc_link = NULL;
#ifdef __e2k__
        check(makecontext_e2k(&co_ctx, null_link_body, 0) == 0,
              "make null-link context");
#else
        makecontext(&co_ctx, null_link_body, 0);
#endif
        setcontext(&co_ctx);
        _exit(42);
    }
    check(waitpid(pid, &status, 0) == pid, "wait child");
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "null-link exit");
    puts("PASS: null-link exit");
}

int main(void)
{
    setbuf(stdout, NULL);
    test_restore();
    co_stack = malloc(CO_STACK_SIZE);
    if (!co_stack) {
        perror("malloc");
        return 1;
    }

    if (getcontext(&co_ctx) < 0) {
        perror("getcontext");
        return 1;
    }
    co_ctx.uc_link = &main_ctx;
    co_ctx.uc_stack.ss_sp = co_stack;
    co_ctx.uc_stack.ss_size = CO_STACK_SIZE;
    co_ctx.uc_stack.ss_flags = 0;

#ifdef __e2k__
    /* E2K: allocates HW stacks, may fail, returns int instead of void */
    if (makecontext_e2k(&co_ctx, coroutine_body, 0) < 0) {
        fprintf(stderr, "makecontext_e2k failed\n");
        return 1;
    }
#else
    makecontext(&co_ctx, coroutine_body, 0);
#endif

    for (int i = 0; i < 4; i++) {
        printf("main: resume %d\n", i);
        if (swapcontext(&main_ctx, &co_ctx) < 0) {
            perror("swapcontext");
            return 1;
        }
    }
    printf("main: done\n");

#ifdef __e2k__
    /* E2K: release the HW stacks allocated by makecontext_e2k() */
    if (freecontext_e2k(&co_ctx) < 0) {
        fprintf(stderr, "freecontext_e2k failed\n");
        return 1;
    }
#endif
    test_arguments();
    test_fpu();
#ifdef __e2k__
    test_boundaries();
#endif
    test_null_link();
    free(co_stack);
    puts("PASS: all coroutine tests");
    return 0;
}
