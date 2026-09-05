/*
 * E2K ucontext syscall regression test.
 *
 * E2K quirk: plain makecontext() does not exist. glibc provides
 * makecontext_e2k() instead, which additionally allocates the hardware
 * procedure/chain stacks (and can therefore fail), and freecontext_e2k()
 * to release them. The ucontext_t must stay alive for the whole lifetime
 * of the coroutine.
 */
#include <errno.h>
#include <fenv.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ucontext.h>

#define CO_STACK_SIZE (64 * 1024)

static ucontext_t main_ctx;
/* Must outlive the coroutine because freecontext_e2k() needs it. */
static ucontext_t co_ctx;
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
    check(makecontext_e2k(&co_ctx, (void (*)(void))argument_body, 10,
                         11L, 22L, 33L, 44L, 55L, 66L, 77L, 88L, 99L, 110L)
          == 0, "make ten-argument context");
    /* The e2k trampoline must follow the live link, not a cached pointer. */
    co_ctx.uc_link = &main_ctx;
    check(swapcontext(&main_ctx, &co_ctx) == 0, "run argument context");
    check(args_seen == 1, "argument function ran");
    check(freecontext_e2k(&co_ctx) == 0, "free argument context");
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
    /* Unlike other ABIs, makecontext_e2k installs default FPU state. */
    check_rounding(FE_TONEAREST);
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
    check(makecontext_e2k(&co_ctx, fpu_body, 0) == 0, "make FPU context");
    check(feclearexcept(FE_ALL_EXCEPT) == 0, "clear main exceptions");
    check(feraiseexcept(FE_DIVBYZERO) == 0, "raise main exception");
    for (int i = 0; i < 101; i++) {
        check(swapcontext(&main_ctx, &co_ctx) == 0, "FPU resume");
        check((fetestexcept(FE_INVALID | FE_DIVBYZERO)) == FE_DIVBYZERO,
              "main FPU exception flags");
        check_rounding(FE_UPWARD);
    }
    check(freecontext_e2k(&co_ctx) == 0, "free FPU context");
    check(fesetenv(&original) == 0, "restore FPU environment");
    puts("PASS: FPU rounding, arithmetic and exception flags");
}

static ucontext_t restart_ctx;
static int restart_old_resumed;
static int restart_runs;

static void restart_old_body(long value)
{
    restart_runs = value;
    check(swapcontext(&restart_ctx, &main_ctx) == 0, "restart yield");
    restart_old_resumed = 1;
}

static void restart_new_body(long value)
{
    restart_runs += value;
}

static void test_restart(void)
{
    check(getcontext(&restart_ctx) == 0, "restart context");
    restart_ctx.uc_stack.ss_sp = co_stack;
    restart_ctx.uc_stack.ss_size = CO_STACK_SIZE;
    restart_ctx.uc_link = &main_ctx;
    check(makecontext_e2k(&restart_ctx, (void (*)(void))restart_old_body, 1,
                          1L) == 0, "make suspended context");
    check(swapcontext(&main_ctx, &restart_ctx) == 0, "run suspended context");
    check(restart_runs == 1, "suspended context ran");

    check(makecontext_e2k(&restart_ctx, (void (*)(void))restart_new_body, 1,
                          10L) == 0, "remake suspended context");
    check(swapcontext(&main_ctx, &restart_ctx) == 0, "run remade context");
    check(restart_runs == 11 && !restart_old_resumed,
          "suspended continuation discarded");

    check(makecontext_e2k(&restart_ctx, (void (*)(void))restart_new_body, 1,
                          20L) == 0, "remake completed context");
    check(swapcontext(&main_ctx, &restart_ctx) == 0,
          "rerun completed context");
    check(restart_runs == 31, "completed context restarted");
    check(freecontext_e2k(&restart_ctx) == 0, "free restarted context");
    puts("PASS: suspended and completed context remake");
}

static ucontext_t deep_ctx;
static int deep_yields;
static unsigned long deep_result;

static __attribute__((noinline)) unsigned long
deep_recurse(int depth, unsigned long seed)
{
    volatile unsigned long keep = seed ^ (unsigned long)depth ^ 0xa5a5a5a5UL;
    unsigned long result;

    if (depth == 0) {
        for (int i = 0; i < 8; i++) {
            deep_yields++;
            check(swapcontext(&deep_ctx, &main_ctx) == 0, "deep-stack yield");
        }
        result = seed;
    } else {
        result = deep_recurse(depth - 1, seed + 0x101UL);
    }
    check(keep == (seed ^ (unsigned long)depth ^ 0xa5a5a5a5UL),
          "deep data stack preserved");
    return result ^ seed ^ (unsigned long)depth;
}

static void deep_body(void)
{
    deep_result = deep_recurse(320, 0x12345678UL);
}

static void test_deep_stacks(void)
{
    check(getcontext(&deep_ctx) == 0, "deep-stack context");
    deep_ctx.uc_stack.ss_sp = co_stack;
    deep_ctx.uc_stack.ss_size = CO_STACK_SIZE;
    deep_ctx.uc_link = &main_ctx;
    check(makecontext_e2k(&deep_ctx, deep_body, 0) == 0,
          "make deep-stack context");
    for (int i = 0; i < 9; i++) {
        check(swapcontext(&main_ctx, &deep_ctx) == 0, "resume deep stack");
    }
    check(deep_yields == 8 && deep_result != 0, "deep context completed");
    check(freecontext_e2k(&deep_ctx) == 0, "free deep-stack context");
    puts("PASS: expanded procedure and chain stacks");
}

static ucontext_t thread_ctx;
static void *thread_stack;
static int thread_ready;
static int thread_stop;

static __attribute__((noinline)) void thread_exit_deep(int depth)
{
    volatile unsigned long keep = 0xfeed0000UL + (unsigned long)depth;

    if (depth) {
        thread_exit_deep(depth - 1);
        check(keep == 0, "thread exit must not return");
    } else {
        __atomic_store_n(&thread_ready, 1, __ATOMIC_RELEASE);
        while (!__atomic_load_n(&thread_stop, __ATOMIC_ACQUIRE)) {
            sched_yield();
        }
        syscall(SYS_exit, 0);
        abort();
    }
}

static void thread_context_body(void)
{
    thread_exit_deep(320);
}

static void *thread_start(void *unused)
{
    (void)unused;
    if (setcontext(&thread_ctx) < 0) {
        return (void *)1;
    }
    return (void *)2;
}

static void test_thread_fork_lifecycle(void)
{
    pthread_t thread;
    void *retval;
    pid_t pid;
    int status;

    thread_stack = malloc(CO_STACK_SIZE);
    check(thread_stack != NULL, "allocate thread context stack");
    check(getcontext(&thread_ctx) == 0, "thread context");
    thread_ctx.uc_stack.ss_sp = thread_stack;
    thread_ctx.uc_stack.ss_size = CO_STACK_SIZE;
    thread_ctx.uc_link = NULL;
    check(makecontext_e2k(&thread_ctx, thread_context_body, 0) == 0,
          "make thread context");
    check(pthread_create(&thread, NULL, thread_start, NULL) == 0,
          "create context thread");
    while (!__atomic_load_n(&thread_ready, __ATOMIC_ACQUIRE)) {
        sched_yield();
    }

    errno = 0;
    check(freecontext_e2k(&thread_ctx) == -1 && errno == EBUSY,
          "active foreign context is busy");
    pid = fork();
    check(pid >= 0, "fork with active context");
    if (pid == 0) {
        errno = 0;
        check(freecontext_e2k(&thread_ctx) == -1 && errno == ENOENT,
              "foreign active context omitted after fork");
        _exit(0);
    }
    check(waitpid(pid, &status, 0) == pid, "wait lifecycle child");
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "forked context registry");

    __atomic_store_n(&thread_stop, 1, __ATOMIC_RELEASE);
    check(pthread_join(thread, &retval) == 0 && retval == NULL,
          "join context thread");
    errno = 0;
    check(freecontext_e2k(&thread_ctx) == -1 && errno == ENOENT,
          "thread exit released active context");
    free(thread_stack);
    puts("PASS: thread exit and fork lifecycle");
}

static void null_link_body(void)
{
    puts("PASS: null-link body");
}

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
        check(makecontext_e2k(&co_ctx, null_link_body, 0) == 0,
              "make null-link context");
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

    /* E2K: allocates HW stacks, may fail, returns int instead of void */
    if (makecontext_e2k(&co_ctx, coroutine_body, 0) < 0) {
        fprintf(stderr, "makecontext_e2k failed\n");
        return 1;
    }

    for (int i = 0; i < 4; i++) {
        printf("main: resume %d\n", i);
        if (swapcontext(&main_ctx, &co_ctx) < 0) {
            perror("swapcontext");
            return 1;
        }
    }
    printf("main: done\n");

    /* E2K: release the HW stacks allocated by makecontext_e2k() */
    if (freecontext_e2k(&co_ctx) < 0) {
        fprintf(stderr, "freecontext_e2k failed\n");
        return 1;
    }
    test_arguments();
    test_fpu();
    test_restart();
    test_deep_stacks();
    test_boundaries();
    test_null_link();
    test_thread_fork_lifecycle();
    free(co_stack);
    puts("PASS: all coroutine tests");
    return 0;
}
