/*
 * Emulation of Linux signals
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "user-mmap.h"
#include "signal-common.h"
#include "qemu/queue.h"
#include "qemu/thread.h"
#include "linux-user/trace.h"
#include "target/e2k/helper-tcg.h"

#define MAX_TC_SIZE 10

#define TIR_NUM 19
#define DAM_ENTRIES_NUM 32
#define SBBP_ENTRIES_NUM 32

/* from user.h !!! */
#define MLT_NUM (16 * 3) /* common for E3M and E3S */

struct target_sigcontext {
    abi_ullong cr0_lo;
    abi_ullong cr0_hi;
    abi_ullong cr1_lo;
    abi_ullong cr1_hi;
    abi_ullong sbr;     /* 21 Stack base register: top of */
                        /*    local data (user) stack */
    abi_ullong usd_lo;  /* 22 Local data (user) stack */
    abi_ullong usd_hi;  /* 23 descriptor: base & size */
    abi_ullong psp_lo;  /* 24 Procedure stack pointer: */
    abi_ullong psp_hi;  /* 25 base & index & size */
    abi_ullong pcsp_lo; /* 26 Procedure chain stack */
    abi_ullong pcsp_hi; /* 27 pointer: base & index & size */

    /* additional part (for binary compiler) */
    abi_ullong rpr_hi;
    abi_ullong rpr_lo;

    abi_ullong nr_TIRs;
    abi_ullong tir_lo[TIR_NUM];
    abi_ullong tir_hi[TIR_NUM];
    abi_ullong trap_cell_addr[MAX_TC_SIZE];
    abi_ullong trap_cell_val[MAX_TC_SIZE];
    uint8_t    trap_cell_tag[MAX_TC_SIZE];
    abi_ullong trap_cell_info[MAX_TC_SIZE];

    abi_ullong dam[DAM_ENTRIES_NUM];
    abi_ullong sbbp[SBBP_ENTRIES_NUM];
    abi_ullong mlt[MLT_NUM];
    abi_ullong upsr;
};

/*
 * This structure is used for compatibility
 * All new fields must be added in this structure
 */
struct target_extra_ucontext {
    abi_int sizeof_extra_uc;    /* size of used fields(in bytes) */
    abi_int curr_cnt;           /* current index into trap_celler */
    abi_int tc_count;           /* trap_celler records count */

    /*
     * For getcontext()
     */
    abi_int fpcr;
    abi_int fpsr;
    abi_int pfpfr;

    abi_ullong ctpr1;
    abi_ullong ctpr2;
    abi_ullong ctpr3;

    abi_int sc_need_rstrt;
};

struct target_ucontext {
    abi_ulong uc_flags;
    abi_ulong uc_link;
    target_stack_t uc_stack;
    struct target_sigcontext uc_mcontext;
    union {
        target_sigset_t uc_sigmask; /* mask last for extensibility */
        abi_ullong pad[16];
    };
    struct target_extra_ucontext uc_extra; /* for compatibility */
};

struct target_sigframe {
    target_siginfo_t info;
    union {
        struct target_ucontext uc;
        // TODO: ucontext_prot
    };

    /* FIXME: move this data to TaskState? */
    E2KAauState aau;
    uint64_t lsr;
    uint64_t lsr_lcnt;
    uint32_t ilcr;
    uint64_t ilcr_lcnt;
    // FIXME: according to ABI only 16-31 must be saved
    E2KReg gregs[16];
    uint8_t gtags[16];
};

#define NF_ALIGNEDSZ  (((sizeof(struct target_signal_frame) + 7) & (~7)))

static abi_long setup_sigcontext(CPUE2KState *env,
    struct target_sigcontext *sc, struct target_extra_ucontext *extra)
{
    E2KCrs crs;
    int i, ret;

    // TODO: save binary compiler state (uspr, rpr, MLT)
    __put_user(env->upsr, &sc->upsr);

    ret = e2k_copy_from_user_crs(&crs, env->pcsp.base + env->pcsp.index);
    if (ret) {
        return ret;
    }

    __put_user(crs.cr0_lo, &sc->cr0_lo);
    __put_user(crs.cr0_hi, &sc->cr0_hi);
    __put_user(crs.cr1.lo, &sc->cr1_lo);
    __put_user(crs.cr1.hi, &sc->cr1_hi);

    __put_user(env->sbr, &sc->sbr);
    __put_user(env->usd.lo, &sc->usd_lo);
    __put_user(env->usd.hi, &sc->usd_hi);
    __put_user(env->psp.lo, &sc->psp_lo);
    __put_user(env->psp.hi, &sc->psp_hi);
    __put_user(env->pcsp.lo, &sc->pcsp_lo);
    __put_user(env->pcsp.hi, &sc->pcsp_hi);

    // TODO: save trap state
    __put_user(0, &sc->nr_TIRs);
    __put_user(0, &sc->tir_lo[0]);
    __put_user(0, &sc->tir_hi[0]);
    __put_user(-1, &extra->curr_cnt);
    __put_user(0, &extra->tc_count);

    __put_user(sizeof(struct target_extra_ucontext) - sizeof(abi_int),
        &extra->sizeof_extra_uc);

    __put_user(env->fpcr.raw, &extra->fpcr);
    __put_user(env->fpsr.raw, &extra->fpsr);
    __put_user(env->pfpfr.raw, &extra->pfpfr);

    __put_user(env->ctprs[0].raw, &extra->ctpr1);
    __put_user(env->ctprs[1].raw, &extra->ctpr2);
    __put_user(env->ctprs[2].raw, &extra->ctpr3);

    for (i = 0; i < DAM_ENTRIES_NUM; i++) {
        __put_user(env->dam[i].raw, &sc->dam[i]);
    }

    return 0;
}

static abi_long setup_ucontext(struct target_ucontext *uc, CPUE2KState *env)
{
    __put_user(0, &uc->uc_flags);
    __put_user(0, &uc->uc_link);

    target_save_altstack(&uc->uc_stack, env);
    return setup_sigcontext(env, &uc->uc_mcontext, &uc->uc_extra);
}

static abi_ulong get_sigframe(struct target_sigaction *ka, CPUE2KState *env,
    size_t frame_size)
{
    abi_ulong sp;

    sp = target_sigsp(env->usd.base, ka);
    sp = (sp - frame_size) & ~15;

    return sp;
}

static void target_setup_frame(int sig, struct target_sigaction *ka,
    target_siginfo_t *info, target_sigset_t *set, CPUE2KState *env)
{
    abi_ulong frame_addr;
    struct target_sigframe *frame;

    if (env->is_bp) {
        /* numas13 FIXME: I am not sure that it is a good solution but
         * the way we handle breakpoints requires these steps.
         * Maybe we need to create more fake kernel frames for breakpoints? */
        e2k_proc_return(env, true);
    }

    /* save current frame */
    e2k_proc_call(env, env->wd.size, env->ip, false);

    frame_addr = get_sigframe(ka, env, sizeof(*frame));
    trace_user_setup_rt_frame(env, frame_addr);
    if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0)) {
        force_sigsegv(sig);
    }
    if (setup_ucontext(&frame->uc, env)) {
        goto fail;
    }
    copy_to_user(frame_addr + offsetof(struct target_sigframe, uc.uc_sigmask),
        set, sizeof(*set));
    copy_to_user(frame_addr + offsetof(struct target_sigframe, aau),
        &env->aau, sizeof(env->aau));
    __put_user(env_lsr_get(env), &frame->lsr);
    __put_user(env->lsr_lcnt, &frame->lsr_lcnt);
    __put_user(env->ilcr, &frame->ilcr);
    __put_user(env->ilcr_lcnt, &frame->ilcr_lcnt);
    copy_to_user(frame_addr + offsetof(struct target_sigframe, gregs),
        &env->greg[16], 16 * sizeof(E2KReg));
    if (env->enable_tags) {
        copy_to_user(frame_addr + offsetof(struct target_sigframe, gtags),
            &env->gtag[16], 16);
    }

    if (ka->sa_flags & TARGET_SA_RESTORER) {
        // TODO: sa_restorer?
        qemu_log_mask(LOG_UNIMP, "target_setup_frame sa_restorer +\n");
    } else {
        // TODO: ignore?
    }

    /* fake kernel frame */
    env->wd.size = 0;
    env->wd.psize = 0;
    env->usd.size = env->sbr - frame_addr;
    env->usd.base = frame_addr;
    e2k_proc_call(env, 0, E2K_SIGRET_ADDR, false);

    env->ip = ka->_sa_handler;
    env->wreg[0].lo = sig;
    if (env->enable_tags) {
        env->wtag[0] = E2K_TAG_NUMBER64;
    }
    env->wd.size = 8;

    if (info && (ka->sa_flags & TARGET_SA_SIGINFO)) {
        frame->info = *info;
        env->wreg[1].lo = frame_addr + offsetof(struct target_sigframe, info);
        env->wreg[2].lo = frame_addr + offsetof(struct target_sigframe, uc);
        if (env->enable_tags) {
            env->wtag[1] = E2K_TAG_NUMBER64;
            env->wtag[2] = E2K_TAG_NUMBER64;
        }
    }

    unlock_user_struct(frame, frame_addr, 1);
    return;

fail:
    unlock_user_struct(frame, frame_addr, 1);
    force_sigsegv(sig);
}

static abi_long target_restore_sigframe(CPUE2KState *env,
    struct target_sigframe *frame)
{
    target_ulong crs_addr = env->pcsp.base + env->pcsp.index;
    E2KCrs crs, *p;

    if (!lock_user_struct(VERIFY_WRITE, p, crs_addr, 0)) {
        return -TARGET_EFAULT;
    }
    __get_user(crs.cr0_hi, &frame->uc.uc_mcontext.cr0_hi);
    __put_user(crs.cr0_hi, &p->cr0_hi);
    unlock_user_struct(p, crs_addr, 1);

    __get_user(env->ctprs[0].raw, &frame->uc.uc_extra.ctpr1);
    __get_user(env->ctprs[1].raw, &frame->uc.uc_extra.ctpr2);
    __get_user(env->ctprs[2].raw, &frame->uc.uc_extra.ctpr3);

    return 0;
}

void setup_frame(int sig, struct target_sigaction *ka,
    target_sigset_t *set, CPUE2KState *env)
{
    target_setup_frame(sig, ka, 0, set, env);
}

void setup_rt_frame(int sig, struct target_sigaction *ka,
    target_siginfo_t *info, target_sigset_t *set, CPUE2KState *env)
{
    target_setup_frame(sig, ka, info, set, env);
}

long do_sigreturn(CPUE2KState *env)
{
    return do_rt_sigreturn(env);
}

long do_rt_sigreturn(CPUE2KState *env)
{
    abi_ulong frame_addr;
    struct target_sigframe *frame;
    sigset_t set;

    /* restore fake kernel frame */
    e2k_proc_return(env, false);
    frame_addr = env->usd.base;

    trace_user_do_rt_sigreturn(env, frame_addr);
    if (!lock_user_struct(VERIFY_READ, frame, frame_addr, 1)) {
        goto badframe;
    }

    target_to_host_sigset(&set, &frame->uc.uc_sigmask);
    set_sigmask(&set);

    if (target_restore_sigframe(env, frame)) {
        goto badframe;
    }
    copy_from_user(&env->aau, frame_addr
        + offsetof(struct target_sigframe, aau), sizeof(env->aau));
    __get_user(env->lsr, &frame->lsr);
    __get_user(env->lsr_lcnt, &frame->lsr_lcnt);
    __get_user(env->ilcr, &frame->ilcr);
    __get_user(env->ilcr_lcnt, &frame->ilcr_lcnt);
    copy_from_user(&env->greg[16], frame_addr
        + offsetof(struct target_sigframe, gregs), 16 * sizeof(E2KReg));
    if (env->enable_tags) {
        copy_from_user(&env->gtag[16], frame_addr
            + offsetof(struct target_sigframe, gtags), 16);
    }

    if (do_sigaltstack(frame_addr +
            offsetof(struct target_sigframe, uc.uc_stack),
            0, env) == -EFAULT)
    {
        goto badframe;
    }

    /* restore user */
    e2k_proc_return(env, false);

    unlock_user_struct(frame, frame_addr, 0);
    return -QEMU_ESIGRETURN;

badframe:
    unlock_user_struct(frame, frame_addr, 0);
    force_sig(TARGET_SIGSEGV);
    return -QEMU_ESIGRETURN;
}

/* ------------------------------------------------------------------------
 * Coroutines (e2k ucontext switching)
 *
 * On e2k ucontext switching is implemented by the kernel, glibc only
 * forwards to the {get,set,swap,make,free}context syscalls, because user
 * code cannot manipulate the hardware procedure/chain stacks on its own.
 *
 * Every context is identified by a key which is the top of its data stack
 * (%sbr).  For each known context we keep the CPU state as of the moment
 * the context trapped into the kernel (or as fabricated by makecontext).
 * Restoring a context means restoring that state and letting the normal
 * syscall return path (E2K_SYSRET_ADDR) pop the topmost chain stack frame,
 * which lands back into the glibc wrapper right after its syscall (for
 * saved contexts) or into makecontext_helper (for makecontext'd ones).
 *
 * Stack contents itself (procedure/chain stack memory) is ordinary guest
 * memory and is preserved by the guest, only the live register window has
 * to be saved here.
 */

typedef struct E2KCoroContext {
    uint64_t key;           /* top of the data stack (%sbr) */
    E2KPsp psp;
    E2KPsp pcsp;
    E2KRwap usd;
    uint64_t sbr;
    E2KWdState wd;
    uint32_t wdbl;
    uint64_t pregs;
    uint32_t psr;
    uint32_t cuir;
    uint32_t upsr;
    E2KReg regs[E2K_NR_COUNT];
    uint8_t tags[E2K_NR_COUNT];
    uint64_t lsr;
    uint64_t lsr_lcnt;
    uint32_t ilcr;
    uint64_t ilcr_lcnt;
    bool allocated;         /* PS/PCS were allocated by makecontext */
    TaskState *owner;       /* guest thread currently executing this context */
    bool fresh;
    QTAILQ_ENTRY(E2KCoroContext) entry;
} E2KCoroContext;

static QTAILQ_HEAD(, E2KCoroContext) coro_ctxs =
    QTAILQ_HEAD_INITIALIZER(coro_ctxs);
static QemuMutex coro_ctxs_lock;

static void __attribute__((constructor)) coro_ctxs_init(void)
{
    qemu_mutex_init(&coro_ctxs_lock);
}

static E2KCoroContext *coro_lookup(uint64_t key)
{
    E2KCoroContext *ctx;

    QTAILQ_FOREACH(ctx, &coro_ctxs, entry) {
        if (ctx->key == key) {
            return ctx;
        }
    }
    return NULL;
}

static void coro_munmap_stacks(E2KPsp *psp, E2KPsp *pcsp)
{
    if (psp->base) {
        target_munmap(psp->base, psp->size);
    }
    if (psp->base_tag) {
        target_munmap(psp->base_tag,
                      QEMU_ALIGN_UP(psp->size / 8, TARGET_PAGE_SIZE));
    }
    if (pcsp->base) {
        target_munmap(pcsp->base, pcsp->size);
    }
}

static bool coro_clear_user(abi_ulong addr, size_t size)
{
    void *p = lock_user(VERIFY_WRITE, addr, size, 0);

    if (!p) {
        return false;
    }
    memset(p, 0, size);
    unlock_user(p, addr, size);
    return true;
}

static void coro_free(E2KCoroContext *ctx)
{
    if (ctx->owner) {
        ctx->owner->e2k_coro_current = NULL;
    }
    if (ctx->allocated) {
        coro_munmap_stacks(&ctx->psp, &ctx->pcsp);
    }
    QTAILQ_REMOVE(&coro_ctxs, ctx, entry);
    g_free(ctx);
}

static void coro_save_env(CPUE2KState *env, E2KCoroContext *ctx)
{
    ctx->psp = env->psp;
    ctx->pcsp = env->pcsp;
    ctx->usd = env->usd;
    ctx->sbr = env->sbr;
    ctx->wd = env->wd;
    ctx->wdbl = env->wdbl;
    ctx->pregs = env->pregs;
    ctx->psr = env->psr;
    ctx->cuir = env->cuir;
    ctx->upsr = env->upsr;
    ctx->lsr = env_lsr_get(env);
    ctx->lsr_lcnt = env->lsr_lcnt;
    ctx->ilcr = env->ilcr;
    ctx->ilcr_lcnt = env->ilcr_lcnt;
    memcpy(ctx->regs, env->regs, sizeof(ctx->regs));
    memcpy(ctx->tags, env->tags, sizeof(ctx->tags));
}

static void coro_restore_env(CPUE2KState *env, E2KCoroContext *ctx)
{
    env->psp = ctx->psp;
    env->pcsp = ctx->pcsp;
    env->usd = ctx->usd;
    env->sbr = ctx->sbr;
    env->wd = ctx->wd;
    env->wdbl = ctx->wdbl;
    env->pregs = ctx->pregs;
    env->psr = ctx->psr;
    env->cuir = ctx->cuir;
    env->upsr = ctx->upsr;
    env_lsr_set(env, ctx->lsr);
    env->lsr_lcnt = ctx->lsr_lcnt;
    env->ilcr = ctx->ilcr;
    env->ilcr_lcnt = ctx->ilcr_lcnt;
    memcpy(env->regs, ctx->regs, sizeof(env->regs));
    memcpy(env->tags, ctx->tags, sizeof(env->tags));
}

/* Context syscalls use only the ABI prefix through pfpfr. */
#define E2K_UCONTEXT_SIZE \
    (offsetof(struct target_ucontext, uc_extra.pfpfr) + sizeof(abi_int))

/* Fill @ucp_addr with the current context, getcontext()/swapcontext() part */
static abi_long coro_fill_ucp(CPUE2KState *env, abi_ulong ucp_addr,
                              bool with_crs)
{
    TaskState *ts = get_task_state(env_cpu(env));
    struct target_ucontext *ucp;
    target_sigset_t tset;
    E2KCrs crs;
    E2KPsp pcsp, psp;

    /*
     * The chain stack record on top describes the glibc wrapper frame
     * which invoked the syscall: its cr0/cr1 tell where to return to.
     */
    if (e2k_copy_from_user_crs(&crs, env->pcsp.base + env->pcsp.index)) {
        return -TARGET_EFAULT;
    }

    ucp = lock_user(VERIFY_WRITE, ucp_addr, E2K_UCONTEXT_SIZE, 1);
    if (!ucp) {
        return -TARGET_EFAULT;
    }

    /* Stack pointers describe the state as if the syscall glue frame
     * has already returned, i.e. they point at the wrapper frame. */
    pcsp = env->pcsp;
    pcsp.index -= sizeof(E2KCrs);
    psp = env->psp;
    psp.index -= crs.cr1.wbs * 32;

    host_to_target_sigset(&tset, &ts->signal_mask);
    __put_user(tset.sig[0], &ucp->uc_sigmask.sig[0]);
    __put_user(env->sbr, &ucp->uc_mcontext.nr_TIRs); /* the key */
    __put_user(pcsp.lo, &ucp->uc_mcontext.pcsp_lo);
    __put_user(pcsp.hi, &ucp->uc_mcontext.pcsp_hi);
    __put_user(psp.lo, &ucp->uc_mcontext.psp_lo);
    __put_user(psp.hi, &ucp->uc_mcontext.psp_hi);
    __put_user(env->sbr, &ucp->uc_mcontext.sbr);
    __put_user(env->fpcr.raw, &ucp->uc_extra.fpcr);
    __put_user(env->fpsr.raw, &ucp->uc_extra.fpsr);
    __put_user(env->pfpfr.raw, &ucp->uc_extra.pfpfr);
    if (with_crs) {
        if (e2k_copy_from_user_crs(&crs, pcsp.base + pcsp.index)) {
            unlock_user(ucp, ucp_addr, E2K_UCONTEXT_SIZE);
            return -TARGET_EFAULT;
        }
        __put_user(crs.cr0_hi, &ucp->uc_mcontext.cr0_hi);
        __put_user(crs.cr1.lo, &ucp->uc_mcontext.cr1_lo);
        __put_user(crs.cr1.hi, &ucp->uc_mcontext.cr1_hi);
    }

    unlock_user(ucp, ucp_addr, E2K_UCONTEXT_SIZE);
    return 0;
}

/* Record the current context in the registry, creating an entry if needed */
static abi_long coro_save_current(CPUE2KState *env, E2KCoroContext **ctxp)
{
    TaskState *ts = get_task_state(env_cpu(env));
    E2KCoroContext *ctx = ts->e2k_coro_current;

    if (!ctx) {
        ctx = coro_lookup(env->sbr);
        if (ctx) {
            if (ctx->owner) {
                return -TARGET_EBUSY;
            }
        } else {
            ctx = g_try_new0(E2KCoroContext, 1);
            if (!ctx) {
                return -TARGET_ENOMEM;
            }
            ctx->key = env->sbr;
            ctx->allocated = false;
            QTAILQ_INSERT_TAIL(&coro_ctxs, ctx, entry);
        }
        ctx->owner = ts;
        ts->e2k_coro_current = ctx;
    }
    coro_save_env(env, ctx);
    *ctxp = ctx;
    return 0;
}

void e2k_coro_fork_start(void)
{
    CPUState *cpu;

    qemu_mutex_lock(&coro_ctxs_lock);
    CPU_FOREACH(cpu) {
        TaskState *ts = get_task_state(cpu);

        if (ts->e2k_coro_current) {
            coro_save_env(cpu_env(cpu), ts->e2k_coro_current);
        }
    }
}

void e2k_coro_fork_end(bool child)
{
    if (child) {
        TaskState *ts = get_task_state(thread_cpu);
        E2KCoroContext *ctx, *next;

        QTAILQ_FOREACH_SAFE(ctx, &coro_ctxs, entry, next) {
            if (ctx->owner && ctx->owner != ts) {
                coro_free(ctx);
            }
        }
        qemu_mutex_init(&coro_ctxs_lock);
    } else {
        qemu_mutex_unlock(&coro_ctxs_lock);
    }
}

void e2k_coro_thread_exit(CPUE2KState *env)
{
    TaskState *ts = get_task_state(env_cpu(env));
    E2KCoroContext *ctx;

    qemu_mutex_lock(&coro_ctxs_lock);
    ctx = ts->e2k_coro_current;
    if (ctx) {
        coro_save_env(env, ctx);
        ts->e2k_coro_current = NULL;
        coro_free(ctx);
    }
    qemu_mutex_unlock(&coro_ctxs_lock);
}

static abi_long coro_switch_to(CPUE2KState *env, abi_ulong ucp_addr)
{
    struct target_ucontext *ucp;
    E2KCoroContext *ctx, *old;
    E2KPsp pcsp = { 0 };
    E2KFpcrState fpcr;
    E2KCrs saved = { 0 }, frame;
    target_sigset_t tset = { 0 };
    sigset_t set;
    abi_ullong key;
    uint32_t index, ps_index;
    bool fresh;
    abi_long ret = 0;
    int fpsr, pfpfr;

    ucp = lock_user(VERIFY_READ, ucp_addr, E2K_UCONTEXT_SIZE, 1);
    if (!ucp) {
        return -TARGET_EFAULT;
    }
    __get_user(key, &ucp->uc_mcontext.nr_TIRs);
    __get_user(tset.sig[0], &ucp->uc_sigmask.sig[0]);
    __get_user(fpcr.raw, &ucp->uc_extra.fpcr);
    __get_user(fpsr, &ucp->uc_extra.fpsr);
    __get_user(pfpfr, &ucp->uc_extra.pfpfr);
    __get_user(pcsp.lo, &ucp->uc_mcontext.pcsp_lo);
    __get_user(pcsp.hi, &ucp->uc_mcontext.pcsp_hi);
    __get_user(saved.cr0_hi, &ucp->uc_mcontext.cr0_hi);
    __get_user(saved.cr1.lo, &ucp->uc_mcontext.cr1_lo);
    __get_user(saved.cr1.hi, &ucp->uc_mcontext.cr1_hi);
    unlock_user(ucp, ucp_addr, 0);

    if (fpcr.pc == FPCR_PC_RESERVED) {
        return -TARGET_EINVAL;
    }

    qemu_mutex_lock(&coro_ctxs_lock);
    ret = coro_save_current(env, &old);
    if (ret) {
        goto out;
    }
    ctx = coro_lookup(key);
    if (!ctx) {
        ret = -TARGET_ESRCH;
        goto out;
    }
    if (ctx->owner && ctx != old) {
        ret = -TARGET_EBUSY;
        goto out;
    }
    fresh = ctx->fresh;
    index = ctx->pcsp.index;
    ps_index = ctx->psp.index;
    if (!fresh) {
        if (!pcsp.index || pcsp.index > index ||
            pcsp.index % sizeof(E2KCrs) ||
            saved.cr1.wbs * 2 + 8 > E2K_NR_COUNT) {
            ret = -TARGET_EINVAL;
            goto out;
        }
        /* Bases can move when QEMU expands a hardware stack. */
        while (index >= pcsp.index) {
            if (e2k_copy_from_user_crs(&frame, ctx->pcsp.base + index)) {
                ret = -TARGET_EFAULT;
                goto out;
            }
            if (frame.cr1.wbs * 32 > ps_index) {
                ret = -TARGET_EINVAL;
                goto out;
            }
            ps_index -= frame.cr1.wbs * 32;
            if (index == pcsp.index) {
                break;
            }
            index -= sizeof(E2KCrs);
        }
        ps_index += saved.cr1.wbs * 32;
        if (ps_index > ctx->psp.size ||
            !access_ok(env_cpu(env), VERIFY_READ, ctx->psp.base, ps_index) ||
            (env->enable_tags &&
             !access_ok(env_cpu(env), VERIFY_READ,
                        ctx->psp.base_tag, ps_index / 8))) {
            ret = -TARGET_EFAULT;
            goto out;
        }
        frame.cr0_hi = saved.cr0_hi;
        frame.cr1 = saved.cr1;
        if (e2k_copy_to_user_crs(ctx->pcsp.base + index, &frame)) {
            ret = -TARGET_EFAULT;
            goto out;
        }
    }
    old->owner = NULL;
    ctx->owner = get_task_state(env_cpu(env));
    ctx->owner->e2k_coro_current = ctx;
    ctx->fresh = false;
    coro_restore_env(env, ctx);
    qemu_mutex_unlock(&coro_ctxs_lock);

    target_to_host_sigset(&set, &tset);
    set_sigmask(&set);
    env->fpcr = fpcr;
    env->fpsr.raw = fpsr;
    env->pfpfr.raw = pfpfr;
    e2k_update_fx_status(env);
    e2k_update_fp_status(env);

    if (fresh) {
        return 0;
    }
    env->pcsp.index = index;
    env->psp.index = ps_index;
    env->wd.psize = 8;
    env->wreg[0].lo = 0;
    env->wtag[0] = E2K_TAG_NUMBER64;
    e2k_proc_return(env, true);
    return -QEMU_ESIGRETURN;

out:
    qemu_mutex_unlock(&coro_ctxs_lock);
    return ret;
}

abi_long do_fast_getcontext(CPUArchState *env, abi_ulong ucp_addr,
                            abi_long sigsetsize)
{
    if (sigsetsize != 8) {
        return -TARGET_EINVAL;
    }

    return coro_fill_ucp(env, ucp_addr, false);
}

abi_long do_fast_siggetmask(CPUArchState *env, abi_ulong oset_addr,
                            abi_long sigsetsize)
{
    TaskState *ts = get_task_state(env_cpu(env));
    target_sigset_t tset;
    abi_ullong *oset;

    if (sigsetsize != 8) {
        return -TARGET_EINVAL;
    }

    oset = lock_user(VERIFY_WRITE, oset_addr, 8, 0);
    if (!oset) {
        return -TARGET_EFAULT;
    }
    host_to_target_sigset(&tset, &ts->signal_mask);
    __put_user(tset.sig[0], oset);
    unlock_user(oset, oset_addr, 8);
    return 0;
}

abi_long do_setcontext(CPUArchState *env, abi_ulong ucp_addr,
                       abi_long sigsetsize)
{
    if (sigsetsize != 8) {
        return -TARGET_EINVAL;
    }
    return coro_switch_to(env, ucp_addr);
}

abi_long do_swapcontext(CPUArchState *env, abi_ulong oucp_addr,
                        abi_ulong ucp_addr, abi_long sigsetsize)
{
    E2KCoroContext *old;
    abi_long ret;

    if (sigsetsize != 8) {
        return -TARGET_EINVAL;
    }

    if (!oucp_addr || !ucp_addr) {
        return -TARGET_EFAULT;
    }
    qemu_mutex_lock(&coro_ctxs_lock);
    ret = coro_save_current(env, &old);
    qemu_mutex_unlock(&coro_ctxs_lock);
    if (ret) {
        return ret;
    }
    ret = coro_fill_ucp(env, oucp_addr, true);
    if (ret) {
        return ret;
    }
    if (ucp_addr == oucp_addr) {
        return 0;
    }
    return coro_switch_to(env, ucp_addr);
}

#define E2K_UCTX_STACK_ALIGN 256 /* E2K_ALIGN_USTACK_BOUNDS */
#define E2K_UCTX_FRAME_ALIGN 16  /* E2K_ALIGN_USTACK_SIZE */
/* Register spill area per fabricated frame: C_ABI_PSIZE * EXT_4_NR_SZ */
#define E2K_UCTX_PS_FRAME  (4 * 32)

abi_long do_makecontext(CPUArchState *env, abi_ulong ucp_addr,
                        abi_ulong helper, abi_ulong args_size,
                        abi_ulong args_addr, abi_long sigsetsize)
{
    struct target_ucontext *ucp;
    E2KCoroContext *ctx;
    E2KCrs crs, tramp_crs;
    E2KPsp psp = { 0 }, pcsp = { 0 };
    E2KRwap usd;
    abi_long addr;
    abi_ulong stk_base, aligned_base;
    abi_ulong link_addr;
    abi_ullong stk_size, top, func_frame_size, func_frame_ptr;
    abi_ullong key;
    abi_long ret = 0;
    bool reused = false;
    int i, nreg_args;

    if (sigsetsize != 8) {
        return -TARGET_EINVAL;
    }

    ucp = lock_user(VERIFY_WRITE, ucp_addr, E2K_UCONTEXT_SIZE, 1);
    if (!ucp) {
        return -TARGET_EFAULT;
    }
    __get_user(stk_base, &ucp->uc_stack.ss_sp);
    __get_user(stk_size, &ucp->uc_stack.ss_size);
    link_addr = ucp_addr + offsetof(struct target_ucontext, uc_link);

    if (args_size < 32 || (args_size & 7)) {
        ret = -TARGET_EINVAL;
        goto out;
    }

    aligned_base = QEMU_ALIGN_UP(stk_base, E2K_UCTX_STACK_ALIGN);
    if (aligned_base < stk_base || aligned_base - stk_base > stk_size ||
        stk_size > UINT64_MAX - stk_base || args_size > UINT32_MAX - 15) {
        ret = -TARGET_EINVAL;
        goto out;
    }
    stk_size -= aligned_base - stk_base;
    stk_base = aligned_base;
    stk_size = QEMU_ALIGN_DOWN(stk_size, E2K_UCTX_STACK_ALIGN);
    top = stk_base + stk_size;

    func_frame_size = QEMU_ALIGN_UP(args_size, E2K_UCTX_FRAME_ALIGN);
    if (!stk_size || func_frame_size > stk_size) {
        ret = -TARGET_EINVAL;
        goto out;
    }
    if (!access_ok(env_cpu(env), VERIFY_WRITE, stk_base, stk_size) ||
        !access_ok(env_cpu(env), VERIFY_READ, args_addr, args_size)) {
        ret = -TARGET_EFAULT;
        goto out;
    }
    func_frame_ptr = top - func_frame_size;
    key = top;

    qemu_mutex_lock(&coro_ctxs_lock);
    ctx = coro_lookup(key);
    if (ctx) {
        if (ctx->owner) {
            qemu_mutex_unlock(&coro_ctxs_lock);
            ret = -TARGET_EBUSY;
            goto out;
        }
        psp = ctx->psp;
        pcsp = ctx->pcsp;
        psp.index = 0;
        pcsp.index = 0;
        reused = true;
        memset(ctx->regs, 0, sizeof(ctx->regs));
        memset(ctx->tags, 0, sizeof(ctx->tags));
        ctx->lsr = 0;
        ctx->lsr_lcnt = 0;
        ctx->ilcr = 0;
        ctx->ilcr_lcnt = 0;
        if (!coro_clear_user(psp.base, 2 * E2K_UCTX_PS_FRAME) ||
            !coro_clear_user(psp.base_tag,
                             2 * E2K_UCTX_PS_FRAME / 8) ||
            !coro_clear_user(pcsp.base, 4 * sizeof(E2KCrs))) {
            goto fail;
        }
    } else {
        ctx = g_try_new0(E2KCoroContext, 1);
        if (!ctx) {
            ret = -TARGET_ENOMEM;
            goto fail;
        }
        addr = target_mmap(0, E2K_DEFAULT_PS_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == -1) {
            ret = -TARGET_ENOMEM;
            goto fail;
        }
        e2k_psp_new(&psp, E2K_DEFAULT_PS_SIZE, addr, 0);
        addr = target_mmap(0, QEMU_ALIGN_UP(E2K_DEFAULT_PS_SIZE / 8,
                                           TARGET_PAGE_SIZE),
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == -1) {
            ret = -TARGET_ENOMEM;
            goto fail;
        }
        psp.base_tag = addr;
        addr = target_mmap(0, E2K_DEFAULT_PCS_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == -1) {
            ret = -TARGET_ENOMEM;
            goto fail;
        }
        e2k_psp_new(&pcsp, E2K_DEFAULT_PCS_SIZE, addr, 0);
    }

    /* Frame records at [0..64) and the spill area at [0..128) are zero for
     * both fresh mappings and contexts reset through the reuse path. */

    /* chain stack: trampoline frame at [64], helper frame at [96] */
    memset(&crs, 0, sizeof(crs));
    crs.cr0_hi = E2K_CTXRET_ADDR;
    crs.cr1.wbs = 4; /* C_ABI_PSIZE */
    crs.cr1.wpsz = 4;
    crs.cr1.wfx = 1;
    crs.cr1.psr = PSR_NMIE | PSR_SGE | PSR_IE;
    crs.cr1.ussz = func_frame_size >> 4;
    tramp_crs = crs;
    if (e2k_copy_to_user_crs(pcsp.base + 2 * sizeof(E2KCrs), &crs)) {
        goto fail;
    }

    crs.cr0_hi = helper & ~7;
    if (e2k_copy_to_user_crs(pcsp.base + 3 * sizeof(E2KCrs), &crs)) {
        goto fail;
    }

    /* uc_link for the trampoline: first slot of the procedure stack,
     * then register arguments (16 bytes per register slot) which are
     * read by ps_fill when the helper frame is entered */
    {
        abi_ullong *ps = lock_user(VERIFY_WRITE, psp.base,
                                   2 * E2K_UCTX_PS_FRAME, 0);
        abi_ullong *args = lock_user(VERIFY_READ, args_addr,
                                     MIN(args_size, 64), 1);
        if (!ps || !args) {
            if (ps) {
                unlock_user(ps, psp.base, 0);
            }
            if (args) {
                unlock_user(args, args_addr, 0);
            }
            goto fail;
        }
        __put_user(link_addr, &ps[0]);
        nreg_args = MIN(args_size, 64) / 8;
        for (i = 0; i < nreg_args; i++) {
            abi_ullong val;
            /* Before v5, pairs of low halves precede their high halves. */
            int slot = env->def.isa >= 5 ? i * 2 : (i / 2) * 4 + i % 2;

            __get_user(val, &args[i]);
            __put_user(val, &ps[E2K_UCTX_PS_FRAME / 8 + slot]);
        }
        unlock_user(args, args_addr, 0);
        unlock_user(ps, psp.base, 2 * E2K_UCTX_PS_FRAME);
    }

    /* stack arguments, if any: the helper picks them at %sp + 0x40 */
    if (args_size > 64) {
        void *src, *dst;

        src = lock_user(VERIFY_READ, args_addr + 64, args_size - 64, 1);
        dst = lock_user(VERIFY_WRITE, func_frame_ptr + 64, args_size - 64, 0);
        if (!src || !dst) {
            if (src) {
                unlock_user(src, args_addr + 64, 0);
            }
            goto fail;
        }
        memcpy(dst, src, args_size - 64);
        unlock_user(dst, func_frame_ptr + 64, args_size - 64);
        unlock_user(src, args_addr + 64, 0);
    }

    /* describe the context to the user */
    usd.lo = func_frame_ptr | USD_LO_READ_BIT | USD_LO_WRITE_BIT;
    usd.hi = (uint64_t) func_frame_size << 32;
    psp.index = 2 * E2K_UCTX_PS_FRAME;
    pcsp.index = 3 * sizeof(E2KCrs);

    __put_user(0, &ucp->uc_sigmask.sig[0]);
    __put_user(key, &ucp->uc_mcontext.nr_TIRs);
    __put_user(tramp_crs.cr0_lo, &ucp->uc_mcontext.cr0_lo);
    __put_user(tramp_crs.cr0_hi, &ucp->uc_mcontext.cr0_hi);
    __put_user(tramp_crs.cr1.lo, &ucp->uc_mcontext.cr1_lo);
    __put_user(tramp_crs.cr1.hi, &ucp->uc_mcontext.cr1_hi);
    /* point at the trampoline frame, like the kernel does */
    pcsp.index -= sizeof(E2KCrs);
    __put_user(pcsp.lo, &ucp->uc_mcontext.pcsp_lo);
    __put_user(pcsp.hi, &ucp->uc_mcontext.pcsp_hi);
    pcsp.index += sizeof(E2KCrs);
    __put_user(psp.lo, &ucp->uc_mcontext.psp_lo);
    __put_user(psp.hi, &ucp->uc_mcontext.psp_hi);
    __put_user(usd.lo, &ucp->uc_mcontext.usd_lo);
    __put_user(usd.hi, &ucp->uc_mcontext.usd_hi);
    __put_user(0x33f, &ucp->uc_extra.fpcr);
    __put_user(0x3f, &ucp->uc_extra.fpsr);
    __put_user(0x1fbf, &ucp->uc_extra.pfpfr);

    /* resume state: the sysret pops the helper frame record at [96] */
    ctx->key = key;
    ctx->psp = psp;
    ctx->pcsp = pcsp;
    ctx->usd = usd;
    ctx->sbr = top;
    ctx->wd.base = 0;
    ctx->wd.size = 8;
    ctx->wd.psize = 8;
    ctx->wd.fx = true;
    ctx->wdbl = 0;
    ctx->pregs = 0;
    ctx->psr = PSR_NMIE | PSR_SGE | PSR_IE;
    ctx->cuir = 0;
    ctx->upsr = env->upsr;
    ctx->allocated = true;
    ctx->owner = NULL;
    ctx->fresh = true;
    if (!reused) {
        QTAILQ_INSERT_TAIL(&coro_ctxs, ctx, entry);
    }
    qemu_mutex_unlock(&coro_ctxs_lock);
    goto out;

fail:
    if (reused) {
        coro_free(ctx);
    } else {
        coro_munmap_stacks(&psp, &pcsp);
        g_free(ctx);
    }
    qemu_mutex_unlock(&coro_ctxs_lock);
    ret = ret ? ret : -TARGET_EFAULT;
out:
    unlock_user(ucp, ucp_addr, ret == 0 ? E2K_UCONTEXT_SIZE : 0);
    return ret;
}

abi_long do_freecontext(CPUArchState *env, abi_ulong ucp_addr)
{
    E2KCoroContext *ctx;
    abi_ullong key;

    if (get_user_u64(key, ucp_addr +
                     offsetof(struct target_ucontext, uc_mcontext.nr_TIRs))) {
        return -TARGET_EFAULT;
    }

    qemu_mutex_lock(&coro_ctxs_lock);
    ctx = coro_lookup(key);
    if (!ctx) {
        qemu_mutex_unlock(&coro_ctxs_lock);
        return -TARGET_ENOENT;
    }
    if (ctx->owner) {
        qemu_mutex_unlock(&coro_ctxs_lock);
        return -TARGET_EBUSY;
    }
    coro_free(ctx);
    qemu_mutex_unlock(&coro_ctxs_lock);
    return 0;
}

#if defined(__MCST__) && defined(__LCC__)
void setup_sigtramp(abi_ulong sigtramp_page) {
    abort();
}
#endif
