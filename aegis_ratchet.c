/**
 * ============================================================================
 * File: aegis_ratchet.c (BistroHardened Phase 1 & Phase 2 Temporal Ratchet)
 * SPDX-License-Identifier: Apache-2.0
 * Build: gcc -O2 -fPIC -shared -Wall -Wextra aegis_ratchet.c -o libaegis_ratchet.so -ldl
 * ============================================================================
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>                                                #include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

/* Phase 1 Ratchet ビットマスク (main() 突入時に発動) */
#define RATCHET_P1_FREEZE_CODE   (1U << 0) /* mmap(PROT_EXEC) 完全禁止 */
#define RATCHET_P1_FREEZE_EXECVE (1U << 1) /* execve/execveat 完全禁止 */
#define RATCHET_P1_FREEZE_TLS    (1U << 2) /* arch_prctl 完全禁止 */

/* Phase 2 Ratchet ビットマスク (listen() 完了時 = 定常ループ突入 時に発動) */
#define RATCHET_P2_ON_LISTEN     (1U << 3) /* listen() 成功をトリ ガーとして Phase 2 へ遷移 */
#define RATCHET_P2_FREEZE_OPEN   (1U << 4) /* Phase 2 で新規 open/openat/openat2 完全禁止 */
#define RATCHET_P2_FREEZE_NET    (1U << 5) /* Phase 2 で新規 socket/connect/bind/listen 禁止 */
#define RATCHET_P2_FREEZE_FORK   (1U << 6) /* Phase 2 で新規 clone/clone3/fork/vfork 禁止 */

#define RATCHET_LEARN_MODE       (1U << 7)
#define RATCHET_P2_FREEZE_CODE   (1U << 8) /* Phase 2 で新規 mmap(PROT_EXEC) / dlopen 禁止 */ /* 学習モード時は KILL ではなく TRACE 通知 */

/* Builder の学習エンジンへ通知する専用タグ */
#define TRACE_TAG_PHASE1_WX_MMAP 10U
#define TRACE_TAG_PHASE1_EXECVE  11U
#define TRACE_TAG_PHASE2_MARKER  20U /* listen() 完了による Phase 2 突入マーカー */
#define TRACE_TAG_PHASE2_OPEN    21U
#define TRACE_TAG_PHASE2_NET     22U
#define TRACE_TAG_PHASE2_FORK    23U
#define TRACE_TAG_PHASE2_WX_MMAP 24U

typedef int (*main_fn_t)(int, char **, char **);
typedef int (*libc_start_main_fn_t)(main_fn_t, int, char **,
                                    void (*)(void), void (*)(void),
                                    void (*)(void), void *);

static main_fn_t    g_real_main       = NULL;
static unsigned int g_ratchet_mask    = 0;
static bool         g_p1_ratchet_done = false;
static bool         g_p2_ratchet_done = false;

static void emit_insn(struct sock_filter *f, size_t *n, struct sock_filter insn) {
    f[(*n)++] = insn;
}

static void emit_action_nr(struct sock_filter *f, size_t *n, uint32_t nr, uint32_t act) {
    emit_insn(f, n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
    emit_insn(f, n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, act));
}

/* ============================================================================
 * Stage 1: Phase 0 (ld-linux) -> Phase 1 (main) 境界ラチェット
 * ============================================================================ */
static void apply_phase1_seccomp_ratchet(unsigned int mask) {
    if (g_p1_ratchet_done || (mask & 0x07U) == 0) return;
    g_p1_ratchet_done = true;

    bool learn = (mask & RATCHET_LEARN_MODE) != 0;
    struct sock_filter f[64];
    size_t n = 0;

    emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    emit_insn(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));

    if (mask & RATCHET_P1_FREEZE_TLS) {
        emit_action_nr(f, &n, __NR_arch_prctl, SECCOMP_RET_KILL_PROCESS);
    }

    if (mask & RATCHET_P1_FREEZE_EXECVE) {
        uint32_t act = learn ? (SECCOMP_RET_TRACE | TRACE_TAG_PHASE1_EXECVE)
                             : SECCOMP_RET_KILL_PROCESS;
        emit_action_nr(f, &n, __NR_execve, act);
#ifdef __NR_execveat
        emit_action_nr(f, &n, __NR_execveat, act);
#endif
    }

    if (mask & RATCHET_P1_FREEZE_CODE) {
        uint32_t act = learn ? (SECCOMP_RET_TRACE | TRACE_TAG_PHASE1_WX_MMAP)
                             : SECCOMP_RET_KILL_PROCESS;
        emit_insn(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 4));
        emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])));
        emit_insn(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 0, 1));
        emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, act));
        emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    struct sock_fprog prog = {
        .len    = (unsigned short)n,
        .filter = f,
    };
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
        _exit(127);
    }
}

/* ============================================================================
 * Stage 2: Phase 1 (App Init) -> Phase 2 (Steady Loop) 境界ラチェット
 * ============================================================================ */
static void apply_phase2_seccomp_ratchet(unsigned int mask) {
    if (g_p2_ratchet_done) return;
    if (!(mask & RATCHET_P2_ON_LISTEN) && !(mask & RATCHET_LEARN_MODE)) return;
    g_p2_ratchet_done = true;

    bool learn = (mask & RATCHET_LEARN_MODE) != 0;
    struct sock_filter f[96];
    size_t n = 0;

    emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    emit_insn(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));

    /* 1. Phase 2 新規ファイルオープン封印 (open / openat / openat2 / creat) */
    if (learn || (mask & RATCHET_P2_FREEZE_OPEN)) {
        uint32_t act = learn ? (SECCOMP_RET_TRACE | TRACE_TAG_PHASE2_OPEN)
                             : (SECCOMP_RET_ERRNO | EACCES);
        emit_action_nr(f, &n, __NR_open, act);
        emit_action_nr(f, &n, __NR_openat, act);
        emit_action_nr(f, &n, __NR_creat, act);
#ifdef __NR_openat2
        emit_action_nr(f, &n, __NR_openat2, act);
#endif
    }

    /* 2. Phase 2 新規ソケット・外向き接続封印 (リバースシェル完全遮断: socket/connect/bind/listen) */
    if (learn || (mask & RATCHET_P2_FREEZE_NET)) {
        uint32_t act = learn ? (SECCOMP_RET_TRACE | TRACE_TAG_PHASE2_NET)
                             : (SECCOMP_RET_ERRNO | EACCES);
        emit_action_nr(f, &n, __NR_socket, act);
        emit_action_nr(f, &n, __NR_connect, act);
        emit_action_nr(f, &n, __NR_bind, act);
        emit_action_nr(f, &n, __NR_listen, act);
    }

    /* 3. Phase 2 新規プロセス・スレッド生成封印 (clone / clone3 / fork / vfork) */
    if (learn || (mask & RATCHET_P2_FREEZE_FORK)) {
        uint32_t act = learn ? (SECCOMP_RET_TRACE | TRACE_TAG_PHASE2_FORK)
                             : SECCOMP_RET_KILL_PROCESS;
        emit_action_nr(f, &n, __NR_clone, act);
        emit_action_nr(f, &n, __NR_fork, act);
        emit_action_nr(f, &n, __NR_vfork, act);
#ifdef __NR_clone3
        emit_action_nr(f, &n, __NR_clone3, act);
#endif
    }

    /* 4. Phase 2 動的コードロード遅延封印 (Python/動的言語の初期 化後 dlopen 完全遮断) */
    if (learn || (mask & RATCHET_P2_FREEZE_CODE)) {
        uint32_t act = learn ? (SECCOMP_RET_TRACE | TRACE_TAG_PHASE2_WX_MMAP)
                             : SECCOMP_RET_KILL_PROCESS;
        emit_insn(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 3));
        emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])));
        emit_insn(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 0, 1));
        emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, act));
    }

    /* 学習モード時は getppid() を Phase 2 突入通知マーカーとして 利用 */
    if (learn) {
        emit_action_nr(f, &n, __NR_getppid, SECCOMP_RET_TRACE | TRACE_TAG_PHASE2_MARKER);
    }

    emit_insn(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    struct sock_fprog prog = {
        .len    = (unsigned short)n,
        .filter = f,
    };
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
        _exit(127);
    }

    /* 学習エンジン(Builder)に「いま listen() が完了し Phase 2 に 入った！」と通知 */
    if (learn) {
        (void)syscall(__NR_getppid);
    }
}

/* トリガー関数インターセプト: listen() が成功した瞬間に Phase 2  ラチェットを発動 */
int listen(int sockfd, int backlog) {
    long ret = syscall(__NR_listen, sockfd, backlog);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    apply_phase2_seccomp_ratchet(g_ratchet_mask);
    return 0;
}

static void scrub_ratchet_env(void) {
    const char *s = getenv("AEGIS_RATCHET");
    if (s) {
        g_ratchet_mask = (unsigned int)strtoul(s, NULL, 16);
        unsetenv("AEGIS_RATCHET");
    }
    unsetenv("LD_PRELOAD");
}

static int aegis_phase1_main_trampoline(int argc, char **argv, char **envp) {
    scrub_ratchet_env();
    apply_phase1_seccomp_ratchet(g_ratchet_mask);
    return g_real_main(argc, argv, envp);
}

int __libc_start_main(main_fn_t main_fn, int argc, char **ubp_av,
                      void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end) {
    g_real_main = main_fn;
    libc_start_main_fn_t real_start =
        (libc_start_main_fn_t)dlsym(RTLD_NEXT, "__libc_start_main");
    if (!real_start) _exit(127);

    return real_start(aegis_phase1_main_trampoline, argc, ubp_av,
                      init, fini, rtld_fini, stack_end);
}

__attribute__((constructor(65535)))
static void aegis_fallback_ctor(void) {
    if (!g_real_main && !g_p1_ratchet_done) {
        scrub_ratchet_env();
        apply_phase1_seccomp_ratchet(g_ratchet_mask);
    }
}
