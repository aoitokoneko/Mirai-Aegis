/**
 * ============================================================================                                                      * File: aegis_init.c (BistroHardened Runtime Security Launcher v4)
 * SPDX-License-Identifier: Apache-2.0
 * Build: gcc -O2 -Wall -Wextra aegis_init.c -o aegis-init
 * ============================================================================                                                      */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/landlock.h>
#include <linux/filter.h>                                         #include <linux/seccomp.h>
#include <linux/audit.h>

#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000U
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

#define DEFAULT_POLICY_PATH "/etc/aegis.policy"
#define RATCHET_SO_PATH     "/lib/libaegis_ratchet.so"
#define MAX_EXTRA_SYSCALLS  512
#define MAX_CUSTOM_ENVS     64
#define MAX_BPF_INSNS       2048

/* SECCOMP_RET_TRACE の通知タグ */
#define TRACE_TAG_SYSCALL   0U
#define TRACE_TAG_OPEN      1U
#define TRACE_TAG_STAT      2U

/* Phase 1 & Phase 2 Ratchet ビットフラグ */
#define RATCHET_P1_FREEZE_CODE   (1U << 0)
#define RATCHET_P1_FREEZE_EXECVE (1U << 1)
#define RATCHET_P1_FREEZE_TLS    (1U << 2)
#define RATCHET_P2_ON_LISTEN     (1U << 3)
#define RATCHET_P2_FREEZE_OPEN   (1U << 4)
#define RATCHET_P2_FREEZE_NET    (1U << 5)
#define RATCHET_P2_FREEZE_FORK   (1U << 6)
#define RATCHET_LEARN_MODE       (1U << 7)
#define RATCHET_P2_FREEZE_CODE   (1U << 8)
#define PRIVSEP_SO_PATH          "/lib/libaegis_privsep.so"

struct aegis_policy_cfg {
    int   extra_syscalls[MAX_EXTRA_SYSCALLS];
    int   extra_count;
    char *env_vars[MAX_CUSTOM_ENVS + 8];
    int   env_count;
    bool  allow_net;
    /* Phase 1 (main突入時) */
    bool  freeze_code;
    bool  freeze_execve;
    bool  freeze_tls;
    /* Phase 2 (listen完了・定常ループ突入時) */
    bool  p2_on_listen;
    bool  p2_freeze_open;
    bool  p2_freeze_net;
    bool  p2_freeze_fork;
    bool p2_freeze_code;
};

static bool is_actively_ptraced(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return false;

    char line[256];
    long tracer_pid = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = strtol(line + 10, NULL, 10);
            break;
        }
    }
    fclose(fp);
    return (tracer_pid > 0);
}

static inline int ll_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
static inline int ll_add_rule(int ruleset_fd, enum landlock_rule_type type, const void *attr, __u32 flags) {
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}
static inline int ll_restrict_self(int ruleset_fd, __u32 flags) {
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

static void add_landlock_path(int ruleset_fd, const char *path, __u64 access_rights) {
    struct stat st;
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return;

    if (fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode)) {
        access_rights &= ~(LANDLOCK_ACCESS_FS_READ_DIR |
                           LANDLOCK_ACCESS_FS_REMOVE_DIR |
                           LANDLOCK_ACCESS_FS_REMOVE_FILE |
                           LANDLOCK_ACCESS_FS_MAKE_REG |
                           LANDLOCK_ACCESS_FS_MAKE_DIR);
    }

    struct landlock_path_beneath_attr rule = {
        .allowed_access = access_rights,
        .parent_fd      = fd,
    };
    if (ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) < 0) {
        fprintf(stderr, "[-] aegis-init: landlock_add_rule failed for '%s': %s\n",
                path, strerror(errno));
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
}

static void add_extra_syscall(struct aegis_policy_cfg *cfg, int nr) {
    if (nr < 0 || nr > 1024) return;
    for (int i = 0; i < cfg->extra_count; i++) {
        if (cfg->extra_syscalls[i] == nr) return;
    }
    if (cfg->extra_count < MAX_EXTRA_SYSCALLS) {
        cfg->extra_syscalls[cfg->extra_count++] = nr;
    }
}

static void add_safe_env(struct aegis_policy_cfg *cfg, const char *kv) {
    if (!strchr(kv, '=')) return;
    if (strncmp(kv, "LD_", 3) == 0) return;
    if (strncmp(kv, "AEGIS_", 6) == 0) return;
    if (cfg->env_count < MAX_CUSTOM_ENVS + 3) {
        char *dup = strdup(kv);
        if (dup) cfg->env_vars[cfg->env_count++] = dup;
    }
}

static void load_policy_and_apply_landlock(const char *policy_path,
                                           const char *target_binary,
                                           struct aegis_policy_cfg *cfg,
                                           bool learn_trace) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->env_vars[cfg->env_count++] = "PATH=/usr/bin:/bin";
    cfg->env_vars[cfg->env_count++] = "LD_BIND_NOW=1";
    cfg->env_vars[cfg->env_count++] = "LANG=C";

    cfg->freeze_code   = true;
    cfg->freeze_execve = true;
    cfg->freeze_tls    = true;

    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE |
                             LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_FILE |
                             LANDLOCK_ACCESS_FS_MAKE_REG |
                             LANDLOCK_ACCESS_FS_MAKE_DIR,
    };

    int ruleset_fd = ll_create_ruleset(&attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        perror("[-] aegis-init: landlock_create_ruleset failed");
        exit(EXIT_FAILURE);
    }

    __u64 rx_rights = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
    __u64 ro_rights = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    __u64 rw_rights = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                      LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG |
                      LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                      LANDLOCK_ACCESS_FS_REMOVE_DIR;

    FILE *fp = fopen(policy_path, "r");
    if (!fp) {
        fprintf(stderr, "[-] aegis-init: cannot open policy '%s': %s\n", policy_path, strerror(errno));
        close(ruleset_fd);
        exit(EXIT_FAILURE);
    }

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;

        if (strncmp(line, "RX ", 3) == 0) {
            add_landlock_path(ruleset_fd, line + 3, rx_rights);
        } else if (strncmp(line, "RO ", 3) == 0) {
            add_landlock_path(ruleset_fd, line + 3, ro_rights);
        } else if (strncmp(line, "RW ", 3) == 0) {
            add_landlock_path(ruleset_fd, line + 3, rw_rights);
        } else if (strncmp(line, "SYSCALL ", 8) == 0) {
            char *endp = NULL;
            long nr = strtol(line + 8, &endp, 10);
            if (endp != line + 8) add_extra_syscall(cfg, (int)nr);
        } else if (strncmp(line, "ALLOW_NET ", 10) == 0) {
            if (atoi(line + 10) == 1) cfg->allow_net = true;
        } else if (strncmp(line, "FREEZE_CODE ", 12) == 0) {
            cfg->freeze_code = (atoi(line + 12) != 0);
        } else if (strncmp(line, "FREEZE_EXECVE ", 14) == 0) {
            cfg->freeze_execve = (atoi(line + 14) != 0);
        } else if (strncmp(line, "FREEZE_TLS ", 11) == 0) {
            cfg->freeze_tls = (atoi(line + 11) != 0);
        } else if (strncmp(line, "PHASE2_ON_LISTEN ", 17) == 0) {
            cfg->p2_on_listen = (atoi(line + 17) != 0);
        } else if (strncmp(line, "PHASE2_FREEZE_OPEN ", 19) == 0) {
            cfg->p2_freeze_open = (atoi(line + 19) != 0);
        } else if (strncmp(line, "PHASE2_FREEZE_NET ", 18) == 0) {
            cfg->p2_freeze_net = (atoi(line + 18) != 0);
        } else if (strncmp(line, "PHASE2_FREEZE_FORK ", 19) == 0) {
            cfg->p2_freeze_fork = (atoi(line + 19) != 0);
        } else if (strncmp(line, "PHASE2_FREEZE_CODE ", 19) == 0) {
            cfg->p2_freeze_code = (atoi(line + 19) != 0);
        } else if (strncmp(line, "ENV ", 4) == 0) {
            add_safe_env(cfg, line + 4);
        }
    }
    fclose(fp);

    const char *ratchet_so = RATCHET_SO_PATH;
    if (learn_trace) {
        const char *env_rso = getenv("AEGIS_RATCHET_SO");
        if (env_rso && env_rso[0] == '/') ratchet_so = env_rso;
    }

    if (access(ratchet_so, R_OK) == 0) {
        add_landlock_path(ruleset_fd, ratchet_so, rx_rights);
        unsigned int rmask = 0;
        if (cfg->freeze_code)    rmask |= RATCHET_P1_FREEZE_CODE;
        if (cfg->freeze_execve)  rmask |= RATCHET_P1_FREEZE_EXECVE;
        if (cfg->freeze_tls)     rmask |= RATCHET_P1_FREEZE_TLS;
        if (cfg->p2_on_listen)   rmask |= RATCHET_P2_ON_LISTEN;
        if (cfg->p2_freeze_open) rmask |= RATCHET_P2_FREEZE_OPEN;
        if (cfg->p2_freeze_net)  rmask |= RATCHET_P2_FREEZE_NET;
        if (cfg->p2_freeze_fork) rmask |= RATCHET_P2_FREEZE_FORK;
        if (cfg->p2_freeze_code) rmask |= RATCHET_P2_FREEZE_CODE;
        if (learn_trace)         rmask |= RATCHET_LEARN_MODE;

        if (rmask != 0) {
            static char preload_env[4096];
            static char ratchet_env[64];
            if (access(PRIVSEP_SO_PATH, R_OK) == 0) {
                add_landlock_path(ruleset_fd, PRIVSEP_SO_PATH, rx_rights);
                add_extra_syscall(cfg, 447); /* __NR_memfd_secret */
                snprintf(preload_env, sizeof(preload_env), "LD_PRELOAD=%s:%s", PRIVSEP_SO_PATH, ratchet_so);
            } else {
                snprintf(preload_env, sizeof(preload_env), "LD_PRELOAD=%s", ratchet_so);
            }
            snprintf(ratchet_env, sizeof(ratchet_env), "AEGIS_RATCHET=0x%x", rmask);
            cfg->env_vars[cfg->env_count++] = preload_env;
            cfg->env_vars[cfg->env_count++] = ratchet_env;
        }
    }

    cfg->env_vars[cfg->env_count] = NULL;

    add_landlock_path(ruleset_fd, target_binary, LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE);

    if (ll_restrict_self(ruleset_fd, 0) < 0) {
        perror("[-] aegis-init: landlock_restrict_self failed");
        close(ruleset_fd);
        exit(EXIT_FAILURE);
    }
    close(ruleset_fd);
}

static void bpf_emit(struct sock_filter *buf, size_t *idx, struct sock_filter insn) {
    if (*idx >= MAX_BPF_INSNS) {
        fprintf(stderr, "[-] aegis-init: BPF filter overflow\n");
        exit(EXIT_FAILURE);
    }
    buf[(*idx)++] = insn;
}

static void bpf_allow_nr(struct sock_filter *buf, size_t *idx, uint32_t nr) {
    bpf_emit(buf, idx, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
    bpf_emit(buf, idx, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
}

static void bpf_kill_nr(struct sock_filter *buf, size_t *idx, uint32_t nr) {
    bpf_emit(buf, idx, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
    bpf_emit(buf, idx, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
}

static void bpf_errno_nr(struct sock_filter *buf, size_t *idx, uint32_t nr, uint16_t err) {
    bpf_emit(buf, idx, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
    bpf_emit(buf, idx, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (err & SECCOMP_RET_DATA)));
}

static void bpf_trace_nr(struct sock_filter *buf, size_t *idx, uint32_t nr, uint16_t tag) {
    bpf_emit(buf, idx, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
    bpf_emit(buf, idx, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | (tag & SECCOMP_RET_DATA)));
}

static void apply_seccomp_filter(const struct aegis_policy_cfg *cfg, bool learn_trace, bool learn_files) {
    struct sock_filter f[MAX_BPF_INSNS];
    size_t n = 0;

    /* 1. アーキテクチャ検証 (x86_64限定) */
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    bpf_emit(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    /* 2. システムコール番号ロード & x32 ABI 遮断 */
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));
    bpf_emit(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, __X32_SYSCALL_BIT, 0, 1));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    /* 3. Phase 0 Strict W^X: mmap RWX 処刑 */
    bpf_emit(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 5));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_WRITE | PROT_EXEC));
    bpf_emit(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROT_WRITE | PROT_EXEC, 0, 1));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    /* 4. Strict W^X: mprotect PROT_EXEC 処刑 */
    bpf_emit(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 4));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])));
    bpf_emit(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 0, 1));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

#ifdef __NR_pkey_mprotect
    bpf_emit(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pkey_mprotect, 0, 4));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])));
    bpf_emit(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 0, 1));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
#endif

    /* 5. 不変ブラックリスト */
    static const uint32_t never_allow[] = {
        __NR_ptrace, __NR_kexec_load, __NR_mount, __NR_umount2,
        __NR_pivot_root, __NR_chroot, __NR_init_module, __NR_swapon,
        __NR_swapoff, __NR_reboot, __NR_setns, __NR_unshare,
#ifdef __NR_finit_module
        __NR_finit_module,
#endif
#ifdef __NR_bpf
        __NR_bpf,
#endif
#ifdef __NR_userfaultfd
        __NR_userfaultfd,
#endif
#ifdef __NR_memfd_create
        __NR_memfd_create,
#endif
#ifdef __NR_io_uring_setup
        __NR_io_uring_setup, __NR_io_uring_enter, __NR_io_uring_register,
#endif
    };
    for (size_t i = 0; i < sizeof(never_allow) / sizeof(never_allow[0]); i++) {
        bpf_kill_nr(f, &n, never_allow[i]);
    }

    /* 6. ネットワーク制御 */
    if (!cfg->allow_net) {
        bpf_errno_nr(f, &n, __NR_socket, EACCES);
        bpf_errno_nr(f, &n, __NR_connect, EACCES);
        bpf_errno_nr(f, &n, __NR_bind, EACCES);
        bpf_errno_nr(f, &n, __NR_listen, EACCES);
    }

    /* 6b. ファイル自動学習モード時のみ、ファイル系Syscallをptrace通知 */
    if (learn_files) {
        bpf_trace_nr(f, &n, __NR_open, TRACE_TAG_OPEN);
        bpf_trace_nr(f, &n, __NR_openat, TRACE_TAG_OPEN);
#ifdef __NR_openat2
        bpf_trace_nr(f, &n, __NR_openat2, TRACE_TAG_OPEN);
#endif
        bpf_trace_nr(f, &n, __NR_execve, TRACE_TAG_OPEN);
#ifdef __NR_execveat
        bpf_trace_nr(f, &n, __NR_execveat, TRACE_TAG_OPEN);
#endif
        bpf_trace_nr(f, &n, __NR_stat, TRACE_TAG_STAT);
        bpf_trace_nr(f, &n, __NR_lstat, TRACE_TAG_STAT);
        bpf_trace_nr(f, &n, __NR_newfstatat, TRACE_TAG_STAT);
#ifdef __NR_statx
        bpf_trace_nr(f, &n, __NR_statx, TRACE_TAG_STAT);
#endif
        bpf_trace_nr(f, &n, __NR_access, TRACE_TAG_STAT);
        bpf_trace_nr(f, &n, __NR_faccessat, TRACE_TAG_STAT);
#ifdef __NR_faccessat2
        bpf_trace_nr(f, &n, __NR_faccessat2, TRACE_TAG_STAT);
#endif
    }

    /* 7. ベースホワイトリスト */
    static const uint32_t base_allow[] = {
        __NR_seccomp,
        __NR_execve, __NR_brk, __NR_munmap, __NR_mremap, __NR_madvise,
        __NR_exit, __NR_exit_group,
        __NR_arch_prctl, __NR_set_tid_address, __NR_set_robust_list,
#ifdef __NR_rseq
        __NR_rseq,
#endif
        __NR_prlimit64, __NR_getrandom, __NR_futex,
        __NR_read, __NR_write, __NR_readv, __NR_writev,
        __NR_pread64, __NR_pwrite64,
        __NR_open, __NR_openat,
#ifdef __NR_openat2
        __NR_openat2,
#endif
        __NR_close,
#ifdef __NR_close_range
        __NR_close_range,
#endif
        __NR_stat, __NR_fstat, __NR_lstat, __NR_newfstatat,
#ifdef __NR_statx
        __NR_statx,
#endif
        __NR_lseek, __NR_access, __NR_faccessat,
#ifdef __NR_faccessat2
        __NR_faccessat2,
#endif
        __NR_getdents, __NR_getdents64,
        __NR_fcntl, __NR_ioctl, __NR_dup, __NR_dup2, __NR_dup3,
        __NR_readlink, __NR_readlinkat, __NR_getcwd, __NR_chdir, __NR_fchdir,
        __NR_mkdir, __NR_mkdirat, __NR_rmdir, __NR_unlink, __NR_unlinkat,
        __NR_rename, __NR_renameat, __NR_renameat2,
        __NR_umask, __NR_utimensat, __NR_fchmod, __NR_fchmodat,
        __NR_rt_sigaction, __NR_rt_sigprocmask, __NR_rt_sigreturn, __NR_sigaltstack,
        __NR_getpid, __NR_getppid, __NR_gettid,
        __NR_getuid, __NR_geteuid, __NR_getgid, __NR_getegid,
        __NR_clock_gettime, __NR_clock_getres, __NR_gettimeofday,
        __NR_nanosleep, __NR_clock_nanosleep,
        __NR_uname, __NR_sysinfo,
    };
    for (size_t i = 0; i < sizeof(base_allow) / sizeof(base_allow[0]); i++) {
        bpf_allow_nr(f, &n, base_allow[i]);
    }

    /* 8. ポリシー内の追加学習済み Syscall */
    for (int i = 0; i < cfg->extra_count; i++) {
        bpf_allow_nr(f, &n, (uint32_t)cfg->extra_syscalls[i]);
    }

    /* 9. Default Deny */
    if (learn_trace) {
        bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | TRACE_TAG_SYSCALL));
    } else {
        bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }

    struct sock_fprog prog = {
        .len    = (unsigned short)n,
        .filter = f,
    };
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
        perror("[-] aegis-init: seccomp failed");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
    bool learn_trace = false;
    bool learn_files = false;
    int  target_idx  = 1;

    if (argc >= 3 && (strcmp(argv[1], "--learn-trace") == 0 ||
                     strcmp(argv[1], "--learn-trace-files") == 0)) {
        if (!is_actively_ptraced()) {
            fprintf(stderr, "[-] aegis-init: learn mode denied (no active ptracer)\n");
            return EXIT_FAILURE;
        }
        learn_trace = true;
        learn_files = (strcmp(argv[1], "--learn-trace-files") == 0);
        target_idx  = 2;
    }

    if (argc <= target_idx || argv[target_idx][0] != '/') {
        fprintf(stderr, "Usage: %s [--learn-trace|--learn-trace-files] </abs/path/to/target> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *policy_path = DEFAULT_POLICY_PATH;
    if (learn_trace) {
        const char *env_pol = getenv("AEGIS_POLICY");
        if (env_pol && env_pol[0] != '\0') policy_path = env_pol;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("[-] aegis-init: prctl(NO_NEW_PRIVS) failed");
        return EXIT_FAILURE;
    }

    struct aegis_policy_cfg cfg;
    load_policy_and_apply_landlock(policy_path, argv[target_idx], &cfg, learn_trace);
    apply_seccomp_filter(&cfg, learn_trace, learn_files);

    execve(argv[target_idx], &argv[target_idx], cfg.env_vars);
    perror("[-] aegis-init: execve failed");
    return EXIT_FAILURE;
}
