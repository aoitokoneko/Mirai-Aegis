/**
 * ============================================================================
 * File: aegis_vpatch.c (BistroHardened Modular Dynamic Virtual Patcher)
 * SPDX-License-Identifier: Apache-2.0
 * Role: Outer Chain-Loader wrapping /bin/aegis-init (Zero code merge required)
 * Build: gcc -O2 -Wall -Wextra -pthread aegis_vpatch.c -o aegis-vpatch
 * Usage: /bin/aegis-vpatch [--vpatch <file>] /bin/aegis-init </abs/target> [args...]
 * ============================================================================
 */
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
#include <signal.h>
#include <limits.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/landlock.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

extern char **environ;

#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000U
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

#define DEFAULT_POLICY_PATH "/etc/aegis.policy"
#define DEFAULT_VPATCH_PATH "/etc/aegis.vpatch"
#define RATCHET_SO_PATH     "/lib/libaegis_ratchet.so"
#define MAX_BPF_INSNS       512
#define MAX_VPATCH_RULES    256

/* ============================================================================
 * 1. Virtual Patch ルール構造体 (SIGHUP アトミック更新用)
 * ============================================================================ */
enum vpatch_type {
    VP_PATH_DENY = 1,
    VP_PATH_REDIR,
    VP_NET_DENY,
    VP_ORIGIN_ONLY,
    VP_SITE_DENY,
    VP_ARG_DENY,
};

struct vpatch_rule {
    enum vpatch_type type;
    int              syscall_nr;
    int              arg_idx;
    uint64_t         arg_val;
    uint64_t         off_start;
    uint64_t         off_end;
    uint32_t         ipv4_be;
    uint16_t         port_be;
    char             str_a[PATH_MAX];
    char             str_b[PATH_MAX];
};

struct vpatch_table {
    struct vpatch_rule rules[MAX_VPATCH_RULES];
    size_t             count;
    bool               has_path_rules;
    bool               has_net_rules;
};

static pthread_rwlock_t     g_vp_lock          = PTHREAD_RWLOCK_INITIALIZER;
static struct vpatch_table *g_vp_table         = NULL;
static const char          *g_policy_path      = DEFAULT_POLICY_PATH;
static const char          *g_vpatch_path      = DEFAULT_VPATCH_PATH;
static pid_t                g_child_pid        = -1;
static int                  g_arm_exec_target  = 2; /* aegis-init経由なら2回目、直接なら1回目のexecveでArm */

/* ============================================================================
 * 2. カーネル Syscall ラッパー & 安全文字列ヘルパ
 * ============================================================================ */
static inline int ll_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
static inline int ll_add_rule(int ruleset_fd, enum landlock_rule_type type, const void *attr, __u32 flags) {
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}
static inline int ll_restrict_self(int ruleset_fd, __u32 flags) {
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
static inline int sys_pidfd_open(pid_t pid, unsigned int flags) {
    return (int)syscall(__NR_pidfd_open, pid, flags);
}
static inline int sys_pidfd_getfd(int pidfd, int targetfd, unsigned int flags) {
    return (int)syscall(__NR_pidfd_getfd, pidfd, targetfd, flags);
}

static int path_copy(char *dst, size_t dst_sz, const char *src) {
    int n = snprintf(dst, dst_sz, "%s", src);
    return (n < 0 || (size_t)n >= dst_sz) ? -1 : 0;
}

/* ============================================================================
 * 3. Confused Deputy 防止: Landlocked Opener 専用スレッド
 *    /etc/aegis.policy と同一の Landlock 制約下でターゲットの openat を代行する
 * ============================================================================ */
struct opener_ipc {
    pthread_mutex_t mtx;
    pthread_cond_t  cv_req;
    pthread_cond_t  cv_res;
    int             ruleset_fd;
    bool            ready;
    bool            has_req;
    int             dfd;
    const char     *path;
    int             flags;
    mode_t          mode;
    int             ret_fd;
    int             ret_err;
};

static struct opener_ipc g_opener = {
    .mtx    = PTHREAD_MUTEX_INITIALIZER,
    .cv_req = PTHREAD_COND_INITIALIZER,
    .cv_res = PTHREAD_COND_INITIALIZER,
};

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
    (void)ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
    close(fd);
}

static int build_opener_ruleset_from_policy(const char *policy_path, const char *real_target) {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                             LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR,
    };
    int ruleset_fd = ll_create_ruleset(&attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        perror("[-] aegis-vpatch: landlock_create_ruleset failed");
        exit(EXIT_FAILURE);
    }

    __u64 rx = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
    __u64 ro = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    __u64 rw = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
               LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG |
               LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
               LANDLOCK_ACCESS_FS_REMOVE_DIR;

    FILE *fp = fopen(policy_path, "r");
    if (fp) {
        char line[2048];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\r\n")] = '\0';
            if (strncmp(line, "RX ", 3) == 0) add_landlock_path(ruleset_fd, line + 3, rx);
            else if (strncmp(line, "RO ", 3) == 0) add_landlock_path(ruleset_fd, line + 3, ro);
            else if (strncmp(line, "RW ", 3) == 0) add_landlock_path(ruleset_fd, line + 3, rw);
        }
        fclose(fp);
    }

    if (access(RATCHET_SO_PATH, R_OK) == 0) add_landlock_path(ruleset_fd, RATCHET_SO_PATH, rx);
    if (real_target && real_target[0] == '/') add_landlock_path(ruleset_fd, real_target, rx);
    return ruleset_fd;
}

static void *landlocked_opener_thread(void *arg) {
    (void)arg;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
        ll_restrict_self(g_opener.ruleset_fd, 0) < 0) {
        perror("[-] aegis-vpatch: opener lockdown failed");
        _exit(EXIT_FAILURE);
    }

    pthread_mutex_lock(&g_opener.mtx);
    g_opener.ready = true;
    pthread_cond_signal(&g_opener.cv_res);

    for (;;) {
        while (!g_opener.has_req) {
            pthread_cond_wait(&g_opener.cv_req, &g_opener.mtx);
        }
        int fd = openat(g_opener.dfd, g_opener.path, g_opener.flags | O_CLOEXEC, g_opener.mode);
        g_opener.ret_fd  = fd;
        g_opener.ret_err = (fd < 0) ? errno : 0;
        g_opener.has_req = false;
        pthread_cond_signal(&g_opener.cv_res);
    }
    return NULL;
}

static int openat_as_landlocked_child(int dfd, const char *path, int flags, mode_t mode, int *out_err) {
    pthread_mutex_lock(&g_opener.mtx);
    g_opener.dfd     = dfd;
    g_opener.path    = path;
    g_opener.flags   = flags;
    g_opener.mode    = mode;
    g_opener.has_req = true;
    pthread_cond_signal(&g_opener.cv_req);
    while (g_opener.has_req) {
        pthread_cond_wait(&g_opener.cv_res, &g_opener.mtx);
    }
    int fd   = g_opener.ret_fd;
    *out_err = g_opener.ret_err;
    pthread_mutex_unlock(&g_opener.mtx);
    return fd;
}

/* ============================================================================
 * 4. Virtual Patch パーサ & SIGHUP ホットリローダ
 * ============================================================================ */
static bool reload_vpatch_table(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return false;

    struct vpatch_table *nt = calloc(1, sizeof(*nt));
    if (!nt) { fclose(fp); return false; }

    char line[2048];
    while (fgets(line, sizeof(line), fp) && nt->count < MAX_VPATCH_RULES) {
        line[strcspn(line, "\r\n")] = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;

        struct vpatch_rule *r = &nt->rules[nt->count];
        if (sscanf(p, "VPATCH_PATH_DENY %4095s", r->str_a) == 1) {
            r->type = VP_PATH_DENY;
            nt->has_path_rules = true;
            nt->count++;
        } else if (sscanf(p, "VPATCH_PATH_REDIR %4095s %4095s", r->str_a, r->str_b) == 2) {
            r->type = VP_PATH_REDIR;
            nt->has_path_rules = true;
            nt->count++;
        } else if (strncmp(p, "VPATCH_NET_DENY ", 16) == 0) {
            char spec[128] = {0};
            if (sscanf(p + 16, "%127s", spec) == 1) {
                char *colon = strchr(spec, ':');
                if (colon) {
                    *colon = '\0';
                    uint16_t port = (uint16_t)strtoul(colon + 1, NULL, 10);
                    struct in_addr addr;
                    if (inet_pton(AF_INET, spec, &addr) == 1) {
                        r->type    = VP_NET_DENY;
                        r->ipv4_be = addr.s_addr;
                        r->port_be = htons(port);
                        nt->has_net_rules = true;
                        nt->count++;
                    }
                }
            }
        } else if (sscanf(p, "VPATCH_ORIGIN_ONLY %d %4095s", &r->syscall_nr, r->str_a) == 2) {
            r->type = VP_ORIGIN_ONLY;
            nt->count++;
        } else if (sscanf(p, "VPATCH_SITE_DENY %d %4095s %lx %lx",
                          &r->syscall_nr, r->str_a, &r->off_start, &r->off_end) == 4) {
            r->type = VP_SITE_DENY;
            nt->count++;
        } else if (sscanf(p, "VPATCH_ARG_DENY %d %d %lx",
                          &r->syscall_nr, &r->arg_idx, &r->arg_val) == 3) {
            if (r->arg_idx >= 0 && r->arg_idx < 6) {
                r->type = VP_ARG_DENY;
                nt->count++;
            }
        }
    }
    fclose(fp);

    pthread_rwlock_wrlock(&g_vp_lock);
    struct vpatch_table *old = g_vp_table;
    g_vp_table = nt;
    pthread_rwlock_unlock(&g_vp_lock);
    free(old);

    fprintf(stderr, "[+] aegis-vpatch: active rules = %zu (from '%s')\n", nt->count, path);
    return true;
}

/* ============================================================================
 * 5. ASLR 対応 RIP Call-Site 解決 & パス正規化
 * ============================================================================ */
static bool resolve_rip_to_elf_offset(pid_t pid, uint64_t rip,
                                      char *out_mod, size_t mod_sz, uint64_t *out_off) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return false;

    char line[PATH_MAX + 128];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        uint64_t start = 0, end = 0, pgoff = 0;
        char perms[8] = {0}, path[PATH_MAX] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %*x:%*x %*u %4095[^\n]",
                       &start, &end, perms, &pgoff, path);
        if (n >= 4 && rip >= start && rip < end) {
            char *trimmed = path;
            while (*trimmed == ' ') trimmed++;
            (void)path_copy(out_mod, mod_sz, trimmed);
            *out_off = pgoff + (rip - start);
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

static ssize_t read_remote_mem(pid_t pid, uint64_t remote_addr, void *buf, size_t len) {
    struct iovec local  = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)(uintptr_t)remote_addr, .iov_len = len };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

static int read_remote_path(pid_t pid, uint64_t addr, char *out, size_t out_sz) {
    if (addr == 0 || out_sz == 0) return -1;
    size_t off = 0;
    while (off < out_sz - 1) {
        size_t chunk = (out_sz - 1 - off < 256) ? (out_sz - 1 - off) : 256;
        ssize_t n = read_remote_mem(pid, addr + off, out + off, chunk);
        if (n <= 0) {
            char c;
            if (read_remote_mem(pid, addr + off, &c, 1) != 1) return -1;
            out[off++] = c;
            if (c == '\0') return 0;
            continue;
        }
        for (ssize_t i = 0; i < n; i++) {
            if (out[off + (size_t)i] == '\0') return 0;
        }
        off += (size_t)n;
    }
    out[out_sz - 1] = '\0';
    return 0;
}

static void normalize_lexical_path(const char *raw, char *out, size_t out_sz) {
    char buf[PATH_MAX * 2 + 32];
    if (path_copy(buf, sizeof(buf), raw) < 0) {
        if (out_sz > 0) out[0] = '\0';
        return;
    }
    const char *segs[256];
    int nseg = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
        if (strcmp(tok, ".") == 0) continue;
        if (strcmp(tok, "..") == 0) { if (nseg > 0) nseg--; continue; }
        if (nseg < 256) segs[nseg++] = tok;
    }
    if (nseg == 0) { (void)path_copy(out, out_sz, "/"); return; }
    size_t pos = 0;
    for (int i = 0; i < nseg && pos + 2 < out_sz; i++) {
        int w = snprintf(out + pos, out_sz - pos, "/%s", segs[i]);
        if (w < 0 || (size_t)w >= out_sz - pos) break;
        pos += (size_t)w;
    }
}

static bool match_path_pattern(const char *pat, const char *path) {
    size_t plen = strlen(pat), slen = strlen(path);
    if (plen > 1 && pat[0] == '*') {
        /* Suffix match: e.g. <wildcard>.pem */
        const char *suf = pat + 1;
        size_t suflen = plen - 1;
        return (slen >= suflen && strcmp(path + slen - suflen, suf) == 0);
    }
    if (plen > 1 && pat[plen - 1] == '*') {
        /* Prefix match: e.g. /etc/secret/<wildcard> */
        return (strncmp(path, pat, plen - 1) == 0);
    }
    return (strcmp(pat, path) == 0);
}

/* ============================================================================
 * 6. seccomp_unotify メディエーションループ (2段階Arm + Zero-TOCTOU強制)
 * ============================================================================ */
static bool notif_id_still_valid(int listener_fd, uint64_t id) {
    return (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0);
}

static void send_notif_resp(int listener_fd, uint64_t id, int64_t val, int32_t err, uint32_t flags) {
    struct seccomp_notif_resp resp = { .id = id, .val = val, .error = err, .flags = flags };
    (void)ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
}

static void *vpatch_mediation_thread(void *arg) {
    int  listener_fd = *(int *)arg;
    int  exec_seen   = 0;
    bool armed       = false;

    for (;;) {
        struct seccomp_notif req;
        memset(&req, 0, sizeof(req));
        if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR || errno == ENOENT) continue;
            break;
        }

        int nr = req.data.nr;

        /* aegis-init のブート処理中 (target の execve 完了前) は一切干渉せず直通させる */
        if (!armed) {
            if ((pid_t)req.pid == g_child_pid && nr == __NR_execve) {
                exec_seen++;
                if (exec_seen >= g_arm_exec_target) {
                    armed = true;
                }
            }
            send_notif_resp(listener_fd, req.id, 0, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
            continue;
        }

        bool blocked   = false;
        int  block_err = -EACCES;

        pthread_rwlock_rdlock(&g_vp_lock);
        const struct vpatch_table *vt = g_vp_table;

        /* [A] スカラー引数パッチ & RIP Call-Site オフセット検証 */
        if (vt && vt->count > 0) {
            char mod_path[PATH_MAX] = {0};
            uint64_t elf_off = 0;
            bool rip_resolved = false;

            for (size_t i = 0; i < vt->count; i++) {
                const struct vpatch_rule *r = &vt->rules[i];
                if (r->type == VP_ARG_DENY && r->syscall_nr == nr) {
                    if (req.data.args[r->arg_idx] == r->arg_val) {
                        fprintf(stderr, "[VPATCH-BLOCK] Scalar arg patch: pid=%u nr=%d arg[%d]=0x%llx\n",
                                req.pid, nr, r->arg_idx, (unsigned long long)r->arg_val);
                        blocked = true; block_err = -EPERM; break;
                    }
                } else if ((r->type == VP_ORIGIN_ONLY || r->type == VP_SITE_DENY) && r->syscall_nr == nr) {
                    if (!rip_resolved) {
                        rip_resolved = resolve_rip_to_elf_offset((pid_t)req.pid,
                                                                 req.data.instruction_pointer,
                                                                 mod_path, sizeof(mod_path), &elf_off);
                        if (!notif_id_still_valid(listener_fd, req.id)) {
                            blocked = true; block_err = -ESRCH; break;
                        }
                    }
                    if (r->type == VP_ORIGIN_ONLY && (!rip_resolved || strcmp(mod_path, r->str_a) != 0)) {
                        fprintf(stderr, "[VPATCH-BLOCK] Origin violation: pid=%u nr=%d from '%s'+0x%lx\n",
                                req.pid, nr, mod_path, elf_off);
                        blocked = true; block_err = -EPERM; break;
                    } else if (r->type == VP_SITE_DENY && rip_resolved &&
                               strcmp(mod_path, r->str_a) == 0 &&
                               elf_off >= r->off_start && elf_off < r->off_end) {
                        fprintf(stderr, "[VPATCH-BLOCK] Vulnerable callsite patched: '%s'+0x%lx\n",
                                mod_path, elf_off);
                        blocked = true; block_err = -EACCES; break;
                    }
                }
            }
        }

        if (blocked) {
            pthread_rwlock_unlock(&g_vp_lock);
            send_notif_resp(listener_fd, req.id, 0, block_err, 0);
            continue;
        }

        /* [B] ファイル系仮想パッチ (Zero-TOCTOU ADDFD + Landlocked Opener) */
        if ((nr == __NR_open || nr == __NR_openat) && vt && vt->has_path_rules) {
            int      tracee_dfd = (nr == __NR_open) ? AT_FDCWD : (int)req.data.args[0];
            uint64_t path_ptr   = (nr == __NR_open) ? req.data.args[0] : req.data.args[1];
            int      flags      = (nr == __NR_open) ? (int)req.data.args[1] : (int)req.data.args[2];
            mode_t   mode       = (nr == __NR_open) ? (mode_t)req.data.args[2] : (mode_t)req.data.args[3];

            int pidfd = sys_pidfd_open((pid_t)req.pid, 0);
            char raw_path[PATH_MAX];
            if (pidfd < 0 || read_remote_path((pid_t)req.pid, path_ptr, raw_path, sizeof(raw_path)) < 0 ||
                !notif_id_still_valid(listener_fd, req.id)) {
                if (pidfd >= 0) close(pidfd);
                pthread_rwlock_unlock(&g_vp_lock);
                send_notif_resp(listener_fd, req.id, 0, -EFAULT, 0);
                continue;
            }

            int local_dfd = -1;
            char combined[PATH_MAX * 2 + 16];
            if (raw_path[0] == '/') {
                (void)path_copy(combined, sizeof(combined), raw_path);
            } else {
                char link_proc[64], base_dir[PATH_MAX];
                if (tracee_dfd == AT_FDCWD) {
                    snprintf(link_proc, sizeof(link_proc), "/proc/%u/cwd", req.pid);
                    local_dfd = open(link_proc, O_PATH | O_DIRECTORY | O_CLOEXEC);
                } else if (tracee_dfd >= 0) {
                    local_dfd = sys_pidfd_getfd(pidfd, tracee_dfd, 0);
                    snprintf(link_proc, sizeof(link_proc), "/proc/self/fd/%d", local_dfd);
                }
                if (local_dfd < 0 || !notif_id_still_valid(listener_fd, req.id)) {
                    if (local_dfd >= 0) close(local_dfd);
                    close(pidfd);
                    pthread_rwlock_unlock(&g_vp_lock);
                    send_notif_resp(listener_fd, req.id, 0, -EBADF, 0);
                    continue;
                }
                ssize_t blen = readlink(link_proc, base_dir, sizeof(base_dir) - 1);
                if (blen > 0) {
                    base_dir[blen] = '\0';
                    snprintf(combined, sizeof(combined), "%s/%s", base_dir, raw_path);
                } else {
                    (void)path_copy(combined, sizeof(combined), raw_path);
                }
            }

            char norm_path[PATH_MAX];
            normalize_lexical_path(combined, norm_path, sizeof(norm_path));

            const char *redir_target = NULL;
            for (size_t i = 0; i < vt->count; i++) {
                const struct vpatch_rule *r = &vt->rules[i];
                if (r->type == VP_PATH_DENY && match_path_pattern(r->str_a, norm_path)) {
                    fprintf(stderr, "[VPATCH-BLOCK] Path virtual patch denied '%s'\n", norm_path);
                    blocked = true; break;
                } else if (r->type == VP_PATH_REDIR && match_path_pattern(r->str_a, norm_path)) {
                    redir_target = r->str_b;
                    fprintf(stderr, "[VPATCH-REDIR] '%s' -> '%s'\n", norm_path, redir_target);
                    break;
                }
            }

            int opened_fd = -1, open_err = EACCES;
            if (!blocked) {
                if (redir_target) {
                    opened_fd = open(redir_target, (flags & ~O_CLOEXEC) | O_CLOEXEC, mode);
                    open_err  = (opened_fd < 0) ? errno : 0;
                } else {
                    int use_dfd = (raw_path[0] == '/') ? AT_FDCWD : local_dfd;
                    opened_fd = openat_as_landlocked_child(use_dfd, raw_path, flags, mode, &open_err);
                }
            }
            pthread_rwlock_unlock(&g_vp_lock);

            if (local_dfd >= 0) close(local_dfd);
            close(pidfd);

            if (blocked || opened_fd < 0) {
                if (opened_fd >= 0) close(opened_fd);
                send_notif_resp(listener_fd, req.id, 0, -(blocked ? EACCES : open_err), 0);
                continue;
            }

            struct seccomp_notif_addfd addfd = {
                .id          = req.id,
                .flags       = 0,
                .srcfd       = (uint32_t)opened_fd,
                .newfd       = 0,
                .newfd_flags = (flags & O_CLOEXEC) ? O_CLOEXEC : 0,
            };
            int remote_fd = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
            int add_err   = errno;
            close(opened_fd);

            if (remote_fd < 0) send_notif_resp(listener_fd, req.id, 0, -add_err, 0);
            else               send_notif_resp(listener_fd, req.id, remote_fd, 0, 0);
            continue;
        }

        /* [C] ネットワーク SSRF 仮想パッチ (Zero-TOCTOU pidfd_getfd connect) */
        if (nr == __NR_connect && vt && vt->has_net_rules) {
            int       tracee_sfd = (int)req.data.args[0];
            uint64_t  addr_ptr   = req.data.args[1];
            socklen_t addr_len   = (socklen_t)req.data.args[2];

            struct sockaddr_storage ss;
            memset(&ss, 0, sizeof(ss));

            int pidfd = sys_pidfd_open((pid_t)req.pid, 0);
            if (pidfd < 0 || addr_len < sizeof(sa_family_t) || addr_len > sizeof(ss) ||
                read_remote_mem((pid_t)req.pid, addr_ptr, &ss, addr_len) != (ssize_t)addr_len ||
                !notif_id_still_valid(listener_fd, req.id)) {
                if (pidfd >= 0) close(pidfd);
                pthread_rwlock_unlock(&g_vp_lock);
                send_notif_resp(listener_fd, req.id, 0, -EFAULT, 0);
                continue;
            }

            bool has_v4 = false;
            uint32_t dst_ip = 0;
            uint16_t dst_port = 0;
            if (ss.ss_family == AF_INET && addr_len >= sizeof(struct sockaddr_in)) {
                const struct sockaddr_in *sin = (const struct sockaddr_in *)&ss;
                has_v4 = true; dst_ip = sin->sin_addr.s_addr; dst_port = sin->sin_port;
            } else if (ss.ss_family == AF_INET6 && addr_len >= sizeof(struct sockaddr_in6)) {
                const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&ss;
                if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
                    has_v4 = true;
                    memcpy(&dst_ip, &sin6->sin6_addr.s6_addr[12], 4);
                    dst_port = sin6->sin6_port;
                }
            }

            if (has_v4) {
                for (size_t i = 0; i < vt->count; i++) {
                    const struct vpatch_rule *r = &vt->rules[i];
                    if (r->type == VP_NET_DENY &&
                        (r->ipv4_be == 0 || r->ipv4_be == dst_ip) &&
                        (r->port_be == 0 || r->port_be == dst_port)) {
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &dst_ip, ip_str, sizeof(ip_str));
                        fprintf(stderr, "[VPATCH-BLOCK] SSRF virtual patch denied %s:%u\n",
                                ip_str, ntohs(dst_port));
                        blocked = true; break;
                    }
                }
            }
            pthread_rwlock_unlock(&g_vp_lock);

            if (blocked) {
                close(pidfd);
                send_notif_resp(listener_fd, req.id, 0, -EACCES, 0);
                continue;
            }

            int dup_sfd = sys_pidfd_getfd(pidfd, tracee_sfd, 0);
            close(pidfd);
            if (dup_sfd < 0 || !notif_id_still_valid(listener_fd, req.id)) {
                if (dup_sfd >= 0) close(dup_sfd);
                send_notif_resp(listener_fd, req.id, 0, -EBADF, 0);
                continue;
            }

            int rc  = connect(dup_sfd, (const struct sockaddr *)&ss, addr_len);
            int err = (rc < 0) ? errno : 0;
            close(dup_sfd);

            send_notif_resp(listener_fd, req.id, 0, (rc < 0) ? -err : 0, 0);
            continue;
        }

        pthread_rwlock_unlock(&g_vp_lock);
        send_notif_resp(listener_fd, req.id, 0, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    }
    return NULL;
}

/* ============================================================================
 * 7. 軽量チェイン専用 BPF 構築 (Default-Deny や W^X は内側の aegis-init に委譲)
 * ============================================================================ */
static void bpf_emit(struct sock_filter *buf, size_t *idx, struct sock_filter insn) {
    if (*idx >= MAX_BPF_INSNS) _exit(EXIT_FAILURE);
    buf[(*idx)++] = insn;
}
static void bpf_notif_nr(struct sock_filter *buf, size_t *idx, uint32_t nr) {
    bpf_emit(buf, idx, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
    bpf_emit(buf, idx, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
}

static int install_vpatch_listener_bpf(void) {
    struct sock_filter f[MAX_BPF_INSNS];
    size_t n = 0;

    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    bpf_emit(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));
    bpf_emit(f, &n, (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, __X32_SYSCALL_BIT, 0, 1));
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    /* コントロールプレーン Syscall のみを USER_NOTIF へルーティング */
    bpf_notif_nr(f, &n, __NR_execve);
    bpf_notif_nr(f, &n, __NR_open);
    bpf_notif_nr(f, &n, __NR_openat);
    bpf_notif_nr(f, &n, __NR_ioctl);
    bpf_notif_nr(f, &n, __NR_connect);

    pthread_rwlock_rdlock(&g_vp_lock);
    if (g_vp_table) {
        for (size_t i = 0; i < g_vp_table->count; i++) {
            int snr = g_vp_table->rules[i].syscall_nr;
            if (snr > 0) bpf_notif_nr(f, &n, (uint32_t)snr);
        }
    }
    pthread_rwlock_unlock(&g_vp_lock);

    /* 残りのシステムコールは内側の aegis-init + libaegis_ratchet.so のフィルタに委ねる */
    bpf_emit(f, &n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    struct sock_fprog prog = { .len = (unsigned short)n, .filter = f };
    return (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

/* ============================================================================
 * 8. SCM_RIGHTS FD 転送 & Main
 * ============================================================================ */
static int send_fd(int sock, int fd) {
    char dummy = 'V';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cmsgbuf, .msg_controllen = sizeof(cmsgbuf) };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    return (sendmsg(sock, &msg, 0) < 0) ? -1 : 0;
}

static int recv_fd(int sock) {
    char dummy;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cmsgbuf, .msg_controllen = sizeof(cmsgbuf) };
    if (recvmsg(sock, &msg, 0) <= 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    int fd = -1;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

static bool ends_with(const char *str, const char *suffix) {
    size_t slen = strlen(str), suflen = strlen(suffix);
    return (slen >= suflen && strcmp(str + slen - suflen, suffix) == 0);
}

int main(int argc, char *argv[]) {
    int idx = 1;
    while (idx < argc && strncmp(argv[idx], "--", 2) == 0) {
        if (strcmp(argv[idx], "--vpatch") == 0 && idx + 1 < argc) {
            g_vpatch_path = argv[idx + 1];
            idx += 2;
        } else if (strcmp(argv[idx], "--policy") == 0 && idx + 1 < argc) {
            g_policy_path = argv[idx + 1];
            idx += 2;
        } else if (strcmp(argv[idx], "--") == 0) {
            idx++;
            break;
        } else {
            break;
        }
    }

    if (idx >= argc || argv[idx][0] != '/') {
        fprintf(stderr,
                "Usage: %s [--vpatch <file>] [--policy <file>] </bin/aegis-init> </abs/target> [args...]\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    /* aegis-init をラップしている場合は 2回目の execve で Arm、直接起動なら 1回目で Arm */
    const char *real_target = argv[idx];
    if (ends_with(argv[idx], "aegis-init") && idx + 1 < argc) {
        g_arm_exec_target = 2;
        real_target       = argv[idx + 1];
    } else {
        g_arm_exec_target = 1;
    }

    reload_vpatch_table(g_vpatch_path);
    int ruleset_fd = build_opener_ruleset_from_policy(g_policy_path, real_target);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
        perror("[-] socketpair");
        return EXIT_FAILURE;
    }

    pid_t parent_pid = getpid();
    g_child_pid = fork();
    if (g_child_pid < 0) {
        perror("[-] fork");
        return EXIT_FAILURE;
    }

    if (g_child_pid == 0) {
        close(sv[0]);
        close(ruleset_fd);
#ifdef PR_SET_PTRACER
        prctl(PR_SET_PTRACER, (unsigned long)parent_pid, 0, 0, 0);
#endif
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) _exit(EXIT_FAILURE);

        int listener_fd = install_vpatch_listener_bpf();
        if (listener_fd < 0 || send_fd(sv[1], listener_fd) < 0) _exit(EXIT_FAILURE);
        close(listener_fd);
        close(sv[1]);

        execve(argv[idx], &argv[idx], environ);
        perror("[-] aegis-vpatch: execve failed");
        _exit(EXIT_FAILURE);
    }

    close(sv[1]);
    int listener_fd = recv_fd(sv[0]);
    close(sv[0]);
    if (listener_fd < 0) {
        fprintf(stderr, "[-] aegis-vpatch: failed to receive listener fd\n");
        return EXIT_FAILURE;
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    g_opener.ruleset_fd = ruleset_fd;
    pthread_t opener_tid;
    if (pthread_create(&opener_tid, NULL, landlocked_opener_thread, NULL) != 0) return EXIT_FAILURE;
    pthread_mutex_lock(&g_opener.mtx);
    while (!g_opener.ready) pthread_cond_wait(&g_opener.cv_res, &g_opener.mtx);
    pthread_mutex_unlock(&g_opener.mtx);
    close(ruleset_fd);

    pthread_t med_tid;
    if (pthread_create(&med_tid, NULL, vpatch_mediation_thread, &listener_fd) != 0) return EXIT_FAILURE;

    int exit_code = EXIT_SUCCESS;
    for (;;) {
        int sig = 0;
        if (sigwait(&mask, &sig) != 0) continue;
        if (sig == SIGHUP) {
            reload_vpatch_table(g_vpatch_path);
        } else if (sig == SIGCHLD) {
            int status = 0;
            if (waitpid(g_child_pid, &status, WNOHANG) == g_child_pid) {
                exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : (128 + WTERMSIG(status));
                break;
            }
        }
    }

    close(listener_fd);
    return exit_code;
}
