/**
 * ============================================================================
 * File: aegis_audit.c (Aegis 3D Security Posture & Gap Visualizer CLI)
 * SPDX-License-Identifier: Apache-2.0
 * Philosophy: Minimalist, Zero-Dependency UNIX Security Auditor in C
 * Build: gcc -O2 -Wall -Wextra aegis_audit.c -o aegis-audit
 * Usage: ./aegis-audit <rootfs_dir> [--vpatch <file>] [--json] [--strict]
 * ============================================================================
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define MAX_PATHS        2048
#define MAX_VPATCH_ITEMS 256
#define MAX_SENSITIVE    64

enum sev_level {
    SEV_GUARDED = 0,
    SEV_LOW     = 1,
    SEV_MED     = 2,
    SEV_HIGH    = 3,
};

struct finding {
    enum sev_level sev;
    char           title[96];
    char           detail[256];
    char           fix[256];
};

struct audit_ctx {
    /* RootFS Physical Scan */
    size_t   total_files;
    size_t   elf_files;
    uint64_t total_bytes;
    bool     has_shell_bin;
    char     shell_found[PATH_MAX];
    bool     has_suid_file;
    bool     has_aegis_init;
    bool     has_ratchet_so;
    bool     has_vpatch_bin;
    char     sensitive_files[MAX_SENSITIVE][PATH_MAX];
    size_t   sensitive_count;

    /* ELF .dynsym Imported Capabilities */
    bool     imp_exec;    /* system, popen, execve, posix_spawn */
    bool     imp_dlopen;  /* dlopen, dlmopen */
    bool     imp_net;     /* socket, connect, bind, listen */

    /* Parsed /etc/aegis.policy */
    bool     policy_loaded;
    char     rx_paths[MAX_PATHS][256];
    size_t   rx_count;
    char     ro_paths[MAX_PATHS][256];
    size_t   ro_count;
    char     rw_paths[MAX_PATHS][256];
    size_t   rw_count;
    bool     allow_net;
    bool     freeze_code;
    bool     freeze_execve;
    bool     freeze_tls;
    bool     p2_on_listen;
    bool     p2_freeze_open;
    bool     p2_freeze_net;
    bool     p2_freeze_fork;
    bool     p2_freeze_code;
    bool     has_privsep_so;
    bool     has_dangerous_syscall;
    int      dangerous_sc_nr;

    /* Parsed aegis.vpatch */
    bool     vpatch_loaded;
    char     vpatch_src[PATH_MAX];
    char     vp_deny_pats[MAX_VPATCH_ITEMS][256];
    size_t   vp_deny_count;
    size_t   vp_redir_count;
    bool     vp_blocks_metadata_ip;
    bool     vp_blocks_tiocsti;
    size_t   vp_origin_count;
    size_t   vp_total_rules;

    /* Findings & Score */
    struct finding findings[64];
    size_t         finding_count;
    int            score;
    int            high_count;
    int            med_count;
    int            low_count;
};

static bool g_use_color = true;

static const char *C_RST(void)  { return g_use_color ? "\033[0m"    : ""; }
static const char *C_BOLD(void) { return g_use_color ? "\033[1m"    : ""; }
static const char *C_GRN(void)  { return g_use_color ? "\033[1;32m" : ""; }
static const char *C_RED(void)  { return g_use_color ? "\033[1;31m" : ""; }
static const char *C_YEL(void)  { return g_use_color ? "\033[1;33m" : ""; }
static const char *C_CYN(void)  { return g_use_color ? "\033[1;36m" : ""; }
static const char *C_DIM(void)  { return g_use_color ? "\033[2m"    : ""; }

static int safe_copy(char *dst, size_t dst_sz, const char *src) {
    int n = snprintf(dst, dst_sz, "%s", src);
    return (n < 0 || (size_t)n >= dst_sz) ? -1 : 0;
}

static int safe_join(char *dst, size_t dst_sz, const char *a, const char *b) {
    int n = snprintf(dst, dst_sz, "%s/%s", a, b);
    return (n < 0 || (size_t)n >= dst_sz) ? -1 : 0;
}

static bool ends_with(const char *s, const char *suf) {
    size_t sl = strlen(s), fl = strlen(suf);
    return (sl >= fl && strcmp(s + sl - fl, suf) == 0);
}

static bool match_vpatch_pattern(const char *pat, const char *path) {
    size_t plen = strlen(pat);
    if (plen > 1 && pat[0] == '*') {
        return ends_with(path, pat + 1);
    }
    if (plen > 1 && pat[plen - 1] == '*') {
        return (strncmp(path, pat, plen - 1) == 0);
    }
    return (strcmp(pat, path) == 0);
}

static bool is_covered_by_vpatch_deny(const struct audit_ctx *ctx, const char *rel_path) {
    for (size_t i = 0; i < ctx->vp_deny_count; i++) {
        if (match_vpatch_pattern(ctx->vp_deny_pats[i], rel_path)) return true;
    }
    return false;
}

static void add_finding(struct audit_ctx *ctx, enum sev_level sev,
                        const char *title, const char *detail, const char *fix, int penalty) {
    if (ctx->finding_count >= 64) return;
    struct finding *f = &ctx->findings[ctx->finding_count++];
    f->sev = sev;
    (void)safe_copy(f->title, sizeof(f->title), title);
    (void)safe_copy(f->detail, sizeof(f->detail), detail);
    (void)safe_copy(f->fix, sizeof(f->fix), fix ? fix : "");

    ctx->score -= penalty;
    if (ctx->score < 0) ctx->score = 0;
    if (sev == SEV_HIGH) ctx->high_count++;
    else if (sev == SEV_MED) ctx->med_count++;
    else if (sev == SEV_LOW) ctx->low_count++;
}

/* ============================================================================
 * 1. 非実行 ELF64 .dynsym 静的スキャナ (危険関数のインポート有無を検査)
 * ============================================================================ */
static void scan_elf_dynsym(struct audit_ctx *ctx, const char *full_path, const char *rel_path) {
    /* libc 自体や Aegis 自身のランタイムは除外し、保護対象アプリ・拡張モジュールのみを検査 */
    if (strstr(rel_path, "/libc.so") || strstr(rel_path, "/ld-linux") ||
        strstr(rel_path, "aegis-init") || strstr(rel_path, "aegis-vpatch") ||
        strstr(rel_path, "aegis-privsep") || strstr(rel_path, "libaegis_ratchet.so") ||
        strstr(rel_path, "libaegis_privsep.so")) {
        return;
    }

    int fd = open(full_path, O_RDONLY);
    if (fd < 0) return;

    struct stat st;
    if (fstat(fd, &st) < 0 || (size_t)st.st_size < sizeof(Elf64_Ehdr)) {
        close(fd);
        return;
    }

    size_t fsize = (size_t)st.st_size;
    void *map = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return;

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)map;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_ident[EI_CLASS] != ELFCLASS64) {
        munmap(map, fsize);
        return;
    }
    ctx->elf_files++;

    if (eh->e_shoff == 0 || eh->e_shentsize != sizeof(Elf64_Shdr) ||
        eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) > fsize) {
        munmap(map, fsize);
        return;
    }

    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)((const char *)map + eh->e_shoff);
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_DYNSYM || shdrs[i].sh_entsize != sizeof(Elf64_Sym)) continue;
        uint32_t link = shdrs[i].sh_link;
        if (link >= eh->e_shnum) continue;

        size_t sym_off = (size_t)shdrs[i].sh_offset, sym_sz = (size_t)shdrs[i].sh_size;
        size_t str_off = (size_t)shdrs[link].sh_offset, str_sz = (size_t)shdrs[link].sh_size;
        if (sym_off + sym_sz > fsize || str_off + str_sz > fsize) continue;

        const Elf64_Sym *syms = (const Elf64_Sym *)((const char *)map + sym_off);
        const char      *strs = (const char *)map + str_off;
        size_t count = sym_sz / sizeof(Elf64_Sym);

        for (size_t s = 0; s < count; s++) {
            if (syms[s].st_shndx != SHN_UNDEF || syms[s].st_name >= str_sz) continue;
            const char *name = strs + syms[s].st_name;
            size_t max_l = str_sz - syms[s].st_name;
            if (strnlen(name, max_l) >= max_l) continue;

            if (strcmp(name, "system") == 0 || strcmp(name, "popen") == 0 ||
                strcmp(name, "execve") == 0 || strcmp(name, "execvp") == 0 ||
                strcmp(name, "execv") == 0  || strcmp(name, "posix_spawn") == 0 ||
                strcmp(name, "posix_spawnp") == 0) {
                ctx->imp_exec = true;
            } else if (strcmp(name, "dlopen") == 0 || strcmp(name, "dlmopen") == 0) {
                ctx->imp_dlopen = true;
            } else if (strcmp(name, "socket") == 0 || strcmp(name, "connect") == 0) {
                ctx->imp_net = true;
            }
        }
    }

    munmap(map, fsize);
}

/* ============================================================================
 * 2. RootFS 物理構造ウォーカー (Shell混入・SUID・機密ファイル露出の検出)
 * ============================================================================ */
static bool is_sensitive_rel_path(const char *rel) {
    if (strcmp(rel, "/etc/shadow") == 0 || strcmp(rel, "/etc/gshadow") == 0) return true;
    if (ends_with(rel, ".env") || ends_with(rel, ".pem") ||
        ends_with(rel, ".key") || ends_with(rel, ".bak") ||
        ends_with(rel, ".swp") || ends_with(rel, "id_rsa")) {
        return true;
    }
    return false;
}

static bool is_lotl_shell(const char *rel) {
    static const char *shells[] = {
        "/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "/bin/zsh",
        "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", NULL
    };
    for (int i = 0; shells[i]; i++) {
        if (strcmp(rel, shells[i]) == 0) return true;
    }
    return false;
}

static void walk_rootfs(struct audit_ctx *ctx, const char *base_root, const char *rel_dir, int depth) {
    if (depth > 32) return;
    char cur_dir[PATH_MAX];
    if (strcmp(rel_dir, "/") == 0) {
        if (safe_copy(cur_dir, sizeof(cur_dir), base_root) < 0) return;
    } else {
        if (snprintf(cur_dir, sizeof(cur_dir), "%s%s", base_root, rel_dir) >= (int)sizeof(cur_dir)) return;
    }

    DIR *d = opendir(cur_dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char child_rel[PATH_MAX];
        char child_full[PATH_MAX];
        if (strcmp(rel_dir, "/") == 0) {
            if (snprintf(child_rel, sizeof(child_rel), "/%s", ent->d_name) >= (int)sizeof(child_rel)) continue;
        } else {
            if (safe_join(child_rel, sizeof(child_rel), rel_dir, ent->d_name) < 0) continue;
        }
        if (snprintf(child_full, sizeof(child_full), "%s%s", base_root, child_rel) >= (int)sizeof(child_full)) continue;

        struct stat st;
        if (lstat(child_full, &st) < 0) continue;

        if (S_ISDIR(st.st_mode)) {
            walk_rootfs(ctx, base_root, child_rel, depth + 1);
        } else if (S_ISREG(st.st_mode)) {
            ctx->total_files++;
            ctx->total_bytes += (uint64_t)st.st_size;

            if (st.st_mode & (S_ISUID | S_ISGID)) ctx->has_suid_file = true;
            if (strcmp(child_rel, "/bin/aegis-init") == 0) ctx->has_aegis_init = true;
            if (strcmp(child_rel, "/lib/libaegis_ratchet.so") == 0) ctx->has_ratchet_so = true;
            if (strcmp(child_rel, "/lib/libaegis_privsep.so") == 0) ctx->has_privsep_so = true;
            if (strcmp(child_rel, "/bin/aegis-vpatch") == 0) ctx->has_vpatch_bin = true;

            if (is_lotl_shell(child_rel)) {
                ctx->has_shell_bin = true;
                (void)safe_copy(ctx->shell_found, sizeof(ctx->shell_found), child_rel);
            }
            if (is_sensitive_rel_path(child_rel) && ctx->sensitive_count < MAX_SENSITIVE) {
                (void)safe_copy(ctx->sensitive_files[ctx->sensitive_count++], PATH_MAX, child_rel);
            }

            scan_elf_dynsym(ctx, child_full, child_rel);
        }
    }
    closedir(d);
}

/* ============================================================================
 * 3. aegis.policy & aegis.vpatch パーサ
 * ============================================================================ */
static bool is_dangerous_extra_syscall(int nr) {
    /* x86_64: ptrace(101), memfd_create(319), bpf(321), userfaultfd(323), io_uring_setup(425) */
    return (nr == 101 || nr == 319 || nr == 321 || nr == 323 || nr == 425);
}

static void parse_policy_file(struct audit_ctx *ctx, const char *policy_path) {
    FILE *fp = fopen(policy_path, "r");
    if (!fp) return;
    ctx->policy_loaded = true;

    /* aegis-init のデフォルト値と一致させる */
    ctx->freeze_code   = true;
    ctx->freeze_execve = true;
    ctx->freeze_tls    = true;

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;

        if (strncmp(line, "RX ", 3) == 0 && ctx->rx_count < MAX_PATHS) {
            (void)safe_copy(ctx->rx_paths[ctx->rx_count++], 256, line + 3);
        } else if (strncmp(line, "RO ", 3) == 0 && ctx->ro_count < MAX_PATHS) {
            (void)safe_copy(ctx->ro_paths[ctx->ro_count++], 256, line + 3);
        } else if (strncmp(line, "RW ", 3) == 0 && ctx->rw_count < MAX_PATHS) {
            (void)safe_copy(ctx->rw_paths[ctx->rw_count++], 256, line + 3);
        } else if (strncmp(line, "ALLOW_NET ", 10) == 0) {
            ctx->allow_net = (atoi(line + 10) == 1);
        } else if (strncmp(line, "FREEZE_CODE ", 12) == 0) {
            ctx->freeze_code = (atoi(line + 12) != 0);
        } else if (strncmp(line, "FREEZE_EXECVE ", 14) == 0) {
            ctx->freeze_execve = (atoi(line + 14) != 0);
        } else if (strncmp(line, "FREEZE_TLS ", 11) == 0) {
            ctx->freeze_tls = (atoi(line + 11) != 0);
        } else if (strncmp(line, "PHASE2_ON_LISTEN ", 17) == 0) {
            ctx->p2_on_listen = (atoi(line + 17) != 0);
        } else if (strncmp(line, "PHASE2_FREEZE_OPEN ", 19) == 0) {
            ctx->p2_freeze_open = (atoi(line + 19) != 0);
        } else if (strncmp(line, "PHASE2_FREEZE_NET ", 18) == 0) {
            ctx->p2_freeze_net = (atoi(line + 18) != 0);
        } else if (strncmp(line, "PHASE2_FREEZE_FORK ", 19) == 0) {
            ctx->p2_freeze_fork = (atoi(line + 19) != 0);
        } else if (strncmp(line, "PHASE2_FREEZE_CODE ", 19) == 0) {
            ctx->p2_freeze_code = (atoi(line + 19) != 0);
        } else if (strncmp(line, "SYSCALL ", 8) == 0) {
            int nr = atoi(line + 8);
            if (is_dangerous_extra_syscall(nr)) {
                ctx->has_dangerous_syscall = true;
                ctx->dangerous_sc_nr       = nr;
            }
        }
    }
    fclose(fp);
}

static void parse_vpatch_file(struct audit_ctx *ctx, const char *vpatch_path) {
    FILE *fp = fopen(vpatch_path, "r");
    if (!fp) return;
    ctx->vpatch_loaded = true;
    (void)safe_copy(ctx->vpatch_src, sizeof(ctx->vpatch_src), vpatch_path);

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;

        char a[256] = {0}, b[256] = {0};
        int nr = 0, idx = 0;
        unsigned long val = 0;

        if (sscanf(p, "VPATCH_PATH_DENY %255s", a) == 1) {
            if (ctx->vp_deny_count < MAX_VPATCH_ITEMS) {
                (void)safe_copy(ctx->vp_deny_pats[ctx->vp_deny_count++], 256, a);
            }
            ctx->vp_total_rules++;
        } else if (sscanf(p, "VPATCH_PATH_REDIR %255s %255s", a, b) == 2) {
            ctx->vp_redir_count++;
            ctx->vp_total_rules++;
        } else if (sscanf(p, "VPATCH_NET_DENY %255s", a) == 1) {
            if (strncmp(a, "169.254.169.254:", 16) == 0) ctx->vp_blocks_metadata_ip = true;
            ctx->vp_total_rules++;
        } else if (sscanf(p, "VPATCH_ORIGIN_ONLY %d %255s", &nr, a) == 2) {
            ctx->vp_origin_count++;
            ctx->vp_total_rules++;
        } else if (strncmp(p, "VPATCH_SITE_DENY ", 17) == 0) {
            ctx->vp_total_rules++;
        } else if (sscanf(p, "VPATCH_ARG_DENY %d %d %lx", &nr, &idx, &val) == 3) {
            if (nr == 16 && idx == 1 && val == 0x5412UL) ctx->vp_blocks_tiocsti = true;
            ctx->vp_total_rules++;
        }
    }
    fclose(fp);
}

/* ============================================================================
 * 4. 3次元クロスギャップ分析エンジン
 * ============================================================================ */
static bool paths_overlap(const char *a, const char *b) {
    if (strcmp(a, "/") == 0 || strcmp(b, "/") == 0) return true;
    size_t al = strlen(a), bl = strlen(b);
    if (strcmp(a, b) == 0) return true;
    if (al < bl && strncmp(b, a, al) == 0 && b[al] == '/') return true;
    if (bl < al && strncmp(a, b, bl) == 0 && a[bl] == '/') return true;
    return false;
}

static void evaluate_posture(struct audit_ctx *ctx) {
    ctx->score = 100;

    if (!ctx->policy_loaded) {
        add_finding(ctx, SEV_HIGH, "Missing Policy File",
                    "/etc/aegis.policy not found in RootFS; sandbox cannot enforce rules.",
                    "Run './bistro-builder bundle ...' to synthesize /etc/aegis.policy", 50);
        return;
    }

    /* [1] 空間軸: Shell 混入検査 (Living-off-the-Land 対策) */
    if (ctx->has_shell_bin) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Shell interpreter '%.160s' exists inside RootFS.", ctx->shell_found);
        add_finding(ctx, SEV_HIGH, "LotL Shell Present", msg,
                    "Remove shell binaries from RootFS to prevent post-exploit command execution", 25);
    } else {
        add_finding(ctx, SEV_GUARDED, "Zero-Shell RootFS",
                    "No /bin/sh or /bin/bash exists in RootFS (Living-off-the-Land shell impossible).",
                    NULL, 0);
    }

    /* [2] 空間軸: RW と RX の重複 (ファイルシステム W^X) */
    bool wx_overlap = false;
    for (size_t i = 0; i < ctx->rw_count && !wx_overlap; i++) {
        if (strcmp(ctx->rw_paths[i], "/dev/null") == 0) continue;
        for (size_t j = 0; j < ctx->rx_count; j++) {
            if (paths_overlap(ctx->rw_paths[i], ctx->rx_paths[j])) {
                wx_overlap = true;
                break;
            }
        }
    }
    if (wx_overlap) {
        add_finding(ctx, SEV_HIGH, "Filesystem W^X Overlap",
                    "A writable (RW) directory overlaps with an executable (RX) Landlock path!",
                    "Separate RW directories (/tmp, /var) strictly from RX binary/library paths", 25);
    } else {
        add_finding(ctx, SEV_GUARDED, "Strict W^X Isolation",
                    "Memory RWX/mprotect(EXEC) killed by BPF & Landlock RW/RX paths are strictly disjoint.",
                    NULL, 0);
    }

    if (ctx->has_suid_file) {
        add_finding(ctx, SEV_MED, "SUID/SGID Bit Detected",
                    "RootFS contains SUID/SGID file(s) (mitigated by PR_SET_NO_NEW_PRIVS, but unnecessary).",
                    "Strip SUID/SGID bits via 'chmod ug-s' inside RootFS", 5);
    }

    /* [3] 時間軸 × ELF シンボル: コマンド実行 (execve/system/popen) */
    if (ctx->has_ratchet_so && ctx->freeze_execve) {
        if (ctx->imp_exec) {
            add_finding(ctx, SEV_GUARDED, "Command Execution",
                        "Target ELF imports exec/system symbols, neutralized at main() by FREEZE_EXECVE=1.",
                        NULL, 0);
        } else {
            add_finding(ctx, SEV_GUARDED, "Execve Ratchet Lock",
                        "execve/execveat permanently frozen at Phase-1 (main entry).",
                        NULL, 0);
        }
    } else if (ctx->imp_exec) {
        add_finding(ctx, SEV_HIGH, "Command Exec Exposed",
                    "Target imports system/popen/execve AND Phase-1 FREEZE_EXECVE is disabled!",
                    "Enable 'FREEZE_EXECVE 1' in aegis.policy or bundle libaegis_ratchet.so", 20);
    } else {
        add_finding(ctx, SEV_MED, "Execve Unfrozen",
                    "Phase-1 FREEZE_EXECVE is inactive (mitigated by Landlock RX whitelist).",
                    "Bundle libaegis_ratchet.so and set 'FREEZE_EXECVE 1' in aegis.policy", 10);
    }

    /* [4] 時間軸 × 境界軸: リバースシェル & SSRF ネットワーク評価 */
    if (!ctx->allow_net) {
        add_finding(ctx, SEV_GUARDED, "Network Air-Gapped",
                    "ALLOW_NET=0: socket/connect/bind/listen blocked at Phase-0.",
                    NULL, 0);
    } else if (ctx->has_ratchet_so && ctx->p2_on_listen && ctx->p2_freeze_net) {
        add_finding(ctx, SEV_GUARDED, "Reverse Shell & SSRF",
                    "Outbound socket/connect permanently frozen after listen() (PHASE2_FREEZE_NET=1).",
                    NULL, 0);
    } else {
        if (!ctx->vp_blocks_metadata_ip) {
            add_finding(ctx, SEV_HIGH, "SSRF / Outbound Net Open",
                        "Steady-state outbound connect() is open without Cloud Metadata SSRF protection!",
                        "Add 'VPATCH_NET_DENY 169.254.169.254:0' to aegis.vpatch (or enable PHASE2_FREEZE_NET)", 18);
        } else {
            add_finding(ctx, SEV_GUARDED, "Cloud Metadata SSRF",
                        "Outbound connect() active, guarded by Zero-TOCTOU VPATCH_NET_DENY (169.254.169.254).",
                        NULL, 0);
        }
    }

    /* [5] 物理機密ファイル × Phase-2 OPEN × Virtual Patch 照合 */
    bool open_frozen_p2 = (ctx->has_ratchet_so && ctx->p2_on_listen && ctx->p2_freeze_open);
    if (open_frozen_p2) {
        add_finding(ctx, SEV_GUARDED, "Steady-State LFI Lock",
                    "All file open/openat syscalls permanently frozen after listen() (PHASE2_FREEZE_OPEN=1).",
                    NULL, 0);
    } else if (ctx->sensitive_count > 0) {
        for (size_t i = 0; i < ctx->sensitive_count; i++) {
            const char *sf = ctx->sensitive_files[i];
            if (is_covered_by_vpatch_deny(ctx, sf)) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Sensitive file '%.140s' in RootFS is shielded by VPATCH_PATH_DENY.", sf);
                add_finding(ctx, SEV_GUARDED, "Virtual Patch Shield", msg, NULL, 0);
            } else {
                char msg[256], fix[256];
                const char *dot = strrchr(sf, '.');
                snprintf(msg, sizeof(msg), "Sensitive file '%.140s' exists in RootFS while steady-state openat() is allowed!", sf);
                if (dot) snprintf(fix, sizeof(fix), "Remove '%.80s' or add 'VPATCH_PATH_DENY *%.32s' to aegis.vpatch", sf, dot);
                else     snprintf(fix, sizeof(fix), "Add 'VPATCH_PATH_DENY %.160s' to aegis.vpatch", sf);
                add_finding(ctx, SEV_HIGH, "Exposed Secret File (LFI)", msg, fix, 18);
            }
        }
    } else if (!is_covered_by_vpatch_deny(ctx, "/test.env") || !is_covered_by_vpatch_deny(ctx, "/test.pem")) {
        add_finding(ctx, SEV_MED, "Steady-State Open Active",
                    "openat() remains open for file serving without proactive *.env / *.pem virtual patch.",
                    "Add 'VPATCH_PATH_DENY *.env' and 'VPATCH_PATH_DENY *.pem' to aegis.vpatch", 8);
    } else {
        add_finding(ctx, SEV_GUARDED, "Proactive LFI Filter",
                    "Steady-state openat() guarded by *.env / *.pem Zero-TOCTOU virtual patches.",
                    NULL, 0);
    }

    /* [6] 動的コードロード (dlopen / FREEZE_CODE / PHASE2_FREEZE_CODE) */
    if (ctx->has_ratchet_so && ctx->freeze_code) {
        add_finding(ctx, SEV_GUARDED, "Immutable Code Pages",
                    "PROT_EXEC mmap frozen at main() entry (FREEZE_CODE=1).",
                    NULL, 0);
    } else if (ctx->has_ratchet_so && ctx->p2_on_listen && ctx->p2_freeze_code) {
        add_finding(ctx, SEV_GUARDED, "Temporal Code Freeze",
                    "Phase-1 import allowed; PROT_EXEC mmap permanently frozen at listen() (PHASE2_FREEZE_CODE=1).",
                    NULL, 0);
    } else {
        add_finding(ctx, SEV_MED, "Runtime dlopen() Open",
                    "FREEZE_CODE=0 (runtime C-extension dlopen active; restricted to Landlock RX whitelist).",
                    "Add 'PHASE2_FREEZE_CODE 1' to aegis.policy to freeze dlopen() after listen()", 5);
    }

    if (ctx->has_privsep_so) {
        add_finding(ctx, SEV_GUARDED, "Secret Memory Vault",
                    "OpenBSD-style privsep & Phase-2 memfd_secret evaporation active (libaegis_privsep.so).",
                    NULL, 0);
    }

    /* [7] 端末コマンド注入 (ioctl TIOCSTI) & 危険システムコール */
    if (ctx->has_dangerous_syscall) {
        char msg[256];
        snprintf(msg, sizeof(msg), "High-risk syscall nr=%d found in aegis.policy!", ctx->dangerous_sc_nr);
        add_finding(ctx, SEV_HIGH, "Dangerous Syscall Policy", msg,
                    "Remove dangerous SYSCALL entry from /etc/aegis.policy", 20);
    }

    if (!ctx->has_vpatch_bin) {
        add_finding(ctx, SEV_LOW, "Live Patcher Not Bundled",
                    "/bin/aegis-vpatch not found in RootFS (zero-downtime SIGHUP patching unavailable).",
                    "Bundle with '--include-rx ./aegis-vpatch:/bin/aegis-vpatch'", 4);
    } else if (!ctx->vp_blocks_tiocsti) {
        add_finding(ctx, SEV_LOW, "Terminal ioctl Unfiltered",
                    "Syscall ioctl(16) allowed without TIOCSTI(0x5412) scalar virtual patch.",
                    "Add 'VPATCH_ARG_DENY 16 1 0x5412' to aegis.vpatch", 3);
    } else {
        add_finding(ctx, SEV_GUARDED, "Scalar ioctl Sanitized",
                    "TIOCSTI(0x5412) terminal injection blocked by VPATCH_ARG_DENY.",
                    NULL, 0);
    }
}

/* ============================================================================
 * 5. レポート出力 (ANSI カラー / プレーンテキスト / JSON 対応)
 * ============================================================================ */
static const char *grade_from_score(int s) {
    if (s >= 95) return "A+ (Fortress)";
    if (s >= 85) return "A  (Hardened)";
    if (s >= 70) return "B  (Moderate)";
    if (s >= 50) return "C  (Exposed)";
    return "D  (Critical Risk)";
}

static void print_human_report(const struct audit_ctx *ctx, const char *rootfs) {
    double mb = (double)ctx->total_bytes / (1024.0 * 1024.0);

    printf("\n%s=== Aegis 3D Security Posture Report: %s ===%s\n", C_BOLD(), rootfs, C_RST());
    printf("[Spatial ] Footprint : %.2f MB (%zu files, %zu ELFs) | Policy: %zu RX, %zu RO, %zu RW\n",
           mb, ctx->total_files, ctx->elf_files, ctx->rx_count, ctx->ro_count, ctx->rw_count);
    printf("[Temporal] Phase-1   : EXECVE=%s, TLS=%s, CODE=%s | Phase-2(listen): %s",
           (ctx->has_ratchet_so && ctx->freeze_execve) ? "LOCKED" : "OPEN",
           (ctx->has_ratchet_so && ctx->freeze_tls)    ? "LOCKED" : "OPEN",
           (ctx->has_ratchet_so && ctx->freeze_code)   ? "LOCKED" : "OPEN",
           (ctx->has_ratchet_so && ctx->p2_on_listen)  ? "ACTIVE" : "INACTIVE");
    if (ctx->has_ratchet_so && ctx->p2_on_listen) {
        printf(" (OPEN=%s, NET=%s, FORK=%s, CODE=%s)",
               ctx->p2_freeze_open ? "LOCKED" : "OPEN",
               ctx->p2_freeze_net  ? "LOCKED" : "OPEN",
               ctx->p2_freeze_fork ? "LOCKED" : "OPEN",
               ctx->p2_freeze_code ? "LOCKED" : "OPEN");
    }
    printf("\n");
    printf("[Boundary] VPatcher  : %s | Loaded Rules: %zu %s%s%s\n",
           ctx->has_vpatch_bin ? "BUNDLED" : "ABSENT",
           ctx->vp_total_rules,
           ctx->vpatch_loaded ? "(" : "(no vpatch file loaded",
           ctx->vpatch_loaded ? ctx->vpatch_src : "",
           ")");

    printf("\n%s--- 3D Vulnerability & Gap Analysis ---%s\n", C_BOLD(), C_RST());
    for (size_t i = 0; i < ctx->finding_count; i++) {
        const struct finding *f = &ctx->findings[i];
        const char *tag = "[GUARDED]";
        const char *col = C_GRN();
        if (f->sev == SEV_HIGH)      { tag = "[HIGH]   "; col = C_RED(); }
        else if (f->sev == SEV_MED)  { tag = "[MED]    "; col = C_YEL(); }
        else if (f->sev == SEV_LOW)  { tag = "[LOW]    "; col = C_CYN(); }

        printf("%s%s%s %-25s : %s\n", col, tag, C_RST(), f->title, f->detail);
        if (f->fix[0] != '\0') {
            printf("          %s-> Fix: %s%s\n", C_DIM(), f->fix, C_RST());
        }
    }

    const char *sc_col = (ctx->score >= 85) ? C_GRN() : (ctx->score >= 70 ? C_YEL() : C_RED());
    printf("\n%sOverall Hardening Score: %s%d / 100 — Grade: %s%s  (HIGH:%d MED:%d LOW:%d)\n\n",
           C_BOLD(), sc_col, ctx->score, grade_from_score(ctx->score), C_RST(),
           ctx->high_count, ctx->med_count, ctx->low_count);
}

static void print_json_report(const struct audit_ctx *ctx, const char *rootfs) {
    printf("{\n"
           "  \"rootfs\": \"%s\",\n"
           "  \"size_bytes\": %llu,\n"
           "  \"score\": %d,\n"
           "  \"grade\": \"%s\",\n"
           "  \"counts\": { \"high\": %d, \"med\": %d, \"low\": %d },\n"
           "  \"findings\": [\n",
           rootfs, (unsigned long long)ctx->total_bytes, ctx->score,
           grade_from_score(ctx->score), ctx->high_count, ctx->med_count, ctx->low_count);
    for (size_t i = 0; i < ctx->finding_count; i++) {
        const struct finding *f = &ctx->findings[i];
        const char *s = (f->sev == SEV_HIGH) ? "HIGH" :
                        (f->sev == SEV_MED)  ? "MED"  :
                        (f->sev == SEV_LOW)  ? "LOW"  : "GUARDED";
        printf("    { \"severity\": \"%s\", \"title\": \"%s\", \"detail\": \"%s\", \"fix\": \"%s\" }%s\n",
               s, f->title, f->detail, f->fix, (i + 1 < ctx->finding_count) ? "," : "");
    }
    printf("  ]\n}\n");
}

int main(int argc, char *argv[]) {
    const char *rootfs      = NULL;
    const char *vpatch_file = NULL;
    bool        json_out    = false;
    bool        strict_mode = false;
    bool        no_color    = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--vpatch") == 0 && i + 1 < argc) {
            vpatch_file = argv[++i];
        } else if (strcmp(argv[i], "--json") == 0) {
            json_out = true;
        } else if (strcmp(argv[i], "--strict") == 0) {
            strict_mode = true;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            no_color = true;
        } else if (argv[i][0] != '-' && !rootfs) {
            rootfs = argv[i];
        } else {
            fprintf(stderr, "Usage: %s <rootfs_dir> [--vpatch <file>] [--json] [--strict] [--no-color]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (!rootfs) {
        fprintf(stderr, "Usage: %s <rootfs_dir> [--vpatch <file>] [--json] [--strict] [--no-color]\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct stat st;
    if (stat(rootfs, &st) < 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "[-] aegis-audit: cannot access rootfs directory '%s': %s\n", rootfs, strerror(errno));
        return EXIT_FAILURE;
    }

    g_use_color = (!no_color && !json_out && isatty(STDOUT_FILENO));

    struct audit_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return EXIT_FAILURE;

    /* 1. RootFS 物理スキャン + ELF .dynsym 検査 */
    walk_rootfs(ctx, rootfs, "/", 0);

    /* 2. /etc/aegis.policy 読み込み */
    char pol_path[PATH_MAX];
    if (snprintf(pol_path, sizeof(pol_path), "%s/etc/aegis.policy", rootfs) < (int)sizeof(pol_path)) {
        parse_policy_file(ctx, pol_path);
    }

    /* 3. aegis.vpatch 読み込み (明示指定 -> RootFS内既定パス の順で探索) */
    if (vpatch_file) {
        parse_vpatch_file(ctx, vpatch_file);
    } else {
        char vp1[PATH_MAX], vp2[PATH_MAX];
        if (snprintf(vp1, sizeof(vp1), "%s/etc/aegis.vpatch", rootfs) < (int)sizeof(vp1) && access(vp1, R_OK) == 0) {
            parse_vpatch_file(ctx, vp1);
        } else if (snprintf(vp2, sizeof(vp2), "%s/etc/patches/aegis.vpatch", rootfs) < (int)sizeof(vp2) && access(vp2, R_OK) == 0) {
            parse_vpatch_file(ctx, vp2);
        }
    }

    /* 4. 3D クロス診断 & スコア算出 */
    evaluate_posture(ctx);

    if (json_out) print_json_report(ctx, rootfs);
    else          print_human_report(ctx, rootfs);

    int rc = (strict_mode && ctx->high_count > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
    free(ctx);
    return rc;
}
