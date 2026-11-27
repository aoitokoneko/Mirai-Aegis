/**
 * ============================================================================
 * File: bistro_hardened_builder.c (Universal Hardened Container Builder v4-step2)
 * Build: gcc -O2 -Wall -Wextra bistro_hardened_builder.c -o bistro-builder
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
#include <signal.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>

#define MAX_SYSCALL_NR   1024
#define MAX_TRACKED_PIDS 4096

#define TRACE_TAG_SYSCALL        0UL
#define TRACE_TAG_OPEN           1UL
#define TRACE_TAG_STAT           2UL
#define TRACE_TAG_PHASE1_WX_MMAP 10UL
#define TRACE_TAG_PHASE1_EXECVE  11UL
#define TRACE_TAG_PHASE2_MARKER  20UL
#define TRACE_TAG_PHASE2_OPEN    21UL
#define TRACE_TAG_PHASE2_NET     22UL
#define TRACE_TAG_PHASE2_FORK    23UL

static const char *LIB_SEARCH_DIRS[] = {
    "/lib64", "/usr/lib64",
    "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
    "/usr/local/lib64", "/usr/local/lib",
    "/lib", "/usr/lib",
    NULL
};

/* 安全な文字列コピー・パス結合ヘルパー (切り詰め検査付き・Warning完全排除) */
static int path_copy(char *dst, size_t dst_sz, const char *src) {
    int n = snprintf(dst, dst_sz, "%s", src);
    return (n < 0 || (size_t)n >= dst_sz) ? -1 : 0;
}

static int path_join(char *dst, size_t dst_sz, const char *a, const char *b) {
    int n = snprintf(dst, dst_sz, "%s/%s", a, b);
    return (n < 0 || (size_t)n >= dst_sz) ? -1 : 0;
}

static int path_concat(char *dst, size_t dst_sz, const char *a, const char *b) {
    int n = snprintf(dst, dst_sz, "%s%s", a, b);
    return (n < 0 || (size_t)n >= dst_sz) ? -1 : 0;
}

/* 動的伸長リスト */
struct str_list {
    char **items;
    size_t count;
    size_t cap;
};

static bool sl_contains(const struct str_list *sl, const char *s) {
    for (size_t i = 0; i < sl->count; i++) {
        if (strcmp(sl->items[i], s) == 0) return true;
    }
    return false;
}

static bool sl_add(struct str_list *sl, const char *s) {
    if (!s || s[0] == '\0' || sl_contains(sl, s)) return false;
    if (sl->count >= sl->cap) {
        size_t new_cap = (sl->cap == 0) ? 128 : sl->cap * 2;
        char **nitems = realloc(sl->items, new_cap * sizeof(char *));
        if (!nitems) {
            perror("[-] realloc");
            exit(EXIT_FAILURE);
        }
        sl->items = nitems;
        sl->cap   = new_cap;
    }
    sl->items[sl->count] = strdup(s);
    if (!sl->items[sl->count]) exit(EXIT_FAILURE);
    sl->count++;
    return true;
}

/* ポリシー全体の状態保持 */
struct policy_state {
    struct str_list rx_paths;
    struct str_list ro_paths;
    struct str_list rw_paths;
    struct str_list env_vars;
    bool            syscalls[MAX_SYSCALL_NR];
    bool            allow_net;
    /* Phase 0 -> Phase 1 (main突入時) */
    bool            freeze_code;
    bool            freeze_execve;
    bool            freeze_tls;
    /* Phase 1 -> Phase 2 (listen完了・定常ループ突入時) */
    bool            p2_on_listen;
    bool            p2_freeze_open;
    bool            p2_freeze_net;
    bool            p2_freeze_fork;
};

/* ELF BFS キュー */
static struct str_list g_elf_queue;
static size_t          g_elf_head = 0;

static void enqueue_elf(const char *path) {
    if (path && path[0] == '/') sl_add(&g_elf_queue, path);
}

static bool is_elf_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    unsigned char magic[4] = {0};
    ssize_t n = read(fd, magic, 4);
    close(fd);
    return (n == 4 && memcmp(magic, ELFMAG, SELFMAG) == 0);
}

static int mkdir_p(const char *dir, mode_t mode) {
    char tmp[PATH_MAX * 2 + 32];
    if (path_copy(tmp, sizeof(tmp), dir) < 0) return -1;
    size_t len = strlen(tmp);
    if (len > 1 && tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -1;
    return 0;
}

static int copy_to_rootfs(const char *src_path, const char *rootfs, const char *dest_rel_path, mode_t mode) {
    char dst[PATH_MAX * 2 + 32];
    char parent[PATH_MAX * 2 + 32];

    if (path_concat(dst, sizeof(dst), rootfs, dest_rel_path) < 0) return -1;
    if (path_copy(parent, sizeof(parent), dst) < 0) return -1;

    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) {
        *slash = '\0';
        if (mkdir_p(parent, 0755) < 0) return -1;
    }

    int in_fd = open(src_path, O_RDONLY);
    if (in_fd < 0) {
        fprintf(stderr, "[-] Cannot open '%s': %s\n", src_path, strerror(errno));
        return -1;
    }

    int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out_fd < 0) {
        fprintf(stderr, "[-] Cannot create '%s': %s\n", dst, strerror(errno));
        close(in_fd);
        return -1;
    }

    unsigned char buf[65536];
    ssize_t n;
    while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out_fd, buf + off, (size_t)(n - off));
            if (w < 0) {
                if (errno == EINTR) continue;
                close(in_fd);
                close(out_fd);
                return -1;
            }
            off += w;
        }
    }

    if (fchmod(out_fd, mode) < 0) perror("[-] fchmod");
    close(in_fd);
    close(out_fd);
    return 0;
}

static int copy_tree_to_rootfs(const char *src, const char *rootfs, const char *dst_rel,
                               bool is_rx, int depth) {
    if (depth > 32) return 0;
    struct stat st;
    if (stat(src, &st) < 0) {
        fprintf(stderr, "[-] Cannot stat '%s': %s\n", src, strerror(errno));
        return -1;
    }

    if (S_ISREG(st.st_mode)) {
        bool elf = is_elf_file(src);
        mode_t mode = (is_rx || elf || (st.st_mode & 0111)) ? 0755 : 0644;
        if (copy_to_rootfs(src, rootfs, dst_rel, mode) < 0) return -1;
        if (is_rx && elf) enqueue_elf(src);
        return 0;
    }

    if (S_ISDIR(st.st_mode)) {
        char dst_dir[PATH_MAX * 2 + 32];
        if (path_concat(dst_dir, sizeof(dst_dir), rootfs, dst_rel) < 0) return -1;
        if (mkdir_p(dst_dir, 0755) < 0) return -1;

        DIR *d = opendir(src);
        if (!d) return -1;
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            char child_src[PATH_MAX * 2];
            char child_dst[PATH_MAX * 2];
            if (path_join(child_src, sizeof(child_src), src, ent->d_name) < 0) continue;
            if (path_join(child_dst, sizeof(child_dst),
                          (strcmp(dst_rel, "/") == 0) ? "" : dst_rel, ent->d_name) < 0) continue;
            if (copy_tree_to_rootfs(child_src, rootfs, child_dst, is_rx, depth + 1) < 0) {
                closedir(d);
                return -1;
            }
        }
        closedir(d);
    }
    return 0;
}

/* ============================================================================
 * 非実行 ELF64 静的パーサ (PT_INTERP / DT_NEEDED / DT_RPATH / DT_RUNPATH)
 * ============================================================================ */
static const char *vma_to_ptr(const void *map, size_t file_size,
                              const Elf64_Ehdr *ehdr, const Elf64_Phdr *phdr,
                              Elf64_Addr vma, size_t *avail_bytes) {
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (vma >= phdr[i].p_vaddr && vma < phdr[i].p_vaddr + phdr[i].p_filesz) {
                size_t delta  = (size_t)(vma - phdr[i].p_vaddr);
                size_t offset = (size_t)phdr[i].p_offset + delta;
                if (offset < file_size) {
                    if (avail_bytes) {
                        size_t seg_rem  = (size_t)phdr[i].p_filesz - delta;
                        size_t file_rem = file_size - offset;
                        *avail_bytes = (seg_rem < file_rem) ? seg_rem : file_rem;
                    }
                    return (const char *)map + offset;
                }
            }
        }
    }
    return NULL;
}

static int try_dir_list(const char *colon_dirs, const char *origin_dir,
                        const char *soname, char *out_path, size_t out_sz) {
    if (!colon_dirs || colon_dirs[0] == '\0') return -1;
    char copy[PATH_MAX * 2];
    if (path_copy(copy, sizeof(copy), colon_dirs) < 0) return -1;

    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, ":", &saveptr); tok != NULL; tok = strtok_r(NULL, ":", &saveptr)) {
        char expanded[PATH_MAX * 2];
        if (strncmp(tok, "$ORIGIN", 7) == 0) {
            if (path_concat(expanded, sizeof(expanded), origin_dir, tok + 7) < 0) continue;
        } else if (strncmp(tok, "${ORIGIN}", 9) == 0) {
            if (path_concat(expanded, sizeof(expanded), origin_dir, tok + 9) < 0) continue;
        } else {
            if (path_copy(expanded, sizeof(expanded), tok) < 0) continue;
        }
        char real_dir[PATH_MAX];
        const char *use_dir = realpath(expanded, real_dir) ? real_dir : expanded;
        char candidate[PATH_MAX * 2];
        if (path_join(candidate, sizeof(candidate), use_dir, soname) < 0) continue;
        if (access(candidate, R_OK) == 0) {
            if (path_copy(out_path, out_sz, candidate) == 0) return 0;
        }
    }
    return -1;
}

static int resolve_soname(const char *soname, const char *owner_elf,
                          const char *rpath, const char *runpath,
                          char *out_path, size_t out_sz) {
    if (soname[0] == '/') {
        if (access(soname, R_OK) == 0) {
            return path_copy(out_path, out_sz, soname);
        }
        return -1;
    }

    char origin_dir[PATH_MAX];
    if (path_copy(origin_dir, sizeof(origin_dir), owner_elf) < 0) return -1;
    char *slash = strrchr(origin_dir, '/');
    if (slash && slash != origin_dir) *slash = '\0';
    else strcpy(origin_dir, "/");

    if (rpath && !runpath && try_dir_list(rpath, origin_dir, soname, out_path, out_sz) == 0) return 0;
    if (runpath && try_dir_list(runpath, origin_dir, soname, out_path, out_sz) == 0) return 0;

    for (int i = 0; LIB_SEARCH_DIRS[i] != NULL; i++) {
        char candidate[PATH_MAX * 2];
        if (path_join(candidate, sizeof(candidate), LIB_SEARCH_DIRS[i], soname) < 0) continue;
        if (access(candidate, R_OK) == 0) {
            if (path_copy(out_path, out_sz, candidate) == 0) return 0;
        }
    }
    return -1;
}

static void inspect_elf_and_enqueue_deps(const char *filepath) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) return;

    struct stat st;
    if (fstat(fd, &st) < 0 || (size_t)st.st_size < sizeof(Elf64_Ehdr)) {
        close(fd);
        return;
    }

    size_t fsize = (size_t)st.st_size;
    void *map = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return;
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)map;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_phoff + (size_t)ehdr->e_phnum * sizeof(Elf64_Phdr) > fsize) {
        munmap(map, fsize);
        close(fd);
        return;
    }

    const Elf64_Phdr *phdr = (const Elf64_Phdr *)((const char *)map + ehdr->e_phoff);
    const Elf64_Dyn  *dyn  = NULL;
    size_t dyn_count = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_INTERP && phdr[i].p_offset + phdr[i].p_filesz <= fsize && phdr[i].p_filesz > 1) {
            char interp[PATH_MAX] = {0};
            size_t n = phdr[i].p_filesz < sizeof(interp) - 1 ? phdr[i].p_filesz : sizeof(interp) - 1;
            memcpy(interp, (const char *)map + phdr[i].p_offset, n);
            interp[n] = '\0';
            enqueue_elf(interp);
        } else if (phdr[i].p_type == PT_DYNAMIC && phdr[i].p_offset + phdr[i].p_filesz <= fsize) {
            dyn = (const Elf64_Dyn *)((const char *)map + phdr[i].p_offset);
            dyn_count = phdr[i].p_filesz / sizeof(Elf64_Dyn);
        }
    }

    if (dyn) {
        const char *strtab = NULL;
        size_t strtab_avail = 0;
        size_t rpath_off = (size_t)-1, runpath_off = (size_t)-1;

        for (size_t i = 0; i < dyn_count && dyn[i].d_tag != DT_NULL; i++) {
            if (dyn[i].d_tag == DT_STRTAB)
                strtab = vma_to_ptr(map, fsize, ehdr, phdr, dyn[i].d_un.d_ptr, &strtab_avail);
            else if (dyn[i].d_tag == DT_RPATH)
                rpath_off = (size_t)dyn[i].d_un.d_val;
            else if (dyn[i].d_tag == DT_RUNPATH)
                runpath_off = (size_t)dyn[i].d_un.d_val;
        }

        if (strtab) {
            const char *rpath   = (rpath_off < strtab_avail)   ? (strtab + rpath_off)   : NULL;
            const char *runpath = (runpath_off < strtab_avail) ? (strtab + runpath_off) : NULL;

            for (size_t i = 0; i < dyn_count && dyn[i].d_tag != DT_NULL; i++) {
                if (dyn[i].d_tag == DT_NEEDED) {
                    size_t off = (size_t)dyn[i].d_un.d_val;
                    if (off < strtab_avail) {
                        size_t max_len = strtab_avail - off;
                        size_t slen = strnlen(strtab + off, max_len);
                        if (slen > 0 && slen < max_len) {
                            char resolved[PATH_MAX];
                            if (resolve_soname(strtab + off, filepath, rpath, runpath, resolved, sizeof(resolved)) == 0) {
                                enqueue_elf(resolved);
                            }
                        }
                    }
                }
            }
        }
    }

    munmap(map, fsize);
    close(fd);
}

static int drain_elf_queue_into_rootfs(const char *rootfs_dir, struct policy_state *pol) {
    while (g_elf_head < g_elf_queue.count) {
        const char *cur = g_elf_queue.items[g_elf_head++];
        char dst_check[PATH_MAX * 2 + 32];
        if (path_concat(dst_check, sizeof(dst_check), rootfs_dir, cur) < 0) return -1;
        if (access(dst_check, F_OK) != 0) {
            printf("  [ELF+RX] %s\n", cur);
            if (copy_to_rootfs(cur, rootfs_dir, cur, 0755) < 0) return -1;
        }
        sl_add(&pol->rx_paths, cur);
        inspect_elf_and_enqueue_deps(cur);
    }
    return 0;
}

/* ============================================================================
 * ポリシーの読み書き (Phase 1 & Phase 2 Temporal Ratchet 対応)
 * ============================================================================ */
static bool covered_by_parent_dir(const struct str_list *dirs, const char *path) {
    for (size_t i = 0; i < dirs->count; i++) {
        const char *d = dirs->items[i];
        size_t dlen = strlen(d);
        if (dlen > 1 && strncmp(path, d, dlen) == 0 && path[dlen] == '/') {
            return true;
        }
    }
    return false;
}

static void load_existing_policy(const char *policy_file, struct policy_state *pol) {
    FILE *fp = fopen(policy_file, "r");
    if (!fp) return;

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "RX ", 3) == 0) sl_add(&pol->rx_paths, line + 3);
        else if (strncmp(line, "RO ", 3) == 0) sl_add(&pol->ro_paths, line + 3);
        else if (strncmp(line, "RW ", 3) == 0) sl_add(&pol->rw_paths, line + 3);
        else if (strncmp(line, "ENV ", 4) == 0) sl_add(&pol->env_vars, line + 4);
        else if (strncmp(line, "ALLOW_NET 1", 11) == 0) pol->allow_net = true;
        else if (strncmp(line, "FREEZE_CODE ", 12) == 0) pol->freeze_code = (atoi(line + 12) != 0);
        else if (strncmp(line, "FREEZE_EXECVE ", 14) == 0) pol->freeze_execve = (atoi(line + 14) != 0);
        else if (strncmp(line, "FREEZE_TLS ", 11) == 0) pol->freeze_tls = (atoi(line + 11) != 0);
        else if (strncmp(line, "PHASE2_ON_LISTEN ", 17) == 0) pol->p2_on_listen = (atoi(line + 17) != 0);
        else if (strncmp(line, "PHASE2_FREEZE_OPEN ", 19) == 0) pol->p2_freeze_open = (atoi(line + 19) != 0);
        else if (strncmp(line, "PHASE2_FREEZE_NET ", 18) == 0) pol->p2_freeze_net = (atoi(line + 18) != 0);
        else if (strncmp(line, "PHASE2_FREEZE_FORK ", 19) == 0) pol->p2_freeze_fork = (atoi(line + 19) != 0);
        else if (strncmp(line, "SYSCALL ", 8) == 0) {
            long nr = strtol(line + 8, NULL, 10);
            if (nr >= 0 && nr < MAX_SYSCALL_NR) pol->syscalls[nr] = true;
        }
    }
    fclose(fp);
}

static int save_policy(const char *policy_file, const struct policy_state *pol) {
    FILE *pf = fopen(policy_file, "w");
    if (!pf) {
        perror("[-] Failed to write aegis.policy");
        return -1;
    }

    fprintf(pf, "# Auto-generated by BistroHardened Builder v4-step2\n");
    fprintf(pf, "# 1. Exact RX whitelist (Executables & Shared Libraries)\n");
    for (size_t i = 0; i < pol->rx_paths.count; i++) {
        fprintf(pf, "RX %s\n", pol->rx_paths.items[i]);
    }

    if (pol->ro_paths.count > 0) {
        struct str_list ro_dirs = {0};
        for (size_t i = 0; i < pol->ro_paths.count; i++) {
            struct stat st;
            if (stat(pol->ro_paths.items[i], &st) == 0 && S_ISDIR(st.st_mode)) {
                sl_add(&ro_dirs, pol->ro_paths.items[i]);
            }
        }

        fprintf(pf, "\n# 2. Minimal RO data/module paths\n");
        for (size_t i = 0; i < pol->ro_paths.count; i++) {
            const char *p = pol->ro_paths.items[i];
            if (sl_contains(&pol->rx_paths, p)) continue;
            if (!sl_contains(&ro_dirs, p) && covered_by_parent_dir(&ro_dirs, p)) continue;
            fprintf(pf, "RO %s\n", p);
        }
    }

    fprintf(pf, "\n# 3. Writable runtime paths (No execute permission)\n");
    for (size_t i = 0; i < pol->rw_paths.count; i++) {
        fprintf(pf, "RW %s\n", pol->rw_paths.items[i]);
    }

    if (pol->env_vars.count > 0) {
        fprintf(pf, "\n# 4. Sanitized static environment variables\n");
        for (size_t i = 0; i < pol->env_vars.count; i++) {
            fprintf(pf, "ENV %s\n", pol->env_vars.items[i]);
        }
    }

    if (pol->allow_net) {
        fprintf(pf, "\n# 5. Network policy\nALLOW_NET 1\n");
    }

    bool any_sc = false;
    for (int i = 0; i < MAX_SYSCALL_NR; i++) {
        if (pol->syscalls[i]) { any_sc = true; break; }
    }
    if (any_sc) {
        fprintf(pf, "\n# 6. Auto-learned extra syscalls\n");
        for (int i = 0; i < MAX_SYSCALL_NR; i++) {
            if (pol->syscalls[i]) fprintf(pf, "SYSCALL %d\n", i);
        }
    }

    fprintf(pf, "\n# 7. Phase 0 -> Phase 1 Temporal Ratchet (at main() entry)\n");
    fprintf(pf, "FREEZE_CODE %d\n",   pol->freeze_code   ? 1 : 0);
    fprintf(pf, "FREEZE_EXECVE %d\n", pol->freeze_execve ? 1 : 0);
    fprintf(pf, "FREEZE_TLS %d\n",    pol->freeze_tls    ? 1 : 0);

    fprintf(pf, "\n# 8. Phase 1 -> Phase 2 Steady-Loop Ratchet (after listen())\n");
    fprintf(pf, "PHASE2_ON_LISTEN %d\n",   pol->p2_on_listen   ? 1 : 0);
    fprintf(pf, "PHASE2_FREEZE_OPEN %d\n", pol->p2_freeze_open ? 1 : 0);
    fprintf(pf, "PHASE2_FREEZE_NET %d\n",  pol->p2_freeze_net  ? 1 : 0);
    fprintf(pf, "PHASE2_FREEZE_FORK %d\n", pol->p2_freeze_fork ? 1 : 0);

    fclose(pf);
    return 0;
}

/* ============================================================================
 * ptrace メモリ文字列安全読み取り & パス正規化
 * ============================================================================ */
static int read_tracee_string(pid_t pid, unsigned long addr, char *out, size_t out_sz) {
    if (addr == 0 || out_sz == 0) return -1;
    unsigned long aligned = addr & ~(sizeof(long) - 1UL);
    size_t skip = (size_t)(addr - aligned);
    size_t off  = 0;

    for (unsigned long cur = aligned; off < out_sz - 1; cur += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)cur, NULL);
        if (errno != 0) {
            out[off] = '\0';
            return (off > 0) ? 0 : -1;
        }
        const char *bytes = (const char *)&word;
        for (size_t b = skip; b < sizeof(long) && off < out_sz - 1; b++) {
            out[off++] = bytes[b];
            if (bytes[b] == '\0') return 0;
        }
        skip = 0;
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
    for (char *tok = strtok_r(buf, "/", &save); tok != NULL; tok = strtok_r(NULL, "/", &save)) {
        if (strcmp(tok, ".") == 0) continue;
        if (strcmp(tok, "..") == 0) {
            if (nseg > 0) nseg--;
            continue;
        }
        if (nseg < 256) segs[nseg++] = tok;
    }

    if (nseg == 0) {
        (void)path_copy(out, out_sz, "/");
        return;
    }
    size_t pos = 0;
    for (int i = 0; i < nseg && pos + 2 < out_sz; i++) {
        int w = snprintf(out + pos, out_sz - pos, "/%s", segs[i]);
        if (w < 0 || (size_t)w >= out_sz - pos) break;
        pos += (size_t)w;
    }
}

static int resolve_tracee_path(pid_t pid, long nr, const struct user_regs_struct *regs,
                               char *out_norm, size_t out_sz) {
    int dfd = AT_FDCWD;
    unsigned long path_ptr = 0;

    if (nr == __NR_open || nr == __NR_stat || nr == __NR_lstat ||
        nr == __NR_access || nr == __NR_execve) {
        path_ptr = (unsigned long)regs->rdi;
    } else {
        dfd      = (int)regs->rdi;
        path_ptr = (unsigned long)regs->rsi;
    }

    char raw_path[PATH_MAX];
    if (read_tracee_string(pid, path_ptr, raw_path, sizeof(raw_path)) < 0 || raw_path[0] == '\0') {
        return -1;
    }

    char combined[PATH_MAX * 2 + 16];
    if (raw_path[0] == '/') {
        if (path_copy(combined, sizeof(combined), raw_path) < 0) return -1;
    } else {
        char proc_link[64];
        char base_dir[PATH_MAX];
        if (dfd == AT_FDCWD) {
            snprintf(proc_link, sizeof(proc_link), "/proc/%d/cwd", (int)pid);
        } else if (dfd >= 0) {
            snprintf(proc_link, sizeof(proc_link), "/proc/%d/fd/%d", (int)pid, dfd);
        } else {
            return -1;
        }
        ssize_t len = readlink(proc_link, base_dir, sizeof(base_dir) - 1);
        if (len <= 0) return -1;
        base_dir[len] = '\0';
        if (path_join(combined, sizeof(combined), base_dir, raw_path) < 0) return -1;
    }

    normalize_lexical_path(combined, out_norm, out_sz);
    return (out_norm[0] == '/') ? 0 : -1;
}

static bool should_ignore_host_path(const char *path, const char *abs_rootfs, const char *abs_ratchet) {
    if (strcmp(path, "/") == 0) return true;
    if (abs_ratchet && abs_ratchet[0] != '\0' && strcmp(path, abs_ratchet) == 0) return true;

    static const char *skip_prefixes[] = {
        "/proc/", "/sys/", "/dev/", "/tmp/", "/run/", "/var/run/", "/var/tmp/", NULL
    };
    static const char *skip_exact[] = {
        "/proc", "/sys", "/dev", "/tmp", "/run", "/var/run", "/var/tmp", NULL
    };
    for (int i = 0; skip_exact[i]; i++) {
        if (strcmp(path, skip_exact[i]) == 0) return true;
    }
    for (int i = 0; skip_prefixes[i]; i++) {
        if (strncmp(path, skip_prefixes[i], strlen(skip_prefixes[i])) == 0) return true;
    }
    if (abs_rootfs && abs_rootfs[0] != '\0') {
        size_t rlen = strlen(abs_rootfs);
        if (strncmp(path, abs_rootfs, rlen) == 0 && (path[rlen] == '/' || path[rlen] == '\0')) {
            return true;
        }
    }
    return false;
}

/* ============================================================================
 * ワンパス自動学習エンジン (Phase 1 & Phase 2 Temporal Ratchet 自動境界学習)
 * ============================================================================ */
static bool pid_mark_seen(pid_t *table, pid_t pid) {
    int empty_slot = -1;
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (table[i] == pid) return true;
        if (empty_slot < 0 && table[i] == 0) empty_slot = i;
    }
    if (empty_slot >= 0) table[empty_slot] = pid;
    return false;
}

static void pid_remove(pid_t *table, pid_t pid) {
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (table[i] == pid) { table[i] = 0; return; }
    }
}

static int run_learner(const char *aegis_bin, const char *ratchet_src, const char *rootfs_dir,
                       struct policy_state *pol, bool learn_files,
                       const char *target_binary, int target_argc, char **target_args) {
    char abs_rootfs[PATH_MAX] = {0};
    if (!realpath(rootfs_dir, abs_rootfs)) {
        (void)path_copy(abs_rootfs, sizeof(abs_rootfs), rootfs_dir);
    }

    char abs_ratchet[PATH_MAX] = {0};
    if (ratchet_src && realpath(ratchet_src, abs_ratchet) == NULL) {
        abs_ratchet[0] = '\0';
    }

    char tmp_pol[] = "/tmp/.aegis-learn-XXXXXX";
    int tmp_fd = mkstemp(tmp_pol);
    if (tmp_fd < 0) {
        perror("[-] mkstemp");
        return -1;
    }
    FILE *tf = fdopen(tmp_fd, "w");
    if (!tf) {
        close(tmp_fd);
        unlink(tmp_pol);
        return -1;
    }
    fprintf(tf, "RX /\nRW /tmp\nRW /dev\n");
    fprintf(tf, "FREEZE_CODE %d\nFREEZE_EXECVE %d\nFREEZE_TLS %d\n",
            pol->freeze_code ? 1 : 0, pol->freeze_execve ? 1 : 0, pol->freeze_tls ? 1 : 0);
    if (pol->allow_net) fprintf(tf, "ALLOW_NET 1\n");
    for (size_t i = 0; i < pol->env_vars.count; i++) fprintf(tf, "ENV %s\n", pol->env_vars.items[i]);
    for (int i = 0; i < MAX_SYSCALL_NR; i++) {
        if (pol->syscalls[i]) fprintf(tf, "SYSCALL %d\n", i);
    }
    fclose(tf);

    printf("\n[*] Starting One-Pass Auto-Learner (%s + Phase 1/2 Temporal Ratchet)...\n",
           learn_files ? "Syscalls + Runtime Files + dlopen ELFs" : "Syscalls only");
    printf("[*] Executing: %s", target_binary);
    for (int i = 0; i < target_argc; i++) printf(" %s", target_args[i]);
    printf("\n");

    pid_t child = fork();
    if (child < 0) {
        unlink(tmp_pol);
        return -1;
    }

    if (child == 0) {
        setenv("AEGIS_POLICY", tmp_pol, 1);
        if (abs_ratchet[0] == '/') {
            setenv("AEGIS_RATCHET_SO", abs_ratchet, 1);
        }
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) _exit(EXIT_FAILURE);
        raise(SIGSTOP);

        char **exec_argv = calloc((size_t)target_argc + 4, sizeof(char *));
        if (!exec_argv) _exit(EXIT_FAILURE);
        exec_argv[0] = (char *)aegis_bin;
        exec_argv[1] = learn_files ? "--learn-trace-files" : "--learn-trace";
        exec_argv[2] = (char *)target_binary;
        for (int i = 0; i < target_argc; i++) exec_argv[3 + i] = target_args[i];
        exec_argv[3 + target_argc] = NULL;

        execv(aegis_bin, exec_argv);
        perror("[-] execv(aegis-init)");
        _exit(EXIT_FAILURE);
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        unlink(tmp_pol);
        return -1;
    }

    unsigned long ptrace_opts = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEFORK |
                                PTRACE_O_TRACEVFORK   | PTRACE_O_TRACECLONE |
                                PTRACE_O_TRACEEXEC    | PTRACE_O_EXITKILL;
    if (ptrace(PTRACE_SETOPTIONS, child, 0, (void *)ptrace_opts) < 0) {
        perror("[-] ptrace(SETOPTIONS)");
        unlink(tmp_pol);
        return -1;
    }

    pid_t seen_pids[MAX_TRACKED_PIDS] = {0};
    pid_mark_seen(seen_pids, child);
    ptrace(PTRACE_CONT, child, 0, 0);

    struct str_list seen_paths = {0};
    int new_sc_count   = 0;
    int new_file_count = 0;

    while (1) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            pid_remove(seen_pids, pid);
            if (pid == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
                fprintf(stderr, "[!] Warning: Target violated Strict W^X, TLS Freeze, or Blacklist (SIGSYS)!\n");
            }
            continue;
        }
        if (!WIFSTOPPED(status)) continue;

        bool was_seen   = pid_mark_seen(seen_pids, pid);
        int  sig        = WSTOPSIG(status);
        unsigned int ev = (unsigned int)status >> 16;
        int deliver_sig = 0;

        if (sig == SIGTRAP && ev == PTRACE_EVENT_SECCOMP) {
            unsigned long tag = 0;
            ptrace(PTRACE_GETEVENTMSG, pid, NULL, &tag);

            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0) {
                long nr = (long)regs.orig_rax;

                /* 1. Phase 1 Temporal Ratchet イベントの自動学習 */
                if (tag == TRACE_TAG_PHASE1_WX_MMAP) {
                    if (pol->freeze_code) {
                        pol->freeze_code = false;
                        printf("  [LEARN-PHASE1] Runtime mmap(PROT_EXEC) after main() detected (dlopen/JIT) -> FREEZE_CODE 0\n");
                    }
                } else if (tag == TRACE_TAG_PHASE1_EXECVE) {
                    if (pol->freeze_execve) {
                        pol->freeze_execve = false;
                        printf("  [LEARN-PHASE1] Runtime execve() after main() detected (child spawn) -> FREEZE_EXECVE 0\n");
                    }
                } else if (tag == TRACE_TAG_PHASE2_MARKER) {
                    /* 2. Phase 1 -> Phase 2 境界 (listen完了) を自動捕捉！ */
                    if (!pol->p2_on_listen) {
                        pol->p2_on_listen   = true;
                        pol->p2_freeze_open = true;
                        pol->p2_freeze_net  = true;
                        pol->p2_freeze_fork = true;
                        printf("  [LEARN-PHASE2] >>> Phase Transition Trigger (listen) reached! Entering Steady-State Loop <<<\n");
                    }
                } else if (tag == TRACE_TAG_PHASE2_OPEN) {
                    if (pol->p2_freeze_open) {
                        pol->p2_freeze_open = false;
                        printf("  [LEARN-PHASE2] File open() detected inside steady loop -> PHASE2_FREEZE_OPEN 0\n");
                    }
                } else if (tag == TRACE_TAG_PHASE2_NET) {
                    if (pol->p2_freeze_net) {
                        pol->p2_freeze_net = false;
                        printf("  [LEARN-PHASE2] Outbound socket/connect detected inside steady loop -> PHASE2_FREEZE_NET 0\n");
                    }
                } else if (tag == TRACE_TAG_PHASE2_FORK) {
                    if (pol->p2_freeze_fork) {
                        pol->p2_freeze_fork = false;
                        printf("  [LEARN-PHASE2] Process/Thread clone() detected inside steady loop -> PHASE2_FREEZE_FORK 0\n");
                    }
                } else if (tag == TRACE_TAG_SYSCALL) {
                    if (nr >= 0 && nr < MAX_SYSCALL_NR && !pol->syscalls[nr]) {
                        pol->syscalls[nr] = true;
                        new_sc_count++;
                        printf("  [LEARN-SYSCALL] nr = %ld\n", nr);
                    }
                }

                /* 3. ファイル・dlopen・子プロセス実行バイナリの自動パッキング */
                if (learn_files && (tag == TRACE_TAG_OPEN || tag == TRACE_TAG_STAT ||
                                    tag == TRACE_TAG_PHASE1_EXECVE || tag == TRACE_TAG_PHASE2_OPEN)) {
                    unsigned long eff_tag = (tag == TRACE_TAG_PHASE1_EXECVE || tag == TRACE_TAG_PHASE2_OPEN)
                                            ? TRACE_TAG_OPEN : tag;
                    char norm_path[PATH_MAX * 2];
                    if (resolve_tracee_path(pid, nr, &regs, norm_path, sizeof(norm_path)) == 0 &&
                        !should_ignore_host_path(norm_path, abs_rootfs, abs_ratchet)) {
                        char cache_key[PATH_MAX * 2 + 32];
                        snprintf(cache_key, sizeof(cache_key), "%lu:%s", eff_tag, norm_path);

                        if (sl_add(&seen_paths, cache_key)) {
                            struct stat st;
                            if (stat(norm_path, &st) == 0) {
                                if (S_ISREG(st.st_mode)) {
                                    char dst_chk[PATH_MAX * 2 + 32];
                                    if (path_concat(dst_chk, sizeof(dst_chk), rootfs_dir, norm_path) == 0) {
                                        if (is_elf_file(norm_path)) {
                                            enqueue_elf(norm_path);
                                            drain_elf_queue_into_rootfs(rootfs_dir, pol);
                                        } else {
                                            if (access(dst_chk, F_OK) != 0) {
                                                if (copy_to_rootfs(norm_path, rootfs_dir, norm_path, 0644) == 0) {
                                                    new_file_count++;
                                                }
                                            }
                                            sl_add(&pol->ro_paths, norm_path);
                                        }
                                    }
                                } else if (S_ISDIR(st.st_mode)) {
                                    char dst_dir[PATH_MAX * 2 + 32];
                                    if (path_concat(dst_dir, sizeof(dst_dir), rootfs_dir, norm_path) == 0) {
                                        mkdir_p(dst_dir, 0755);
                                        if (eff_tag == TRACE_TAG_OPEN) {
                                            sl_add(&pol->ro_paths, norm_path);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if (ev != 0) {
            deliver_sig = 0;
        } else if (sig == SIGSTOP && !was_seen) {
            deliver_sig = 0;
        } else if (sig != SIGTRAP) {
            deliver_sig = sig;
        }

        ptrace(PTRACE_CONT, pid, 0, (void *)(uintptr_t)deliver_sig);
    }

    unlink(tmp_pol);
    printf("[+] Auto-Learner finished: +%d new syscall(s), +%d runtime data/module file(s)\n",
           new_sc_count, new_file_count);
    printf("[+] Phase-1 Ratchet: FREEZE_CODE=%d, FREEZE_EXECVE=%d, FREEZE_TLS=%d\n",
           pol->freeze_code ? 1 : 0, pol->freeze_execve ? 1 : 0, pol->freeze_tls ? 1 : 0);
    if (pol->p2_on_listen) {
        printf("[+] Phase-2 Ratchet (on listen): FREEZE_OPEN=%d, FREEZE_NET=%d, FREEZE_FORK=%d\n",
               pol->p2_freeze_open ? 1 : 0, pol->p2_freeze_net ? 1 : 0, pol->p2_freeze_fork ? 1 : 0);
    }
    return 0;
}

static void write_dockerfile(const char *rootfs_dir, const char *target_binary) {
    char df_path[PATH_MAX * 2 + 32];
    snprintf(df_path, sizeof(df_path), "%s.Dockerfile", rootfs_dir);
    FILE *df = fopen(df_path, "w");
    if (!df) return;

    fprintf(df,
            "# Auto-generated by BistroHardened Builder v4-step2\n"
            "FROM scratch\n"
            "COPY %s/ /\n"
            "USER 65532:65532\n"
            "ENTRYPOINT [\"/bin/aegis-init\", \"%s\"]\n",
            rootfs_dir, target_binary);
    fclose(df);
    printf("[+] Generated zero-OS Dockerfile: %s\n", df_path);
}

static void parse_src_dst(const char *spec, char *src, size_t src_sz, char *dst, size_t dst_sz) {
    const char *colon = strchr(spec, ':');
    if (colon) {
        size_t slen = (size_t)(colon - spec);
        if (slen >= src_sz) slen = src_sz - 1;
        memcpy(src, spec, slen);
        src[slen] = '\0';
        (void)path_copy(dst, dst_sz, colon + 1);
    } else {
        (void)path_copy(src, src_sz, spec);
        (void)path_copy(dst, dst_sz, spec);
    }
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  1) Bundle (+ Optional Auto-Learn):\n"
            "     %s bundle </abs/target> --out <rootfs> [options] [-- <target_args...>]\n\n"
            "  2) Incremental Learn / Add Paths to Existing RootFS:\n"
            "     %s learn --out <rootfs> [options] -- </abs/target> [target_args...]\n\n"
            "Options:\n"
            "  --aegis <path>            Path to compiled aegis-init (default: ./aegis-init)\n"
            "  --ratchet <path>          Path to compiled libaegis_ratchet.so (default: ./libaegis_ratchet.so)\n"
            "  --learn                   Auto-learn syscalls + Phase 1/2 temporal ratchet policy\n"
            "  --learn-files             Auto-learn syscalls + bundle accessed files & dlopen .so\n"
            "  --include-ro <src[:dst]>  Bundle extra file/dir as RO (e.g., ./app.py:/app/app.py)\n"
            "  --include-rx <src[:dst]>  Bundle extra ELF/dir as RX (+ resolve its .so deps)\n"
            "  --include-rw <dst_dir>    Create writable dir in rootfs & grant Landlock RW\n"
            "  --env <KEY=VAL>           Add sanitized static environment variable\n"
            "  --allow-net               Allow socket/connect/bind/listen syscalls\n",
            prog, prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    bool is_bundle = (strcmp(argv[1], "bundle") == 0);
    bool is_learn  = (strcmp(argv[1], "learn") == 0);
    if (!is_bundle && !is_learn) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_binary = NULL;
    const char *rootfs_dir    = NULL;
    const char *aegis_src     = "./aegis-init";
    const char *ratchet_src   = "./libaegis_ratchet.so";
    bool do_learn             = is_learn;
    bool learn_files          = false;
    bool allow_net            = false;
    int  dash_idx             = -1;

    struct str_list inc_ro = {0}, inc_rx = {0}, inc_rw = {0}, cli_envs = {0};

    int arg_start = 2;
    if (is_bundle) {
        if (argc < 5) { print_usage(argv[0]); return EXIT_FAILURE; }
        target_binary = argv[2];
        arg_start     = 3;
    }

    for (int i = arg_start; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            dash_idx = i;
            break;
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            rootfs_dir = argv[++i];
        } else if (strcmp(argv[i], "--aegis") == 0 && i + 1 < argc) {
            aegis_src = argv[++i];
        } else if (strcmp(argv[i], "--ratchet") == 0 && i + 1 < argc) {
            ratchet_src = argv[++i];
        } else if (strcmp(argv[i], "--learn") == 0) {
            do_learn = true;
        } else if (strcmp(argv[i], "--learn-files") == 0) {
            do_learn    = true;
            learn_files = true;
        } else if (strcmp(argv[i], "--allow-net") == 0) {
            allow_net = true;
        } else if (strcmp(argv[i], "--include-ro") == 0 && i + 1 < argc) {
            sl_add(&inc_ro, argv[++i]);
        } else if (strcmp(argv[i], "--include-rx") == 0 && i + 1 < argc) {
            sl_add(&inc_rx, argv[++i]);
        } else if (strcmp(argv[i], "--include-rw") == 0 && i + 1 < argc) {
            sl_add(&inc_rw, argv[++i]);
        } else if (strcmp(argv[i], "--env") == 0 && i + 1 < argc) {
            sl_add(&cli_envs, argv[++i]);
        }
    }

    if (is_learn) {
        if (!rootfs_dir || dash_idx < 0 || dash_idx + 1 >= argc) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        target_binary = argv[dash_idx + 1];
    }

    if (!rootfs_dir || !target_binary || target_binary[0] != '/') {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    char policy_file[PATH_MAX * 2 + 32];
    if (path_concat(policy_file, sizeof(policy_file), rootfs_dir, "/etc/aegis.policy") < 0) {
        return EXIT_FAILURE;
    }

    struct policy_state pol = {0};
    pol.freeze_code   = true;
    pol.freeze_execve = true;
    pol.freeze_tls    = true;

    if (is_learn) {
        load_existing_policy(policy_file, &pol);
    }

    sl_add(&pol.rw_paths, "/tmp");
    sl_add(&pol.rw_paths, "/dev/null");
    if (allow_net) pol.allow_net = true;
    for (size_t i = 0; i < cli_envs.count; i++) sl_add(&pol.env_vars, cli_envs.items[i]);

    if (is_bundle) {
        printf("[*] BistroHardened Builder v4-step2 starting\n");
        printf("[*] Target : %s\n", target_binary);
        printf("[*] RootFS : %s\n\n", rootfs_dir);

        char dir_buf[PATH_MAX * 2 + 32];
        if (path_concat(dir_buf, sizeof(dir_buf), rootfs_dir, "/tmp") < 0 ||
            mkdir_p(dir_buf, 01777) < 0 || chmod(dir_buf, 01777) < 0) {
            perror("[-] Failed to setup /tmp");
            return EXIT_FAILURE;
        }
        if (path_concat(dir_buf, sizeof(dir_buf), rootfs_dir, "/etc") < 0 ||
            mkdir_p(dir_buf, 0755) < 0) {
            perror("[-] Failed to setup /etc");
            return EXIT_FAILURE;
        }

        enqueue_elf(target_binary);

        if (access(ratchet_src, R_OK) == 0) {
            printf("[+] Injecting Phase 1/2 Ratchet Stub -> %s/lib/libaegis_ratchet.so\n", rootfs_dir);
            if (copy_to_rootfs(ratchet_src, rootfs_dir, "/lib/libaegis_ratchet.so", 0755) < 0) {
                return EXIT_FAILURE;
            }
            sl_add(&pol.rx_paths, "/lib/libaegis_ratchet.so");
            inspect_elf_and_enqueue_deps(ratchet_src);
        } else {
            fprintf(stderr, "[!] Warning: '%s' not found; Temporal Ratchet will be skipped unless built.\n", ratchet_src);
        }

        if (drain_elf_queue_into_rootfs(rootfs_dir, &pol) < 0) return EXIT_FAILURE;

        printf("[+] Injecting Aegis Runtime Launcher -> %s/bin/aegis-init\n", rootfs_dir);
        if (copy_to_rootfs(aegis_src, rootfs_dir, "/bin/aegis-init", 0755) < 0) {
            return EXIT_FAILURE;
        }
    }

    for (size_t i = 0; i < inc_ro.count; i++) {
        char src[PATH_MAX], dst[PATH_MAX];
        parse_src_dst(inc_ro.items[i], src, sizeof(src), dst, sizeof(dst));
        printf("[+] Including RO: %s -> %s\n", src, dst);
        if (copy_tree_to_rootfs(src, rootfs_dir, dst, false, 0) < 0) return EXIT_FAILURE;
        sl_add(&pol.ro_paths, dst);
    }
    for (size_t i = 0; i < inc_rx.count; i++) {
        char src[PATH_MAX], dst[PATH_MAX];
        parse_src_dst(inc_rx.items[i], src, sizeof(src), dst, sizeof(dst));
        printf("[+] Including RX: %s -> %s\n", src, dst);
        if (copy_tree_to_rootfs(src, rootfs_dir, dst, true, 0) < 0) return EXIT_FAILURE;
        sl_add(&pol.rx_paths, dst);
        if (drain_elf_queue_into_rootfs(rootfs_dir, &pol) < 0) return EXIT_FAILURE;
    }
    for (size_t i = 0; i < inc_rw.count; i++) {
        char rw_dir[PATH_MAX * 2 + 32];
        if (path_concat(rw_dir, sizeof(rw_dir), rootfs_dir, inc_rw.items[i]) < 0 ||
            mkdir_p(rw_dir, 01777) < 0 || chmod(rw_dir, 01777) < 0) {
            return EXIT_FAILURE;
        }
        sl_add(&pol.rw_paths, inc_rw.items[i]);
    }

    if (do_learn) {
        int l_argc   = 0;
        char **l_arg = NULL;
        if (is_bundle && dash_idx >= 0) {
            l_argc = argc - (dash_idx + 1);
            l_arg  = &argv[dash_idx + 1];
        } else if (is_learn && dash_idx >= 0) {
            l_argc = argc - (dash_idx + 2);
            l_arg  = &argv[dash_idx + 2];
        }
        if (run_learner(aegis_src, ratchet_src, rootfs_dir, &pol, learn_files,
                        target_binary, l_argc, l_arg) < 0) {
            return EXIT_FAILURE;
        }
    }

    if (save_policy(policy_file, &pol) < 0) return EXIT_FAILURE;
    printf("[+] Saved policy: %s (%zu RX, %zu RO, %zu RW | P1: code=%d exec=%d tls=%d | P2: listen=%d open=%d net=%d fork=%d)\n",
           policy_file, pol.rx_paths.count, pol.ro_paths.count, pol.rw_paths.count,
           pol.freeze_code ? 1 : 0, pol.freeze_execve ? 1 : 0, pol.freeze_tls ? 1 : 0,
           pol.p2_on_listen ? 1 : 0, pol.p2_freeze_open ? 1 : 0,
           pol.p2_freeze_net ? 1 : 0, pol.p2_freeze_fork ? 1 : 0);

    if (is_bundle) {
        write_dockerfile(rootfs_dir, target_binary);
    }

    printf("\n[SUCCESS] Fortress RootFS ready at '%s'!\n", rootfs_dir);
    return EXIT_SUCCESS;
}
