#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <pthread.h>

#ifndef __NR_memfd_secret
#if defined(__x86_64__)
#define __NR_memfd_secret 447
#elif defined(__aarch64__)
#define __NR_memfd_secret 279
#else
#define __NR_memfd_secret 447
#endif
#endif

#define AEGIS_VAULT_FD        103
#define AEGIS_SECRET_PREFIX   "/run/aegis/ephemeral/"
#define AEGIS_MAX_SECRETS     32
#define AEGIS_NAME_MAX        64
#define AEGIS_VAL_MAX         256
#define AEGIS_ARENA_SIZE      4096

/* Vault IPC Commands */
#define VAULT_CMD_GET_EPHEMERAL 1
#define VAULT_CMD_SEAL_PHASE2   2
#define VAULT_CMD_CRYPTO_SIGN   3

/* Vault Status Codes */
#define VAULT_STATUS_OK         0
#define VAULT_STATUS_SEALED     1
#define VAULT_STATUS_NOTFOUND   2
#define VAULT_STATUS_ERR        3

struct vault_req {
    uint32_t cmd;
    char name[AEGIS_NAME_MAX];
    char payload[AEGIS_VAL_MAX];
};

struct vault_resp {
    uint32_t status;
    char data[AEGIS_VAL_MAX];
};

/* Helper: Allocate page-aligned secret memory via memfd_secret(2) with Tier-2 fallback */
static void *alloc_secret_region(size_t size, int *out_fd, const char **out_tier) {
    int fd = (int)syscall(__NR_memfd_secret, O_CLOEXEC);
    if (fd >= 0) {
        if (ftruncate(fd, (off_t)size) == 0) {
            void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (p != MAP_FAILED) {
                *out_fd = fd;
                if (out_tier) *out_tier = "TIER-1: memfd_secret(2) [Kernel Direct-Map Unmapped]";
                return p;
            }
        }
        close(fd);
    }
    /* Tier-2 Fallback for containers/kernels without secretmem.enable=1 */
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    (void)mlock(p, size);
#ifdef MADV_DONTDUMP
    (void)madvise(p, size, MADV_DONTDUMP);
#endif
#ifdef MADV_WIPEONFORK
    (void)madvise(p, size, MADV_WIPEONFORK);
#endif
    *out_fd = -1;
    if (out_tier) *out_tier = "TIER-2: mlock+MADV_DONTDUMP [Locked Private RAM]";
    return p;
}

/* Keyed DJB2-XOR-FNV256 MAC for zero-dependency Keyless Crypto-Oracle demonstration */
__attribute__((unused)) static void compute_keyed_mac(const char *key, const char *msg, char *out_hex, size_t out_sz) {
    uint64_t h1 = 0xcbf29ce484222325ULL;
    uint64_t h2 = 0x84222325cbf29ce4ULL;
    uint64_t h3 = 0x100000001b3ULL;
    uint64_t h4 = 0x9e3779b97f4a7c15ULL;

    for (size_t i = 0; key[i] != '\0'; i++) {
        uint64_t b = (uint8_t)key[i];
        h1 = (h1 ^ b) * 0x100000001b3ULL;
        h2 = ((h2 << 5) + h2) ^ (b * 0x9e3779b97f4a7c15ULL);
        h3 = (h3 ^ (b + i)) * 0xcbf29ce484222325ULL;
        h4 = (h4 << 7) ^ (h1 + b);
    }
    for (size_t i = 0; msg[i] != '\0'; i++) {
        uint64_t b = (uint8_t)msg[i];
        h1 = (h1 ^ b) * 0x100000001b3ULL;
        h2 = (h2 ^ (b + h1)) * 0x9e3779b97f4a7c15ULL;
        h3 = (h3 ^ (b ^ h2)) * 0xcbf29ce484222325ULL;
        h4 = (h4 ^ (b + h3)) * 0x100000001b3ULL;
    }
    snprintf(out_hex, out_sz, "%016llx%016llx%016llx%016llx",
             (unsigned long long)h1, (unsigned long long)h2,
             (unsigned long long)h3, (unsigned long long)h4);
}

#ifndef AEGIS_PRIVSEP_SHIM
/* =========================================================================
 * PART 1: aegis-privsep (OpenBSD-style Privilege-Separated Vault Supervisor)
 * ========================================================================= */

struct secret_entry {
    bool is_keyless;
    char name[AEGIS_NAME_MAX];
    char value[AEGIS_VAL_MAX];
};

struct vault_storage {
    size_t count;
    bool phase2_sealed;
    struct secret_entry entries[AEGIS_MAX_SECRETS];
};

static int load_secrets_into_vault(const char *path, struct vault_storage *vs) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;

        char type[32] = {0}, name[AEGIS_NAME_MAX] = {0}, val[AEGIS_VAL_MAX] = {0};
        if (sscanf(p, "%31s %63s %255[^\r\n]", type, name, val) == 3) {
            if (vs->count >= AEGIS_MAX_SECRETS) break;
            struct secret_entry *e = &vs->entries[vs->count++];
            e->is_keyless = (strcmp(type, "KEYLESS") == 0);
            snprintf(e->name, sizeof(e->name), "%s", name);
            snprintf(e->value, sizeof(e->value), "%s", val);
        }
    }
    /* Scrub stack buffer before closing */
    explicit_bzero(line, sizeof(line));
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    int sep_idx = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            sep_idx = i;
            break;
        }
    }
    if (sep_idx < 2 || sep_idx + 1 >= argc) {
        fprintf(stderr, "Usage: %s <secrets.conf> -- <target_prog> [args...]\n", argv[0]);
        return 1;
    }

    const char *conf_path = argv[1];
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) {
        perror("[aegis-privsep] socketpair");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("[aegis-privsep] fork");
        return 1;
    }

    if (pid == 0) {
        /* Child: Target Worker Process */
        close(sv[0]);
        if (sv[1] != AEGIS_VAULT_FD) {
            if (dup2(sv[1], AEGIS_VAULT_FD) < 0) {
                perror("[aegis-privsep] dup2");
                _exit(1);
            }
            close(sv[1]);
        }
        /* Ensure FD 103 stays open across execve into aegis-init / target */
        int flags = fcntl(AEGIS_VAULT_FD, F_GETFD);
        if (flags >= 0) (void)fcntl(AEGIS_VAULT_FD, F_SETFD, flags & ~FD_CLOEXEC);

        execvp(argv[sep_idx + 1], &argv[sep_idx + 1]);
        perror("[aegis-privsep] execvp");
        _exit(127);
    }

    /* Parent: Privilege-Separated Vault Process */
    close(sv[1]);
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    int secret_fd = -1;
    const char *tier_desc = NULL;
    size_t vault_sz = sizeof(struct vault_storage);
    size_t page_sz = (vault_sz + 4095) & ~4095ULL;
    struct vault_storage *vs = (struct vault_storage *)alloc_secret_region(page_sz, &secret_fd, &tier_desc);
    if (!vs) {
        fprintf(stderr, "[aegis-privsep] Failed to allocate secret vault memory\n");
        kill(pid, SIGKILL);
        return 1;
    }
    memset(vs, 0, page_sz);

    if (load_secrets_into_vault(conf_path, vs) < 0) {
        fprintf(stderr, "[aegis-privsep] Failed to load secrets from %.140s\n", conf_path);
        kill(pid, SIGKILL);
        return 1;
    }

    fprintf(stderr, "[aegis-privsep] Vault active (%s) | Loaded %zu secrets for worker PID %d\n",
            tier_desc, vs->count, pid);

    /* Serve requests over SOCK_SEQPACKET until worker exits */
    struct vault_req req;
    struct vault_resp resp;
    while (1) {
        ssize_t n = recv(sv[0], &req, sizeof(req), 0);
        if (n <= 0) break;

        memset(&resp, 0, sizeof(resp));
        if (req.cmd == VAULT_CMD_SEAL_PHASE2) {
            vs->phase2_sealed = true;
            /* Evaporate EPHEMERAL secrets even from the Vault upon Phase 2 transition! */
            for (size_t i = 0; i < vs->count; i++) {
                if (!vs->entries[i].is_keyless) {
                    explicit_bzero(vs->entries[i].value, sizeof(vs->entries[i].value));
                }
            }
            resp.status = VAULT_STATUS_OK;
            fprintf(stderr, "[aegis-privsep] PHASE-2 HARDWARE SEAL engaged! Ephemeral secrets wiped; Keyless Crypto-Oracle only.\n");
        } else if (req.cmd == VAULT_CMD_GET_EPHEMERAL) {
            if (vs->phase2_sealed) {
                resp.status = VAULT_STATUS_SEALED;
            } else {
                resp.status = VAULT_STATUS_NOTFOUND;
                for (size_t i = 0; i < vs->count; i++) {
                    if (!vs->entries[i].is_keyless && strcmp(vs->entries[i].name, req.name) == 0) {
                        resp.status = VAULT_STATUS_OK;
                        snprintf(resp.data, sizeof(resp.data), "%s", vs->entries[i].value);
                        break;
                    }
                }
            }
        } else if (req.cmd == VAULT_CMD_CRYPTO_SIGN) {
            resp.status = VAULT_STATUS_NOTFOUND;
            for (size_t i = 0; i < vs->count; i++) {
                if (vs->entries[i].is_keyless && strcmp(vs->entries[i].name, req.name) == 0) {
                    resp.status = VAULT_STATUS_OK;
                    compute_keyed_mac(vs->entries[i].value, req.payload, resp.data, sizeof(resp.data));
                    break;
                }
            }
        } else {
            resp.status = VAULT_STATUS_ERR;
        }
        if (send(sv[0], &resp, sizeof(resp), MSG_NOSIGNAL) < 0) break;
        explicit_bzero(&req, sizeof(req));
        explicit_bzero(&resp, sizeof(resp));
    }

    /* Final cleanup: evaporate Vault memfd_secret region */
    explicit_bzero(vs, page_sz);
    munmap(vs, page_sz);
    if (secret_fd >= 0) close(secret_fd);
    close(sv[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

#else
/* =========================================================================
 * PART 2: libaegis_privsep.so (Worker Preload Shim & Phase-2 Evaporator)
 * ========================================================================= */

#define MAX_VFD          8
#define MAX_TAINT_BUFS   64
#define VFD_BASE         900

struct ephemeral_arena {
    char slots[MAX_VFD][AEGIS_VAL_MAX];
    size_t used;
};

struct vfd_slot {
    bool active;
    size_t slot_idx;
    size_t offset;
    size_t len;
};

struct taint_buf {
    void *ptr;
    size_t len;
    bool active;
};

static pthread_mutex_t g_privsep_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ephemeral_arena *g_arena = NULL;
static int g_arena_fd = -1;
static bool g_phase2_evaporated = false;
static struct vfd_slot g_vfds[MAX_VFD];
static struct taint_buf g_taints[MAX_TAINT_BUFS];

static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static FILE *(*real_fopen)(const char *, const char *) = NULL;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
static int (*real_close)(int) = NULL;
static int (*real_listen)(int, int) = NULL;

__attribute__((constructor))
static void init_privsep_shim(void) {
    real_open   = dlsym(RTLD_NEXT, "open");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_fopen  = dlsym(RTLD_NEXT, "fopen");
    real_read   = dlsym(RTLD_NEXT, "read");
    real_close  = dlsym(RTLD_NEXT, "close");
    real_listen = dlsym(RTLD_NEXT, "listen");

    /* Prevent child processes from inheriting Vault FD 103 */
    int flags = fcntl(AEGIS_VAULT_FD, F_GETFD);
    if (flags >= 0) (void)fcntl(AEGIS_VAULT_FD, F_SETFD, flags | FD_CLOEXEC);
}

static void record_taint_buffer(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
    for (int i = 0; i < MAX_TAINT_BUFS; i++) {
        if (!g_taints[i].active || g_taints[i].ptr == ptr) {
            g_taints[i].ptr = ptr;
            g_taints[i].len = len;
            g_taints[i].active = true;
            return;
        }
    }
}

/* Verify via /proc/self/maps that [addr, addr+len) is currently in a writable VMA */
static bool is_writable_vma(uintptr_t addr, size_t len) {
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE *fp = real_fopen("/proc/self/maps", "r");
    if (!fp) return false;

    char line[512];
    bool ok = false;
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3) {
            if (addr >= start && (addr + len) <= end && perms[1] == 'w') {
                ok = true;
                break;
            }
        }
    }
    fclose(fp);
    return ok;
}

static int fetch_ephemeral_slot(const char *secret_name, size_t *out_slot) {
    if (g_phase2_evaporated) {
        errno = EACCES;
        return -1;
    }
    if (!g_arena) {
        const char *tier = NULL;
        g_arena = (struct ephemeral_arena *)alloc_secret_region(AEGIS_ARENA_SIZE, &g_arena_fd, &tier);
        if (!g_arena) {
            errno = ENOMEM;
            return -1;
        }
        memset(g_arena, 0, AEGIS_ARENA_SIZE);
    }
    if (g_arena->used >= MAX_VFD) {
        errno = ENOMEM;
        return -1;
    }

    struct vault_req req;
    struct vault_resp resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.cmd = VAULT_CMD_GET_EPHEMERAL;
    snprintf(req.name, sizeof(req.name), "%s", secret_name);

    if (send(AEGIS_VAULT_FD, &req, sizeof(req), MSG_NOSIGNAL) < 0 ||
        recv(AEGIS_VAULT_FD, &resp, sizeof(resp), 0) <= 0) {
        errno = EIO;
        return -1;
    }

    if (resp.status == VAULT_STATUS_SEALED) {
        explicit_bzero(&resp, sizeof(resp));
        errno = EACCES;
        return -1;
    }
    if (resp.status != VAULT_STATUS_OK) {
        explicit_bzero(&resp, sizeof(resp));
        errno = ENOENT;
        return -1;
    }

    size_t idx = g_arena->used++;
    snprintf(g_arena->slots[idx], AEGIS_VAL_MAX, "%s", resp.data);
    explicit_bzero(&resp, sizeof(resp));
    *out_slot = idx;
    return 0;
}

static int open_virtual_secret(const char *secret_name) {
    size_t slot_idx = 0;
    if (fetch_ephemeral_slot(secret_name, &slot_idx) < 0) return -1;

    for (int i = 0; i < MAX_VFD; i++) {
        if (!g_vfds[i].active) {
            g_vfds[i].active = true;
            g_vfds[i].slot_idx = slot_idx;
            g_vfds[i].offset = 0;
            g_vfds[i].len = strlen(g_arena->slots[slot_idx]);
            return VFD_BASE + i;
        }
    }
    errno = EMFILE;
    return -1;
}

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (strncmp(pathname, AEGIS_SECRET_PREFIX, strlen(AEGIS_SECRET_PREFIX)) == 0) {
        pthread_mutex_lock(&g_privsep_lock);
        int vfd = open_virtual_secret(pathname + strlen(AEGIS_SECRET_PREFIX));
        pthread_mutex_unlock(&g_privsep_lock);
        return vfd;
    }
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    return real_open(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (strncmp(pathname, AEGIS_SECRET_PREFIX, strlen(AEGIS_SECRET_PREFIX)) == 0) {
        pthread_mutex_lock(&g_privsep_lock);
        int vfd = open_virtual_secret(pathname + strlen(AEGIS_SECRET_PREFIX));
        pthread_mutex_unlock(&g_privsep_lock);
        return vfd;
    }
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");
    return real_openat(dirfd, pathname, flags, mode);
}

FILE *fopen(const char *pathname, const char *mode) {
    if (strncmp(pathname, AEGIS_SECRET_PREFIX, strlen(AEGIS_SECRET_PREFIX)) == 0) {
        pthread_mutex_lock(&g_privsep_lock);
        size_t slot_idx = 0;
        if (fetch_ephemeral_slot(pathname + strlen(AEGIS_SECRET_PREFIX), &slot_idx) < 0) {
            pthread_mutex_unlock(&g_privsep_lock);
            return NULL;
        }
        char *buf = g_arena->slots[slot_idx];
        size_t len = strlen(buf);
        FILE *fp = fmemopen(buf, len, "r");
        if (fp) setvbuf(fp, NULL, _IONBF, 0); /* Disable glibc internal 4KB malloc copy buffer! */
        pthread_mutex_unlock(&g_privsep_lock);
        return fp;
    }
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    return real_fopen(pathname, mode);
}

ssize_t read(int fd, void *buf, size_t count) {
    if (fd >= VFD_BASE && fd < VFD_BASE + MAX_VFD) {
        pthread_mutex_lock(&g_privsep_lock);
        int idx = fd - VFD_BASE;
        if (!g_vfds[idx].active || g_phase2_evaporated || !g_arena) {
            pthread_mutex_unlock(&g_privsep_lock);
            errno = EBADF;
            return -1;
        }
        size_t avail = g_vfds[idx].len - g_vfds[idx].offset;
        size_t to_copy = (count < avail) ? count : avail;
        if (to_copy > 0 && buf) {
            memcpy(buf, g_arena->slots[g_vfds[idx].slot_idx] + g_vfds[idx].offset, to_copy);
            g_vfds[idx].offset += to_copy;
            /* Track caller's destination buffer for Phase-2 evaporation */
            record_taint_buffer(buf, to_copy);
        }
        pthread_mutex_unlock(&g_privsep_lock);
        return (ssize_t)to_copy;
    }
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    return real_read(fd, buf, count);
}

int close(int fd) {
    if (fd >= VFD_BASE && fd < VFD_BASE + MAX_VFD) {
        pthread_mutex_lock(&g_privsep_lock);
        int idx = fd - VFD_BASE;
        if (!g_vfds[idx].active) {
            pthread_mutex_unlock(&g_privsep_lock);
            errno = EBADF;
            return -1;
        }
        if (g_arena) {
            explicit_bzero(g_arena->slots[g_vfds[idx].slot_idx], AEGIS_VAL_MAX);
        }
        g_vfds[idx].active = false;
        pthread_mutex_unlock(&g_privsep_lock);
        return 0;
    }
    if (!real_close) real_close = dlsym(RTLD_NEXT, "close");
    return real_close(fd);
}

/* Scrub any SECRET / KEY / TOKEN / PASS environment variables in-place on the stack */
static void scrub_secret_environ(void) {
    extern char **environ;
    if (!environ) return;
    for (char **env = environ; *env != NULL; env++) {
        if (strstr(*env, "SECRET") || strstr(*env, "KEY") ||
            strstr(*env, "TOKEN")  || strstr(*env, "PASS")) {
            char *eq = strchr(*env, '=');
            if (eq && *(eq + 1) != '\0') {
                explicit_bzero(eq + 1, strlen(eq + 1));
            }
        }
    }
}

/* Phase 1 -> Phase 2 Transition Hook: Evaporate all secret memory before network loop */
int listen(int sockfd, int backlog) {
    pthread_mutex_lock(&g_privsep_lock);
    if (!g_phase2_evaporated) {
        g_phase2_evaporated = true;

        /* 1. Zero-wipe all taint-tracked destination buffers in worker RAM */
        for (int i = 0; i < MAX_TAINT_BUFS; i++) {
            if (g_taints[i].active && g_taints[i].ptr) {
                if (is_writable_vma((uintptr_t)g_taints[i].ptr, g_taints[i].len)) {
                    explicit_bzero(g_taints[i].ptr, g_taints[i].len);
                }
                g_taints[i].active = false;
            }
        }

        /* 2. Evaporate memfd_secret Ephemeral Arena from worker page tables */
        if (g_arena) {
            explicit_bzero(g_arena, AEGIS_ARENA_SIZE);
            munmap(g_arena, AEGIS_ARENA_SIZE);
            g_arena = NULL;
        }
        if (g_arena_fd >= 0) {
            if (!real_close) real_close = dlsym(RTLD_NEXT, "close");
            real_close(g_arena_fd);
            g_arena_fd = -1;
        }

        /* 3. Scrub secret environment variables in-place */
        scrub_secret_environ();

        /* 4. Engage Hardware Seal on the Vault Supervisor */
        struct vault_req req;
        struct vault_resp resp;
        memset(&req, 0, sizeof(req));
        req.cmd = VAULT_CMD_SEAL_PHASE2;
        if (send(AEGIS_VAULT_FD, &req, sizeof(req), MSG_NOSIGNAL) > 0) {
            (void)recv(AEGIS_VAULT_FD, &resp, sizeof(resp), 0);
        }
        fprintf(stderr, "[libaegis_privsep] Phase 1->2 Memory Evaporation complete (Arena unmapped, Taint buffers zeroed).\n");
    }
    pthread_mutex_unlock(&g_privsep_lock);

    if (!real_listen) real_listen = dlsym(RTLD_NEXT, "listen");
    return real_listen(sockfd, backlog);
}

/* Public API for Keyless Crypto-Oracle Signing over FD 103 (0 key bytes in worker!) */
int aegis_privsep_sign(const char *key_name, const char *message, char *out_sig, size_t out_sz) {
    if (!key_name || !message || !out_sig || out_sz == 0) return -1;
    struct vault_req req;
    struct vault_resp resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.cmd = VAULT_CMD_CRYPTO_SIGN;
    snprintf(req.name, sizeof(req.name), "%s", key_name);
    snprintf(req.payload, sizeof(req.payload), "%s", message);

    pthread_mutex_lock(&g_privsep_lock);
    ssize_t s = send(AEGIS_VAULT_FD, &req, sizeof(req), MSG_NOSIGNAL);
    ssize_t r = (s > 0) ? recv(AEGIS_VAULT_FD, &resp, sizeof(resp), 0) : -1;
    pthread_mutex_unlock(&g_privsep_lock);

    if (r <= 0 || resp.status != VAULT_STATUS_OK) return -1;
    snprintf(out_sig, out_sz, "%s", resp.data);
    explicit_bzero(&resp, sizeof(resp));
    return 0;
}
#endif
