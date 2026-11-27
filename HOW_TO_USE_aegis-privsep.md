## 🛡️ Module 6: `aegis-privsep` & `libaegis_privsep.so` (Automated OpenBSD `privsep` & `memfd_secret` Evaporation)

`aegis-privsep` protects sensitive credentials (`.env`, DB passwords) and long-term cryptographic keys (TLS/API signing keys) against Heartbleed-style arbitrary memory disclosure, LFI, and `/proc/<pid>/mem` dumps without recompiling your application.

### 1. Build

```bash
make aegis-privsep libaegis_privsep.so
```

### 2. Create a Secrets Configuration (`aegis.secrets`)

Secrets are divided into two strict lifecycle classes:
* **`EPHEMERAL <name> <secret>`**: Exposed via `/run/aegis/ephemeral/<name>` **only during Phase 1 (initialization)**. The moment the server calls `listen()` (Phase 2), the `memfd_secret(2)` arena is wiped (`explicit_bzero`) and unmapped (`munmap`) from the worker's page tables, and all taint-tracked read buffers are zeroed.
* **`KEYLESS <key_id> <master_key>`**: **Never enters the worker process's RAM (0 bytes in worker).** Stored exclusively inside the isolated `aegis-privsep` Vault supervisor's `memfd_secret(2)` memory (`PR_SET_DUMPABLE=0`). The worker requests signatures/MACs over fixed `AF_UNIX SOCK_SEQPACKET` descriptor `FD 103`.

```text
# /etc/aegis.secrets
EPHEMERAL db_boot        AEGIS_DB_BOOT_PASS_2026_ULTRA_SECRET
KEYLESS   tls_master_key PRIVATE_KEY_RSA_PRIME_99887766_HEARTBLEED_TARGET
```

### 3. Run with `aegis-privsep` (Standalone or Chained with `aegis-init`)

```bash
# Chained with aegis-init (automatically chains libaegis_privsep.so + libaegis_ratchet.so when /lib/libaegis_privsep.so exists in RootFS)
./aegis-privsep /etc/aegis.secrets -- /bin/aegis-init /usr/bin/python3 /srv/www/app.py

# Standalone execution with any binary
./aegis-privsep /etc/aegis.secrets -- env LD_PRELOAD=./libaegis_privsep.so ./your_server
```

### 4. Empirical Verification: Simulated Heartbleed Full-RAM Scanner (`test_heartbleed_poc.c`)

```bash
gcc -O2 -Wall -Wextra -o test_heartbleed_poc test_heartbleed_poc.c -ldl

# 1. Baseline (Legacy Unprotected Server) -> Both secrets are leaked from [heap] RAM!
./test_heartbleed_poc --legacy

# 2. Protected by aegis-privsep -> 0 bytes leaked in full-RAM scan while Keyless signing returns 200 OK!
./aegis-privsep /etc/aegis.secrets -- env LD_PRELOAD=./libaegis_privsep.so ./test_heartbleed_poc --hardened
