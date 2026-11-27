---

## 🛡️ Module 6: `aegis-privsep` & `libaegis_privsep.so` (Automated OpenBSD `privsep` & `memfd_secret` Evaporation)

`aegis-privsep` protects sensitive credentials (`.env`, DB passwords) and long-term cryptographic keys (TLS/API signing keys) against Heartbleed-style arbitrary memory disclosure, LFI, and `/proc/<pid>/mem` dumps without recompiling your application.

### 1. Build

```bash
make aegis-privsep libaegis_privsep.so
