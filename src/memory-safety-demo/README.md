# Memory-Safety Demo

This directory contains a self-contained demonstration of **memory-corruption attacks and
mitigations** required by the project brief (§Secure Coding — "memory attack prevention:
buffer overflow, use-after-free, integer overflow, format string").

> The two binaries below are intentionally vulnerable / hardened.  They are **never**
> shipped in the production banking image — they exist only as a teaching artefact and
> as a target for the Red/Blue team drill.

## Files

| File | Purpose |
|------|---------|
| `vuln.c`            | Classic `strcpy` buffer overflow + format-string + integer overflow + UAF |
| `hardened.c`        | Same logical function but using safe APIs + bounds checks |
| `Makefile`          | Builds both binaries; hardened build adds ASLR, RELRO, FORTIFY, stack canary |
| `Dockerfile.vuln`   | Vulnerable image (compiled WITHOUT hardening) — for red-team drill |
| `Dockerfile.hardened` | Hardened image (PIE, stack canary, RELRO, FORTIFY_SOURCE=3) |
| `attack.sh`         | Reproducible attack inputs (oversized arg, %x %x %x …, etc.) |
| `verify_hardening.sh` | Uses `checksec` to prove the hardened binary has every mitigation |

## Mitigations demonstrated

| Class | Vulnerable code | Mitigation in hardened build |
|-------|----------------|------------------------------|
| Stack-buffer overflow | `strcpy(buf, argv[1])` | `strncpy_s`/`snprintf` + `-fstack-protector-strong` |
| Format-string | `printf(user)` | `printf("%s", user)` + `-Wformat -Wformat-security` |
| Integer overflow | `n*sizeof(int)` (32-bit wrap) | `__builtin_mul_overflow` check |
| Use-after-free | `free(p); printf("%s", p)` | `free_and_null(&p)` helper |
| Code-injection / ROP | n/a | `-fPIE -pie -Wl,-z,relro -Wl,-z,now` + ASLR |
| Data-execution | n/a | NX bit (default on x86_64) |
| Heap metadata abuse | n/a | glibc `MALLOC_CHECK_=3` + tcache hardening |

## Build & run

```bash
# from project root
docker build -f src/memory-safety-demo/Dockerfile.vuln     -t securebank/vuln:demo     src/memory-safety-demo
docker build -f src/memory-safety-demo/Dockerfile.hardened -t securebank/hardened:demo src/memory-safety-demo

# Attack the vulnerable binary
docker run --rm securebank/vuln:demo bash attack.sh

# Run the hardened binary against the same payload — should refuse / abort safely
docker run --rm securebank/hardened:demo bash attack.sh
```

## Falco runtime detection

When the **vulnerable** container crashes via SIGSEGV/SIGABRT, the rule
`Memory corruption in banking workload` in
[`monitor/falco/rules/securebank.yaml`](../../monitor/falco/rules/securebank.yaml) fires
and a QRadar offense `OFF_MEMORY_CORRUPT` is opened (see
[`monitor/qradar/rules/memory-corruption.aql`](../../monitor/qradar/rules/memory-corruption.aql)).

## Live-demo script

1. Show the source of both files side-by-side (Lead Developer).
2. Run `verify_hardening.sh` inside `securebank/hardened:demo` — prove every mitigation
   is enabled (output of `checksec`).
3. Run `attack.sh` inside `securebank/vuln:demo` — process is killed, Falco event
   appears in the Security Console of the GUI in real time.
4. Run the same `attack.sh` inside `securebank/hardened:demo` — process aborts safely
   via `__stack_chk_fail` / `__fortify_fail`.
