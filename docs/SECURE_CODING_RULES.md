# OPTIGA™ Trust M Host Library — Secure Coding Rules

These rules apply to all C code in this repository (`src/`, `include/`, `extras/pal/`,
`examples/`, `tests/`). They build on SEI CERT C, MISRA C:2012 (the code is
checked with PC-lint; see the `// lint --e{...}` annotations) and the CWE Top 25, and they support
IEC 62443-4-1 secure development and EU Cyber Resilience Act obligations for
products that integrate this library.

Reviewers cite rules by ID (for example `SC-MEM-02`).

## Memory and buffers

| ID | Rule |
|----|------|
| SC-MEM-01 | Every length that comes from outside the current function (the I2C/UART bus, an OPTIGA response, a record header, a caller argument) must be checked against both the source and the destination buffer size **before** any copy, index, or pointer arithmetic. |
| SC-MEM-02 | Size checks must cover the full number of bytes written, including padding, headers, tags, and terminators. |
| SC-MEM-03 | Length arithmetic must not wrap. Use `uint32_t` for sums, check each addition, and never truncate a length to `uint8_t`/`uint16_t` without a range check. |
| SC-MEM-04 | In-out length parameters (`uint32_t *len`) hold the buffer capacity on entry and the produced length on exit; check the capacity before writing and set it to 0 on error. |
| SC-MEM-05 | Use `pal_os_memcpy` / `pal_os_memset`; don't call libc directly in `src/`. Never pass overlapping buffers to `pal_os_memcpy`. |
| SC-MEM-06 | No dynamic allocation in `src/`. Stack buffers larger than 256 bytes need a comment explaining the size; target MCUs have small stacks. |

## Cryptography and secrets

| ID | Rule |
|----|------|
| SC-CRY-01 | Compare MACs, tags, signatures, and secrets in constant time. `memcmp` and early-exit loops are forbidden for secret data. |
| SC-CRY-02 | Zeroize keys, shared secrets, plaintext, and session state with a memset that the compiler can't optimize away, on **all** exit paths including errors. |
| SC-CRY-03 | Generate IVs, nonces, and challenges with `optiga_crypt_random(OPTIGA_RNG_TYPE_TRNG, ...)` unless the mode explicitly requires a counter (CTR/CCM nonce) and uniqueness is proven. CBC IVs must be unpredictable. Never reuse a nonce under the same key. |
| SC-CRY-04 | Use encrypt-then-MAC. The MAC must cover every field that influences interpretation: header, version, length, sequence number, IV, and ciphertext. Verify the MAC **before** decrypting or acting on the data. |
| SC-CRY-05 | Authentication failures must not leak which step failed (padding vs MAC vs length). Return one generic error and release no plaintext. |
| SC-CRY-06 | Replay counters must reject `<=` the last accepted value and must be authenticated. |
| SC-CRY-07 | No new code may use ECB for more than one block, SHA-1, RSA < 2048, ECC < 256, or PKCS#1 v1.5 encryption. Existing support for these is legacy only. |
| SC-CRY-08 | Never log or print secrets, keys, shared secrets, or plaintext, even under `OPTIGA_LIB_ENABLE_LOGGING`. |
| SC-CRY-09 | OID metadata must follow least privilege. Don't widen access conditions (`Always`, `0x00`) on key or secret objects without justification. Lifecycle state (LcsO) changes are irreversible and must be explicit. |

## Error handling and control flow

| ID | Rule |
|----|------|
| SC-ERR-01 | Check every `optiga_*` and `pal_*` return value. Use the `do { ... } while (FALSE);` + `break` pattern, and make the error path release instances, locks, and timers. |
| SC-ERR-02 | Initialize return-status variables to an error value, never to success. |
| SC-ERR-03 | Security decisions (signature valid, MAC equal, access allowed) must not rest on a single comparison of a value an attacker can glitch. Prefer redundant checks and non-trivial success constants over `TRUE`/`0` (fault-injection hardening). |
| SC-ERR-04 | An asynchronous callback must not be assumed complete until `optiga_lib_status` leaves `OPTIGA_LIB_BUSY`. Busy-wait loops on target code need a timeout. |

## Concurrency and instances

| ID | Rule |
|----|------|
| SC-CON-01 | Respect `instance_state` (`OPTIGA_LIB_INSTANCE_BUSY`). Shared state touched from callbacks must be `volatile` and protected by `pal_os_lock`. |
| SC-CON-02 | Code in `extras/pal/` must be safe to call from the event/timer context it runs in. No blocking calls in ISR context. |

## API, configuration and compliance

| ID | Rule |
|----|------|
| SC-API-01 | Changes to public headers (`include/*.h`) must keep the ABI or be called out in `CHANGELOG.md`, keep Doxygen `\param` and `\retval` blocks accurate, and keep `LIBRARY_EXPORTS` and `extern "C"` guards. |
| SC-API-02 | Defaults in `optiga_lib_config*.h` must not weaken security (for example lowering `OPTIGA_COMMS_DEFAULT_PROTECTION_LEVEL` or enabling verbose logging by default). |
| SC-LIC-01 | Every new source file carries an `SPDX-FileCopyrightText` and `SPDX-License-Identifier` header, or is covered by `.reuse/dep5` (REUSE compliance). |
