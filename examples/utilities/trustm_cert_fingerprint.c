/**
 * SPDX-FileCopyrightText: 2026 Infineon Technologies AG
 * SPDX-License-Identifier: MIT
 *
 * \author Infineon Technologies AG
 *
 * \file trustm_cert_fingerprint.c
 *
 * \brief   This file implements computing, formatting and pinning the SHA-256 fingerprint of a
 *          certificate stored in OPTIGA Trust M.
 *
 * \ingroup grOptigaExample
 *
 * @{
 */

#include "trustm_cert_fingerprint.h"

#include "optiga_crypt.h"
#include "optiga_util.h"
#include "pal_os_lock.h"
#include "pal_os_memory.h"
#include "pal_os_timer.h"

#ifdef OPTIGA_CRYPT_HASH_ENABLED

/// Tag of the TLS identity format used for certificates in OPTIGA data objects
#define TRUSTM_CERT_TLS_IDENTITY_TAG (0xC0)
/// TLS identity header: tag (1) | total length (2) | chain length (3) | certificate length (3)
#define TRUSTM_CERT_TLS_IDENTITY_HEADER_LENGTH (9U)
/// Maximum size of a certificate data object
#define TRUSTM_CERT_MAX_LENGTH (1728U)

/**
 * State of the fingerprint operation in progress. It is static so that an OPTIGA operation that
 * completes late (after a timeout) only writes to memory owned by this module, never to a
 * caller's buffer or stack. Access is serialized through the busy flag.
 */
typedef struct trustm_cert_fingerprint_ctx {
    /// Completion status written by the OPTIGA callback
    volatile optiga_lib_status_t status;
    /// Certificate read from OPTIGA
    uint8_t cert[TRUSTM_CERT_MAX_LENGTH];
    /// Certificate length, updated by OPTIGA when the read completes
    uint16_t cert_length;
    /// Hash input descriptor, read by OPTIGA while hashing
    hash_data_from_host_t hash_input;
    /// Digest computed by OPTIGA, copied to the caller on success
    uint8_t digest[TRUSTM_CERT_FINGERPRINT_LENGTH];
    /// Instances kept after a timeout, released by #trustm_cert_fingerprint_reset
    optiga_util_t *abandoned_util;
    optiga_crypt_t *abandoned_crypt;
} trustm_cert_fingerprint_ctx_t;

static trustm_cert_fingerprint_ctx_t trustm_cert_fingerprint_ctx;
/// TRUE while a call is in progress, or after a timeout until #trustm_cert_fingerprint_reset
static volatile bool_t trustm_cert_fingerprint_busy = FALSE;

static void trustm_cert_fingerprint_callback(void *context, optiga_lib_status_t return_status) {
    pal_os_lock_enter_critical_section();
    ((trustm_cert_fingerprint_ctx_t *)context)->status = return_status;
    pal_os_lock_exit_critical_section();
}

static void trustm_cert_fingerprint_set_status(optiga_lib_status_t status) {
    pal_os_lock_enter_critical_section();
    trustm_cert_fingerprint_ctx.status = status;
    pal_os_lock_exit_critical_section();
}

static optiga_lib_status_t trustm_cert_fingerprint_get_status(void) {
    optiga_lib_status_t status;

    pal_os_lock_enter_critical_section();
    status = trustm_cert_fingerprint_ctx.status;
    pal_os_lock_exit_critical_section();
    return status;
}

/**
 * Atomically claim the utility. Returns TRUE if the caller now owns it.
 */
static bool_t trustm_cert_fingerprint_acquire(void) {
    bool_t acquired = FALSE;

    pal_os_lock_enter_critical_section();
    if (FALSE == trustm_cert_fingerprint_busy) {
        trustm_cert_fingerprint_busy = TRUE;
        acquired = TRUE;
    }
    pal_os_lock_exit_critical_section();
    return acquired;
}

static void trustm_cert_fingerprint_release(void) {
    pal_os_lock_enter_critical_section();
    trustm_cert_fingerprint_busy = FALSE;
    pal_os_lock_exit_critical_section();
}

/**
 * Wait for an asynchronous OPTIGA operation started with api_status and return its result.
 * Sets *timed_out when the operation did not complete within TRUSTM_CERT_FINGERPRINT_TIMEOUT_MS.
 */
static optiga_lib_status_t
trustm_cert_fingerprint_wait(optiga_lib_status_t api_status, bool_t *timed_out) {
    uint32_t start_time;

    if (OPTIGA_LIB_SUCCESS != api_status) {
        return api_status;
    }
    start_time = pal_os_timer_get_time_in_milliseconds();
    while (OPTIGA_LIB_BUSY == trustm_cert_fingerprint_get_status()) {
        // Unsigned subtraction keeps the comparison correct across timer wrap-around
        if ((pal_os_timer_get_time_in_milliseconds() - start_time)
            >= TRUSTM_CERT_FINGERPRINT_TIMEOUT_MS) {
            *timed_out = TRUE;
            return OPTIGA_UTIL_ERROR;
        }
    }
    return trustm_cert_fingerprint_get_status();
}

optiga_lib_status_t trustm_cert_fingerprint_reset(void) {
    trustm_cert_fingerprint_ctx_t *ctx = &trustm_cert_fingerprint_ctx;
    optiga_lib_status_t return_status = OPTIGA_LIB_SUCCESS;

    // OPTIGA has been re-initialized, so the abandoned operation can no longer complete
    if (NULL != ctx->abandoned_crypt) {
        if (OPTIGA_LIB_SUCCESS != optiga_crypt_destroy(ctx->abandoned_crypt)) {
            return OPTIGA_UTIL_ERROR;
        }
        ctx->abandoned_crypt = NULL;
    }
    if (NULL != ctx->abandoned_util) {
        if (OPTIGA_LIB_SUCCESS != optiga_util_destroy(ctx->abandoned_util)) {
            return OPTIGA_UTIL_ERROR;
        }
        ctx->abandoned_util = NULL;
    }
    trustm_cert_fingerprint_release();
    return return_status;
}

optiga_lib_status_t trustm_get_cert_fingerprint(uint16_t cert_oid, uint8_t *fingerprint) {
    trustm_cert_fingerprint_ctx_t *ctx = &trustm_cert_fingerprint_ctx;
    uint32_t der_length;
    bool_t timed_out = FALSE;
    optiga_util_t *me_util = NULL;
    optiga_crypt_t *me_crypt = NULL;
    optiga_lib_status_t return_status = OPTIGA_UTIL_ERROR;

    if (NULL == fingerprint) {
        return OPTIGA_UTIL_ERROR;
    }
    if (FALSE == trustm_cert_fingerprint_acquire()) {
        return OPTIGA_UTIL_ERROR_INSTANCE_IN_USE;
    }

    do {
        me_util = optiga_util_create(0, trustm_cert_fingerprint_callback, ctx);
        me_crypt = optiga_crypt_create(0, trustm_cert_fingerprint_callback, ctx);
        if ((NULL == me_util) || (NULL == me_crypt)) {
            break;
        }

        // Read the certificate
        ctx->cert_length = sizeof(ctx->cert);
        trustm_cert_fingerprint_set_status(OPTIGA_LIB_BUSY);
        return_status = trustm_cert_fingerprint_wait(
            optiga_util_read_data(me_util, cert_oid, 0, ctx->cert, &ctx->cert_length),
            &timed_out
        );
        if (OPTIGA_LIB_SUCCESS != return_status) {
            break;
        }

        // Remove the TLS identity header if present
        if ((ctx->cert_length > TRUSTM_CERT_TLS_IDENTITY_HEADER_LENGTH)
            && (TRUSTM_CERT_TLS_IDENTITY_TAG == ctx->cert[0])) {
            der_length =
                ((uint32_t)ctx->cert[6] << 16) | ((uint32_t)ctx->cert[7] << 8) | ctx->cert[8];
            if ((0 == der_length)
                || (der_length
                    > (uint32_t)(ctx->cert_length - TRUSTM_CERT_TLS_IDENTITY_HEADER_LENGTH))) {
                return_status = OPTIGA_UTIL_ERROR;
                break;
            }
            ctx->hash_input.buffer = &ctx->cert[TRUSTM_CERT_TLS_IDENTITY_HEADER_LENGTH];
        } else {
            der_length = ctx->cert_length;
            ctx->hash_input.buffer = ctx->cert;
        }
        ctx->hash_input.length = der_length;

        // Hash the DER certificate on OPTIGA
        trustm_cert_fingerprint_set_status(OPTIGA_LIB_BUSY);
        return_status = trustm_cert_fingerprint_wait(
            optiga_crypt_hash(
                me_crypt,
                OPTIGA_HASH_TYPE_SHA_256,
                OPTIGA_CRYPT_HOST_DATA,
                &ctx->hash_input,
                ctx->digest
            ),
            &timed_out
        );
        if (OPTIGA_LIB_SUCCESS != return_status) {
            break;
        }

        pal_os_memcpy(fingerprint, ctx->digest, TRUSTM_CERT_FINGERPRINT_LENGTH);
    } while (FALSE);

    if (TRUE == timed_out) {
        // The pending operation may still complete and use the instances and ctx buffers.
        // Keep the instances and leave the utility locked until trustm_cert_fingerprint_reset().
        ctx->abandoned_util = me_util;
        ctx->abandoned_crypt = me_crypt;
        return OPTIGA_UTIL_ERROR;
    }

    if (me_crypt) {
        if (OPTIGA_LIB_SUCCESS != optiga_crypt_destroy(me_crypt)) {
            return_status = OPTIGA_UTIL_ERROR;
        }
    }
    if (me_util) {
        if (OPTIGA_LIB_SUCCESS != optiga_util_destroy(me_util)) {
            return_status = OPTIGA_UTIL_ERROR;
        }
    }
    trustm_cert_fingerprint_release();
    return return_status;
}

optiga_lib_status_t
trustm_format_cert_fingerprint(const uint8_t *fingerprint, char *output, uint16_t output_length) {
    static const char hex_digits[] = "0123456789ABCDEF";
    char *p_output = output;
    uint8_t index;

    if ((NULL == fingerprint) || (NULL == output)
        || (output_length < TRUSTM_CERT_FINGERPRINT_STRING_LENGTH)) {
        return OPTIGA_UTIL_ERROR;
    }

    for (index = 0; index < TRUSTM_CERT_FINGERPRINT_LENGTH; index++) {
        *p_output++ = hex_digits[fingerprint[index] >> 4];
        *p_output++ = hex_digits[fingerprint[index] & 0x0F];
        *p_output++ = ':';
    }
    // Replace the trailing separator with the string terminator
    *(p_output - 1) = '\0';

    return OPTIGA_LIB_SUCCESS;
}

optiga_lib_status_t trustm_verify_cert_fingerprint(
    uint16_t cert_oid,
    const uint8_t *expected,
    uint16_t expected_length
) {
    uint8_t fingerprint[TRUSTM_CERT_FINGERPRINT_LENGTH];
    volatile uint8_t forward_diff = 0;
    volatile uint8_t backward_diff = 0;
    uint16_t index;
    optiga_lib_status_t return_status;

    if ((NULL == expected) || (expected_length < TRUSTM_CERT_FINGERPRINT_MIN_PIN_LENGTH)
        || (expected_length > TRUSTM_CERT_FINGERPRINT_LENGTH)) {
        return OPTIGA_UTIL_ERROR;
    }

    return_status = trustm_get_cert_fingerprint(cert_oid, fingerprint);
    if (OPTIGA_LIB_SUCCESS != return_status) {
        return return_status;
    }

    // Compare the pinned fingerprint (or its leading prefix) twice, in opposite directions with
    // independent accumulators, so a single skipped instruction cannot turn a mismatch into a match
    for (index = 0; index < expected_length; index++) {
        forward_diff |= (uint8_t)(fingerprint[index] ^ expected[index]);
    }
    for (index = expected_length; index > 0; index--) {
        backward_diff |= (uint8_t)(fingerprint[index - 1] ^ expected[index - 1]);
    }
    if (0 != forward_diff) {
        return OPTIGA_UTIL_ERROR;
    }
    if (0 != backward_diff) {
        return OPTIGA_UTIL_ERROR;
    }
    return ((0 == forward_diff) && (0 == backward_diff)) ? OPTIGA_LIB_SUCCESS : OPTIGA_UTIL_ERROR;
}

#endif  // OPTIGA_CRYPT_HASH_ENABLED

/**
 * @}
 */
