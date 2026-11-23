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

#include <string.h>

#include "optiga_crypt.h"
#include "optiga_util.h"

#ifdef OPTIGA_CRYPT_HASH_ENABLED

/// Tag of the TLS identity format used for certificates in OPTIGA data objects
#define TRUSTM_CERT_TLS_IDENTITY_TAG (0xC0)
/// TLS identity header: tag (1) | total length (2) | chain length (3) | certificate length (3)
#define TRUSTM_CERT_TLS_IDENTITY_HEADER_LENGTH (9U)
/// Maximum size of a certificate data object
#define TRUSTM_CERT_MAX_LENGTH (1728U)

/**
 * Callback when optiga_util_xxxx / optiga_crypt_xxxx operation is completed asynchronously
 */
static volatile optiga_lib_status_t trustm_cert_fingerprint_status;

// lint --e{818} suppress "argument "context" is not used in the sample provided"
static void trustm_cert_fingerprint_callback(void *context, optiga_lib_status_t return_status) {
    trustm_cert_fingerprint_status = return_status;
    if (NULL != context) {
        // callback to upper layer here
    }
}

/**
 * Wait for an asynchronous OPTIGA operation started with api_status and return its result
 */
static optiga_lib_status_t trustm_cert_fingerprint_wait(optiga_lib_status_t api_status) {
    if (OPTIGA_LIB_SUCCESS != api_status) {
        return api_status;
    }
    while (OPTIGA_LIB_BUSY == trustm_cert_fingerprint_status) {
    }
    return trustm_cert_fingerprint_status;
}

optiga_lib_status_t trustm_get_cert_fingerprint(uint16_t cert_oid, uint8_t *fingerprint) {
    // Static to keep the certificate off the stack of small MCUs
    static uint8_t cert[TRUSTM_CERT_MAX_LENGTH];
    uint16_t cert_length = sizeof(cert);
    hash_data_from_host_t hash_input;
    uint32_t der_length;
    optiga_util_t *me_util = NULL;
    optiga_crypt_t *me_crypt = NULL;
    optiga_lib_status_t return_status = OPTIGA_UTIL_ERROR;

    do {
        if (NULL == fingerprint) {
            break;
        }

        me_util = optiga_util_create(0, trustm_cert_fingerprint_callback, NULL);
        me_crypt = optiga_crypt_create(0, trustm_cert_fingerprint_callback, NULL);
        if ((NULL == me_util) || (NULL == me_crypt)) {
            break;
        }

        // Read the certificate
        trustm_cert_fingerprint_status = OPTIGA_LIB_BUSY;
        return_status = trustm_cert_fingerprint_wait(
            optiga_util_read_data(me_util, cert_oid, 0, cert, &cert_length)
        );
        if (OPTIGA_LIB_SUCCESS != return_status) {
            break;
        }

        // Remove the TLS identity header if present
        if ((cert_length > TRUSTM_CERT_TLS_IDENTITY_HEADER_LENGTH)
            && (TRUSTM_CERT_TLS_IDENTITY_TAG == cert[0])) {
            der_length = ((uint32_t)cert[6] << 16) | ((uint32_t)cert[7] << 8) | cert[8];
            if ((0 == der_length)
                || (der_length > (uint32_t)(cert_length - TRUSTM_CERT_TLS_IDENTITY_HEADER_LENGTH))) {
                return_status = OPTIGA_UTIL_ERROR;
                break;
            }
            hash_input.buffer = &cert[TRUSTM_CERT_TLS_IDENTITY_HEADER_LENGTH];
        } else {
            der_length = cert_length;
            hash_input.buffer = cert;
        }
        hash_input.length = der_length;

        // Hash the DER certificate on OPTIGA
        trustm_cert_fingerprint_status = OPTIGA_LIB_BUSY;
        return_status = trustm_cert_fingerprint_wait(optiga_crypt_hash(
            me_crypt,
            OPTIGA_HASH_TYPE_SHA_256,
            OPTIGA_CRYPT_HOST_DATA,
            &hash_input,
            fingerprint
        ));
    } while (FALSE);

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
    optiga_lib_status_t return_status;

    if ((NULL == expected) || (expected_length > TRUSTM_CERT_FINGERPRINT_LENGTH)) {
        return OPTIGA_UTIL_ERROR;
    }

    return_status = trustm_get_cert_fingerprint(cert_oid, fingerprint);
    if (OPTIGA_LIB_SUCCESS != return_status) {
        return return_status;
    }

    // Compare the pinned fingerprint (or its leading prefix)
    if (0 != memcmp(fingerprint, expected, expected_length)) {
        return OPTIGA_UTIL_ERROR;
    }
    return OPTIGA_LIB_SUCCESS;
}

#endif  // OPTIGA_CRYPT_HASH_ENABLED

/**
 * @}
 */
