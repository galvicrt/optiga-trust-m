/**
 * SPDX-FileCopyrightText: 2026 Infineon Technologies AG
 * SPDX-License-Identifier: MIT
 *
 * \author Infineon Technologies AG
 *
 * \file example_optiga_cert_fingerprint.c
 *
 * \brief   This file provides an example for computing the device certificate fingerprint and
 *          verifying it against a pinned value.
 *
 * \ingroup grUseCases
 *
 * @{
 */

#include "optiga_example.h"
#include "optiga_util.h"
#include "trustm_cert_fingerprint.h"

#ifdef OPTIGA_CRYPT_HASH_ENABLED

#ifndef OPTIGA_INIT_DEINIT_DONE_EXCLUSIVELY
extern void example_optiga_init(void);
extern void example_optiga_deinit(void);
#endif

/**
 * Demo pin of the device certificate fingerprint. Replace it with the fingerprint recorded for
 * your device during production.
 */
static const uint8_t pinned_cert_fingerprint[TRUSTM_CERT_FINGERPRINT_LENGTH] = {
    0x3A, 0x7F, 0x12, 0xC4, 0x9E, 0x05, 0xB8, 0x61, 0xD2, 0x4C, 0x88, 0x17, 0xE9, 0x30, 0x5B, 0xA6,
    0x0D, 0x94, 0x2E, 0x7B, 0xC1, 0x58, 0xF3, 0x06, 0x6A, 0xBD, 0x41, 0x9C, 0x23, 0xE7, 0x75, 0x1F};

/**
 * The below example demonstrates reading the device certificate fingerprint and checking it
 * against a pinned value.
 *
 * Example for
 *  #trustm_get_cert_fingerprint,
 *  #trustm_format_cert_fingerprint and
 *  #trustm_verify_cert_fingerprint
 */
void example_optiga_cert_fingerprint(void) {
    uint8_t fingerprint[TRUSTM_CERT_FINGERPRINT_LENGTH];
    char fingerprint_string[TRUSTM_CERT_FINGERPRINT_STRING_LENGTH];
    uint32_t time_taken = 0;
    optiga_lib_status_t return_status = !OPTIGA_LIB_SUCCESS;

    do {
#ifndef OPTIGA_INIT_DEINIT_DONE_EXCLUSIVELY
        /**
         * Open the application on OPTIGA which is a precondition to perform any other operations
         * using optiga_util_open_application
         */
        example_optiga_init();
#endif  // OPTIGA_INIT_DEINIT_DONE_EXCLUSIVELY

        OPTIGA_EXAMPLE_LOG_MESSAGE(__FUNCTION__);

        START_PERFORMANCE_MEASUREMENT(time_taken);

        /**
         * 1. Compute the fingerprint of the device certificate
         */
        return_status =
            trustm_get_cert_fingerprint(TRUSTM_CERT_FINGERPRINT_DEFAULT_OID, fingerprint);
        if (OPTIGA_LIB_SUCCESS != return_status) {
            break;
        }

        READ_PERFORMANCE_MEASUREMENT(time_taken);

        /**
         * 2. Print the fingerprint
         */
        return_status = trustm_format_cert_fingerprint(
            fingerprint,
            fingerprint_string,
            sizeof(fingerprint_string)
        );
        if (OPTIGA_LIB_SUCCESS != return_status) {
            break;
        }
        OPTIGA_EXAMPLE_LOG_MESSAGE(fingerprint_string);

        /**
         * 3. Verify the certificate against the pinned fingerprint
         */
        return_status = trustm_verify_cert_fingerprint(
            TRUSTM_CERT_FINGERPRINT_DEFAULT_OID,
            pinned_cert_fingerprint,
            sizeof(pinned_cert_fingerprint)
        );
        if (OPTIGA_LIB_SUCCESS != return_status) {
            OPTIGA_EXAMPLE_LOG_MESSAGE("Certificate does not match the pinned fingerprint");
            break;
        }
        OPTIGA_EXAMPLE_LOG_MESSAGE("Certificate matches the pinned fingerprint");
    } while (FALSE);
    OPTIGA_EXAMPLE_LOG_STATUS(return_status);

#ifndef OPTIGA_INIT_DEINIT_DONE_EXCLUSIVELY
    /**
     * Close the application on OPTIGA after all the operations are executed
     * using optiga_util_close_application
     */
    example_optiga_deinit();
#endif  // OPTIGA_INIT_DEINIT_DONE_EXCLUSIVELY
    OPTIGA_EXAMPLE_LOG_PERFORMANCE_VALUE(time_taken, return_status);
}

#endif  // OPTIGA_CRYPT_HASH_ENABLED
/**
 * @}
 */
