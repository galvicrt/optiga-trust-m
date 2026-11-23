/**
 * SPDX-FileCopyrightText: 2026 Infineon Technologies AG
 * SPDX-License-Identifier: MIT
 *
 * \author Infineon Technologies AG
 *
 * \file trustm_cert_fingerprint.h
 *
 * \brief   This file provides APIs to compute, format and pin the SHA-256 fingerprint of a
 *          certificate stored in OPTIGA Trust M.
 *
 * \ingroup grOptigaExample
 *
 * @{
 */

#ifndef _TRUSTM_CERT_FINGERPRINT_H_
#define _TRUSTM_CERT_FINGERPRINT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "optiga_lib_common.h"

/// Default OID of the Infineon device certificate
#define TRUSTM_CERT_FINGERPRINT_DEFAULT_OID (0xE0E0)
/// Length of a SHA-256 certificate fingerprint in bytes
#define TRUSTM_CERT_FINGERPRINT_LENGTH (32U)
/// Buffer size needed for a formatted fingerprint ("AA:BB:...:FF") including the terminator
#define TRUSTM_CERT_FINGERPRINT_STRING_LENGTH ((2U * TRUSTM_CERT_FINGERPRINT_LENGTH) + 1U)

/**
 * \brief Computes the SHA-256 fingerprint of the X.509 certificate stored in a certificate OID.
 *
 * \details
 * Reads the certificate, removes the TLS identity header if present and hashes the DER
 * certificate on OPTIGA.
 *
 * \pre
 * - The application on OPTIGA must be opened using #optiga_util_open_application.
 *
 * \param[in]   cert_oid        Certificate OID (for example #TRUSTM_CERT_FINGERPRINT_DEFAULT_OID)
 * \param[out]  fingerprint     Buffer of #TRUSTM_CERT_FINGERPRINT_LENGTH bytes for the fingerprint
 *
 * \retval      #OPTIGA_LIB_SUCCESS     Fingerprint computed
 * \retval      #OPTIGA_UTIL_ERROR      Invalid input or unsupported certificate format
 * \retval      Others                  Error returned by OPTIGA
 */
optiga_lib_status_t trustm_get_cert_fingerprint(uint16_t cert_oid, uint8_t *fingerprint);

/**
 * \brief Formats a fingerprint as colon-separated uppercase hex ("AA:BB:...:FF").
 *
 * \param[in]   fingerprint     Fingerprint of #TRUSTM_CERT_FINGERPRINT_LENGTH bytes
 * \param[out]  output          Output string buffer
 * \param[in]   output_length   Size of <b>output</b>, at least #TRUSTM_CERT_FINGERPRINT_STRING_LENGTH
 *
 * \retval      #OPTIGA_LIB_SUCCESS     Fingerprint formatted
 * \retval      #OPTIGA_UTIL_ERROR      Invalid input or output buffer too small
 */
optiga_lib_status_t
trustm_format_cert_fingerprint(const uint8_t *fingerprint, char *output, uint16_t output_length);

/**
 * \brief Verifies the certificate in a certificate OID against a pinned fingerprint.
 *
 * \details
 * The pinned fingerprint can be the full SHA-256 value or a leading prefix of it, for
 * configurations that store a shortened pin.
 *
 * \param[in]   cert_oid            Certificate OID
 * \param[in]   expected            Pinned fingerprint (or fingerprint prefix)
 * \param[in]   expected_length     Length of <b>expected</b>, at most #TRUSTM_CERT_FINGERPRINT_LENGTH
 *
 * \retval      #OPTIGA_LIB_SUCCESS     Certificate matches the pinned fingerprint
 * \retval      #OPTIGA_UTIL_ERROR      Mismatch or invalid input
 * \retval      Others                  Error returned by OPTIGA
 */
optiga_lib_status_t trustm_verify_cert_fingerprint(
    uint16_t cert_oid,
    const uint8_t *expected,
    uint16_t expected_length
);

#ifdef __cplusplus
}
#endif

#endif /* _TRUSTM_CERT_FINGERPRINT_H_ */

/**
 * @}
 */
