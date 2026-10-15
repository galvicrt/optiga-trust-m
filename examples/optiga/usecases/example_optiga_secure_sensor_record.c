/**
 * SPDX-FileCopyrightText: 2026 Infineon Technologies AG
 * SPDX-License-Identifier: MIT
 *
 * \author Infineon Technologies AG
 *
 * \file example_optiga_secure_sensor_record.c
 *
 * \brief   This file provides an example for sealing and opening sensor telemetry records
 *          using OPTIGA symmetric encryption (AES-128 CBC) and HMAC-SHA256.
 *
 * \ingroup grUseCases
 *
 * @{
 */

#include "optiga_crypt.h"
#include "optiga_example.h"
#include "optiga_util.h"
#include "pal_os_memory.h"

#if defined(OPTIGA_CRYPT_SYM_ENCRYPT_ENABLED) && defined(OPTIGA_CRYPT_SYM_DECRYPT_ENABLED) \
    && defined(OPTIGA_CRYPT_HMAC_ENABLED)

#ifndef OPTIGA_INIT_DEINIT_DONE_EXCLUSIVELY
extern void example_optiga_init(void);
extern void example_optiga_deinit(void);
#endif

extern optiga_lib_status_t generate_symmetric_key(void);

/**
 * Sealed record layout:
 *
 * | version (1) | flags (1) | ciphertext length (2, BE) | sequence (4, BE) |
 * | IV (16) | ciphertext (n * 16) | HMAC-SHA256 (32) |
 */
#define SENSOR_RECORD_VERSION (0x01)
#define SENSOR_RECORD_HEADER_LENGTH (8U)
#define SENSOR_RECORD_AES_BLOCK_SIZE (16U)
#define SENSOR_RECORD_IV_LENGTH (16U)
#define SENSOR_RECORD_MAC_LENGTH (32U)
#define SENSOR_RECORD_MAX_PAYLOAD (128U)
#define SENSOR_RECORD_HMAC_SECRET_OID (0xF1D0)

#define SENSOR_RECORD_ERROR (0x8001)
#define SENSOR_RECORD_ERROR_PADDING (0x8002)
#define SENSOR_RECORD_ERROR_MAC (0x8003)
#define SENSOR_RECORD_ERROR_REPLAY (0x8004)

/**
 * Callback when optiga_crypt_xxxx operation is completed asynchronously
 */
static volatile optiga_lib_status_t optiga_lib_status;

/**
 * Sequence number of the last sealed record and the last accepted record
 */
static uint32_t sensor_record_tx_sequence = 0;
static uint32_t sensor_record_rx_sequence = 0;

// lint --e{818} suppress "argument "context" is not used in the sample provided"
static void optiga_crypt_callback(void *context, optiga_lib_status_t return_status) {
    optiga_lib_status = return_status;
    if (NULL != context) {
        // callback to upper layer here
    }
}

static void sensor_record_write_u32_be(uint8_t *buffer, uint32_t value) {
    buffer[0] = (uint8_t)(value >> 24);
    buffer[1] = (uint8_t)(value >> 16);
    buffer[2] = (uint8_t)(value >> 8);
    buffer[3] = (uint8_t)(value);
}

static uint32_t sensor_record_read_u32_be(const uint8_t *buffer) {
    return ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) | ((uint32_t)buffer[2] << 8)
           | (uint32_t)buffer[3];
}

/**
 * Derive the IV from the record sequence number. A unique IV per record is guaranteed by the
 * monotonically increasing sequence number, which saves an additional random number request to
 * OPTIGA for every record.
 */
static void sensor_record_build_iv(uint8_t *iv, uint32_t sequence) {
    pal_os_memset(iv, 0x00, SENSOR_RECORD_IV_LENGTH);
    sensor_record_write_u32_be(&iv[SENSOR_RECORD_IV_LENGTH - 4], sequence);
}

/**
 * Apply PKCS#7 padding in place and return the padded length
 */
static uint32_t sensor_record_pkcs7_pad(uint8_t *buffer, uint32_t data_length) {
    uint8_t pad = (uint8_t)(SENSOR_RECORD_AES_BLOCK_SIZE
                            - (data_length % SENSOR_RECORD_AES_BLOCK_SIZE));
    pal_os_memset(&buffer[data_length], pad, pad);
    return (data_length + pad);
}

/**
 * Remove PKCS#7 padding and return the unpadded length
 */
static optiga_lib_status_t
sensor_record_pkcs7_unpad(const uint8_t *buffer, uint32_t data_length, uint32_t *unpadded_length) {
    uint8_t pad = buffer[data_length - 1];

    if (pad > SENSOR_RECORD_AES_BLOCK_SIZE) {
        return SENSOR_RECORD_ERROR_PADDING;
    }
    *unpadded_length = data_length - pad;
    return OPTIGA_LIB_SUCCESS;
}

/**
 * Seal a sensor payload into a record: AES-128 CBC encrypt using the session key in
 * OPTIGA_KEY_ID_SECRET_BASED and append an HMAC-SHA256 computed with the secret in 0xF1D0.
 */
optiga_lib_status_t sensor_record_seal(
    optiga_crypt_t *me,
    const uint8_t *payload,
    uint32_t payload_length,
    uint8_t *record,
    uint32_t *record_length
) {
    optiga_lib_status_t return_status = SENSOR_RECORD_ERROR;
    uint8_t padded_payload[SENSOR_RECORD_MAX_PAYLOAD + SENSOR_RECORD_AES_BLOCK_SIZE];
    uint8_t *iv = &record[SENSOR_RECORD_HEADER_LENGTH];
    uint8_t *ciphertext = &record[SENSOR_RECORD_HEADER_LENGTH + SENSOR_RECORD_IV_LENGTH];
    uint32_t padded_length;
    uint32_t ciphertext_length;
    uint32_t mac_length = SENSOR_RECORD_MAC_LENGTH;
    uint16_t total_length;

    do {
        if ((NULL == payload) || (NULL == record) || (NULL == record_length)
            || (payload_length > sizeof(padded_payload))) {
            break;
        }

        pal_os_memcpy(padded_payload, payload, payload_length);
        padded_length = sensor_record_pkcs7_pad(padded_payload, payload_length);

        total_length = SENSOR_RECORD_HEADER_LENGTH + SENSOR_RECORD_IV_LENGTH + padded_length
                       + SENSOR_RECORD_MAC_LENGTH;
        if (*record_length < total_length) {
            break;
        }

        sensor_record_tx_sequence++;

        // Header
        record[0] = SENSOR_RECORD_VERSION;
        record[1] = 0x00;
        record[2] = (uint8_t)(padded_length >> 8);
        record[3] = (uint8_t)(padded_length);
        sensor_record_write_u32_be(&record[4], sensor_record_tx_sequence);

        sensor_record_build_iv(iv, sensor_record_tx_sequence);

        // Encrypt the padded payload
        ciphertext_length = padded_length;
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_symmetric_encrypt(
            me,
            OPTIGA_SYMMETRIC_CBC,
            OPTIGA_KEY_ID_SECRET_BASED,
            padded_payload,
            padded_length,
            iv,
            SENSOR_RECORD_IV_LENGTH,
            NULL,
            0,
            ciphertext,
            &ciphertext_length
        );
        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        // Authenticate the ciphertext
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_hmac(
            me,
            OPTIGA_HMAC_SHA_256,
            SENSOR_RECORD_HMAC_SECRET_OID,
            ciphertext,
            ciphertext_length,
            &ciphertext[ciphertext_length],
            &mac_length
        );
        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        *record_length = total_length;
        return_status = OPTIGA_LIB_SUCCESS;
    } while (FALSE);

    return (return_status);
}

/**
 * Open a sealed sensor record: decrypt the ciphertext, verify the HMAC and reject replayed records.
 */
optiga_lib_status_t sensor_record_open(
    optiga_crypt_t *me,
    const uint8_t *record,
    uint32_t record_length,
    uint8_t *payload,
    uint32_t *payload_length
) {
    optiga_lib_status_t return_status = SENSOR_RECORD_ERROR;
    uint8_t decrypted[SENSOR_RECORD_MAX_PAYLOAD + SENSOR_RECORD_AES_BLOCK_SIZE];
    uint8_t expected_mac[SENSOR_RECORD_MAC_LENGTH];
    uint32_t expected_mac_length = sizeof(expected_mac);
    uint32_t decrypted_length = sizeof(decrypted);
    uint32_t unpadded_length = 0;
    uint32_t ciphertext_length;
    uint32_t sequence;
    const uint8_t *iv;
    const uint8_t *ciphertext;
    const uint8_t *received_mac;

    do {
        if ((NULL == record) || (NULL == payload) || (NULL == payload_length)
            || (record_length < SENSOR_RECORD_HEADER_LENGTH)) {
            break;
        }

        if (SENSOR_RECORD_VERSION != record[0]) {
            break;
        }

        ciphertext_length = ((uint32_t)record[2] << 8) | record[3];
        sequence = sensor_record_read_u32_be(&record[4]);
        iv = &record[SENSOR_RECORD_HEADER_LENGTH];
        ciphertext = &record[SENSOR_RECORD_HEADER_LENGTH + SENSOR_RECORD_IV_LENGTH];
        received_mac = &ciphertext[ciphertext_length];

        if (sequence < sensor_record_rx_sequence) {
            return_status = SENSOR_RECORD_ERROR_REPLAY;
            break;
        }

        // Decrypt the ciphertext
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_symmetric_decrypt(
            me,
            OPTIGA_SYMMETRIC_CBC,
            OPTIGA_KEY_ID_SECRET_BASED,
            ciphertext,
            ciphertext_length,
            iv,
            SENSOR_RECORD_IV_LENGTH,
            NULL,
            0,
            decrypted,
            &decrypted_length
        );
        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        return_status = sensor_record_pkcs7_unpad(decrypted, decrypted_length, &unpadded_length);
        if (OPTIGA_LIB_SUCCESS != return_status) {
            break;
        }

        pal_os_memcpy(payload, decrypted, unpadded_length);
        *payload_length = unpadded_length;

        // Verify the HMAC over the ciphertext
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_hmac(
            me,
            OPTIGA_HMAC_SHA_256,
            SENSOR_RECORD_HMAC_SECRET_OID,
            ciphertext,
            ciphertext_length,
            expected_mac,
            &expected_mac_length
        );
        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        if (0 != memcmp(expected_mac, received_mac, SENSOR_RECORD_MAC_LENGTH)) {
            return_status = SENSOR_RECORD_ERROR_MAC;
            break;
        }

        sensor_record_rx_sequence = sequence;
        return_status = OPTIGA_LIB_SUCCESS;
    } while (FALSE);

    return (return_status);
}

/**
 * Write the HMAC secret to 0xF1D0 with
 * Execute access condition = Always
 * Data object type  =  Pre-shared secret
 */
static optiga_lib_status_t sensor_record_provision_hmac_secret(void) {
    optiga_lib_status_t return_status = !OPTIGA_LIB_SUCCESS;
    optiga_util_t *me_util = NULL;
    const uint8_t secret_metadata[] = {0x20, 0x06, 0xD3, 0x01, 0x00, 0xE8, 0x01, 0x21};
    const uint8_t hmac_secret[] = {
        0x8d,
        0xe4,
        0x3f,
        0xff,
        0x65,
        0x2d,
        0xa0,
        0xa7,
        0xf0,
        0x4e,
        0x8f,
        0x22,
        0x84,
        0xa4,
        0x28,
        0x3b,
        0x5a,
        0xb0,
        0xad,
        0xd1,
        0x1d,
        0x3f,
        0x8e,
        0x85,
        0xd8,
        0x2c,
        0x6d,
        0xf1,
        0x62,
        0x82,
        0x06,
        0x19};

    do {
        me_util = optiga_util_create(0, optiga_crypt_callback, NULL);
        if (NULL == me_util) {
            break;
        }

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_write_metadata(
            me_util,
            SENSOR_RECORD_HMAC_SECRET_OID,
            secret_metadata,
            sizeof(secret_metadata)
        );
        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_write_data(
            me_util,
            SENSOR_RECORD_HMAC_SECRET_OID,
            OPTIGA_UTIL_ERASE_AND_WRITE,
            0,
            hmac_secret,
            sizeof(hmac_secret)
        );
        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);
    } while (FALSE);

    if (me_util) {
        if (OPTIGA_LIB_SUCCESS != optiga_util_destroy(me_util)) {
            return_status = !OPTIGA_LIB_SUCCESS;
        }
    }
    return (return_status);
}

/**
 * The below example demonstrates sealing a sensor reading into an authenticated, encrypted record
 * and opening it again on the receiving side.
 *
 * Example for
 *  #optiga_crypt_symmetric_encrypt,
 *  #optiga_crypt_symmetric_decrypt and
 *  #optiga_crypt_hmac
 */
void example_optiga_secure_sensor_record(void) {
    // Sample reading: device id (4), timestamp (4), temperature, humidity, pressure (2 each)
    const uint8_t sensor_reading[] = {0x00, 0x00, 0x12, 0x34, 0x66, 0x1F, 0x3A, 0x80,
                                      0x09, 0x6C, 0x13, 0x88, 0x27, 0x10};
    uint8_t record[SENSOR_RECORD_HEADER_LENGTH + SENSOR_RECORD_IV_LENGTH + SENSOR_RECORD_MAX_PAYLOAD
                   + SENSOR_RECORD_AES_BLOCK_SIZE + SENSOR_RECORD_MAC_LENGTH];
    uint32_t record_length = sizeof(record);
    uint8_t opened_payload[SENSOR_RECORD_MAX_PAYLOAD];
    uint32_t opened_payload_length = sizeof(opened_payload);
    uint32_t time_taken = 0;
    optiga_crypt_t *me = NULL;
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

        /**
         * 1. Create OPTIGA Crypt Instance
         */
        me = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == me) {
            break;
        }

        /**
         * 2. Generate the AES-128 session key and provision the HMAC secret
         */
        return_status = generate_symmetric_key();
        if (OPTIGA_LIB_SUCCESS != return_status) {
            break;
        }

        return_status = sensor_record_provision_hmac_secret();
        if (OPTIGA_LIB_SUCCESS != return_status) {
            break;
        }

        START_PERFORMANCE_MEASUREMENT(time_taken);

        /**
         * 3. Seal the sensor reading
         */
        return_status =
            sensor_record_seal(me, sensor_reading, sizeof(sensor_reading), record, &record_length);
        if (OPTIGA_LIB_SUCCESS != return_status) {
            break;
        }

        /**
         * 4. Open the sealed record and compare against the original reading
         */
        return_status =
            sensor_record_open(me, record, record_length, opened_payload, &opened_payload_length);
        if (OPTIGA_LIB_SUCCESS != return_status) {
            break;
        }

        READ_PERFORMANCE_MEASUREMENT(time_taken);

        if ((opened_payload_length != sizeof(sensor_reading))
            || (0 != memcmp(opened_payload, sensor_reading, sizeof(sensor_reading)))) {
            return_status = !OPTIGA_LIB_SUCCESS;
            break;
        }

        return_status = OPTIGA_LIB_SUCCESS;
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

    if (me) {
        // Destroy the instance after the completion of usecase if not required.
        return_status = optiga_crypt_destroy(me);
        if (OPTIGA_LIB_SUCCESS != return_status) {
            // lint --e{774} suppress This is a generic macro
            OPTIGA_EXAMPLE_LOG_STATUS(return_status);
        }
    }
}

#endif  // OPTIGA_CRYPT_SYM_ENCRYPT_ENABLED && OPTIGA_CRYPT_SYM_DECRYPT_ENABLED &&
        // OPTIGA_CRYPT_HMAC_ENABLED
/**
 * @}
 */
