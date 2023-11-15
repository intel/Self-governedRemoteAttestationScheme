/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of verification callbacks for TLS libraries. The callbacks
 * verify the correctness of a self-signed RA-TLS certificate with an SGX quote embedded in it. The
 * callbacks call into the `libsgx_dcap_quoteverify` DCAP library for ECDSA-based verification. A
 * callback ra_tls_verify_callback() can be used directly in mbedTLS, and a more generic version
 * ra_tls_verify_callback_der() should be used for other TLS libraries.
 *
 * This file is part of the RA-TLS verification library which is typically linked into client
 * applications. This library is *not* thread-safe.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <jansson.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

// #include "quote.h"
#include "ra_tls.h"
// #include "sgx_arch.h"
// #include "sgx_attest.h"
#include "util.h"
#include "sgx_dcap_quoteverify.h"

extern verify_measurements_cb_t g_verify_measurements_cb;
extern char *ce_tcbinfos;
extern char *tcb_id;

/* we cannot include libsgx_dcap_verify headers because they conflict with Gramine SGX headers,
 * so we declare the used types and functions below */

/* QL stands for Quoting Library; QV stands for Quote Verification */
#define SGX_QL_QV_MK_ERROR(x) (0x0000A000 | (x))
// typedef enum _sgx_ql_qv_result_t {
//     /* quote verification passed and is at the latest TCB level */
//     SGX_QL_QV_RESULT_OK = 0x0000,
//     /* quote verification passed and the platform is patched to the latest TCB level but additional
//      * configuration of the SGX platform may be needed */
//     SGX_QL_QV_RESULT_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(0x0001),
//     /* quote is good but TCB level of the platform is out of date; platform needs patching to be at
//      * the latest TCB level */
//     SGX_QL_QV_RESULT_OUT_OF_DATE = SGX_QL_QV_MK_ERROR(0x0002),
//     /* quote is good but the TCB level of the platform is out of date and additional configuration
//      * of the SGX platform at its current patching level may be needed; platform needs patching to
//      * be at the latest TCB level */
//     SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(0x0003),
//     /* signature over the application report is invalid */
//     SGX_QL_QV_RESULT_INVALID_SIGNATURE = SGX_QL_QV_MK_ERROR(0x0004),
//     /* attestation key or platform has been revoked */
//     SGX_QL_QV_RESULT_REVOKED = SGX_QL_QV_MK_ERROR(0x0005),
//     /* quote verification failed due to an error in one of the input */
//     SGX_QL_QV_RESULT_UNSPECIFIED = SGX_QL_QV_MK_ERROR(0x0006),
//     /* TCB level of the platform is up to date, but SGX SW hardening is needed */
//     SGX_QL_QV_RESULT_SW_HARDENING_NEEDED = SGX_QL_QV_MK_ERROR(0x0007),
//     /* TCB level of the platform is up to date, but additional configuration of the platform at its
//      * current patching level may be needed; moreover, SGX SW hardening is also needed */
//     SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED = SGX_QL_QV_MK_ERROR(0x0008),
// } sgx_ql_qv_result_t;

// int sgx_qv_get_quote_supplemental_data_size(uint32_t* p_data_size);
// int sgx_qv_verify_quote(const uint8_t* p_quote, uint32_t quote_size, void* p_quote_collateral,
//                         const time_t expiration_check_date,
//                         uint32_t* p_collateral_expiration_status,
//                         sgx_ql_qv_result_t* p_quote_verification_result, void* p_qve_report_info,
//                         uint32_t supplemental_data_size, uint8_t* p_supplemental_data);

static const char* sgx_ql_qv_result_to_str(sgx_ql_qv_result_t verification_result) {
    switch (verification_result) {
        case SGX_QL_QV_RESULT_OK:
            return "OK";
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
            return "CONFIG_NEEDED";
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
            return "OUT_OF_DATE";
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            return "OUT_OF_DATE_CONFIG_NEEDED";
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            return "SW_HARDENING_NEEDED";
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            return "CONFIG_AND_SW_HARDENING_NEEDED";
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
            return "INVALID_SIGNATURE";
        case SGX_QL_QV_RESULT_REVOKED:
            return "REVOKED";
        case SGX_QL_QV_RESULT_UNSPECIFIED:
            return "UNSPECIFIED";
    }
    return "<unrecognized error>";
}

int ra_tls_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    (void)data;

    int ret;

    uint8_t* supplemental_data      = NULL;
    uint32_t supplemental_data_size = 0;

    if (depth != 0) {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }

    /* extract SGX quote from "quote" OID extension from crt */
    sgx_quote3_t* quote;
    size_t quote_size;
    ret = extract_quote_and_verify_pubkey(crt, &quote, &quote_size);
    if (ret < 0) {
        ERROR("extract_quote_and_verify_pubkey failed: %d\n", ret);
        goto out;
    }

    /* prepare user-supplied verification parameters "allow outdated TCB"/"allow debug enclave" */
    bool allow_outdated_tcb  = getenv_allow_outdated_tcb();
    bool allow_debug_enclave = getenv_allow_debug_enclave();

    /* call into libsgx_dcap_quoteverify to get supplemental data size */
    ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (ret) {
        ERROR("sgx_qv_get_quote_supplemental_data_size failed: %d\n", ret);
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    if (!supplemental_data) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    time_t current_time = time(NULL);
    if (current_time == ((time_t)-1)) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    uint32_t collateral_expiration_status  = 1;
    sgx_ql_qv_result_t verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    uint8_t** p_quote_collaterals = NULL;
    char** ids = NULL;
    int collateral_num = 0;
    if (!parseCollateral(ce_tcbinfos, &p_quote_collaterals, &ids, &collateral_num)) {
        goto out;
    }

    int selected_i = -1;
    for(int i = 0;i < collateral_num;++i) {
        uint8_t* p_quote_collateral = p_quote_collaterals[i];
        /* call into libsgx_dcap_quoteverify to verify ECDSA-based SGX quote */
        ret = sgx_qv_verify_quote((uint8_t*)quote, (uint32_t)quote_size, /*p_quote_collateral=*/p_quote_collateral,
                                current_time, &collateral_expiration_status, &verification_result,
                                /*p_qve_report_info=*/NULL, supplemental_data_size,
                                supplemental_data);
        p_quote_collateral = NULL;
        if (!ret) {
            selected_i = i;
            break;
        }
    }

    // Get the tcb id which is used to successfully verify quote
    char* tcbId = NULL;
    if (selected_i >= 0) {
        tcbId = (char*)malloc(strlen(ids[selected_i]) + 1);
        memcpy(tcbId, ids[selected_i], strlen(ids[selected_i]) + 1);
        tcb_id = tcbId;
    }
    
    if (ret) {
        ERROR("sgx_qv_verify_quote failed: %d\n", ret);
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    switch (verification_result) {
        case SGX_QL_QV_RESULT_OK:
            if (collateral_expiration_status != 0) {
                INFO("WARNING: The collateral is out of date.\n");
            }
            ret = 0;
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            ret = allow_outdated_tcb ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
    }
    if (ret < 0) {
        ERROR("Quote: verification failed with error %s\n",
              sgx_ql_qv_result_to_str(verification_result));
        goto out;
    }

    // sgx_quote_body_t* quote_body = &quote->body;

    // /* verify enclave attributes from the SGX quote body */
    // ret = verify_quote_body_enclave_attributes(quote_body, allow_debug_enclave);
    // if (ret < 0) {
    //     ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    //     goto out;
    // }

    // /* verify other relevant enclave information from the SGX quote */
    // if (g_verify_measurements_cb) {
    //     /* use user-supplied callback to verify measurements */
    //     ret = g_verify_measurements_cb((const char*)&quote_body->report_body.mr_enclave,
    //                                    (const char*)&quote_body->report_body.mr_signer,
    //                                    (const char*)&quote_body->report_body.isv_prod_id,
    //                                    (const char*)&quote_body->report_body.isv_svn);
    // } else {
    //     /* use default logic to verify measurements */
    //     ret = verify_quote_body_against_envvar_measurements(quote_body);
    // }
    // if (ret < 0) {
    //     ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    //     goto out;
    // }

    // ret = 0;
out:
    // Free collaterals and ids
    if (p_quote_collaterals) {
        for(int i = 0;i < collateral_num;++i) {
            if (p_quote_collaterals[i]) {
                freeCollateral(p_quote_collaterals[i]);
            }
        }
        free(p_quote_collaterals);
    }
    if (ids) {
        for(int i = 0;i < collateral_num;++i) {
            if (ids[i]) {
                free(ids[i]);
            }
        }
        free(ids);
    }
    if (supplemental_data) {
        free(supplemental_data);
    }
    return ret;
}

bool parseCollateral(const char* base64_encoded_collateral, uint8_t*** pp_quote_collaterals, char*** p_ids, int* p_collateral_num) {
    // Parse collateral
    json_t* collaterals_object = json_loads(base64_encoded_collateral, 0, NULL);
    int collateral_num = json_object_size(collaterals_object);
    if (collateral_num <= 0) {
        printf("Error: collateral number is less than 0\n");
        return false;
    }
    *p_collateral_num = collateral_num;

    *pp_quote_collaterals = (uint8_t**)malloc(collateral_num * sizeof(uint8_t*));
    if (*pp_quote_collaterals == NULL) {
        printf("Allocate p_quote_collaterals failed\n");
        return false;
    }
    uint8_t** p_quote_collaterals = *pp_quote_collaterals;
    for (int i = 0;i < collateral_num;++i) {
        p_quote_collaterals[i] = NULL;
    }

    *p_ids = (char**)malloc(collateral_num * sizeof(char*));
    if (*p_ids == NULL) {
        printf("Allocate ids failed\n");
        return false;
    }
    char** ids = *p_ids;
    for (int i = 0;i < collateral_num;++i) {
        ids[i] = NULL;
    }

    void* iter = json_object_iter(collaterals_object);
    for (int i = 0;i < collateral_num;++i) {
        const char* tcbId = json_object_iter_key(iter);
        ids[i] = (char*)malloc(strlen(tcbId) + 1);
        if (ids[i] == NULL) {
            printf("Allocate ids %d failed\n", i);
            return false;
        }
        memcpy(ids[i], tcbId, strlen(tcbId) + 1);
        json_t* collateral_object = json_object_iter_value(iter);
        uint32_t collateral_size = json_integer_value(json_object_get(collateral_object, "collateral_size"));
        uint32_t version = json_integer_value(json_object_get(collateral_object, "version"));
        uint32_t tee_type = json_integer_value(json_object_get(collateral_object, "tee_type"));

        const char *pck_crl_issuer_chain_base64 = json_string_value(json_object_get(collateral_object, "pck_crl_issuer_chain"));
        uint32_t pck_crl_issuer_chain_size = json_integer_value(json_object_get(collateral_object, "pck_crl_issuer_chain_size"));

        const char *root_ca_crl_base64 = json_string_value(json_object_get(collateral_object, "root_ca_crl"));
        uint32_t root_ca_crl_size = json_integer_value(json_object_get(collateral_object, "root_ca_crl_size"));

        const char *pck_crl_base64 = json_string_value(json_object_get(collateral_object, "pck_crl"));
        uint32_t pck_crl_size = json_integer_value(json_object_get(collateral_object, "pck_crl_size"));

        const char *tcb_info_issuer_chain_base64 = json_string_value(json_object_get(collateral_object, "tcb_info_issuer_chain"));
        uint32_t tcb_info_issuer_chain_size = json_integer_value(json_object_get(collateral_object, "tcb_info_issuer_chain_size"));

        const char *tcb_info_base64 = json_string_value(json_object_get(collateral_object, "tcb_info"));
        uint32_t tcb_info_size = json_integer_value(json_object_get(collateral_object, "tcb_info_size"));

        const char *qe_identity_issuer_chain_base64 = json_string_value(json_object_get(collateral_object, "qe_identity_issuer_chain"));
        uint32_t qe_identity_issuer_chain_size = json_integer_value(json_object_get(collateral_object, "qe_identity_issuer_chain_size"));

        const char *qe_identity_base64 = json_string_value(json_object_get(collateral_object, "qe_identity"));
        uint32_t qe_identity_size = json_integer_value(json_object_get(collateral_object, "qe_identity_size"));

        // Construct p_quote_collater
        printf("\nCollateral size: %d\n", collateral_size);
        sgx_ql_qve_collateral_t* p_quote_collateral_struct = (sgx_ql_qve_collateral_t*)malloc(sizeof(sgx_ql_qve_collateral_t));
        if (p_quote_collateral_struct == NULL) {
            printf("Allocate p_quote_collateral_struct failed\n");
            return false;
        }
        p_quote_collateral_struct->pck_crl = NULL;
        p_quote_collateral_struct->pck_crl_issuer_chain = NULL;
        p_quote_collateral_struct->qe_identity = NULL;
        p_quote_collateral_struct->qe_identity_issuer_chain = NULL;
        p_quote_collateral_struct->root_ca_crl = NULL;
        p_quote_collateral_struct->tcb_info = NULL;
        p_quote_collateral_struct->tcb_info_issuer_chain = NULL;

        p_quote_collateral_struct->version = version;
        p_quote_collateral_struct->tee_type = tee_type;
        // printf("Assign version and type finished\n");
        char* pck_crl_issuer_chain_buffer = (char*)malloc(pck_crl_issuer_chain_size);
        if (pck_crl_issuer_chain_buffer == NULL) {
            printf("Allocate pck_crl_issuer_chain_buffer failed\n");
            p_quote_collaterals[i] = (uint8_t*)(p_quote_collateral_struct);
            return false;
        }
        base64Decode(pck_crl_issuer_chain_base64, pck_crl_issuer_chain_buffer, pck_crl_issuer_chain_size);
        p_quote_collateral_struct->pck_crl_issuer_chain = pck_crl_issuer_chain_buffer;
        // printf("Assign pck_crl_issuer_chain finished\n");
        p_quote_collateral_struct->pck_crl_issuer_chain_size = pck_crl_issuer_chain_size;

        char* root_ca_crl_buffer = (char*)malloc(root_ca_crl_size);
        if (root_ca_crl_buffer == NULL) {
            printf("Allocate root_ca_crl_buffer failed\n");
            p_quote_collaterals[i] = (uint8_t*)(p_quote_collateral_struct);
            return false;
        }
        base64Decode(root_ca_crl_base64, root_ca_crl_buffer, root_ca_crl_size);
        p_quote_collateral_struct->root_ca_crl = root_ca_crl_buffer;
        // printf("Assign root_ca_crl finished\n");
        p_quote_collateral_struct->root_ca_crl_size = root_ca_crl_size;

        char* pck_crl_buffer = (char*)malloc(pck_crl_size);
        if (pck_crl_buffer == NULL) {
            printf("Allocate pck_crl_buffer failed\n");
            p_quote_collaterals[i] = (uint8_t*)(p_quote_collateral_struct);
            return false;
        }
        base64Decode(pck_crl_base64, pck_crl_buffer, pck_crl_size);
        p_quote_collateral_struct->pck_crl = pck_crl_buffer;
        // printf("Assign pck_crl finished\n");
        p_quote_collateral_struct->pck_crl_size = pck_crl_size;
        
        char* tcb_info_issuer_chain_buffer = (char*)malloc(tcb_info_issuer_chain_size);
        if (tcb_info_issuer_chain_buffer == NULL) {
            printf("Allocate tcb_info_issuer_chain_buffer failed\n");
            p_quote_collaterals[i] = (uint8_t*)(p_quote_collateral_struct);
            return false;
        }
        base64Decode(tcb_info_issuer_chain_base64, tcb_info_issuer_chain_buffer, tcb_info_issuer_chain_size);
        p_quote_collateral_struct->tcb_info_issuer_chain = tcb_info_issuer_chain_buffer;
        // printf("Assign tcb_info_issuer_chain finished\n");
        p_quote_collateral_struct->tcb_info_issuer_chain_size = tcb_info_issuer_chain_size;
        
        char* tcb_info_buffer = (char*)malloc(tcb_info_size);
        if (tcb_info_buffer == NULL) {
            printf("Allocate tcb_info_buffer failed\n");
            p_quote_collaterals[i] = (uint8_t*)(p_quote_collateral_struct);
            return false;
        }
        base64Decode(tcb_info_base64, tcb_info_buffer, tcb_info_size);
        p_quote_collateral_struct->tcb_info = tcb_info_buffer;
        // printf("Assign tcb_info finished\n");
        p_quote_collateral_struct->tcb_info_size = tcb_info_size;
        
        char* qe_identity_issuer_chain_buffer = (char*)malloc(qe_identity_issuer_chain_size);
        if (qe_identity_issuer_chain_buffer == NULL) {
            printf("Allocate qe_identity_issuer_chain_buffer failed\n");
            p_quote_collaterals[i] = (uint8_t*)(p_quote_collateral_struct);
            return false;
        }
        base64Decode(qe_identity_issuer_chain_base64, qe_identity_issuer_chain_buffer, qe_identity_issuer_chain_size);
        p_quote_collateral_struct->qe_identity_issuer_chain = qe_identity_issuer_chain_buffer;
        // printf("Assign qe_identity_issuer_chain finished\n");
        p_quote_collateral_struct->qe_identity_issuer_chain_size = qe_identity_issuer_chain_size;

        char* qe_identity_buffer = (char*)malloc(qe_identity_size);
        if (qe_identity_buffer == NULL) {
            printf("Allocate qe_identity_buffer failed\n");
            p_quote_collaterals[i] = (uint8_t*)(p_quote_collateral_struct);
            return false;
        }
        base64Decode(qe_identity_base64, qe_identity_buffer, qe_identity_size);
        p_quote_collateral_struct->qe_identity = qe_identity_buffer;
        // printf("Assign qe_identity finished\n");
        p_quote_collateral_struct->qe_identity_size = qe_identity_size;

        uint8_t* p_quote_collateral = (uint8_t*)(p_quote_collateral_struct);
        p_quote_collaterals[i] = p_quote_collateral;
    }

    printf("Construct collateral finished\n");

    return true;
}

int base64Decode(const char* input, unsigned char* output, int size) {
    int decode_table[256];
    memset(decode_table, -1, 256);

    const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 64; ++i) {
        decode_table[table[i]] = i;
    }

    int input_len = strlen(input);
    int padding = 0;
    if (input_len > 0 && input[input_len - 1] == '=') {
        padding++;
    }
    if (input_len > 1 && input[input_len - 2] == '=') {
        padding++;
    }

    int output_len = 3 * input_len / 4 - padding;
    if (output_len > size) {
        return -1;
    }

    for (int i = 0, j = 0; i < input_len;) {
        uint32_t sextet_a = input[i] == '=' ? 0 & i++ : decode_table[(int) input[i++]];
        uint32_t sextet_b = input[i] == '=' ? 0 & i++ : decode_table[(int) input[i++]];
        uint32_t sextet_c = input[i] == '=' ? 0 & i++ : decode_table[(int) input[i++]];
        uint32_t sextet_d = input[i] == '=' ? 0 & i++ : decode_table[(int) input[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
                        + (sextet_b << 2 * 6)
                        + (sextet_c << 1 * 6)
                        + (sextet_d << 0 * 6);

        if (j < output_len) {
            output[j++] = (triple >> 2 * 8) & 0xFF;
        }
        if (j < output_len) {
            output[j++] = (triple >> 1 * 8) & 0xFF;
        }
        if (j < output_len) {
            output[j++] = (triple >> 0 * 8) & 0xFF;
        }
    }

    return 0;
}

void freeCollateral(uint8_t* p_quote_collateral) {
    sgx_ql_qve_collateral_t* p_quote_collateral_struct = (sgx_ql_qve_collateral_t*)p_quote_collateral;
    if (p_quote_collateral_struct->pck_crl_issuer_chain) {
        free(p_quote_collateral_struct->pck_crl_issuer_chain);
    }
    if (p_quote_collateral_struct->pck_crl) {
        free(p_quote_collateral_struct->pck_crl);
    }
    if (p_quote_collateral_struct->qe_identity) {
        free(p_quote_collateral_struct->qe_identity);
    }
    if (p_quote_collateral_struct->qe_identity_issuer_chain) {
        free(p_quote_collateral_struct->qe_identity_issuer_chain);
    }
    if (p_quote_collateral_struct->root_ca_crl) {
        free(p_quote_collateral_struct->root_ca_crl);
    }
    if (p_quote_collateral_struct->tcb_info) {
        free(p_quote_collateral_struct->tcb_info);
    }
    if (p_quote_collateral_struct->tcb_info_issuer_chain) {
        free(p_quote_collateral_struct->tcb_info_issuer_chain);
    }
}