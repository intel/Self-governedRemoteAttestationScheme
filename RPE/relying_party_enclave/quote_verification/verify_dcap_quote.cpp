#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <jansson.h>
#include "verify_dcap_quote.h"
#include "hex_string.h"
#include "base64.h"
#include "sgx_report.h"
#include "sgx_quote_3.h"

typedef union _supp_ver_t{
    uint32_t version;
    struct {
        uint16_t major_version;
        uint16_t minor_version;
    };
} supp_ver_t;

int teeVerifyQuote(std::string base64_encoded_quote, size_t quote_size, std::string base64_encoded_collateral) {
    int ret;
    supp_ver_t latest_ver;
    tee_supp_data_descriptor_t supp_data;

    memset(&supp_data, 0, sizeof(tee_supp_data_descriptor_t));

    std::vector<uint8_t> quote = base64_decode(base64_encoded_quote);
    quote_size = quote.size();

    // Get supplemental data version and size
    ret = tee_get_supplemental_data_version_and_size(quote.data(),
                                            (uint32_t)quote.size(),
                                            &latest_ver.version,
                                            &supp_data.data_size);

    if (ret == SGX_QL_SUCCESS && supp_data.data_size == sizeof(sgx_ql_qv_supplemental_t)) {
        printf("\tInfo: tee_get_quote_supplemental_data_version_and_size successfully returned.\n");
        printf("\tInfo: latest supplemental data major version: %d, minor version: %d, size: %d\n", latest_ver.major_version, latest_ver.minor_version, supp_data.data_size);
        supp_data.p_data = (uint8_t*)malloc(supp_data.data_size);
        if (supp_data.p_data != NULL) {
            memset(supp_data.p_data, 0, supp_data.data_size);
        }

        //Just print error in sample
        //
        else {
            printf("\tError: Cannot allocate memory for supplemental data.\n");
            return ret;
        }
    }
    else {
        if (ret != SGX_QL_SUCCESS) {
            printf("\tError: tee_get_quote_supplemental_data_size failed: 0x%04x\n", ret);
            return ret;
        }
        if (supp_data.data_size != sizeof(sgx_ql_qv_supplemental_t)) {
            printf("\tWarning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.\n");
        }

        supp_data.data_size = 0;
    }

    time_t current_time = time(NULL);
    uint32_t collateral_expiration_status  = 1;
    sgx_ql_qv_result_t verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    // Parse collateral
    uint8_t* p_quote_collateral = parseCollateral(std::move(base64_encoded_collateral));
    std::cout << "Parse collateral finished" << std::endl;

    /* call into libsgx_dcap_quoteverify to verify ECDSA-based SGX quote */
    ret = tee_verify_quote(
        quote.data(), (uint32_t)quote.size(),
        p_quote_collateral,
        current_time,
        &collateral_expiration_status,
        &verification_result,
        NULL,
        &supp_data);

    free(supp_data.p_data);
    freeCollateral(p_quote_collateral);
    supp_data.p_data = NULL;
    p_quote_collateral = NULL;

    if (ret) {
        std::cout << "DCAP ERROR: Error verify dcap quote" << std::endl;
        return ret;
    }
    switch (verification_result) {
        case SGX_QL_QV_RESULT_OK:
            if (collateral_expiration_status != 0) {
                std::cout << "WARNING: The collateral is out of date." << std::endl;
            }
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            // std::cout << "DCAP ERROR: Error verification with non-terminal result" << std::endl;
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            std::cout << "DCAP ERROR: Error verification with terminal result" << std::endl;
            break;
    }
    ret = verification_result;
    return ret;
}

int sgxVerifyQuote(std::string base64_encoded_quote, size_t quote_size, std::string base64_encoded_collateral) {
    int ret;
    uint8_t* supplemental_data = NULL;
    uint32_t supplemental_data_size = 0;
    ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (ret) {
        std::cout << "get_quote_supplemental_data_size error!" << std::endl;
        return ret;
    }
    // Parse collateral
    uint8_t* p_quote_collateral = parseCollateral(std::move(base64_encoded_collateral));
    std::cout << "Parse collateral finished" << std::endl;
    sgx_ql_qve_collateral_t* p_quote_collateral_struct = reinterpret_cast<sgx_ql_qve_collateral_t*>(p_quote_collateral);
    
    std::vector<uint8_t> quote = base64_decode(base64_encoded_quote);
    quote_size = quote.size();
    supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    time_t current_time = time(NULL);
    uint32_t collateral_expiration_status  = 1;
    sgx_ql_qv_result_t verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    /* call into libsgx_dcap_quoteverify to verify ECDSA-based SGX quote */
    ret = sgx_qv_verify_quote((uint8_t*)(quote.data()), (uint32_t)quote_size, /*p_quote_collateral=*/p_quote_collateral_struct,
                              current_time, &collateral_expiration_status, &verification_result,
                              /*p_qve_report_info=*/NULL, supplemental_data_size,
                              supplemental_data);

    free(supplemental_data);
    freeCollateral(p_quote_collateral);
    supplemental_data = NULL;
    p_quote_collateral = NULL;
    if (ret) {
        std::cout << "DCAP ERROR: Error verify dcap quote" << std::endl;
        return ret;
    }
    switch (verification_result) {
        case SGX_QL_QV_RESULT_OK:
            if (collateral_expiration_status != 0) {
                std::cout << "WARNING: The collateral is out of date." << std::endl;
            }
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            // std::cout << "DCAP ERROR: Error verification with non-terminal result" << std::endl;
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            std::cout << "DCAP ERROR: Error verification with terminal result" << std::endl;
            break;
    }
    ret = verification_result;
    return ret;
}

int sgxVerifyQuoteBody(std::string base64_encoded_quote, std::string rpe_policies_to_verify) {
    // Get MR_ENCLAVE, MR_SIGNER, QEID and report_data from rpe_policies_to_verify
    json_t* policies_object = json_loads(rpe_policies_to_verify.c_str(), 0, NULL);

    const char *hex_encoded_mr_enclave = json_string_value(json_object_get(policies_object, "mr_enclave"));
    std::string hex_encoded_mr_enclave_string(hex_encoded_mr_enclave);
    std::vector<uint8_t> mr_enclave_bytes = HexStringToBinary(hex_encoded_mr_enclave_string);
    const char* mr_enclave = reinterpret_cast<const char*>(mr_enclave_bytes.data());

    const char *hex_encoded_mr_signer = json_string_value(json_object_get(policies_object, "mr_signer"));
    std::string hex_encoded_mr_signer_string(hex_encoded_mr_signer);
    std::vector<uint8_t> mr_signer_bytes = HexStringToBinary(hex_encoded_mr_signer_string);
    const char* mr_signer = reinterpret_cast<const char*>(mr_signer_bytes.data());

    const char *isv_prod_id = json_string_value(json_object_get(policies_object, "isv_prod_id"));
    const char *isv_svn = json_string_value(json_object_get(policies_object, "isv_svn"));

    const char *hex_encoded_report_data = json_string_value(json_object_get(policies_object, "base64_encoded_report_data"));
    std::string hex_encoded_report_data_string(hex_encoded_report_data);
    std::vector<uint8_t> report_data_bytes = base64_decode(hex_encoded_report_data_string);
    const char* report_data = reinterpret_cast<const char*>(report_data_bytes.data());
    
    const char *hex_encoded_qeid = json_string_value(json_object_get(policies_object, "qeid"));
    std::string hex_encoded_qeid_string(hex_encoded_qeid);
    std::vector<uint8_t> qeid_bytes = HexStringToBinary(hex_encoded_qeid_string);
    const char* qeid = reinterpret_cast<const char*>(qeid_bytes.data());

    std::vector<uint8_t> quote = base64_decode(base64_encoded_quote);
    sgx_quote3_t* p_quote = reinterpret_cast<sgx_quote3_t*>(quote.data());

    const bool validate_mrenclave   = true;
    const bool validate_mrsigner    = true;
    const bool validate_isv_prod_id = true;
    const bool validate_isv_svn     = true;
    const bool validate_report_data = true;
    const bool validate_qeid        = true;

    // Compare policies
    int ret = sgx_verify_quote_body(p_quote, validate_mrenclave ? mr_enclave : NULL,
                            validate_mrsigner ? mr_signer : NULL,
                            validate_isv_prod_id ? isv_prod_id : NULL,
                            validate_isv_svn ? isv_svn : NULL,
                            validate_report_data ? report_data : NULL,
                            validate_qeid ? qeid : NULL);
    if (ret) {
        std::cout << "Quote: error to verify quote body" << std::endl;
    }
    return ret;
}

int sgx_verify_quote_body(const sgx_quote3_t* p_quote, const char* mr_enclave,
                      const char* mr_signer, const char* isv_prod_id, const char* isv_svn,
                      const char* report_data, const char* qeid) {
    int ret = -1;

    sgx_quote3_t* quote = (sgx_quote3_t*)p_quote;
    sgx_report_body_t* report_body = &quote->report_body;
    sgx_quote_header_t* quote_header = &quote->header;

    sgx_measurement_t expected_mr;
    if (mr_enclave) {
        memcpy(&expected_mr, mr_enclave, sizeof(expected_mr));
        if (memcmp(&report_body->mr_enclave, &expected_mr, sizeof(expected_mr)) != 0) {
            std::cout << "Quote: mr_enclave doesn't match the expected value" << std::endl;
            return ret;
        }
    }
    
    if (mr_signer) {
        memcpy(&expected_mr, mr_signer, sizeof(expected_mr));
        if (memcmp(&report_body->mr_signer, &expected_mr, sizeof(expected_mr)) != 0) {
            std::cout << "Quote: mr_signer doesn't match the expected value" << std::endl;
            return ret;
        }
    }

    // Product ID must match, security version must be greater or equal
    if (isv_prod_id) {
        sgx_prod_id_t prod_id;
        prod_id = strtoul(isv_prod_id, NULL, UINT16_MAX);
        if (report_body->isv_prod_id != prod_id) {
            char error_msg[100];
            sprintf(error_msg, "Quote: invalid prod_id (expected %d, but %d)", prod_id, report_body->isv_prod_id);
            std::cout << error_msg << std::endl;
            return ret;
        }
    }

    if (isv_svn) {
        sgx_isv_svn_t svn;
        svn = strtoul(isv_svn, NULL, UINT16_MAX);
        if (report_body->isv_svn < svn) {
            char error_msg[100];
            sprintf(error_msg, "Quote: invalid prod_id (expected %d, but %d)", svn, report_body->isv_svn);
            std::cout << error_msg << std::endl;
            return ret;
        }
    }

    if (report_data) {
        sgx_report_data_t rd;
        memcpy(&rd, report_data, sizeof(rd));
        if (memcmp(&report_body->report_data, &rd, sizeof(rd)) != 0) {
            std::cout << "Quote: report_data doesn't match the expected value" << std::endl;
            return ret;
        }
    }

    if (qeid) {
        size_t qeid_size = 16;
        uint8_t expected_qeid[qeid_size];
        memcpy(&expected_qeid, qeid, qeid_size);
        if (memcmp(&quote_header->user_data, &expected_qeid, qeid_size) != 0) {
            std::cout << "Quote: qeid doesn't match the expected value" << std::endl;
            return ret;
        }
    }

    ret = 0;
    return ret;
}

int tdxVerifyQuoteBody(std::string base64_encoded_quote, std::string tdx_policies_to_verify) {
    // Get MR_TD, MRSIGNER and report_data from tdx_policies_to_verify
    json_t* policies_object = json_loads(tdx_policies_to_verify.c_str(), 0, NULL);

    const char *hex_encoded_mr_td = json_string_value(json_object_get(policies_object, "mr_td"));
    std::string hex_encoded_mr_td_string(hex_encoded_mr_td);
    std::vector<uint8_t> mr_td_bytes = HexStringToBinary(hex_encoded_mr_td_string);
    const char* mr_td = reinterpret_cast<const char*>(mr_td_bytes.data());

    const char *hex_encoded_mr_signer = json_string_value(json_object_get(policies_object, "mr_signer"));
    std::string hex_encoded_mr_signer_string(hex_encoded_mr_signer);
    std::vector<uint8_t> mr_signer_bytes = HexStringToBinary(hex_encoded_mr_signer_string);
    const char* mr_signer = reinterpret_cast<const char*>(mr_signer_bytes.data());

    const char *hex_encoded_report_data = json_string_value(json_object_get(policies_object, "base64_encoded_report_data"));
    std::string hex_encoded_report_data_string(hex_encoded_report_data);
    std::vector<uint8_t> report_data_bytes = base64_decode(hex_encoded_report_data_string);
    const char* report_data = reinterpret_cast<const char*>(report_data_bytes.data());
    
    // const char *hex_encoded_qeid = json_string_value(json_object_get(policies_object, "qeid"));
    // std::string hex_encoded_qeid_string(hex_encoded_qeid);
    // std::vector<uint8_t> qeid_bytes = HexStringToBinary(hex_encoded_qeid_string);
    // const char* qeid = reinterpret_cast<const char*>(qeid_bytes.data());

    std::vector<uint8_t> quote = base64_decode(base64_encoded_quote);
    sgx_quote4_t* p_quote = reinterpret_cast<sgx_quote4_t*>(quote.data());

    const bool validate_mrtd        = true;
    const bool validate_mrsigner    = false;
    const bool validate_report_data = true;
    const bool validate_qeid        = false;

    // Compare policies
    int ret = tdx_verify_quote_body(p_quote, validate_mrtd ? mr_td : NULL,
                            validate_mrsigner ? mr_signer : NULL,
                            validate_report_data ? report_data : NULL,
                            NULL);
    if (ret) {
        std::cout << "Quote: error verify quote body" << std::endl;
    }
    return ret;
}

int tdx_verify_quote_body(const sgx_quote4_t* p_quote, const char* mr_td,
                      const char* mr_signer, const char* report_data, const char* qeid) {
    int ret = -1;

    sgx_quote4_t* quote = (sgx_quote4_t*)p_quote;
    sgx_report2_body_t* report_body = &quote->report_body;
    sgx_quote4_header_t* quote_header = &quote->header;

    tee_measurement_t expected_mr;
    if (mr_td) {
        memcpy(&expected_mr, mr_td, sizeof(expected_mr));
        if (memcmp(&report_body->mr_td, &expected_mr, sizeof(expected_mr)) != 0) {
            std::cout << "Quote: mr_td doesn't match the expected value" << std::endl;
            return ret;
        }
    }
    
    if (mr_signer) {
        memcpy(&expected_mr, mr_signer, sizeof(expected_mr));
        if (memcmp(&report_body->mrsigner_seam, &expected_mr, sizeof(expected_mr)) != 0) {
            std::cout << "Quote: mr_signer doesn't match the expected value" << std::endl;
            return ret;
        }
    }

    if (report_data) {
        tee_report_data_t rd;
        memcpy(&rd, report_data, sizeof(rd));
        if (memcmp(&report_body->report_data, &rd, sizeof(rd)) != 0) {
            std::cout << "Quote: report_data doesn't match the expected value" << std::endl;
            return ret;
        }
    }

    if (qeid) {
        size_t qeid_size = 16;
        uint8_t expected_qeid[qeid_size];
        memcpy(&expected_qeid, qeid, qeid_size);
        if (memcmp(&quote_header->user_data, &expected_qeid, qeid_size) != 0) {
            std::cout << "Quote: qeid doesn't match the expected value" << std::endl;
            return ret;
        }
    }

    ret = 0;
    return ret;
}

uint8_t* parseCollateral(std::string base64_encoded_collateral) {
    // Parse collateral
    json_t* collateral_object = json_loads(base64_encoded_collateral.c_str(), 0, NULL);
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
        return NULL;
    }
    p_quote_collateral_struct->version = version;
    p_quote_collateral_struct->tee_type = tee_type;
    // printf("Assign version and type finished\n");
    char* pck_crl_issuer_chain_buffer = (char*)malloc(pck_crl_issuer_chain_size);
    base64Decode(pck_crl_issuer_chain_base64, (unsigned char*)pck_crl_issuer_chain_buffer, pck_crl_issuer_chain_size);
    p_quote_collateral_struct->pck_crl_issuer_chain = pck_crl_issuer_chain_buffer;
    // printf("Assign pck_crl_issuer_chain finished\n");
    p_quote_collateral_struct->pck_crl_issuer_chain_size = pck_crl_issuer_chain_size;

    char* root_ca_crl_buffer = (char*)malloc(root_ca_crl_size);
    base64Decode(root_ca_crl_base64, (unsigned char*)root_ca_crl_buffer, root_ca_crl_size);
    p_quote_collateral_struct->root_ca_crl = root_ca_crl_buffer;
    // printf("Assign root_ca_crl finished\n");
    p_quote_collateral_struct->root_ca_crl_size = root_ca_crl_size;

    char* pck_crl_buffer = (char*)malloc(pck_crl_size);
    base64Decode(pck_crl_base64, (unsigned char*)pck_crl_buffer, pck_crl_size);
    p_quote_collateral_struct->pck_crl = pck_crl_buffer;
    // printf("Assign pck_crl finished\n");
    p_quote_collateral_struct->pck_crl_size = pck_crl_size;
    
    char* tcb_info_issuer_chain_buffer = (char*)malloc(tcb_info_issuer_chain_size);
    base64Decode(tcb_info_issuer_chain_base64, (unsigned char*)tcb_info_issuer_chain_buffer, tcb_info_issuer_chain_size);
    p_quote_collateral_struct->tcb_info_issuer_chain = tcb_info_issuer_chain_buffer;
    // printf("Assign tcb_info_issuer_chain finished\n");
    p_quote_collateral_struct->tcb_info_issuer_chain_size = tcb_info_issuer_chain_size;
    
    char* tcb_info_buffer = (char*)malloc(tcb_info_size);
    base64Decode(tcb_info_base64, (unsigned char*)tcb_info_buffer, tcb_info_size);
    p_quote_collateral_struct->tcb_info = tcb_info_buffer;
    // printf("Assign tcb_info finished\n");
    p_quote_collateral_struct->tcb_info_size = tcb_info_size;
    
    char* qe_identity_issuer_chain_buffer = (char*)malloc(qe_identity_issuer_chain_size);
    base64Decode(qe_identity_issuer_chain_base64, (unsigned char*)qe_identity_issuer_chain_buffer, qe_identity_issuer_chain_size);
    p_quote_collateral_struct->qe_identity_issuer_chain = qe_identity_issuer_chain_buffer;
    // printf("Assign qe_identity_issuer_chain finished\n");
    p_quote_collateral_struct->qe_identity_issuer_chain_size = qe_identity_issuer_chain_size;

    char* qe_identity_buffer = (char*)malloc(qe_identity_size);
    base64Decode(qe_identity_base64, (unsigned char*)qe_identity_buffer, qe_identity_size);
    p_quote_collateral_struct->qe_identity = qe_identity_buffer;
    // printf("Assign qe_identity finished\n");
    p_quote_collateral_struct->qe_identity_size = qe_identity_size;

    uint8_t* p_quote_collateral = reinterpret_cast<uint8_t*>(p_quote_collateral_struct);

    std::cout << "Construct collateral finished" << std::endl;

    return p_quote_collateral;
}

void freeCollateral(uint8_t* p_quote_collateral) {
    sgx_ql_qve_collateral_t* p_quote_collateral_struct = reinterpret_cast<sgx_ql_qve_collateral_t*>(p_quote_collateral);
    free(p_quote_collateral_struct->pck_crl_issuer_chain);
    free(p_quote_collateral_struct->root_ca_crl);
    free(p_quote_collateral_struct->pck_crl);
    free(p_quote_collateral_struct->tcb_info_issuer_chain);
    free(p_quote_collateral_struct->tcb_info);
    free(p_quote_collateral_struct->qe_identity_issuer_chain);
    free(p_quote_collateral_struct->qe_identity);
    free(p_quote_collateral_struct);
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