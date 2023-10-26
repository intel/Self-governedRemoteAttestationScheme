#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "verify_dcap_quote.h"
#include "json/jsonvalue.h"
#include "json/parson.h"
#include "json/json_utils.h"
#include "error.h"
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

    // Parse collateral
    uint8_t* p_quote_collateral = parseCollateral(base64_encoded_collateral);
    std::cout << "Parse collateral finished" << std::endl;

    ByteArray quote = Base64EncodedStringToByteArray(base64_encoded_quote);
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
    uint8_t* p_quote_collateral = parseCollateral(base64_encoded_collateral);
    std::cout << "Parse collateral finished" << std::endl;
    sgx_ql_qve_collateral_t* p_quote_collateral_struct = reinterpret_cast<sgx_ql_qve_collateral_t*>(p_quote_collateral);
    
    ByteArray quote = Base64EncodedStringToByteArray(base64_encoded_quote);
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
    JsonValue policies_parsed(json_parse_string(rpe_policies_to_verify.c_str()));
    tcf::error::ThrowIfNull(
        policies_parsed.value, "failed to parse the rpe_policies_to_verify, badly formed JSON");

    JSON_Object* policies_object = json_value_get_object(policies_parsed);
    tcf::error::ThrowIfNull(policies_object, "Missing JSON object in rpe_policies_to_verify");
    std::string hex_encoded_mr_enclave = GetJsonStr(
                policies_object,
                "mr_enclave",
                "invalid policies; failed to retrieve mr_enclave");
    ByteArray mr_enclave_bytes = HexEncodedStringToByteArray(hex_encoded_mr_enclave);
    std::string mr_enclave = ByteArrayToString(mr_enclave_bytes);
    std::string hex_encoded_mr_signer = GetJsonStr(
                policies_object,
                "mr_signer",
                "invalid policies; failed to retrieve mr_signer");
    ByteArray mr_signer_bytes = HexEncodedStringToByteArray(hex_encoded_mr_signer);
    std::string mr_signer = ByteArrayToString(mr_signer_bytes);
    std::string isv_prod_id = GetJsonStr(
                policies_object,
                "isv_prod_id",
                "invalid policies; failed to retrieve isv_prod_id");
    std::string isv_svn = GetJsonStr(
                policies_object,
                "isv_svn",
                "invalid policies; failed to retrieve isv_svn");
    std::string base64_encoded_report_data = GetJsonStr(
                policies_object,
                "base64_encoded_report_data",
                "invalid policies; failed to retrieve base64_encoded_report_data");
    ByteArray report_data_bytes = Base64EncodedStringToByteArray(base64_encoded_report_data);
    std::string report_data = ByteArrayToString(report_data_bytes);
    std::string hex_encoded_qeid = GetJsonStr(
                policies_object,
                "qeid",
                "invalid policies; failed to retrieve qeid");
    ByteArray qeid_bytes = HexEncodedStringToByteArray(hex_encoded_qeid);
    std::string qeid = ByteArrayToString(qeid_bytes);

    ByteArray quote = Base64EncodedStringToByteArray(base64_encoded_quote);
    sgx_quote3_t* p_quote = reinterpret_cast<sgx_quote3_t*>(quote.data());

    bool validate_mrenclave   = true;
    bool validate_mrsigner    = true;
    bool validate_isv_prod_id = true;
    bool validate_isv_svn     = true;
    bool validate_report_data = true;
    bool validate_qeid        = true;

    // Compare policies
    int ret = sgx_verify_quote_body(p_quote, validate_mrenclave ? mr_enclave.data() : NULL,
                            validate_mrsigner ? mr_signer.data() : NULL,
                            validate_isv_prod_id ? isv_prod_id.data() : NULL,
                            validate_isv_svn ? isv_svn.data() : NULL,
                            validate_report_data ? report_data.data() : NULL,
                            validate_qeid ? qeid.data() : NULL);
    if (ret) {
        tcf::error::ThrowIf<tcf::error::ValueError>(true, "Quote: error verify quote body");
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
            tcf::error::ThrowIf<tcf::error::ValueError>(true, "Quote: mr_enclave doesn't match the expected value");
            return ret;
        }
    }
    
    if (mr_signer) {
        memcpy(&expected_mr, mr_signer, sizeof(expected_mr));
        if (memcmp(&report_body->mr_signer, &expected_mr, sizeof(expected_mr)) != 0) {
            tcf::error::ThrowIf<tcf::error::ValueError>(true, "Quote: mr_signer doesn't match the expected value");
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
            tcf::error::ThrowIf<tcf::error::ValueError>(true, error_msg);
            return ret;
        }
    }

    if (isv_svn) {
        sgx_isv_svn_t svn;
        svn = strtoul(isv_svn, NULL, UINT16_MAX);
        if (report_body->isv_svn < svn) {
            char error_msg[100];
            sprintf(error_msg, "Quote: invalid prod_id (expected %d, but %d)", svn, report_body->isv_svn);
            tcf::error::ThrowIf<tcf::error::ValueError>(true, error_msg);
            return ret;
        }
    }

    if (report_data) {
        sgx_report_data_t rd;
        memcpy(&rd, report_data, sizeof(rd));
        if (memcmp(&report_body->report_data, &rd, sizeof(rd)) != 0) {
            tcf::error::ThrowIf<tcf::error::ValueError>(true, "Quote: report_data doesn't match the expected value");
            return ret;
        }
    }

    if (qeid) {
        size_t qeid_size = 16;
        uint8_t expected_qeid[qeid_size];
        memcpy(&expected_qeid, qeid, qeid_size);
        if (memcmp(&quote_header->user_data, &expected_qeid, qeid_size) != 0) {
            tcf::error::ThrowIf<tcf::error::ValueError>(true, "Quote: qeid doesn't match the expected value");
            return ret;
        }
    }

    ret = 0;
    return ret;
}

int tdxVerifyQuoteBody(std::string base64_encoded_quote, std::string tdx_policies_to_verify) {
    // Get MR_TD, MRSIGNER and report_data from tdx_policies_to_verify
    JsonValue policies_parsed(json_parse_string(tdx_policies_to_verify.c_str()));
    tcf::error::ThrowIfNull(
        policies_parsed.value, "failed to parse the tdx_policies_to_verify, badly formed JSON");

    JSON_Object* policies_object = json_value_get_object(policies_parsed);
    tcf::error::ThrowIfNull(policies_object, "Missing JSON object in tdx_policies_to_verify");
    std::string hex_encoded_mr_td = GetJsonStr(
                policies_object,
                "mr_td",
                "invalid policies; failed to retrieve mr_td");
    ByteArray mr_td_bytes = HexEncodedStringToByteArray(hex_encoded_mr_td);
    std::string mr_td = ByteArrayToString(mr_td_bytes);
    std::string hex_encoded_mr_signer = GetJsonStr(
                policies_object,
                "mr_signer",
                "invalid policies; failed to retrieve mr_signer");
    ByteArray mr_signer_bytes = HexEncodedStringToByteArray(hex_encoded_mr_signer);
    std::string mr_signer = ByteArrayToString(mr_signer_bytes);
    std::string base64_encoded_report_data = GetJsonStr(
                policies_object,
                "base64_encoded_report_data",
                "invalid policies; failed to retrieve base64_encoded_report_data");
    ByteArray report_data_bytes = Base64EncodedStringToByteArray(base64_encoded_report_data);
    std::string report_data = ByteArrayToString(report_data_bytes);
    // std::string hex_encoded_qeid = GetJsonStr(
    //             policies_object,
    //             "qeid",
    //             "invalid policies; failed to retrieve qeid");
    // ByteArray qeid_bytes = HexEncodedStringToByteArray(hex_encoded_qeid);
    // std::string qeid = ByteArrayToString(qeid_bytes);

    ByteArray quote = Base64EncodedStringToByteArray(base64_encoded_quote);
    sgx_quote4_t* p_quote = reinterpret_cast<sgx_quote4_t*>(quote.data());

    bool validate_mrtd        = true;
    bool validate_mrsigner    = false;
    bool validate_report_data = true;
    bool validate_qeid        = false;

    // Compare policies
    int ret = tdx_verify_quote_body(p_quote, validate_mrtd ? mr_td.data() : NULL,
                            validate_mrsigner ? mr_signer.data() : NULL,
                            validate_report_data ? report_data.data() : NULL,
                            NULL);
    if (ret) {
        tcf::error::ThrowIf<tcf::error::ValueError>(true, "Quote: error verify quote body");
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
            tcf::error::ThrowIf<tcf::error::ValueError>(true, "Quote: mr_td doesn't match the expected value");
            return ret;
        }
    }
    
    if (mr_signer) {
        memcpy(&expected_mr, mr_signer, sizeof(expected_mr));
        if (memcmp(&report_body->mrsigner_seam, &expected_mr, sizeof(expected_mr)) != 0) {
            tcf::error::ThrowIf<tcf::error::ValueError>(true, "Quote: mr_signer doesn't match the expected value");
            return ret;
        }
    }

    if (report_data) {
        tee_report_data_t rd;
        memcpy(&rd, report_data, sizeof(rd));
        if (memcmp(&report_body->report_data, &rd, sizeof(rd)) != 0) {
            tcf::error::ThrowIf<tcf::error::ValueError>(true, "Quote: report_data doesn't match the expected value");
            return ret;
        }
    }

    if (qeid) {
        size_t qeid_size = 16;
        uint8_t expected_qeid[qeid_size];
        memcpy(&expected_qeid, qeid, qeid_size);
        if (memcmp(&quote_header->user_data, &expected_qeid, qeid_size) != 0) {
            tcf::error::ThrowIf<tcf::error::ValueError>(true, "Quote: qeid doesn't match the expected value");
            return ret;
        }
    }

    ret = 0;
    return ret;
}

uint8_t* parseCollateral(std::string base64_encoded_collateral) {
    // Parse collateral
    JsonValue collateral_parsed(json_parse_string(base64_encoded_collateral.c_str()));
    tcf::error::ThrowIfNull(
        collateral_parsed.value, "failed to parse the collateral, badly formed JSON");
    JSON_Object* collateral_object = json_value_get_object(collateral_parsed);
    tcf::error::ThrowIfNull(collateral_object, "Missing JSON object in collateral_parsed");
    uint32_t collateral_size = GetJsonNumber(collateral_object, "collateral_size");
    uint32_t version = GetJsonNumber(collateral_object, "version");
    uint32_t tee_type = GetJsonNumber(collateral_object, "tee_type");

    const char *pck_crl_issuer_chain_base64 = GetJsonStr(collateral_object, "pck_crl_issuer_chain", "failed to parse pck_crl_issuer_chain from collateral_object");
    std::string pck_crl_issuer_chain(pck_crl_issuer_chain_base64);
    std::vector<uint8_t> pck_crl_issuer_chain_vector = base64_decode(pck_crl_issuer_chain);
    uint32_t pck_crl_issuer_chain_size = GetJsonNumber(collateral_object, "pck_crl_issuer_chain_size");

    const char *root_ca_crl_base64 = GetJsonStr(collateral_object, "root_ca_crl", "failed to parse root_ca_crl from collateral_object");
    std::string root_ca_crl(root_ca_crl_base64);
    std::vector<uint8_t> root_ca_crl_vector = base64_decode(root_ca_crl);
    uint32_t root_ca_crl_size = GetJsonNumber(collateral_object, "root_ca_crl_size");

    const char *pck_crl_base64 = GetJsonStr(collateral_object, "pck_crl", "failed to parse pck_crl from collateral_object");
    std::string pck_crl(pck_crl_base64);
    std::vector<uint8_t> pck_crl_vector = base64_decode(pck_crl);
    uint32_t pck_crl_size = GetJsonNumber(collateral_object, "pck_crl_size");

    const char *tcb_info_issuer_chain_base64 = GetJsonStr(collateral_object, "tcb_info_issuer_chain", "failed to parse tcb_info_issuer_chain from collateral_object");
    std::string tcb_info_issuer_chain(tcb_info_issuer_chain_base64);
    std::vector<uint8_t> tcb_info_issuer_chain_vector = base64_decode(tcb_info_issuer_chain);
    uint32_t tcb_info_issuer_chain_size = GetJsonNumber(collateral_object, "tcb_info_issuer_chain_size");

    const char *tcb_info_base64 = GetJsonStr(collateral_object, "tcb_info", "failed to parse tcb_info from collateral_object");
    std::string tcb_info(tcb_info_base64);
    std::vector<uint8_t> tcb_info_vector = base64_decode(tcb_info);
    uint32_t tcb_info_size = GetJsonNumber(collateral_object, "tcb_info_size");

    const char *qe_identity_issuer_chain_base64 = GetJsonStr(collateral_object, "qe_identity_issuer_chain", "failed to parse qe_identity_issuer_chain from collateral_object");
    std::string qe_identity_issuer_chain(qe_identity_issuer_chain_base64);
    std::vector<uint8_t> qe_identity_issuer_chain_vector = base64_decode(qe_identity_issuer_chain);
    uint32_t qe_identity_issuer_chain_size = GetJsonNumber(collateral_object, "qe_identity_issuer_chain_size");
    
    const char *qe_identity_base64 = GetJsonStr(collateral_object, "qe_identity", "failed to parse qe_identity from collateral_object");
    std::string qe_identity(qe_identity_base64);
    std::vector<uint8_t> qe_identity_vector = base64_decode(qe_identity);
    uint32_t qe_identity_size = GetJsonNumber(collateral_object, "qe_identity_size");

    // Construct p_quote_collater
    std::cout << "Collateral size: " << collateral_size <<  std::endl;
    sgx_ql_qve_collateral_t* p_quote_collateral_struct = (sgx_ql_qve_collateral_t*)malloc(sizeof(sgx_ql_qve_collateral_t));
    if (p_quote_collateral_struct == NULL) {
        std::cout << "Allocate p_quote_collateral_struct failed" << std::endl;
        return NULL;
    }
    p_quote_collateral_struct->version = version;
    p_quote_collateral_struct->tee_type = tee_type;
    // std::cout << "Assign version and type finished" << std::endl;
    char* pck_crl_issuer_chain_buffer = (char*)malloc(pck_crl_issuer_chain_size);
    memcpy((void*)pck_crl_issuer_chain_buffer, (const void*)(pck_crl_issuer_chain_vector.data()), pck_crl_issuer_chain_size);
    p_quote_collateral_struct->pck_crl_issuer_chain = pck_crl_issuer_chain_buffer;
    // std::cout << "Assign pck_crl_issuer_chain finished" << std::endl;
    p_quote_collateral_struct->pck_crl_issuer_chain_size = pck_crl_issuer_chain_size;

    char* root_ca_crl_buffer = (char*)malloc(root_ca_crl_size);
    memcpy((void*)root_ca_crl_buffer, (const void*)(root_ca_crl_vector.data()), root_ca_crl_size);
    p_quote_collateral_struct->root_ca_crl = root_ca_crl_buffer;
    // std::cout << "Assign root_ca_crl finished" << std::endl;
    p_quote_collateral_struct->root_ca_crl_size = root_ca_crl_size;

    char* pck_crl_buffer = (char*)malloc(pck_crl_size);
    memcpy((void*)pck_crl_buffer, (const void*)(pck_crl_vector.data()), pck_crl_size);
    p_quote_collateral_struct->pck_crl = pck_crl_buffer;
    // std::cout << "Assign pck_crl finished" << std::endl;
    p_quote_collateral_struct->pck_crl_size = pck_crl_size;
    
    char* tcb_info_issuer_chain_buffer = (char*)malloc(tcb_info_issuer_chain_size);
    memcpy((void*)tcb_info_issuer_chain_buffer, (const void*)(tcb_info_issuer_chain_vector.data()), tcb_info_issuer_chain_size);
    p_quote_collateral_struct->tcb_info_issuer_chain = tcb_info_issuer_chain_buffer;
    // std::cout << "Assign tcb_info_issuer_chain finished" << std::endl;
    p_quote_collateral_struct->tcb_info_issuer_chain_size = tcb_info_issuer_chain_size;
    
    char* tcb_info_buffer = (char*)malloc(tcb_info_size);
    memcpy((void*)tcb_info_buffer, (const void*)(tcb_info_vector.data()), tcb_info_size);
    p_quote_collateral_struct->tcb_info = tcb_info_buffer;
    // std::cout << "Assign tcb_info finished" << std::endl;
    p_quote_collateral_struct->tcb_info_size = tcb_info_size;
    
    char* qe_identity_issuer_chain_buffer = (char*)malloc(qe_identity_issuer_chain_size);
    memcpy((void*)qe_identity_issuer_chain_buffer, (const void*)(qe_identity_issuer_chain_vector.data()), qe_identity_issuer_chain_size);
    p_quote_collateral_struct->qe_identity_issuer_chain = qe_identity_issuer_chain_buffer;
    // std::cout << "Assign qe_identity_issuer_chain finished" << std::endl;
    p_quote_collateral_struct->qe_identity_issuer_chain_size = qe_identity_issuer_chain_size;

    char* qe_identity_buffer = (char*)malloc(qe_identity_size);
    memcpy((void*)qe_identity_buffer, (const void*)(qe_identity_vector.data()), qe_identity_size);
    p_quote_collateral_struct->qe_identity = qe_identity_buffer;
    // std::cout << "Assign qe_identity finished" << std::endl;
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