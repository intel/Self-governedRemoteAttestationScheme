#pragma once

#include <sstream>
#include "sgx_dcap_quoteverify.h"
#include "sgx_quote_4.h"

int teeVerifyQuote(std::string base64_encoded_quote, size_t quote_size, std::string base64_encoded_collateral);
int sgxVerifyQuote(std::string base64_encoded_quote, size_t quote_size, std::string base64_encoded_collateral);
int sgxVerifyQuoteBody(std::string base64_encoded_quote, std::string rpe_policies_to_verify);
int sgx_verify_quote_body(const sgx_quote3_t* p_quote, const char* mr_enclave,
                      const char* mr_signer, const char* isv_prod_id, const char* isv_svn,
                      const char* report_data, const char* qeid);
int tdxVerifyQuoteBody(std::string base64_encoded_quote, std::string tdx_policies_to_verify);
int tdx_verify_quote_body(const sgx_quote4_t* p_quote, const char* mr_td,
                      const char* mr_signer, const char* report_data, const char* qeid);
uint8_t* parseCollateral(std::string base64_encoded_collateral);
void freeCollateral(uint8_t* p_quote_collateral);
int base64Decode(const char* input, unsigned char* output, int size);