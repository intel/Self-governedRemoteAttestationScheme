#include <stdlib.h>
#include <vector>
#include <string>
#include <string.h>
#include <assert.h>
#include <fstream>
#include <iostream>
#include <exception>
#include <openssl/sha.h>
#include <jansson.h>
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"
#include "base64.h"

#define PATHSIZE 0x418U

using namespace std;

vector<uint8_t> readBinaryContent(const string& filePath)
{
    ifstream file(filePath, ios::binary);
    if (!file.is_open())
    {
        printf("Error: Unable to open quote file %s\n", filePath.c_str());
        return {};
    }

    file.seekg(0, ios_base::end);
    streampos fileSize = file.tellg();

    file.seekg(0, ios_base::beg);
    vector<uint8_t> retVal(fileSize);
    file.read(reinterpret_cast<char*>(retVal.data()), fileSize);
    file.close();
    return retVal;
}

void computeDegist(const char* str, int size){
    uint8_t hash[SHA384_DIGEST_LENGTH];

    SHA512_CTX sha384;
    SHA384_Init(&sha384);
    SHA384_Update(&sha384, str, size);
    SHA384_Final(hash, &sha384);
    vector<uint8_t> hash_bytes(hash, hash + SHA384_DIGEST_LENGTH);
    string base64_hash = base64_encode(hash_bytes);
    cout << "collateral hash: " << base64_hash << endl;
}

void get_collateral(vector<uint8_t> quote) {
    const uint8_t *p_quote = quote.data();
    uint8_t* p_quote_collateral = NULL;
    uint32_t p_collateral_size;

    int dcap_ret = tee_qv_get_collateral(p_quote, (uint32_t)quote.size(), &p_quote_collateral, &p_collateral_size);
    cout << endl;
    cout << "collateral size: " << p_collateral_size << endl;
    cout << "ret: " << dcap_ret << endl;
    cout << "quote_size: " << quote.size() << endl;

    // Get collateral items and transform to base64 encode
    sgx_ql_qve_collateral_t*  p_quote_collateral_struct = reinterpret_cast<sgx_ql_qve_collateral_t*>(p_quote_collateral);
    uint32_t version = p_quote_collateral_struct->version;
    uint32_t tee_type = p_quote_collateral_struct->tee_type;
    char *pck_crl_issuer_chain = p_quote_collateral_struct->pck_crl_issuer_chain;
    uint32_t pck_crl_issuer_chain_size = p_quote_collateral_struct->pck_crl_issuer_chain_size;
    char *root_ca_crl = p_quote_collateral_struct->root_ca_crl;
    uint32_t root_ca_crl_size = p_quote_collateral_struct->root_ca_crl_size;
    char *pck_crl = p_quote_collateral_struct->pck_crl;
    uint32_t pck_crl_size = p_quote_collateral_struct->pck_crl_size;
    char *tcb_info_issuer_chain = p_quote_collateral_struct->tcb_info_issuer_chain;
    uint32_t tcb_info_issuer_chain_size = p_quote_collateral_struct->tcb_info_issuer_chain_size;
    char *tcb_info = p_quote_collateral_struct->tcb_info;
    uint32_t tcb_info_size = p_quote_collateral_struct->tcb_info_size;
    char *qe_identity_issuer_chain = p_quote_collateral_struct->qe_identity_issuer_chain;
    uint32_t qe_identity_issuer_chain_size = p_quote_collateral_struct->qe_identity_issuer_chain_size;
    char *qe_identity = p_quote_collateral_struct->qe_identity;
    uint32_t qe_identity_size = p_quote_collateral_struct->qe_identity_size;

    // Transform and save collateral
    json_t* collateral_json_obj = json_object();
    json_object_set_new(collateral_json_obj, "collateral_size", json_integer(p_collateral_size));
    json_object_set_new(collateral_json_obj, "version", json_integer(version));
    json_object_set_new(collateral_json_obj, "tee_type", json_integer(tee_type));

    vector<uint8_t> pck_crl_issuer_chain_vector(pck_crl_issuer_chain, pck_crl_issuer_chain + pck_crl_issuer_chain_size);
    string pck_crl_issuer_chain_base64 = base64_encode(pck_crl_issuer_chain_vector);
    json_object_set_new(collateral_json_obj, "pck_crl_issuer_chain", json_string(pck_crl_issuer_chain_base64.c_str()));
    json_object_set_new(collateral_json_obj, "pck_crl_issuer_chain_size", json_integer(pck_crl_issuer_chain_size));

    vector<uint8_t> root_ca_crl_vector(root_ca_crl, root_ca_crl + root_ca_crl_size);
    string root_ca_crl_base64 = base64_encode(root_ca_crl_vector);
    json_object_set_new(collateral_json_obj, "root_ca_crl", json_string(root_ca_crl_base64.c_str()));
    json_object_set_new(collateral_json_obj, "root_ca_crl_size", json_integer(root_ca_crl_size));

    vector<uint8_t> pck_crl_vector(pck_crl, pck_crl + pck_crl_size);
    string pck_crl_base64 = base64_encode(pck_crl_vector);
    json_object_set_new(collateral_json_obj, "pck_crl", json_string(pck_crl_base64.c_str()));
    json_object_set_new(collateral_json_obj, "pck_crl_size", json_integer(pck_crl_size));

    vector<uint8_t> tcb_info_issuer_chain_vector(tcb_info_issuer_chain, tcb_info_issuer_chain + tcb_info_issuer_chain_size);
    string tcb_info_issuer_chain_base64 = base64_encode(tcb_info_issuer_chain_vector);
    json_object_set_new(collateral_json_obj, "tcb_info_issuer_chain", json_string(tcb_info_issuer_chain_base64.c_str()));
    json_object_set_new(collateral_json_obj, "tcb_info_issuer_chain_size", json_integer(tcb_info_issuer_chain_size));

    vector<uint8_t> tcb_info_vector(tcb_info, tcb_info + tcb_info_size);
    string tcb_info_base64 = base64_encode(tcb_info_vector);
    json_object_set_new(collateral_json_obj, "tcb_info", json_string(tcb_info_base64.c_str()));
    json_object_set_new(collateral_json_obj, "tcb_info_size", json_integer(tcb_info_size));

    vector<uint8_t> qe_identity_issuer_chain_vector(qe_identity_issuer_chain, qe_identity_issuer_chain + qe_identity_issuer_chain_size);
    string qe_identity_issuer_chain_base64 = base64_encode(qe_identity_issuer_chain_vector);
    json_object_set_new(collateral_json_obj, "qe_identity_issuer_chain", json_string(qe_identity_issuer_chain_base64.c_str()));
    json_object_set_new(collateral_json_obj, "qe_identity_issuer_chain_size", json_integer(qe_identity_issuer_chain_size));

    vector<uint8_t> qe_identity_vector(qe_identity, qe_identity + qe_identity_size);
    string qe_identity_base64 = base64_encode(qe_identity_vector);
    json_object_set_new(collateral_json_obj, "qe_identity", json_string(qe_identity_base64.c_str()));
    json_object_set_new(collateral_json_obj, "qe_identity_size", json_integer(qe_identity_size));

    const char* collateral_json_string = json_dumps(collateral_json_obj, 0);
    json_decref(collateral_json_obj);
    uint32_t collateral_json_size = strlen(collateral_json_string);

    FILE* fptr0 = fopen("collateral.dat", "w");
    if (!fptr0) {
        printf("Cannot open collateral.dat\n");
        return;
    }
    // fputs((char*)p_quote_collateral, fptr0);
    fwrite(collateral_json_string, collateral_json_size, 1, fptr0);
    fclose(fptr0);

    // Compute SHA384 of collateral
    computeDegist(collateral_json_string, collateral_json_size);

    // for(int i = 0;i < serialized_buffer.size() - 1;++i) {
    //     cout << serialized_buffer[i];
    // }
}

int main() {
    vector<uint8_t> quote;

    char quote_path[PATHSIZE] = "quote.dat";

    //read quote from file
    //
    quote = readBinaryContent(quote_path);
    if (quote.empty()) {
        return -1;
    }

    printf("Info: ECDSA quote path: %s\n", quote_path);

    get_collateral(std::move(quote));

    printf("\n");

    return 0;
}