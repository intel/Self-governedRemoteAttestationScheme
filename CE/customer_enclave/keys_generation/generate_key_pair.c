#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ec.h>


// Generate secp384r1 ECDSA key pair
void generate_ecdsa_keypair(char** private_pem, char** public_pem) {
    EC_KEY* ecdsa = EC_KEY_new_by_curve_name(NID_secp384r1);

    // Generate key pair
    EC_KEY_generate_key(ecdsa);

    // Export private key and public key to PEM format
    BIO* private_bio = BIO_new(BIO_s_mem());
    BIO* public_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_ECPrivateKey(private_bio, ecdsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(public_bio, ecdsa);

    BUF_MEM* private_mem = NULL;
    BIO_get_mem_ptr(private_bio, &private_mem);
    *private_pem = (char*)malloc(private_mem->length + 1);
    memcpy(*private_pem, private_mem->data, private_mem->length);
    (*private_pem)[private_mem->length] = '\0';

    BUF_MEM* public_mem = NULL;
    BIO_get_mem_ptr(public_bio, &public_mem);
    *public_pem = (char*)malloc(public_mem->length + 1);
    memcpy(*public_pem, public_mem->data, public_mem->length);
    (*public_pem)[public_mem->length] = '\0';

    // Release resource
    EC_KEY_free(ecdsa);
    BIO_free_all(private_bio);
    BIO_free_all(public_bio);
}

// Generate RSA3072 key pair
void generate_rsa_keypair(char** private_pem, char** public_pem) {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    int bits = 3072;
    unsigned long e = RSA_F4;

    // Generate key pair
    BN_set_word(bn, e);
    RSA_generate_key_ex(rsa, bits, bn, NULL);

    // Export private key and public key to PEM format
    BIO* private_bio = BIO_new(BIO_s_mem());
    BIO* public_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(private_bio, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSA_PUBKEY(public_bio, rsa);

    BUF_MEM* private_mem = NULL;
    BIO_get_mem_ptr(private_bio, &private_mem);
    *private_pem = (char*)malloc(private_mem->length + 1);
    memcpy(*private_pem, private_mem->data, private_mem->length);
    (*private_pem)[private_mem->length] = '\0';

    BUF_MEM* public_mem = NULL;
    BIO_get_mem_ptr(public_bio, &public_mem);
    *public_pem = (char*)malloc(public_mem->length + 1);
    memcpy(*public_pem, public_mem->data, public_mem->length);
    (*public_pem)[public_mem->length] = '\0';

    // Release resource
    RSA_free(rsa);
    BN_free(bn);
    BIO_free_all(private_bio);
    BIO_free_all(public_bio);
}