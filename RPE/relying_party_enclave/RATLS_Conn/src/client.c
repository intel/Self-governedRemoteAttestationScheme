/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *               2020, Intel Labs
 */

/*
 * SSL client demonstration program (with RA-TLS).
 * This program is originally based on an mbedTLS example ssl_client1.c but uses RA-TLS flows (SGX
 * Remote Attestation flows) if RA-TLS library is required by user.
 * Note that this program builds against mbedTLS 3.x.
 */

#include "mbedtls/build_info.h"

#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define mbedtls_fprintf fprintf
#define mbedtls_printf printf

#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

/* RA-TLS: on client, only need to register ra_tls_verify_callback_der() for cert verification */
int (*ra_tls_verify_callback_der_f)(uint8_t* der_crt, size_t der_crt_size);

/* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char* mrenclave, const char* mrsigner,
                                          const char* isv_prod_id, const char* isv_svn));

/* RA-TLS: on server, only need ra_tls_create_key_and_crt_der() to create keypair and X.509 cert */
int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                       size_t* der_crt_size);
                            

// #define SERVER_PORT "4433"
// #define SERVER_NAME "192.168.122.54"
#define GET_REQUEST "  Hello RPO\r\n\r\n"

#define DEBUG_LEVEL 0

// #define CA_CRT_PATH "./ca.crt"
// #define SRV_CRT_PATH "ssl/server.crt"
// #define SRV_KEY_PATH "ssl/server.key"

static char signing_key_buf[375];
static char encryption_keys_buf[651];

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

static int parse_hex(const char* hex, void* buffer, size_t buffer_size) {
    if (strlen(hex) != buffer_size * 2)
        return -1;

    for (size_t i = 0; i < buffer_size; i++) {
        if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1]))
            return -1;
        sscanf(hex + i * 2, "%02hhx", &((uint8_t*)buffer)[i]);
    }
    return 0;
}


/* expected SGX measurements in binary form */
// static char g_expected_mrenclave[32];
// static char g_expected_mrsigner[32];
// static char g_expected_isv_prod_id[2];
// static char g_expected_isv_svn[2];

// static bool g_verify_mrenclave   = false;
// static bool g_verify_mrsigner    = false;
// static bool g_verify_isv_prod_id = false;
// static bool g_verify_isv_svn     = false;

/* RA-TLS: our own callback to verify SGX measurements */
// static int my_verify_measurements(const char* mrenclave, const char* mrsigner,
//                                   const char* isv_prod_id, const char* isv_svn) {
//     assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

//     if (g_verify_mrenclave &&
//             memcmp(mrenclave, g_expected_mrenclave, sizeof(g_expected_mrenclave)))
//         return -1;

//     if (g_verify_mrsigner &&
//             memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner)))
//         return -1;

//     if (g_verify_isv_prod_id &&
//             memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)))
//         return -1;

//     if (g_verify_isv_svn &&
//             memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn)))
//         return -1;

//     return 0;
// }

/* RA-TLS: mbedTLS-specific callback to verify the x509 certificate */
static int my_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    (void)data;

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
    return ra_tls_verify_callback_der_f(crt->raw.p, crt->raw.len);
}

static ssize_t file_read(const char* path, char* buf, size_t count) {
    FILE* f = fopen(path, "r");
    if (!f)
        return -errno;

    ssize_t bytes = fread(buf, 1, count, f);
    if (bytes <= 0) {
        int errsv = errno;
        fclose(f);
        return -errsv;
    }

    int close_ret = fclose(f);
    if (close_ret < 0)
        return -errno;

    return bytes;
}

static bool getenv_client_inside_sgx() {
    char* str = getenv("RA_TLS_CLIENT_INSIDE_SGX");
    if (!str)
        return false;

    return !strcmp(str, "1") || !strcmp(str, "true") || !strcmp(str, "TRUE");
}

void init_pubkeys(const char * signing_key, const char * encryption_keys){
    strcpy(signing_key_buf, signing_key);
    strcpy(encryption_keys_buf, encryption_keys);
}

unsigned char data[3072];
unsigned char verification_result[2048];
char *ra_tls_client(const char * hostname, const char * port) {
    int ret;
    size_t len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char* pers = "ssl_client1";
    bool in_sgx = getenv_client_inside_sgx();

    char* error;
    void* ra_tls_verify_lib           = NULL;
    ra_tls_verify_callback_der_f      = NULL;
    ra_tls_set_measurement_callback_f = NULL;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt cltcert;
    mbedtls_pk_context pkey;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&cltcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);


    // if (argc < 2 ||
    //         (strcmp(argv[1], "native") && strcmp(argv[1], "epid") && strcmp(argv[1], "dcap"))) {
    //     mbedtls_printf("USAGE: %s native|epid|dcap [SGX measurements]\n", argv[0]);
    //     return 1;
    // }

    // if (!strcmp(argv[1], "epid")) {
    //     ra_tls_verify_lib = dlopen("libra_tls_verify_epid.so", RTLD_LAZY);
    //     if (!ra_tls_verify_lib) {
    //         mbedtls_printf("%s\n", dlerror());
    //         mbedtls_printf("User requested RA-TLS verification with EPID but cannot find lib\n");
    //         if (in_sgx) {
    //             mbedtls_printf("Please make sure that you are using client_epid.manifest\n");
    //         }
    //         return 1;
    //     }
    // } else if (!strcmp(argv[1], "dcap")) 
    // {
    if (in_sgx) {
        /*
            * RA-TLS verification with DCAP inside SGX enclave uses dummies instead of real
            * functions from libsgx_urts.so, thus we don't need to load this helper library.
            */
        ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
        if (!ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
            mbedtls_printf("Please make sure that you are using client_dcap.manifest\n");
            return NULL;
        }
    } else {
        void* helper_sgx_urts_lib = dlopen("libsgx_urts.so", RTLD_NOW | RTLD_GLOBAL);
        if (!helper_sgx_urts_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find helper"
                            " libsgx_urts.so lib\n");
            return NULL;
        }

        ra_tls_verify_lib = dlopen("libra_tls_verify_dcap.so", RTLD_LAZY);
        if (!ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find lib\n");
            return NULL;
        }
    }
    // }

    if (ra_tls_verify_lib) {
        ra_tls_verify_callback_der_f = dlsym(ra_tls_verify_lib, "ra_tls_verify_callback_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return NULL;
        }

        ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return NULL;
        }
    }

    mbedtls_printf("[ using default SGX-measurement verification callback"
                    " (via RA_TLS_* environment variables) ]\n");
    (*ra_tls_set_measurement_callback_f)(NULL); /* just to test RA-TLS code */


    //=====================================================================================
    void* ra_tls_attest_lib;
    uint8_t* der_key = NULL;
    uint8_t* der_crt = NULL;
    char attestation_type_str[32] = {0};
    ret = file_read("/dev/attestation/attestation_type", attestation_type_str,
                    sizeof(attestation_type_str) - 1);
    if (ret < 0 && ret != -ENOENT) {
        mbedtls_printf("User requested RA-TLS attestation but cannot read SGX-specific file "
                       "/dev/attestation/attestation_type\n");
        return NULL;
    }

    if (ret == -ENOENT || !strcmp(attestation_type_str, "none")) {
        ra_tls_attest_lib = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    } else if (!strcmp(attestation_type_str, "epid") || !strcmp(attestation_type_str, "dcap")) {
        ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!ra_tls_attest_lib) {
            mbedtls_printf("User requested RA-TLS attestation but cannot find lib\n");
            return NULL;
        }

        char* error;
        ra_tls_create_key_and_crt_der_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return NULL;
        }
    } else {
        mbedtls_printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return NULL;
    }

    //=====================================================================================



    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    //=====================================================================================
    if (ra_tls_attest_lib) {
        mbedtls_printf("\n  . Creating the RA-TLS server cert and key (using \"%s\" as "
                       "attestation type)...", attestation_type_str);
        fflush(stdout);

        size_t der_key_size;
        size_t der_crt_size;

        ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt, &der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  ra_tls_create_key_and_crt_der returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_x509_crt_parse(&cltcert, (unsigned char*)der_crt, der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_pk_parse_key(&pkey, (unsigned char*)der_key, der_key_size, /*pwd=*/NULL, 0,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }
    //=====================================================================================

    mbedtls_printf("  . Connecting to tcp/%s/%s...", hostname, port);
    fflush(stdout);

    ret = mbedtls_net_connect(&server_fd, hostname, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_printf(" failed  ! mbedtls_net_connect returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Setting up the default SSL configuration...");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    // mbedtls_printf("  . Loading the CA root certificate ...");
    // fflush(stdout);

    // ret = mbedtls_x509_crt_parse_file(&cacert, CA_CRT_PATH);
    // if (ret < 0) {
    //     mbedtls_printf( " cacert failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret );
    //     goto exit;
    // }

    //=====================================================================================
        // mbedtls_printf("\n  . Creating normal server cert and key...");
        // fflush(stdout);
        // ret = mbedtls_x509_crt_parse_file(&cltcert, SRV_CRT_PATH);
        // if (ret != 0) {
        //     mbedtls_printf(" cltcert failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
        //     goto exit;
        // }
        // ret = mbedtls_pk_parse_keyfile(&pkey, SRV_KEY_PATH, /*password=*/NULL,
        //                                mbedtls_ctr_drbg_random, &ctr_drbg);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile returned %d\n\n", ret);
        //     goto exit;
        // }

        // mbedtls_printf(" ok\n");

    //=====================================================================================




    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    // mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    // mbedtls_printf(" ok\n");

    if (ra_tls_verify_lib) {
        /* use RA-TLS verification callback; this will overwrite CA chain set up above */
        mbedtls_printf("  . Installing RA-TLS callback ...");
        mbedtls_ssl_conf_verify(&conf, &my_verify_callback, NULL);
        mbedtls_printf(" ok\n");
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    mbedtls_printf("  . Setting up the SSL data....");
    //=====================================================================================
    ret = mbedtls_ssl_conf_own_cert(&conf, &cltcert, &pkey);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    //=====================================================================================



    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl, hostname);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }
    mbedtls_printf(" ok\n");

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            goto exit;
        }
    }

    mbedtls_printf(" ...ok\n");

    // mbedtls_printf("  . Verifying peer (rpo) X.509 certificate...");

    // flags = mbedtls_ssl_get_verify_result(&ssl);
    // if (flags != 0) {
    //     char vrfy_buf[512];
    //     mbedtls_printf(" failed\n");
    //     mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
    //     mbedtls_printf("%s\n", vrfy_buf);

    //     /* verification failed for whatever reason, fail loudly */
    //     goto exit;
    // } else {
    //     mbedtls_printf(" ok\n");
    // }

    mbedtls_printf("  > Say hello to rpo:");
    fflush(stdout);
    len = sprintf((char*)buf, GET_REQUEST);

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }
    len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s", len, (char*)buf);

    /* write public signing key to rpe */
    mbedtls_printf("  > Write signing key to rpo:");
    fflush(stdout);
    len = sizeof(signing_key_buf) - 1;
    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char *)signing_key_buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }
    len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s", len, (char*)signing_key_buf);

    /* write public encryption key to rpe */
    mbedtls_printf("  > Write encryption key to rpo:");
    fflush(stdout);
    len = sizeof(encryption_keys_buf) - 1;
    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char *)encryption_keys_buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }
    len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s", len, (char*)encryption_keys_buf);   

    mbedtls_printf("  < Read from rpo:");
    fflush(stdout);
    memset(data, 0, sizeof(data));
    do {
        len = sizeof(data) - 1;
        ret = mbedtls_ssl_read(&ssl, data, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE){
            memset(data, 0, sizeof(data));
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            mbedtls_printf("This is a test print for getting data.\n\n"); 
            break;

        if (ret < 0) {
            mbedtls_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret); 
            break;
        }

        if (ret == 0) {
            mbedtls_printf("\n\nEOF\n\n");
            break;
        }

        len = ret;
        mbedtls_printf("\n %lu bytes read\n%s", len, (char*)data);
        
        // TODO: if read data larger than buf
        
    } while (1);
    
    mbedtls_printf("  < Read result from rpo:");
    fflush(stdout);
    memset(verification_result, 0, sizeof(verification_result));
    do {
        len = sizeof(verification_result) - 1;
        ret = mbedtls_ssl_read(&ssl, verification_result, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE){
            memset(verification_result, 0, sizeof(verification_result));
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            mbedtls_printf("This is a test print for getting signed result.\n\n"); 
            break;

        if (ret < 0) {
            mbedtls_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret); 
            break;
        }

        if (ret == 0) {
            mbedtls_printf("\n\nEOF\n\n");
            break;
        }

        len = ret;
        mbedtls_printf("\n %lu bytes read\n%s", len, (char*)verification_result);
    } while (1);
 
    return (char*)data;

    mbedtls_ssl_close_notify(&ssl);
    exit_code = MBEDTLS_EXIT_SUCCESS;
exit:
#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    if (ra_tls_verify_lib)
        dlclose(ra_tls_verify_lib);

    mbedtls_net_free(&server_fd);

    mbedtls_x509_crt_free(&cltcert);
    mbedtls_pk_free(&pkey);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    free(der_key);
    free(der_crt);

    return "None";
}

char *get_verification_result(){
    return (char *)verification_result;
}

int something_client(const char * hostname, const char * port, const char * something) {
    int ret;
    size_t len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    const char* pers = "ssl_client1";
    bool in_sgx = getenv_client_inside_sgx();

    unsigned char buf[1024];
    char *buffer1;
    buffer1 = (char *)malloc(strlen(something)+1);
    memset(buffer1,0,strlen(something)+1);
    strcpy(buffer1, something);

    char* error;
    void* ra_tls_verify_lib           = NULL;
    ra_tls_verify_callback_der_f      = NULL;
    ra_tls_set_measurement_callback_f = NULL;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt cltcert;
    mbedtls_pk_context pkey;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&cltcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);

    if (in_sgx) {
        /*
            * RA-TLS verification with DCAP inside SGX enclave uses dummies instead of real
            * functions from libsgx_urts.so, thus we don't need to load this helper library.
            */
        ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
        if (!ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
            mbedtls_printf("Please make sure that you are using client_dcap.manifest\n");
            return 1;
        }
    } else {
        void* helper_sgx_urts_lib = dlopen("libsgx_urts.so", RTLD_NOW | RTLD_GLOBAL);
        if (!helper_sgx_urts_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find helper"
                            " libsgx_urts.so lib\n");
            return 1;
        }

        ra_tls_verify_lib = dlopen("libra_tls_verify_dcap.so", RTLD_LAZY);
        if (!ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find lib\n");
            return 1;
        }
    }

    if (ra_tls_verify_lib) {
        ra_tls_verify_callback_der_f = dlsym(ra_tls_verify_lib, "ra_tls_verify_callback_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return 1;
        }

        ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return 1;
        }
    }

    mbedtls_printf("[ using default SGX-measurement verification callback"
                    " (via RA_TLS_* environment variables) ]\n");
    (*ra_tls_set_measurement_callback_f)(NULL); /* just to test RA-TLS code */

    void* ra_tls_attest_lib;
    uint8_t* der_key = NULL;
    uint8_t* der_crt = NULL;
    char attestation_type_str[32] = {0};
    ret = file_read("/dev/attestation/attestation_type", attestation_type_str,
                    sizeof(attestation_type_str) - 1);
    if (ret < 0 && ret != -ENOENT) {
        mbedtls_printf("User requested RA-TLS attestation but cannot read SGX-specific file "
                       "/dev/attestation/attestation_type\n");
        return 1;
    }

    if (ret == -ENOENT || !strcmp(attestation_type_str, "none")) {
        ra_tls_attest_lib = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    } else if (!strcmp(attestation_type_str, "epid") || !strcmp(attestation_type_str, "dcap")) {
        ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!ra_tls_attest_lib) {
            mbedtls_printf("User requested RA-TLS attestation but cannot find lib\n");
            return 1;
        }

        char* error;
        ra_tls_create_key_and_crt_der_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return 1;
        }
    } else {
        mbedtls_printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return 1;
    }

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    if (ra_tls_attest_lib) {
        mbedtls_printf("\n  . Creating the RA-TLS server cert and key (using \"%s\" as "
                       "attestation type)...", attestation_type_str);
        fflush(stdout);

        size_t der_key_size;
        size_t der_crt_size;

        ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt, &der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  ra_tls_create_key_and_crt_der returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_x509_crt_parse(&cltcert, (unsigned char*)der_crt, der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_pk_parse_key(&pkey, (unsigned char*)der_key, der_key_size, /*pwd=*/NULL, 0,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }

    mbedtls_printf("  . Connecting to tcp/%s/%s...", hostname, port);
    fflush(stdout);

    ret = mbedtls_net_connect(&server_fd, hostname, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_printf(" failed  ! mbedtls_net_connect returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Setting up the default SSL configuration...");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");


    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    // mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    // mbedtls_printf(" ok\n");

    if (ra_tls_verify_lib) {
        /* use RA-TLS verification callback; this will overwrite CA chain set up above */
        mbedtls_printf("  . Installing RA-TLS callback ...");
        mbedtls_ssl_conf_verify(&conf, &my_verify_callback, NULL);
        mbedtls_printf(" ok\n");
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    mbedtls_printf("  . Setting up the SSL data....");
    ret = mbedtls_ssl_conf_own_cert(&conf, &cltcert, &pkey);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl, hostname);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }
    mbedtls_printf(" ok\n");

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            goto exit;
        }
    }

    mbedtls_printf(" ...ok\n");

    // mbedtls_printf("  . Verifying peer (rpo) X.509 certificate...");

    // flags = mbedtls_ssl_get_verify_result(&ssl);
    // if (flags != 0) {
    //     char vrfy_buf[512];
    //     mbedtls_printf(" failed\n");
    //     mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
    //     mbedtls_printf("%s\n", vrfy_buf);

    //     /* verification failed for whatever reason, fail loudly */
    //     goto exit;
    // } else {
    //     mbedtls_printf(" ok\n");
    // }

  
    /* Write something to rpo */
    mbedtls_printf("  > Write to rpo:");
    fflush(stdout);
    len = strlen(buffer1);
    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char *)buffer1, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }
    len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s\n", len, (char*)buffer1);
  
   
    mbedtls_printf("  < Read from rpo:");
    fflush(stdout);
    memset(buf, 0, sizeof(buf));
    do {
        len = sizeof(buf) - 1;
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE){
            memset(buf, 0, sizeof(buf));
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            mbedtls_printf("This is a test print for getting data.\n\n"); 
            break;

        if (ret < 0) {
            mbedtls_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret); 
            break;
        }

        if (ret == 0) {
            mbedtls_printf("\n\nEOF\n\n");
            break;
        }

        len = ret;
        mbedtls_printf("\n +_+_++_+_+_+_++_+++_+_+_+_+_+_");
        mbedtls_printf("\n %lu bytes read\n%s", len, (char*)buf);
        
        // TODO: if read data larger than buf
        
    } while (1);
 
    return 0;

    mbedtls_ssl_close_notify(&ssl);
    exit_code = MBEDTLS_EXIT_SUCCESS;
exit:
#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    if (ra_tls_verify_lib)
        dlclose(ra_tls_verify_lib);

    mbedtls_net_free(&server_fd);

    mbedtls_x509_crt_free(&cltcert);
    mbedtls_pk_free(&pkey);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    free(der_key);
    free(der_crt);

    return 1;
}
