#include "main.h"

void main(void) {
    sig_verify();
    enc_dec();
    exit(0);
}

ENGINE *init_engine(ENGINE *e) {
	ENGINE_load_builtin_engines();
	ENGINE_load_dynamic();
    e = ENGINE_by_id("dynamic");
    if(ENGINE_ctrl_cmd_string(e, "SO_PATH", "capi", 0) == 0) {
        ERR_print_errors_fp(stderr);
        exit(255);
    }

    if(ENGINE_ctrl_cmd_string(e, "LIST_ADD", "1", 0) == 0) {
		ERR_print_errors_fp(stderr);
		exit(255);
	}

    if(ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0) == 0) {
        ERR_print_errors_fp(stderr);
		exit(255);
    }

    if(ENGINE_set_default(e, ENGINE_METHOD_ALL) == 0) {
        ERR_print_errors_fp(stderr);
		exit(255);
    }

    if(ENGINE_init(e) == 0) {
        ERR_print_errors_fp(stderr);
		exit(255);
    }

    if(!ENGINE_ctrl(e, (ENGINE_CMD_BASE + 2), 2, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
		exit(255);
    }

    if(!ENGINE_ctrl(e, (ENGINE_CMD_BASE + 3), 0, "capi.log", NULL)) {
        ERR_print_errors_fp(stderr);
		exit(255);
    }

    return e;
}

EVP_PKEY *load_key(EVP_PKEY *key, ENGINE *e) {
    key = ENGINE_load_private_key(e, "MyTestCertificate", NULL, NULL);
    return key;
}

X509 *load_cert(X509 *cert) {
    FILE *file;
    char *filename = "cert001-cert.pem";
    
    if(!(file = fopen(filename, "r"))) {
        fprintf(stderr, "Cannot open certificate %s\n", filename);
        exit(255);
    }

    if(!PEM_read_X509(file, &cert, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
        exit(255);
    }

    return cert;
}

EVP_PKEY *load_pubkey(X509 *cert) {
    return X509_get_pubkey(cert);
}

EVP_MD_CTX *init_ctx_sign(EVP_MD_CTX *ctx, ENGINE *e) {
    ctx = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX));
    EVP_MD_CTX_init(ctx);
    if(EVP_SignInit_ex(ctx, EVP_md5(), e) == 0) {
        ERR_print_errors_fp(stderr);
        exit(255);
    }
    return ctx;
}

EVP_MD_CTX *init_ctx_verify(EVP_MD_CTX *ctx, ENGINE *e) {
    ctx = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX));
    EVP_MD_CTX_init(ctx);
    if(EVP_VerifyInit_ex(ctx, EVP_md5(), e) == 0) {
        ERR_print_errors_fp(stderr);
        exit(255);
    }
    return ctx;
}

void sig_verify() {
	ENGINE *e = NULL;
    EVP_PKEY *key = NULL, *pubkey = NULL;
    X509 *cert = NULL;
    EVP_MD_CTX *sigctx = NULL, *verctx = NULL;
    char *data = "Hello World!";
    unsigned char *sig = NULL;
    unsigned int *siglen;

    e = init_engine(e);
    key = load_key(key, e);
    cert = load_cert(cert);
    pubkey = load_pubkey(cert);
    sigctx = init_ctx_sign(sigctx, NULL);
    verctx = init_ctx_verify(verctx, NULL);

    EVP_SignUpdate(sigctx, (void *) data, strlen(data));
    sig = (unsigned char *)malloc(EVP_PKEY_size(key));
    memset(sig, 0, EVP_PKEY_size(key));
    siglen = (unsigned int *)malloc(sizeof(int));
    memset(siglen, 0, sizeof(int));
    if(EVP_SignFinal(sigctx, sig, siglen, key) == 0) {
        ERR_print_errors_fp(stderr);
        exit(255);
    }

    EVP_VerifyUpdate(verctx, data, strlen(data));
    if(EVP_VerifyFinal(verctx, sig, *siglen, pubkey) != 1) {
        ERR_print_errors_fp(stderr);
        exit(255);
    } else {
        printf("Verification successful!\n");
    }

    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(key);
    X509_free(cert);
    free((void *) sig);
    free((void *) siglen);
    free((void *)sigctx);
    free((void *)verctx);
    ENGINE_free(e);
}

void enc_dec() {
	ENGINE *e = NULL;
    EVP_PKEY *key = NULL, *pubkey = NULL;
    X509 *cert = NULL;
    unsigned char *data = "Hello World!";
    unsigned char **pubkeys = NULL;
    unsigned char **ek = NULL;
    int *ekl, outl = 0, datal = 12;
    EVP_CIPHER_CTX *encctx = NULL, *decctx = NULL;
    unsigned char *out;

    e = init_engine(e);
    key = load_key(key, e);
    cert = load_cert(cert);
    pubkey = load_pubkey(cert);
    
    ek = (unsigned char **)malloc(sizeof(unsigned char *));
    ekl = (int *)malloc(sizeof(int));
    encctx = init_ctx_enc(encctx, ek, ekl, key);

    out = (unsigned char *)malloc(EVP_CIPHER_CTX_block_size(encctx) + strlen(data));
    memset(out, 0, EVP_CIPHER_CTX_block_size(encctx) + strlen(data));
    EVP_SealUpdate(encctx, out, &outl, data, strlen(data));
    EVP_SealFinal(encctx, out, &outl);

    decctx = init_ctx_dec(decctx, ek[0], ekl[0], key);
    data = (unsigned char *)malloc(outl);
    memset(data, 0, outl);
    EVP_OpenUpdate(decctx, data, &datal, out, outl);
    EVP_OpenFinal(decctx, data, &datal);

    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(key);
    X509_free(cert);
    ENGINE_free(e);
}

EVP_CIPHER_CTX *init_ctx_enc(EVP_CIPHER_CTX *ctx, unsigned char **ek, int *ekl, EVP_PKEY *key) {
    EVP_PKEY **keys;

    ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
    keys = (EVP_PKEY **) malloc(sizeof(EVP_PKEY *));
    keys[0] = key;
    ek[0] = (unsigned char *) malloc(EVP_PKEY_size(keys[0]));
    if(EVP_SealInit(ctx, EVP_aes_256_ecb(), ek, ekl, NULL, keys, 1) == 0) {
        ERR_print_errors_fp(stderr);
        exit(255);
    }

    return ctx;
}

EVP_CIPHER_CTX *init_ctx_dec(EVP_CIPHER_CTX *ctx, unsigned char *ek, int ekl, EVP_PKEY *key) {

    ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
    if(EVP_OpenInit(ctx, EVP_aes_256_ecb(), ek, ekl, NULL, key) == 0) {
        ERR_print_errors_fp(stderr);
        exit(255);
    }
    return ctx;
}