#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <string.h>

void main(void);
ENGINE *init_engine(ENGINE *e);
EVP_PKEY *load_key(EVP_PKEY *key, ENGINE *e);
X509 *load_cert(X509 *cert);
EVP_PKEY *load_pubkey(X509 *cert);
EVP_MD_CTX *init_ctx_sign(EVP_MD_CTX *ctx, ENGINE *e);
EVP_MD_CTX *init_ctx_verify(EVP_MD_CTX *ctx, ENGINE *e);
void sig_verify(void);
void enc_dec(void);
EVP_CIPHER_CTX *init_ctx_enc(EVP_CIPHER_CTX *ctx, unsigned char **ek, int *ekl, EVP_PKEY *key);
EVP_CIPHER_CTX *init_ctx_dec(EVP_CIPHER_CTX *ctx, unsigned char *ek, int ekl, EVP_PKEY *key);