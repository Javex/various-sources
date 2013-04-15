#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/err.h>


int main()
{
    STACK_OF(X509) *certs;
    FILE *fp;
    BIO *bio;
    PKCS7 *p7;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    certs = sk_X509_new_null();
    fp = fopen("cert.pem", "r");
    sk_X509_push(certs, PEM_read_X509(fp, NULL, NULL, NULL));
    fclose(fp);

    bio = BIO_new_file("data.txt", "r");
    p7 = PKCS7_encrypt(certs, bio, EVP_des_ede3_cbc(), 0);
    BIO_free(bio);

    bio = BIO_new_file("data.txt.enc", "w");
    i2d_PKCS7_bio(bio, p7);
    BIO_flush(bio);
    BIO_free(bio);

    ERR_print_errors_fp(stdout);
    return 0;
}
