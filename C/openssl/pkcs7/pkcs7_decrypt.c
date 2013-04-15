#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/err.h>


int main()
{
    EVP_PKEY *key;
    FILE *fp;
    BIO *bio;
    PKCS7 *p7;
    X509 *cert;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    fp = fopen("privkey.pem", "r");
    key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    fp = fopen("cert.pem", "r");
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    bio = BIO_new_file("data.txt.enc", "r");
    p7 = d2i_PKCS7_bio(bio, NULL);
    BIO_free(bio);

    ERR_print_errors_fp(stdout);
    bio = BIO_new_file("data.txt.dec", "w");
    PKCS7_decrypt(p7, key, cert, bio, 0);
    BIO_flush(bio);
    BIO_free(bio);

    ERR_print_errors_fp(stdout);

    return 0;
}
