PKCS#7 encrypt/decrypt sample
=============================

Create private key:

    openssl genrsa -out privkey.pem

Create self signed cert:

    openssl req -out csr.pem -key privkey.pem -new
    openssl x509 -req -days 365 -in csr.pem -signkey privkey.pem -out cert.pem

Create some data to be enc'ed:

    echo "Hello World!" > data.txt

Compile both programs:

    gcc -o pkcs7_encrypt -O3 -Wall  -lcrypto pkcs7_encrypt.c
    gcc -o pkcs7_decrypt -O3 -Wall  -lcrypto pkcs7_decrypt.c

Then run them

    ./pkcs7_encrypt && ./pkcs7_decrypt && cat data.txt.dec
