Small code examples
=====================

This repository keeps small code examples of various scripts.
Feel free to use any of this code for your own purpose, but be aware that many examples are poorly documented and not well coded.
They can still be of help, if you want to see some real applications of these functions.

C
=====================

OpenSSL
---------------------

Available examples:
* EVP interface

### EVP interface
Makes use of the OpenSSL EVP interface. In addition it uses the engine interface to load a key from the CAPI engine. It basically signs and verifies as well as encrypts and decrypts using an X509 certificate (its public key) from the file system and a private key loaded from the engine (CAPI in this case). It signs/encrypts "Hello World!" and verifies/decrypts it directly after.
The purpose of this intially was to test functionalities of the Engine.


