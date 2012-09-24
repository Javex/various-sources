Small code examples
=====================

This repository keeps small code examples of various scripts.
Feel free to use any of this code for your own purpose, but be aware that many 
examples are poorly documented and not well coded. They can still be of help, 
if you want to see some real applications of these functions.

C
=====================

OpenSSL
---------------------

Available examples:
* EVP interface
* Engine configuration

### EVP interface
Makes use of the OpenSSL EVP interface. In addition it uses the engine interface 
to load a key from the CAPI engine. It basically signs and verifies as well as 
encrypts and decrypts using an X509 certificate (its public key) from the file 
system and a private key loaded from the engine (CAPI in this case). It 
signs/encrypts "Hello World!" and verifies/decrypts it directly after. The 
purpose of this intially was to test functionalities of the Engine.

### Engine configuration
An engine for OpenSSL can be loaded either dynamically from the command line or 
with a configuration file. This shows an example of using a configuration file.
Refer to the configuration file for further documentation


Tools
=====

Available examples:
* Certreq

### Certreq
Certreq is a Microsoft tool to create certificate signing requests (CSRs) and 
private keys. This provides an example configuration with documentation. Pay
attention to the parts marked with Note or Warning as they contain information
that is not available in the original documentation (or hidden in other
documentation outside of the Certreq documentation itself).