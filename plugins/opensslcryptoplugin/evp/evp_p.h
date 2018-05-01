/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHCRYPTO_PLUGIN_CRYPTO_OPENSSL_EVP_P_H
#define SAILFISHCRYPTO_PLUGIN_CRYPTO_OPENSSL_EVP_P_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

namespace OpenSslEvp {

int init();
void cleanup();

int pkcs5_pbkdf2_hmac(const char *pass, int passlen,
                      const unsigned char *salt, int saltlen,
                      int iter, int digestFunction,
                      int keylen, unsigned char *out);

int aes_encrypt_plaintext(const EVP_CIPHER *evp_cipher,
                          const unsigned char *init_vector,
                          const unsigned char *key,
                          int key_length,
                          const unsigned char *plaintext,
                          int plaintext_length,
                          unsigned char **encrypted);

int aes_decrypt_ciphertext(const EVP_CIPHER *evp_cipher,
                           const unsigned char *init_vector,
                           const unsigned char *key,
                           int key_length,
                           const unsigned char *ciphertext,
                           int ciphertext_length,
                           unsigned char **decrypted);


int aes_auth_encrypt_plaintext(const EVP_CIPHER *evp_cipher,
                               const unsigned char *init_vector,
                               int init_vector_length,
                               const unsigned char *key,
                               int key_length,
                               const unsigned char *auth,
                               int auth_length,
                               const unsigned char *plaintext,
                               int plaintext_length,
                               unsigned char **encrypted,
                               unsigned char **authenticationTag,
                               int authenticationTag_length);

int aes_auth_decrypt_ciphertext(const EVP_CIPHER *evp_cipher,
                                const unsigned char *init_vector,
                                int init_vector_length,
                                const unsigned char *key,
                                int key_length,
                                const unsigned char *auth,
                                int auth_length,
                                unsigned char *authenticationTag,
                                int authenticationTag_length,
                                const unsigned char *ciphertext,
                                int ciphertext_length,
                                unsigned char **decrypted,
                                int *verified);

int pkey_encrypt_plaintext(EVP_PKEY *pkey,
                           int padding,
                           const unsigned char *plaintext,
                           size_t plaintext_length,
                           uint8_t **encrypted,
                           size_t *encrypted_length);

int pkey_decrypt_ciphertext(EVP_PKEY *pkey,
                            int padding,
                            const unsigned char *ciphertext,
                            size_t ciphertext_length,
                            uint8_t **decrypted,
                            size_t *decrypted_length);

int digest(const EVP_MD *digestFunc,
           const void *bytes,
           size_t bytesCount,
           uint8_t **digest,
           size_t *digestLength);

int sign(const EVP_MD *digestFunc,
         EVP_PKEY *pkey,
         const void *bytes,
         size_t bytesCount,
         uint8_t **signature,
         size_t *signatureLength);

int verify(const EVP_MD *digestFunc,
           EVP_PKEY *pkey,
           const void *bytes,
           size_t bytesCount,
           const uint8_t *signature,
           size_t signatureLength);

int generate_ec_key(int curveNid,
                    uint8_t **publicKeyBytes,
                    size_t *publicKeySize,
                    uint8_t **privateKeyBytes,
                    size_t *privateKeySize);

bool key_is_rsa(EVP_PKEY *pkey);

} // OpenSslEvp

#endif // SAILFISHCRYPTO_PLUGIN_CRYPTO_OPENSSL_EVP_P_H
