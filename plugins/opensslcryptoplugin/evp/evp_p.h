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

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#ifdef __cplusplus
extern "C" {
#endif

int osslevp_init();

const EVP_CIPHER *osslevp_aes_cipher(int block_mode, int key_length_bytes);

int osslevp_pkcs5_pbkdf2_hmac(const char *pass, int passlen,
                              const unsigned char *salt, int saltlen,
                              int iter, int digestFunction,
                              int keylen, unsigned char *out);

int osslevp_aes_encrypt_plaintext(int block_mode,
                                  const unsigned char *init_vector,
                                  const unsigned char *key,
                                  int key_length,
                                  const unsigned char *plaintext,
                                  int plaintext_length,
                                  unsigned char **encrypted);

int osslevp_aes_decrypt_ciphertext(int block_mode,
                                   const unsigned char *init_vector,
                                   const unsigned char *key,
                                   int key_length,
                                   const unsigned char *ciphertext,
                                   int ciphertext_length,
                                   unsigned char **decrypted);

int osslevp_digest(const EVP_MD *digestFunc,
                 const void *bytes,
                 size_t bytesCount,
                 uint8_t **digest,
                 size_t *digestLength);

int osslevp_sign(const EVP_MD *digestFunc,
                 EVP_PKEY *pkey,
                 const void *bytes,
                 size_t bytesCount,
                 uint8_t **signature,
                 size_t *signatureLength);

int osslevp_verify(const EVP_MD *digestFunc,
                   EVP_PKEY *pkey,
                   const void *bytes,
                   size_t bytesCount,
                   const uint8_t *signature,
                   size_t signatureLength);

#ifdef __cplusplus
}
#endif

#endif // SAILFISHCRYPTO_PLUGIN_CRYPTO_OPENSSL_EVP_P_H
