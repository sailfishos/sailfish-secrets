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

#define OSSLEVP_CHECK_RESULT(check, freestuff, message) if (check) { ERR_print_errors_fp(stderr); freestuff; fprintf(stderr, "%s: %s\n", __FUNCTION__, message); return -1; }

#ifdef __cplusplus
extern "C" {
#endif

/*
    int osslevp_init()

    Initializes the OpenSSL engine for encryption and decryption.
    Returns 1 on success, 0 on failure.
 */
int osslevp_init()
{
    static int initialized;
    if (initialized < 1) {
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OPENSSL_config(NULL);
        initialized += 1;
    }
    return initialized;
}

/*
    int osslevp_aes_encrypt_plaintext(const unsigned char *init_vector,
                                      const unsigned char *key,
                                      int key_length,
                                      const unsigned char *plaintext,
                                      int plaintext_length,
                                      unsigned char **encrypted)

    Encrypts the \a plaintext of the specified \a plaintext_length with the
    given symmetric encryption \a key.  The result is stored in \a encrypted.
    The caller owns the content of the \a encrypted buffer and must free().

    The given \a init_vector must be a 16 byte buffer containing the
    initialisation vector for the AES encryption context.

    Only the first 32 bytes of \a key will be used.  If \a key_length is less
    than 32, a 32 byte key will be created from the first \a key_length bytes
    of \a key padded out to 32 bytes with null bytes.

    Returns the length of the \a encrypted output on success, or -1 if the
    arguments are invalid or encryption otherwise fails.
*/
int osslevp_aes_encrypt_plaintext(const unsigned char *init_vector,
                                  const unsigned char *key,
                                  int key_length,
                                  const unsigned char *plaintext,
                                  int plaintext_length,
                                  unsigned char **encrypted)
{
    unsigned char padded_key[32] = { 0 };
    int ciphertext_length = plaintext_length + AES_BLOCK_SIZE;
    int update_length = 0;
    int final_length = 0;
    int i = 0;
    unsigned char *ciphertext = NULL;

    if (plaintext_length <= 0 || plaintext == NULL
            || key_length <= 0 || key == NULL || encrypted == NULL) {
        /* Invalid arguments */
        fprintf(stderr, "%s\n", "invalid arguments, aborting encryption");
        return -1;
    }

    /* Create a 32-byte padded-key from the key */
    for (i = 0; i < 32; ++i) {
        if (i < key_length) {
            padded_key[i] = key[i];
        } else {
            padded_key[i] = '\0';
        }
    }

    /* Allocate the buffer for the encrypted output */
    ciphertext = (unsigned char *)malloc(ciphertext_length);
    memset(ciphertext, 0, ciphertext_length);

    /* Create the encryption context */
    EVP_CIPHER_CTX *encryption_context = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(encryption_context, EVP_aes_256_cbc(), NULL, padded_key, init_vector)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        fprintf(stderr, "%s\n", "failed to initialize encryption context");
        return -1;
    }

    /* Encrypt the plaintext into the encrypted output buffer */
    if (!EVP_EncryptUpdate(encryption_context, ciphertext, &update_length, plaintext, plaintext_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        fprintf(stderr, "%s\n", "failed to update ciphertext buffer with encrypted content");
        return -1;
    }

    if (!EVP_EncryptFinal_ex(encryption_context, ciphertext+update_length, &final_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        fprintf(stderr, "%s\n", "failed to encrypt final block");
        return -1;
    }

    /* Update the out parameter */
    *encrypted = ciphertext;

    /* Clean up the encryption context */
    EVP_CIPHER_CTX_free(encryption_context);
    ciphertext_length = update_length + final_length;
    return ciphertext_length;
}

/*
    int osslevp_aes_decrypt_ciphertext(const unsigned char *init_vector,
                                       const unsigned char *key,
                                       int key_length,
                                       const unsigned char *ciphertext,
                                       int ciphertext_length,
                                       unsigned char **decrypted)

    Decrypts the \a ciphertext of the specified \a ciphertext_length with the
    given symmetric decryption \a key.  The result is stored in \a decrypted.
    The caller owns the content of the \a decrypted buffer and must free().

    The given \a init_vector must be a 16 byte buffer containing the
    initialisation vector for the AES decryption context.

    Only the first 32 bytes of \a key will be used.  If \a key_length is less
    than 32, a 32 byte key will be created from the first \a key_length bytes
    of \a key padded out to 32 bytes with null bytes.

    Returns the length of the \a decrypted output on success, or -1 if the
    arguments are invalid or decryption otherwise fails.
*/
int osslevp_aes_decrypt_ciphertext(const unsigned char *init_vector,
                                   const unsigned char *key,
                                   int key_length,
                                   const unsigned char *ciphertext,
                                   int ciphertext_length,
                                   unsigned char **decrypted)
{
    unsigned char padded_key[32] = { 0 };
    int plaintext_length = 0;
    int update_length = 0;
    int final_length = 0;
    int i = 0;
    unsigned char *plaintext = NULL;

    if (ciphertext_length <= 0 || ciphertext == NULL
            || key_length <= 0 || key == NULL || decrypted == NULL) {
        /* Invalid arguments */
        fprintf(stderr,
                "%s: %s\n",
                "osslevp_aes_decrypt_ciphertext()",
                "invalid arguments, aborting decryption");
        return -1;
    }

    /* Create a 32-byte padded-key from the key */
    for (i = 0; i < 32; ++i) {
        if (i < key_length) {
            padded_key[i] = key[i];
        } else {
            padded_key[i] = '\0';
        }
    }

    /* Allocate the buffer for the decrypted output */
    plaintext = (unsigned char *)malloc(ciphertext_length + AES_BLOCK_SIZE);
    memset(plaintext, 0, ciphertext_length + AES_BLOCK_SIZE);

    /* Create the decryption context */
    EVP_CIPHER_CTX *decryption_context = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(decryption_context, EVP_aes_256_cbc(), NULL, padded_key, init_vector)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decryption_context);
        free(plaintext);
        fprintf(stderr,
                "%s: %s\n",
                "osslevp_aes_decrypt_ciphertext()",
                "failed to initialize decryption context");
        return -1;
    }

    /* Decrypt the ciphertext into the decrypted output buffer */
    if (!EVP_DecryptUpdate(decryption_context, plaintext, &update_length, ciphertext, ciphertext_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decryption_context);
        free(plaintext);
        fprintf(stderr,
                "%s: %s\n",
                "osslevp_aes_decrypt_ciphertext()",
                "failed to update plaintext buffer with decrypted content");
        return -1;
    }

    if (!EVP_DecryptFinal_ex(decryption_context, plaintext+update_length, &final_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decryption_context);
        free(plaintext);
        fprintf(stderr,
                "%s: %s\n",
                "osslevp_aes_decrypt_ciphertext()",
                "failed to decrypt final block: key failure");
        return -1;
    }

    /* Update the out parameter */
    *decrypted = plaintext;

    /* Clean up the decryption context */
    EVP_CIPHER_CTX_free(decryption_context);
    plaintext_length = update_length + final_length;
    return plaintext_length;
}

/*
    int osslevp_sign(const EVP_MD *digestFunc,
                     EVP_PKEY *pkey,
                     const void *bytes,
                     size_t bytesCount,
                     uint8_t **signature,
                     size_t *signatureLength)

    Implements signing according to:
    https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying

    Arguments:
    * digestFunc: should be the result of an EVP function, eg. EVP_sha256()
    * pkey: the private key used for signing
    * bytes: data to sign
    * bytesCount: the number of bytes in 'bytes'
    * signature: where the generated signature will be stored, which will have to be freed using OPENSSL_free
    * signatureLength: where the length of the generated signature will be stored

    Return value:
    * 1 when the operation was successful.
    * less than 0 when there was an error.
 */
int osslevp_sign(const EVP_MD *digestFunc,
                 EVP_PKEY *pkey,
                 const void *bytes,
                 size_t bytesCount,
                 uint8_t **signature,
                 size_t *signatureLength)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

    int r = EVP_DigestSignInit(mdctx, NULL, digestFunc, NULL, pkey);
    OSSLEVP_CHECK_RESULT(r != 1, EVP_MD_CTX_destroy(mdctx), "failed call to EVP_DigestSignInit.");

    r = EVP_DigestSignUpdate(mdctx, bytes, bytesCount);
    OSSLEVP_CHECK_RESULT(r != 1, EVP_MD_CTX_destroy(mdctx), "failed call to EVP_DigestSignUpdate.");

    r = EVP_DigestSignFinal(mdctx, NULL, signatureLength);
    OSSLEVP_CHECK_RESULT(r != 1, EVP_MD_CTX_destroy(mdctx), "failed first call to EVP_DigestSignFinal.");

    *signature = (uint8_t *) OPENSSL_malloc(*signatureLength);
    OSSLEVP_CHECK_RESULT(*signature, EVP_MD_CTX_destroy(mdctx), "failed to allocate memory for signature.");

    r = EVP_DigestSignFinal(mdctx, *signature, signatureLength);
    OSSLEVP_CHECK_RESULT(r != 1, EVP_MD_CTX_destroy(mdctx), "failed second call to EVP_DigestSignFinal.");

    EVP_MD_CTX_destroy(mdctx);
    return 1;
}

/*
    int osslevp_verify(const EVP_MD *digestFunc,
                       EVP_PKEY *pkey,
                       const void *bytes,
                       size_t bytesCount,
                       const uint8_t *signature,
                       size_t signatureLength)

    Verifies a signature according to:
    https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying

    Arguments:
    * digestFunc: should be the result of an EVP function, eg. EVP_sha256()
    * pkey: the public key used for verification (pair of the private key used for signing)
    * bytes: data whose signature must be verified
    * bytesCount: the number of bytes in 'bytes'
    * signature: the signature which needs to be verified
    * signatureLength: byte length of the signature to be verified

    Return value:
    * 1 when the operation was successful and the signature is correct.
    * 0 when the operation was successful but the signature is NOT correct.
    * less than 0 when there was an error and the operation was unsuccessful.
 */
int osslevp_verify(const EVP_MD *digestFunc,
                   EVP_PKEY *pkey,
                   const void *bytes,
                   size_t bytesCount,
                   const uint8_t *signature,
                   size_t signatureLength)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

    int r = EVP_DigestVerifyInit(mdctx, NULL, digestFunc, NULL, pkey);
    OSSLEVP_CHECK_RESULT(r != 1, EVP_MD_CTX_destroy(mdctx), "failed call to EVP_DigestSignInit.");

    r = EVP_DigestVerifyUpdate(mdctx, bytes, bytesCount);
    OSSLEVP_CHECK_RESULT(r != 1, EVP_MD_CTX_destroy(mdctx), "failed call to EVP_DigestVerifyUpdate.");

    r = EVP_DigestVerifyFinal(mdctx, signature, signatureLength);
    EVP_MD_CTX_destroy(mdctx);
    return r;
}

#ifdef __cplusplus
}
#endif

#endif // SAILFISHCRYPTO_PLUGIN_CRYPTO_OPENSSL_EVP_P_H
