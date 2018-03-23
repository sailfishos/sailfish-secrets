/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "evp_p.h"

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

        // TODO: figure out what is needed in openssl 1.1.0 instead of OPENSSL_config,
        //       see https://github.com/sailfishos/sailfish-secrets/issues/34 for discussion.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        OPENSSL_config(NULL);
#pragma GCC diagnostic pop

        initialized += 1;
    }
    return initialized;
}

/*
    int osslevp_pkcs5_pbkdf2_hmac(const char *pass,
                                  int passlen,
                                  const unsigned char *salt,
                                  int saltlen,
                                  int iter,
                                  int digestFunction,
                                  int keylen,
                                  unsigned char *out)

    Derive a key from input data via PKCS5_PBKDF2 key derivation
    using HMAC with a digest function specified by the client.

    Returns 1 on success, 0 on failure.
 */
int osslevp_pkcs5_pbkdf2_hmac(const char *pass, int passlen,
                              const unsigned char *salt, int saltlen,
                              int iter, int digestFunction,
                              int keylen, unsigned char *out)
{
    const EVP_MD *md = 0;

    // see CryptoManager::DigestFunction
    switch (digestFunction) {
        case 10: md = EVP_sha1(); break;
        case 21: md = EVP_sha256(); break;
        case 23: md = EVP_sha512(); break;
        default: md = EVP_sha256(); break;
    }

    return PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen,
                             iter, md, keylen, out);
}

/*
    int osslevp_aes_encrypt_plaintext(const EVP_CIPHER *evp_cipher,
                                      const unsigned char *init_vector,
                                      const unsigned char *key,
                                      int key_length,
                                      const unsigned char *plaintext,
                                      int plaintext_length,
                                      unsigned char **encrypted)

    Encrypts the \a plaintext of the specified \a plaintext_length with the
    given symmetric encryption \a key, using the specified cipher. The result
    is stored in \a encrypted. The caller owns the content of the
    \a encrypted buffer and must free().

    The given \a init_vector must be a 16 byte buffer containing the
    initialisation vector for the AES encryption context.

    Returns the length of the \a encrypted output on success, or -1 if the
    arguments are invalid or encryption otherwise fails.
*/
int osslevp_aes_encrypt_plaintext(const EVP_CIPHER *evp_cipher,
                                  const unsigned char *init_vector,
                                  const unsigned char *key,
                                  int key_length,
                                  const unsigned char *plaintext,
                                  int plaintext_length,
                                  unsigned char **encrypted)
{
    int ciphertext_length = plaintext_length + AES_BLOCK_SIZE;
    int update_length = 0;
    int final_length = 0;
    unsigned char *ciphertext = NULL;

    if (evp_cipher == NULL || plaintext_length <= 0 || plaintext == NULL
            || key_length <= 0 || key == NULL || encrypted == NULL) {
        /* Invalid arguments */
        fprintf(stderr, "%s\n", "invalid arguments, aborting encryption");
        return -1;
    }

    /* Allocate the buffer for the encrypted output */
    ciphertext = (unsigned char *)malloc(ciphertext_length);
    memset(ciphertext, 0, ciphertext_length);

    /* Create the encryption context */
    EVP_CIPHER_CTX *encryption_context = EVP_CIPHER_CTX_new();

    if (!EVP_EncryptInit_ex(encryption_context, evp_cipher, NULL, key, init_vector)) {
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
    int osslevp_aes_decrypt_ciphertext(const EVP_CIPHER *evp_cipher,
                                       const unsigned char *init_vector,
                                       const unsigned char *key,
                                       int key_length,
                                       const unsigned char *ciphertext,
                                       int ciphertext_length,
                                       unsigned char **decrypted)

    Decrypts the \a ciphertext of the specified \a ciphertext_length with the
    given symmetric decryption \a key, using the specified \a evp_cipher. The
    result is stored in \a encrypted. The caller owns the content of the
    \a decrypted buffer and must free().

    The given \a init_vector must be a 16 byte buffer containing the
    initialisation vector for the AES decryption context.

    Returns the length of the \a decrypted output on success, or -1 if the
    arguments are invalid or decryption otherwise fails.
*/
int osslevp_aes_decrypt_ciphertext(const EVP_CIPHER *evp_cipher,
                                   const unsigned char *init_vector,
                                   const unsigned char *key,
                                   int key_length,
                                   const unsigned char *ciphertext,
                                   int ciphertext_length,
                                   unsigned char **decrypted)
{
    int plaintext_length = 0;
    int update_length = 0;
    int final_length = 0;
    unsigned char *plaintext = NULL;

    if (evp_cipher == NULL || ciphertext_length <= 0 || ciphertext == NULL
            || key_length <= 0 || key == NULL || decrypted == NULL) {
        /* Invalid arguments */
        fprintf(stderr,
                "%s: %s\n",
                "osslevp_aes_decrypt_ciphertext()",
                "invalid arguments, aborting decryption");
        return -1;
    }

    /* Allocate the buffer for the decrypted output */
    plaintext = (unsigned char *)malloc(ciphertext_length + AES_BLOCK_SIZE);
    memset(plaintext, 0, ciphertext_length + AES_BLOCK_SIZE);

    /* Create the decryption context */
    EVP_CIPHER_CTX *decryption_context = EVP_CIPHER_CTX_new();

    if (!EVP_DecryptInit_ex(decryption_context, evp_cipher, NULL, key, init_vector)) {
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
    int osslevp_digest(const EVP_MD *digestFunc,
                       const void *bytes,
                       size_t bytesCount,
                       uint8_t **digest,
                       size_t *digestLength)

    Implements digests according to:
    https://wiki.openssl.org/index.php/EVP_Message_Digests

    Arguments:
    * digestFunc: should be the result of an EVP function, eg. EVP_sha256()
    * bytes: data to digest
    * bytesCount: the number of bytes in 'bytes'
    * digest: where the generated digest will be stored, which will have to be freed using OPENSSL_free
    * digestLength: where the length of the generated digest will be stored

    Return value:
    * 1 when the operation was successful.
    * less than 0 when there was an error.
 */
int osslevp_digest(const EVP_MD *digestFunc,
                   const void *bytes,
                   size_t bytesCount,
                   uint8_t **digest,
                   size_t *digestLength)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to allocate memory for MD context");
        return -1;
    }

    int r = EVP_DigestInit_ex(mdctx, digestFunc, NULL);
    if (r != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_destroy(mdctx);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to initialise Digest");
        return -1;
    }

    r = EVP_DigestUpdate(mdctx, bytes, bytesCount);
    if (r != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_destroy(mdctx);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to update Digest");
        return -1;
    }

    *digestLength = EVP_MD_size(digestFunc);
    *digest = (uint8_t *) OPENSSL_malloc(*digestLength);
    if (!digest) {
        EVP_MD_CTX_destroy(mdctx);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to allocate memory for digest");
        return -1;
    }

    unsigned int actualDigestLength = 0;
    r = EVP_DigestFinal_ex(mdctx, *digest, &actualDigestLength);
    if (r != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_destroy(mdctx);
        OPENSSL_free(*digest);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to finalize DigestSign (2nd call)");
        return -1;
    }

    // Set correct length to the output argument
    *digestLength = actualDigestLength;

    EVP_MD_CTX_destroy(mdctx);
    return 1;
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
    if (!mdctx) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to allocate memory for MD context");
        return -1;
    }

    int r = EVP_DigestSignInit(mdctx, NULL, digestFunc, NULL, pkey);
    if (r != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_destroy(mdctx);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to initialise DigestSign");
        return -1;
    }

    r = EVP_DigestSignUpdate(mdctx, bytes, bytesCount);
    if (r != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_destroy(mdctx);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to update DigestSign");
        return -1;
    }

    r = EVP_DigestSignFinal(mdctx, NULL, signatureLength);
    if (r != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_destroy(mdctx);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to finalize DigestSign (1st call)");
        return -1;
    }

    *signature = (uint8_t *) OPENSSL_malloc(*signatureLength);
    if (!signature) {
        EVP_MD_CTX_destroy(mdctx);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to allocate memory for signature");
        return -1;
    }

    r = EVP_DigestSignFinal(mdctx, *signature, signatureLength);
    if (r != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_destroy(mdctx);
        OPENSSL_free(*signature);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to finalize DigestSign (2nd call)");
        return -1;
    }

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
    if (!mdctx) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to allocate memory for MD context");
        return -1;
    }

    int r = EVP_DigestVerifyInit(mdctx, NULL, digestFunc, NULL, pkey);
    if (r != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_destroy(mdctx);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to initialise DigestVerify");
        return -1;
    }

    r = EVP_DigestVerifyUpdate(mdctx, bytes, bytesCount);
    if (r != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_destroy(mdctx);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to update DigestVerify");
        return -1;
    }

    r = EVP_DigestVerifyFinal(mdctx, signature, signatureLength);
    if (r < 0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_destroy(mdctx);
        fprintf(stderr,
                "%s: %s\n",
                __FUNCTION__,
                "failed to finalize DigestVerify");
        return r;
    }

    EVP_MD_CTX_destroy(mdctx);
    return r;
}
