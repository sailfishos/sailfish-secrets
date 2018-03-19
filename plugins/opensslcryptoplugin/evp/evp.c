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

const EVP_CIPHER *osslevp_aes_cipher(int block_mode, int key_length_bytes)
{
    if (block_mode == 3) {  // Sailfish::Crypto::CryptoManager::BlockModeCbc == 3
        switch (key_length_bytes * 8) {
        case 128:
            return EVP_aes_128_cbc();
        case 192:
            return EVP_aes_192_cbc();
        case 256:
            return EVP_aes_256_cbc();
        default:
            fprintf(stderr, "%s: %d\n", "unsupported encryption size for CBC block mode", (key_length_bytes * 8));
            return NULL;
        }
    }

    fprintf(stderr, "%s\n", "unsupported encryption mode");
    return NULL;
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
    int osslevp_aes_encrypt_plaintext(int block_mode,
                                      const unsigned char *init_vector,
                                      const unsigned char *key,
                                      int key_length,
                                      const unsigned char *plaintext,
                                      int plaintext_length,
                                      unsigned char **encrypted)

    Encrypts the \a plaintext of the specified \a plaintext_length with the
    given symmetric encryption \a key, using the specified encryption
    \a block_mode. The result is stored in \a encrypted.
    The caller owns the content of the \a encrypted buffer and must free().

    The given \a init_vector must be a 16 byte buffer containing the
    initialisation vector for the AES encryption context.

    Only the first 32 bytes of \a key will be used.  If \a key_length is less
    than 32, a 32 byte key will be created from the first \a key_length bytes
    of \a key padded out to 32 bytes with null bytes.

    Returns the length of the \a encrypted output on success, or -1 if the
    arguments are invalid or encryption otherwise fails.
*/
int osslevp_aes_encrypt_plaintext(int block_mode,
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

    if (plaintext_length <= 0 || plaintext == NULL
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

    const EVP_CIPHER *evp_cipher = osslevp_aes_cipher(block_mode, key_length);
    if (evp_cipher == NULL) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        fprintf(stderr, "%s\n", "failed to create cipher");
        return -1;
    }

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
    int osslevp_aes_decrypt_ciphertext(int block_mode,
                                       const unsigned char *init_vector,
                                       const unsigned char *key,
                                       int key_length,
                                       const unsigned char *ciphertext,
                                       int ciphertext_length,
                                       unsigned char **decrypted)

    Decrypts the \a ciphertext of the specified \a ciphertext_length with the
    given symmetric decryption \a key, using the specified encryption
    \a block_mode. The result is stored in \a encrypted.
    The caller owns the content of the \a decrypted buffer and must free().

    The given \a init_vector must be a 16 byte buffer containing the
    initialisation vector for the AES decryption context.

    Only the first 32 bytes of \a key will be used.  If \a key_length is less
    than 32, a 32 byte key will be created from the first \a key_length bytes
    of \a key padded out to 32 bytes with null bytes.

    Returns the length of the \a decrypted output on success, or -1 if the
    arguments are invalid or decryption otherwise fails.
*/
int osslevp_aes_decrypt_ciphertext(int block_mode,
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

    if (ciphertext_length <= 0 || ciphertext == NULL
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

    const EVP_CIPHER *cipher = osslevp_aes_cipher(block_mode, key_length);
    if (cipher == NULL) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decryption_context);
        free(plaintext);
        fprintf(stderr, "%s\n", "failed to create cipher");
        return -1;
    }

    if (!EVP_DecryptInit_ex(decryption_context, cipher, NULL, key, init_vector)) {
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
