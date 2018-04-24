/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "evp_p.h"

#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

#include <QtCore/QMutex>
#include <QtCore/QVector>
#include <QtCore/QThread>
#include <QtCore/QHash>

#define OSSLEVP_PRINT_ERR(message) \
    fprintf(stderr, "%s#%d, %s: %s\n", __FILE__, __LINE__, __FUNCTION__, message);

#define OSSLEVP_HANDLE_ERR(condition, result, message, labelname) \
    if (condition) {                 \
        ERR_print_errors_fp(stderr); \
        OSSLEVP_PRINT_ERR(message);  \
        result;                      \
        goto labelname;              \
    }

// Below code is for the old threading API before OpenSSL 1.1
// explanation: https://www.openssl.org/blog/blog/2017/02/21/threads/
#if OPENSSL_VERSION_NUMBER < 0x10100000L

static QVector<QMutex*> s_mutexes;

extern "C" {

static void qthreads_locking_callback(int mode, int type, const char * /* file */, int /* line */)
{
    if (mode & CRYPTO_LOCK) {
        QMutex *mutex = s_mutexes.value(type);
        if (mutex) {
            mutex->lock();
        } else {
            fprintf(stderr, "OpenSslEvp: locking callback: no mutex for type %i\n", type);
        }
    } else {
        QMutex *mutex = s_mutexes.value(type);
        if (mutex) {
            mutex->unlock();
        } else {
            fprintf(stderr, "OpenSslEvp: unlocking callback: no mutex for type %i\n", type);
        }
    }
}

static unsigned long qthreads_thread_id()
{
    QThread *thread = QThread::currentThread();
    unsigned long retn = qHash(thread);
    return retn;
}

} /* extern "C" */


#endif // OPENSSL_VERSION_NUMBER < 0x10100000L

/*
    int OpenSslEvp::init()

    Initializes the OpenSSL engine for encryption and decryption.
    Returns 1 on success, 0 on failure.
 */
int OpenSslEvp::init()
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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        while (s_mutexes.size() < CRYPTO_num_locks()) {
            s_mutexes.append(new QMutex);
        }
        CRYPTO_set_id_callback(qthreads_thread_id);
        CRYPTO_set_locking_callback(qthreads_locking_callback);
#endif

        initialized += 1;
    }
    return initialized;
}

/*
    void OpenSslEvp::cleanup()

    Cleans up memory which was allocated during initialization.
 */
void OpenSslEvp::cleanup()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    qDeleteAll(s_mutexes);
    s_mutexes.clear();
#endif
}

/*
    int OpenSslEvp::pkcs5_pbkdf2_hmac(const char *pass,
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
int OpenSslEvp::pkcs5_pbkdf2_hmac(const char *pass, int passlen,
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
    int OpenSslEvp::aes_encrypt_plaintext(const EVP_CIPHER *evp_cipher,
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
    initialization vector for the AES encryption context.

    Returns the length of the \a encrypted output on success, or -1 if the
    arguments are invalid or encryption otherwise fails.
*/
int OpenSslEvp::aes_encrypt_plaintext(const EVP_CIPHER *evp_cipher,
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
    int OpenSslEvp::aes_decrypt_ciphertext(const EVP_CIPHER *evp_cipher,
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
    initialization vector for the AES decryption context.

    Returns the length of the \a decrypted output on success, or -1 if the
    arguments are invalid or decryption otherwise fails.
*/
int OpenSslEvp::aes_decrypt_ciphertext(const EVP_CIPHER *evp_cipher,
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
                "OpenSslEvp::aes_decrypt_ciphertext()",
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
                "OpenSslEvp::aes_decrypt_ciphertext()",
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
                "OpenSslEvp::aes_decrypt_ciphertext()",
                "failed to update plaintext buffer with decrypted content");
        return -1;
    }

    if (!EVP_DecryptFinal_ex(decryption_context, plaintext+update_length, &final_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decryption_context);
        free(plaintext);
        fprintf(stderr,
                "%s: %s\n",
                "OpenSslEvp::aes_decrypt_ciphertext()",
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

int OpenSslEvp::aes_auth_encrypt_plaintext(const EVP_CIPHER *evp_cipher,
                                           const unsigned char *init_vector,
                                           int init_vector_length,
                                           const unsigned char *key,
                                           int key_length,
                                           const unsigned char *auth,
                                           int auth_length,
                                           const unsigned char *plaintext,
                                           int plaintext_length,
                                           unsigned char **encrypted,
                                           unsigned char **tag,
                                           int tag_length)
{
    int ciphertext_length = plaintext_length + AES_BLOCK_SIZE;
    int update_length = 0;
    int final_length = 0;
    const int cipher_mode = EVP_CIPHER_mode(evp_cipher);
    unsigned char *ciphertext = NULL;
    unsigned char *tag_output = NULL;

    if (evp_cipher == NULL || plaintext_length <= 0 || plaintext == NULL
            || auth == NULL || auth_length <= 0
            || key_length <= 0 || key == NULL || encrypted == NULL || tag_length <= 0) {
        /* Invalid arguments */
        fprintf(stderr, "%s\n", "invalid arguments, aborting encryption");
        return -1;
    }

    /* Allocate the buffer for the encrypted output */
    ciphertext = (unsigned char *)malloc(ciphertext_length);
    memset(ciphertext, 0, ciphertext_length);

    tag_output = (unsigned char *)malloc(tag_length);
    memset(tag_output, 0, tag_length);

    /* Create the encryption context */
    EVP_CIPHER_CTX *encryption_context = EVP_CIPHER_CTX_new();

    /* Initialize the encryption operation. */
    if (!EVP_EncryptInit_ex(encryption_context, evp_cipher, NULL, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        free(tag_output);
        fprintf(stderr, "%s\n", "failed to initialize encryption context");
        return -1;
    }

    /* Set IV length */
    if ( (cipher_mode == EVP_CIPH_GCM_MODE
            && !EVP_CIPHER_CTX_ctrl(encryption_context, EVP_CTRL_GCM_SET_IVLEN, init_vector_length, NULL))
         || (cipher_mode == EVP_CIPH_CCM_MODE
             && !EVP_CIPHER_CTX_ctrl(encryption_context, EVP_CTRL_CCM_SET_IVLEN, init_vector_length, NULL)) ) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        free(tag_output);
        fprintf(stderr, "%s\n", "failed to set IV length");
        return -1;
    }

    /* For CCM, set tag length */
    if (cipher_mode == EVP_CIPH_CCM_MODE
            && !EVP_CIPHER_CTX_ctrl(encryption_context, EVP_CTRL_CCM_SET_TAG, tag_length, NULL)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        free(tag_output);
        fprintf(stderr, "%s\n", "failed to set authentication tag length");
        return -1;
    }

    /* Initialize key and IV */
    if (!EVP_EncryptInit_ex(encryption_context, NULL, NULL, key, init_vector)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        free(tag_output);
        fprintf(stderr, "%s\n", "failed to initialize encryption context");
        return -1;
    }

    /* For CCM, provide the total plaintext length */
    if (cipher_mode == EVP_CIPH_CCM_MODE
            && !EVP_EncryptUpdate(encryption_context, NULL, &update_length, NULL, plaintext_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        free(tag_output);
        fprintf(stderr, "%s\n", "failed to set plaintext length");
        return -1;
    }

    /* Provide auth data */
    if (!EVP_EncryptUpdate(encryption_context, NULL, &update_length, auth, auth_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        free(tag_output);
        fprintf(stderr, "%s\n", "failed to set authentication data");
        return -1;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * For CCM, EVP_EncryptUpdate can only be called once for this.
     */
    if (!EVP_EncryptUpdate(encryption_context, ciphertext, &update_length, plaintext, plaintext_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        free(tag_output);
        fprintf(stderr, "%s\n", "failed to update ciphertext buffer with encrypted content");
        return -1;
    }

    /* Finalize the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM/CCM mode
     */
    if (!EVP_EncryptFinal_ex(encryption_context, ciphertext+update_length, &final_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        free(tag_output);
        fprintf(stderr, "%s\n", "failed to encrypt final block");
        return -1;
    }

    /* Get the tag */
    if ( (cipher_mode == EVP_CIPH_GCM_MODE
          && !EVP_CIPHER_CTX_ctrl(encryption_context, EVP_CTRL_GCM_GET_TAG, tag_length, tag_output))
          || (cipher_mode == EVP_CIPH_CCM_MODE
              && !EVP_CIPHER_CTX_ctrl(encryption_context, EVP_CTRL_CCM_GET_TAG, tag_length, tag_output)) ) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(encryption_context);
        free(ciphertext);
        free(tag_output);
        fprintf(stderr, "%s\n", "failed to get tag");
        return -1;
    }

    /* Update the out parameter */
    *encrypted = ciphertext;
    *tag = tag_output;

    /* Clean up the encryption context */
    EVP_CIPHER_CTX_free(encryption_context);
    ciphertext_length = update_length + final_length;

    return ciphertext_length;
}

int OpenSslEvp::aes_auth_decrypt_ciphertext(const EVP_CIPHER *evp_cipher,
                                            const unsigned char *init_vector,
                                            int init_vector_length,
                                            const unsigned char *key,
                                            int key_length,
                                            const unsigned char *auth,
                                            int auth_length,
                                            unsigned char *tag,
                                            int tag_length,
                                            const unsigned char *ciphertext,
                                            int ciphertext_length,
                                            unsigned char **decrypted,
                                            int *verified)
{
    int plaintext_length = 0;
    int update_length = 0;
    int final_length = 0;
    int last_update_result = 0;
    const int cipher_mode = EVP_CIPHER_mode(evp_cipher);
    unsigned char *plaintext = NULL;

    if (evp_cipher == NULL || ciphertext_length <= 0 || ciphertext == NULL
            || auth == NULL || auth_length <= 0 || tag == NULL || tag_length <= 0
            || key_length <= 0 || key == NULL || decrypted == NULL || verified == NULL) {
        /* Invalid arguments */
        fprintf(stderr,
                "%s: %s\n",
                "OpenSslEvp::aes_auth_decrypt_ciphertext()",
                "invalid arguments, aborting decryption");
        return -1;
    }

    /* Allocate the buffer for the decrypted output */
    plaintext = (unsigned char *)malloc(ciphertext_length + AES_BLOCK_SIZE);
    memset(plaintext, 0, ciphertext_length + AES_BLOCK_SIZE);

    /* Create the decryption context */
    EVP_CIPHER_CTX *decryption_context = EVP_CIPHER_CTX_new();

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(decryption_context, evp_cipher, NULL, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decryption_context);
        free(plaintext);
        fprintf(stderr,
                "%s: %s\n",
                "OpenSslEvp::aes_decrypt_ciphertext()",
                "failed to initialize decryption context");
        return -1;
    }

    /* Set IV length */
    if ( (cipher_mode == EVP_CIPH_GCM_MODE
          && !EVP_CIPHER_CTX_ctrl(decryption_context, EVP_CTRL_GCM_SET_IVLEN, init_vector_length, NULL))
         || (cipher_mode == EVP_CIPH_CCM_MODE
             && !EVP_CIPHER_CTX_ctrl(decryption_context, EVP_CTRL_CCM_SET_IVLEN, init_vector_length, NULL)) ) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decryption_context);
        free(plaintext);
        fprintf(stderr,
                "%s: %s\n",
                "OpenSslEvp::aes_decrypt_ciphertext()",
                "failed to set IV length");
        return -1;
    }

    /* For CCM, set expected tag value. */
    if (cipher_mode == EVP_CIPH_CCM_MODE
            && !EVP_CIPHER_CTX_ctrl(decryption_context, EVP_CTRL_CCM_SET_TAG, tag_length, tag)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decryption_context);
        free(plaintext);
        fprintf(stderr,
                "%s: %s\n",
                "OpenSslEvp::aes_decrypt_ciphertext()",
                "failed to set expected tag value");
        return -1;
    }

    /* Initialize key and IV */
    if (!EVP_DecryptInit_ex(decryption_context, NULL, NULL, key, init_vector)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decryption_context);
        free(plaintext);
        fprintf(stderr,
                "%s: %s\n",
                "OpenSslEvp::aes_decrypt_ciphertext()",
                "failed to initialize key and IV");
        return -1;
    }

    /* For CCM, provide the total ciphertext length */
    if (cipher_mode == EVP_CIPH_CCM_MODE
            && !EVP_DecryptUpdate(decryption_context, NULL, &update_length, NULL, ciphertext_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decryption_context);
        free(plaintext);
        fprintf(stderr,
                "%s: %s\n",
                "OpenSslEvp::aes_decrypt_ciphertext()",
                "failed to set ciphertext length");
        return -1;
    }

    /* Provide auth data */
    if (!EVP_DecryptUpdate(decryption_context, NULL, &update_length, auth, auth_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(decryption_context);
        free(plaintext);
        fprintf(stderr,
                "%s: %s\n",
                "OpenSslEvp::aes_decrypt_ciphertext()",
                "failed to set authentication data");
        return -1;
    }

    /* Decrypt the ciphertext into the decrypted output buffer */
    last_update_result = EVP_DecryptUpdate(decryption_context, plaintext, &update_length, ciphertext, ciphertext_length);
    if (cipher_mode == EVP_CIPH_GCM_MODE) {
        if (!last_update_result) {
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_free(decryption_context);
            free(plaintext);
            fprintf(stderr,
                    "%s: %s\n",
                    "OpenSslEvp::aes_decrypt_ciphertext()",
                    "failed to update plaintext buffer with decrypted content");
            return -1;
        }
        /* Set expected tag value. */
        if (!EVP_CIPHER_CTX_ctrl(decryption_context, EVP_CTRL_GCM_SET_TAG, tag_length, tag)) {
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_free(decryption_context);
            free(plaintext);
            fprintf(stderr,
                    "%s: %s\n",
                    "OpenSslEvp::aes_decrypt_ciphertext()",
                    "failed to set expected tag value");
            return -1;
        }
        /* Finalize the decryption. A positive return value indicates success,
         * anything else is a failure - the plaintext is not trustworthy.
         */
        *verified = EVP_DecryptFinal_ex(decryption_context, plaintext+update_length, &final_length);
    } else if (cipher_mode == EVP_CIPH_CCM_MODE) {
        /* For CCM, tag verification comes from the final call to EVP_DecryptUpdate; there is no
         * call to EVP_DecryptFinal.
         */
        *verified = last_update_result;
    }

    /* Update the out parameter */
    *decrypted = plaintext;

    /* Clean up the decryption context */
    EVP_CIPHER_CTX_free(decryption_context);
    plaintext_length = update_length + final_length;
    return plaintext_length;
}

/*
    int OpenSslEvp::pkey_encrypt_plaintext(EVP_PKEY *pkey,
                                       int padding,
                                       const unsigned char *plaintext,
                                       size_t plaintext_length,
                                       uint8_t **encrypted,
                                       size_t *encrypted_length);

    Implements encryption with an asymmetric key.
    See: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_encrypt.html

    Arguments:
    * pkey: key used for encryption
    * padding: padding scheme used
    * plaintext: the data to encrypt
    * plaintext_length: number of bytes in 'plaintext'
    * encrypted: output argument, where memory will be allocated for the
    *            encrypted data, needs to be freed with OPENSSL_free
    * encrypted_length: output argument, where the number of encrypted
    *                   bytes will be put.

    Return value:
    * 1 when the operation was successful
    * less than 0 when there was an error
 */
int OpenSslEvp::pkey_encrypt_plaintext(EVP_PKEY *pkey,
                                   int padding,
                                   const uint8_t *plaintext,
                                   size_t plaintext_length,
                                   uint8_t **encrypted,
                                   size_t *encrypted_length)
{
    int r = -1;

    EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new(pkey, NULL);
    OSSLEVP_HANDLE_ERR(pkctx == NULL, r = -1, "failed to create EVP_PKEY_CTX", err_dontfree);

    r = EVP_PKEY_encrypt_init(pkctx);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to initialize EVP_PKEY_CTX for encryption", err_free_pkctx);

    if (OpenSslEvp::key_is_rsa(pkey)) {
        r = EVP_PKEY_CTX_set_rsa_padding(pkctx, padding);
        OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to set RSA padding", err_free_pkctx);
    }

    r = EVP_PKEY_encrypt(pkctx, NULL, encrypted_length, plaintext, plaintext_length);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to calculate PKEY encrypted size", err_free_pkctx);

    *encrypted = static_cast<uint8_t*>(OPENSSL_malloc(*encrypted_length));
    OSSLEVP_HANDLE_ERR(*encrypted == NULL, r = -1, "failed to allocate memory for encrypted data", err_free_pkctx);

    r = EVP_PKEY_encrypt(pkctx, *encrypted, encrypted_length, plaintext, plaintext_length);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to encrypt with PKEY", err_free_encrypted);

    r = 1;
    goto success;

    err_free_encrypted:
    OPENSSL_free(*encrypted);
    success:
    err_free_pkctx:
    EVP_PKEY_CTX_free(pkctx);
    err_dontfree:
    return r;
}

/*
    int OpenSslEvp::pkey_decrypt_ciphertext(EVP_PKEY *pkey,
                                        int padding,
                                        const unsigned char *ciphertext,
                                        size_t ciphertext_length,
                                        uint8_t **decrypted,
                                        size_t *decrypted_length);

    Decrypts the given ciphertext using the supplied key.

    Arguments:
    * pkey: key used for decryption
    * padding: padding scheme used
    * ciphertext: the data to decrypt
    * ciphertext_length: number of bytes in 'ciphertext'
    * decrypted: output argument, where memory will be allocated for the
    *            decrypted data, needs to be freed with OPENSSL_free
    * decrypted_length: output argument, where the number of decrypted
    *                   bytes will be put.

    Return value:
    * 1 when the operation was successful
    * less than 0 when there was an error
*/
int OpenSslEvp::pkey_decrypt_ciphertext(EVP_PKEY *pkey,
                                    int padding,
                                    const unsigned char *ciphertext,
                                    size_t ciphertext_length,
                                    uint8_t **decrypted,
                                    size_t *decrypted_length)
{
    int r = -1;

    EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new(pkey, NULL);
    OSSLEVP_HANDLE_ERR(pkctx == NULL, r = -1, "failed to create EVP_PKEY_CTX", err_dontfree);

    r = EVP_PKEY_decrypt_init(pkctx);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to initialize EVP_PKEY_CTX for decryption", err_free_pkctx);

    if (OpenSslEvp::key_is_rsa(pkey)) {
        r = EVP_PKEY_CTX_set_rsa_padding(pkctx, padding);
        OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to set RSA padding", err_free_pkctx);
    }

    r = EVP_PKEY_decrypt(pkctx, NULL, decrypted_length, ciphertext, ciphertext_length);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to calculate PKEY encrypted size", err_free_pkctx);

    *decrypted = (uint8_t*) OPENSSL_malloc(*decrypted_length);
    OSSLEVP_HANDLE_ERR(*decrypted == NULL, r = -1, "failed to allocate memory for encrypted data", err_free_pkctx);

    r = EVP_PKEY_decrypt(pkctx, *decrypted, decrypted_length, ciphertext, ciphertext_length);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to encrypt with PKEY", err_free_decrypted);

    r = 1;
    goto success;

    err_free_decrypted:
    OPENSSL_free(*decrypted);
    success:
    err_free_pkctx:
    EVP_PKEY_CTX_free(pkctx);
    err_dontfree:
    return r;
}

/*
    int OpenSslEvp::digest(const EVP_MD *digestFunc,
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
int OpenSslEvp::digest(const EVP_MD *digestFunc,
                       const void *bytes,
                       size_t bytesCount,
                       uint8_t **digest,
                       size_t *digestLength)
{
    int r = -1;
    unsigned int actualDigestLength = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    OSSLEVP_HANDLE_ERR(mdctx == NULL, r = -1, "failed to allocate memory for MD context", err_dontfree);

    r = EVP_DigestInit_ex(mdctx, digestFunc, NULL);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to initialize Digest", err_free_mdctx);

    r = EVP_DigestUpdate(mdctx, bytes, bytesCount);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to update Digest", err_free_mdctx);

    *digestLength = EVP_MD_size(digestFunc);
    *digest = (uint8_t *) OPENSSL_malloc(*digestLength);
    OSSLEVP_HANDLE_ERR(*digest == NULL, r = -1, "failed to allocate memory for digest", err_free_mdctx);

    r = EVP_DigestFinal_ex(mdctx, *digest, &actualDigestLength);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1; OPENSSL_free(*digest), "failed to finalize Digest", err_free_mdctx);

    // Set correct length to the output argument
    *digestLength = actualDigestLength;

    err_free_mdctx:
    EVP_MD_CTX_destroy(mdctx);
    err_dontfree:
    return r;
}

/*
    int OpenSslEvp::sign(const EVP_MD *digestFunc,
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
int OpenSslEvp::sign(const EVP_MD *digestFunc,
                     EVP_PKEY *pkey,
                     const void *bytes,
                     size_t bytesCount,
                     uint8_t **signature,
                     size_t *signatureLength)
{
    int r = -1;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    OSSLEVP_HANDLE_ERR(mdctx == NULL, r = -1, "failed to allocate memory for MD context", err_dontfree);

    r = EVP_DigestSignInit(mdctx, NULL, digestFunc, NULL, pkey);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to initialize DigestSign", err_free_mdctx);

    r = EVP_DigestSignUpdate(mdctx, bytes, bytesCount);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to update DigestSign", err_free_mdctx);

    r = EVP_DigestSignFinal(mdctx, NULL, signatureLength);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to finalize DigestSign (1st call)", err_free_mdctx);

    *signature = (uint8_t *) OPENSSL_malloc(*signatureLength);
    OSSLEVP_HANDLE_ERR(*signature == NULL, r = -1, "failed to allocate memory for signature", err_free_mdctx);

    r = EVP_DigestSignFinal(mdctx, *signature, signatureLength);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1; OPENSSL_free(*signature), "failed to finalize DigestSign (2nd call)", err_free_mdctx);

    err_free_mdctx:
    EVP_MD_CTX_destroy(mdctx);
    err_dontfree:
    return r;
}

/*
    int OpenSslEvp::verify(const EVP_MD *digestFunc,
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
int OpenSslEvp::verify(const EVP_MD *digestFunc,
                       EVP_PKEY *pkey,
                       const void *bytes,
                       size_t bytesCount,
                       const uint8_t *signature,
                       size_t signatureLength)
{
    int r = -1;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    OSSLEVP_HANDLE_ERR(mdctx == NULL, r = -1, "failed to allocate memory for MD context", err_dontfree);

    r = EVP_DigestVerifyInit(mdctx, NULL, digestFunc, NULL, pkey);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to initialize DigestVerify", err_free_mdctx);

    r = EVP_DigestVerifyUpdate(mdctx, bytes, bytesCount);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to update DigestVerify", err_free_mdctx);

    r = EVP_DigestVerifyFinal(mdctx, signature, signatureLength);
    OSSLEVP_HANDLE_ERR(r < 0,, "failed to finalize DigestVerify", err_free_mdctx);

    err_free_mdctx:
    EVP_MD_CTX_destroy(mdctx);
    err_dontfree:
    return r;
}

/*
    int OpenSslEvp::generate_ec_key(int curveNid,
                                    uint8_t **publicKeyBytes,
                                    size_t *publicKeySize,
                                    uint8_t **privateKeyBytes,
                                    size_t *privateKeySize)

    Generates an EC key according to:
    https://wiki.openssl.org/index.php/EVP_Key_and_Parameter_Generation

    Arguments:
    * curveNid: the NID of the curve to use
    * publicKeyBytes: this is where the generated public key will be allocated, needs to be freed with OPENSSL_free
    * keyByteCount: this is where the byte count of the generated public key will be written
    * privateKeyBytes: this is where the generated private key will be allocated, needs to be freed with OPENSSL_free
    * privateKeySize: this is where the byte count of the generated private key will be written

    Return value:
    * 1 when successful
    * less than 0 when there was an error and the operation was unsuccessful:
      -1 indicates general error
      -2 indicates unsupported curve
 */
int OpenSslEvp::generate_ec_key(int curveNid,
                                uint8_t **publicKeyBytes,
                                size_t *publicKeySize,
                                uint8_t **privateKeyBytes,
                                size_t *privateKeySize)
{
    int r = -1;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *key = NULL;
    BIO *bioPrivateKey = NULL;
    BIO *bioPublicKey = NULL;
    size_t privKeyLength = 0;
    size_t pubKeyLength = 0;
    uint8_t *privKeyBuffer = 0;
    uint8_t *pubKeyBuffer = 0;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    OSSLEVP_HANDLE_ERR(pctx == NULL, r = -1, "failed to allocate memory for key parameter generation context", err_dontfree);

    r = EVP_PKEY_paramgen_init(pctx);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to initialize parameter generation", err_free_pctx);

    r = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curveNid);
    OSSLEVP_HANDLE_ERR(r != 1, r = -2, "failed to set EC curve NID", err_free_pctx);

    r = EVP_PKEY_paramgen(pctx, &params);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to generate key parameters", err_free_pctx);
    kctx = EVP_PKEY_CTX_new(params, NULL);
    OSSLEVP_HANDLE_ERR(kctx == NULL, r = -1, "failed to allocate memory for key generation context", err_free_params);

    r = EVP_PKEY_keygen_init(kctx);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to initialize key generation", err_free_kctx);

    r = EVP_PKEY_keygen(kctx, &key);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to generate key", err_free_kctx);

    bioPrivateKey = BIO_new(BIO_s_mem());
    OSSLEVP_HANDLE_ERR(bioPrivateKey == NULL, r = -1, "failed to allocate memory for private key BIO", err_free_key);

    r = PEM_write_bio_PrivateKey(bioPrivateKey, key, NULL, NULL, 0, NULL, NULL);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to write private key to BIO in PEM format", err_free_bioPrivateKey);
    privKeyLength = BIO_get_mem_data(bioPrivateKey, NULL);

    bioPublicKey = BIO_new(BIO_s_mem());
    OSSLEVP_HANDLE_ERR(bioPublicKey == NULL, r = -1, "failed to allocate memory for public key BIO", err_free_bioPrivateKey);

    r = PEM_write_bio_PUBKEY(bioPublicKey, key);
    OSSLEVP_HANDLE_ERR(r != 1, r = -1, "failed to write public key to BIO in PEM format", err_free_bioPublicKey);
    pubKeyLength = BIO_get_mem_data(bioPublicKey, NULL);

    privKeyBuffer = (uint8_t *) OPENSSL_malloc(privKeyLength);
    OSSLEVP_HANDLE_ERR(privKeyBuffer == NULL, r = -1, "failed to allocate memory for private key buffer", err_free_bioPublicKey);

    pubKeyBuffer = (uint8_t *) OPENSSL_malloc(pubKeyLength);
    OSSLEVP_HANDLE_ERR(pubKeyBuffer == NULL, r = -1, "failed to allocate memory for public key buffer", err_free_privKeyBuffer);

    r = BIO_read(bioPrivateKey, privKeyBuffer, privKeyLength);
    OSSLEVP_HANDLE_ERR(r != (int) privKeyLength, r = -1, "failed to copy private key into buffer", err_free_pubKeyBuffer);

    r = BIO_read(bioPublicKey, pubKeyBuffer, pubKeyLength);
    OSSLEVP_HANDLE_ERR(r != (int) pubKeyLength, r = -1, "failed to copy public key into buffer", err_free_pubKeyBuffer);

    // Set output parameters and return value, then goto the appropriate label
    *publicKeyBytes = pubKeyBuffer;
    *publicKeySize = pubKeyLength;
    *privateKeyBytes = privKeyBuffer;
    *privateKeySize = privKeyLength;
    r = 1;
    goto success;

    // These should only be called when an error occours.
    // Otherwise should be freed by the caller with OPENSSL_free.
    err_free_pubKeyBuffer:
    OPENSSL_free(pubKeyBuffer);
    err_free_privKeyBuffer:
    OPENSSL_free(privKeyBuffer);

    // These should be freed during normal operation, too.
    success:
    err_free_bioPublicKey:
    BIO_free(bioPublicKey);
    err_free_bioPrivateKey:
    BIO_free(bioPrivateKey);
    err_free_key:
    EVP_PKEY_free(key);
    err_free_kctx:
    EVP_PKEY_CTX_free(kctx);
    err_free_params:
    EVP_PKEY_free(params);
    err_free_pctx:
    EVP_PKEY_CTX_free(pctx);
    err_dontfree:
    return r;
}

/*
    bool OpenSslEvp::key_is_rsa(EVP_PKEY *pkey)

    Tells if a given key is an RSA key or not.

    Arguments:
    * pkey: The key to examine

    Return value:
    * true if the given key is an RSA key
    * false otherwise
*/
bool OpenSslEvp::key_is_rsa(EVP_PKEY *pkey)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    return rsa != NULL;
#else
    return pkey->type == EVP_PKEY_RSA;
#endif
}
