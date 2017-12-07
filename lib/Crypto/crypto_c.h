/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_CRYPTO_C_H
#define LIBSAILFISHCRYPTO_CRYPTO_C_H

/* This file provides a C-compatible wrapper for Crypto */

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/******************************** Result ************************************/

enum Sailfish_Crypto_Result_Code {
    Sailfish_Crypto_Result_Succeeded = 0,
    Sailfish_Crypto_Result_Pending = 1,
    Sailfish_Crypto_Result_Failed = 2
};

struct Sailfish_Crypto_Result {
    enum Sailfish_Crypto_Result_Code code;
    int errorCode;
    int storageErrorCode;
    char *errorMessage;
};

struct Sailfish_Crypto_Result*
Sailfish_Crypto_Result_new(
        enum Sailfish_Crypto_Result_Code code,
        int errorCode,
        int storageErrorCode,
        const char *errorMessage);

void Sailfish_Crypto_Result_delete(
        struct Sailfish_Crypto_Result *result);

/********************************* Key **************************************/

struct Sailfish_Crypto_Key_Identifier {
    char *name;
    char *collectionName;
};

struct Sailfish_Crypto_Key_FilterDatum {
    char *field;
    char *value;
    struct Sailfish_Crypto_Key_FilterDatum *next;
};

struct Sailfish_Crypto_Key_CustomParameter {
    unsigned char *parameter;
    size_t parameterSize;
    struct Sailfish_Crypto_Key_CustomParameter *next;
};

enum Sailfish_Crypto_Key_Origin {
    Sailfish_Crypto_Key_OriginUnknown       = 0,
    Sailfish_Crypto_Key_OriginImported,
    Sailfish_Crypto_Key_OriginDevice,
    Sailfish_Crypto_Key_OriginSecureDevice
};

enum Sailfish_Crypto_Key_Algorithm {
    Sailfish_Crypto_Key_AlgorithmUnknown    = 0,

    Sailfish_Crypto_Key_Aes128              = 10,
    Sailfish_Crypto_Key_Aes196,
    Sailfish_Crypto_Key_Aes256,

    Sailfish_Crypto_Key_Dsa512              = 20,
    Sailfish_Crypto_Key_Dsa1024,
    Sailfish_Crypto_Key_Dsa2048,
    Sailfish_Crypto_Key_Dsa3072,
    Sailfish_Crypto_Key_Dsa4096,

    Sailfish_Crypto_Key_Rsa512              = 30,
    Sailfish_Crypto_Key_Rsa1028,
    Sailfish_Crypto_Key_Rsa2048,
    Sailfish_Crypto_Key_Rsa3072,
    Sailfish_Crypto_Key_Rsa4096,

    Sailfish_Crypto_Key_NistEcc192          = 40,
    Sailfish_Crypto_Key_NistEcc224,
    Sailfish_Crypto_Key_NistEcc256,
    Sailfish_Crypto_Key_NistEcc384,
    Sailfish_Crypto_Key_NistEcc521,

    Sailfish_Crypto_Key_BpEcc160            = 50,
    Sailfish_Crypto_Key_BpEcc192,
    Sailfish_Crypto_Key_BpEcc224,
    Sailfish_Crypto_Key_BpEcc256,
    Sailfish_Crypto_Key_BpEcc320,
    Sailfish_Crypto_Key_BpEcc384,
    Sailfish_Crypto_Key_BpEcc512
};

enum Sailfish_Crypto_Key_BlockMode {
    Sailfish_Crypto_Key_BlockModeUnknown    = 0,
    Sailfish_Crypto_Key_BlockModeCBC        = 1,
    Sailfish_Crypto_Key_BlockModeCTR        = 2,
    Sailfish_Crypto_Key_BlockModeECB        = 4,
    Sailfish_Crypto_Key_BlockModeGCM        = 8
};

enum Sailfish_Crypto_Key_EncryptionPadding {
    Sailfish_Crypto_Key_EncryptionPaddingUnknown    = 0,
    Sailfish_Crypto_Key_EncryptionPaddingNone       = 1,
    Sailfish_Crypto_Key_EncryptionPaddingPkcs7      = 2,
    Sailfish_Crypto_Key_EncryptionPaddingRsaOaep    = 4,
    Sailfish_Crypto_Key_EncryptionPaddingRsaOaepMgf1= 8,
    Sailfish_Crypto_Key_EncryptionPaddingRsaPkcs1   = 16,
    Sailfish_Crypto_Key_EncryptionPaddingAnsiX923   = 32
};

enum Sailfish_Crypto_Key_SignaturePadding {
    Sailfish_Crypto_Key_SignaturePaddingUnknown     = 0,
    Sailfish_Crypto_Key_SignaturePaddingNone        = 1,
    Sailfish_Crypto_Key_SignaturePaddingRsaPss      = 2,
    Sailfish_Crypto_Key_SignaturePaddingRsaPkcs1    = Sailfish_Crypto_Key_EncryptionPaddingRsaPkcs1,
    Sailfish_Crypto_Key_SignaturePaddingAnsiX923    = Sailfish_Crypto_Key_EncryptionPaddingAnsiX923
};

enum Sailfish_Crypto_Key_Digest {
    Sailfish_Crypto_Key_DigestUnknown       = 0,
    Sailfish_Crypto_Key_DigestSha1          = 1,
    Sailfish_Crypto_Key_DigestSha256        = 2,
    Sailfish_Crypto_Key_DigestSha384        = 4,
    Sailfish_Crypto_Key_DigestSha512        = 8
};

enum Sailfish_Crypto_Key_Operation {
    Sailfish_Crypto_Key_OperationUnknown    = 0,
    Sailfish_Crypto_Key_Sign                = 1,
    Sailfish_Crypto_Key_Verify              = 2,
    Sailfish_Crypto_Key_Encrypt             = 4,
    Sailfish_Crypto_Key_Decrypt             = 8
};

struct Sailfish_Crypto_Key {
    struct Sailfish_Crypto_Key_Identifier *identifier;

    enum Sailfish_Crypto_Key_Origin origin;
    enum Sailfish_Crypto_Key_Algorithm algorithm;
    int blockModes;
    int encryptionPaddings;
    int signaturePaddings;
    int digests;
    int operations;

    unsigned char *secretKey;
    size_t secretKeySize;
    unsigned char *publicKey;
    size_t publicKeySize;
    unsigned char *privateKey;
    size_t privateKeySize;

    time_t validityStart;
    time_t validityEnd;

    struct Sailfish_Crypto_Key_CustomParameter *customParameters;
    struct Sailfish_Crypto_Key_FilterDatum *filterData;
};

struct Sailfish_Crypto_Key_Identifier*
Sailfish_Crypto_Key_Identifier_new(
        const char *name,
        const char *collectionName);

void Sailfish_Crypto_Key_Identifier_delete(
        struct Sailfish_Crypto_Key_Identifier *ident);

struct Sailfish_Crypto_Key_FilterDatum*
Sailfish_Crypto_Key_FilterDatum_new(
        const char *field,
        const char *value);

void Sailfish_Crypto_Key_FilterDatum_delete(
        struct Sailfish_Crypto_Key_FilterDatum *filter);

struct Sailfish_Crypto_Key_CustomParameter*
Sailfish_Crypto_Key_CustomParameter_new(
        const unsigned char *parameter,
        size_t parameterSize);

void Sailfish_Crypto_Key_CustomParameter_delete(
        struct Sailfish_Crypto_Key_CustomParameter *param);

struct Sailfish_Crypto_Key*
Sailfish_Crypto_Key_new(
        const char *name,
        const char *collectionName);

void Sailfish_Crypto_Key_setPrivateKey(
        struct Sailfish_Crypto_Key *key,
        const unsigned char *privateKey,
        size_t privateKeySize);

void Sailfish_Crypto_Key_setPublicKey(
        struct Sailfish_Crypto_Key *key,
        const unsigned char *publicKey,
        size_t publicKeySize);

void Sailfish_Crypto_Key_setSecretKey(
        struct Sailfish_Crypto_Key *key,
        const unsigned char *secretKey,
        size_t secretKeySize);

void Sailfish_Crypto_Key_addFilter(
        struct Sailfish_Crypto_Key *key,
        const char *field,
        const char *value);

void Sailfish_Crypto_Key_addCustomParameter(
        struct Sailfish_Crypto_Key *key,
        const unsigned char *parameter,
        size_t parameterSize);

void Sailfish_Crypto_Key_delete(
        struct Sailfish_Crypto_Key *key);

/****************************** Crypto Manager ******************************/

int Sailfish_Crypto_CryptoManager_generateKey(
        struct Sailfish_Crypto_Key *keyTemplate,
        const char *cryptosystemProviderName,
        struct Sailfish_Crypto_Result **out_result,
        struct Sailfish_Crypto_Key **out_key);

int Sailfish_Crypto_CryptoManager_generateStoredKey(
        struct Sailfish_Crypto_Key *keyTemplate,
        const char *cryptosystemProviderName,
        const char *storageProviderName,
        struct Sailfish_Crypto_Result **out_result,
        struct Sailfish_Crypto_Key **out_keyReference);

int Sailfish_Crypto_CryptoManager_storedKey(
        struct Sailfish_Crypto_Key_Identifier *ident,
        struct Sailfish_Crypto_Result **out_result,
        struct Sailfish_Crypto_Key **out_key);

int Sailfish_Crypto_CryptoManager_deleteStoredKey(
        struct Sailfish_Crypto_Key_Identifier *ident,
        struct Sailfish_Crypto_Result **out_result);

int Sailfish_Crypto_CryptoManager_sign(
        const unsigned char *data,
        size_t dataSize,
        struct Sailfish_Crypto_Key *key,
        enum Sailfish_Crypto_Key_SignaturePadding padding,
        enum Sailfish_Crypto_Key_Digest digest,
        const char *cryptosystemProviderName,
        struct Sailfish_Crypto_Result **out_result,
        unsigned char **out_signature,
        size_t *out_signature_size);

int Sailfish_Crypto_CryptoManager_verify(
        const unsigned char *data,
        size_t dataSize,
        struct Sailfish_Crypto_Key *key,
        enum Sailfish_Crypto_Key_SignaturePadding padding,
        enum Sailfish_Crypto_Key_Digest digest,
        const char *cryptosystemProviderName,
        struct Sailfish_Crypto_Result **out_result,
        int *out_verified);

int Sailfish_Crypto_CryptoManager_encrypt(
        const unsigned char *data,
        size_t dataSize,
        struct Sailfish_Crypto_Key *key,
        enum Sailfish_Crypto_Key_BlockMode blockMode,
        enum Sailfish_Crypto_Key_EncryptionPadding padding,
        enum Sailfish_Crypto_Key_Digest digest,
        const char *cryptosystemProviderName,
        struct Sailfish_Crypto_Result **out_result,
        unsigned char **out_ciphertext,
        size_t *out_ciphertext_size);

int Sailfish_Crypto_CryptoManager_decrypt(
        const unsigned char *data,
        size_t dataSize,
        struct Sailfish_Crypto_Key *key,
        enum Sailfish_Crypto_Key_BlockMode blockMode,
        enum Sailfish_Crypto_Key_EncryptionPadding padding,
        enum Sailfish_Crypto_Key_Digest digest,
        const char *cryptosystemProviderName,
        struct Sailfish_Crypto_Result **out_result,
        unsigned char **out_plaintext,
        size_t *out_plaintext_size);

void Sailfish_Crypto_disconnectFromServer();

#ifdef __cplusplus
} /* extern C */
#endif /* __cplusplus */

#endif /* LIBSAILFISHCRYPTO_CRYPTO_C_H */
