/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETSCRYPTO_CRYPTO_H
#define LIBSAILFISHSECRETSCRYPTO_CRYPTO_H

/*
 * This file provides a C-compatible wrapper for Crypto.
 *
 * No source or binary compatibility promises are made!
 *
 * The interfaces provided here may change from release
 * to release as the Secrets/Crypto framework changes!
 */

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum Sailfish_Crypto_Algorithm {
	Sailfish_Crypto_AlgorithmUnknown        = 0,
	Sailfish_Crypto_AlgorithmCustom         = 1,
Sailfish_Crypto_FirstAsymmetricAlgorithm    = 10,
	Sailfish_Crypto_AlgorithmRsa            = 10,
	Sailfish_Crypto_AlgorithmDsa            = 20,
	Sailfish_Crypto_AlgorithmDh             = 30,
	Sailfish_Crypto_AlgorithmEc             = 40,
	Sailfish_Crypto_AlgorithmEcDsa,
	Sailfish_Crypto_AlgorithmEdDsa,
	Sailfish_Crypto_AlgorithmEcDh,
	Sailfish_Crypto_AlgorithmEcMqv,
Sailfish_Crypto_LastAsymmetricAlgorithm     = 255,
Sailfish_Crypto_FirstSymmetricAlgorithm,
	Sailfish_Crypto_AlgorithmAes            = 260,
	Sailfish_Crypto_AlgorithmGost           = 270,
	Sailfish_Crypto_AlgorithmTdea           = 280,
	Sailfish_Crypto_AlgorithmTdes           = Sailfish_Crypto_AlgorithmTdea,
	Sailfish_Crypto_AlgorithmBlowfish       = 290,
	Sailfish_Crypto_AlgorithmSalsa          = 300,
	Sailfish_Crypto_AlgorithmSalsa20        = Sailfish_Crypto_AlgorithmSalsa,
	Sailfish_Crypto_AlgorithmChaCha         = 310,
	Sailfish_Crypto_AlgorithmChaCha20       = Sailfish_Crypto_AlgorithmChaCha,
	Sailfish_Crypto_AlgorithmRc4            = 320,
	Sailfish_Crypto_AlgorithmRc5            = 330,
	Sailfish_Crypto_AlgorithmRc6            = 340,
	Sailfish_Crypto_AlgorithmSquare         = 350,
	Sailfish_Crypto_AlgorithmSerpent        = 360,
	Sailfish_Crypto_AlgorithmPanama         = 370,
Sailfish_Crypto_LastSymmetricAlgorithm      = 4095, // reserve
Sailfish_Crypto_LastAlgorithm               = Sailfish_Crypto_LastSymmetricAlgorithm
};

enum Sailfish_Crypto_BlockMode {
	Sailfish_Crypto_BlockModeUnknown    = 0,
	Sailfish_Crypto_BlockModeCustom,
	Sailfish_Crypto_BlockModeEcb,
	Sailfish_Crypto_BlockModeCbc,
	Sailfish_Crypto_BlockModePcbc,
	Sailfish_Crypto_BlockModeCfb1,
	Sailfish_Crypto_BlockModeCfb8,
	Sailfish_Crypto_BlockModeCfb128,
	Sailfish_Crypto_BlockModeOfb,
	Sailfish_Crypto_BlockModeCtr,
	Sailfish_Crypto_BlockModeGcm,
	Sailfish_Crypto_BlockModeLrw,
	Sailfish_Crypto_BlockModeXex,
	Sailfish_Crypto_BlockModeXts,
	Sailfish_Crypto_BlockModeCmc,
	Sailfish_Crypto_BlockModeEme,
	Sailfish_Crypto_BlockModeCcm,
Sailfish_Crypto_LastBlockMode           = 255 // reserve
};

enum Sailfish_Crypto_EncryptionPadding {
	Sailfish_Crypto_EncryptionPaddingUnknown    = 0,
	Sailfish_Crypto_EncryptionPaddingCustom,
	Sailfish_Crypto_EncryptionPaddingNone,
	Sailfish_Crypto_EncryptionPaddingPkcs7,
	Sailfish_Crypto_EncryptionPaddingRsaOaep,
	Sailfish_Crypto_EncryptionPaddingRsaOaepMgf1,
	Sailfish_Crypto_EncryptionPaddingRsaPkcs1,
	Sailfish_Crypto_EncryptionPaddingAnsiX923,
Sailfish_Crypto_LastEncryptionPadding           = 255 // reserve
};

enum Sailfish_Crypto_SignaturePadding {
	Sailfish_Crypto_SignaturePaddingUnknown     = 0,
	Sailfish_Crypto_SignaturePaddingCustom,
	Sailfish_Crypto_SignaturePaddingNone,
	Sailfish_Crypto_SignaturePaddingRsaPss,
	Sailfish_Crypto_SignaturePaddingRsaPkcs1    = Sailfish_Crypto_EncryptionPaddingRsaPkcs1,
	Sailfish_Crypto_SignaturePaddingAnsiX923    = Sailfish_Crypto_EncryptionPaddingAnsiX923,
Sailfish_Crypto_LastSignaturePadding            = 255 // reserve
};

enum Sailfish_Crypto_DigestFunction {
	Sailfish_Crypto_DigestUnknown       = 0,
	Sailfish_Crypto_DigestCustom        = 1,
	Sailfish_Crypto_DigestMd5           = 5,
	Sailfish_Crypto_DigestSha1          = 10,
	Sailfish_Crypto_DigestSha2_224      = 20,
	Sailfish_Crypto_DigestSha2_256      = 21,
	Sailfish_Crypto_DigestSha256        = Sailfish_Crypto_DigestSha2_256,
	Sailfish_Crypto_DigestSha2_384      = 22,
	Sailfish_Crypto_DigestSha2_512      = 23,
	Sailfish_Crypto_DigestSha512        = Sailfish_Crypto_DigestSha2_512,
	Sailfish_Crypto_DigestSha2_512_224  = 24,
	Sailfish_Crypto_DigestSha2_512_256  = 25,
	Sailfish_Crypto_DigestSha3_224      = 30,
	Sailfish_Crypto_DigestSha3_256,
	Sailfish_Crypto_DigestSha3_384,
	Sailfish_Crypto_DigestSha3_512,
	Sailfish_Crypto_DigestShake128,
	Sailfish_Crypto_DigestShake256,
	Sailfish_Crypto_DigestGost          = 40,
	Sailfish_Crypto_DigestBlake         = 50,
	Sailfish_Crypto_DigestBlake2,
	Sailfish_Crypto_DigestBlake2b,
	Sailfish_Crypto_DigestBlake2s,
	Sailfish_Crypto_DigestWhirlpool     = 60,
	Sailfish_Crypto_DigestRipeMd        = 70,
	Sailfish_Crypto_DigestRipeMd128_256,
	Sailfish_Crypto_DigestRipeMd160,
	Sailfish_Crypto_DigestRipeMd320,
	Sailfish_Crypto_DigestTiger         = 80,
	Sailfish_Crypto_DigestTiger128,
	Sailfish_Crypto_DigestTiger160,
	Sailfish_Crypto_DigestTiger192,
	Sailfish_Crypto_DigestTiger2,
	Sailfish_Crypto_DigestTiger2_128,
	Sailfish_Crypto_DigestTiger2_160,
	Sailfish_Crypto_DigestTiger2_192,
	Sailfish_Crypto_DigestRadioGatun    = 90,
Sailfish_Crypto_LastDigestFunction      = 4095 // reserve
};

enum Sailfish_Crypto_MessageAuthenticationCode {
	Sailfish_Crypto_MacUnknown          = 0,
	Sailfish_Crypto_MacCustom           = 1,
	Sailfish_Crypto_MacHmac             = 10,
	Sailfish_Crypto_MacCmac             = 20,
	Sailfish_Crypto_MacVmac             = 30,
	Sailfish_Crypto_MacPoly1305         = 40,
Sailfish_Crypto_LastMac                 = 255 // reserve
};

enum Sailfish_Crypto_KeyDerivationFunction {
	Sailfish_Crypto_KdfUnknown          = 0,
	Sailfish_Crypto_KdfCustom           = 1,
	Sailfish_Crypto_KdfPkcs5Pbkdf2      = 10,
	Sailfish_Crypto_KdfHkdf             = 20,
	Sailfish_Crypto_KdfBcrypt           = 30,
	Sailfish_Crypto_KdfScrypt           = 40,
	Sailfish_Crypto_KdfArgon2           = 50,
	Sailfish_Crypto_KdfArgon2d          = Sailfish_Crypto_KdfArgon2,
	Sailfish_Crypto_KdfArgon2i          = 51,
	Sailfish_Crypto_KdfArgon2id         = 52,
	Sailfish_Crypto_KdfLyra2            = 60,
Sailfish_Crypto_LastKdf                 = 255 // reserve
};

enum Sailfish_Crypto_VerificationStatusType {
	Sailfish_Crypto_VerificationStatusUnknown    = 0,
	Sailfish_Crypto_VerificationSucceeded        = 1,
	Sailfish_Crypto_VerificationFailed           = 2,
	Sailfish_Crypto_VerificationSignatureInvalid = 4,
	Sailfish_Crypto_VerificationSignatureExpired = 8,
	Sailfish_Crypto_VerificationKeyExpired       = 16,
	Sailfish_Crypto_VerificationKeyRevoked       = 32,
	Sailfish_Crypto_VerificationKeyInvalid       = 64
};

/****************************** Result ******************************/

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
	int refcount;
};

void Sailfish_Crypto_Result_ref(
		struct Sailfish_Crypto_Result *result);

void Sailfish_Crypto_Result_unref(
		struct Sailfish_Crypto_Result *result);

/****************************** Key ******************************/

struct Sailfish_Crypto_Key_Identifier {
	char *name;
	char *collectionName;
	char *storagePluginName;
	int refcount;
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

enum Sailfish_Crypto_Key_Operation {
	Sailfish_Crypto_Key_OperationUnknown        = 0,
	Sailfish_Crypto_Key_OperationCustom         = 1,
	Sailfish_Crypto_Key_OperationSign           = 2,
	Sailfish_Crypto_Key_OperationVerify         = 4,
	Sailfish_Crypto_Key_OperationEncrypt        = 8,
	Sailfish_Crypto_Key_OperationDecrypt        = 16,
	Sailfish_Crypto_Key_OperationCalculateDigest= 32,
	Sailfish_Crypto_Key_OperationCalculateMac   = 64,
	Sailfish_Crypto_Key_OperationDeriveKey      = 128
};

enum Sailfish_Crypto_Key_Component {
	Sailfish_Crypto_Key_NoData          = 0,
	Sailfish_Crypto_Key_MetaData        = 1,
	Sailfish_Crypto_Key_PublicKeyData   = 2,
	Sailfish_Crypto_Key_PrivateKeyData  = 4,
	Sailfish_Crypto_Key_SecretKeyData   = Sailfish_Crypto_Key_PrivateKeyData
};

struct Sailfish_Crypto_Key {
	struct Sailfish_Crypto_Key_Identifier *identifier;

	enum Sailfish_Crypto_Key_Origin origin;
	enum Sailfish_Crypto_Algorithm algorithm;
	int operations;
	int componentConstraints;
	int size;

	unsigned char *publicKey;
	size_t publicKeySize;
	unsigned char *privateKey;
	size_t privateKeySize;
	unsigned char *secretKey;
	size_t secretKeySize;

	struct Sailfish_Crypto_Key_CustomParameter *customParameters;
	struct Sailfish_Crypto_Key_FilterDatum *filterData;

	int refcount;
};

struct Sailfish_Crypto_Key_Identifier*
Sailfish_Crypto_Key_Identifier_new(
		const char *name,
		const char *collectionName,
		const char *storagePluginName);

void Sailfish_Crypto_Key_Identifier_ref(
		struct Sailfish_Crypto_Key_Identifier *ident);

void Sailfish_Crypto_Key_Identifier_unref(
		struct Sailfish_Crypto_Key_Identifier *ident);

struct Sailfish_Crypto_Key_FilterDatum*
Sailfish_Crypto_Key_FilterDatum_new(
		const char *field,
		const char *value);

void Sailfish_Crypto_Key_FilterDatum_ref(
		struct Sailfish_Crypto_Key_FilterDatum *filter);

void Sailfish_Crypto_Key_FilterDatum_unref(
		struct Sailfish_Crypto_Key_FilterDatum *filter);

struct Sailfish_Crypto_Key_CustomParameter*
Sailfish_Crypto_Key_CustomParameter_new(
		const unsigned char *parameter,
		size_t parameterSize);

void Sailfish_Crypto_Key_CustomParameter_unref(
		struct Sailfish_Crypto_Key_CustomParameter *param);

struct Sailfish_Crypto_Key*
Sailfish_Crypto_Key_new(
		const char *name,
		const char *collectionName,
		const char *storagePluginName);

void Sailfish_Crypto_Key_ref(
		struct Sailfish_Crypto_Key *key);

void Sailfish_Crypto_Key_unref(
		struct Sailfish_Crypto_Key *key);

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

enum Sailfish_Crypto_CustomParameter_ValueType {
	Sailfish_Crypto_CustomParameter_ValueTypeUnknown = 0,
	Sailfish_Crypto_CustomParameter_ValueTypeBool,
	Sailfish_Crypto_CustomParameter_ValueTypeInt32,
	Sailfish_Crypto_CustomParameter_ValueTypeUInt32,
	Sailfish_Crypto_CustomParameter_ValueTypeInt64,
	Sailfish_Crypto_CustomParameter_ValueTypeUInt64,
	Sailfish_Crypto_CustomParameter_ValueTypeString,
	Sailfish_Crypto_CustomParameter_ValueTypeByteArray,
};

struct Sailfish_Crypto_CustomParameter {
	char *key;
	Sailfish_Crypto_CustomParameter_ValueType valueType;
	int valueBool;
	int32_t valueInt32;
	uint32_t valueUInt32;
	int64_t valueInt64;
	uint64_t valueUInt64;
	char *valueString;
	unsigned char *valueByteArray;
	size_t valueByteArraySize;

	struct Sailfish_Crypto_CustomParameter *next;
};

struct Sailfish_Crypto_CustomParameter*
Sailfish_Crypto_CustomParameter_new(
		const char *key,
		Sailfish_Crypto_CustomParameter_ValueType type);

void Sailfish_Crypto_CustomParameter_unref(
		struct Sailfish_Crypto_CustomParameter *paramsList);

void Sailfish_Crypto_CustomParameter_addParameter(
		struct Sailfish_Crypto_CustomParameter *paramsList,
		struct Sailfish_Crypto_CustomParameter *param);

enum Sailfish_Crypto_KeyPairType {
	Sailfish_Crypto_KeyPairUnknown    = Sailfish_Crypto_AlgorithmUnknown,
	Sailfish_Crypto_KeyPairCustom     = Sailfish_Crypto_AlgorithmCustom,
	Sailfish_Crypto_KeyPairDh         = Sailfish_Crypto_AlgorithmDh,
	Sailfish_Crypto_KeyPairDsa        = Sailfish_Crypto_AlgorithmDsa,
	Sailfish_Crypto_KeyPairRsa        = Sailfish_Crypto_AlgorithmRsa,
	Sailfish_Crypto_KeyPairEc         = Sailfish_Crypto_AlgorithmEc,
Sailfish_Crypto_LastKeyPairType       = Sailfish_Crypto_LastAlgorithm
};

struct Sailfish_Crypto_KeyPairGenerationParameters {
	Sailfish_Crypto_KeyPairType keyPairType;
	struct Sailfish_Crypto_CustomParameter *subclassParameters;
	struct Sailfish_Crypto_CustomParameter *customParameters;

	int refcount;
};

struct Sailfish_Crypto_KeyPairGenerationParameters*
Sailfish_Crypto_KeyPairGenerationParameters_new(
		Sailfish_Crypto_KeyPairType keyPairType,
		struct Sailfish_Crypto_CustomParameter *subclassParameters,
		struct Sailfish_Crypto_CustomParameter *customParameters);

void Sailfish_Crypto_KeyPairGenerationParameters_ref(
		struct Sailfish_Crypto_KeyPairGenerationParameters *kpgParams);

void Sailfish_Crypto_KeyPairGenerationParameters_unref(
		struct Sailfish_Crypto_KeyPairGenerationParameters *kpgParams);

struct Sailfish_Crypto_KeyDerivationParameters {
	unsigned char *inputData;
	size_t inputDataSize;
	unsigned char *salt;
	size_t saltSize;
	Sailfish_Crypto_KeyDerivationFunction keyDerivationFunction;
	Sailfish_Crypto_MessageAuthenticationCode keyDerivationMac;
	Sailfish_Crypto_Algorithm keyDerivationAlgorithm;
	Sailfish_Crypto_DigestFunction keyDerivationDigestFunction;
	int iterations;
	int parallelism;
	int outputKeySize;
	struct Sailfish_Crypto_CustomParameter *customParameters;

	int refcount;
};

struct Sailfish_Crypto_KeyDerivationParameters*
Sailfish_Crypto_KeyDerivationParameters_new(
		unsigned char *inputData,
		size_t inputDataSize,
		unsigned char *salt,
		size_t saltSize,
		Sailfish_Crypto_KeyDerivationFunction keyDerivationFunction,
		Sailfish_Crypto_MessageAuthenticationCode keyDerivationMac,
		Sailfish_Crypto_Algorithm keyDerivationAlgorithm,
		Sailfish_Crypto_DigestFunction keyDerivationDigestFunction,
		int iterations,
		int parallelism,
		int outputKeySize,
		struct Sailfish_Crypto_CustomParameter *customParameters);

void Sailfish_Crypto_KeyDerivationParameters_ref(
		struct Sailfish_Crypto_KeyDerivationParameters *kdfParams);

void Sailfish_Crypto_KeyDerivationParameters_unref(
		struct Sailfish_Crypto_KeyDerivationParameters *kdfParams);

/****************************** Crypto Manager ******************************/

typedef void (*Sailfish_Crypto_CryptoManager_generateKey_callback)
		(void *context, struct Sailfish_Crypto_Result *result, struct Sailfish_Crypto_Key *key);
typedef void (*Sailfish_Crypto_CryptoManager_generateStoredKey_callback)
		(void *context, struct Sailfish_Crypto_Result *result, struct Sailfish_Crypto_Key *keyReference);
typedef void (*Sailfish_Crypto_CryptoManager_storedKey_callback)
		(void *context, struct Sailfish_Crypto_Result *result, struct Sailfish_Crypto_Key *key);
typedef void (*Sailfish_Crypto_CryptoManager_deleteStoredKey_callback)
		(void *context, struct Sailfish_Crypto_Result *result);
typedef void (*Sailfish_Crypto_CryptoManager_sign_callback)
		(void *context, struct Sailfish_Crypto_Result *result, unsigned char *signature, size_t signatureSize);
typedef void (*Sailfish_Crypto_CryptoManager_verify_callback)
		(void *context, struct Sailfish_Crypto_Result *result, int verified);
typedef void (*Sailfish_Crypto_CryptoManager_encrypt_callback)
		(void *context, struct Sailfish_Crypto_Result *result, unsigned char *ciphertext, size_t ciphertextSize);
typedef void (*Sailfish_Crypto_CryptoManager_decrypt_callback)
		(void *context, struct Sailfish_Crypto_Result *result, unsigned char *plaintext, size_t plaintextSize);

int Sailfish_Crypto_CryptoManager_generateKey(
		struct Sailfish_Crypto_Key *keyTemplate,
		struct Sailfish_Crypto_KeyPairGenerationParameters *kpgParams,
		struct Sailfish_Crypto_KeyDerivationParameters *skdfParams,
		struct Sailfish_Crypto_CustomParameter *customParameters,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_generateKey_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_generateStoredKey(
		struct Sailfish_Crypto_Key *keyTemplate,
		struct Sailfish_Crypto_KeyPairGenerationParameters *kpgParams,
		struct Sailfish_Crypto_KeyDerivationParameters *skdfParams,
		struct Sailfish_Crypto_CustomParameter *customParameters,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_generateStoredKey_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_storedKey(
		struct Sailfish_Crypto_Key_Identifier *ident,
		int keyComponents,
		struct Sailfish_Crypto_CustomParameter *customParameters,
		Sailfish_Crypto_CryptoManager_storedKey_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_deleteStoredKey(
		struct Sailfish_Crypto_Key_Identifier *ident,
		Sailfish_Crypto_CryptoManager_deleteStoredKey_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_sign(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_SignaturePadding padding,
		enum Sailfish_Crypto_Digest digest,
		struct Sailfish_Crypto_CustomParameter *customParameters,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_sign_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_verify(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_SignaturePadding padding,
		enum Sailfish_Crypto_Digest digest,
		struct Sailfish_Crypto_CustomParameter *customParameters,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_verify_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_encrypt(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_BlockMode blockMode,
		enum Sailfish_Crypto_EncryptionPadding padding,
		enum Sailfish_Crypto_Digest digest,
		struct Sailfish_Crypto_CustomParameter *customParameters,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_encrypt_callback callback,
		void *callback_context);

int Sailfish_Crypto_CryptoManager_decrypt(
		const unsigned char *data,
		size_t dataSize,
		struct Sailfish_Crypto_Key *key,
		enum Sailfish_Crypto_BlockMode blockMode,
		enum Sailfish_Crypto_EncryptionPadding padding,
		enum Sailfish_Crypto_Digest digest,
		struct Sailfish_Crypto_CustomParameter *customParameters,
		const char *cryptosystemProviderName,
		Sailfish_Crypto_CryptoManager_decrypt_callback callback,
		void *callback_context);

/****************************** Daemon Connection *******************/

typedef void (*Sailfish_Crypto_connectToServer_callback)
		(void *context, struct Sailfish_Crypto_Result *result);
typedef void (*Sailfish_Crypto_disconnectFromServer_callback)
		(void *context, struct Sailfish_Crypto_Result *result);

int Sailfish_Crypto_busy();

int Sailfish_Crypto_connectedToServer();

int Sailfish_Crypto_connectToServer(
		Sailfish_Crypto_connectToServer_callback callback,
		void *callback_context);

int Sailfish_Crypto_disconnectFromServer(
		Sailfish_Crypto_disconnectFromServer_callback callback,
		void *callback_context);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LIBSAILFISHSECRETSCRYPTO_CRYPTO_H */

