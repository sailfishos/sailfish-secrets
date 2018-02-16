/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_CRYPTOMANAGER_H
#define LIBSAILFISHCRYPTO_CRYPTOMANAGER_H

#include "Crypto/cryptoglobal.h"

#include <QtCore/QObject>
#include <QtCore/QString>

namespace Sailfish {

namespace Crypto {

class CryptoManagerPrivate;
class SAILFISH_CRYPTO_API CryptoManager : public QObject
{
    Q_OBJECT

public:
    static const QString DefaultCryptoPluginName;
    static const QString DefaultCryptoStoragePluginName;

    enum Algorithm {
        AlgorithmUnknown        = 0,
        AlgorithmCustom         = 1,
    FirstAsymmetricAlgorithm    = 10,
        AlgorithmRsa            = 10,
        AlgorithmDsa            = 20,
        AlgorithmDh             = 30,
        AlgorithmEc             = 40,
        AlgorithmEcDsa          = 41,
        AlgorithmEdDsa          = 42,
        AlgorithmEcDh           = 43,
        AlgorithmEcMqv          = 44,
    LastAsymmetricAlgorithm     = 255,
    FirstSymmetricAlgorithm     = 256,
        AlgorithmAes            = 260,
        AlgorithmGost           = 270,
        AlgorithmTdea           = 280,
        AlgorithmTdes           = AlgorithmTdea,
        AlgorithmBlowfish       = 290,
        AlgorithmSalsa          = 300,
        AlgorithmSalsa20        = AlgorithmSalsa,
        AlgorithmChaCha         = 310,
        AlgorithmChaCha20       = AlgorithmChaCha,
        AlgorithmRc4            = 320,
        AlgorithmRc5            = 330,
        AlgorithmRc6            = 340,
        AlgorithmSquare         = 350,
        AlgorithmSerpent        = 360,
        AlgorithmPanama         = 370,
    LastAlgorithm               = 4095 // reserve
    };
    Q_ENUM(Algorithm)

    enum BlockMode {
        BlockModeUnknown    = 0,
        BlockModeCustom     = 1,
        BlockModeEcb        = 2,
        BlockModeCbc        = 3,
        BlockModePcbc       = 4,
        BlockModeCfb        = 5,
        BlockModeOfb        = 6,
        BlockModeCtr        = 7,
        BlockModeGcm        = 8,
        BlockModeLrw        = 9,
        BlockModeXex        = 10,
        BlockModeXts        = 11,
        BlockModeCmc        = 12,
        BlockModeEme        = 13,
        LastBlockMode       = 255 // reserve
    };
    Q_ENUM(BlockMode)

    enum EncryptionPadding {
        EncryptionPaddingUnknown    = 0,
        EncryptionPaddingCustom     = 1,
        EncryptionPaddingNone       = 2,
        EncryptionPaddingPkcs7      = 3,
        EncryptionPaddingRsaOaep    = 4,
        EncryptionPaddingRsaOaepMgf1= 5,
        EncryptionPaddingRsaPkcs1   = 6,
        EncryptionPaddingAnsiX923   = 7,
        LastEncryptionPadding       = 255 // reserve
    };
    Q_ENUM(EncryptionPadding)

    enum SignaturePadding {
        SignaturePaddingUnknown     = 0,
        SignaturePaddingCustom      = 1,
        SignaturePaddingNone        = 2,
        SignaturePaddingRsaPss      = 3,
        SignaturePaddingRsaPkcs1    = EncryptionPaddingRsaPkcs1,
        SignaturePaddingAnsiX923    = EncryptionPaddingAnsiX923,
        LastSignaturePadding        = 255 // reserve
    };
    Q_ENUM(SignaturePadding)

    enum DigestFunction {
        DigestUnknown       = 0,
        DigestCustom        = 1,
        DigestMd5           = 5,
        DigestSha1          = 10,
        DigestSha2_224      = 20,
        DigestSha2_256      = 21,
        DigestSha256        = DigestSha2_256,
        DigestSha2_384      = 22,
        DigestSha2_512      = 23,
        DigestSha512        = DigestSha2_512,
        DigestSha2_512_224  = 24,
        DigestSha2_512_256  = 25,
        DigestSha3_224      = 30,
        DigestSha3_256      = 31,
        DigestSha3_384      = 32,
        DigestSha3_512      = 33,
        DigestShake128      = 34,
        DigestShake256      = 35,
        DigestGost          = 40,
        DigestBlake         = 50,
        DigestBlake2        = 51,
        DigestBlake2b       = 52,
        DigestBlake2s       = 53,
        DigestWhirlpool     = 60,
        DigestRipeMd        = 70,
        DigestRipeMd128_256 = 71,
        DigestRipeMd160     = 72,
        DigestRipeMd320     = 73,
        DigestTiger         = 80,
        DigestTiger128      = 81,
        DigestTiger160      = 82,
        DigestTiger192      = 83,
        DigestTiger2        = 84,
        DigestTiger2_128    = 85,
        DigestTiger2_160    = 86,
        DigestTiger2_192    = 87,
        DigestRadioGatun    = 90,
        LastDigestFunction  = 4095 // reserve
    };
    Q_ENUM(DigestFunction)

    enum MessageAuthenticationCode {
        MacUnknown          = 0,
        MacCustom           = 1,
        MacHmac             = 10,
        MacCmac             = 20,
        MacVmac             = 30,
        MacPoly1305         = 40,
        LastMac             = 255 // reserve
    };
    Q_ENUM(MessageAuthenticationCode)

    enum KeyDerivationFunction {
        KdfUnknown          = 0,
        KdfCustom           = 1,
        KdfPkcs5Pbkdf2      = 10,
        KdfHkdf             = 20,
        KdfBcrypt           = 30,
        KdfScrypt           = 40,
        KdfArgon2           = 50,
        KdfArgon2d          = KdfArgon2,
        KdfArgon2i          = 51,
        KdfArgon2id         = 52,
        KdfLyra2            = 60,
        LastKdf             = 255 // reserve
    };
    Q_ENUM(KeyDerivationFunction)

    enum Operation {
        OperationUnknown        = 0,
        OperationCustom         = 1,
        OperationSign           = 2,
        OperationVerify         = 4,
        OperationEncrypt        = 8,
        OperationDecrypt        = 16,
        OperationDeriveDigest   = 32,
        OperationDeriveMac      = 64,
        OperationDeriveKey      = 128
    };
    Q_ENUM(Operation)
    Q_DECLARE_FLAGS(Operations, Operation)
    Q_FLAG(Operations)

    CryptoManager(QObject *parent = Q_NULLPTR);
    ~CryptoManager();

    bool isInitialised() const;

private:
    QScopedPointer<CryptoManagerPrivate> const d_ptr;
    Q_DECLARE_PRIVATE(CryptoManager)
    friend class CipherRequest;
    friend class DecryptRequest;
    friend class DeleteStoredKeyRequest;
    friend class EncryptRequest;
    friend class GenerateKeyRequest;
    friend class GenerateRandomDataRequest;
    friend class GenerateStoredKeyRequest;
    friend class PluginInfoRequest;
    friend class SeedRandomDataGeneratorRequest;
    friend class SignRequest;
    friend class StoredKeyIdentifiersRequest;
    friend class StoredKeyRequest;
    friend class ValidateCertificateChainRequest;
    friend class VerifyRequest;
};

} // namespace Crypto

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::CryptoManager::Algorithm);
Q_DECLARE_METATYPE(Sailfish::Crypto::CryptoManager::BlockMode);
Q_DECLARE_METATYPE(Sailfish::Crypto::CryptoManager::EncryptionPadding);
Q_DECLARE_METATYPE(Sailfish::Crypto::CryptoManager::SignaturePadding);
Q_DECLARE_METATYPE(Sailfish::Crypto::CryptoManager::DigestFunction);
Q_DECLARE_METATYPE(Sailfish::Crypto::CryptoManager::Operation);
Q_DECLARE_METATYPE(Sailfish::Crypto::CryptoManager::Operations);
Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::CryptoManager::Operations);

#endif // LIBSAILFISHCRYPTO_CRYPTOMANAGER_H
