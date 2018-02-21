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

    enum EllipticCurve {
        CurveUnknown            = 0,

        // SECT curves
        CurveSect163k1          = 10,
        CurveSect163r1          = 11,
        CurveSect163r2          = 12,
        CurveSect193r1          = 13,
        CurveSect193r2          = 14,
        CurveSect233k1          = 15,
        CurveSect233r1          = 16,
        CurveSect239k1          = 17,
        CurveSect283k1          = 18,
        CurveSect283r1          = 19,
        CurveSect409k1          = 20,
        CurveSect409r1          = 21,
        CurveSect571k1          = 22,
        CurveSect571r1          = 23,

        // SECP curves
        CurveSecp160k1          = 50,
        CurveSecp160r1          = 51,
        CurveSecp160r2          = 52,
        CurveSecp192k1          = 53,
        CurveSecp192r1          = 54,
        CurveSecp224k1          = 55,
        CurveSecp224r1          = 56,
        CurveSecp256k1          = 57,
        CurveSecp256r1          = 58,
        CurveSecp384r1          = 59,
        CurveSecp521r1          = 60,

        // NIST curves
        CurveNistK163           = CurveSect163k1,
        CurveNistB163           = CurveSect163r2,
        CurveNistK233           = CurveSect233k1,
        CurveNistB233           = CurveSect233r1,
        CurveNistK283           = CurveSect283k1,
        CurveNistB283           = CurveSect283r1,
        CurveNistK409           = CurveSect409k1,
        CurveNistB409           = CurveSect409r1,
        CurveNistK571           = CurveSect571k1,
        CurveNistB571           = CurveSect571k1,
        CurveNistP192           = CurveSecp192r1,
        CurveNistP224           = CurveSecp224r1,
        CurveNistP256           = CurveSecp256r1,
        CurveNistP384           = CurveSecp384r1,
        CurveNistP521           = CurveSecp521r1,

        // ANSI X9.62 primary field curves
        CurveAX962prime192v1    = CurveSecp192r1,
        CurveAX962prime192v2    = 101,
        CurveAX962prime192v3    = 102,
        CurveAX962prime239v1    = 103,
        CurveAX962prime239v2    = 104,
        CurveAX962prime239v3    = 105,
        CurveAX962prime256v1    = CurveSecp256r1,

        // ANSI X9.62 binary field curves
        CurveAX962c2pnb163v1    = 150,
        CurveAX962c2pnb163v2    = 151,
        CurveAX962c2pnb163v3    = 152,
        CurveAX962c2pnb176v1    = 153,
        CurveAX962c2tnb191v1    = 154,
        CurveAX962c2tnb191v2    = 155,
        CurveAX962c2tnb191v3    = 156,
        CurveAX962c2pnb208w1    = 157,
        CurveAX962c2tnb239v1    = 158,
        CurveAX962c2tnb239v2    = 159,
        CurveAX962c2tnb239v3    = 160,
        CurveAX962c2pnb272w1    = 161,
        CurveAX962c2pnb304w1    = 162,
        CurveAX962c2tnb359v1    = 163,
        CurveAX962c2pnb368w1    = 164,
        CurveAX962c2tnb431r1    = 165,

        // WTLS
        CurveWapWsgIdmEcidWtls1 = 200,
        CurveWapWsgIdmEcidWtls2 = 201,
        CurveWapWsgIdmEcidWtls3 = 202,
        CurveWapWsgIdmEcidWtls4 = 203,
        CurveWapWsgIdmEcidWtls5 = 204,
        CurveWapWsgIdmEcidWtls6 = 205,
        CurveWapWsgIdmEcidWtls7 = 206,
        CurveWapWsgIdmEcidWtls8 = 207,
        CurveWapWsgIdmEcidWtls9 = 208,
        CurveWapWsgIdmEcidWtls10= 209,
        CurveWapWsgIdmEcidWtls11= 210,
        CurveWapWsgIdmEcidWtls12= 211,

        // Independent "special" curves
        Curve25519          = 250,  // 128 bit security
        Curve41417          = 251,
        Curve1174           = 252,
        CurveM221           = 253,
        CurveE222           = 254,
        CurveE382           = 255,
        CurveM383           = 256,
        Curve448            = 257,  // 224 bit security
        CurveEd448Goldilocks= 258,
        CurveM511           = 259,
        CurveE521           = 260,

        // Brainpool "random" prime curves
        CurveBrainpoolP160r1= 300,
        CurveBrainpoolP160t1= 301,
        CurveBrainpoolP192r1= 302,
        CurveBrainpoolP192t1= 303,
        CurveBrainpoolP224r1= 304,
        CurveBrainpoolP224t1= 305,
        CurveBrainpoolP256r1= 306,
        CurveBrainpoolP256t1= 307,
        CurveBrainpoolP320r1= 308,
        CurveBrainpoolP320t1= 309,
        CurveBrainpoolP384r1= 310,
        CurveBrainpoolP384t1= 311,
        CurveBrainpoolP512r1= 312,
        CurveBrainpoolP512t1= 313,

        LastCurve           = 4096 // reserve
    };
    Q_ENUM(EllipticCurve)

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
