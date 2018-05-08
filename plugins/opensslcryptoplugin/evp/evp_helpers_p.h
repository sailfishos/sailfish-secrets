/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/key.h"
#include "Crypto/keypairgenerationparameters.h"
#include "Crypto/keyderivationparameters.h"

#include <QtCore/QTimer>
#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>
#include <QtCore/QUuid>
#include <QtCore/QCryptographicHash>
#include <QtDebug>

#include <fstream>
#include <cstdlib>
#include <limits>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#define CIPHER_SESSION_INACTIVITY_TIMEOUT 60000 /* 1 minute, change to 10 sec for timeout test */
#define MAX_CIPHER_SESSIONS_PER_CLIENT 5
#define SAILFISH_CRYPTO_GCM_TAG_SIZE 16
#define SAILFISH_CRYPTO_GCM_IV_SIZE 12
#define SAILFISH_CRYPTO_CCM_TAG_SIZE 14
#define SAILFISH_CRYPTO_CCM_IV_SIZE 7

class CipherSessionData
{
public:
    QByteArray iv;
    Sailfish::Crypto::Key key;
    Sailfish::Crypto::CryptoManager::Operation operation = Sailfish::Crypto::CryptoManager::OperationUnknown;
    Sailfish::Crypto::CryptoManager::BlockMode blockMode = Sailfish::Crypto::CryptoManager::BlockModeUnknown;
    Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding = Sailfish::Crypto::CryptoManager::EncryptionPaddingUnknown;
    Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding = Sailfish::Crypto::CryptoManager::SignaturePaddingUnknown;
    Sailfish::Crypto::CryptoManager::DigestFunction digestFunction = Sailfish::Crypto::CryptoManager::DigestUnknown;
    quint32 cipherSessionToken = 0;
    EVP_MD_CTX *evp_md_ctx = nullptr;
    EVP_CIPHER_CTX *evp_cipher_ctx = nullptr;
    QTimer *timeout;
};

struct CipherSessionDataDeleter
{
    static inline void cleanup(CipherSessionData *csd)
    {
        if (csd->evp_cipher_ctx) {
            EVP_CIPHER_CTX_free(csd->evp_cipher_ctx);
        }
        if (csd->evp_md_ctx) {
            EVP_MD_CTX_destroy(csd->evp_md_ctx);
        }
        if (csd->timeout) {
            csd->timeout->deleteLater();
        }
        delete csd;
    }
};

struct LibCrypto_BN_Deleter
{
    static inline void cleanup(BIGNUM *pointer)
    {
        BN_free(pointer);
    }
};

struct LibCrypto_RSA_Deleter
{
    static inline void cleanup(RSA *pointer)
    {
        RSA_free(pointer);
    }
};

struct LibCrypto_BIO_Deleter
{
    static inline void cleanup(BIO *pointer)
    {
        BIO_free(pointer);
    }
};

struct LibCrypto_EVP_PKEY_Deleter
{
    static inline void cleanup(EVP_PKEY *pointer)
    {
        EVP_PKEY_free(pointer);
    }
};

quint32 getNextCipherSessionToken(QMap<quint64, QMap<quint32, CipherSessionData*> > *sessions, quint64 clientId)
{
    if (!sessions->contains(clientId)) {
        return 1;
    } else for (quint32 possible = 1; possible < MAX_CIPHER_SESSIONS_PER_CLIENT; ++possible) {
        if (!sessions->value(clientId).contains(possible)) {
            return possible;
        }
    }
    return 0; // no cipher sessions available.
}

int initializationVectorSize(Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                             Sailfish::Crypto::CryptoManager::BlockMode blockMode,
                             int keySize)
{
    Q_UNUSED(keySize)   // not yet used in calculations

    if (blockMode == Sailfish::Crypto::CryptoManager::BlockModeEcb) {
        // IV not required for these configurations
        return 0;
    }

    switch (algorithm) {
    case Sailfish::Crypto::CryptoManager::AlgorithmRsa:
        // IV not yet supported for RSA
        return 0;
    case Sailfish::Crypto::CryptoManager::AlgorithmAes:
        if (blockMode == Sailfish::Crypto::CryptoManager::BlockModeGcm) {
            return SAILFISH_CRYPTO_GCM_IV_SIZE;
        } else if (blockMode == Sailfish::Crypto::CryptoManager::BlockModeCcm) {
            return SAILFISH_CRYPTO_CCM_IV_SIZE;
        } else {
            return 16;  // AES = 128-bit block size
        }
    default:
        break;
    }

    // Unrecognized configuration, IV should be ignored
    return -1;
}

int authenticationTagSize(Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                          Sailfish::Crypto::CryptoManager::BlockMode blockMode)
{
    switch (algorithm) {
    case Sailfish::Crypto::CryptoManager::AlgorithmAes:
        if (blockMode == Sailfish::Crypto::CryptoManager::BlockModeGcm) {
            return SAILFISH_CRYPTO_GCM_TAG_SIZE;
        } else if (blockMode == Sailfish::Crypto::CryptoManager::BlockModeCcm) {
            return SAILFISH_CRYPTO_CCM_TAG_SIZE;
        }
    default:
        break;
    }
    return 0;
}

const EVP_MD *getEvpDigestFunction(Sailfish::Crypto::CryptoManager::DigestFunction digestFunction) {
    switch (digestFunction) {
    case Sailfish::Crypto::CryptoManager::DigestSha256:
        return EVP_sha256();
    case Sailfish::Crypto::CryptoManager::DigestSha512:
        return EVP_sha512();
    case Sailfish::Crypto::CryptoManager::DigestMd5:
        return EVP_md5();
    default:
        return Q_NULLPTR;
    }
}

const EVP_CIPHER *getEvpCipher(int block_mode, int key_length_bytes)
{
    const int key_length_bits = key_length_bytes * 8;

    if (block_mode == Sailfish::Crypto::CryptoManager::BlockModeEcb) {
        switch (key_length_bits) {
        case 128: return EVP_aes_128_ecb();
        case 192: return EVP_aes_192_ecb();
        case 256: return EVP_aes_256_ecb();
        default:
            fprintf(stderr, "%s: %d\n", "unsupported encryption size for ECB block mode", key_length_bits);
            return NULL;
        }
    } else if (block_mode == Sailfish::Crypto::CryptoManager::BlockModeCbc) {
        switch (key_length_bits) {
        case 128: return EVP_aes_128_cbc();
        case 192: return EVP_aes_192_cbc();
        case 256: return EVP_aes_256_cbc();
        default:
            fprintf(stderr, "%s: %d\n", "unsupported encryption size for CBC block mode", key_length_bits);
            return NULL;
        }
    } else if (block_mode == Sailfish::Crypto::CryptoManager::BlockModeCfb1) {
        switch (key_length_bits) {
        case 128: return EVP_aes_128_cfb1();
        case 192: return EVP_aes_192_cfb1();
        case 256: return EVP_aes_256_cfb1();
        default:
            fprintf(stderr, "%s: %d\n", "unsupported encryption size for CFB-1 block mode", key_length_bits);
            return NULL;
        }
    } else if (block_mode == Sailfish::Crypto::CryptoManager::BlockModeCfb8) {
        switch (key_length_bits) {
        case 128: return EVP_aes_128_cfb8();
        case 192: return EVP_aes_192_cfb8();
        case 256: return EVP_aes_256_cfb8();
        default:
            fprintf(stderr, "%s: %d\n", "unsupported encryption size for CFB-8 block mode", key_length_bits);
            return NULL;
        }
    } else if (block_mode == Sailfish::Crypto::CryptoManager::BlockModeCfb128) {
        switch (key_length_bits) {
        case 128: return EVP_aes_128_cfb128();
        case 192: return EVP_aes_192_cfb128();
        case 256: return EVP_aes_256_cfb128();
        default:
            fprintf(stderr, "%s: %d\n", "unsupported encryption size for CFB-128 block mode", key_length_bits);
            return NULL;
        }
    } else if (block_mode == Sailfish::Crypto::CryptoManager::BlockModeOfb) {
        switch (key_length_bits) {
        case 128: return EVP_aes_128_ofb();
        case 192: return EVP_aes_192_ofb();
        case 256: return EVP_aes_256_ofb();
        default:
            fprintf(stderr, "%s: %d\n", "unsupported encryption size for OFB block mode", key_length_bits);
            return NULL;
        }
    } else if (block_mode == Sailfish::Crypto::CryptoManager::BlockModeCtr) {
        switch (key_length_bits) {
        case 128: return EVP_aes_128_ctr();
        case 192: return EVP_aes_192_ctr();
        case 256: return EVP_aes_256_ctr();
        default:
            fprintf(stderr, "%s: %d\n", "unsupported encryption size for OFB block mode", key_length_bits);
            return NULL;
        }
    } else if (block_mode == Sailfish::Crypto::CryptoManager::BlockModeGcm) {
        switch (key_length_bits) {
        case 128: return EVP_aes_128_gcm();
        case 192: return EVP_aes_192_gcm();
        case 256: return EVP_aes_256_gcm();
        default:
            fprintf(stderr, "%s: %d\n", "unsupported encryption size for GCM block mode", key_length_bits);
            return NULL;
        }
    } else if (block_mode == Sailfish::Crypto::CryptoManager::BlockModeCcm) {
        switch (key_length_bits) {
        case 128: return EVP_aes_128_ccm();
        case 192: return EVP_aes_192_ccm();
        case 256: return EVP_aes_256_ccm();
        default:
            fprintf(stderr, "%s: %d\n", "unsupported encryption size for CCM block mode", key_length_bits);
            return NULL;
        }
    } else if (block_mode == Sailfish::Crypto::CryptoManager::BlockModeXts) {
        switch (key_length_bits) {
        // Note: current openssl does not support XTS 192-bit.
        case 128: return EVP_aes_128_xts();
        case 256: return EVP_aes_256_xts();
        default:
            fprintf(stderr, "%s: %d\n", "unsupported encryption size for XTS block mode", key_length_bits);
            return NULL;
        }
    }

    fprintf(stderr, "%s\n", "unsupported encryption mode");
    return NULL;
}

int getOpenSslRsaPadding(Sailfish::Crypto::CryptoManager::EncryptionPadding padding) {
    switch (padding) {
    case Sailfish::Crypto::CryptoManager::EncryptionPaddingNone:
        return RSA_NO_PADDING;
    case Sailfish::Crypto::CryptoManager::EncryptionPaddingRsaPkcs1:
        return RSA_PKCS1_PADDING;
    case Sailfish::Crypto::CryptoManager::EncryptionPaddingRsaOaep:
        return RSA_PKCS1_OAEP_PADDING;
    default:
        return 0;
    }
}

int getEllipticCurveNid(Sailfish::Crypto::CryptoManager::EllipticCurve curve) {
    // TODO: add more curves
    switch (curve) {
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb163v1:
        return NID_X9_62_c2pnb163v1;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb163v2:
        return NID_X9_62_c2pnb163v2;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb163v3:
        return NID_X9_62_c2pnb163v3;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb176v1:
        return NID_X9_62_c2pnb176v1;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb208w1:
        return NID_X9_62_c2pnb208w1;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb272w1:
        return NID_X9_62_c2pnb272w1;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb304w1:
        return NID_X9_62_c2pnb304w1;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb368w1:
        return NID_X9_62_c2pnb368w1;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb191v1:
        return NID_X9_62_c2tnb191v1;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb191v2:
        return NID_X9_62_c2tnb191v2;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb191v3:
        return NID_X9_62_c2tnb191v3;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb239v1:
        return NID_X9_62_c2tnb239v1;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb239v2:
        return NID_X9_62_c2tnb239v2;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb239v3:
        return NID_X9_62_c2tnb239v3;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb359v1:
        return NID_X9_62_c2tnb359v1;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb431r1:
        return NID_X9_62_c2tnb431r1;
    case Sailfish::Crypto::CryptoManager::CurveSecp160k1:
        return NID_secp160k1;
    case Sailfish::Crypto::CryptoManager::CurveSecp160r1:
        return NID_secp160r1;
    case Sailfish::Crypto::CryptoManager::CurveSecp160r2:
        return NID_secp160r2;
    case Sailfish::Crypto::CryptoManager::CurveSecp192k1:
        return NID_secp192k1;
    case Sailfish::Crypto::CryptoManager::CurveSecp192r1:
        return 0;
    case Sailfish::Crypto::CryptoManager::CurveSecp224k1:
        return NID_secp224k1;
    case Sailfish::Crypto::CryptoManager::CurveSecp224r1:
        return NID_secp224r1;
    case Sailfish::Crypto::CryptoManager::CurveSecp256k1:
        return NID_secp256k1;
    case Sailfish::Crypto::CryptoManager::CurveSecp256r1:
        return 0;
    case Sailfish::Crypto::CryptoManager::CurveSecp384r1:
        return NID_secp384r1;
    case Sailfish::Crypto::CryptoManager::CurveSecp521r1:
        return NID_secp521r1;
    default:
        return 0;
    }
}

int getEllipticCurveKeySize(Sailfish::Crypto::CryptoManager::EllipticCurve curve) {
    // TODO: add more curves
    switch (curve) {
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb163v1:
        return 163;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb163v2:
        return 163;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb163v3:
        return 163;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb176v1:
        return 176;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb208w1:
        return 208;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb272w1:
        return 272;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb304w1:
        return 304;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2pnb368w1:
        return 368;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb191v1:
        return 191;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb191v2:
        return 191;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb191v3:
        return 191;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb239v1:
        return 239;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb239v2:
        return 239;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb239v3:
        return 359;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb359v1:
        return 359;
    case Sailfish::Crypto::CryptoManager::CurveAX962c2tnb431r1:
        return 431;
    case Sailfish::Crypto::CryptoManager::CurveSecp160k1:
        return 160;
    case Sailfish::Crypto::CryptoManager::CurveSecp160r1:
        return 160;
    case Sailfish::Crypto::CryptoManager::CurveSecp160r2:
        return 160;
    case Sailfish::Crypto::CryptoManager::CurveSecp192k1:
        return 192;
    case Sailfish::Crypto::CryptoManager::CurveSecp192r1:
        return 192;
    case Sailfish::Crypto::CryptoManager::CurveSecp224k1:
        return 224;
    case Sailfish::Crypto::CryptoManager::CurveSecp224r1:
        return 224;
    case Sailfish::Crypto::CryptoManager::CurveSecp256k1:
        return 256;
    case Sailfish::Crypto::CryptoManager::CurveSecp256r1:
        return 256;
    case Sailfish::Crypto::CryptoManager::CurveSecp384r1:
        return 384;
    case Sailfish::Crypto::CryptoManager::CurveSecp521r1:
        return 521;
    default:
        return 0;
    }
}

typedef EVP_PKEY *(*evpKeyReadFunc)(BIO *, EVP_PKEY **, pem_password_cb *, void *);

EVP_PKEY *readEvpKey(const QByteArray &key, evpKeyReadFunc read)
{
    QScopedPointer<BIO, LibCrypto_BIO_Deleter> bio(BIO_new(BIO_s_mem()));

    // Use BIO to write public key data
    int r = BIO_write(bio.data(), key.data(), key.length());
    if (r != key.length()) {
        return Q_NULLPTR;
    }

    // Read the public key data into an EVP_PKEY
    EVP_PKEY *pkeyPtr = Q_NULLPTR;
    read(bio.data(), &pkeyPtr, Q_NULLPTR, Q_NULLPTR);

    return pkeyPtr;
}

EVP_PKEY *readEvpPrivKey(const QByteArray privKey)
{
    return readEvpKey(privKey, PEM_read_bio_PrivateKey);
}

EVP_PKEY *readEvpPubKey(const QByteArray pubKey)
{
    return readEvpKey(pubKey, PEM_read_bio_PUBKEY);
}

