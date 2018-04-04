/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/key.h"
#include "Crypto/certificate.h"
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

    if (algorithm == Sailfish::Crypto::CryptoManager::AlgorithmRsa
            || blockMode == Sailfish::Crypto::CryptoManager::BlockModeEcb) {
        // IV not required for these configurations
        return 0;
    }

    // Ensure the IV has the correct size. The IV size for most modes is the same as the block size.
    switch (algorithm) {
    case Sailfish::Crypto::CryptoManager::AlgorithmAes:
        if (blockMode == Sailfish::Crypto::CryptoManager::BlockModeGcm) {
            return SAILFISH_CRYPTO_GCM_IV_SIZE;
        } else {
            return 16;  // AES = 128-bit block size
        }
    default:
        break;
    }

    // Unrecognized configuration
    return -1;
}

const EVP_MD *getEvpDigestFunction(Sailfish::Crypto::CryptoManager::DigestFunction digestFunction) {
    switch (digestFunction) {
    case Sailfish::Crypto::CryptoManager::DigestSha256:
        return EVP_sha256();
        break;
    default:
        return Q_NULLPTR;
        break;
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
