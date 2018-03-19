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
    QByteArray generatedIV;
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

bool validInitializationVector(const QByteArray &initVector,
                               Sailfish::Crypto::CryptoManager::BlockMode blockMode,
                               Sailfish::Crypto::CryptoManager::Algorithm algorithm)
{
    if (blockMode == Sailfish::Crypto::CryptoManager::BlockModeEcb) {
        // IV not required for this mode
        return true;
    }

    // Ensure the IV has the correct size. The IV size for most modes is the same as the block size.
    switch (algorithm) {
    case Sailfish::Crypto::CryptoManager::AlgorithmAes:
        return initVector.size() == 16;  // AES = 128-bit block size
    default:
        break;
    }

    return false;
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

