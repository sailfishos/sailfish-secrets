/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/key.h"
#include "Crypto/certificate.h"

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

#include <openssl/rand.h>

#define CIPHER_SESSION_INACTIVITY_TIMEOUT 60000 /* 1 minute, change to 10 sec for timeout test */
#define MAX_CIPHER_SESSIONS_PER_CLIENT 5
#define SAILFISH_CRYPTO_GCM_TAG_SIZE 16

class CipherSessionData
{
public:
    QByteArray iv;
    Sailfish::Crypto::Key key;
    Sailfish::Crypto::Key::Operation operation = Sailfish::Crypto::Key::OperationUnknown;
    Sailfish::Crypto::Key::BlockMode blockMode = Sailfish::Crypto::Key::BlockModeUnknown;
    Sailfish::Crypto::Key::EncryptionPadding encryptionPadding = Sailfish::Crypto::Key::EncryptionPaddingUnknown;
    Sailfish::Crypto::Key::SignaturePadding signaturePadding = Sailfish::Crypto::Key::SignaturePaddingUnknown;
    Sailfish::Crypto::Key::Digest digest = Sailfish::Crypto::Key::DigestUnknown;
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

namespace {
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
}

QVector<Sailfish::Crypto::Key::Algorithm>
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedAlgorithms() const
{
    QVector<Sailfish::Crypto::Key::Algorithm> retn;
    retn.append(Sailfish::Crypto::Key::Aes256);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes>
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedBlockModes() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::BlockModeCBC);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings>
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedEncryptionPaddings() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::EncryptionPaddingNone);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings>
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedSignaturePaddings() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::SignaturePaddingNone);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests>
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedDigests() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::DigestSha256);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations>
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedOperations() const
{
    // TODO: should this be algorithm specific?  not sure?
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::Encrypt | Sailfish::Crypto::Key::Decrypt);
    return retn;
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::generateRandomData(
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes,
        QByteArray *randomData)
{
    Q_UNUSED(callerIdent)

    static const int maxBytes = 4096;
    bool useDevURandom = false;

    if (csprngEngineName == QStringLiteral("/dev/urandom")) {
        useDevURandom = true;
    } else if (csprngEngineName != Sailfish::Crypto::GenerateRandomDataRequest::DefaultCsprngEngineName) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginRandomDataError,
                                        QLatin1String("This crypto plugin only supports default and /dev/urandom engines"));
    }

    if (!numberBytes || numberBytes > maxBytes) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginRandomDataError,
                                        QLatin1String("This crypto plugin can only generate up to 4096 bytes of random data at a time"));
    }

    int nbytes = numberBytes;
    QScopedPointer<char> buf(new char[nbytes]);
    if (useDevURandom) {
        std::ifstream rand("/dev/urandom");
        rand.read(buf.data(), nbytes);
        rand.close();
    } else if (RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()), nbytes) != 1) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginRandomDataError,
                                        QLatin1String("This crypto plugin failed to generate the random data"));
    }

    *randomData = QByteArray(reinterpret_cast<const char *>(buf.data()), nbytes);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::validateCertificateChain(
        const QVector<Sailfish::Crypto::Certificate> &chain,
        bool *validated)
{
    Q_UNUSED(chain);
    Q_UNUSED(validated);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: validateCertificateChain"));
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::generateKey(
        const Sailfish::Crypto::Key &keyTemplate,
        Sailfish::Crypto::Key *key)
{
    if (keyTemplate.algorithm() != Sailfish::Crypto::Key::Aes256) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: algorithms other than Aes256"));
    }

    const QUuid seed = QUuid::createUuid();
    const QByteArray hashed = QCryptographicHash::hash(seed.toByteArray(), QCryptographicHash::Sha256);
    *key = keyTemplate;
    key->setSecretKey(hashed);

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::sign(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        QByteArray *signature)
{
    // TODO: support more operations and algorithms in this plugin!
    Q_UNUSED(data);
    Q_UNUSED(key);
    Q_UNUSED(padding);
    Q_UNUSED(digest);
    Q_UNUSED(signature);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: sign"));
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::verify(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        bool *verified)
{
    // TODO: support more operations and algorithms in this plugin!
    Q_UNUSED(data);
    Q_UNUSED(key);
    Q_UNUSED(padding);
    Q_UNUSED(digest);
    Q_UNUSED(verified);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: verify"));
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        QByteArray *encrypted)
{
    Sailfish::Crypto::Key fullKey = getFullKey(key);
    if (fullKey.secretKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySecretKey,
                                        QLatin1String("Cannot encrypt with empty secret key"));
    }

    if (fullKey.algorithm() != Sailfish::Crypto::Key::Aes256) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: algorithms other than Aes256"));
    }

    if (blockMode != Sailfish::Crypto::Key::BlockModeCBC) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: block modes other than CBC"));
    }

    if (padding != Sailfish::Crypto::Key::EncryptionPaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: encryption padding other than None"));
    }

    // generate key hash and normalise init vector
    QCryptographicHash keyHash(QCryptographicHash::Sha512);
    keyHash.addData(fullKey.secretKey());
    QByteArray initVector = iv;
    if (initVector.size() > 16) {
        initVector.chop(initVector.size() - 16);
    } else while (initVector.size() < 16) {
        initVector.append('\0');
    }

    // encrypt plaintext
    QByteArray ciphertext = aes_encrypt_plaintext(data, keyHash.result(), initVector);

    // return result
    if (ciphertext.size()) {
        *encrypted = ciphertext;
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    }

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginEncryptionError,
                                     QLatin1String("OpenSSL crypto plugin failed to encrypt the data"));
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::decrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        QByteArray *decrypted)
{
    Sailfish::Crypto::Key fullKey = getFullKey(key);
    if (fullKey.secretKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySecretKey,
                                        QLatin1String("Cannot decrypt with empty secret key"));
    }

    if (fullKey.algorithm() != Sailfish::Crypto::Key::Aes256) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: algorithms other than Aes256"));
    }

    if (blockMode != Sailfish::Crypto::Key::BlockModeCBC) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: block modes other than CBC"));
    }

    if (padding != Sailfish::Crypto::Key::EncryptionPaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: encryption padding other than None"));
    }

    // generate key hash and normalise init vector
    QCryptographicHash keyHash(QCryptographicHash::Sha512);
    keyHash.addData(fullKey.secretKey());
    QByteArray initVector = iv;
    if (initVector.size() > 16) {
        initVector.chop(initVector.size() - 16);
    } else while (initVector.size() < 16) {
        initVector.append('\0');
    }

    // decrypt ciphertext
    QByteArray plaintext = aes_decrypt_ciphertext(data, keyHash.result(), initVector);
    if (!plaintext.size() || (plaintext.size() == 1 && plaintext.at(0) == 0)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginDecryptionError,
                                         QLatin1String("Failed to decrypt the secret"));
    }

    // return result
    *decrypted = plaintext;
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::initialiseCipherSession(
        quint64 clientId,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        Sailfish::Crypto::Key::Operation operation,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding encryptionPadding,
        Sailfish::Crypto::Key::SignaturePadding signaturePadding,
        Sailfish::Crypto::Key::Digest digest,
        quint32 *cipherSessionToken,
        QByteArray *generatedIV)
{
    Sailfish::Crypto::Key fullKey = getFullKey(key);
    if (fullKey.secretKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySecretKey,
                                        QLatin1String("Cannot create a cipher session with empty secret key"));
    }

    if (fullKey.algorithm() != Sailfish::Crypto::Key::Aes256) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: algorithms other than Aes256"));
    }

    if (blockMode != Sailfish::Crypto::Key::BlockModeCBC) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: block modes other than CBC"));
    }

    if (encryptionPadding != Sailfish::Crypto::Key::EncryptionPaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: encryption padding other than None"));
    }

    if (signaturePadding != Sailfish::Crypto::Key::SignaturePaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: signature padding other than None"));
    }

    if (digest != Sailfish::Crypto::Key::DigestSha256) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: digests other than Sha256"));
    }

    quint32 sessionToken = getNextCipherSessionToken(&m_cipherSessions, clientId);
    if (sessionToken == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Too many concurrent cipher sessions initiated by client"));
    }

    QByteArray initIV(iv);
    if (operation == Sailfish::Crypto::Key::Encrypt
            && fullKey.algorithm() == Sailfish::Crypto::Key::Aes256) {
        if (iv.size() != 16) {
            // the user-supplied IV is the wrong size.
            // generate an appropriately sized IV.
            unsigned char ivBuf[16] = { 0 };
            if (RAND_bytes(ivBuf, 16) != 1) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to generate initialisation vector"));
            }
            *generatedIV = QByteArray(reinterpret_cast<char*>(ivBuf), 16);
            initIV = *generatedIV;
        }
    }

    EVP_MD_CTX *evp_md_ctx = NULL;
    EVP_CIPHER_CTX *evp_cipher_ctx = NULL;
    if (operation == Sailfish::Crypto::Key::Encrypt) {
        evp_cipher_ctx = EVP_CIPHER_CTX_new();
        if (evp_cipher_ctx == NULL) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Unable to initialise cipher context for encryption"));
        }
        if (fullKey.algorithm() == Sailfish::Crypto::Key::Aes256
                && blockMode == Sailfish::Crypto::Key::BlockModeCBC) {
            if (fullKey.secretKey().size() != 32) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Invalid key size for AES 256 operation"));
            }
            if (EVP_EncryptInit_ex(evp_cipher_ctx, EVP_aes_256_cbc(), NULL,
                                   reinterpret_cast<const unsigned char*>(fullKey.secretKey().constData()),
                                   reinterpret_cast<const unsigned char*>(initIV.constData())) != 1) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to initialise encryption cipher context in AES 256 CBC mode"));
            }
        }
    } else if (operation == Sailfish::Crypto::Key::Decrypt) {
        evp_cipher_ctx = EVP_CIPHER_CTX_new();
        if (evp_cipher_ctx == NULL) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Unable to initialise cipher context for decryption"));
        }
        if (fullKey.algorithm() == Sailfish::Crypto::Key::Aes256
                && blockMode == Sailfish::Crypto::Key::BlockModeCBC) {
            if (fullKey.secretKey().size() != 32) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Invalid key size for AES 256 operation"));
            }
            if (EVP_DecryptInit_ex(evp_cipher_ctx, EVP_aes_256_cbc(), NULL,
                                   reinterpret_cast<const unsigned char *>(fullKey.secretKey().constData()),
                                   reinterpret_cast<const unsigned char *>(initIV.constData())) != 1) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to initialise decryption cipher context in AES 256 CBC mode"));
            }
        }
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("TODO: implement sign/verify data!"));
    }

    CipherSessionData *csd = new CipherSessionData;
    csd->iv = initIV;
    csd->key = fullKey;
    csd->operation = operation;
    csd->blockMode = blockMode;
    csd->encryptionPadding = encryptionPadding;
    csd->signaturePadding = signaturePadding;
    csd->digest = digest;
    csd->cipherSessionToken = sessionToken;
    csd->generatedIV = *generatedIV;
    csd->evp_cipher_ctx = evp_cipher_ctx;
    csd->evp_md_ctx = evp_md_ctx;
    QTimer *timeout = new QTimer(this);
    timeout->setSingleShot(true);
    timeout->setInterval(CIPHER_SESSION_INACTIVITY_TIMEOUT);
    QObject::connect(timeout, &QTimer::timeout,
                     [this, timeout] {
        CipherSessionLookup lookup(this->m_cipherSessionTimeouts.take(timeout));
        if (lookup.csd) {
            this->m_cipherSessions[lookup.clientId].remove(lookup.sessionToken);
            QScopedPointer<CipherSessionData,CipherSessionDataDeleter> csdd(lookup.csd);
        } else {
            timeout->deleteLater();
        }
    });
    timeout->start();
    csd->timeout = timeout;
    m_cipherSessions[clientId].insert(sessionToken, csd);

    CipherSessionLookup lookup;
    lookup.csd = csd;
    lookup.sessionToken = sessionToken;
    lookup.clientId = clientId;
    m_cipherSessionTimeouts.insert(timeout, lookup);

    *cipherSessionToken = sessionToken;
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::updateCipherSessionAuthentication(
        quint64 clientId,
        const QByteArray &authenticationData,
        quint32 cipherSessionToken)
{
    if (!m_cipherSessions.contains(clientId)
            || !m_cipherSessions[clientId].contains(cipherSessionToken)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Unknown cipher session token provided"));
    }

    CipherSessionData *csd = m_cipherSessions[clientId].value(cipherSessionToken);
    if (csd->blockMode != Sailfish::Crypto::Key::BlockModeGCM) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Block mode is not GCM, cannot update authentication data"));
    } else if (csd->evp_cipher_ctx == NULL) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Cipher context has not been initialised"));
    }

    csd->timeout->start(); // restart the timeout due to activity.
    int len = 0;
    if (csd->operation == Sailfish::Crypto::Key::Encrypt) {
        if (EVP_EncryptUpdate(csd->evp_cipher_ctx, NULL, &len,
                              reinterpret_cast<const unsigned char *>(authenticationData.constData()),
                              authenticationData.size()) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Failed to update encryption cipher authentication data"));
        }
    } else if (csd->operation == Sailfish::Crypto::Key::Decrypt) {
        if (EVP_DecryptUpdate(csd->evp_cipher_ctx, NULL, &len,
                              reinterpret_cast<const unsigned char *>(authenticationData.constData()),
                              authenticationData.size()) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Failed to update decryption cipher authentication data"));
        }
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("TODO: implement sign/verify authentication data!"));
    }

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::updateCipherSession(
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken,
        QByteArray *generatedData)
{
    if (!m_cipherSessions.contains(clientId)
            || !m_cipherSessions[clientId].contains(cipherSessionToken)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Unknown cipher session token provided"));
    }

    CipherSessionData *csd = m_cipherSessions[clientId].value(cipherSessionToken);
    if (csd->evp_cipher_ctx == NULL) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Cipher context has not been initialised"));
    }

    csd->timeout->start(); // restart the timeout due to activity.
    int blockSizeForCipher = 16; // TODO: lookup for different algorithms, but AES is 128 bit blocks = 16 bytes
    QScopedPointer<unsigned char> generatedDataBuf(new unsigned char[data.size() + blockSizeForCipher]);
    int generatedDataSize = 0;
    if (csd->operation == Sailfish::Crypto::Key::Encrypt) {
        if (EVP_EncryptUpdate(csd->evp_cipher_ctx,
                              generatedDataBuf.data(), &generatedDataSize,
                              reinterpret_cast<const unsigned char *>(data.constData()),
                              data.size()) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Failed to update encryption cipher data"));
        }
    } else if (csd->operation == Sailfish::Crypto::Key::Decrypt) {
        if (EVP_DecryptUpdate(csd->evp_cipher_ctx,
                              generatedDataBuf.data(), &generatedDataSize,
                              reinterpret_cast<const unsigned char *>(data.constData()),
                              data.size()) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Failed to update decryption cipher data"));
        }
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("TODO: implement sign/verify data!"));
    }

    *generatedData = QByteArray(reinterpret_cast<const char *>(generatedDataBuf.data()), generatedDataSize);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::finaliseCipherSession(
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken,
        QByteArray *generatedData,
        bool *verified)
{
    if (!m_cipherSessions.contains(clientId)
            || !m_cipherSessions[clientId].contains(cipherSessionToken)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Unknown cipher session token provided"));
    }

    CipherSessionData *csd = m_cipherSessions[clientId].value(cipherSessionToken);
    if (csd->evp_cipher_ctx == NULL) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Cipher context has not been initialised"));
    }

    QScopedPointer<CipherSessionData,CipherSessionDataDeleter> csdd(m_cipherSessions[clientId].take(cipherSessionToken));
    m_cipherSessionTimeouts.remove(csd->timeout);
    int blockSizeForCipher = 16; // TODO: lookup for different algorithms, but AES is 128 bit blocks = 16 bytes
    QScopedPointer<unsigned char> generatedDataBuf(new unsigned char[blockSizeForCipher*2]); // final 1 or 2 blocks.
    int generatedDataSize = 0;
    if (csd->operation == Sailfish::Crypto::Key::Encrypt) {
        if (EVP_EncryptFinal_ex(csd->evp_cipher_ctx, generatedDataBuf.data(), &generatedDataSize) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Failed to finalise encryption cipher"));
        }
        if (csd->blockMode == Sailfish::Crypto::Key::BlockModeGCM) {
            // in GCM mode, the finalisation above does not write extra ciphertext.
            // instead, we should retrieve the tag.
            if (generatedDataSize > 0) {
                // This should never happen.
                qWarning() << "INTERNAL ERROR: GCM finalisation produced ciphertext data!";
            }
            generatedDataBuf.reset(new unsigned char[SAILFISH_CRYPTO_GCM_TAG_SIZE]);
            generatedDataSize = SAILFISH_CRYPTO_GCM_TAG_SIZE;
            if (EVP_CIPHER_CTX_ctrl(csd->evp_cipher_ctx, EVP_CTRL_GCM_GET_TAG, generatedDataSize, generatedDataBuf.data()) != 1) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Failed to retrieve authentication tag"));
            }
        }
    } else if (csd->operation == Sailfish::Crypto::Key::Decrypt) {
        if (csd->blockMode == Sailfish::Crypto::Key::BlockModeGCM) {
            // in GCM mode, the finalisation requires setting the provided tag data.
            if (data.size() != SAILFISH_CRYPTO_GCM_TAG_SIZE) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("GCM tag data is not the expected size"));
            }
            QByteArray tagData(data);
            if (!EVP_CIPHER_CTX_ctrl(csd->evp_cipher_ctx, EVP_CTRL_GCM_SET_TAG, data.size(),
                                     reinterpret_cast<void *>(tagData.data()))) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to set the GCM tag to finalise the cipher"));
            }
            int evpRet = EVP_DecryptFinal_ex(csd->evp_cipher_ctx, generatedDataBuf.data(), &generatedDataSize);
            *verified = evpRet > 0;
        } else {
            if (EVP_DecryptFinal_ex(csd->evp_cipher_ctx, generatedDataBuf.data(), &generatedDataSize) != 1) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Failed to finalise the decryption cipher"));
            }
        }
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("TODO: implement sign/verify authentication data!"));
    }

    *generatedData = QByteArray(reinterpret_cast<const char *>(generatedDataBuf.data()), generatedDataSize);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

QByteArray
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::aes_encrypt_plaintext(
        const QByteArray &plaintext,
        const QByteArray &key,
        const QByteArray &init_vector)
{
    QByteArray encryptedData;
    unsigned char *encrypted = NULL;
    int size = osslevp_aes_encrypt_plaintext((const unsigned char *)init_vector.constData(),
                                             (const unsigned char *)key.constData(),
                                             key.size(),
                                             (const unsigned char *)plaintext.constData(),
                                             plaintext.size(),
                                             &encrypted);
    if (size <= 0) {
        return encryptedData;
    }

    encryptedData = QByteArray((const char *)encrypted, size);
    free(encrypted);
    return encryptedData;
}

QByteArray
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::aes_decrypt_ciphertext(
        const QByteArray &ciphertext,
        const QByteArray &key,
        const QByteArray &init_vector)
{
    QByteArray decryptedData;
    unsigned char *decrypted = NULL;
    int size = osslevp_aes_decrypt_ciphertext((const unsigned char *)init_vector.constData(),
                                              (const unsigned char *)key.constData(),
                                              key.size(),
                                              (const unsigned char *)ciphertext.constData(),
                                              ciphertext.size(),
                                              &decrypted);
    if (size <= 0) {
        return decryptedData;
    }

    decryptedData = QByteArray((const char *)decrypted, size);
    free(decrypted);
    return decryptedData;
}
