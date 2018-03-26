/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHCRYPTO_APIIMPL_CRYPTOPLUGINFUNCTIONWRAPPERS_P_H
#define SAILFISHCRYPTO_APIIMPL_CRYPTOPLUGINFUNCTIONWRAPPERS_P_H

#include "Crypto/key.h"
#include "Crypto/extensionplugins.h"
#include "Crypto/cryptomanager.h"
#include "Crypto/result.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>

#include <tuple>

namespace Sailfish {

namespace Crypto {

struct TagDataResult {
    TagDataResult(const Sailfish::Crypto::Result &r = Sailfish::Crypto::Result(),
                  const QByteArray &d = QByteArray(),
                  const QByteArray &t = QByteArray())
        : result(r), data(d), tag(t) {}
    TagDataResult(const TagDataResult &other)
        : result(other.result), data(other.data), tag(other.tag) {}
    Sailfish::Crypto::Result result;
    QByteArray data;
    QByteArray tag;
};

struct DataResult {
    DataResult(const Sailfish::Crypto::Result &r = Sailfish::Crypto::Result(),
               const QByteArray &d = QByteArray())
        : result(r), data(d) {}
    DataResult(const DataResult &other)
        : result(other.result), data(other.data) {}
    Sailfish::Crypto::Result result;
    QByteArray data;
};

struct VerifiedDataResult {
    VerifiedDataResult(const Sailfish::Crypto::Result &r = Sailfish::Crypto::Result(),
                       const QByteArray &d = QByteArray(), bool v = false)
        : result(r), data(d), verified(v) {}
    VerifiedDataResult(const VerifiedDataResult &other)
        : result(other.result), data(other.data), verified(other.verified) {}
    Sailfish::Crypto::Result result;
    QByteArray data;
    bool verified;
};

struct ValidatedResult {
    ValidatedResult(const Sailfish::Crypto::Result &r = Sailfish::Crypto::Result(),
                    bool v = false)
        : result(r), validated(v) {}
    ValidatedResult(const ValidatedResult &other)
        : result(other.result), validated(other.validated) {}
    Sailfish::Crypto::Result result;
    bool validated;
};

struct KeyResult {
    KeyResult(const Sailfish::Crypto::Result &r = Sailfish::Crypto::Result(),
              const Sailfish::Crypto::Key &k = Sailfish::Crypto::Key())
        : result(r), key(k) {}
    KeyResult(const KeyResult &other)
        : result(other.result), key(other.key) {}
    Sailfish::Crypto::Result result;
    Sailfish::Crypto::Key key;
};

struct IdentifiersResult {
    IdentifiersResult(const Sailfish::Crypto::Result &r = Sailfish::Crypto::Result(),
                      const QVector<Sailfish::Crypto::Key::Identifier> &i = QVector<Sailfish::Crypto::Key::Identifier>())
        : result(r), identifiers(i) {}
    IdentifiersResult(const IdentifiersResult &other)
        : result(other.result), identifiers(other.identifiers) {}
    Sailfish::Crypto::Result result;
    QVector<Sailfish::Crypto::Key::Identifier> identifiers;
};

struct CipherSessionTokenResult {
    CipherSessionTokenResult(const Sailfish::Crypto::Result &r = Sailfish::Crypto::Result(),
                             quint32 cst = 0)
        : result(r), cipherSessionToken(cst) {}
    CipherSessionTokenResult(const CipherSessionTokenResult &other)
        : result(other.result)
        , cipherSessionToken(other.cipherSessionToken) {}
    Sailfish::Crypto::Result result;
    quint32 cipherSessionToken;
};

namespace Daemon {

namespace ApiImpl {

namespace CryptoPluginWrapper {

bool isLocked(Sailfish::Crypto::CryptoPlugin *plugin);
bool lock(Sailfish::Crypto::CryptoPlugin *plugin);
bool unlock(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const QByteArray &lockCode);
bool setLockCode(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const QByteArray &oldLockCode,
        const QByteArray &newLockCode);

DataResult generateRandomData(
        Sailfish::Crypto::CryptoPlugin *plugin,
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes);

Sailfish::Crypto::Result seedRandomDataGenerator(
        Sailfish::Crypto::CryptoPlugin *plugin,
        quint64 callerIdent,
        const QString &csprngEngineName,
        const QByteArray &seedData,
        double entropyEstimate);

DataResult generateInitializationVector(
        Sailfish::Crypto::CryptoPlugin *plugin,
        Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        int keySize);

ValidatedResult validateCertificateChain(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const QVector<Sailfish::Crypto::Certificate> &chain);

KeyResult importKey(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const Sailfish::Crypto::Key &keyData,
        const QByteArray &passphrase);

KeyResult importAndStoreKey(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const Sailfish::Crypto::Key &keyData,
        const QByteArray &passphrase);

KeyResult generateKey(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams);

KeyResult generateAndStoreKey(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams);

KeyResult storedKey(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const Sailfish::Crypto::Key::Identifier &identifier,
        Sailfish::Crypto::Key::Components keyComponents);

IdentifiersResult storedKeyIdentifiers(
        Sailfish::Crypto::CryptoPlugin *plugin);

DataResult calculateDigest(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const QByteArray &data,
        std::tuple<Sailfish::Crypto::CryptoManager::SignaturePadding,
                   Sailfish::Crypto::CryptoManager::DigestFunction> options);

DataResult sign(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        std::tuple<Sailfish::Crypto::CryptoManager::SignaturePadding,
                   Sailfish::Crypto::CryptoManager::DigestFunction> options);

ValidatedResult verify(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const QByteArray &signature,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        std::tuple<Sailfish::Crypto::CryptoManager::SignaturePadding,
                   Sailfish::Crypto::CryptoManager::DigestFunction> options);

TagDataResult encrypt(
        Sailfish::Crypto::CryptoPlugin *plugin,
        std::tuple<QByteArray, QByteArray> dataAndIv,
        const Sailfish::Crypto::Key &key,
        std::tuple<Sailfish::Crypto::CryptoManager::BlockMode,
                   Sailfish::Crypto::CryptoManager::EncryptionPadding> options,
        const QByteArray &authenticationData);

VerifiedDataResult decrypt(
        Sailfish::Crypto::CryptoPlugin *plugin,
        std::tuple<QByteArray, QByteArray> dataAndIv,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        std::tuple<Sailfish::Crypto::CryptoManager::BlockMode,
                   Sailfish::Crypto::CryptoManager::EncryptionPadding> options,
        std::tuple<QByteArray, QByteArray> authDataAndTag);

CipherSessionTokenResult initialiseCipherSession(
        Sailfish::Crypto::CryptoPlugin *plugin,
        quint64 clientId,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        std::tuple<CryptoManager::Operation,
                   CryptoManager::BlockMode,
                   CryptoManager::EncryptionPadding,
                   CryptoManager::SignaturePadding,
                   CryptoManager::DigestFunction> options);

Sailfish::Crypto::Result updateCipherSessionAuthentication(
        Sailfish::Crypto::CryptoPlugin *plugin,
        quint64 clientId,
        const QByteArray &authenticationData,
        quint32 cipherSessionToken);

DataResult updateCipherSession(
        Sailfish::Crypto::CryptoPlugin *plugin,
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken);

VerifiedDataResult finaliseCipherSession(
        Sailfish::Crypto::CryptoPlugin *plugin,
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken);

} // CryptoPluginWrapper

} // ApiImpl

} // Daemon

} // Crypto

} // Sailfish

#endif // SAILFISHCRYPTO_APIIMPL_CRYPTOPLUGINFUNCTIONWRAPPERS_P_H
