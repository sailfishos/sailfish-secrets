/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHCRYPTO_APIIMPL_CRYPTOPLUGINFUNCTIONWRAPPERS_P_H
#define SAILFISHCRYPTO_APIIMPL_CRYPTOPLUGINFUNCTIONWRAPPERS_P_H

#include "CryptoImpl/cryptopluginwrapper_p.h"

#include "CryptoPluginApi/extensionplugins.h"

#include "Crypto/key.h"
#include "Crypto/cryptomanager.h"
#include "Crypto/result.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>

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

struct SignatureOptions {
    SignatureOptions(Sailfish::Crypto::CryptoManager::SignaturePadding p = Sailfish::Crypto::CryptoManager::SignaturePaddingNone,
                     Sailfish::Crypto::CryptoManager::DigestFunction df = Sailfish::Crypto::CryptoManager::DigestUnknown)
        : signaturePadding(p), digestFunction(df) {}
    SignatureOptions(const SignatureOptions &other)
        : signaturePadding(other.signaturePadding)
        , digestFunction(other.digestFunction) {}
    Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding;
    Sailfish::Crypto::CryptoManager::DigestFunction digestFunction;
};

struct EncryptionOptions {
    EncryptionOptions(Sailfish::Crypto::CryptoManager::BlockMode bm = Sailfish::Crypto::CryptoManager::BlockModeUnknown,
                      Sailfish::Crypto::CryptoManager::EncryptionPadding p = Sailfish::Crypto::CryptoManager::EncryptionPaddingNone)
        : blockMode(bm), encryptionPadding(p) {}
    EncryptionOptions(const EncryptionOptions &other)
        : blockMode(other.blockMode)
        , encryptionPadding(other.encryptionPadding) {}
    Sailfish::Crypto::CryptoManager::BlockMode blockMode;
    Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding;
};

struct CipherSessionOptions {
    CipherSessionOptions(Sailfish::Crypto::CryptoManager::Operation op = Sailfish::Crypto::CryptoManager::OperationUnknown,
                         Sailfish::Crypto::CryptoManager::BlockMode bm = Sailfish::Crypto::CryptoManager::BlockModeUnknown,
                         Sailfish::Crypto::CryptoManager::EncryptionPadding ep = Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
                         Sailfish::Crypto::CryptoManager::SignaturePadding sp = Sailfish::Crypto::CryptoManager::SignaturePaddingNone,
                         Sailfish::Crypto::CryptoManager::DigestFunction df = Sailfish::Crypto::CryptoManager::DigestUnknown)
        : operation(op), blockMode(bm), encryptionPadding(ep), signaturePadding(sp), digestFunction(df) {}
    CipherSessionOptions(const CipherSessionOptions &other)
        : operation(other.operation)
        , blockMode(other.blockMode)
        , encryptionPadding(other.encryptionPadding)
        , signaturePadding(other.signaturePadding)
        , digestFunction(other.digestFunction) {}
    Sailfish::Crypto::CryptoManager::Operation operation;
    Sailfish::Crypto::CryptoManager::BlockMode blockMode;
    Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding;
    Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding;
    Sailfish::Crypto::CryptoManager::DigestFunction digestFunction;
};

struct DataAndIV {
    DataAndIV(const QByteArray &d = QByteArray(),
              const QByteArray &iv = QByteArray())
        : data(d), initVector(iv) {}
    DataAndIV(const DataAndIV &other)
        : data(other.data)
        , initVector(other.initVector) {}
    QByteArray data;
    QByteArray initVector;
};

struct AuthDataAndTag {
    AuthDataAndTag(const QByteArray &ad = QByteArray(),
                   const QByteArray &t = QByteArray())
        : authData(ad)
        , tag(t) {}
    AuthDataAndTag(const AuthDataAndTag &other)
        : authData(other.authData)
        , tag(other.tag) {}
    QByteArray authData;
    QByteArray tag;
};

struct PluginAndCustomParams {
    PluginAndCustomParams(CryptoPlugin *p = Q_NULLPTR, const QVariantMap &cp = QVariantMap())
        : plugin(p), customParameters(cp) {}
    PluginAndCustomParams(const PluginAndCustomParams &other)
        : plugin(other.plugin)
        , customParameters(other.customParameters) {}
    CryptoPlugin *plugin;
    QVariantMap customParameters;
};

struct PluginWrapperAndCustomParams {
    PluginWrapperAndCustomParams(Daemon::ApiImpl::CryptoStoragePluginWrapper *p = Q_NULLPTR,
                                 const QVariantMap &cp = QVariantMap())
        : plugin(p), customParameters(cp) {}
    PluginWrapperAndCustomParams(const PluginWrapperAndCustomParams &other)
        : plugin(other.plugin)
        , customParameters(other.customParameters) {}
    Daemon::ApiImpl::CryptoStoragePluginWrapper *plugin;
    QVariantMap customParameters;
};

namespace Daemon {

namespace ApiImpl {

namespace CryptoPluginFunctionWrapper {

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
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes);

Sailfish::Crypto::Result seedRandomDataGenerator(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 callerIdent,
        const QString &csprngEngineName,
        const QByteArray &seedData,
        double entropyEstimate);

DataResult generateInitializationVector(
        const PluginAndCustomParams &pluginAndCustomParams,
        Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        int keySize);

KeyResult importKey(
        const PluginAndCustomParams &pluginAndCustomParams,
        const Sailfish::Crypto::Key &keyData,
        const QByteArray &passphrase);

KeyResult importAndStoreKey(
        const PluginWrapperAndCustomParams &pluginAndCustomParams,
        const Sailfish::Crypto::Key &keyData,
        const QByteArray &passphrase,
        const QByteArray &collectionDecryptionKey);

KeyResult generateKey(
        const PluginAndCustomParams &pluginAndCustomParams,
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams);

KeyResult storedKey(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const Sailfish::Crypto::Key::Identifier &identifier,
        Sailfish::Crypto::Key::Components keyComponents);

IdentifiersResult storedKeyIdentifiers(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const QString &collectionName);

DataResult calculateDigest(
        const PluginAndCustomParams &pluginAndCustomParams,
        const QByteArray &data,
        const SignatureOptions &options);

DataResult sign(
        const PluginAndCustomParams &pluginAndCustomParams,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        const SignatureOptions &options);

ValidatedResult verify(
        const PluginAndCustomParams &pluginAndCustomParams,
        const QByteArray &signature,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        const SignatureOptions &options);

TagDataResult encrypt(
        const PluginAndCustomParams &pluginAndCustomParams,
        const DataAndIV &dataAndIv,
        const Sailfish::Crypto::Key &key,
        const EncryptionOptions &options,
        const QByteArray &authenticationData);

VerifiedDataResult decrypt(
        const PluginAndCustomParams &pluginAndCustomParams,
        const DataAndIV &dataAndIv,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        const EncryptionOptions &options,
        const AuthDataAndTag &authDataAndTag);

CipherSessionTokenResult initialiseCipherSession(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 clientId,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        const CipherSessionOptions &options);

Sailfish::Crypto::Result updateCipherSessionAuthentication(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 clientId,
        const QByteArray &authenticationData,
        quint32 cipherSessionToken);

DataResult updateCipherSession(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken);

VerifiedDataResult finaliseCipherSession(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken);

KeyResult generateAndStoreKey(
        const PluginWrapperAndCustomParams &pluginAndCustomParams,
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        const QByteArray &collectionUnlockCode);

} // CryptoPluginFunctionWrapper

} // ApiImpl

} // Daemon

} // Crypto

} // Sailfish

#endif // SAILFISHCRYPTO_APIIMPL_CRYPTOPLUGINFUNCTIONWRAPPERS_P_H
