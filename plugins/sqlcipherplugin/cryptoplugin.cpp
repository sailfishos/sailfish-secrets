/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "sqlcipherplugin.h"
#include "evp_p.h"

#include "util_p.h"

#include "Crypto/key.h"
#include "Crypto/generaterandomdatarequest.h"

#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>
#include <QtCore/QUuid>
#include <QtCore/QCryptographicHash>

#include <fstream>
#include <cstdlib>

#include <openssl/rand.h>

namespace {
    void nullifyKeyFields(Sailfish::Crypto::Key *key, Sailfish::Crypto::Key::Components keep) {
        // Null-out fields if the client hasn't specified that they be kept,
        // or which the key component constraints don't allow to be read back.
        // Note that by default we treat CustomParameters as PublicKeyData.
        Sailfish::Crypto::Key::Components kcc = key->componentConstraints();
        if (!(keep & Sailfish::Crypto::Key::MetaData)
                || !(kcc & Sailfish::Crypto::Key::MetaData)) {
            key->setIdentifier(Sailfish::Crypto::Key::Identifier());
            key->setOrigin(Sailfish::Crypto::Key::OriginUnknown);
            key->setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmUnknown);
            key->setOperations(Sailfish::Crypto::CryptoManager::OperationUnknown);
            key->setComponentConstraints(Sailfish::Crypto::Key::NoData);
            key->setFilterData(Sailfish::Crypto::Key::FilterData());
        }

        if (!(keep & Sailfish::Crypto::Key::PublicKeyData)
                || !(kcc & Sailfish::Crypto::Key::PublicKeyData)) {
            key->setCustomParameters(QVector<QByteArray>());
            key->setPublicKey(QByteArray());
        }

        if (!(keep & Sailfish::Crypto::Key::PrivateKeyData)
                || !(kcc & Sailfish::Crypto::Key::PrivateKeyData)) {
            key->setPrivateKey(QByteArray());
            key->setSecretKey(QByteArray());
        }
    }
}

using namespace Sailfish::Secrets::Daemon::Util;

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::seedRandomDataGenerator(
        quint64 callerIdent,
        const QString &csprngEngineName,
        const QByteArray &seedData,
        double entropyEstimate,
        const QVariantMap & /* customParameters */)
{
    Q_UNUSED(callerIdent)
    Q_UNUSED(csprngEngineName)
    Q_UNUSED(seedData)
    Q_UNUSED(entropyEstimate)
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginRandomDataError,
                                    QLatin1String("The SQLCipher crypto plugin doesn't support client-provided seed data"));
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::generateAndStoreKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *keyMetadata)
{
    if (keyTemplate.identifier().name().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Empty key name given"));
    } else if (keyTemplate.identifier().collectionName().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (keyTemplate.identifier().collectionName().compare(QLatin1String("standalone"), Qt::CaseInsensitive) == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Invalid collection name given"));
    }

    Sailfish::Crypto::Key fullKey(keyTemplate);
    Sailfish::Crypto::Result retn = generateKey(keyTemplate, kpgParams, skdfParams, customParameters, &fullKey);
    if (retn.code() == Sailfish::Crypto::Result::Failed) {
        return retn;
    }

    // store the key as a secret.
    const QMap<QString, QString> filterData(fullKey.filterData());
    Sailfish::Secrets::Result storeResult = setSecret(
                fullKey.identifier().collectionName(),
                fullKey.identifier().name(),
                Sailfish::Crypto::Key::serialise(fullKey, Sailfish::Crypto::Key::LossySerialisationMode),
                filterData);
    if (storeResult.code() == Sailfish::Secrets::Result::Failed) {
        retn.setCode(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(storeResult.errorCode());
        retn.setErrorMessage(storeResult.errorMessage());
        return retn;
    }

    Sailfish::Crypto::Key partialKey(fullKey);
    partialKey.setSecretKey(QByteArray());
    partialKey.setPrivateKey(QByteArray());
    *keyMetadata = partialKey;
    return retn;
}


Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::importAndStoreKey(
        const Sailfish::Crypto::Key &key,
        const QByteArray &passphrase,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *keyMetadata)
{
    if (key.identifier().name().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Empty key name given"));
    } else if (key.identifier().collectionName().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (key.identifier().collectionName().compare(QLatin1String("standalone"), Qt::CaseInsensitive) == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Invalid collection name given"));
    }

    Sailfish::Crypto::Key importedKey(key);
    Sailfish::Crypto::Result retn = importKey(key, passphrase, customParameters, &importedKey);
    if (retn.code() == Sailfish::Crypto::Result::Failed) {
        return retn;
    }

    // store the key as a secret.
    const QMap<QString, QString> filterData(importedKey.filterData());
    Sailfish::Secrets::Result storeResult = setSecret(
                importedKey.identifier().collectionName(),
                importedKey.identifier().name(),
                Sailfish::Crypto::Key::serialise(importedKey, Sailfish::Crypto::Key::LossySerialisationMode),
                filterData);
    if (storeResult.code() == Sailfish::Secrets::Result::Failed) {
        retn.setCode(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(storeResult.errorCode());
        retn.setErrorMessage(storeResult.errorMessage());
        return retn;
    }

    Sailfish::Crypto::Key partialKey(importedKey);
    partialKey.setSecretKey(QByteArray());
    partialKey.setPrivateKey(QByteArray());
    *keyMetadata = partialKey;
    return retn;
}


Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::storedKey_internal(
        const Sailfish::Crypto::Key::Identifier &identifier,
        Sailfish::Crypto::Key *key)
{
    if (identifier.name().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Empty key name given"));
    } else if (identifier.collectionName().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (identifier.collectionName().compare(QLatin1String("standalone"), Qt::CaseInsensitive) == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Invalid collection name given"));
    }

    QByteArray secret;
    Sailfish::Secrets::Secret::FilterData sfd;
    Sailfish::Secrets::Result storageResult = getSecret(
                identifier.collectionName(),
                identifier.name(),
                &secret,
                &sfd);
    if (storageResult.code() == Sailfish::Secrets::Result::Failed) {
        return transformSecretsResult(storageResult);
    }

    QMap<QString, QString> filterData = sfd;

    bool ok = true;
    Sailfish::Crypto::Key fullKey = Sailfish::Crypto::Key::deserialise(secret, &ok);
    if (!ok) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::SerialisationError,
                                        QLatin1String("Unable to deserialise key from secret blob"));
    }

    fullKey.setIdentifier(Sailfish::Crypto::Key::Identifier(
            identifier.name(), identifier.collectionName(), name()));
    fullKey.setFilterData(filterData);
    *key = fullKey;
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::storedKey(
        const Sailfish::Crypto::Key::Identifier &identifier,
        Sailfish::Crypto::Key::Components keyComponents,
        Sailfish::Crypto::Key *key)
{
    Sailfish::Crypto::Key fullKey;
    Sailfish::Crypto::Result retn = storedKey_internal(
                identifier,
                &fullKey);
    *key = fullKey;
    nullifyKeyFields(key, keyComponents);
    return retn;
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::storedKeyIdentifiers(
        const QString &collectionName,
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
{
    bool locked = false;
    Sailfish::Secrets::Result result = isCollectionLocked(collectionName, &locked);
    if (result.code() != Result::Succeeded) {
        return transformSecretsResult(result);
    }

    if (locked) {
        return transformSecretsResult(
                    Sailfish::Secrets::Result(
                        Sailfish::Secrets::Result::CollectionIsLockedError,
                        QStringLiteral("Collection %1 is locked")
                        .arg(collectionName)));
    }

    QStringList snames;
    result = secretNames(collectionName, &snames);
    if (result.code() != Result::Succeeded) {
        return transformSecretsResult(result);
    }

    for (const QString &sname : snames) {
        identifiers->append(Sailfish::Crypto::Key::Identifier(
                                sname, collectionName, name()));
    }

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}


Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::getFullKey(
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key *fullKey)
{
    Sailfish::Crypto::Result result(Sailfish::Crypto::Result::Succeeded);
    if (!key.identifier().name().isEmpty()
            && key.identifier().storagePluginName() == name()) {
        // this is a reference to a key which should be stored in our storage.
        Sailfish::Crypto::Key readKey;
        result = storedKey_internal(key.identifier(), &readKey);
        if (result.code() == Sailfish::Crypto::Result::Succeeded) {
            *fullKey = readKey;
        }
    } else {
        // this is not a reference key but is a normal key.
        *fullKey = key;
    }
    return result;
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::generateRandomData(
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes,
        const QVariantMap &customParameters,
        QByteArray *randomData)
{
    return m_opensslCryptoPlugin.generateRandomData(callerIdent, csprngEngineName, numberBytes, customParameters, randomData);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::generateInitializationVector(
        Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        int keySize,
        const QVariantMap &customParameters,
        QByteArray *generatedIV)
{
    return m_opensslCryptoPlugin.generateInitializationVector(algorithm, blockMode, keySize, customParameters, generatedIV);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::generateKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *key)
{
    return m_opensslCryptoPlugin.generateKey(keyTemplate, kpgParams, skdfParams, customParameters, key);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::importKey(
        const Sailfish::Crypto::Key &key,
        const QByteArray &passphrase,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *importedKey)
{
    return m_opensslCryptoPlugin.importKey(key, passphrase, customParameters, importedKey);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::calculateDigest(
        const QByteArray &data,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        QByteArray *digest)
{
    return m_opensslCryptoPlugin.calculateDigest(data, padding, digestFunction, customParameters, digest);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::sign(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        QByteArray *signature)
{
    Sailfish::Crypto::Key fullKey;
    Sailfish::Crypto::Result keyResult = getFullKey(key, &fullKey);
    if (keyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        return keyResult;
    }

    return m_opensslCryptoPlugin.sign(data, fullKey, padding, digestFunction, customParameters, signature);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::verify(
        const QByteArray &signature,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        bool *verified)
{
    Sailfish::Crypto::Key fullKey;
    Sailfish::Crypto::Result keyResult = getFullKey(key, &fullKey);
    if (keyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        return keyResult;
    }

    return m_opensslCryptoPlugin.verify(signature, data, fullKey, padding, digestFunction, customParameters, verified);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
        QByteArray *encrypted,
        QByteArray *authenticationTag)
{
    Sailfish::Crypto::Key fullKey;
    Sailfish::Crypto::Result keyResult = getFullKey(key, &fullKey);
    if (keyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        return keyResult;
    }

    return m_opensslCryptoPlugin.encrypt(data, iv, fullKey, blockMode, padding, authenticationData, customParameters, encrypted, authenticationTag);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::decrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QByteArray &authenticationTag,
        const QVariantMap &customParameters,
        QByteArray *decrypted,
        bool *verified)
{
    Sailfish::Crypto::Key fullKey;
    Sailfish::Crypto::Result keyResult = getFullKey(key, &fullKey);
    if (keyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        return keyResult;
    }

    return m_opensslCryptoPlugin.decrypt(data, iv, fullKey, blockMode, padding, authenticationData, authenticationTag, customParameters, decrypted, verified);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::initializeCipherSession(
        quint64 clientId,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        Sailfish::Crypto::CryptoManager::Operation operation,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
        Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        quint32 *cipherSessionToken)
{
    Sailfish::Crypto::Key fullKey;
    Sailfish::Crypto::Result keyResult = getFullKey(key, &fullKey);
    if (keyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        return keyResult;
    }

    return m_opensslCryptoPlugin.initializeCipherSession(clientId,
                                                         iv,
                                                         fullKey,
                                                         operation,
                                                         blockMode,
                                                         encryptionPadding,
                                                         signaturePadding,
                                                         digestFunction,
                                                         customParameters,
                                                         cipherSessionToken);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::updateCipherSessionAuthentication(
        quint64 clientId,
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken)
{
    return m_opensslCryptoPlugin.updateCipherSessionAuthentication(clientId,
                                                                   authenticationData,
                                                                   customParameters,
                                                                   cipherSessionToken);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::updateCipherSession(
        quint64 clientId,
        const QByteArray &data,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken,
        QByteArray *generatedData)
{
    return m_opensslCryptoPlugin.updateCipherSession(clientId,
                                                     data,
                                                     customParameters,
                                                     cipherSessionToken,
                                                     generatedData);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::finaliseCipherSession(
        quint64 clientId,
        const QByteArray &data,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken,
        QByteArray *generatedData,
        bool *verified)
{
    return m_opensslCryptoPlugin.finaliseCipherSession(clientId,
                                                       data,
                                                       customParameters,
                                                       cipherSessionToken,
                                                       generatedData,
                                                       verified);
}
