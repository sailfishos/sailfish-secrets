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
#include "Crypto/certificate.h"
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

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::seedRandomDataGenerator(
        quint64 callerIdent,
        const QString &csprngEngineName,
        const QByteArray &seedData,
        double entropyEstimate)
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
    Sailfish::Crypto::Result retn = generateKey(keyTemplate, kpgParams, skdfParams, &fullKey);
    if (retn.code() == Sailfish::Crypto::Result::Failed) {
        return retn;
    }

    // store the key as a secret.
    const QString hashedSecretName = Sailfish::Secrets::Daemon::Util::generateHashedSecretName(fullKey.identifier().collectionName(), fullKey.identifier().name());
    const QMap<QString, QString> filterData(fullKey.filterData());
    Sailfish::Secrets::Result storeResult = setSecret(
                fullKey.identifier().collectionName(),
                hashedSecretName,
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
    Sailfish::Crypto::Result retn = importKey(key, passphrase, &importedKey);
    if (retn.code() == Sailfish::Crypto::Result::Failed) {
        return retn;
    }

    // store the key as a secret.
    const QString hashedSecretName = Sailfish::Secrets::Daemon::Util::generateHashedSecretName(importedKey.identifier().collectionName(), importedKey.identifier().name());
    const QMap<QString, QString> filterData(importedKey.filterData());
    Sailfish::Secrets::Result storeResult = setSecret(
                importedKey.identifier().collectionName(),
                hashedSecretName,
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

    QString secretName;
    QByteArray secret;
    Sailfish::Secrets::Secret::FilterData sfd;

    const QString hashedSecretName = Sailfish::Secrets::Daemon::Util::generateHashedSecretName(identifier.collectionName(), identifier.name());
    Sailfish::Secrets::Result storageResult = getSecret(
                identifier.collectionName(),
                hashedSecretName,
                &secretName,
                &secret,
                &sfd);
    if (storageResult.code() == Sailfish::Secrets::Result::Failed) {
        Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(storageResult.errorCode());
        retn.setErrorMessage(storageResult.errorMessage());
        return retn;
    }

    QMap<QString, QString> filterData = sfd;

    bool ok = true;
    Sailfish::Crypto::Key fullKey = Sailfish::Crypto::Key::deserialise(secret, &ok);
    if (!ok) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::SerialisationError,
                                        QLatin1String("Unable to deserialise key from secret blob"));
    }

    fullKey.setIdentifier(Sailfish::Crypto::Key::Identifier(identifier.name(), identifier.collectionName()));
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
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
{
    Q_UNUSED(identifiers);
    // We could only return those identifiers from unlocked collections,
    // and in any case the main keyentries bookkeeping table will have this information.
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("This operation is deliberately not supported"));
}


Sailfish::Crypto::Key
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::getFullKey(
        const Sailfish::Crypto::Key &key)
{
    Sailfish::Crypto::Key fullKey;
    if (storedKey_internal(key.identifier(), &fullKey).code() == Sailfish::Crypto::Result::Succeeded) {
        return fullKey;
    }
    return key;
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::generateRandomData(
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes,
        QByteArray *randomData)
{
    return m_opensslCryptoPlugin.generateRandomData(callerIdent, csprngEngineName, numberBytes, randomData);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::generateInitializationVector(
        Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        int keySize,
        QByteArray *generatedIV)
{
    return m_opensslCryptoPlugin.generateInitializationVector(algorithm, blockMode, keySize, generatedIV);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::validateCertificateChain(
        const QVector<Sailfish::Crypto::Certificate> &chain,
        bool *validated)
{
    return m_opensslCryptoPlugin.validateCertificateChain(chain, validated);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::generateKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        Sailfish::Crypto::Key *key)
{
    return m_opensslCryptoPlugin.generateKey(keyTemplate, kpgParams, skdfParams, key);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::importKey(
        const Sailfish::Crypto::Key &key,
        const QByteArray &passphrase,
        Sailfish::Crypto::Key *importedKey)
{
    return m_opensslCryptoPlugin.importKey(key, passphrase, importedKey);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::calculateDigest(
        const QByteArray &data,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        QByteArray *digest)
{
    return m_opensslCryptoPlugin.calculateDigest(data, padding, digestFunction, digest);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::sign(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        QByteArray *signature)
{
    return m_opensslCryptoPlugin.sign(data, key, padding, digestFunction, signature);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::verify(
        const QByteArray &signature,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        bool *verified)
{
    return m_opensslCryptoPlugin.verify(signature, data, key, padding, digestFunction, verified);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        QByteArray *encrypted,
        QByteArray *authenticationTag)
{
    return m_opensslCryptoPlugin.encrypt(data, iv, key, blockMode, padding, authenticationData, encrypted, authenticationTag);
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
        QByteArray *decrypted,
        bool *verified)
{
    return m_opensslCryptoPlugin.decrypt(data, iv, key, blockMode, padding, authenticationData, authenticationTag, decrypted, verified);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::initialiseCipherSession(quint64 clientId,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        Sailfish::Crypto::CryptoManager::Operation operation,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
        Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        quint32 *cipherSessionToken)
{
    return m_opensslCryptoPlugin.initialiseCipherSession(clientId,
                                                         iv,
                                                         key,
                                                         operation,
                                                         blockMode,
                                                         encryptionPadding,
                                                         signaturePadding,
                                                         digestFunction,
                                                         cipherSessionToken);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::updateCipherSessionAuthentication(
        quint64 clientId,
        const QByteArray &authenticationData,
        quint32 cipherSessionToken)
{
    return m_opensslCryptoPlugin.updateCipherSessionAuthentication(clientId,
                                                                   authenticationData,
                                                                   cipherSessionToken);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::updateCipherSession(
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken,
        QByteArray *generatedData)
{
    return m_opensslCryptoPlugin.updateCipherSession(clientId,
                                                     data,
                                                     cipherSessionToken,
                                                     generatedData);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::finaliseCipherSession(
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken,
        QByteArray *generatedData,
        bool *verified)
{
    return m_opensslCryptoPlugin.finaliseCipherSession(clientId,
                                                       data,
                                                       cipherSessionToken,
                                                       generatedData,
                                                       verified);
}
