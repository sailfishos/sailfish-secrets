/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "cryptopluginwrapper_p.h"
#include "logging_p.h"
#include "util_p.h"

using namespace Sailfish::Crypto;
using namespace Sailfish::Crypto::Daemon::ApiImpl;
using namespace Sailfish::Secrets::Daemon::Util;

CryptoStoragePluginWrapper::CryptoStoragePluginWrapper(
        Sailfish::Crypto::CryptoPlugin *cryptoPlugin,
        Sailfish::Secrets::EncryptedStoragePlugin *plugin,
        bool autotestMode)
    : Sailfish::Secrets::Daemon::ApiImpl::EncryptedStoragePluginWrapper(plugin, autotestMode)
    , m_cryptoPlugin(cryptoPlugin)
{
}

CryptoStoragePluginWrapper::~CryptoStoragePluginWrapper()
{
}

Sailfish::Secrets::Result
CryptoStoragePluginWrapper::keyNames(
        const QString &collectionName,
        QStringList *keyNames)
{
    QStringList knownKeys;
    Sailfish::Secrets::Result sresult = m_metadataDb.keyNames(collectionName, &knownKeys);
    if (sresult.code() != Sailfish::Secrets::Result::Succeeded) {
        return sresult;
    }

    QVector<Key::Identifier> identifiers;
    if (m_cryptoPlugin->canStoreKeys()) {
        Result result = m_cryptoPlugin->storedKeyIdentifiers(collectionName, &identifiers);
        if (result != Result::Succeeded) {
            if (result.storageErrorCode() != 0) {
                return Sailfish::Secrets::Result(static_cast<Sailfish::Secrets::Result::ErrorCode>(result.storageErrorCode()),
                                                 result.errorMessage());
            } else {
                return Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                 result.errorMessage());
            }
        }

        for (const Key::Identifier &ident : identifiers) {
            if (ident.collectionName() == collectionName
                    && !knownKeys.contains(ident.name())) {
                knownKeys.append(ident.name());
            }
        }
    }

    *keyNames = knownKeys;
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Crypto::Result
CryptoStoragePluginWrapper::storedKeyIdentifiers(
        const QString &collectionName,
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
{
    return m_cryptoPlugin->storedKeyIdentifiers(collectionName, identifiers);
}

Result
CryptoStoragePluginWrapper::prepareToStoreKey(
        const Sailfish::Secrets::Daemon::ApiImpl::SecretMetadata &metadata,
        const QByteArray &collectionUnlockKey,
        bool *wasLocked)
{
    if (m_encryptedStoragePlugin->isLocked()) {
        return Result(Result::CryptoPluginIsLockedError,
                      QStringLiteral("Plugin %1 is locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    if (isMasterLocked()) {
        return Result(Result::CryptoPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    if (!m_cryptoPlugin->canStoreKeys()) {
        return Result(Result::OperationNotSupportedError,
                      QStringLiteral("Plugin %1 cannot store keys")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    bool locked = false;
    Sailfish::Secrets::Result sresult = m_encryptedStoragePlugin->isCollectionLocked(metadata.collectionName, &locked);
    if (sresult.code() != Sailfish::Secrets::Result::Succeeded) {
        return transformSecretsResult(sresult);
    }

    *wasLocked = locked;
    if (locked) {
        sresult = m_encryptedStoragePlugin->setEncryptionKey(metadata.collectionName, collectionUnlockKey);
        if (sresult.code() != Sailfish::Secrets::Result::Succeeded) {
            return transformSecretsResult(sresult);
        }
        locked = false;
        sresult = m_encryptedStoragePlugin->isCollectionLocked(metadata.collectionName, &locked);
        if (locked) {
            sresult.setCode(Sailfish::Secrets::Result::Failed);
            sresult.setErrorCode(Sailfish::Secrets::Result::CollectionIsLockedError);
            sresult.setErrorMessage(QStringLiteral("Collection %1 from plugin %2 is locked")
                                    .arg(metadata.collectionName, m_encryptedStoragePlugin->name()));
            return transformSecretsResult(sresult);
        }
    }

    bool exists = false;
    Sailfish::Secrets::Daemon::ApiImpl::SecretMetadata currentMetadata;
    sresult = m_metadataDb.secretMetadata(
                metadata.collectionName,
                metadata.secretName,
                &currentMetadata,
                &exists);
    if (sresult.code() != Sailfish::Secrets::Result::Succeeded) {
        return transformSecretsResult(sresult);
    }

    if (exists) {
        return Result(Result::DuplicateKeyIdentifier,
                      QStringLiteral("A secret with that name already exists in the collection"));
    }

    if (!m_metadataDb.beginTransaction()) {
        sresult.setCode(Sailfish::Secrets::Result::Failed);
        sresult.setErrorCode(Sailfish::Secrets::Result::DatabaseTransactionError);
        sresult.setErrorMessage(QStringLiteral("Unable to start metadata db transaction for generateAndStoreKey"));
        return transformSecretsResult(sresult);
    }

    sresult = m_metadataDb.insertSecretMetadata(metadata);
    if (sresult.code() != Sailfish::Secrets::Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return transformSecretsResult(sresult);
    }

    return Result(Result::Succeeded);
}

Result
CryptoStoragePluginWrapper::generateAndStoreKey(
        const Sailfish::Secrets::Daemon::ApiImpl::SecretMetadata &metadata,
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
        const QByteArray &collectionUnlockKey,
        Sailfish::Crypto::Key *keyReference)
{
    bool wasLocked = false;
    Result result = prepareToStoreKey(metadata, collectionUnlockKey, &wasLocked);
    if (result.code() == Result::Succeeded) {
        result = m_cryptoPlugin->generateAndStoreKey(
                    keyTemplate,
                    kpgParams,
                    skdfParams,
                    customParameters,
                    keyReference);
        if (result.code() != Result::Succeeded) {
            m_metadataDb.rollbackTransaction();
        } else {
            m_metadataDb.commitTransaction();
        }
    }

    if (wasLocked) {
        Sailfish::Secrets::Result relockResult = m_encryptedStoragePlugin->setEncryptionKey(
                    metadata.collectionName, QByteArray());
        if (relockResult.code() != Sailfish::Secrets::Result::Succeeded) {
            qCWarning(lcSailfishSecretsDaemon) << "Error relocking collection:" << metadata.collectionName
                                               << relockResult.errorMessage();
        }
    }

    return result;
}

Result
CryptoStoragePluginWrapper::importAndStoreKey(
        const Sailfish::Secrets::Daemon::ApiImpl::SecretMetadata &metadata,
        const QByteArray &data,
        const Key &keyTemplate,
        const QByteArray &importPassphrase,
        const QVariantMap &customParameters,
        const QByteArray &collectionUnlockKey,
        Key *keyReference)
{
    bool wasLocked = false;
    Result result = prepareToStoreKey(metadata, collectionUnlockKey, &wasLocked);
    if (result.code() == Result::Succeeded) {
        result = m_cryptoPlugin->importAndStoreKey(
                    data,
                    keyTemplate,
                    importPassphrase,
                    customParameters,
                    keyReference);
        if (result.code() != Result::Succeeded) {
            m_metadataDb.rollbackTransaction();
        } else {
            m_metadataDb.commitTransaction();
        }
    }

    if (wasLocked) {
        Sailfish::Secrets::Result relockResult = m_encryptedStoragePlugin->setEncryptionKey(
                    metadata.collectionName, QByteArray());
        if (relockResult.code() != Sailfish::Secrets::Result::Succeeded) {
            qCWarning(lcSailfishSecretsDaemon) << "Error relocking collection:" << metadata.collectionName
                                               << relockResult.errorMessage();
        }
    }

    return result;
}
