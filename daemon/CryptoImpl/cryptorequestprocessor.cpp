/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "CryptoImpl/cryptorequestprocessor_p.h"

#include "SecretsImpl/secrets_p.h"
#include "Secrets/result.h"

#include "util_p.h"
#include "logging_p.h"

#include <QtCore/QDir>
#include <QtCore/QPluginLoader>
#include <QtCore/QObject>

namespace {
    Sailfish::Crypto::Result transformSecretsResult(const Sailfish::Secrets::Result &result) {
        Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Succeeded);
        if (result.code() == Sailfish::Secrets::Result::Failed) {
            retn.setCode(Sailfish::Crypto::Result::Failed);
            retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
            retn.setStorageErrorCode(static_cast<int>(result.errorCode()));
            retn.setErrorMessage(result.errorMessage());
        } else if (result.code() == Sailfish::Secrets::Result::Pending) {
            retn.setCode(Sailfish::Crypto::Result::Pending);
        }
        return retn;
    }

    void nullifyKeyFields(Sailfish::Crypto::Key *key, Sailfish::Crypto::StoredKeyRequest::KeyComponents keep) {
        // This method is called for keys stored in generic secrets storage plugins.
        // Null-out fields if the client hasn't specified that they be kept.
        // Note that by default we treat CustomParameters as PublicKeyData.
        if (!(keep & Sailfish::Crypto::StoredKeyRequest::MetaData)) {
            key->setIdentifier(Sailfish::Crypto::Key::Identifier());
            key->setOrigin(Sailfish::Crypto::Key::OriginUnknown);
            key->setAlgorithm(Sailfish::Crypto::Key::AlgorithmUnknown);
            key->setBlockModes(Sailfish::Crypto::Key::BlockModeUnknown);
            key->setEncryptionPaddings(Sailfish::Crypto::Key::EncryptionPaddingUnknown);
            key->setSignaturePaddings(Sailfish::Crypto::Key::SignaturePaddingUnknown);
            key->setDigests(Sailfish::Crypto::Key::DigestUnknown);
            key->setOperations(Sailfish::Crypto::Key::OperationUnknown);
            key->setFilterData(Sailfish::Crypto::Key::FilterData());
        }

        if (!(keep & Sailfish::Crypto::StoredKeyRequest::PublicKeyData)) {
            key->setCustomParameters(QVector<QByteArray>());
            key->setPublicKey(QByteArray());
        }

        if (!(keep & Sailfish::Crypto::StoredKeyRequest::SecretKeyData)) {
            key->setPrivateKey(QByteArray());
            key->setSecretKey(QByteArray());
        }
    }
}

using namespace Sailfish::Crypto;

Daemon::ApiImpl::RequestProcessor::RequestProcessor(
        Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *secrets,
        bool autotestMode,
        Daemon::ApiImpl::CryptoRequestQueue *parent)
    : QObject(parent), m_requestQueue(parent), m_secrets(secrets), m_autotestMode(autotestMode)
{
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storedKeyCompleted,
            this, &Daemon::ApiImpl::RequestProcessor::secretsStoredKeyCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storeKeyCompleted,
            this, &Daemon::ApiImpl::RequestProcessor::secretsStoreKeyCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storeKeyMetadataCompleted,
            this, &Daemon::ApiImpl::RequestProcessor::secretsStoreKeyMetadataCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::deleteStoredKeyCompleted,
            this, &Daemon::ApiImpl::RequestProcessor::secretsDeleteStoredKeyCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::deleteStoredKeyMetadataCompleted,
            this, &Daemon::ApiImpl::RequestProcessor::secretsDeleteStoredKeyMetadataCompleted);
}

bool
Daemon::ApiImpl::RequestProcessor::loadPlugins(const QString &pluginDir)
{
    // First, see if any of the EncryptedStorage plugins from Secrets are also
    // Crypto plugins (providing generateAndStoreKey() functionality internally).
    qCDebug(lcSailfishCryptoDaemon) << "Loading crypto storage plugins";
    QMap<QString, QObject*> potentialCryptoPlugins = m_secrets->potentialCryptoStoragePlugins();
    for (QMap<QString, QObject*>::const_iterator it = potentialCryptoPlugins.constBegin(); it != potentialCryptoPlugins.constEnd(); it++) {
        CryptoPlugin *cryptoPlugin = qobject_cast<CryptoPlugin*>(it.value());
        if (cryptoPlugin) {
            if (cryptoPlugin->name().isEmpty() || m_cryptoPlugins.contains(cryptoPlugin->name())) {
                qCDebug(lcSailfishCryptoDaemon) << "ignoring crypto storage plugin:" << it.key() << "with duplicate name:" << cryptoPlugin->name();
            } else if (cryptoPlugin->name().endsWith(QStringLiteral(".test"), Qt::CaseInsensitive) != m_autotestMode) {
                qCDebug(lcSailfishCryptoDaemon) << "ignoring crypto storage plugin:" << it.key() << "due to mode";
            } else {
                qCDebug(lcSailfishCryptoDaemon) << "loading crypto storage plugin:" << it.key();
                m_cryptoPlugins.insert(it.key(), cryptoPlugin);
            }
        }
    }

    qCDebug(lcSailfishCryptoDaemon) << "Loading crypto plugins from directory:" << pluginDir;
    QDir dir(pluginDir);
    Q_FOREACH (const QString &pluginFile, dir.entryList(QDir::Files | QDir::NoDot | QDir::NoDotDot, QDir::Name)) {
        // load the plugin and query it for its data.
        QPluginLoader loader(pluginFile);
        QObject *plugin = loader.instance();
        CryptoPlugin *cryptoPlugin = qobject_cast<CryptoPlugin*>(plugin);
        if (cryptoPlugin) {
            if (cryptoPlugin->name().isEmpty() || m_cryptoPlugins.contains(cryptoPlugin->name())) {
                qCDebug(lcSailfishCryptoDaemon) << "ignoring crypto plugin:" << pluginFile << "with duplicate name:" << cryptoPlugin->name();
                loader.unload();
                continue;
            } else if (cryptoPlugin->name().endsWith(QStringLiteral(".test"), Qt::CaseInsensitive) != m_autotestMode) {
                qCDebug(lcSailfishCryptoDaemon) << "ignoring crypto plugin:" << pluginFile << "due to mode";
                loader.unload();
                continue;
            } else {
                qCDebug(lcSailfishCryptoDaemon) << "loading crypto plugin:" << pluginFile << "with name:" << cryptoPlugin->name();
                m_cryptoPlugins.insert(cryptoPlugin->name(), cryptoPlugin);
            }
        } else {
            qCWarning(lcSailfishCryptoDaemon) << "ignoring plugin:" << pluginFile << "- not a crypto plugin or Qt version mismatch";
            loader.unload();
            continue;
        }
    }

    return true;
}

Result
Daemon::ApiImpl::RequestProcessor::getPluginInfo(
        pid_t callerPid,
        quint64 requestId,
        QVector<CryptoPluginInfo> *cryptoPlugins,
        QStringList *storagePlugins)
{
    Result retn(transformSecretsResult(m_secrets->storagePluginNames(callerPid, requestId, storagePlugins)));
    if (retn.code() == Result::Failed) {
        return retn;
    }

    QMap<QString, CryptoPlugin*>::const_iterator it = m_cryptoPlugins.constBegin();
    for (; it != m_cryptoPlugins.constEnd(); it++) {
        cryptoPlugins->append(CryptoPluginInfo(it.value()));
    }

    return retn;
}

Result
Daemon::ApiImpl::RequestProcessor::generateRandomData(
        pid_t callerPid,
        quint64 requestId,
        quint64 numberBytes,
        const QString &csprngEngineName,
        const QString &cryptosystemProviderName,
        QByteArray *randomData)
{
    // TODO: access control!
    Q_UNUSED(requestId);

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    return m_cryptoPlugins[cryptosystemProviderName]->generateRandomData(
                static_cast<quint64>(callerPid), csprngEngineName, numberBytes, randomData);
}

Result
Daemon::ApiImpl::RequestProcessor::seedRandomDataGenerator(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &seedData,
        double entropyEstimate,
        const QString &csprngEngineName,
        const QString &cryptosystemProviderName)
{
    // TODO: access control!
    Q_UNUSED(requestId);

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    return m_cryptoPlugins[cryptosystemProviderName]->seedRandomDataGenerator(
                static_cast<quint64>(callerPid), csprngEngineName, seedData, entropyEstimate);
}

Result
Daemon::ApiImpl::RequestProcessor::validateCertificateChain(
        pid_t callerPid,
        quint64 requestId,
        const QVector<Certificate> &chain,
        const QString &cryptosystemProviderName,
        bool *valid)
{
    // TODO: access control!
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    return m_cryptoPlugins[cryptosystemProviderName]->validateCertificateChain(chain, valid);
}

Result
Daemon::ApiImpl::RequestProcessor::generateKey(
        pid_t callerPid,
        quint64 requestId,
        const Key &keyTemplate,
        const QString &cryptosystemProviderName,
        Key *key)
{
    // TODO: access control!
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    return m_cryptoPlugins[cryptosystemProviderName]->generateKey(keyTemplate, key);
}

Result
Daemon::ApiImpl::RequestProcessor::generateStoredKey(
        pid_t callerPid,
        quint64 requestId,
        const Key &keyTemplate,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName,
        Key *key)
{
    Q_UNUSED(key) // asynchronous outparam, returned in generateStoredKey_inStoragePlugin/_inCryptoPlugin

    Result retn(Result::Succeeded);
    if (keyTemplate.identifier().name().isEmpty()) {
        return Result(Result::InvalidKeyIdentifier,
                      QLatin1String("Template key identifier has empty name"));
    } else {
        QVector<Key::Identifier> identifiers;
        retn = transformSecretsResult(m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers));
        if (retn.code() == Result::Failed) {
            return retn;
        }
        if (identifiers.contains(keyTemplate.identifier())) {
            return Result(Result::DuplicateKeyIdentifier,
                          QLatin1String("Template key identifier duplicates existing key"));
        }
    }

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (storageProviderName == cryptosystemProviderName) {
        if (!m_cryptoPlugins[cryptosystemProviderName]->canStoreKeys()) {
            return Result(Result::StorageError,
                          QLatin1String("The specified cryptographic service provider cannot store keys"));
        }

        retn = transformSecretsResult(m_secrets->storeKeyMetadata(callerPid, requestId, keyTemplate.identifier(), storageProviderName));
        if (retn.code() == Result::Failed) {
            return retn;
        }

        // wait for the asynchronous operation to complete.
        // when complete it will invoke generateStoredKey_inCryptoPlugin().
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::GenerateStoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<Key>(keyTemplate)
                                                    << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                    << QVariant::fromValue<QString>(storageProviderName)));
        return Result(Result::Pending);
    } else {
        // generate the key
        Key fullKey(keyTemplate);
        Result keyResult = m_cryptoPlugins[cryptosystemProviderName]->generateKey(keyTemplate, &fullKey);
        if (keyResult.code() == Result::Failed) {
            return keyResult;
        }

        retn = transformSecretsResult(m_secrets->storeKey(
                                            callerPid,
                                            requestId,
                                            fullKey.identifier(),
                                            Key::serialise(fullKey, Key::LossySerialisationMode),
                                            fullKey.filterData(),
                                            storageProviderName));
        if (retn.code() == Result::Failed) {
            return retn;
        }

        // asynchronous operation, will call back to generateStoredKey_inStoragePlugin().
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::GenerateStoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<Key>(fullKey)
                                                    << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                    << QVariant::fromValue<QString>(storageProviderName)));
        return Result(Result::Pending);
    }
}

void
Daemon::ApiImpl::RequestProcessor::generateStoredKey_inStoragePlugin(
        pid_t callerPid,
        quint64 requestId,
        const Result &result,
        const Key &fullKey,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName)
{
    // This method is invoked in the "generate from crypto plugin, store in secrets storage plugin" codepath.
    // if it was successfully stored into secrets, then add the key entry.
    Result retn(result);
    if (result.code() == Result::Succeeded) {
        retn = transformSecretsResult(m_secrets->addKeyEntry(callerPid, requestId, fullKey.identifier(), cryptosystemProviderName, storageProviderName));
        if (retn.code() == Result::Failed) {
            // Attempt to remove the key from secrets storage, to cleanup.
            // TODO: in the future we should refactor so that this can be done via a transaction rollback!
            Result cleanupResult = transformSecretsResult(m_secrets->deleteStoredKey(callerPid, requestId, fullKey.identifier()));
            if (cleanupResult.code() != Result::Failed) {
                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::GenerateStoredKeyRequest,
                                             QVariantList() << QVariant::fromValue<Key>(fullKey)
                                                            << QVariant::fromValue<Result>(retn)));
                return;
            }
            // TODO: we now have stale data in the secrets main table.
            //       Add a dirty flag for this datum, and attempt to cleanup later.
            qCWarning(lcSailfishCryptoDaemon) << "Failed to clean up stored key after failed generateStoredKey request:"
                                              << cleanupResult.storageErrorCode() << cleanupResult.errorMessage();
        }
    }

    // finish the asynchronous request.
    Key partialKey(fullKey);
    partialKey.setPrivateKey(QByteArray());
    partialKey.setSecretKey(QByteArray());
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Result>(retn);
    outParams << QVariant::fromValue<Key>(partialKey);
    m_requestQueue->requestFinished(requestId, outParams);
}

void
Daemon::ApiImpl::RequestProcessor::generateStoredKey_inCryptoPlugin(
        pid_t callerPid,
        quint64 requestId,
        const Result &result,
        const Key &keyTemplate,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName)
{
    // This method is invoked in the "generate and store into crypto plugin" codepath.
    if (result.code() != Result::Succeeded) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(result);
        outParams << QVariant::fromValue<Key>(keyTemplate);
        m_requestQueue->requestFinished(requestId, outParams);
        return;
    }

    // if the metadata was successfully stored into secrets, then generate the full key
    // and store it in the crypto plugin, and if that succeeds, add the key entry.
    Key fullKey(keyTemplate);
    Result retn(transformSecretsResult(m_secrets->addKeyEntry(
                                          callerPid,
                                          requestId,
                                          keyTemplate.identifier(),
                                          cryptosystemProviderName,
                                          storageProviderName)));
    if (retn.code() == Result::Failed) {
        // Attempt to remove the key metadata from secrets storage, to cleanup.
        // In this case, the key has not yet been stored in the (crypto) plugin, so it is enough
        // to merely delete the metadata.  We need a specific deleteStoredKeyMetadata(),
        // as any attempt to delete the actual secret from the plugin will fail (it doesn't exist).
        Result cleanupResult = transformSecretsResult(m_secrets->deleteStoredKeyMetadata(callerPid, requestId, keyTemplate.identifier()));
        if (cleanupResult.code() != Result::Failed) {
            m_pendingRequests.insert(requestId,
                                     Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Daemon::ApiImpl::GenerateStoredKeyRequest,
                                         QVariantList() << QVariant::fromValue<Key>(keyTemplate)
                                                        << QVariant::fromValue<Result>(retn)));
            return;
        }
        // TODO: we now have stale data in the secrets main table.
        //       Add a dirty flag for this datum, and attempt to cleanup later.
        // Also clean up the key entry as it doesn't actually exist.
        qCWarning(lcSailfishCryptoDaemon) << "Failed to clean up stored key metadata after failed generateStoredKey request:"
                                          << cleanupResult.storageErrorCode() << cleanupResult.errorMessage();
        m_secrets->removeKeyEntry(callerPid, requestId, keyTemplate.identifier());
    } else {
        retn = m_cryptoPlugins[cryptosystemProviderName]->generateAndStoreKey(keyTemplate, &fullKey);
        if (retn.code() == Result::Failed) {
            // Attempt to remove the key metadata from secrets storage, to cleanup.
            // Note: the keyEntry should be cascade deleted automatically.
            Result cleanupResult = transformSecretsResult(m_secrets->deleteStoredKeyMetadata(callerPid, requestId, keyTemplate.identifier()));
            if (cleanupResult.code() != Result::Failed) {
                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::GenerateStoredKeyRequest,
                                             QVariantList() << QVariant::fromValue<Key>(keyTemplate)
                                                            << QVariant::fromValue<Result>(retn)));
                return;
            }
            // TODO: we now have stale data in the secrets main table.
            //       Add a dirty flag for this datum, and attempt to cleanup later.
            // Also clean up the key entry as it doesn't actually exist.
            qCWarning(lcSailfishCryptoDaemon) << "Failed to clean up stored key metadata after failed generateStoredKey request:"
                                              << cleanupResult.storageErrorCode() << cleanupResult.errorMessage();
            m_secrets->removeKeyEntry(callerPid, requestId, keyTemplate.identifier());
        }
    }

    // finish the asynchronous request.
    Key partialKey(fullKey);
    partialKey.setPrivateKey(QByteArray());
    partialKey.setSecretKey(QByteArray());
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Result>(retn);
    outParams << QVariant::fromValue<Key>(partialKey);
    m_requestQueue->requestFinished(requestId, outParams);
}

void
Daemon::ApiImpl::RequestProcessor::generateStoredKey_failedCleanup(
        pid_t callerPid,
        quint64 requestId,
        const Key &keyTemplate,
        const Result &initialResult,
        const Result &result)
{
    Q_UNUSED(callerPid)

    // This method will be invoked if the generateStoredKey() failed
    // and we had to cleanup the stored key data or metadata from secrets.
    // check to see if the result of the deleteStoredKey/deleteStoredKeyMetadata failed
    if (result.code() == Result::Failed) {
        // TODO: we now have stale data in the secrets main table.
        //       Add a dirty flag for this datum, and attempt to cleanup later.
        // Also clean up the key entry as it doesn't actually exist.
        qCWarning(lcSailfishCryptoDaemon) << "Failed to clean up stored key or metadata after failed generateStoredKey request:"
                                          << result.storageErrorCode() << result.errorMessage();
        m_secrets->removeKeyEntry(callerPid, requestId, keyTemplate.identifier()); // expected fail/no-op in the inStoragePlugin case.
    }

    // Finish the asynchronous request.
    Key partialKey(keyTemplate);
    partialKey.setPrivateKey(QByteArray());
    partialKey.setSecretKey(QByteArray());
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Result>(initialResult);
    outParams << QVariant::fromValue<Key>(partialKey);
    m_requestQueue->requestFinished(requestId, outParams);
}

Result
Daemon::ApiImpl::RequestProcessor::storedKey(
        pid_t callerPid,
        quint64 requestId,
        const Key::Identifier &identifier,
        StoredKeyRequest::KeyComponents keyComponents,
        Key *key)
{
    // TODO: access control
    QVector<Key::Identifier> identifiers;
    Result retn(transformSecretsResult(m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers)));
    if (retn.code() == Result::Failed) {
        return retn;
    }

    if (!identifiers.contains(identifier)) {
        return Result(Result::InvalidKeyIdentifier,
                      QLatin1String("No such key exists in storage"));
    }

    QString cryptoPluginName, storagePluginName;
    retn = transformSecretsResult(m_secrets->keyEntry(callerPid, requestId, identifier, &cryptoPluginName, &storagePluginName));
    if (retn.code() == Result::Failed) {
        return retn;
    } else if (storagePluginName.isEmpty()) {
        return Result(Result::InvalidStorageProvider,
                      QLatin1String("Internal error: storage plugin associated with that key is empty"));
    }

    if (m_cryptoPlugins.contains(storagePluginName)) {
        return m_cryptoPlugins[storagePluginName]->storedKey(identifier, keyComponents, key);
    }

    QByteArray serialisedKey;
    QMap<QString, QString> filterData;
    retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, identifier, &serialisedKey, &filterData));
    if (retn.code() == Result::Failed) {
        return retn;
    } else if (retn.code() == Result::Pending) {
        // asynchronous flow required, will eventually call back to storedKey2().
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::StoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<Key::Identifier>(identifier)
                                                    << QVariant::fromValue<StoredKeyRequest::KeyComponents>(keyComponents)));
        return retn;
    }

    *key = Key::deserialise(serialisedKey);
    key->setFilterData(filterData);
    nullifyKeyFields(key, keyComponents);
    return retn;
}

void
Daemon::ApiImpl::RequestProcessor::storedKey2(
        quint64 requestId,
        StoredKeyRequest::KeyComponents keyComponents,
        const Result &result,
        const QByteArray &serialisedKey,
        const QMap<QString, QString> &filterData)
{
    Key retn(Key::deserialise(serialisedKey));
    retn.setFilterData(filterData);
    nullifyKeyFields(&retn, keyComponents);

    // finish the request.
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Result>(result);
    outParams << QVariant::fromValue<Key>(retn);
    m_requestQueue->requestFinished(requestId, outParams);
}

Result
Daemon::ApiImpl::RequestProcessor::deleteStoredKey(
        pid_t callerPid,
        quint64 requestId,
        const Key::Identifier &identifier)
{
    // TODO: access control
    QString cryptoPluginName, storagePluginName;
    Result retn = transformSecretsResult(m_secrets->keyEntry(callerPid, requestId, identifier, &cryptoPluginName, &storagePluginName));
    if (retn.code() == Result::Failed) {
        return retn;
    } else if (storagePluginName.isEmpty()) {
        return Result(Result::InvalidStorageProvider,
                      QLatin1String("Internal error: storage plugin associated with that key is empty"));
    }

    // delete from secrets storage
    retn = transformSecretsResult(m_secrets->deleteStoredKey(callerPid, requestId, identifier));
    if (retn.code() == Result::Succeeded) {
        m_secrets->removeKeyEntry(callerPid, requestId, identifier);
        // TODO: if that fails, re-try later etc.
    } else if (retn.code() == Result::Pending) {
        // asynchronous flow, will call back to deleteStoredKey2().
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::DeleteStoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<Key::Identifier>(identifier)));
    }

    return retn;
}

void Daemon::ApiImpl::RequestProcessor::deleteStoredKey2(
        pid_t callerPid,
        quint64 requestId,
        const Result &result,
        const Key::Identifier &identifier)
{
    // finish the request.
    if (result.code() == Result::Succeeded) {
        m_secrets->removeKeyEntry(callerPid, requestId, identifier);
        // TODO: if that fails, re-try later etc.
    }
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Result>(result);
    m_requestQueue->requestFinished(requestId, outParams);
}


Result
Daemon::ApiImpl::RequestProcessor::storedKeyIdentifiers(
        pid_t callerPid,
        quint64 requestId,
        QVector<Key::Identifier> *identifiers)
{
    return transformSecretsResult(m_secrets->keyEntryIdentifiers(callerPid, requestId, identifiers));
}

Result
Daemon::ApiImpl::RequestProcessor::sign(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const Key &key,
        Key::SignaturePadding padding,
        Key::Digest digest,
        const QString &cryptosystemProviderName,
        QByteArray *signature)
{
    // TODO: Access Control

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & Key::Sign)) {
        return Result(Result::UnsupportedOperation,
                      QLatin1String("The specified cryptographic service provider does not support sign operations"));
    } else if (!(cryptoPlugin->supportedSignaturePaddings().value(key.algorithm()) & padding)) {
        return Result(Result::UnsupportedSignaturePadding,
                      QLatin1String("The specified cryptographic service provider does not support that signature padding"));
    } else if (!(cryptoPlugin->supportedDigests().value(key.algorithm()) & digest)) {
        return Result(Result::UnsupportedDigest,
                      QLatin1String("The specified cryptographic service provider does not support that digest"));
    }

    Key fullKey;
    if (key.privateKey().isEmpty() && key.secretKey().isEmpty()) {
        // the key is a key reference, attempt to read the full key from storage.
        Result retn(Result::Succeeded);
        if (key.identifier().name().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Reference key has empty identifier"));
        } else {
            QVector<Key::Identifier> identifiers;
            retn = transformSecretsResult(m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers));
            if (retn.code() == Result::Failed) {
                return retn;
            }
            if (!identifiers.contains(key.identifier())) {
                return Result(Result::InvalidKeyIdentifier,
                              QLatin1String("Reference key identifier doesn't exist"));
            }
        }

        QByteArray serialisedKey;
        QMap<QString, QString> filterData;
        retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, key.identifier(), &serialisedKey, &filterData));
        if (retn.code() == Result::Failed) {
            return retn;
        } else if (retn.code() == Result::Pending) {
            // asynchronous flow required, will call back to sign2().
            m_pendingRequests.insert(requestId,
                                     Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Daemon::ApiImpl::SignRequest,
                                         QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                        << QVariant::fromValue<Key::SignaturePadding>(padding)
                                                        << QVariant::fromValue<Key::Digest>(digest)
                                                        << QVariant::fromValue<QString>(cryptosystemProviderName)));
            return retn;
        }

        fullKey = Key::deserialise(serialisedKey);
    } else {
        fullKey = key;
    }

    return cryptoPlugin->sign(data, fullKey, padding, digest, signature);
}

void
Daemon::ApiImpl::RequestProcessor::sign2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &data,
        Key::SignaturePadding padding,
        Key::Digest digest,
        const QString &cryptoPluginName)
{
    // finish the request.
    QList<QVariant> outParams;
    QByteArray signature;
    if (result.code() == Result::Succeeded) {
        Key fullKey = Key::deserialise(serialisedKey);
        Result cryptoResult = m_cryptoPlugins[cryptoPluginName]->sign(data, fullKey, padding, digest, &signature);
        outParams << QVariant::fromValue<Result>(cryptoResult);
    } else {
        outParams << QVariant::fromValue<Result>(result);
    }
    outParams << QVariant::fromValue<QByteArray>(signature);
    m_requestQueue->requestFinished(requestId, outParams);
}

Result
Daemon::ApiImpl::RequestProcessor::verify(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const Key &key,
        Key::SignaturePadding padding,
        Key::Digest digest,
        const QString &cryptosystemProviderName,
        bool *verified)
{
    // TODO: Access Control

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & Key::Verify)) {
        return Result(Result::UnsupportedOperation,
                      QLatin1String("The specified cryptographic service provider does not support verify operations"));
    } else if (!(cryptoPlugin->supportedSignaturePaddings().value(key.algorithm()) & padding)) {
        return Result(Result::UnsupportedSignaturePadding,
                      QLatin1String("The specified cryptographic service provider does not support that signature padding"));
    } else if (!(cryptoPlugin->supportedDigests().value(key.algorithm()) & digest)) {
        return Result(Result::UnsupportedDigest,
                      QLatin1String("The specified cryptographic service provider does not support that digest"));
    }

    Key fullKey;
    if (key.publicKey().isEmpty() && key.privateKey().isEmpty() && key.secretKey().isEmpty()) { // can use public key to verify
        // the key is a key reference, attempt to read the full key from storage.
        Result retn(Result::Succeeded);
        if (key.identifier().name().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Reference key has empty identifier"));
        } else {
            QVector<Key::Identifier> identifiers;
            retn = transformSecretsResult(m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers));
            if (retn.code() == Result::Failed) {
                return retn;
            }
            if (!identifiers.contains(key.identifier())) {
                return Result(Result::InvalidKeyIdentifier,
                              QLatin1String("Reference key identifier doesn't exist"));
            }
        }

        QByteArray serialisedKey;
        QMap<QString, QString> filterData;
        retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, key.identifier(), &serialisedKey, &filterData));
        if (retn.code() == Result::Failed) {
            return retn;
        } else if (retn.code() == Result::Pending) {
            // asynchronous flow required, will call back to verify2().
            m_pendingRequests.insert(requestId,
                                     Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Daemon::ApiImpl::VerifyRequest,
                                         QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                        << QVariant::fromValue<Key::SignaturePadding>(padding)
                                                        << QVariant::fromValue<Key::Digest>(digest)
                                                        << QVariant::fromValue<QString>(cryptosystemProviderName)));
            return retn;
        }

        fullKey = Key::deserialise(serialisedKey);
    } else {
        fullKey = key;
    }

    return cryptoPlugin->verify(data, fullKey, padding, digest, verified);
}

void
Daemon::ApiImpl::RequestProcessor::verify2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &data,
        Key::SignaturePadding padding,
        Key::Digest digest,
        const QString &cryptoPluginName)
{
    // finish the request.
    QList<QVariant> outParams;
    bool verified = false;
    if (result.code() == Result::Succeeded) {
        Key fullKey = Key::deserialise(serialisedKey);
        Result cryptoResult = m_cryptoPlugins[cryptoPluginName]->verify(data, fullKey, padding, digest, &verified);
        outParams << QVariant::fromValue<Result>(cryptoResult);
    } else {
        outParams << QVariant::fromValue<Result>(result);
    }
    outParams << QVariant::fromValue<bool>(verified);
    m_requestQueue->requestFinished(requestId, outParams);
}

Result
Daemon::ApiImpl::RequestProcessor::encrypt(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key,
        Key::BlockMode blockMode,
        Key::EncryptionPadding padding,
        const QString &cryptosystemProviderName,
        QByteArray *encrypted)
{
    // TODO: Access Control

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & Key::Encrypt)) {
        return Result(Result::UnsupportedOperation,
                      QLatin1String("The specified cryptographic service provider does not support encrypt operations"));
    } else if (!(cryptoPlugin->supportedBlockModes().value(key.algorithm()) & blockMode)) {
        return Result(Result::UnsupportedBlockMode,
                      QLatin1String("The specified cryptographic service provider does not support that block mode"));
    } else if (!(cryptoPlugin->supportedSignaturePaddings().value(key.algorithm()) & padding)) {
        return Result(Result::UnsupportedEncryptionPadding,
                      QLatin1String("The specified cryptographic service provider does not support that encryption padding"));
    }

    Key fullKey;
    if (key.publicKey().isEmpty() && key.privateKey().isEmpty() && key.secretKey().isEmpty()) { // can use public key to encrypt
        // the key is a key reference, attempt to read the full key from storage.
        Result retn(Result::Succeeded);
        if (key.identifier().name().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Reference key has empty identifier"));
        } else {
            QVector<Key::Identifier> identifiers;
            retn = transformSecretsResult(m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers));
            if (retn.code() == Result::Failed) {
                return retn;
            }
            if (!identifiers.contains(key.identifier())) {
                return Result(Result::InvalidKeyIdentifier,
                              QLatin1String("Reference key identifier doesn't exist"));
            }
        }

        QByteArray serialisedKey;
        QMap<QString, QString> filterData;
        retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, key.identifier(), &serialisedKey, &filterData));
        if (retn.code() == Result::Failed) {
            return retn;
        } else if (retn.code() == Result::Pending) {
            // asynchronous flow required, will call back to encrypt2().
            m_pendingRequests.insert(requestId,
                                     Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Daemon::ApiImpl::EncryptRequest,
                                         QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                        << QVariant::fromValue<QByteArray>(iv)
                                                        << QVariant::fromValue<Key::BlockMode>(blockMode)
                                                        << QVariant::fromValue<Key::EncryptionPadding>(padding)
                                                        << QVariant::fromValue<QString>(cryptosystemProviderName)));
            return retn;
        }

        fullKey = Key::deserialise(serialisedKey);
    } else {
        fullKey = key;
    }

    return cryptoPlugin->encrypt(data, iv, fullKey, blockMode, padding, encrypted);
}

void
Daemon::ApiImpl::RequestProcessor::encrypt2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &data,
        const QByteArray &iv,
        Key::BlockMode blockMode,
        Key::EncryptionPadding padding,
        const QString &cryptoPluginName)
{
    // finish the request.
    QList<QVariant> outParams;
    QByteArray encrypted;
    if (result.code() == Result::Succeeded) {
        bool ok = false;
        Key fullKey = Key::deserialise(serialisedKey, &ok);
        if (!ok) {
            outParams << QVariant::fromValue<Result>(Result(Result::SerialisationError,
                                                            QLatin1String("Failed to deserialise key!")));
        } else {
            Result cryptoResult = m_cryptoPlugins[cryptoPluginName]->encrypt(data, iv, fullKey, blockMode, padding, &encrypted);
            outParams << QVariant::fromValue<Result>(cryptoResult);
        }
    } else {
        outParams << QVariant::fromValue<Result>(result);
    }
    outParams << QVariant::fromValue<QByteArray>(encrypted);
    m_requestQueue->requestFinished(requestId, outParams);
}

Result
Daemon::ApiImpl::RequestProcessor::decrypt(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key,
        Key::BlockMode blockMode,
        Key::EncryptionPadding padding,
        const QString &cryptosystemProviderName,
        QByteArray *decrypted)
{
    // TODO: Access Control

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    // TODO: FIXME: don't check these here, if the key is a keyreference it won't contain algorithm metadata!
    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & Key::Decrypt)) {
        return Result(Result::UnsupportedOperation,
                      QLatin1String("The specified cryptographic service provider does not support decrypt operations"));
    } else if (!(cryptoPlugin->supportedBlockModes().value(key.algorithm()) & blockMode)) {
        return Result(Result::UnsupportedBlockMode,
                      QLatin1String("The specified cryptographic service provider does not support that block mode"));
    } else if (!(cryptoPlugin->supportedSignaturePaddings().value(key.algorithm()) & padding)) {
        return Result(Result::UnsupportedEncryptionPadding,
                      QLatin1String("The specified cryptographic service provider does not support that encryption padding"));
    }

    Key fullKey;
    if (key.privateKey().isEmpty() && key.secretKey().isEmpty()) {
        // the key is a key reference, attempt to read the full key from storage.
        Result retn(Result::Succeeded);
        if (key.identifier().name().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Reference key has empty identifier"));
        } else {
            QVector<Key::Identifier> identifiers;
            retn = transformSecretsResult(m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers));
            if (retn.code() == Result::Failed) {
                return retn;
            }
            if (!identifiers.contains(key.identifier())) {
                return Result(Result::InvalidKeyIdentifier,
                              QLatin1String("Reference key identifier doesn't exist"));
            }
        }

        // TODO: FIXME: if the crypto plugin is the storage plugin for the key, call it directly instead of fetching the key!
        QByteArray serialisedKey;
        QMap<QString, QString> filterData;
        retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, key.identifier(), &serialisedKey, &filterData));
        if (retn.code() == Result::Failed) {
            return retn;
        } else if (retn.code() == Result::Pending) {
            // asynchronous flow required, will call back to decrypt2().
            m_pendingRequests.insert(requestId,
                                     Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Daemon::ApiImpl::DecryptRequest,
                                         QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                        << QVariant::fromValue<QByteArray>(iv)
                                                        << QVariant::fromValue<Key::BlockMode>(blockMode)
                                                        << QVariant::fromValue<Key::EncryptionPadding>(padding)
                                                        << QVariant::fromValue<QString>(cryptosystemProviderName)));
            return retn;
        }

        fullKey = Key::deserialise(serialisedKey);
    } else {
        fullKey = key;
    }

    return cryptoPlugin->decrypt(data, iv, fullKey, blockMode, padding, decrypted);
}

void
Daemon::ApiImpl::RequestProcessor::decrypt2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &data,
        const QByteArray &iv,
        Key::BlockMode blockMode,
        Key::EncryptionPadding padding,
        const QString &cryptoPluginName)
{
    // finish the request.
    QList<QVariant> outParams;
    QByteArray decrypted;
    if (result.code() == Result::Succeeded) {
        Key fullKey = Key::deserialise(serialisedKey);
        Result cryptoResult = m_cryptoPlugins[cryptoPluginName]->decrypt(data, iv, fullKey, blockMode, padding, &decrypted);
        outParams << QVariant::fromValue<Result>(cryptoResult);
    } else {
        outParams << QVariant::fromValue<Result>(result);
    }
    outParams << QVariant::fromValue<QByteArray>(decrypted);
    m_requestQueue->requestFinished(requestId, outParams);
}


Result
Daemon::ApiImpl::RequestProcessor::initialiseCipherSession(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &iv,
        const Key &key,
        Key::Operation operation,
        Key::BlockMode blockMode,
        Key::EncryptionPadding encryptionPadding,
        Key::SignaturePadding signaturePadding,
        Key::Digest digest,
        const QString &cryptosystemProviderName,
        quint32 *cipherSessionToken,
        QByteArray *generatedIV)
{
    // TODO: Access Control

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    Key fullKey;
    if (key.privateKey().isEmpty() && key.secretKey().isEmpty()) {
        // the key is a key reference, attempt to read the full key from storage.
        Result retn(Result::Succeeded);
        if (key.identifier().name().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Reference key has empty identifier"));
        } else {
            QVector<Key::Identifier> identifiers;
            retn = transformSecretsResult(m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers));
            if (retn.code() == Result::Failed) {
                return retn;
            }
            if (!identifiers.contains(key.identifier())) {
                return Result(Result::InvalidKeyIdentifier,
                              QLatin1String("Reference key identifier doesn't exist"));
            }
        }

        // find out if the key is stored in the crypto plugin.
        // if so, we don't need to pull it into the daemon process address space.
        const QString keyCollectionName = key.identifier().collectionName().isEmpty() ? QLatin1String("standalone") : key.identifier().collectionName();
        const QString hashedKeyName = Sailfish::Secrets::Daemon::Util::generateHashedSecretName(keyCollectionName, key.identifier().name());
        Sailfish::Secrets::Result pluginResult = m_secrets->confirmKeyStoragePlugin(callerPid, requestId, hashedKeyName, keyCollectionName, cryptosystemProviderName);
        if (pluginResult.code() == Sailfish::Secrets::Result::Succeeded) {
            // yes, it is stored in the plugin.
            fullKey = key; // not a full key, but a reference to a key that the plugin stores.
        } else {
            // no, it is stored in some other plugin
            QByteArray serialisedKey;
            QMap<QString, QString> filterData;
            retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, key.identifier(), &serialisedKey, &filterData));
            if (retn.code() == Result::Failed) {
                return retn;
            } else if (retn.code() == Result::Pending) {
                // asynchronous flow required, will call back to initialiseCipherSession2().
                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::InitialiseCipherSessionRequest,
                                             QVariantList() << QVariant::fromValue<pid_t>(callerPid)
                                                            << QVariant::fromValue<QByteArray>(iv)
                                                            << QVariant::fromValue<Key::Operation>(operation)
                                                            << QVariant::fromValue<Key::BlockMode>(blockMode)
                                                            << QVariant::fromValue<Key::EncryptionPadding>(encryptionPadding)
                                                            << QVariant::fromValue<Key::SignaturePadding>(signaturePadding)
                                                            << QVariant::fromValue<Key::Digest>(digest)
                                                            << QVariant::fromValue<QString>(cryptosystemProviderName)));
                return retn;
            }

            fullKey = Key::deserialise(serialisedKey);
        }
    } else {
        fullKey = key;
    }

    return cryptoPlugin->initialiseCipherSession(
                callerPid,
                iv, fullKey, operation,
                blockMode, encryptionPadding,
                signaturePadding, digest,
                cipherSessionToken, generatedIV);
}

void
Daemon::ApiImpl::RequestProcessor::initialiseCipherSession2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serialisedKey,
        pid_t callerPid,
        const QByteArray &iv,
        Key::Operation operation,
        Key::BlockMode blockMode,
        Key::EncryptionPadding encryptionPadding,
        Key::SignaturePadding signaturePadding,
        Key::Digest digest,
        const QString &cryptoPluginName)
{
    // finish the request.
    QList<QVariant> outParams;
    quint32 cipherSessionToken = 0;
    QByteArray generatedIV;
    if (result.code() == Result::Succeeded) {
        Key fullKey = Key::deserialise(serialisedKey);
        Result cryptoResult = m_cryptoPlugins[cryptoPluginName]->initialiseCipherSession(
                    callerPid,
                    iv, fullKey, operation, blockMode,
                    encryptionPadding, signaturePadding,
                    digest, &cipherSessionToken, &generatedIV);
        outParams << QVariant::fromValue<Result>(cryptoResult);
    } else {
        outParams << QVariant::fromValue<Result>(result);
    }
    outParams << QVariant::fromValue<quint32>(cipherSessionToken);
    outParams << QVariant::fromValue<QByteArray>(generatedIV);
    m_requestQueue->requestFinished(requestId, outParams);
}

Result
Daemon::ApiImpl::RequestProcessor::updateCipherSessionAuthentication(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &authenticationData,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken)
{
    Q_UNUSED(requestId); // TODO: Access Control

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    return cryptoPlugin->updateCipherSessionAuthentication(
                callerPid,
                authenticationData,
                cipherSessionToken);
}

Result
Daemon::ApiImpl::RequestProcessor::updateCipherSession(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken,
        QByteArray *generatedData)
{
    Q_UNUSED(requestId); // TODO: Access Control

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    return cryptoPlugin->updateCipherSession(
                callerPid,
                data,
                cipherSessionToken,
                generatedData);
}

Result
Daemon::ApiImpl::RequestProcessor::finaliseCipherSession(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken,
        QByteArray *generatedData,
        bool *verified)
{
    Q_UNUSED(requestId); // TODO: Access Control

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    return cryptoPlugin->finaliseCipherSession(
                callerPid,
                data,
                cipherSessionToken,
                generatedData,
                verified);
}


// asynchronous operation (retrieve stored key) has completed.
void Daemon::ApiImpl::RequestProcessor::secretsStoredKeyCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result,
        const QByteArray &serialisedKey,
        const QMap<QString, QString> &filterData)
{
    // look up the pending request in our list
    if (m_pendingRequests.contains(requestId)) {
        // transform the error code.
        Result returnResult(transformSecretsResult(result));

        // call the appropriate method to complete the request
        Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
        switch (pr.requestType) {
            case StoredKeyRequest: {
                (void)pr.parameters.takeFirst(); // the identifier, we don't need it.
                StoredKeyRequest::KeyComponents keyComponents = pr.parameters.takeFirst().value<StoredKeyRequest::KeyComponents>();
                storedKey2(requestId, keyComponents, returnResult, serialisedKey, filterData);
                break;
            }
            case SignRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                Key::SignaturePadding padding = pr.parameters.takeFirst().value<Key::SignaturePadding>();
                Key::Digest digest = pr.parameters.takeFirst().value<Key::Digest>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                sign2(requestId, returnResult, serialisedKey, data, padding, digest, cryptoPluginName);
                break;
            }
            case VerifyRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                Key::SignaturePadding padding = pr.parameters.takeFirst().value<Key::SignaturePadding>();
                Key::Digest digest = pr.parameters.takeFirst().value<Key::Digest>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                verify2(requestId, returnResult, serialisedKey, data, padding, digest, cryptoPluginName);
                break;
            }
            case EncryptRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                QByteArray iv = pr.parameters.takeFirst().value<QByteArray>();
                Key::BlockMode blockMode = pr.parameters.takeFirst().value<Key::BlockMode>();
                Key::EncryptionPadding padding = pr.parameters.takeFirst().value<Key::EncryptionPadding>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                encrypt2(requestId, returnResult, serialisedKey, data, iv, blockMode, padding, cryptoPluginName);
                break;
            }
            case DecryptRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                QByteArray iv = pr.parameters.takeFirst().value<QByteArray>();
                Key::BlockMode blockMode = pr.parameters.takeFirst().value<Key::BlockMode>();
                Key::EncryptionPadding padding = pr.parameters.takeFirst().value<Key::EncryptionPadding>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                decrypt2(requestId, returnResult, serialisedKey, data, iv, blockMode, padding, cryptoPluginName);
                break;
            }
            case InitialiseCipherSessionRequest: {
                pid_t callerPid = pr.parameters.takeFirst().value<pid_t>();
                QByteArray iv = pr.parameters.takeFirst().value<QByteArray>();
                Key::Operation operation = pr.parameters.takeFirst().value<Key::Operation>();
                Key::BlockMode blockMode = pr.parameters.takeFirst().value<Key::BlockMode>();
                Key::EncryptionPadding encryptionPadding = pr.parameters.takeFirst().value<Key::EncryptionPadding>();
                Key::SignaturePadding signaturePadding = pr.parameters.takeFirst().value<Key::SignaturePadding>();
                Key::Digest digest = pr.parameters.takeFirst().value<Key::Digest>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                initialiseCipherSession2(requestId, returnResult, serialisedKey,
                                         callerPid, iv, operation, blockMode, encryptionPadding,
                                         signaturePadding, digest, cryptoPluginName);
                break;
            }
            default: {
                qCWarning(lcSailfishCryptoDaemon) << "Secrets completed storedKey() operation for request:" << requestId << "of invalid type:" << pr.requestType;
                break;
            }
        }
    } else {
        qCWarning(lcSailfishCryptoDaemon) << "Secrets completed storedKey() operation for unknown request:" << requestId;
    }
}

// asynchronous operation (store key) has completed.
void Daemon::ApiImpl::RequestProcessor::secretsStoreKeyCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result)
{
    // look up the pending request in our list
    if (m_pendingRequests.contains(requestId)) {
        // transform the error code.
        Result returnResult(transformSecretsResult(result));

        // call the appropriate method to complete the request
        Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
        switch (pr.requestType) {
            case GenerateStoredKeyRequest: {
                Key fullKey = pr.parameters.takeFirst().value<Key>();
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                QString storagePluginName = pr.parameters.takeFirst().value<QString>();
                generateStoredKey_inStoragePlugin(pr.callerPid, requestId, returnResult, fullKey, cryptosystemProviderName, storagePluginName);
                break;
            }
            default: {
                qCWarning(lcSailfishCryptoDaemon) << "Secrets completed storeKey() operation for request:" << requestId << "of invalid type:" << pr.requestType;
                break;
            }
        }
    } else {
        qCWarning(lcSailfishCryptoDaemon) << "Secrets completed storeKey() operation for unknown request:" << requestId;
    }
}

// asynchronous operation (store key metadata) has completed.
void Daemon::ApiImpl::RequestProcessor::secretsStoreKeyMetadataCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result)
{
    // look up the pending request in our list
    if (m_pendingRequests.contains(requestId)) {
        // transform the error code.
        Result returnResult(transformSecretsResult(result));

        // call the appropriate method to complete the request
        Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
        switch (pr.requestType) {
            case GenerateStoredKeyRequest: {
                Key keyTemplate = pr.parameters.takeFirst().value<Key>();
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                QString storagePluginName = pr.parameters.takeFirst().value<QString>();
                generateStoredKey_inCryptoPlugin(pr.callerPid, requestId, returnResult, keyTemplate, cryptosystemProviderName, storagePluginName);
                break;
            }
            default: {
                qCWarning(lcSailfishCryptoDaemon) << "Secrets completed storeKeyMetadata() operation for request:" << requestId << "of invalid type:" << pr.requestType;
                break;
            }
        }
    } else {
        qCWarning(lcSailfishCryptoDaemon) << "Secrets completed storeKeyMetadata() operation for unknown request:" << requestId;
    }
}

// asynchronous operation (delete stored key) has completed.
void Daemon::ApiImpl::RequestProcessor::secretsDeleteStoredKeyCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result)
{
    // look up the pending request in our list
    if (m_pendingRequests.contains(requestId)) {
        // transform the error code.
        Result returnResult(transformSecretsResult(result));

        // call the appropriate method to complete the request
        Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
        switch (pr.requestType) {
            case DeleteStoredKeyRequest: {
                Key::Identifier identifier = pr.parameters.size()
                        ? pr.parameters.first().value<Key::Identifier>()
                        : Key::Identifier();
                deleteStoredKey2(pr.callerPid, requestId, returnResult, identifier);
                break;
            }
            case GenerateStoredKeyRequest: {
                Key fullKey = pr.parameters.takeFirst().value<Key>();
                Result initialResult = pr.parameters.takeFirst().value<Result>();
                generateStoredKey_failedCleanup(pr.callerPid, requestId, fullKey, initialResult, returnResult);
                break;
            }
            default: {
                qCWarning(lcSailfishCryptoDaemon) << "Secrets completed deleteStoredKey() operation for request:" << requestId << "of invalid type:" << pr.requestType;
                break;
            }
        }
    } else {
        qCWarning(lcSailfishCryptoDaemon) << "Secrets completed deleteStoredKey() operation for unknown request:" << requestId;
    }
}

// asynchronous operation (delete stored key metadata) has completed.
void Daemon::ApiImpl::RequestProcessor::secretsDeleteStoredKeyMetadataCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result)
{
    // look up the pending request in our list
    if (m_pendingRequests.contains(requestId)) {
        // transform the error code.
        Result returnResult(transformSecretsResult(result));

        // call the appropriate method to complete the request
        Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
        switch (pr.requestType) {
            case GenerateStoredKeyRequest: {
                Key keyTemplate = pr.parameters.takeFirst().value<Key>();
                Result initialResult = pr.parameters.takeFirst().value<Result>();
                generateStoredKey_failedCleanup(pr.callerPid, requestId, keyTemplate, initialResult, returnResult);
                break;
            }
            default: {
                qCWarning(lcSailfishCryptoDaemon) << "Secrets completed deleteStoredKeyMetadata() operation for request:" << requestId << "of invalid type:" << pr.requestType;
                break;
            }
        }
    } else {
        qCWarning(lcSailfishCryptoDaemon) << "Secrets completed deleteStoredKeyMetadata() operation for unknown request:" << requestId;
    }
}
