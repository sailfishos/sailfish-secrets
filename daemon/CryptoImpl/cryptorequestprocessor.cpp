/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "CryptoImpl/cryptorequestprocessor_p.h"

#include "SecretsImpl/secrets_p.h"
#include "Secrets/result.h"

#include "logging_p.h"

#include <QtCore/QDir>
#include <QtCore/QPluginLoader>
#include <QtCore/QObject>

Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::RequestProcessor(Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *secrets,
                 Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue *parent)
    : QObject(parent), m_requestQueue(parent), m_secrets(secrets)
{
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storedKeyCompleted,
            this, &Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::secretsStoredKeyCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storeKeyCompleted,
            this, &Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::secretsStoreKeyCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storeKeyMetadataCompleted,
            this, &Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::secretsStoreKeyMetadataCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::deleteStoredKeyCompleted,
            this, &Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::secretsDeleteStoredKeyCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::deleteStoredKeyMetadataCompleted,
            this, &Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::secretsDeleteStoredKeyMetadataCompleted);
}

bool
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::loadPlugins(const QString &pluginDir, bool autotestMode)
{
    // First, see if any of the EncryptedStorage plugins from Secrets are also
    // Crypto plugins (providing generateAndStoreKey() functionality internally).
    qCDebug(lcSailfishCryptoDaemon) << "Loading crypto storage plugins";
    QMap<QString, QObject*> potentialCryptoPlugins = m_secrets->potentialCryptoStoragePlugins();
    for (QMap<QString, QObject*>::const_iterator it = potentialCryptoPlugins.constBegin(); it != potentialCryptoPlugins.constEnd(); it++) {
        Sailfish::Crypto::CryptoPlugin *cryptoPlugin = qobject_cast<Sailfish::Crypto::CryptoPlugin*>(it.value());
        if (cryptoPlugin) {
            if (cryptoPlugin->isTestPlugin() != autotestMode) {
                qCDebug(lcSailfishCryptoDaemon) << "ignoring crypto storage plugin:" << it.key() << "due to mode";
            } else if (cryptoPlugin->name().isEmpty() || m_cryptoPlugins.contains(cryptoPlugin->name())) {
                qCDebug(lcSailfishCryptoDaemon) << "ignoring crypto storage plugin:" << it.key() << "with duplicate name:" << cryptoPlugin->name();
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
        Sailfish::Crypto::CryptoPlugin *cryptoPlugin = qobject_cast<Sailfish::Crypto::CryptoPlugin*>(plugin);
        if (cryptoPlugin) {
            if (cryptoPlugin->isTestPlugin() != autotestMode) {
                qCDebug(lcSailfishCryptoDaemon) << "ignoring crypto plugin:" << pluginFile << "due to mode";
                loader.unload();
                continue;
            } else if (cryptoPlugin->name().isEmpty() || m_cryptoPlugins.contains(cryptoPlugin->name())) {
                qCDebug(lcSailfishCryptoDaemon) << "ignoring crypto plugin:" << pluginFile << "with duplicate name:" << cryptoPlugin->name();
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

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::getPluginInfo(
        pid_t callerPid,
        quint64 requestId,
        QVector<Sailfish::Crypto::CryptoPluginInfo> *cryptoPlugins,
        QStringList *storagePlugins)
{
    Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Succeeded);
    Sailfish::Secrets::Result secretsResult = m_secrets->storagePluginNames(callerPid, requestId, storagePlugins);
    if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
        retn.setCode(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(secretsResult.errorCode());
        retn.setErrorMessage(secretsResult.errorMessage());
        return retn;
    }

    QMap<QString, Sailfish::Crypto::CryptoPlugin*>::const_iterator it = m_cryptoPlugins.constBegin();
    for (; it != m_cryptoPlugins.constEnd(); it++) {
        cryptoPlugins->append(Sailfish::Crypto::CryptoPluginInfo(it.value()));
    }

    return retn;
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::validateCertificateChain(
        pid_t callerPid,
        quint64 requestId,
        const QVector<Sailfish::Crypto::Certificate> &chain,
        const QString &cryptosystemProviderName,
        bool *valid)
{
    // TODO: access control!
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidCryptographicServiceProvider,
                                        QLatin1String("No such cryptographic service provider plugin exists"));
    }

    return m_cryptoPlugins[cryptosystemProviderName]->validateCertificateChain(chain, valid);
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::generateKey(
        pid_t callerPid,
        quint64 requestId,
        const Sailfish::Crypto::Key &keyTemplate,
        const QString &cryptosystemProviderName,
        Sailfish::Crypto::Key *key)
{
    // TODO: access control!
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidCryptographicServiceProvider,
                                        QLatin1String("No such cryptographic service provider plugin exists"));
    }

    return m_cryptoPlugins[cryptosystemProviderName]->generateKey(keyTemplate, key);
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::generateStoredKey(
        pid_t callerPid,
        quint64 requestId,
        const Sailfish::Crypto::Key &keyTemplate,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName,
        Sailfish::Crypto::Key *key)
{
    Q_UNUSED(key) // asynchronous outparam, returned in generateStoredKey_inStoragePlugin/_inCryptoPlugin

    Sailfish::Secrets::Result secretsResult;
    if (keyTemplate.identifier().name().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                        QLatin1String("Template key identifier has empty name"));
    } else {
        QVector<Sailfish::Crypto::Key::Identifier> identifiers;
        secretsResult = m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers);
        if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
            Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Failed);
            retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
            retn.setStorageErrorCode(secretsResult.errorCode());
            retn.setErrorMessage(secretsResult.errorMessage());
            return retn;
        }
        if (identifiers.contains(keyTemplate.identifier())) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::DuplicateKeyIdentifier,
                                            QLatin1String("Template key identifier duplicates existing key"));
        }
    }

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidCryptographicServiceProvider,
                                        QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (storageProviderName == cryptosystemProviderName) {
        if (!m_cryptoPlugins[cryptosystemProviderName]->canStoreKeys()) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::StorageError,
                                            QLatin1String("The specified cryptographic service provider cannot store keys"));
        }

        secretsResult = m_secrets->storeKeyMetadata(callerPid, requestId, keyTemplate.identifier(), storageProviderName);
        if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
            Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Failed);
            retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
            retn.setStorageErrorCode(secretsResult.errorCode());
            retn.setErrorMessage(secretsResult.errorMessage());
            return retn;
        }

        // wait for the asynchronous operation to complete.
        // when complete it will invoke generateStoredKey_inCryptoPlugin().
        m_pendingRequests.insert(requestId,
                                 Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Sailfish::Crypto::Daemon::ApiImpl::GenerateStoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<Sailfish::Crypto::Key>(keyTemplate)
                                                    << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                    << QVariant::fromValue<QString>(storageProviderName)));
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Pending);
    } else {
        // generate the key
        Sailfish::Crypto::Key fullKey(keyTemplate);
        Sailfish::Crypto::Result keyResult = m_cryptoPlugins[cryptosystemProviderName]->generateKey(keyTemplate, &fullKey);
        if (keyResult.code() == Sailfish::Crypto::Result::Failed) {
            return keyResult;
        }

        secretsResult = m_secrets->storeKey(
                    callerPid,
                    requestId,
                    fullKey.identifier(),
                    Sailfish::Crypto::Key::serialise(fullKey, Sailfish::Crypto::Key::LossySerialisationMode),
                    fullKey.filterData(),
                    storageProviderName);
        if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
            // return storeKey error to the client.
            Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Failed);
            retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
            retn.setStorageErrorCode(secretsResult.errorCode());
            retn.setErrorMessage(secretsResult.errorMessage());
            return retn;
        }

        // asynchronous operation, will call back to generateStoredKey_inStoragePlugin().
        m_pendingRequests.insert(requestId,
                                 Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Sailfish::Crypto::Daemon::ApiImpl::GenerateStoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<Sailfish::Crypto::Key>(fullKey)
                                                    << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                    << QVariant::fromValue<QString>(storageProviderName)));
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Pending);
    }
}

void
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::generateStoredKey_inStoragePlugin(
        pid_t callerPid,
        quint64 requestId,
        const Sailfish::Crypto::Result &result,
        const Sailfish::Crypto::Key &fullKey,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName)
{
    // This method is invoked in the "generate from crypto plugin, store in secrets storage plugin" codepath.
    // if it was successfully stored into secrets, then add the key entry.
    Sailfish::Crypto::Result retn(result);
    if (result.code() == Sailfish::Crypto::Result::Succeeded) {
        Sailfish::Secrets::Result secretsResult = m_secrets->addKeyEntry(callerPid, requestId, fullKey.identifier(), cryptosystemProviderName, storageProviderName);
        if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
            // transform the error
            retn.setCode(Sailfish::Crypto::Result::Failed);
            retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
            retn.setStorageErrorCode(secretsResult.errorCode());
            retn.setErrorMessage(secretsResult.errorMessage());
            // Attempt to remove the key from secrets storage, to cleanup.
            // TODO: in the future we should refactor so that this can be done via a transaction rollback!
            secretsResult = m_secrets->deleteStoredKey(callerPid, requestId, fullKey.identifier());
            if (secretsResult.code() != Sailfish::Secrets::Result::Failed) {
                m_pendingRequests.insert(requestId,
                                         Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Sailfish::Crypto::Daemon::ApiImpl::GenerateStoredKeyRequest,
                                             QVariantList() << QVariant::fromValue<Sailfish::Crypto::Key>(fullKey)
                                                            << QVariant::fromValue<Sailfish::Crypto::Result>(retn)));
                return;
            }
            // TODO: we now have stale data in the secrets main table.
            //       Add a dirty flag for this datum, and attempt to cleanup later.
            qCWarning(lcSailfishCryptoDaemon) << "Failed to clean up stored key after failed generateStoredKey request:"
                                              << secretsResult.errorCode() << secretsResult.errorMessage();
        }
    }

    // finish the asynchronous request.
    Sailfish::Crypto::Key partialKey(fullKey);
    partialKey.setPrivateKey(QByteArray());
    partialKey.setSecretKey(QByteArray());
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Sailfish::Crypto::Result>(retn);
    outParams << QVariant::fromValue<Sailfish::Crypto::Key>(partialKey);
    m_requestQueue->requestFinished(requestId, outParams);
}

void
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::generateStoredKey_inCryptoPlugin(
        pid_t callerPid,
        quint64 requestId,
        const Sailfish::Crypto::Result &result,
        const Sailfish::Crypto::Key &keyTemplate,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName)
{
    // This method is invoked in the "generate and store into crypto plugin" codepath.
    if (result.code() != Sailfish::Crypto::Result::Succeeded) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Sailfish::Crypto::Result>(result);
        outParams << QVariant::fromValue<Sailfish::Crypto::Key>(keyTemplate);
        m_requestQueue->requestFinished(requestId, outParams);
        return;
    }

    // if the metadata was successfully stored into secrets, then generate the full key
    // and store it in the crypto plugin, and if that succeeds, add the key entry.
    Sailfish::Crypto::Key fullKey(keyTemplate);
    Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Succeeded);
    Sailfish::Secrets::Result secretsResult = m_secrets->addKeyEntry(callerPid, requestId, keyTemplate.identifier(), cryptosystemProviderName, storageProviderName);
    if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
        // transform the error
        retn.setCode(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(secretsResult.errorCode());
        retn.setErrorMessage(secretsResult.errorMessage());
        // Attempt to remove the key metadata from secrets storage, to cleanup.
        // In this case, the key has not yet been stored in the (crypto) plugin, so it is enough
        // to merely delete the metadata.  We need a specific deleteStoredKeyMetadata(),
        // as any attempt to delete the actual secret from the plugin will fail (it doesn't exist).
        secretsResult = m_secrets->deleteStoredKeyMetadata(callerPid, requestId, keyTemplate.identifier());
        if (secretsResult.code() != Sailfish::Secrets::Result::Failed) {
            m_pendingRequests.insert(requestId,
                                     Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Sailfish::Crypto::Daemon::ApiImpl::GenerateStoredKeyRequest,
                                         QVariantList() << QVariant::fromValue<Sailfish::Crypto::Key>(keyTemplate)
                                                        << QVariant::fromValue<Sailfish::Crypto::Result>(retn)));
            return;
        }
        // TODO: we now have stale data in the secrets main table.
        //       Add a dirty flag for this datum, and attempt to cleanup later.
        // Also clean up the key entry as it doesn't actually exist.
        qCWarning(lcSailfishCryptoDaemon) << "Failed to clean up stored key metadata after failed generateStoredKey request:"
                                          << secretsResult.errorCode() << secretsResult.errorMessage();
        m_secrets->removeKeyEntry(callerPid, requestId, keyTemplate.identifier());
    } else {
        retn = m_cryptoPlugins[cryptosystemProviderName]->generateAndStoreKey(keyTemplate, &fullKey);
        if (retn.code() == Sailfish::Crypto::Result::Failed) {
            // Attempt to remove the key metadata from secrets storage, to cleanup.
            // Note: the keyEntry should be cascade deleted automatically.
            secretsResult = m_secrets->deleteStoredKeyMetadata(callerPid, requestId, keyTemplate.identifier());
            if (secretsResult.code() != Sailfish::Secrets::Result::Failed) {
                m_pendingRequests.insert(requestId,
                                         Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Sailfish::Crypto::Daemon::ApiImpl::GenerateStoredKeyRequest,
                                             QVariantList() << QVariant::fromValue<Sailfish::Crypto::Key>(keyTemplate)
                                                            << QVariant::fromValue<Sailfish::Crypto::Result>(retn)));
                return;
            }
            // TODO: we now have stale data in the secrets main table.
            //       Add a dirty flag for this datum, and attempt to cleanup later.
            // Also clean up the key entry as it doesn't actually exist.
            qCWarning(lcSailfishCryptoDaemon) << "Failed to clean up stored key metadata after failed generateStoredKey request:"
                                              << secretsResult.errorCode() << secretsResult.errorMessage();
            m_secrets->removeKeyEntry(callerPid, requestId, keyTemplate.identifier());
        }
    }

    // finish the asynchronous request.
    Sailfish::Crypto::Key partialKey(fullKey);
    partialKey.setPrivateKey(QByteArray());
    partialKey.setSecretKey(QByteArray());
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Sailfish::Crypto::Result>(retn);
    outParams << QVariant::fromValue<Sailfish::Crypto::Key>(partialKey);
    m_requestQueue->requestFinished(requestId, outParams);
}

void
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::generateStoredKey_failedCleanup(
        pid_t callerPid,
        quint64 requestId,
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::Result &initialResult,
        const Sailfish::Crypto::Result &result)
{
    Q_UNUSED(callerPid)

    // This method will be invoked if the generateStoredKey() failed
    // and we had to cleanup the stored key data or metadata from secrets.
    // check to see if the result of the deleteStoredKey/deleteStoredKeyMetadata failed
    if (result.code() == Sailfish::Crypto::Result::Failed) {
        // TODO: we now have stale data in the secrets main table.
        //       Add a dirty flag for this datum, and attempt to cleanup later.
        // Also clean up the key entry as it doesn't actually exist.
        qCWarning(lcSailfishCryptoDaemon) << "Failed to clean up stored key or metadata after failed generateStoredKey request:"
                                          << result.storageErrorCode() << result.errorMessage();
        m_secrets->removeKeyEntry(callerPid, requestId, keyTemplate.identifier()); // expected fail/no-op in the inStoragePlugin case.
    }

    // Finish the asynchronous request.
    Sailfish::Crypto::Key partialKey(keyTemplate);
    partialKey.setPrivateKey(QByteArray());
    partialKey.setSecretKey(QByteArray());
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Sailfish::Crypto::Result>(initialResult);
    outParams << QVariant::fromValue<Sailfish::Crypto::Key>(partialKey);
    m_requestQueue->requestFinished(requestId, outParams);
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::storedKey(
        pid_t callerPid,
        quint64 requestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        Sailfish::Crypto::Key *key)
{
    // TODO: access control

    Sailfish::Crypto::Result retn = Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);

    QVector<Sailfish::Crypto::Key::Identifier> identifiers;
    Sailfish::Secrets::Result secretsResult = m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers);
    if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
        retn.setCode(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(secretsResult.errorCode());
        retn.setErrorMessage(secretsResult.errorMessage());
        return retn;
    }

    if (!identifiers.contains(identifier)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                        QLatin1String("No such key exists in storage"));
    }

    QString cryptoPluginName, storagePluginName;
    secretsResult = m_secrets->keyEntry(callerPid, requestId, identifier, &cryptoPluginName, &storagePluginName);
    if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
        retn.setCode(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(secretsResult.errorCode());
        retn.setErrorMessage(secretsResult.errorMessage());
        return retn;
    } else if (storagePluginName.isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidStorageProvider,
                                        QLatin1String("Internal error: storage plugin associated with that key is empty"));
    }

    if (m_cryptoPlugins.contains(storagePluginName)) {
        return m_cryptoPlugins[storagePluginName]->storedKey(identifier, key);
    }

    QByteArray serialisedKey;
    QMap<QString, QString> filterData;
    secretsResult = m_secrets->storedKey(callerPid, requestId, identifier, &serialisedKey, &filterData);
    if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
        retn.setCode(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(secretsResult.errorCode());
        retn.setErrorMessage(secretsResult.errorMessage());
        return retn;
    } else if (secretsResult.code() == Sailfish::Secrets::Result::Pending) {
        // asynchronous flow required, will eventually call back to storedKey2().
        m_pendingRequests.insert(requestId,
                                 Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Sailfish::Crypto::Daemon::ApiImpl::StoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<Sailfish::Crypto::Key::Identifier>(identifier)));
        retn.setCode(Sailfish::Crypto::Result::Pending);
        return retn;
    }

    *key = Sailfish::Crypto::Key::deserialise(serialisedKey);
    key->setFilterData(filterData);
    return retn;
}

void
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::storedKey2(
        quint64 requestId,
        const Sailfish::Crypto::Result &result,
        const QByteArray &serialisedKey,
        const QMap<QString, QString> &filterData)
{
    Sailfish::Crypto::Key retn(Sailfish::Crypto::Key::deserialise(serialisedKey));
    retn.setFilterData(filterData);

    // finish the request.
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Sailfish::Crypto::Result>(result);
    outParams << QVariant::fromValue<Sailfish::Crypto::Key>(retn);
    m_requestQueue->requestFinished(requestId, outParams);
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::deleteStoredKey(
        pid_t callerPid,
        quint64 requestId,
        const Sailfish::Crypto::Key::Identifier &identifier)
{
    // TODO: access control

    Sailfish::Crypto::Result retn = Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);

    QString cryptoPluginName, storagePluginName;
    Sailfish::Secrets::Result secretsResult = m_secrets->keyEntry(callerPid, requestId, identifier, &cryptoPluginName, &storagePluginName);
    if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
        retn.setCode(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(secretsResult.errorCode());
        retn.setErrorMessage(secretsResult.errorMessage());
        return retn;
    } else if (storagePluginName.isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidStorageProvider,
                                        QLatin1String("Internal error: storage plugin associated with that key is empty"));
    }

    // delete from secrets storage
    secretsResult = m_secrets->deleteStoredKey(callerPid, requestId, identifier);
    if (secretsResult.code() == Sailfish::Secrets::Result::Succeeded) {
        m_secrets->removeKeyEntry(callerPid, requestId, identifier);
        // TODO: if that fails, re-try later etc.
    } else if (secretsResult.code() == Sailfish::Secrets::Result::Pending) {
        // asynchronous flow, will call back to deleteStoredKey2().
        m_pendingRequests.insert(requestId,
                                 Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Sailfish::Crypto::Daemon::ApiImpl::DeleteStoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<Sailfish::Crypto::Key::Identifier>(identifier)));
        retn.setCode(Sailfish::Crypto::Result::Pending);
    } else {
        retn.setCode(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(static_cast<int>(secretsResult.errorCode()));
        retn.setErrorMessage(secretsResult.errorMessage());
    }

    return retn;
}

void Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::deleteStoredKey2(
        pid_t callerPid,
        quint64 requestId,
        const Sailfish::Crypto::Result &result,
        const Sailfish::Crypto::Key::Identifier &identifier)
{
    // finish the request.
    if (result.code() == Sailfish::Crypto::Result::Succeeded) {
        m_secrets->removeKeyEntry(callerPid, requestId, identifier);
        // TODO: if that fails, re-try later etc.
    }
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Sailfish::Crypto::Result>(result);
    m_requestQueue->requestFinished(requestId, outParams);
}


Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::storedKeyIdentifiers(
        pid_t callerPid,
        quint64 requestId,
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
{
    Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Succeeded);
    Sailfish::Secrets::Result secretsResult = m_secrets->keyEntryIdentifiers(callerPid, requestId, identifiers);
    if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
        retn.setCode(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(secretsResult.errorCode());
        retn.setErrorMessage(secretsResult.errorMessage());
    }
    return retn;
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::sign(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName,
        QByteArray *signature)
{
    // TODO: Access Control

    Sailfish::Crypto::CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidCryptographicServiceProvider,
                                        QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & Sailfish::Crypto::Key::Sign)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The specified cryptographic service provider does not support sign operations"));
    } else if (!(cryptoPlugin->supportedSignaturePaddings().value(key.algorithm()) & padding)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedSignaturePadding,
                                        QLatin1String("The specified cryptographic service provider does not support that signature padding"));
    } else if (!(cryptoPlugin->supportedDigests().value(key.algorithm()) & digest)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedDigest,
                                        QLatin1String("The specified cryptographic service provider does not support that digest"));
    }

    Sailfish::Crypto::Key fullKey;
    if (key.privateKey().isEmpty() && key.secretKey().isEmpty()) {
        // the key is a key reference, attempt to read the full key from storage.
        Sailfish::Secrets::Result secretsResult(Sailfish::Secrets::Result::Succeeded);
        Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Succeeded);
        if (key.identifier().name().isEmpty()) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                            QLatin1String("Reference key has empty identifier"));
        } else {
            QVector<Sailfish::Crypto::Key::Identifier> identifiers;
            secretsResult = m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers);
            if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
                retn.setCode(Sailfish::Crypto::Result::Succeeded);
                retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
                retn.setStorageErrorCode(secretsResult.errorCode());
                retn.setErrorMessage(secretsResult.errorMessage());
                return retn;
            }
            if (!identifiers.contains(key.identifier())) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                                QLatin1String("Reference key identifier doesn't exist"));
            }
        }

        QByteArray serialisedKey;
        QMap<QString, QString> filterData;
        secretsResult = m_secrets->storedKey(callerPid, requestId, key.identifier(), &serialisedKey, &filterData);
        if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
            Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Failed);
            retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
            retn.setStorageErrorCode(secretsResult.errorCode());
            retn.setErrorMessage(secretsResult.errorMessage());
            return retn;
        } else if (secretsResult.code() == Sailfish::Secrets::Result::Pending) {
            // asynchronous flow required, will call back to sign2().
            m_pendingRequests.insert(requestId,
                                     Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Sailfish::Crypto::Daemon::ApiImpl::SignRequest,
                                         QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                        << QVariant::fromValue<Sailfish::Crypto::Key::SignaturePadding>(padding)
                                                        << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest)
                                                        << QVariant::fromValue<QString>(cryptosystemProviderName)));
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Pending);
        }

        fullKey = Sailfish::Crypto::Key::deserialise(serialisedKey);
    } else {
        fullKey = key;
    }

    return cryptoPlugin->sign(data, fullKey, padding, digest, signature);
}

void
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::sign2(
        quint64 requestId,
        const Sailfish::Crypto::Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &data,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptoPluginName)
{
    // finish the request.
    QList<QVariant> outParams;
    QByteArray signature;
    if (result.code() == Sailfish::Crypto::Result::Succeeded) {
        Sailfish::Crypto::Key fullKey = Sailfish::Crypto::Key::deserialise(serialisedKey);
        Sailfish::Crypto::Result cryptoResult = m_cryptoPlugins[cryptoPluginName]->sign(data, fullKey, padding, digest, &signature);
        outParams << QVariant::fromValue<Sailfish::Crypto::Result>(cryptoResult);
    } else {
        outParams << QVariant::fromValue<Sailfish::Crypto::Result>(result);
    }
    outParams << QVariant::fromValue<QByteArray>(signature);
    m_requestQueue->requestFinished(requestId, outParams);
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::verify(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName,
        bool *verified)
{
    // TODO: Access Control

    Sailfish::Crypto::CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidCryptographicServiceProvider,
                                        QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & Sailfish::Crypto::Key::Verify)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The specified cryptographic service provider does not support verify operations"));
    } else if (!(cryptoPlugin->supportedSignaturePaddings().value(key.algorithm()) & padding)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedSignaturePadding,
                                        QLatin1String("The specified cryptographic service provider does not support that signature padding"));
    } else if (!(cryptoPlugin->supportedDigests().value(key.algorithm()) & digest)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedDigest,
                                        QLatin1String("The specified cryptographic service provider does not support that digest"));
    }

    Sailfish::Crypto::Key fullKey;
    if (key.publicKey().isEmpty() && key.privateKey().isEmpty() && key.secretKey().isEmpty()) { // can use public key to verify
        // the key is a key reference, attempt to read the full key from storage.
        Sailfish::Secrets::Result secretsResult(Sailfish::Secrets::Result::Succeeded);
        Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Succeeded);
        if (key.identifier().name().isEmpty()) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                            QLatin1String("Reference key has empty identifier"));
        } else {
            QVector<Sailfish::Crypto::Key::Identifier> identifiers;
            secretsResult = m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers);
            if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
                retn.setCode(Sailfish::Crypto::Result::Succeeded);
                retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
                retn.setStorageErrorCode(secretsResult.errorCode());
                retn.setErrorMessage(secretsResult.errorMessage());
                return retn;
            }
            if (!identifiers.contains(key.identifier())) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                                QLatin1String("Reference key identifier doesn't exist"));
            }
        }

        QByteArray serialisedKey;
        QMap<QString, QString> filterData;
        secretsResult = m_secrets->storedKey(callerPid, requestId, key.identifier(), &serialisedKey, &filterData);
        if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
            Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Failed);
            retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
            retn.setStorageErrorCode(secretsResult.errorCode());
            retn.setErrorMessage(secretsResult.errorMessage());
            return retn;
        } else if (secretsResult.code() == Sailfish::Secrets::Result::Pending) {
            // asynchronous flow required, will call back to verify2().
            m_pendingRequests.insert(requestId,
                                     Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Sailfish::Crypto::Daemon::ApiImpl::VerifyRequest,
                                         QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                        << QVariant::fromValue<Sailfish::Crypto::Key::SignaturePadding>(padding)
                                                        << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest)
                                                        << QVariant::fromValue<QString>(cryptosystemProviderName)));
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Pending);
        }

        fullKey = Sailfish::Crypto::Key::deserialise(serialisedKey);
    } else {
        fullKey = key;
    }

    return cryptoPlugin->verify(data, fullKey, padding, digest, verified);
}

void
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::verify2(
        quint64 requestId,
        const Sailfish::Crypto::Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &data,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptoPluginName)
{
    // finish the request.
    QList<QVariant> outParams;
    bool verified = false;
    if (result.code() == Sailfish::Crypto::Result::Succeeded) {
        Sailfish::Crypto::Key fullKey = Sailfish::Crypto::Key::deserialise(serialisedKey);
        Sailfish::Crypto::Result cryptoResult = m_cryptoPlugins[cryptoPluginName]->verify(data, fullKey, padding, digest, &verified);
        outParams << QVariant::fromValue<Sailfish::Crypto::Result>(cryptoResult);
    } else {
        outParams << QVariant::fromValue<Sailfish::Crypto::Result>(result);
    }
    outParams << QVariant::fromValue<bool>(verified);
    m_requestQueue->requestFinished(requestId, outParams);
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::encrypt(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName,
        QByteArray *encrypted)
{
    // TODO: Access Control

    Sailfish::Crypto::CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidCryptographicServiceProvider,
                                        QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & Sailfish::Crypto::Key::Encrypt)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The specified cryptographic service provider does not support encrypt operations"));
    } else if (!(cryptoPlugin->supportedBlockModes().value(key.algorithm()) & blockMode)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedBlockMode,
                                        QLatin1String("The specified cryptographic service provider does not support that block mode"));
    } else if (!(cryptoPlugin->supportedSignaturePaddings().value(key.algorithm()) & padding)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedEncryptionPadding,
                                        QLatin1String("The specified cryptographic service provider does not support that encryption padding"));
    } else if (!(cryptoPlugin->supportedDigests().value(key.algorithm()) & digest)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedDigest,
                                        QLatin1String("The specified cryptographic service provider does not support that digest"));
    }

    Sailfish::Crypto::Key fullKey;
    if (key.publicKey().isEmpty() && key.privateKey().isEmpty() && key.secretKey().isEmpty()) { // can use public key to encrypt
        // the key is a key reference, attempt to read the full key from storage.
        Sailfish::Secrets::Result secretsResult(Sailfish::Secrets::Result::Succeeded);
        Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Succeeded);
        if (key.identifier().name().isEmpty()) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                            QLatin1String("Reference key has empty identifier"));
        } else {
            QVector<Sailfish::Crypto::Key::Identifier> identifiers;
            secretsResult = m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers);
            if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
                retn.setCode(Sailfish::Crypto::Result::Succeeded);
                retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
                retn.setStorageErrorCode(secretsResult.errorCode());
                retn.setErrorMessage(secretsResult.errorMessage());
                return retn;
            }
            if (!identifiers.contains(key.identifier())) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                                QLatin1String("Reference key identifier doesn't exist"));
            }
        }

        QByteArray serialisedKey;
        QMap<QString, QString> filterData;
        secretsResult = m_secrets->storedKey(callerPid, requestId, key.identifier(), &serialisedKey, &filterData);
        if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
            Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Failed);
            retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
            retn.setStorageErrorCode(secretsResult.errorCode());
            retn.setErrorMessage(secretsResult.errorMessage());
            return retn;
        } else if (secretsResult.code() == Sailfish::Secrets::Result::Pending) {
            // asynchronous flow required, will call back to encrypt2().
            m_pendingRequests.insert(requestId,
                                     Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Sailfish::Crypto::Daemon::ApiImpl::EncryptRequest,
                                         QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                        << QVariant::fromValue<Sailfish::Crypto::Key::BlockMode>(blockMode)
                                                        << QVariant::fromValue<Sailfish::Crypto::Key::EncryptionPadding>(padding)
                                                        << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest)
                                                        << QVariant::fromValue<QString>(cryptosystemProviderName)));
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Pending);
        }

        fullKey = Sailfish::Crypto::Key::deserialise(serialisedKey);
    } else {
        fullKey = key;
    }

    return cryptoPlugin->encrypt(data, fullKey, blockMode, padding, digest, encrypted);
}

void
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::encrypt2(
        quint64 requestId,
        const Sailfish::Crypto::Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &data,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptoPluginName)
{
    // finish the request.
    QList<QVariant> outParams;
    QByteArray encrypted;
    if (result.code() == Sailfish::Crypto::Result::Succeeded) {
        bool ok = false;
        Sailfish::Crypto::Key fullKey = Sailfish::Crypto::Key::deserialise(serialisedKey, &ok);
        if (!ok) {
            outParams << QVariant::fromValue<Sailfish::Crypto::Result>(Sailfish::Crypto::Result(
                                                                           Sailfish::Crypto::Result::SerialisationError,
                                                                           QLatin1String("Failed to deserialise key!")));
        } else {
            Sailfish::Crypto::Result cryptoResult = m_cryptoPlugins[cryptoPluginName]->encrypt(data, fullKey, blockMode, padding, digest, &encrypted);
            outParams << QVariant::fromValue<Sailfish::Crypto::Result>(cryptoResult);
        }
    } else {
        outParams << QVariant::fromValue<Sailfish::Crypto::Result>(result);
    }
    outParams << QVariant::fromValue<QByteArray>(encrypted);
    m_requestQueue->requestFinished(requestId, outParams);
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::decrypt(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName,
        QByteArray *decrypted)
{
    // TODO: Access Control

    Sailfish::Crypto::CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidCryptographicServiceProvider,
                                        QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & Sailfish::Crypto::Key::Decrypt)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The specified cryptographic service provider does not support decrypt operations"));
    } else if (!(cryptoPlugin->supportedBlockModes().value(key.algorithm()) & blockMode)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedBlockMode,
                                        QLatin1String("The specified cryptographic service provider does not support that block mode"));
    } else if (!(cryptoPlugin->supportedSignaturePaddings().value(key.algorithm()) & padding)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedEncryptionPadding,
                                        QLatin1String("The specified cryptographic service provider does not support that encryption padding"));
    } else if (!(cryptoPlugin->supportedDigests().value(key.algorithm()) & digest)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedDigest,
                                        QLatin1String("The specified cryptographic service provider does not support that digest"));
    }

    Sailfish::Crypto::Key fullKey;
    if (key.privateKey().isEmpty() && key.secretKey().isEmpty()) {
        // the key is a key reference, attempt to read the full key from storage.
        Sailfish::Secrets::Result secretsResult(Sailfish::Secrets::Result::Succeeded);
        Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Succeeded);
        if (key.identifier().name().isEmpty()) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                            QLatin1String("Reference key has empty identifier"));
        } else {
            QVector<Sailfish::Crypto::Key::Identifier> identifiers;
            secretsResult = m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers);
            if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
                retn.setCode(Sailfish::Crypto::Result::Succeeded);
                retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
                retn.setStorageErrorCode(secretsResult.errorCode());
                retn.setErrorMessage(secretsResult.errorMessage());
                return retn;
            }
            if (!identifiers.contains(key.identifier())) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                                QLatin1String("Reference key identifier doesn't exist"));
            }
        }

        QByteArray serialisedKey;
        QMap<QString, QString> filterData;
        secretsResult = m_secrets->storedKey(callerPid, requestId, key.identifier(), &serialisedKey, &filterData);
        if (secretsResult.code() == Sailfish::Secrets::Result::Failed) {
            Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Failed);
            retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
            retn.setStorageErrorCode(secretsResult.errorCode());
            retn.setErrorMessage(secretsResult.errorMessage());
            return retn;
        } else if (secretsResult.code() == Sailfish::Secrets::Result::Pending) {
            // asynchronous flow required, will call back to decrypt2().
            m_pendingRequests.insert(requestId,
                                     Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Sailfish::Crypto::Daemon::ApiImpl::DecryptRequest,
                                         QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                        << QVariant::fromValue<Sailfish::Crypto::Key::BlockMode>(blockMode)
                                                        << QVariant::fromValue<Sailfish::Crypto::Key::EncryptionPadding>(padding)
                                                        << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest)
                                                        << QVariant::fromValue<QString>(cryptosystemProviderName)));
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Pending);
        }

        fullKey = Sailfish::Crypto::Key::deserialise(serialisedKey);
    } else {
        fullKey = key;
    }

    return cryptoPlugin->decrypt(data, fullKey, blockMode, padding, digest, decrypted);
}

void
Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::decrypt2(
        quint64 requestId,
        const Sailfish::Crypto::Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &data,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptoPluginName)
{
    // finish the request.
    QList<QVariant> outParams;
    QByteArray decrypted;
    if (result.code() == Sailfish::Crypto::Result::Succeeded) {
        Sailfish::Crypto::Key fullKey = Sailfish::Crypto::Key::deserialise(serialisedKey);
        Sailfish::Crypto::Result cryptoResult = m_cryptoPlugins[cryptoPluginName]->decrypt(data, fullKey, blockMode, padding, digest, &decrypted);
        outParams << QVariant::fromValue<Sailfish::Crypto::Result>(cryptoResult);
    } else {
        outParams << QVariant::fromValue<Sailfish::Crypto::Result>(result);
    }
    outParams << QVariant::fromValue<QByteArray>(decrypted);
    m_requestQueue->requestFinished(requestId, outParams);
}


// asynchronous operation (retrieve stored key) has completed.
void Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::secretsStoredKeyCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result,
        const QByteArray &serialisedKey,
        const QMap<QString, QString> &filterData)
{
    // look up the pending request in our list
    if (m_pendingRequests.contains(requestId)) {
        // transform the error code.
        Sailfish::Crypto::Result returnResult;
        if (result.code() == Sailfish::Secrets::Result::Succeeded) {
            returnResult.setCode(Sailfish::Crypto::Result::Succeeded);
        } else {
            returnResult.setCode(Sailfish::Crypto::Result::Failed);
            returnResult.setErrorCode(Sailfish::Crypto::Result::StorageError);
            returnResult.setStorageErrorCode(result.errorCode());
            returnResult.setErrorMessage(result.errorMessage());
        }

        // call the appropriate method to complete the request
        Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
        switch (pr.requestType) {
            case StoredKeyRequest: {
                storedKey2(requestId, returnResult, serialisedKey, filterData);
                break;
            }
            case SignRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                Sailfish::Crypto::Key::SignaturePadding padding = pr.parameters.takeFirst().value<Sailfish::Crypto::Key::SignaturePadding>();
                Sailfish::Crypto::Key::Digest digest = pr.parameters.takeFirst().value<Sailfish::Crypto::Key::Digest>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                sign2(requestId, returnResult, serialisedKey, data, padding, digest, cryptoPluginName);
                break;
            }
            case VerifyRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                Sailfish::Crypto::Key::SignaturePadding padding = pr.parameters.takeFirst().value<Sailfish::Crypto::Key::SignaturePadding>();
                Sailfish::Crypto::Key::Digest digest = pr.parameters.takeFirst().value<Sailfish::Crypto::Key::Digest>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                verify2(requestId, returnResult, serialisedKey, data, padding, digest, cryptoPluginName);
                break;
            }
            case EncryptRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                Sailfish::Crypto::Key::BlockMode blockMode = pr.parameters.takeFirst().value<Sailfish::Crypto::Key::BlockMode>();
                Sailfish::Crypto::Key::EncryptionPadding padding = pr.parameters.takeFirst().value<Sailfish::Crypto::Key::EncryptionPadding>();
                Sailfish::Crypto::Key::Digest digest = pr.parameters.takeFirst().value<Sailfish::Crypto::Key::Digest>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                encrypt2(requestId, returnResult, serialisedKey, data, blockMode, padding, digest, cryptoPluginName);
                break;
            }
            case DecryptRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                Sailfish::Crypto::Key::BlockMode blockMode = pr.parameters.takeFirst().value<Sailfish::Crypto::Key::BlockMode>();
                Sailfish::Crypto::Key::EncryptionPadding padding = pr.parameters.takeFirst().value<Sailfish::Crypto::Key::EncryptionPadding>();
                Sailfish::Crypto::Key::Digest digest = pr.parameters.takeFirst().value<Sailfish::Crypto::Key::Digest>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                decrypt2(requestId, returnResult, serialisedKey, data, blockMode, padding, digest, cryptoPluginName);
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
void Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::secretsStoreKeyCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result)
{
    // look up the pending request in our list
    if (m_pendingRequests.contains(requestId)) {
        // transform the error code.
        Sailfish::Crypto::Result returnResult;
        if (result.code() == Sailfish::Secrets::Result::Succeeded) {
            returnResult.setCode(Sailfish::Crypto::Result::Succeeded);
        } else {
            returnResult.setCode(Sailfish::Crypto::Result::Failed);
            returnResult.setErrorCode(Sailfish::Crypto::Result::StorageError);
            returnResult.setStorageErrorCode(result.errorCode());
            returnResult.setErrorMessage(result.errorMessage());
        }

        // call the appropriate method to complete the request
        Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
        switch (pr.requestType) {
            case GenerateStoredKeyRequest: {
                Sailfish::Crypto::Key fullKey = pr.parameters.takeFirst().value<Sailfish::Crypto::Key>();
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
void Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::secretsStoreKeyMetadataCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result)
{
    // look up the pending request in our list
    if (m_pendingRequests.contains(requestId)) {
        // transform the error code.
        Sailfish::Crypto::Result returnResult;
        if (result.code() == Sailfish::Secrets::Result::Succeeded) {
            returnResult.setCode(Sailfish::Crypto::Result::Succeeded);
        } else {
            returnResult.setCode(Sailfish::Crypto::Result::Failed);
            returnResult.setErrorCode(Sailfish::Crypto::Result::StorageError);
            returnResult.setStorageErrorCode(result.errorCode());
            returnResult.setErrorMessage(result.errorMessage());
        }

        // call the appropriate method to complete the request
        Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
        switch (pr.requestType) {
            case GenerateStoredKeyRequest: {
                Sailfish::Crypto::Key keyTemplate = pr.parameters.takeFirst().value<Sailfish::Crypto::Key>();
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
void Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::secretsDeleteStoredKeyCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result)
{
    // look up the pending request in our list
    if (m_pendingRequests.contains(requestId)) {
        // transform the error code.
        Sailfish::Crypto::Result returnResult;
        if (result.code() == Sailfish::Secrets::Result::Succeeded) {
            returnResult.setCode(Sailfish::Crypto::Result::Succeeded);
        } else {
            returnResult.setCode(Sailfish::Crypto::Result::Failed);
            returnResult.setErrorCode(Sailfish::Crypto::Result::StorageError);
            returnResult.setStorageErrorCode(result.errorCode());
            returnResult.setErrorMessage(result.errorMessage());
        }

        // call the appropriate method to complete the request
        Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
        switch (pr.requestType) {
            case DeleteStoredKeyRequest: {
                Sailfish::Crypto::Key::Identifier identifier = pr.parameters.size()
                        ? pr.parameters.first().value<Sailfish::Crypto::Key::Identifier>()
                        : Sailfish::Crypto::Key::Identifier();
                deleteStoredKey2(pr.callerPid, requestId, returnResult, identifier);
                break;
            }
            case GenerateStoredKeyRequest: {
                Sailfish::Crypto::Key fullKey = pr.parameters.takeFirst().value<Sailfish::Crypto::Key>();
                Sailfish::Crypto::Result initialResult = pr.parameters.takeFirst().value<Sailfish::Crypto::Result>();
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
void Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::secretsDeleteStoredKeyMetadataCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result)
{
    // look up the pending request in our list
    if (m_pendingRequests.contains(requestId)) {
        // transform the error code.
        Sailfish::Crypto::Result returnResult;
        if (result.code() == Sailfish::Secrets::Result::Succeeded) {
            returnResult.setCode(Sailfish::Crypto::Result::Succeeded);
        } else {
            returnResult.setCode(Sailfish::Crypto::Result::Failed);
            returnResult.setErrorCode(Sailfish::Crypto::Result::StorageError);
            returnResult.setStorageErrorCode(result.errorCode());
            returnResult.setErrorMessage(result.errorMessage());
        }

        // call the appropriate method to complete the request
        Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
        switch (pr.requestType) {
            case GenerateStoredKeyRequest: {
                Sailfish::Crypto::Key keyTemplate = pr.parameters.takeFirst().value<Sailfish::Crypto::Key>();
                Sailfish::Crypto::Result initialResult = pr.parameters.takeFirst().value<Sailfish::Crypto::Result>();
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
