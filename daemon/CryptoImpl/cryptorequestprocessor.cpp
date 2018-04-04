/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "CryptoImpl/cryptorequestprocessor_p.h"

#include "SecretsImpl/secrets_p.h"
#include "Secrets/result.h"
#include "Secrets/interactionparameters.h"

#include "util_p.h"
#include "logging_p.h"
#include "plugin_p.h"

#include "cryptopluginfunctionwrappers_p.h"

#include <QtCore/QDir>
#include <QtCore/QPluginLoader>
#include <QtCore/QObject>
#include <QtCore/QCoreApplication>
#include <QtCore/QFuture>
#include <QtCore/QFutureWatcher>

#include <QtConcurrent>

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

    void nullifyKeyFields(Sailfish::Crypto::Key *key, Sailfish::Crypto::Key::Components keep) {
        // This method is called for keys stored in generic secrets storage plugins.
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

using namespace Sailfish::Crypto;

Daemon::ApiImpl::RequestProcessor::RequestProcessor(
        Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *secrets,
        bool autotestMode,
        Daemon::ApiImpl::CryptoRequestQueue *parent)
    : QObject(parent), m_requestQueue(parent), m_secrets(secrets), m_autotestMode(autotestMode)
{
    m_cryptoPlugins = ::Sailfish::Secrets::Daemon::ApiImpl::PluginManager::instance()->getPlugins<CryptoPlugin>();
    qCDebug(lcSailfishCryptoDaemon) << "Using the following crypto plugins:" << m_cryptoPlugins.keys();

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
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::userInputCompleted,
            this, &Daemon::ApiImpl::RequestProcessor::secretsUserInputCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::cryptoPluginLockCodeRequestCompleted,
            this, &Daemon::ApiImpl::RequestProcessor::secretsCryptoPluginLockCodeRequestCompleted);
}

QMap<QString, CryptoPlugin*>
Daemon::ApiImpl::RequestProcessor::plugins() const
{
    return m_cryptoPlugins;
}

bool Daemon::ApiImpl::RequestProcessor::lockPlugins()
{
    bool retn = true;
    for (CryptoPlugin *p : m_cryptoPlugins) {
        if (p->supportsLocking()) {
            if (!p->lock()) {
                qCWarning(lcSailfishCryptoDaemon) << "Failed to lock crypto plugin:" << p->name();
                retn = false;
            }
        }
    }
    return retn;
}

bool Daemon::ApiImpl::RequestProcessor::unlockPlugins(
        const QByteArray &unlockCode)
{
    bool retn = true;
    for (CryptoPlugin *p : m_cryptoPlugins) {
        if (p->supportsLocking()) {
            if (!p->unlock(unlockCode)) {
                qCWarning(lcSailfishCryptoDaemon) << "Failed to unlock crypto plugin:" << p->name();
                retn = false;
            }
        }
    }
    return retn;
}

bool Daemon::ApiImpl::RequestProcessor::setLockCodePlugins(
        const QByteArray &oldCode,
        const QByteArray &newCode)
{
    bool retn = true;
    for (CryptoPlugin *p : m_cryptoPlugins) {
        if (p->supportsLocking()) {
            if (!p->setLockCode(oldCode, newCode)) {
                qCWarning(lcSailfishCryptoDaemon) << "Failed to set lock code for crypto plugin:" << p->name();
                retn = false;
            }
        }
    }
    return retn;
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
    Q_UNUSED(requestId);  // TODO: access control!
    Q_UNUSED(randomData); // asynchronous out-param.

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    QFutureWatcher<DataResult> *watcher = new QFutureWatcher<DataResult>(this);
    QFuture<DataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::generateRandomData,
                m_cryptoPlugins[cryptosystemProviderName],
                static_cast<quint64>(callerPid),
                csprngEngineName,
                numberBytes);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DataResult>::finished, [=] {
        watcher->deleteLater();
        DataResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<QByteArray>(dr.data);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
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

    QFutureWatcher<Result> *watcher = new QFutureWatcher<Result>(this);
    QFuture<Result> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::seedRandomDataGenerator,
                m_cryptoPlugins[cryptosystemProviderName],
                static_cast<quint64>(callerPid),
                csprngEngineName,
                seedData,
                entropyEstimate);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<Result>::finished, [=] {
        watcher->deleteLater();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(watcher->future().result());
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::generateInitializationVector(
        pid_t callerPid,
        quint64 requestId,
        CryptoManager::Algorithm algorithm,
        CryptoManager::BlockMode blockMode,
        int keySize,
        const QString &cryptosystemProviderName,
        QByteArray *generatedIV)
{
    // TODO: access control!
    Q_UNUSED(callerPid);
    Q_UNUSED(generatedIV); // asynchronous out-param.

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    QFutureWatcher<DataResult> *watcher = new QFutureWatcher<DataResult>(this);
    QFuture<DataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::generateInitializationVector,
                m_cryptoPlugins[cryptosystemProviderName],
                algorithm,
                blockMode,
                keySize);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DataResult>::finished, [=] {
        watcher->deleteLater();
        DataResult vr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(vr.result);
        outParams << QVariant::fromValue<QByteArray>(vr.data);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
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
    Q_UNUSED(valid); // asynchronous out-param.

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    QFutureWatcher<ValidatedResult> *watcher = new QFutureWatcher<ValidatedResult>(this);
    QFuture<ValidatedResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::validateCertificateChain,
                m_cryptoPlugins[cryptosystemProviderName],
                chain);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<ValidatedResult>::finished, [=] {
        watcher->deleteLater();
        ValidatedResult vr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(vr.result);
        outParams << QVariant::fromValue<bool>(vr.validated);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::generateKey(
        pid_t callerPid,
        quint64 requestId,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const QString &cryptosystemProviderName,
        Key *key)
{
    // TODO: access control!
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);
    Q_UNUSED(key); // asynchronous out-param.

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
    QFuture<KeyResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::generateKey,
                m_cryptoPlugins[cryptosystemProviderName],
                keyTemplate,
                kpgParams,
                skdfParams);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<KeyResult>::finished, [=] {
        watcher->deleteLater();
        KeyResult kr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(kr.result);
        outParams << QVariant::fromValue<Key>(kr.key);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::validateKeyIdentifier(pid_t callerPid, quint64 requestId, const Key &keyTemplate)
{
    Result retn(Result::Succeeded);
    if (keyTemplate.identifier().name().isEmpty()) {
        retn = Result(Result::InvalidKeyIdentifier,
                      QLatin1String("Template key identifier has empty name"));
    } else {
        QVector<Key::Identifier> identifiers;
        retn = transformSecretsResult(m_secrets->keyEntryIdentifiers(callerPid, requestId, &identifiers));
        if (identifiers.contains(keyTemplate.identifier())) {
            retn = Result(Result::DuplicateKeyIdentifier,
                          QLatin1String("Template key identifier duplicates existing key"));
        }
    }
    return retn;
}

Result
Daemon::ApiImpl::RequestProcessor::generateStoredKey(
        pid_t callerPid,
        quint64 requestId,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const InteractionParameters &uiParams,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName,
        Key *key)
{
    Q_UNUSED(key) // asynchronous outparam, returned in generateStoredKey_inStoragePlugin/_inCryptoPlugin

    Result retn = validateKeyIdentifier(callerPid, requestId, keyTemplate);
    if (retn.code() == Result::Failed) {
        return retn;
    } else if (!m_secrets->interleavedRequestsAllowed(keyTemplate.identifier().collectionName())) {
        return transformSecretsResult(m_secrets->interleavedRequestError());
    }

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    // check to see if we need a user interaction flow to get a passphrase/PIN.
    if (!skdfParams.isValid() || !uiParams.isValid()) {
        // we don't need to perform a UI request to get the input data for the KDF.
        return generateStoredKey2(
                    callerPid,
                    requestId,
                    keyTemplate,
                    kpgParams,
                    skdfParams,
                    cryptosystemProviderName,
                    storageProviderName);
    }

    // yes, we need to perform a user interaction flow to get the input key data.
    Sailfish::Secrets::InteractionParameters ikdRequest;
    ikdRequest.setSecretName(keyTemplate.identifier().name());
    ikdRequest.setCollectionName(keyTemplate.identifier().collectionName());
    ikdRequest.setOperation(Sailfish::Secrets::InteractionParameters::DeriveKey);
    ikdRequest.setAuthenticationPluginName(uiParams.authenticationPluginName());
    ikdRequest.setPromptText(uiParams.promptText());
    ikdRequest.setInputType(static_cast<Sailfish::Secrets::InteractionParameters::InputType>(uiParams.inputType()));
    ikdRequest.setEchoMode(static_cast<Sailfish::Secrets::InteractionParameters::EchoMode>(uiParams.echoMode()));
    retn = transformSecretsResult(m_secrets->userInput(
                                        callerPid,
                                        requestId,
                                        ikdRequest));
    if (retn.code() == Result::Failed) {
        return retn;
    }

    // asynchronous operation, will call back to generateStoredKey_withInputData().
    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::GenerateStoredKeyRequest,
                                 QVariantList() << QVariant::fromValue<Key>(keyTemplate)
                                                << QVariant::fromValue<KeyPairGenerationParameters>(kpgParams)
                                                << QVariant::fromValue<KeyDerivationParameters>(skdfParams)
                                                << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                << QVariant::fromValue<QString>(storageProviderName)));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::generateStoredKey2(
        pid_t callerPid,
        quint64 requestId,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName)
{
    Result retn(Result::Succeeded);
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
                                                    << QVariant::fromValue<KeyPairGenerationParameters>(kpgParams)
                                                    << QVariant::fromValue<KeyDerivationParameters>(skdfParams)
                                                    << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                    << QVariant::fromValue<QString>(storageProviderName)));
        return Result(Result::Pending);
    } else {
        // generate the key
        QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
        QFuture<KeyResult> future = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                    CryptoPluginWrapper::generateKey,
                    m_cryptoPlugins[cryptosystemProviderName],
                    keyTemplate,
                    kpgParams,
                    skdfParams);

        watcher->setFuture(future);
        connect(watcher, &QFutureWatcher<KeyResult>::finished, [=] {
            watcher->deleteLater();
            KeyResult kr = watcher->future().result();
            if (kr.result.code() == Result::Failed) {
                QVariantList outParams;
                outParams << QVariant::fromValue<Result>(kr.result);
                m_requestQueue->requestFinished(requestId, outParams);
            } else {
                Result storeKeyResult = transformSecretsResult(
                            m_secrets->storeKey(
                                callerPid,
                                requestId,
                                kr.key.identifier(),
                                Key::serialise(kr.key, Key::LossySerialisationMode),
                                kr.key.filterData(),
                                storageProviderName));
                if (storeKeyResult.code() == Result::Failed) {
                    QVariantList outParams;
                    outParams << QVariant::fromValue<Result>(storeKeyResult);
                    m_requestQueue->requestFinished(requestId, outParams);
                } else {
                    // asynchronous operation, will call back to generateStoredKey_inStoragePlugin().
                    m_pendingRequests.insert(requestId,
                                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                                 callerPid,
                                                 requestId,
                                                 Daemon::ApiImpl::GenerateStoredKeyRequest,
                                                 QVariantList() << QVariant::fromValue<Key>(kr.key)
                                                                << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                                << QVariant::fromValue<QString>(storageProviderName)));
                }
            }
        });

        return Result(Result::Pending);
    }
}

void
Daemon::ApiImpl::RequestProcessor::generateStoredKey_withInputData(
        pid_t callerPid,
        quint64 requestId,
        const Result &result,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName)
{
    // This method is invoked after the user input has been retrieved
    // from the user, but before the key has been generated or stored.
    // If the user input was retrieved successfully, continue with
    // key generation and storage.
    Result retn(result);
    if (result.code() == Result::Succeeded) {
        retn = generateStoredKey2(
                    callerPid,
                    requestId,
                    keyTemplate,
                    kpgParams,
                    skdfParams,
                    cryptosystemProviderName,
                    storageProviderName);
    }

    // finish the asynchronous request if it failed.
    if (retn.code() == Result::Failed) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(retn);
        outParams << QVariant::fromValue<Key>(keyTemplate);
        m_requestQueue->requestFinished(requestId, outParams);
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
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
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

        // finish the asynchronous request.
        Key partialKey(fullKey);
        partialKey.setPrivateKey(QByteArray());
        partialKey.setSecretKey(QByteArray());
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(retn);
        outParams << QVariant::fromValue<Key>(partialKey);
        m_requestQueue->requestFinished(requestId, outParams);
    } else {
        QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
        QFuture<KeyResult> future = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                    CryptoPluginWrapper::generateAndStoreKey,
                    m_cryptoPlugins[cryptosystemProviderName],
                    keyTemplate,
                    kpgParams,
                    skdfParams);

        watcher->setFuture(future);
        connect(watcher, &QFutureWatcher<KeyResult>::finished, [=] {
            watcher->deleteLater();
            KeyResult kr = watcher->future().result();
            if (kr.result.code() == Result::Failed) {
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
                                                                << QVariant::fromValue<Result>(kr.result)));
                    return;
                } else {
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
            outParams << QVariant::fromValue<Result>(kr.result);
            outParams << QVariant::fromValue<Key>(partialKey);
            m_requestQueue->requestFinished(requestId, outParams);
        });
    }
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

Result Daemon::ApiImpl::RequestProcessor::promptForKeyPassphrase(
        pid_t callerPid,
        quint64 requestId,
        const Key &key,
        const Sailfish::Crypto::InteractionParameters &uiParams)
{
    Sailfish::Secrets::InteractionParameters ikdRequest;
    ikdRequest.setSecretName(key.identifier().name());
    ikdRequest.setCollectionName(key.identifier().collectionName());
    ikdRequest.setOperation(Sailfish::Secrets::InteractionParameters::Decrypt);
    ikdRequest.setAuthenticationPluginName(uiParams.authenticationPluginName());
    ikdRequest.setPromptText(uiParams.promptText());
    ikdRequest.setInputType(static_cast<Sailfish::Secrets::InteractionParameters::InputType>(uiParams.inputType()));
    ikdRequest.setEchoMode(static_cast<Sailfish::Secrets::InteractionParameters::EchoMode>(uiParams.echoMode()));

    return transformSecretsResult(m_secrets->userInput(callerPid, requestId, ikdRequest));
}

Result
Daemon::ApiImpl::RequestProcessor::importKey(
        pid_t callerPid,
        quint64 requestId,
        const Key &key,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QString &cryptosystemProviderName,
        const QByteArray &passphrase,
        Key *importedKey)
{
    // TODO: access control!
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);
    Q_UNUSED(importedKey); // asynchronous out-param

    if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
    QFuture<KeyResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::importKey,
                m_cryptoPlugins.value(cryptosystemProviderName),
                key,
                passphrase);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<KeyResult>::finished, [=] {
        watcher->deleteLater();
        KeyResult kr = watcher->future().result();
        Result result = kr.result;
        Key outputKey = kr.key;
        if (result.code() == Result::Failed
                && result.errorCode() == Result::CryptoPluginIncorrectPassphrase
                && uiParams.isValid()) {
            result = promptForKeyPassphrase(callerPid, requestId, key, uiParams);
        }

        if (result.code() != Result::Failed) {
            outputKey.setOrigin(Key::OriginImported);
            if (!(key.componentConstraints() & Key::PrivateKeyData)) {
                outputKey.setPrivateKey(QByteArray());
                outputKey.setSecretKey(QByteArray());
            }
        }

        if (result.code() == Result::Pending) {
            m_pendingRequests.insert(requestId, Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Daemon::ApiImpl::ImportKeyRequest,
                                         QVariantList() << QVariant::fromValue<Key>(key)
                                                        << QVariant::fromValue<InteractionParameters>(uiParams)
                                                        << QVariant::fromValue<QString>(cryptosystemProviderName)));
        } else {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            outParams << QVariant::fromValue<Key>(outputKey);
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::importKey_withPassphrase(
        pid_t callerPid,
        quint64 requestId,
        const Result &result,
        const Key &key,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QString &cryptosystemProviderName,
        const QByteArray &passphrase)
{
    Result retn = result;
    Key importedKey(key);

    if (retn.code() == Result::Succeeded) {
        retn = importKey(callerPid, requestId, key, uiParams, cryptosystemProviderName, passphrase, &importedKey);
    }

    if (retn.code() != Result::Pending) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(retn);
        outParams << QVariant::fromValue<Key>(importedKey);
        m_requestQueue->requestFinished(requestId, outParams);
    }
}

Result
Daemon::ApiImpl::RequestProcessor::importStoredKey(
        pid_t callerPid,
        quint64 requestId,
        const Key &key,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName,
        const QByteArray &passphrase,
        Key *importedKey)
{
    Q_UNUSED(importedKey); // asynchronous out-param.

    Result retn = validateKeyIdentifier(callerPid, requestId, key);
    if (retn.code() == Result::Failed) {
        return retn;
    } else if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QStringLiteral("No such cryptographic service provider plugin exists %1").arg(cryptosystemProviderName));
    }

    if (cryptosystemProviderName == storageProviderName) {
        if (!m_cryptoPlugins.value(cryptosystemProviderName)->canStoreKeys()) {
            return Result(Result::StorageError,
                          QLatin1String("The specified cryptographic service provider cannot store keys"));
        }

        retn = transformSecretsResult(m_secrets->storeKeyMetadata(
                    callerPid, requestId, key.identifier(), storageProviderName));

        if (retn.code() == Result::Failed) {
            return retn;
        }

        m_pendingRequests.insert(requestId,Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::ImportStoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<Key>(key)
                                                    << QVariant::fromValue<InteractionParameters>(uiParams)
                                                    << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                    << QVariant::fromValue<QString>(storageProviderName)));
        return Result(Result::Pending);
    } else {
        QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
        QFuture<KeyResult> future = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                    CryptoPluginWrapper::importAndStoreKey,
                    m_cryptoPlugins.value(cryptosystemProviderName),
                    key,
                    passphrase);

        watcher->setFuture(future);
        connect(watcher, &QFutureWatcher<KeyResult>::finished, [=] {
            watcher->deleteLater();
            KeyResult kr = watcher->future().result();
            Result result = kr.result;
            Key outputKey = kr.key;
            if (result.code() == Result::Failed
                    && result.errorCode() == Result::CryptoPluginIncorrectPassphrase
                    && uiParams.isValid()) {
                m_pendingRequests.insert(requestId,Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::ImportStoredKeyRequest,
                                             QVariantList() << QVariant::fromValue<Key>(key)
                                                            << QVariant::fromValue<InteractionParameters>(uiParams)
                                                            << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                            << QVariant::fromValue<QString>(storageProviderName)));
                result = Result(Result::Pending);
            } else if (result.code() == Result::Succeeded) {
                outputKey.setOrigin(Key::OriginImported);
                if (!(key.componentConstraints() & Key::PrivateKeyData)) {
                    outputKey.setPrivateKey(QByteArray());
                    outputKey.setSecretKey(QByteArray());
                }

                result = transformSecretsResult(m_secrets->storeKey(
                                                    callerPid,
                                                    requestId,
                                                    outputKey.identifier(),
                                                    Key::serialise(outputKey, Key::LossySerialisationMode),
                                                    outputKey.filterData(),
                                                    storageProviderName));
                if (result.code() != Result::Failed) {
                    m_pendingRequests.insert(requestId,Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                                 callerPid,
                                                 requestId,
                                                 Daemon::ApiImpl::ImportStoredKeyRequest,
                                                 QVariantList() << QVariant::fromValue<Key>(*importedKey)
                                                                << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                                << QVariant::fromValue<QString>(storageProviderName)));
                }
            }

            if (result.code() != Result::Pending) {
                QVariantList outParams;
                outParams << QVariant::fromValue<Result>(result);
                outParams << QVariant::fromValue<Key>(outputKey);
                m_requestQueue->requestFinished(requestId, outParams);
            }
        });
        return Result(Result::Pending);
    }
}

bool
Daemon::ApiImpl::RequestProcessor::importStoredKey_revert(
        pid_t callerPid,
        quint64 requestId,
        const Result &result,
        const Key &key)
{
    Result cleanupResult = transformSecretsResult(m_secrets->deleteStoredKeyMetadata(callerPid, requestId, key.identifier()));
    if (cleanupResult.code() != Result::Failed) {
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::ImportStoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<Key>(key)
                                                    << QVariant::fromValue<Result>(result)));
        return true;
    } else {
        // TODO: we now have stale data in the secrets main table.
        //       Add a dirty flag for this datum, and attempt to cleanup later.
        // Also clean up the importedKey entry as it doesn't actually exist
        qCWarning(lcSailfishCryptoDaemon) << "Failed to clean up stored importedKey metadata after failed importStoredKey request:"
                                          << cleanupResult.storageErrorCode() << cleanupResult.errorMessage();
        m_secrets->removeKeyEntry(callerPid, requestId, key.identifier());

        return false;
    }
}

void
Daemon::ApiImpl::RequestProcessor::importStoredKey_withPassphrase(
        pid_t callerPid,
        quint64 requestId,
        const Result &result,
        const Key &key,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName,
        const QByteArray &passphrase)
{
    Key importedKey(key);
    Result retn = result;
    if (retn.code() == Result::Failed) {
        if (importStoredKey_revert(callerPid, requestId, result, key)) {
            return;
        }
    } else if (cryptosystemProviderName != storageProviderName) {
        retn = importStoredKey(
                    callerPid,
                    requestId,
                    key,
                    uiParams,
                    cryptosystemProviderName,
                    storageProviderName,
                    passphrase,
                    &importedKey);
    } else {
        QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
        QFuture<KeyResult> future = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                    CryptoPluginWrapper::importAndStoreKey,
                    m_cryptoPlugins.value(cryptosystemProviderName),
                    key,
                    passphrase);

        watcher->setFuture(future);
        connect(watcher, &QFutureWatcher<KeyResult>::finished, [=] {
            watcher->deleteLater();
            KeyResult kr = watcher->future().result();
            Result outputResult = kr.result;
            Key outputKey = kr.key;
            if (outputResult.code() != Result::Failed) {
                outputKey.setOrigin(Key::OriginImported);
            } else {
                if (outputResult.errorCode() == Result::CryptoPluginIncorrectPassphrase && uiParams.isValid()) {
                    outputResult = promptForKeyPassphrase(callerPid, requestId, key, uiParams);
                    if (outputResult.code() == Result::Pending) {
                        m_pendingRequests.insert(requestId, Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                                     callerPid,
                                                     requestId,
                                                     Daemon::ApiImpl::ImportStoredKeyRequest,
                                                     QVariantList() << QVariant::fromValue<Key>(key)
                                                                    << QVariant::fromValue<InteractionParameters>(uiParams)
                                                                    << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                                    << QVariant::fromValue<QString>(storageProviderName)));
                    }
                }

                if (outputResult.code() != Result::Pending) {
                    if (importStoredKey_revert(callerPid, requestId, outputResult, importedKey)) {
                        outputResult = Result(Result::Pending);
                    }
                }
            }

            if (outputResult.code() != Result::Pending) {
                QList<QVariant> outParams;
                outParams << QVariant::fromValue<Result>(outputResult);
                outParams << QVariant::fromValue<Key>(outputKey);
                m_requestQueue->requestFinished(requestId, outParams);
            }
        });

        retn = Result(Result::Pending);
    }

    if (retn.code() != Result::Pending) {
        // finish the asynchronous request.
        Key partialKey(importedKey);
        partialKey.setPrivateKey(QByteArray());
        partialKey.setSecretKey(QByteArray());
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(retn);
        outParams << QVariant::fromValue<Key>(partialKey);
        m_requestQueue->requestFinished(requestId, outParams);
    }
}

void
Daemon::ApiImpl::RequestProcessor::importStoredKey_inCryptoPlugin(
        pid_t callerPid,
        quint64 requestId,
        const Result &result,
        const Key &key,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName)
{
    // This method is invoked in the "generate and store into crypto plugin" codepath.
    if (result.code() != Result::Succeeded) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(result);
        outParams << QVariant::fromValue<Key>(key);
        m_requestQueue->requestFinished(requestId, outParams);
    } else {
        importStoredKey_withPassphrase(
                    callerPid,
                    requestId,
                    result,
                    key,
                    uiParams,
                    cryptosystemProviderName,
                    storageProviderName,
                    QByteArray());
    }
}

Result
Daemon::ApiImpl::RequestProcessor::storedKey(
        pid_t callerPid,
        quint64 requestId,
        const Key::Identifier &identifier,
        Key::Components keyComponents,
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
        QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
        QFuture<KeyResult> future = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(storagePluginName).data(),
                    CryptoPluginWrapper::storedKey,
                    m_cryptoPlugins[storagePluginName],
                    identifier,
                    keyComponents);

        watcher->setFuture(future);
        connect(watcher, &QFutureWatcher<KeyResult>::finished, [=] {
            watcher->deleteLater();
            KeyResult kr = watcher->future().result();
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(kr.result);
            outParams << QVariant::fromValue<Key>(kr.key);
            m_requestQueue->requestFinished(requestId, outParams);
        });

        return Result(Result::Pending);
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
                                                    << QVariant::fromValue<Key::Components>(keyComponents)));
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
        Key::Components keyComponents,
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
Daemon::ApiImpl::RequestProcessor::calculateDigest(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QString &cryptosystemProviderName,
        QByteArray *digest)
{
    // TODO: Access Control
    Q_UNUSED(callerPid)
    Q_UNUSED(requestId)
    Q_UNUSED(digest); // asynchronous out-param.

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    QFutureWatcher<DataResult> *watcher = new QFutureWatcher<DataResult>(this);
    QFuture<DataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::calculateDigest,
                cryptoPlugin,
                data,
                std::make_tuple(padding, digestFunction));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DataResult>::finished, [=] {
        watcher->deleteLater();
        DataResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<QByteArray>(dr.data);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::sign(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const Key &key,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QString &cryptosystemProviderName,
        QByteArray *signature)
{
    // TODO: Access Control
    Q_UNUSED(signature); // asynchronous out-param.

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & CryptoManager::OperationSign)) {
        return Result(Result::UnsupportedOperation,
                      QLatin1String("The specified cryptographic service provider does not support sign operations"));
    } else if (!(cryptoPlugin->supportedSignaturePaddings().value(key.algorithm()).contains(padding))) {
        return Result(Result::UnsupportedSignaturePadding,
                      QLatin1String("The specified cryptographic service provider does not support that signature padding"));
    } else if (!(cryptoPlugin->supportedDigests().value(key.algorithm()).contains(digestFunction))) {
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
                // asynchronous flow required, will call back to sign2().
                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::SignRequest,
                                             QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                            << QVariant::fromValue<CryptoManager::SignaturePadding>(padding)
                                                            << QVariant::fromValue<CryptoManager::DigestFunction>(digestFunction)
                                                            << QVariant::fromValue<QString>(cryptosystemProviderName)));
                return retn;
            }

            fullKey = Key::deserialise(serialisedKey);
        }
    } else {
        fullKey = key;
    }

    QFutureWatcher<DataResult> *watcher = new QFutureWatcher<DataResult>(this);
    QFuture<DataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::sign,
                cryptoPlugin,
                data,
                fullKey,
                std::make_tuple(padding, digestFunction));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DataResult>::finished, [=] {
        watcher->deleteLater();
        DataResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<QByteArray>(dr.data);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::sign2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &data,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QString &cryptoPluginName)
{
    if (result.code() != Result::Succeeded) {
        QList<QVariant> outParams;
        QByteArray signature;
        outParams << QVariant::fromValue<Result>(result);
        outParams << QVariant::fromValue<QByteArray>(signature);
        m_requestQueue->requestFinished(requestId, outParams);
        return;
    }

    QFutureWatcher<DataResult> *watcher = new QFutureWatcher<DataResult>(this);
    QFuture<DataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptoPluginName).data(),
                CryptoPluginWrapper::sign,
                m_cryptoPlugins[cryptoPluginName],
                data,
                Key::deserialise(serialisedKey),
                std::make_tuple(padding, digestFunction));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DataResult>::finished, [=] {
        watcher->deleteLater();
        DataResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<QByteArray>(dr.data);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

Result
Daemon::ApiImpl::RequestProcessor::verify(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &signature,
        const QByteArray &data,
        const Key &key,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QString &cryptosystemProviderName,
        bool *verified)
{
    // TODO: Access Control
    Q_UNUSED(verified); // asynchronous out-param.

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & CryptoManager::OperationVerify)) {
        return Result(Result::UnsupportedOperation,
                      QLatin1String("The specified cryptographic service provider does not support verify operations"));
    } else if (!(cryptoPlugin->supportedSignaturePaddings().value(key.algorithm()).contains(padding))) {
        return Result(Result::UnsupportedSignaturePadding,
                      QLatin1String("The specified cryptographic service provider does not support that signature padding"));
    } else if (!(cryptoPlugin->supportedDigests().value(key.algorithm()).contains(digestFunction))) {
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
                // asynchronous flow required, will call back to verify2().
                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::VerifyRequest,
                                             QVariantList() << QVariant::fromValue<QByteArray>(signature)
                                                            << QVariant::fromValue<QByteArray>(data)
                                                            << QVariant::fromValue<CryptoManager::SignaturePadding>(padding)
                                                            << QVariant::fromValue<CryptoManager::DigestFunction>(digestFunction)
                                                            << QVariant::fromValue<QString>(cryptosystemProviderName)));
                return retn;
            }

            fullKey = Key::deserialise(serialisedKey);
        }
    } else {
        fullKey = key;
    }

    QFutureWatcher<ValidatedResult> *watcher = new QFutureWatcher<ValidatedResult>(this);
    QFuture<ValidatedResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::verify,
                cryptoPlugin,
                signature,
                data,
                fullKey,
                std::make_tuple(padding, digestFunction));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<ValidatedResult>::finished, [=] {
        watcher->deleteLater();
        ValidatedResult vr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(vr.result);
        outParams << QVariant::fromValue<bool>(vr.validated);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::verify2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &signature,
        const QByteArray &data,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QString &cryptoPluginName)
{
    if (result.code() != Result::Succeeded) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(result);
        outParams << QVariant::fromValue<bool>(false);
        m_requestQueue->requestFinished(requestId, outParams);
        return;
    }

    QFutureWatcher<ValidatedResult> *watcher = new QFutureWatcher<ValidatedResult>(this);
    QFuture<ValidatedResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptoPluginName).data(),
                CryptoPluginWrapper::verify,
                m_cryptoPlugins[cryptoPluginName],
                signature,
                data,
                Key::deserialise(serialisedKey),
                std::make_tuple(padding, digestFunction));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<ValidatedResult>::finished, [=] {
        watcher->deleteLater();
        ValidatedResult vr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(vr.result);
        outParams << QVariant::fromValue<bool>(vr.validated);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

Result
Daemon::ApiImpl::RequestProcessor::encrypt(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QString &cryptosystemProviderName,
        QByteArray *encrypted,
        QByteArray *authenticationTag)
{
    // TODO: Access Control
    Q_UNUSED(encrypted); // asynchronous out-param.
    Q_UNUSED(authenticationTag); // asynchronous out-param

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & CryptoManager::OperationEncrypt)) {
        return Result(Result::UnsupportedOperation,
                      QLatin1String("The specified cryptographic service provider does not support encrypt operations"));
    } else if (!(cryptoPlugin->supportedBlockModes().value(key.algorithm()).contains(blockMode))) {
        return Result(Result::UnsupportedBlockMode,
                      QLatin1String("The specified cryptographic service provider does not support that block mode"));
    } else if (!(cryptoPlugin->supportedEncryptionPaddings().value(key.algorithm()).contains(padding))) {
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
                // asynchronous flow required, will call back to encrypt2().
                QVariantList args;
                args << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<QByteArray>(iv)
                               << QVariant::fromValue<CryptoManager::BlockMode>(blockMode)
                               << QVariant::fromValue<CryptoManager::EncryptionPadding>(padding)
                               << QVariant::fromValue<QByteArray>(authenticationData)
                               << QVariant::fromValue<QString>(cryptosystemProviderName);
                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::EncryptRequest,
                                             args));
                return retn;
            }

            fullKey = Key::deserialise(serialisedKey);
        }
    } else {
        fullKey = key;
    }

    QFutureWatcher<TagDataResult> *watcher = new QFutureWatcher<TagDataResult>(this);
    QFuture<TagDataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::encrypt,
                cryptoPlugin,
                std::make_tuple(data, iv),
                fullKey,
                std::make_tuple(blockMode, padding),
                authenticationData);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<TagDataResult>::finished, [=] {
        watcher->deleteLater();
        TagDataResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<QByteArray>(dr.data);
        outParams << QVariant::fromValue<QByteArray>(dr.tag);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::encrypt2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &data,
        const QByteArray &iv,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QString &cryptoPluginName)
{
    if (result.code() != Result::Succeeded) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(result);
        outParams << QVariant::fromValue<QByteArray>(QByteArray());
        outParams << QVariant::fromValue<QByteArray>(QByteArray());
        m_requestQueue->requestFinished(requestId, outParams);
        return;
    }

    bool ok = false;
    Key fullKey = Key::deserialise(serialisedKey, &ok);
    if (!ok) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(Result(Result::SerialisationError,
                                                        QLatin1String("Failed to deserialise key!")));
        outParams << QVariant::fromValue<QByteArray>(QByteArray());
        outParams << QVariant::fromValue<QByteArray>(QByteArray());
        m_requestQueue->requestFinished(requestId, outParams);
        return;
    }

    QFutureWatcher<TagDataResult> *watcher = new QFutureWatcher<TagDataResult>(this);
    QFuture<TagDataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptoPluginName).data(),
                CryptoPluginWrapper::encrypt,
                m_cryptoPlugins[cryptoPluginName],
                std::make_tuple(data, iv),
                fullKey,
                std::make_tuple(blockMode, padding),
                authenticationData);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<TagDataResult>::finished, [=] {
        watcher->deleteLater();
        TagDataResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<QByteArray>(dr.data);
        outParams << QVariant::fromValue<QByteArray>(dr.tag);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

Sailfish::Crypto::Result
Daemon::ApiImpl::RequestProcessor::decrypt(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QByteArray &authenticationTag,
        const QString &cryptosystemProviderName,
        QByteArray *decrypted,
        bool *verified)
{
    // TODO: Access Control
    Q_UNUSED(decrypted); // asynchronous out-param.
    Q_UNUSED(verified); // asynchronous out-param.

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    // TODO: FIXME: don't check these here, if the key is a keyreference it won't contain algorithm metadata!
    if (!(cryptoPlugin->supportedOperations().value(key.algorithm()) & CryptoManager::OperationDecrypt)) {
        return Result(Result::UnsupportedOperation,
                      QLatin1String("The specified cryptographic service provider does not support decrypt operations"));
    } else if (!(cryptoPlugin->supportedBlockModes().value(key.algorithm()).contains(blockMode))) {
        return Result(Result::UnsupportedBlockMode,
                      QLatin1String("The specified cryptographic service provider does not support that block mode"));
    } else if (!(cryptoPlugin->supportedEncryptionPaddings().value(key.algorithm()).contains(padding))) {
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
                // asynchronous flow required, will call back to decrypt2().
                QVariantList args;
                args << QVariant::fromValue<QByteArray>(data)
                     << QVariant::fromValue<QByteArray>(iv)
                     << QVariant::fromValue<CryptoManager::BlockMode>(blockMode)
                     << QVariant::fromValue<CryptoManager::EncryptionPadding>(padding)
                     << QVariant::fromValue<QByteArray>(authenticationData)
                     << QVariant::fromValue<QByteArray>(authenticationTag)
                     << QVariant::fromValue<QString>(cryptosystemProviderName);
                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::DecryptRequest,
                                             args));
                return retn;
            }

            fullKey = Key::deserialise(serialisedKey);
        }
    } else {
        fullKey = key;
    }

    QFutureWatcher<VerifiedDataResult> *watcher = new QFutureWatcher<VerifiedDataResult>(this);
    QFuture<VerifiedDataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::decrypt,
                cryptoPlugin,
                std::make_tuple(data, iv),
                fullKey,
                std::make_tuple(blockMode, padding),
                std::make_tuple(authenticationData, authenticationTag));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<VerifiedDataResult>::finished, [=] {
        watcher->deleteLater();
        VerifiedDataResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<QByteArray>(dr.data);
        outParams << QVariant::fromValue<bool>(dr.verified);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::decrypt2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serialisedKey,
        const QByteArray &data,
        const QByteArray &iv,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QByteArray &authenticationTag,
        const QString &cryptoPluginName)
{
    if (result.code() != Result::Succeeded) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(result);
        outParams << QVariant::fromValue<QByteArray>(QByteArray());
        outParams << QVariant::fromValue<bool>(false);
        m_requestQueue->requestFinished(requestId, outParams);
    }

    QFutureWatcher<VerifiedDataResult> *watcher = new QFutureWatcher<VerifiedDataResult>(this);
    QFuture<VerifiedDataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptoPluginName).data(),
                CryptoPluginWrapper::decrypt,
                m_cryptoPlugins[cryptoPluginName],
                std::make_tuple(data, iv),
                Key::deserialise(serialisedKey),
                std::make_tuple(blockMode, padding),
                std::make_tuple(authenticationData, authenticationTag));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<VerifiedDataResult>::finished, [=] {
        watcher->deleteLater();
        VerifiedDataResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<QByteArray>(dr.data);
        outParams << QVariant::fromValue<bool>(dr.verified);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

Result
Daemon::ApiImpl::RequestProcessor::initialiseCipherSession(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &iv,
        const Key &key,
        CryptoManager::Operation operation,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding encryptionPadding,
        CryptoManager::SignaturePadding signaturePadding,
        CryptoManager::DigestFunction digestFunction,
        const QString &cryptosystemProviderName,
        quint32 *cipherSessionToken)
{
    // TODO: Access Control
    Q_UNUSED(cipherSessionToken); // asynchronous out-param.

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
                                                            << QVariant::fromValue<CryptoManager::Operation>(operation)
                                                            << QVariant::fromValue<CryptoManager::BlockMode>(blockMode)
                                                            << QVariant::fromValue<CryptoManager::EncryptionPadding>(encryptionPadding)
                                                            << QVariant::fromValue<CryptoManager::SignaturePadding>(signaturePadding)
                                                            << QVariant::fromValue<CryptoManager::DigestFunction>(digestFunction)
                                                            << QVariant::fromValue<QString>(cryptosystemProviderName)));
                return retn;
            }

            fullKey = Key::deserialise(serialisedKey);
        }
    } else {
        fullKey = key;
    }

    QFutureWatcher<CipherSessionTokenResult> *watcher = new QFutureWatcher<CipherSessionTokenResult>(this);
    QFuture<CipherSessionTokenResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::initialiseCipherSession,
                cryptoPlugin,
                callerPid,
                iv,
                fullKey,
                std::make_tuple(
                    operation,
                    blockMode,
                    encryptionPadding,
                    signaturePadding,
                    digestFunction));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<CipherSessionTokenResult>::finished, [=] {
        watcher->deleteLater();
        CipherSessionTokenResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<quint32>(dr.cipherSessionToken);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::initialiseCipherSession2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serialisedKey,
        pid_t callerPid,
        const QByteArray &iv,
        CryptoManager::Operation operation,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding encryptionPadding,
        CryptoManager::SignaturePadding signaturePadding,
        CryptoManager::DigestFunction digestFunction,
        const QString &cryptoPluginName)
{
    if (result.code() != Result::Succeeded) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(result);
        outParams << QVariant::fromValue<quint32>(0);
        m_requestQueue->requestFinished(requestId, outParams);
        return;
    }

    QFutureWatcher<CipherSessionTokenResult> *watcher = new QFutureWatcher<CipherSessionTokenResult>(this);
    QFuture<CipherSessionTokenResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptoPluginName).data(),
                CryptoPluginWrapper::initialiseCipherSession,
                m_cryptoPlugins[cryptoPluginName],
                callerPid,
                iv,
                Key::deserialise(serialisedKey),
                std::make_tuple(
                    operation,
                    blockMode,
                    encryptionPadding,
                    signaturePadding,
                    digestFunction));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<CipherSessionTokenResult>::finished, [=] {
        watcher->deleteLater();
        CipherSessionTokenResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<quint32>(dr.cipherSessionToken);
        m_requestQueue->requestFinished(requestId, outParams);
    });
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

    QFutureWatcher<Result> *watcher = new QFutureWatcher<Result>(this);
    QFuture<Result> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::updateCipherSessionAuthentication,
                cryptoPlugin,
                callerPid,
                authenticationData,
                cipherSessionToken);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<Result>::finished, [=] {
        watcher->deleteLater();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(watcher->future().result());
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
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
    Q_UNUSED(generatedData); // asynchronous out-param.

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    QFutureWatcher<DataResult> *watcher = new QFutureWatcher<DataResult>(this);
    QFuture<DataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::updateCipherSession,
                cryptoPlugin,
                callerPid,
                data,
                cipherSessionToken);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DataResult>::finished, [=] {
        watcher->deleteLater();
        DataResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<QByteArray>(dr.data);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
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
    Q_UNUSED(generatedData); // asynchronous out-param.
    Q_UNUSED(verified);      // asynchronous out-param.

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    QFutureWatcher<VerifiedDataResult> *watcher = new QFutureWatcher<VerifiedDataResult>(this);
    QFuture<VerifiedDataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginWrapper::finaliseCipherSession,
                cryptoPlugin,
                callerPid,
                data,
                cipherSessionToken);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<VerifiedDataResult>::finished, [=] {
        watcher->deleteLater();
        VerifiedDataResult vdr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(vdr.result);
        outParams << QVariant::fromValue<QByteArray>(vdr.data);
        outParams << QVariant::fromValue<bool>(vdr.verified);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::modifyLockCode(
        pid_t callerPid,
        quint64 requestId,
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParameters)
{
    Q_UNUSED(lockCodeTargetType); // ExtensionPlugin is the only supported type currently.

    if (!m_cryptoPlugins.contains(lockCodeTarget)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QStringLiteral("Invalid crypto plugin name specified as lock code target"));
    }

    // We call to the secrets side in order to perform the user interaction flows.
    // The plugin interactions are implemented also on secrets side for simplicity.
    Sailfish::Secrets::InteractionParameters uiParams;
    uiParams.setPluginName(lockCodeTarget);
    uiParams.setOperation(Sailfish::Secrets::InteractionParameters::ModifyLockPlugin);
    uiParams.setAuthenticationPluginName(interactionParameters.authenticationPluginName());
    uiParams.setPromptText(interactionParameters.promptText());
    uiParams.setInputType(static_cast<Sailfish::Secrets::InteractionParameters::InputType>(interactionParameters.inputType()));
    uiParams.setEchoMode(static_cast<Sailfish::Secrets::InteractionParameters::EchoMode>(interactionParameters.echoMode()));
    Result retn = transformSecretsResult(m_secrets->modifyCryptoPluginLockCode(callerPid, requestId, lockCodeTarget, uiParams));
    if (retn.code() == Result::Pending) {
        // asynchronous flow required, will call back to secretsCryptoPluginLockCodeRequestCompleted().
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::ModifyLockCodeRequest,
                                     QVariantList() << QVariant::fromValue<pid_t>(callerPid)
                                                    << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
                                                    << QVariant::fromValue<QString>(lockCodeTarget)
                                                    << QVariant::fromValue<InteractionParameters>(interactionParameters)));
    }

    return retn;
}

Result
Daemon::ApiImpl::RequestProcessor::provideLockCode(
        pid_t callerPid,
        quint64 requestId,
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const Sailfish::Crypto::InteractionParameters &interactionParameters)
{
    Q_UNUSED(lockCodeTargetType); // ExtensionPlugin is the only supported type currently.

    if (!m_cryptoPlugins.contains(lockCodeTarget)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QStringLiteral("Invalid crypto plugin name specified as lock code target"));
    }

    // We call to the secrets side in order to perform the user interaction flows.
    // The plugin interactions are implemented also on secrets side for simplicity.
    Sailfish::Secrets::InteractionParameters uiParams;
    uiParams.setPluginName(lockCodeTarget);
    uiParams.setOperation(Sailfish::Secrets::InteractionParameters::UnlockPlugin);
    uiParams.setAuthenticationPluginName(interactionParameters.authenticationPluginName());
    uiParams.setPromptText(interactionParameters.promptText());
    uiParams.setInputType(static_cast<Sailfish::Secrets::InteractionParameters::InputType>(interactionParameters.inputType()));
    uiParams.setEchoMode(static_cast<Sailfish::Secrets::InteractionParameters::EchoMode>(interactionParameters.echoMode()));
    Result retn = transformSecretsResult(m_secrets->provideCryptoPluginLockCode(callerPid, requestId, lockCodeTarget, uiParams));
    if (retn.code() == Result::Pending) {
        // asynchronous flow required, will call back to secretsCryptoPluginLockCodeRequestCompleted().
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::ProvideLockCodeRequest,
                                     QVariantList() << QVariant::fromValue<pid_t>(callerPid)
                                                    << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
                                                    << QVariant::fromValue<QString>(lockCodeTarget)
                                                    << QVariant::fromValue<InteractionParameters>(interactionParameters)));
    }

    return retn;
}

Result
Daemon::ApiImpl::RequestProcessor::forgetLockCode(
        pid_t callerPid,
        quint64 requestId,
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const Sailfish::Crypto::InteractionParameters &interactionParameters)
{
    Q_UNUSED(lockCodeTargetType); // ExtensionPlugin is the only supported type currently.

    if (!m_cryptoPlugins.contains(lockCodeTarget)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QStringLiteral("Invalid crypto plugin name specified as lock code target"));
    }

    // We call to the secrets side in order to perform the user interaction flows.
    // The plugin interactions are implemented also on secrets side for simplicity.
    Sailfish::Secrets::InteractionParameters uiParams;
    uiParams.setPluginName(lockCodeTarget);
    uiParams.setOperation(Sailfish::Secrets::InteractionParameters::LockPlugin);
    uiParams.setAuthenticationPluginName(interactionParameters.authenticationPluginName());
    uiParams.setPromptText(interactionParameters.promptText());
    uiParams.setInputType(static_cast<Sailfish::Secrets::InteractionParameters::InputType>(interactionParameters.inputType()));
    uiParams.setEchoMode(static_cast<Sailfish::Secrets::InteractionParameters::EchoMode>(interactionParameters.echoMode()));
    Result retn = transformSecretsResult(m_secrets->forgetCryptoPluginLockCode(callerPid, requestId, lockCodeTarget, uiParams));
    if (retn.code() == Result::Pending) {
        // asynchronous flow required, will call back to secretsCryptoPluginLockCodeRequestCompleted().
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::ForgetLockCodeRequest,
                                     QVariantList() << QVariant::fromValue<pid_t>(callerPid)
                                                    << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
                                                    << QVariant::fromValue<QString>(lockCodeTarget)
                                                    << QVariant::fromValue<InteractionParameters>(interactionParameters)));
    }

    return retn;
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
                Key::Components keyComponents = pr.parameters.takeFirst().value<Key::Components>();
                storedKey2(requestId, keyComponents, returnResult, serialisedKey, filterData);
                break;
            }
            case SignRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                CryptoManager::SignaturePadding padding = pr.parameters.takeFirst().value<CryptoManager::SignaturePadding>();
                CryptoManager::DigestFunction digestFunction = pr.parameters.takeFirst().value<CryptoManager::DigestFunction>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                sign2(requestId, returnResult, serialisedKey, data, padding, digestFunction, cryptoPluginName);
                break;
            }
            case VerifyRequest: {
                QByteArray signature = pr.parameters.takeFirst().value<QByteArray>();
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                CryptoManager::SignaturePadding padding = pr.parameters.takeFirst().value<CryptoManager::SignaturePadding>();
                CryptoManager::DigestFunction digestFunction = pr.parameters.takeFirst().value<CryptoManager::DigestFunction>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                verify2(requestId, returnResult, serialisedKey, signature, data, padding, digestFunction, cryptoPluginName);
                break;
            }
            case EncryptRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                QByteArray iv = pr.parameters.takeFirst().value<QByteArray>();
                CryptoManager::BlockMode blockMode = pr.parameters.takeFirst().value<CryptoManager::BlockMode>();
                CryptoManager::EncryptionPadding padding = pr.parameters.takeFirst().value<CryptoManager::EncryptionPadding>();
                QByteArray authenticationData = pr.parameters.takeFirst().value<QByteArray>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                encrypt2(requestId, returnResult, serialisedKey, data, iv, blockMode, padding, authenticationData, cryptoPluginName);
                break;
            }
            case DecryptRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                QByteArray iv = pr.parameters.takeFirst().value<QByteArray>();
                CryptoManager::BlockMode blockMode = pr.parameters.takeFirst().value<CryptoManager::BlockMode>();
                CryptoManager::EncryptionPadding padding = pr.parameters.takeFirst().value<CryptoManager::EncryptionPadding>();
                QByteArray authenticationData = pr.parameters.takeFirst().value<QByteArray>();
                QByteArray authenticationTag = pr.parameters.takeFirst().value<QByteArray>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                decrypt2(requestId, returnResult, serialisedKey, data, iv, blockMode, padding, authenticationData, authenticationTag, cryptoPluginName);
                break;
            }
            case InitialiseCipherSessionRequest: {
                pid_t callerPid = pr.parameters.takeFirst().value<pid_t>();
                QByteArray iv = pr.parameters.takeFirst().value<QByteArray>();
                CryptoManager::Operation operation = pr.parameters.takeFirst().value<CryptoManager::Operation>();
                CryptoManager::BlockMode blockMode = pr.parameters.takeFirst().value<CryptoManager::BlockMode>();
                CryptoManager::EncryptionPadding encryptionPadding = pr.parameters.takeFirst().value<CryptoManager::EncryptionPadding>();
                CryptoManager::SignaturePadding signaturePadding = pr.parameters.takeFirst().value<CryptoManager::SignaturePadding>();
                CryptoManager::DigestFunction digestFunction = pr.parameters.takeFirst().value<CryptoManager::DigestFunction>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                initialiseCipherSession2(requestId, returnResult, serialisedKey,
                                         callerPid, iv, operation, blockMode, encryptionPadding,
                                         signaturePadding, digestFunction, cryptoPluginName);
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
            case GenerateStoredKeyRequest:
            case ImportStoredKeyRequest: {
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
                KeyPairGenerationParameters kpgParams = pr.parameters.takeFirst().value<KeyPairGenerationParameters>();
                KeyDerivationParameters skdfParams = pr.parameters.takeFirst().value<KeyDerivationParameters>();
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                QString storagePluginName = pr.parameters.takeFirst().value<QString>();
                generateStoredKey_inCryptoPlugin(pr.callerPid, requestId, returnResult, keyTemplate, kpgParams, skdfParams, cryptosystemProviderName, storagePluginName);
                break;
            }
            case ImportStoredKeyRequest: {
                Key key = pr.parameters.takeFirst().value<Key>();
                InteractionParameters uiParams = pr.parameters.takeFirst().value<InteractionParameters>();
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                QString storagePluginName = pr.parameters.takeFirst().value<QString>();
                importStoredKey_inCryptoPlugin(pr.callerPid, requestId, returnResult, key, uiParams, cryptosystemProviderName, storagePluginName);
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
            case GenerateStoredKeyRequest:
            case ImportStoredKeyRequest: {
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
            case GenerateStoredKeyRequest:
            case ImportStoredKeyRequest: {
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

// asynchronous operation (retrieve user input as KDF input data) has completed
void Daemon::ApiImpl::RequestProcessor::secretsUserInputCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result,
        const QByteArray &userInput)
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
                KeyPairGenerationParameters kpgParams = pr.parameters.takeFirst().value<KeyPairGenerationParameters>();
                KeyDerivationParameters skdfParams = pr.parameters.takeFirst().value<KeyDerivationParameters>();
                skdfParams.setInputData(userInput);
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                QString storagePluginName = pr.parameters.takeFirst().value<QString>();
                generateStoredKey_withInputData(pr.callerPid, requestId, returnResult, keyTemplate, kpgParams, skdfParams, cryptosystemProviderName, storagePluginName);
                break;
            }
            case ImportKeyRequest: {
                Key key = pr.parameters.takeFirst().value<Key>();
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                InteractionParameters uiParams = pr.parameters.takeFirst().value<InteractionParameters>();
                importKey_withPassphrase(pr.callerPid, requestId, returnResult, key, uiParams, cryptosystemProviderName, userInput);
                break;
            }
            case ImportStoredKeyRequest: {
                Key key = pr.parameters.takeFirst().value<Key>();
                InteractionParameters uiParams = pr.parameters.takeFirst().value<InteractionParameters>();
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                QString storagePluginName = pr.parameters.takeFirst().value<QString>();
                importStoredKey_withPassphrase(
                            pr.callerPid,
                            requestId,
                            returnResult,
                            key,
                            uiParams,
                            cryptosystemProviderName,
                            storagePluginName,
                            userInput);
                break;
            }
            default: {
                qCWarning(lcSailfishCryptoDaemon) << "Secrets completed userInput() operation for request:" << requestId << "of invalid type:" << pr.requestType;
                break;
            }
        }
    } else {
        qCWarning(lcSailfishCryptoDaemon) << "Secrets completed userInput() operation for unknown request:" << requestId;
    }
}

// asynchronous operation (crypto plugin lock code request) has completed.
void Daemon::ApiImpl::RequestProcessor::secretsCryptoPluginLockCodeRequestCompleted(
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
            case ModifyLockCodeRequest:   // flow on
            case ProvideLockCodeRequest:  // flow on
            case ForgetLockCodeRequest: {
                // nothing more to do, return the result directly.
                QList<QVariant> outParams;
                outParams << QVariant::fromValue<Result>(returnResult);
                m_requestQueue->requestFinished(requestId, outParams);
                break;
            }
            default: {
                qCWarning(lcSailfishCryptoDaemon) << "Secrets completed crypto plugin lock code operation for request:" << requestId << "of invalid type:" << pr.requestType;
                break;
            }
        }
    } else {
        qCWarning(lcSailfishCryptoDaemon) << "Secrets completed crypto plugin lock code operation for unknown request:" << requestId;
    }
}
