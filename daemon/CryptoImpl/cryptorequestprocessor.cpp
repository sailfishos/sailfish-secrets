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
#include "Secrets/plugininfo.h"

#include "Crypto/plugininfo.h"

#include "util_p.h"
#include "logging_p.h"
#include "plugin_p.h"

#include "cryptopluginfunctionwrappers_p.h"
#include "cryptopluginwrapper_p.h"

#include <QtCore/QDir>
#include <QtCore/QPluginLoader>
#include <QtCore/QObject>
#include <QtCore/QCoreApplication>
#include <QtCore/QFuture>
#include <QtCore/QFutureWatcher>

#include <QtConcurrent>

namespace {
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
using namespace Sailfish::Secrets::Daemon::Util;

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
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storeKeyPreCheckCompleted,
            this, &Daemon::ApiImpl::RequestProcessor::secretsStoreKeyPreCheckCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storeKeyCompleted,
            this, &Daemon::ApiImpl::RequestProcessor::secretsStoreKeyCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::deleteStoredKeyCompleted,
            this, &Daemon::ApiImpl::RequestProcessor::secretsDeleteStoredKeyCompleted);
    connect(m_secrets, &Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storedKeyIdentifiersCompleted,
            this, &Daemon::ApiImpl::RequestProcessor::secretsStoredKeyIdentifiersCompleted);
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

bool Daemon::ApiImpl::RequestProcessor::lockPlugin(
        const QString &pluginName)
{
    if (m_cryptoPlugins.contains(pluginName)) {
        return false;
    }

    QFuture<bool> future
            = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(pluginName).data(),
                    CryptoPluginFunctionWrapper::lock,
                    m_cryptoPlugins[pluginName]);
    future.waitForFinished();
    return future.result();
}

bool Daemon::ApiImpl::RequestProcessor::unlockPlugin(
        const QString &pluginName,
        const QByteArray &lockCode)
{
    if (m_cryptoPlugins.contains(pluginName)) {
        return false;
    }

    QFuture<bool> future
            = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(pluginName).data(),
                    CryptoPluginFunctionWrapper::unlock,
                    m_cryptoPlugins[pluginName],
                    lockCode);
    future.waitForFinished();
    return future.result();
}

bool Daemon::ApiImpl::RequestProcessor::setLockCodePlugin(
        const QString &pluginName,
        const QByteArray &oldCode,
        const QByteArray &newCode)
{
    if (m_cryptoPlugins.contains(pluginName)) {
        return false;
    }

    QFuture<bool> future
            = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(pluginName).data(),
                    CryptoPluginFunctionWrapper::setLockCode,
                    m_cryptoPlugins[pluginName],
                    oldCode,
                    newCode);
    future.waitForFinished();
    return future.result();
}

Result
Daemon::ApiImpl::RequestProcessor::getPluginInfo(
        pid_t callerPid,
        quint64 requestId,
        QVector<PluginInfo> *cryptoPlugins,
        QVector<PluginInfo> *storagePlugins)
{
    QVector<Sailfish::Secrets::PluginInfo> storagePluginInfos;
    Result retn(transformSecretsResult(m_secrets->storagePluginInfo(callerPid, requestId, &storagePluginInfos)));
    if (retn.code() == Result::Failed) {
        return retn;
    }

    for (const Sailfish::Secrets::PluginInfo &plugin : storagePluginInfos) {
        storagePlugins->append(PluginInfo(plugin.displayName(),
                                          plugin.name(),
                                          plugin.version(),
                                          static_cast<PluginInfo::StatusFlags>(
                                              static_cast<int>(plugin.statusFlags()))));
    }

    QList<Sailfish::Secrets::PluginBase*> cplugins;
    for (CryptoPlugin *plugin : m_cryptoPlugins.values()) {
        cplugins.append(plugin);
    }
    const QMap<QString, Sailfish::Secrets::PluginInfo> cryptoPluginInfos
            = m_requestQueue->controller()->pluginInfoForPlugins(cplugins, m_secrets->masterLocked());
    for (const Sailfish::Secrets::PluginInfo &plugin : cryptoPluginInfos) {
        cryptoPlugins->append(PluginInfo(plugin.displayName(),
                                         plugin.name(),
                                         plugin.version(),
                                         static_cast<PluginInfo::StatusFlags>(
                                             static_cast<int>(plugin.statusFlags()))));
    }

    return retn;
}

Result
Daemon::ApiImpl::RequestProcessor::generateRandomData(
        pid_t callerPid,
        quint64 requestId,
        quint64 numberBytes,
        const QString &csprngEngineName,
        const QVariantMap &customParameters,
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
                CryptoPluginFunctionWrapper::generateRandomData,
                PluginAndCustomParams(m_cryptoPlugins[cryptosystemProviderName], customParameters),
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
        const QVariantMap &customParameters,
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
                CryptoPluginFunctionWrapper::seedRandomDataGenerator,
                PluginAndCustomParams(m_cryptoPlugins[cryptosystemProviderName], customParameters),
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
        const QVariantMap &customParameters,
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
                CryptoPluginFunctionWrapper::generateInitializationVector,
                PluginAndCustomParams(m_cryptoPlugins[cryptosystemProviderName], customParameters),
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
Daemon::ApiImpl::RequestProcessor::generateKey(
        pid_t callerPid,
        quint64 requestId,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
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

    // Note: we don't need to potentially perform any user input request
    // to get the input key data here (in contrast with generateStoredKeyRequest)
    // because this method assumes that the secret data can be / will be returned
    // to the application anyway (so the application can request the input key data
    // from the user itself).
    // Thus, the key pair generation parameters or key derivation parameters
    // will be fully specified with input key data.

    QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
    QFuture<KeyResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginFunctionWrapper::generateKey,
                PluginAndCustomParams(m_cryptoPlugins[cryptosystemProviderName], customParameters),
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
Daemon::ApiImpl::RequestProcessor::generateStoredKey(
        pid_t callerPid,
        quint64 requestId,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const InteractionParameters &uiParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        Key *key)
{
    Q_UNUSED(key) // asynchronous outparam, returned in generateStoredKey_inStoragePlugin/_inCryptoPlugin

    if (keyTemplate.identifier().name().isEmpty()) {
        return Result(Result::InvalidKeyIdentifier,
                      QLatin1String("Template key identifier has empty name"));
    } else if (keyTemplate.identifier().collectionName().isEmpty()) {
        return Result(Result::InvalidKeyIdentifier,
                      QLatin1String("Template key identifier has empty collection name"));
    } else if (keyTemplate.identifier().collectionName() == QStringLiteral("standalone")) {
        return Result(Result::InvalidKeyIdentifier,
                      QLatin1String("Template key identifier has invalid collection name"));
    } else if (cryptosystemProviderName.isEmpty()) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("Empty cryptographic service provider plugin name given"));
    } else if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    } else if (keyTemplate.identifier().storagePluginName().isEmpty()) {
        return Result(Result::InvalidStorageProvider,
                      QLatin1String("Empty storage plugin name specified in key template identifier"));
    } else if (!m_secrets->encryptedStoragePluginNames().contains(keyTemplate.identifier().storagePluginName())
               && !m_secrets->storagePluginNames().contains(keyTemplate.identifier().storagePluginName())) {
        return Result(Result::InvalidStorageProvider,
                      QLatin1String("Unknown storage plugin name specified in key template identifier"));
    } else if (cryptosystemProviderName == keyTemplate.identifier().storagePluginName()
               && !m_cryptoPlugins[cryptosystemProviderName]->canStoreKeys()) {
        return Result(Result::StorageError,
                      QLatin1String("The specified cryptographic service provider cannot store keys"));
    }

    // check for collection existence and duplicate secrets
    Result preStoreKeyCheckResult = transformSecretsResult(
                m_secrets->storeKeyPreCheck(
                    callerPid,
                    requestId,
                    keyTemplate.identifier()));
    if (preStoreKeyCheckResult.code() == Result::Failed) {
        return preStoreKeyCheckResult;
    } else {
        // asynchronous operation, will call back to generateStoredKey_afterPreCheck().
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::GenerateStoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<Key>(keyTemplate)
                                                    << QVariant::fromValue<KeyPairGenerationParameters>(kpgParams)
                                                    << QVariant::fromValue<KeyDerivationParameters>(skdfParams)
                                                    << QVariant::fromValue<InteractionParameters>(uiParams)
                                                    << QVariant::fromValue<QVariantMap>(customParameters)
                                                    << QVariant::fromValue<QString>(cryptosystemProviderName)));
    }
    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::generateStoredKey_afterPreCheck(
        pid_t callerPid,
        quint64 requestId,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const InteractionParameters &uiParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const Result &preCheckResult,
        const QByteArray &collectionDecryptionKey)
{
    Result result(preCheckResult);
    if (result.code() == Result::Succeeded) {
        // check to see if we need a user interaction flow to get a passphrase/PIN.
        if (!skdfParams.isValid() || !uiParams.isValid()) {
            // we don't need to perform a UI request to get the input data for the KDF.
            result = generateStoredKey_withKdfData(
                        callerPid,
                        requestId,
                        keyTemplate,
                        kpgParams,
                        skdfParams,
                        customParameters,
                        cryptosystemProviderName,
                        collectionDecryptionKey);
            if (result.code() != Result::Pending) {
                QList<QVariant> outParams;
                outParams << QVariant::fromValue<Result>(result);
                outParams << QVariant::fromValue<Key>(keyTemplate);
                m_requestQueue->requestFinished(requestId, outParams);
                return;
            }
        } else {
            // yes, we need to perform a user interaction flow to get the input key data.
            Sailfish::Secrets::InteractionParameters promptParams;
            promptParams.setSecretName(keyTemplate.identifier().name());
            promptParams.setCollectionName(keyTemplate.identifier().collectionName());
            promptParams.setPluginName(keyTemplate.identifier().storagePluginName());
            promptParams.setOperation(Sailfish::Secrets::InteractionParameters::DeriveKey);
            promptParams.setAuthenticationPluginName(uiParams.authenticationPluginName());
            //: This will be displayed to the user, prompting them to enter a passphrase from which a key will be derived. %1 is the key name, %2 is the collection name, %3 is the plugin name.
            //% "An application wants to store a new key named %1 within collection %2 in plugin %3. Enter a passphrase from which the key will be derived."
            promptParams.setPromptText(qtTrId("sailfish_crypto-generate_stored_key-la-enter_key_passphrase")
                                       .arg(keyTemplate.identifier().name(),
                                            keyTemplate.identifier().collectionName(),
                                            m_requestQueue->controller()->displayNameForPlugin(keyTemplate.identifier().storagePluginName())));
            promptParams.setInputType(static_cast<Sailfish::Secrets::InteractionParameters::InputType>(uiParams.inputType()));
            promptParams.setEchoMode(static_cast<Sailfish::Secrets::InteractionParameters::EchoMode>(uiParams.echoMode()));
            result = transformSecretsResult(m_secrets->userInput(
                                                callerPid,
                                                requestId,
                                                promptParams));
            if (result.code() == Result::Pending) {
                // asynchronous operation, will call back to generateStoredKey_withInputData().
                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::GenerateStoredKeyRequest,
                                             QVariantList() << QVariant::fromValue<Key>(keyTemplate)
                                                            << QVariant::fromValue<KeyPairGenerationParameters>(kpgParams)
                                                            << QVariant::fromValue<KeyDerivationParameters>(skdfParams)
                                                            << QVariant::fromValue<QVariantMap>(customParameters)
                                                            << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                            << QVariant::fromValue<QByteArray>(collectionDecryptionKey)));
            }
        }
    }

    if (result.code() != Result::Pending) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(result);
        outParams << QVariant::fromValue<Key>(keyTemplate);
        m_requestQueue->requestFinished(requestId, outParams);
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
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QByteArray &collectionDecryptionKey)
{
    // This method is invoked after the user input has been retrieved
    // from the user, but before the key has been generated or stored.
    // If the user input was retrieved successfully, continue with
    // key generation and storage.
    Result retn(result);
    if (result.code() == Result::Succeeded) {
        retn = generateStoredKey_withKdfData(
                    callerPid,
                    requestId,
                    keyTemplate,
                    kpgParams,
                    skdfParams,
                    customParameters,
                    cryptosystemProviderName,
                    collectionDecryptionKey);
    }

    // finish the asynchronous request if it failed.
    if (retn.code() != Result::Pending) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(retn);
        outParams << QVariant::fromValue<Key>(keyTemplate);
        m_requestQueue->requestFinished(requestId, outParams);
    }
}

Result
Daemon::ApiImpl::RequestProcessor::generateStoredKey_withKdfData(
        pid_t callerPid,
        quint64 requestId,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QByteArray &collectionDecryptionKey)
{
    if (keyTemplate.identifier().storagePluginName() == cryptosystemProviderName) {
        // generate and store directly into the crypto-storage plugin.
        generateStoredKey_inCryptoPlugin(callerPid,
                                         requestId,
                                         keyTemplate,
                                         kpgParams,
                                         skdfParams,
                                         customParameters,
                                         cryptosystemProviderName,
                                         collectionDecryptionKey);
    } else {
        // generate the key, then store it separately in the storage plugin
        QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
        QFuture<KeyResult> future = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                    CryptoPluginFunctionWrapper::generateKey,
                    PluginAndCustomParams(m_cryptoPlugins[cryptosystemProviderName], customParameters),
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
                                Key::serialize(kr.key, Key::LossySerializationMode),
                                kr.key.filterData(),
                                collectionDecryptionKey));
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
                                                 QVariantList() << QVariant::fromValue<Key>(kr.key)));
                }
            }
        });
    }

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::generateStoredKey_inStoragePlugin(
        pid_t callerPid,
        quint64 requestId,
        const Result &result,
        const Key &fullKey)
{
    Q_UNUSED(callerPid);
    // This method is invoked in the "generate from crypto plugin, store in secrets storage plugin" codepath.
    // finish the asynchronous request.
    Key partialKey(fullKey);
    partialKey.setPrivateKey(QByteArray());
    partialKey.setSecretKey(QByteArray());
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Result>(result);
    outParams << QVariant::fromValue<Key>(partialKey);
    m_requestQueue->requestFinished(requestId, outParams);
}

void
Daemon::ApiImpl::RequestProcessor::generateStoredKey_inCryptoPlugin(
        pid_t callerPid,
        quint64 requestId,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QByteArray &collectionDecryptionKey)
{
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);

    QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
    QFuture<KeyResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginFunctionWrapper::generateAndStoreKey,
                PluginWrapperAndCustomParams(m_secrets->cryptoStoragePluginWrapper(cryptosystemProviderName), customParameters),
                keyTemplate,
                kpgParams,
                skdfParams,
                collectionDecryptionKey);

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<KeyResult>::finished, [=] {
        watcher->deleteLater();
        KeyResult kr = watcher->future().result();
        Key partialKey(kr.key);
        partialKey.setPrivateKey(QByteArray());
        partialKey.setSecretKey(QByteArray());
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(kr.result);
        outParams << QVariant::fromValue<Key>(partialKey);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

Result Daemon::ApiImpl::RequestProcessor::promptForKeyPassphrase(
        pid_t callerPid,
        quint64 requestId,
        const Key &key,
        const Sailfish::Crypto::InteractionParameters &uiParams)
{
    Sailfish::Secrets::InteractionParameters promptParams;
    if (key.identifier().isValid()) {
        promptParams.setSecretName(key.identifier().name());
        promptParams.setCollectionName(key.identifier().collectionName());
        promptParams.setOperation(Sailfish::Secrets::InteractionParameters::ImportKey);
        promptParams.setAuthenticationPluginName(uiParams.authenticationPluginName());
        //: This will be displayed to the user, prompting them to enter a passphrase to import a stored key. %1 is the key name, %2 is the collection name, %3 is the plugin name.
        //% "A passphrase is required in order to import the key %1 into collection %2 in plugin %2. Enter the key import passphrase."
        promptParams.setPromptText(qtTrId("sailfish_crypto-import_key-la-enter_import_passphrase")
                                   .arg(key.identifier().name(),
                                        key.identifier().collectionName(),
                                        m_requestQueue->controller()->displayNameForPlugin(key.identifier().storagePluginName())));
        promptParams.setInputType(static_cast<Sailfish::Secrets::InteractionParameters::InputType>(uiParams.inputType()));
        promptParams.setEchoMode(static_cast<Sailfish::Secrets::InteractionParameters::EchoMode>(uiParams.echoMode()));
    } else {
        promptParams.setAuthenticationPluginName(uiParams.authenticationPluginName());
        promptParams.setOperation(Sailfish::Secrets::InteractionParameters::ImportKey);
        //: This will be displayed to the user, prompting them to enter a passphrase to import a key which will then be returned to the application.  %1 is the plugin name.
        //% "A passphrase is required in order to import a key with plugin %1 which will then be returned to the application"
        promptParams.setPromptText(qtTrId("sailfish_crypto-import_key-la-enter_application_import_passphrase")
                                   .arg(m_requestQueue->controller()->displayNameForPlugin(key.identifier().storagePluginName())));
        promptParams.setInputType(static_cast<Sailfish::Secrets::InteractionParameters::InputType>(uiParams.inputType()));
        promptParams.setEchoMode(static_cast<Sailfish::Secrets::InteractionParameters::EchoMode>(uiParams.echoMode()));
    }

    return transformSecretsResult(m_secrets->userInput(callerPid, requestId, promptParams));
}

Result
Daemon::ApiImpl::RequestProcessor::importKey(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QVariantMap &customParameters,
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
                CryptoPluginFunctionWrapper::importKey,
                PluginAndCustomParams(m_cryptoPlugins.value(cryptosystemProviderName),
                                      customParameters),
                data,
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
            result = promptForKeyPassphrase(callerPid, requestId, Key(), uiParams);
        }

        if (result.code() != Result::Failed) {
            outputKey.setOrigin(Key::OriginImported);
        }

        if (result.code() == Result::Pending) {
            m_pendingRequests.insert(requestId, Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Daemon::ApiImpl::ImportKeyRequest,
                                         QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                        << QVariant::fromValue<InteractionParameters>(uiParams)
                                                        << QVariant::fromValue<QVariantMap>(customParameters)
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
        const QByteArray &data,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const Result &result,
        const QByteArray &passphrase)
{
    Result retn = result;
    Key importedKey;

    if (retn.code() == Result::Succeeded) {
        retn = importKey(callerPid, requestId, data, uiParams,customParameters, cryptosystemProviderName, passphrase, &importedKey);
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
        const QByteArray &data,
        const Key &keyTemplate,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        Key *importedKey)
{
    Q_UNUSED(importedKey); // asynchronous out-param.

    if (keyTemplate.identifier().name().isEmpty()) {
        return Result(Result::InvalidKeyIdentifier,
                      QLatin1String("Template key identifier has empty name"));
    } else if (keyTemplate.identifier().collectionName().isEmpty()) {
        return Result(Result::InvalidKeyIdentifier,
                      QLatin1String("Template key identifier has empty collection name"));
    } else if (keyTemplate.identifier().collectionName() == QStringLiteral("standalone")) {
        return Result(Result::InvalidKeyIdentifier,
                      QLatin1String("Template key identifier has invalid collection name"));
    } else if (cryptosystemProviderName.isEmpty()) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("Empty cryptographic service provider plugin name given"));
    } else if (!m_cryptoPlugins.contains(cryptosystemProviderName)) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    } else if (keyTemplate.identifier().storagePluginName().isEmpty()) {
        return Result(Result::InvalidStorageProvider,
                      QLatin1String("Empty storage plugin name specified in key template identifier"));
    } else if (!m_secrets->encryptedStoragePluginNames().contains(keyTemplate.identifier().storagePluginName())
               && !m_secrets->storagePluginNames().contains(keyTemplate.identifier().storagePluginName())) {
        return Result(Result::InvalidStorageProvider,
                      QLatin1String("Unknown storage plugin name specified in key template identifier"));
    } else if (cryptosystemProviderName == keyTemplate.identifier().storagePluginName()
               && !m_cryptoPlugins[cryptosystemProviderName]->canStoreKeys()) {
        return Result(Result::StorageError,
                      QLatin1String("The specified cryptographic service provider cannot store keys"));
    }

    // check for collection existence and duplicate secrets
    Result preStoreKeyCheckResult = transformSecretsResult(
                m_secrets->storeKeyPreCheck(
                    callerPid,
                    requestId,
                    keyTemplate.identifier()));
    if (preStoreKeyCheckResult.code() == Result::Failed) {
        return preStoreKeyCheckResult;
    } else {
        // asynchronous operation, will call back to importStoredKey_afterPreCheck().
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::ImportStoredKeyRequest,
                                     QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                    << QVariant::fromValue<Key>(keyTemplate)
                                                    << QVariant::fromValue<InteractionParameters>(uiParams)
                                                    << QVariant::fromValue<QVariantMap>(customParameters)
                                                    << QVariant::fromValue<QString>(cryptosystemProviderName)));
    }
    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::importStoredKey_afterPreCheck(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const Key &keyTemplate,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const Result &preCheckResult,
        const QByteArray &collectionDecryptionKey)
{
    if (preCheckResult.code() != Result::Succeeded) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(preCheckResult);
        outParams << QVariant::fromValue<Key>(keyTemplate);
        m_requestQueue->requestFinished(requestId, outParams);
        return;
    }

    // now try to import using a null passphrase.
    importStoredKey_withPassphrase(
                callerPid,
                requestId,
                data,
                keyTemplate,
                uiParams,
                customParameters,
                cryptosystemProviderName,
                collectionDecryptionKey,
                Result(Result::Succeeded),
                QByteArray());
}

void
Daemon::ApiImpl::RequestProcessor::importStoredKey_withPassphrase(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const Key &keyTemplate,
        const Sailfish::Crypto::InteractionParameters &uiParams,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        const QByteArray &collectionDecryptionKey,
        const Result &passphraseResult,
        const QByteArray &passphrase)
{
    if (passphraseResult.code() != Result::Succeeded) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(passphraseResult);
        outParams << QVariant::fromValue<Key>(keyTemplate);
        m_requestQueue->requestFinished(requestId, outParams);
        return;
    }

    if (cryptosystemProviderName == keyTemplate.identifier().storagePluginName()) {
        QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
        QFuture<KeyResult> future = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                    CryptoPluginFunctionWrapper::importAndStoreKey,
                    PluginWrapperAndCustomParams(m_secrets->cryptoStoragePluginWrapper(cryptosystemProviderName),
                                                 customParameters),
                    data,
                    keyTemplate,
                    passphrase,
                    collectionDecryptionKey);

        watcher->setFuture(future);
        connect(watcher, &QFutureWatcher<KeyResult>::finished, [=] {
            watcher->deleteLater();
            KeyResult kr = watcher->future().result();
            Result outputResult = kr.result;
            Key outputKey = kr.key;
            if (outputResult.code() != Result::Failed) {
                outputKey.setOrigin(Key::OriginImported);
            } else if (outputResult.errorCode() == Result::CryptoPluginIncorrectPassphrase && uiParams.isValid()) {
                outputResult = promptForKeyPassphrase(callerPid, requestId, keyTemplate, uiParams);
                if (outputResult.code() == Result::Pending) {
                    m_pendingRequests.insert(requestId, Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                                 callerPid,
                                                 requestId,
                                                 Daemon::ApiImpl::ImportStoredKeyRequest,
                                                 QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                                << QVariant::fromValue<Key>(keyTemplate)
                                                                << QVariant::fromValue<InteractionParameters>(uiParams)
                                                                << QVariant::fromValue<QVariantMap>(customParameters)
                                                                << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                                << QVariant::fromValue<QByteArray>(collectionDecryptionKey)));
                }
            }
            if (outputResult.code() != Result::Pending) {
                QVariantList outParams;
                outParams << QVariant::fromValue<Result>(outputResult);
                outParams << QVariant::fromValue<Key>(outputKey);
                m_requestQueue->requestFinished(requestId, outParams);
            }
        });
    } else {
        QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
        QFuture<KeyResult> future = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                    CryptoPluginFunctionWrapper::importKey,
                    PluginAndCustomParams(m_cryptoPlugins.value(cryptosystemProviderName),
                                          customParameters),
                    data,
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
                // ask the user for the passphrase required to import the key.
                m_pendingRequests.insert(requestId,Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::ImportStoredKeyRequest,
                                             QVariantList() << QVariant::fromValue<QByteArray>(data)
                                                            << QVariant::fromValue<Key>(keyTemplate)
                                                            << QVariant::fromValue<InteractionParameters>(uiParams)
                                                            << QVariant::fromValue<QVariantMap>(customParameters)
                                                            << QVariant::fromValue<QString>(cryptosystemProviderName)
                                                            << QVariant::fromValue<QByteArray>(collectionDecryptionKey)));
                result = Result(Result::Pending);
            } else if (result.code() == Result::Succeeded) {
                // successfully imported, now store in the specified plugin
                outputKey.setOrigin(Key::OriginImported);
                result = transformSecretsResult(m_secrets->storeKey(
                                                    callerPid,
                                                    requestId,
                                                    outputKey.identifier(),
                                                    Key::serialize(outputKey, Key::LossySerializationMode),
                                                    outputKey.filterData(),
                                                    collectionDecryptionKey));
                if (result.code() != Result::Failed) {
                    m_pendingRequests.insert(requestId,Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                                 callerPid,
                                                 requestId,
                                                 Daemon::ApiImpl::ImportStoredKeyRequest,
                                                 QVariantList() << QVariant::fromValue<Key>(keyTemplate)));
                }
            }

            if (result.code() != Result::Pending) {
                QVariantList outParams;
                outParams << QVariant::fromValue<Result>(result);
                outParams << QVariant::fromValue<Key>(outputKey);
                m_requestQueue->requestFinished(requestId, outParams);
            }
        });
    }
}

void
Daemon::ApiImpl::RequestProcessor::importStoredKey_inStoragePlugin(
        pid_t callerPid,
        quint64 requestId,
        const Result &result,
        const Key &fullKey)
{
    Q_UNUSED(callerPid);
    // This method is invoked in the "generate from crypto plugin, store in secrets storage plugin" codepath.
    // finish the asynchronous request.
    Key partialKey(fullKey);
    partialKey.setPrivateKey(QByteArray());
    partialKey.setSecretKey(QByteArray());
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Result>(result);
    outParams << QVariant::fromValue<Key>(partialKey);
    m_requestQueue->requestFinished(requestId, outParams);
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
    if (identifier.storagePluginName().isEmpty()) {
        return Result(Result::InvalidStorageProvider,
                      QLatin1String("Empty storage plugin name specified in identifier"));
    } else if (!m_secrets->encryptedStoragePluginNames().contains(identifier.storagePluginName())
               && !m_secrets->storagePluginNames().contains(identifier.storagePluginName())) {
        return Result(Result::InvalidStorageProvider,
                      QLatin1String("Unknown storage plugin name specified in identifier"));
    }

    if (m_cryptoPlugins.contains(identifier.storagePluginName())) {
        QFutureWatcher<KeyResult> *watcher = new QFutureWatcher<KeyResult>(this);
        QFuture<KeyResult> future = QtConcurrent::run(
                    m_requestQueue->controller()->threadPoolForPlugin(identifier.storagePluginName()).data(),
                    CryptoPluginFunctionWrapper::storedKey,
                    m_cryptoPlugins[identifier.storagePluginName()],
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

    QByteArray serializedKey;
    QMap<QString, QString> filterData;
    Result retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, identifier, &serializedKey, &filterData));
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

    *key = Key::deserialize(serializedKey);
    key->setFilterData(filterData);
    nullifyKeyFields(key, keyComponents);
    return retn;
}

void
Daemon::ApiImpl::RequestProcessor::storedKey2(
        quint64 requestId,
        Key::Components keyComponents,
        const Result &result,
        const QByteArray &serializedKey,
        const QMap<QString, QString> &filterData)
{
    Key retn(Key::deserialize(serializedKey));
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
    // delete from secrets storage
    Result retn = transformSecretsResult(m_secrets->deleteStoredKey(callerPid, requestId, identifier));
    if (retn.code() == Result::Pending) {
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
    Q_UNUSED(callerPid);
    Q_UNUSED(identifier);
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Result>(result);
    m_requestQueue->requestFinished(requestId, outParams);
}

Result
Daemon::ApiImpl::RequestProcessor::storedKeyIdentifiers(
        pid_t callerPid,
        quint64 requestId,
        const QString &storagePluginName,
        const QString &collectionName,
        QVector<Key::Identifier> *identifiers)
{
    // TODO: access control
    Result retn = transformSecretsResult(m_secrets->storedKeyIdentifiers(
                callerPid, requestId, collectionName, storagePluginName, identifiers));

    if (retn.code() == Result::Pending) {
        // asynchronous flow, will call back to storedKeyIdentifiers2().
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::StoredKeyIdentifiersRequest,
                                     QVariantList()));
    }

    return retn;
}

void Daemon::ApiImpl::RequestProcessor::storedKeyIdentifiers2(
        pid_t callerPid,
        quint64 requestId,
        const Result &result,
        const QVector<Key::Identifier> &identifiers)
{
    Q_UNUSED(callerPid);
    QList<QVariant> outParams;
    outParams << QVariant::fromValue<Result>(result)
              << QVariant::fromValue<QVector<Key::Identifier> >(identifiers);
    m_requestQueue->requestFinished(requestId, outParams);
}

Result
Daemon::ApiImpl::RequestProcessor::calculateDigest(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
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
                CryptoPluginFunctionWrapper::calculateDigest,
                PluginAndCustomParams(cryptoPlugin, customParameters),
                data,
                SignatureOptions(padding, digestFunction));

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
        const QVariantMap &customParameters,
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

    Key fullKey;
    if (key.privateKey().isEmpty() && key.secretKey().isEmpty()) {
        // the key is a key reference, we may need to read the full key from storage.
        if (key.identifier().name().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty key name given in key reference identifier"));
        } else if (key.identifier().collectionName().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty collection name given in key reference identifier"));
        } else if (key.identifier().storagePluginName().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty storage plugin name given in key reference identifier"));
        } else if (!m_secrets->encryptedStoragePluginNames().contains(key.identifier().storagePluginName())
                   && !m_secrets->storagePluginNames().contains(key.identifier().storagePluginName())) {
            return Result(Result::InvalidStorageProvider,
                          QLatin1String("Unknown storage plugin name specified in key reference identifier"));
        }

        // find out if the key is stored in the crypto plugin.
        // if so, we don't need to pull it into the daemon process address space.
        if (key.identifier().storagePluginName() == cryptosystemProviderName) {
            // yes, it is stored in the crypto plugin.
            fullKey = key; // not a full key, but a reference to a key that the plugin stores.
        } else {
            // no, it is stored in some other plugin
            QByteArray serializedKey;
            QMap<QString, QString> filterData;
            Result retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, key.identifier(), &serializedKey, &filterData));
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
                                                            << QVariant::fromValue<QVariantMap>(customParameters)
                                                            << QVariant::fromValue<QString>(cryptosystemProviderName)));
                return retn;
            }

            fullKey = Key::deserialize(serializedKey);
        }
    } else {
        fullKey = key;
    }

    QFutureWatcher<DataResult> *watcher = new QFutureWatcher<DataResult>(this);
    QFuture<DataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginFunctionWrapper::sign,
                PluginAndCustomParams(cryptoPlugin, customParameters),
                data,
                fullKey,
                SignatureOptions(padding, digestFunction));

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
        const QByteArray &serializedKey,
        const QByteArray &data,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
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
                CryptoPluginFunctionWrapper::sign,
                PluginAndCustomParams(m_cryptoPlugins[cryptoPluginName], customParameters),
                data,
                Key::deserialize(serializedKey),
                SignatureOptions(padding, digestFunction));

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
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus)
{
    // TODO: Access Control
    Q_UNUSED(verificationStatus); // asynchronous out-param.

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    Key fullKey;
    if (key.publicKey().isEmpty() && key.privateKey().isEmpty() && key.secretKey().isEmpty()) { // can use public key to verify
        // the key is a key reference, we may need to read the full key from storage.
        if (key.identifier().name().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty key name given in key reference identifier"));
        } else if (key.identifier().collectionName().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty collection name given in key reference identifier"));
        } else if (key.identifier().storagePluginName().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty storage plugin name given in key reference identifier"));
        } else if (!m_secrets->encryptedStoragePluginNames().contains(key.identifier().storagePluginName())
                   && !m_secrets->storagePluginNames().contains(key.identifier().storagePluginName())) {
            return Result(Result::InvalidStorageProvider,
                          QLatin1String("Unknown storage plugin name specified in key reference identifier"));
        }

        // find out if the key is stored in the crypto plugin.
        // if so, we don't need to pull it into the daemon process address space.
        if (key.identifier().storagePluginName() == cryptosystemProviderName) {
            // yes, it is stored in the plugin.
            fullKey = key; // not a full key, but a reference to a key that the plugin stores.
        } else {
            // no, it is stored in some other plugin
            QByteArray serializedKey;
            QMap<QString, QString> filterData;
            Result retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, key.identifier(), &serializedKey, &filterData));
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
                                                            << QVariant::fromValue<QVariantMap>(customParameters)
                                                            << QVariant::fromValue<QString>(cryptosystemProviderName)));
                return retn;
            }

            fullKey = Key::deserialize(serializedKey);
        }
    } else {
        fullKey = key;
    }

    QFutureWatcher<ValidatedResult> *watcher = new QFutureWatcher<ValidatedResult>(this);
    QFuture<ValidatedResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginFunctionWrapper::verify,
                PluginAndCustomParams(cryptoPlugin, customParameters),
                signature,
                data,
                fullKey,
                SignatureOptions(padding, digestFunction));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<ValidatedResult>::finished, [=] {
        watcher->deleteLater();
        ValidatedResult vr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(vr.result);
        outParams << QVariant::fromValue<CryptoManager::VerificationStatus>(vr.verificationStatus);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::verify2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serializedKey,
        const QByteArray &signature,
        const QByteArray &data,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        const QString &cryptoPluginName)
{
    if (result.code() != Result::Succeeded) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(result);
        outParams << QVariant::fromValue<CryptoManager::VerificationStatus>(CryptoManager::VerificationFailed);
        m_requestQueue->requestFinished(requestId, outParams);
        return;
    }

    QFutureWatcher<ValidatedResult> *watcher = new QFutureWatcher<ValidatedResult>(this);
    QFuture<ValidatedResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptoPluginName).data(),
                CryptoPluginFunctionWrapper::verify,
                PluginAndCustomParams(m_cryptoPlugins[cryptoPluginName], customParameters),
                signature,
                data,
                Key::deserialize(serializedKey),
                SignatureOptions(padding, digestFunction));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<ValidatedResult>::finished, [=] {
        watcher->deleteLater();
        ValidatedResult vr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(vr.result);
        outParams << QVariant::fromValue<CryptoManager::VerificationStatus>(vr.verificationStatus);
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
        const QVariantMap &customParameters,
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

    Key fullKey;
    if (key.publicKey().isEmpty() && key.privateKey().isEmpty() && key.secretKey().isEmpty()) { // can use public key to encrypt
        // the key is a key reference, we may need to read the full key from storage.
        if (key.identifier().name().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty key name given in key reference identifier"));
        } else if (key.identifier().collectionName().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty collection name given in key reference identifier"));
        } else if (key.identifier().storagePluginName().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty storage plugin name given in key reference identifier"));
        } else if (!m_secrets->encryptedStoragePluginNames().contains(key.identifier().storagePluginName())
                   && !m_secrets->storagePluginNames().contains(key.identifier().storagePluginName())) {
            return Result(Result::InvalidStorageProvider,
                          QLatin1String("Unknown storage plugin name specified in key reference identifier"));
        }

        // find out if the key is stored in the crypto plugin.
        // if so, we don't need to pull it into the daemon process address space.
        if (key.identifier().storagePluginName() == cryptosystemProviderName) {
            // yes, it is stored in the plugin.
            fullKey = key; // not a full key, but a reference to a key that the plugin stores.
        } else {
            // no, it is stored in some other plugin
            QByteArray serializedKey;
            QMap<QString, QString> filterData;
            Result retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, key.identifier(), &serializedKey, &filterData));
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
                               << QVariant::fromValue<QVariantMap>(customParameters)
                               << QVariant::fromValue<QString>(cryptosystemProviderName);
                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::EncryptRequest,
                                             args));
                return retn;
            }

            fullKey = Key::deserialize(serializedKey);
        }
    } else {
        fullKey = key;
    }

    QFutureWatcher<TagDataResult> *watcher = new QFutureWatcher<TagDataResult>(this);
    QFuture<TagDataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginFunctionWrapper::encrypt,
                PluginAndCustomParams(cryptoPlugin, customParameters),
                DataAndIV(data, iv),
                fullKey,
                EncryptionOptions(blockMode, padding),
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
        const QByteArray &serializedKey,
        const QByteArray &data,
        const QByteArray &iv,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
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
    Key fullKey = Key::deserialize(serializedKey, &ok);
    if (!ok) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(Result(Result::SerializationError,
                                                        QLatin1String("Failed to deserialize key!")));
        outParams << QVariant::fromValue<QByteArray>(QByteArray());
        outParams << QVariant::fromValue<QByteArray>(QByteArray());
        m_requestQueue->requestFinished(requestId, outParams);
        return;
    }

    QFutureWatcher<TagDataResult> *watcher = new QFutureWatcher<TagDataResult>(this);
    QFuture<TagDataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptoPluginName).data(),
                CryptoPluginFunctionWrapper::encrypt,
                PluginAndCustomParams(m_cryptoPlugins[cryptoPluginName], customParameters),
                DataAndIV(data, iv),
                fullKey,
                EncryptionOptions(blockMode, padding),
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
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        QByteArray *decrypted,
        Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus)
{
    // TODO: Access Control
    Q_UNUSED(decrypted); // asynchronous out-param.
    Q_UNUSED(verificationStatus); // asynchronous out-param.

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    Key fullKey;
    if (key.privateKey().isEmpty() && key.secretKey().isEmpty()) {
        // the key is a key reference, we may need to read the full key from storage.
        if (key.identifier().name().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty key name given in key reference identifier"));
        } else if (key.identifier().collectionName().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty collection name given in key reference identifier"));
        } else if (key.identifier().storagePluginName().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty storage plugin name given in key reference identifier"));
        } else if (!m_secrets->encryptedStoragePluginNames().contains(key.identifier().storagePluginName())
                   && !m_secrets->storagePluginNames().contains(key.identifier().storagePluginName())) {
            return Result(Result::InvalidStorageProvider,
                          QLatin1String("Unknown storage plugin name specified in key reference identifier"));
        }

        // find out if the key is stored in the crypto plugin.
        // if so, we don't need to pull it into the daemon process address space.
        if (key.identifier().storagePluginName() == cryptosystemProviderName) {
            // yes, it is stored in the plugin.
            fullKey = key; // not a full key, but a reference to a key that the plugin stores.
        } else {
            // no, it is stored in some other plugin
            QByteArray serializedKey;
            QMap<QString, QString> filterData;
            Result retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, key.identifier(), &serializedKey, &filterData));
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
                     << QVariant::fromValue<QVariantMap>(customParameters)
                     << QVariant::fromValue<QString>(cryptosystemProviderName);
                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::DecryptRequest,
                                             args));
                return retn;
            }

            fullKey = Key::deserialize(serializedKey);
        }
    } else {
        fullKey = key;
    }

    QFutureWatcher<VerifiedDataResult> *watcher = new QFutureWatcher<VerifiedDataResult>(this);
    QFuture<VerifiedDataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginFunctionWrapper::decrypt,
                PluginAndCustomParams(cryptoPlugin, customParameters),
                DataAndIV(data, iv),
                fullKey,
                EncryptionOptions(blockMode, padding),
                AuthDataAndTag(authenticationData, authenticationTag));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<VerifiedDataResult>::finished, [=] {
        watcher->deleteLater();
        VerifiedDataResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<QByteArray>(dr.data);
        outParams << QVariant::fromValue<CryptoManager::VerificationStatus>(dr.verificationStatus);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::decrypt2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serializedKey,
        const QByteArray &data,
        const QByteArray &iv,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QByteArray &authenticationTag,
        const QVariantMap &customParameters,
        const QString &cryptoPluginName)
{
    if (result.code() != Result::Succeeded) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(result);
        outParams << QVariant::fromValue<QByteArray>(QByteArray());
        outParams << QVariant::fromValue<CryptoManager::VerificationStatus>(CryptoManager::VerificationFailed);
        m_requestQueue->requestFinished(requestId, outParams);
    }

    QFutureWatcher<VerifiedDataResult> *watcher = new QFutureWatcher<VerifiedDataResult>(this);
    QFuture<VerifiedDataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptoPluginName).data(),
                CryptoPluginFunctionWrapper::decrypt,
                PluginAndCustomParams(m_cryptoPlugins[cryptoPluginName], customParameters),
                DataAndIV(data, iv),
                Key::deserialize(serializedKey),
                EncryptionOptions(blockMode, padding),
                AuthDataAndTag(authenticationData, authenticationTag));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<VerifiedDataResult>::finished, [=] {
        watcher->deleteLater();
        VerifiedDataResult dr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(dr.result);
        outParams << QVariant::fromValue<QByteArray>(dr.data);
        outParams << QVariant::fromValue<CryptoManager::VerificationStatus>(dr.verificationStatus);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

Result
Daemon::ApiImpl::RequestProcessor::initializeCipherSession(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &iv,
        const Key &key,
        CryptoManager::Operation operation,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding encryptionPadding,
        CryptoManager::SignaturePadding signaturePadding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
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
        // the key is a key reference, we may need to read the full key from storage.
        if (key.identifier().name().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty key name given in key reference identifier"));
        } else if (key.identifier().collectionName().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty collection name given in key reference identifier"));
        } else if (key.identifier().storagePluginName().isEmpty()) {
            return Result(Result::InvalidKeyIdentifier,
                          QLatin1String("Empty storage plugin name given in key reference identifier"));
        } else if (!m_secrets->encryptedStoragePluginNames().contains(key.identifier().storagePluginName())
                   && !m_secrets->storagePluginNames().contains(key.identifier().storagePluginName())) {
            return Result(Result::InvalidStorageProvider,
                          QLatin1String("Unknown storage plugin name specified in key reference identifier"));
        }

        // find out if the key is stored in the crypto plugin.
        // if so, we don't need to pull it into the daemon process address space.
        if (key.identifier().storagePluginName() == cryptosystemProviderName) {
            // yes, it is stored in the plugin.
            fullKey = key; // not a full key, but a reference to a key that the plugin stores.
        } else {
            // no, it is stored in some other plugin
            QByteArray serializedKey;
            QMap<QString, QString> filterData;
            Result retn = transformSecretsResult(m_secrets->storedKey(callerPid, requestId, key.identifier(), &serializedKey, &filterData));
            if (retn.code() == Result::Failed) {
                return retn;
            } else if (retn.code() == Result::Pending) {
                // asynchronous flow required, will call back to initializeCipherSession2().
                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::InitializeCipherSessionRequest,
                                             QVariantList() << QVariant::fromValue<pid_t>(callerPid)
                                                            << QVariant::fromValue<QByteArray>(iv)
                                                            << QVariant::fromValue<CryptoManager::Operation>(operation)
                                                            << QVariant::fromValue<CryptoManager::BlockMode>(blockMode)
                                                            << QVariant::fromValue<CryptoManager::EncryptionPadding>(encryptionPadding)
                                                            << QVariant::fromValue<CryptoManager::SignaturePadding>(signaturePadding)
                                                            << QVariant::fromValue<CryptoManager::DigestFunction>(digestFunction)
                                                            << QVariant::fromValue<QVariantMap>(customParameters)
                                                            << QVariant::fromValue<QString>(cryptosystemProviderName)));
                return retn;
            }

            fullKey = Key::deserialize(serializedKey);
        }
    } else {
        fullKey = key;
    }

    QFutureWatcher<CipherSessionTokenResult> *watcher = new QFutureWatcher<CipherSessionTokenResult>(this);
    QFuture<CipherSessionTokenResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginFunctionWrapper::initializeCipherSession,
                PluginAndCustomParams(cryptoPlugin, customParameters),
                callerPid,
                iv,
                fullKey,
                CipherSessionOptions(
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
Daemon::ApiImpl::RequestProcessor::initializeCipherSession2(
        quint64 requestId,
        const Result &result,
        const QByteArray &serializedKey,
        pid_t callerPid,
        const QByteArray &iv,
        CryptoManager::Operation operation,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding encryptionPadding,
        CryptoManager::SignaturePadding signaturePadding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
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
                CryptoPluginFunctionWrapper::initializeCipherSession,
                PluginAndCustomParams(m_cryptoPlugins[cryptoPluginName], customParameters),
                callerPid,
                iv,
                Key::deserialize(serializedKey),
                CipherSessionOptions(
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
        const QVariantMap &customParameters,
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
                CryptoPluginFunctionWrapper::updateCipherSessionAuthentication,
                PluginAndCustomParams(cryptoPlugin, customParameters),
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
        const QVariantMap &customParameters,
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
                CryptoPluginFunctionWrapper::updateCipherSession,
                PluginAndCustomParams(cryptoPlugin, customParameters),
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
Daemon::ApiImpl::RequestProcessor::finalizeCipherSession(
        pid_t callerPid,
        quint64 requestId,
        const QByteArray &data,
        const QVariantMap &customParameters,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken,
        QByteArray *generatedData,
        Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus)
{
    Q_UNUSED(requestId); // TODO: Access Control
    Q_UNUSED(generatedData); // asynchronous out-param.
    Q_UNUSED(verificationStatus);      // asynchronous out-param.

    CryptoPlugin* cryptoPlugin = m_cryptoPlugins.value(cryptosystemProviderName);
    if (cryptoPlugin == Q_NULLPTR) {
        return Result(Result::InvalidCryptographicServiceProvider,
                      QLatin1String("No such cryptographic service provider plugin exists"));
    }

    QFutureWatcher<VerifiedDataResult> *watcher = new QFutureWatcher<VerifiedDataResult>(this);
    QFuture<VerifiedDataResult> future = QtConcurrent::run(
                m_requestQueue->controller()->threadPoolForPlugin(cryptosystemProviderName).data(),
                CryptoPluginFunctionWrapper::finalizeCipherSession,
                PluginAndCustomParams(cryptoPlugin, customParameters),
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
        outParams << QVariant::fromValue<CryptoManager::VerificationStatus>(vdr.verificationStatus);
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
    // TODO: Support bkdb target from crypto side also
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
    // TODO: Support bkdb target from crypto side also
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
    // TODO: Support bkdb target from crypto side also
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
        const QByteArray &serializedKey,
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
                storedKey2(requestId, keyComponents, returnResult, serializedKey, filterData);
                break;
            }
            case SignRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                CryptoManager::SignaturePadding padding = pr.parameters.takeFirst().value<CryptoManager::SignaturePadding>();
                CryptoManager::DigestFunction digestFunction = pr.parameters.takeFirst().value<CryptoManager::DigestFunction>();
                QVariantMap customParameters = pr.parameters.takeFirst().value<QVariantMap>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                sign2(requestId, returnResult, serializedKey, data, padding, digestFunction, customParameters, cryptoPluginName);
                break;
            }
            case VerifyRequest: {
                QByteArray signature = pr.parameters.takeFirst().value<QByteArray>();
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                CryptoManager::SignaturePadding padding = pr.parameters.takeFirst().value<CryptoManager::SignaturePadding>();
                CryptoManager::DigestFunction digestFunction = pr.parameters.takeFirst().value<CryptoManager::DigestFunction>();
                QVariantMap customParameters = pr.parameters.takeFirst().value<QVariantMap>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                verify2(requestId, returnResult, serializedKey, signature, data, padding, digestFunction, customParameters, cryptoPluginName);
                break;
            }
            case EncryptRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                QByteArray iv = pr.parameters.takeFirst().value<QByteArray>();
                CryptoManager::BlockMode blockMode = pr.parameters.takeFirst().value<CryptoManager::BlockMode>();
                CryptoManager::EncryptionPadding padding = pr.parameters.takeFirst().value<CryptoManager::EncryptionPadding>();
                QByteArray authenticationData = pr.parameters.takeFirst().value<QByteArray>();
                QVariantMap customParameters = pr.parameters.takeFirst().value<QVariantMap>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                encrypt2(requestId, returnResult, serializedKey, data, iv, blockMode, padding, authenticationData, customParameters, cryptoPluginName);
                break;
            }
            case DecryptRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                QByteArray iv = pr.parameters.takeFirst().value<QByteArray>();
                CryptoManager::BlockMode blockMode = pr.parameters.takeFirst().value<CryptoManager::BlockMode>();
                CryptoManager::EncryptionPadding padding = pr.parameters.takeFirst().value<CryptoManager::EncryptionPadding>();
                QByteArray authenticationData = pr.parameters.takeFirst().value<QByteArray>();
                QByteArray authenticationTag = pr.parameters.takeFirst().value<QByteArray>();
                QVariantMap customParameters = pr.parameters.takeFirst().value<QVariantMap>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                decrypt2(requestId, returnResult, serializedKey, data, iv, blockMode, padding, authenticationData, authenticationTag, customParameters, cryptoPluginName);
                break;
            }
            case InitializeCipherSessionRequest: {
                pid_t callerPid = pr.parameters.takeFirst().value<pid_t>();
                QByteArray iv = pr.parameters.takeFirst().value<QByteArray>();
                CryptoManager::Operation operation = pr.parameters.takeFirst().value<CryptoManager::Operation>();
                CryptoManager::BlockMode blockMode = pr.parameters.takeFirst().value<CryptoManager::BlockMode>();
                CryptoManager::EncryptionPadding encryptionPadding = pr.parameters.takeFirst().value<CryptoManager::EncryptionPadding>();
                CryptoManager::SignaturePadding signaturePadding = pr.parameters.takeFirst().value<CryptoManager::SignaturePadding>();
                CryptoManager::DigestFunction digestFunction = pr.parameters.takeFirst().value<CryptoManager::DigestFunction>();
                QVariantMap customParameters = pr.parameters.takeFirst().value<QVariantMap>();
                QString cryptoPluginName = pr.parameters.takeFirst().value<QString>();
                initializeCipherSession2(requestId, returnResult, serializedKey,
                                         callerPid, iv, operation, blockMode,
                                         encryptionPadding, signaturePadding,
                                         digestFunction, customParameters, cryptoPluginName);
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

// asynchronous operation (store key pre-check) has completed.
void Daemon::ApiImpl::RequestProcessor::secretsStoreKeyPreCheckCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result,
        const QByteArray &collectionDecryptionKey)
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
                InteractionParameters uiParams = pr.parameters.takeFirst().value<InteractionParameters>();
                QVariantMap customParameters = pr.parameters.takeFirst().value<QVariantMap>();
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                generateStoredKey_afterPreCheck(pr.callerPid,
                                                requestId,
                                                keyTemplate,
                                                kpgParams,
                                                skdfParams,
                                                uiParams,
                                                customParameters,
                                                cryptosystemProviderName,
                                                returnResult,
                                                collectionDecryptionKey);
                break;
            }
            case ImportStoredKeyRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                Key keyTemplate = pr.parameters.takeFirst().value<Key>();
                InteractionParameters uiParams = pr.parameters.takeFirst().value<InteractionParameters>();
                QVariantMap customParameters = pr.parameters.takeFirst().value<QVariantMap>();
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                importStoredKey_afterPreCheck(pr.callerPid,
                                              requestId,
                                              data,
                                              keyTemplate,
                                              uiParams,
                                              customParameters,
                                              cryptosystemProviderName,
                                              returnResult,
                                              collectionDecryptionKey);
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
                generateStoredKey_inStoragePlugin(pr.callerPid, requestId, returnResult, fullKey);
                break;
            }
            case ImportStoredKeyRequest: {
                Key key = pr.parameters.takeFirst().value<Key>();
                importStoredKey_inStoragePlugin(pr.callerPid, requestId, returnResult, key);
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
            default: {
                qCWarning(lcSailfishCryptoDaemon) << "Secrets completed deleteStoredKey() operation for request:" << requestId << "of invalid type:" << pr.requestType;
                break;
            }
        }
    } else {
        qCWarning(lcSailfishCryptoDaemon) << "Secrets completed deleteStoredKey() operation for unknown request:" << requestId;
    }
}

// asynchronous operation (stored key identifiers) has completed.
void Daemon::ApiImpl::RequestProcessor::secretsStoredKeyIdentifiersCompleted(
        quint64 requestId,
        const Sailfish::Secrets::Result &result,
        const QVector<Sailfish::Secrets::Secret::Identifier> &idents)
{
    // look up the pending request in our list
    if (m_pendingRequests.contains(requestId)) {
        // transform the error code.
        Result returnResult(transformSecretsResult(result));

        // transform the identifiers.
        QVector<Key::Identifier> identifiers;
        for (const Sailfish::Secrets::Secret::Identifier &id : idents) {
            identifiers.append(Key::Identifier(
                    id.name(), id.collectionName(), id.storagePluginName()));
        }

        // call the appropriate method to complete the request
        Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
        switch (pr.requestType) {
            case StoredKeyIdentifiersRequest: {
                storedKeyIdentifiers2(pr.callerPid, requestId, returnResult, identifiers);
                break;
            }
            default: {
                qCWarning(lcSailfishCryptoDaemon) << "Secrets completed storedKeyIdentifiers() operation for request:" << requestId << "of invalid type:" << pr.requestType;
                break;
            }
        }
    } else {
        qCWarning(lcSailfishCryptoDaemon) << "Secrets completed storedKeyIdentifiers() operation for unknown request:" << requestId;
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
                QVariantMap customParameters = pr.parameters.takeFirst().value<QVariantMap>();
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                QByteArray collectionDecryptionKey = pr.parameters.takeFirst().value<QByteArray>();
                generateStoredKey_withInputData(pr.callerPid, requestId, returnResult, keyTemplate, kpgParams, skdfParams, customParameters, cryptosystemProviderName, collectionDecryptionKey);
                break;
            }
            case ImportKeyRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                InteractionParameters uiParams = pr.parameters.takeFirst().value<InteractionParameters>();
                QVariantMap customParameters = pr.parameters.takeFirst().value<QVariantMap>();
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                importKey_withPassphrase(pr.callerPid, requestId, data, uiParams, customParameters, cryptosystemProviderName, returnResult, userInput);
                break;
            }
            case ImportStoredKeyRequest: {
                QByteArray data = pr.parameters.takeFirst().value<QByteArray>();
                Key keyTemplate = pr.parameters.takeFirst().value<Key>();
                InteractionParameters uiParams = pr.parameters.takeFirst().value<InteractionParameters>();
                QVariantMap customParameters = pr.parameters.takeFirst().value<QVariantMap>();
                QString cryptosystemProviderName = pr.parameters.takeFirst().value<QString>();
                QByteArray collectionDecryptionKey = pr.parameters.takeFirst().value<QByteArray>();
                importStoredKey_withPassphrase(
                            pr.callerPid,
                            requestId,
                            data,
                            keyTemplate,
                            uiParams,
                            customParameters,
                            cryptosystemProviderName,
                            collectionDecryptionKey,
                            returnResult,
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
