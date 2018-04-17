/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "SecretsImpl/secrets_p.h"
#include "SecretsImpl/secretsrequestprocessor_p.h"

#include "Secrets/result.h"

#include "Crypto/result.h"
#include "Crypto/key.h"

#include "util_p.h"

#include <QtCore/QStringList>
#include <QtCore/QVector>
#include <QtCore/QByteArray>
#include <QtCore/QMutexLocker>
#include <QtCore/QMutex>
#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishSecretsCryptoHelpers, "org.sailfishos.secrets.cryptohelpers", QtWarningMsg)

using namespace Sailfish::Secrets;

// The methods in this file exist to help fulfil Sailfish Crypto API requests,
// while allowing the use of a single (secrets) database for atomicity reasons.

QStringList
Daemon::ApiImpl::SecretsRequestQueue::storagePluginNames() const
{
    return m_requestProcessor->storagePluginNames();
}

QStringList
Daemon::ApiImpl::SecretsRequestQueue::encryptedStoragePluginNames() const
{
    return m_requestProcessor->encryptedStoragePluginNames();
}

QMap<QString, QObject*>
Daemon::ApiImpl::SecretsRequestQueue::potentialCryptoStoragePlugins() const
{
    return m_requestProcessor->potentialCryptoStoragePlugins();
}

QMap<QString, QObject*>
Daemon::ApiImpl::RequestProcessor::potentialCryptoStoragePlugins() const
{
    return m_potentialCryptoStoragePlugins;
}

Sailfish::Crypto::Daemon::ApiImpl::CryptoStoragePluginWrapper *
Daemon::ApiImpl::SecretsRequestQueue::cryptoStoragePluginWrapper(const QString &pluginName) const
{
    return m_requestProcessor->cryptoStoragePluginWrapper(pluginName);
}

Sailfish::Crypto::Daemon::ApiImpl::CryptoStoragePluginWrapper *
Daemon::ApiImpl::RequestProcessor::cryptoStoragePluginWrapper(const QString &pluginName) const
{
    return m_cryptoStoragePlugins.value(pluginName);
}

Sailfish::Secrets::Result
Daemon::ApiImpl::SecretsRequestQueue::storedKeyIdentifiers(const QString &storagePluginName,
                                                           QVector<Secret::Identifier> *idents) const
{
    // TODO: make this asynchronous, emit a signal when complete.
    return m_requestProcessor->storedKeyIdentifiers(storagePluginName, idents);
}

QStringList
Daemon::ApiImpl::RequestProcessor::storagePluginNames() const
{
    return m_storagePlugins.keys();
}

QStringList
Daemon::ApiImpl::RequestProcessor::encryptedStoragePluginNames() const
{
    return m_encryptedStoragePlugins.keys();
}

QVector<PluginInfo>
Daemon::ApiImpl::RequestProcessor::storagePluginInfo() const
{
    QVector<PluginInfo> infos;
    for (StoragePluginWrapper *plugin : m_storagePlugins) {
        infos.append(PluginInfo(plugin->name(), plugin->version()));
    }
    for (EncryptedStoragePluginWrapper *plugin : m_encryptedStoragePlugins) {
        infos.append(PluginInfo(plugin->name(), plugin->version()));
    }
    return infos;
}

Result
Daemon::ApiImpl::SecretsRequestQueue::storagePluginInfo(
        pid_t callerPid,
        quint64 cryptoRequestId,
        QVector<PluginInfo> *infos) const
{
    // TODO: Access control
    Q_UNUSED(callerPid)
    Q_UNUSED(cryptoRequestId)

    *infos = m_requestProcessor->storagePluginInfo();
    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::storeKeyPreCheck(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret::Identifier>(
                    Secret::Identifier(identifier.name(),
                                       identifier.collectionName(),
                                       identifier.storagePluginName()))
             << QVariant::fromValue<SecretManager::UserInteractionMode>(SecretManager::SystemInteraction);
    Result enqueueResult(Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Daemon::ApiImpl::SetCollectionKeyPreCheckRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Daemon::ApiImpl::SecretsRequestQueue::StoreKeyPreCheckCryptoApiHelperRequest);
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::storeKey(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        const QByteArray &serialisedKey,
        const QMap<QString, QString> &filterData,
        const QByteArray &collectionDecryptionKey)
{
    // perform the "set collection secret" request, as a secrets-for-crypto request.
    Secret secret(Secret::Identifier(identifier.name(), identifier.collectionName(), identifier.storagePluginName()));
    secret.setFilterData(filterData);
    secret.setType(Secret::TypeCryptoKey);
    secret.setData(serialisedKey);
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret>(secret)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(SecretManager::SystemInteraction)
             << QVariant::fromValue<QByteArray>(collectionDecryptionKey);
    Result enqueueResult(Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Daemon::ApiImpl::SetCollectionKeyRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Daemon::ApiImpl::SecretsRequestQueue::StoreKeyCryptoApiHelperRequest);
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::deleteStoredKey(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier)
{
    // perform the "delete collection secret" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret::Identifier>(Secret::Identifier(identifier.name(),
                                                                           identifier.collectionName(),
                                                                           identifier.storagePluginName()))
             << QVariant::fromValue<SecretManager::UserInteractionMode>(SecretManager::SystemInteraction)
             << QVariant::fromValue<QString>(QString());
    Result enqueueResult(Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Daemon::ApiImpl::DeleteCollectionSecretRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Daemon::ApiImpl::SecretsRequestQueue::DeleteStoredKeyCryptoApiHelperRequest);
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::storedKey(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        QByteArray *serialisedKey,
        QMap<QString, QString> *filterData)
{
    Q_UNUSED(serialisedKey); // this request is always asynchronous
    Q_UNUSED(filterData);

    // perform the "get collection secret" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret::Identifier>(Secret::Identifier(identifier.name(),
                                                                           identifier.collectionName(),
                                                                           identifier.storagePluginName()))
             << QVariant::fromValue<SecretManager::UserInteractionMode>(SecretManager::SystemInteraction)
             << QVariant::fromValue<QString>(QString());
    Result enqueueResult(Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Daemon::ApiImpl::GetCollectionSecretRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Daemon::ApiImpl::SecretsRequestQueue::StoredKeyCryptoApiHelperRequest);
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::userInput(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Secrets::InteractionParameters &uiParams)
{
    // perform the "get user input" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<InteractionParameters>(uiParams);
    Result enqueueResult(Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Daemon::ApiImpl::UserInputRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Daemon::ApiImpl::SecretsRequestQueue::UserInputCryptoApiHelperRequest);
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::modifyCryptoPluginLockCode(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const QString &cryptoPluginName,
        const Sailfish::Secrets::InteractionParameters &uiParams)
{
    // perform the "modify lock code" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Secrets::LockCodeRequest::LockCodeTargetType>(Sailfish::Secrets::LockCodeRequest::ExtensionPlugin)
             << QVariant::fromValue<QString>(cryptoPluginName)
             << QVariant::fromValue<Sailfish::Secrets::InteractionParameters>(uiParams)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(Sailfish::Secrets::SecretManager::SystemInteraction)
             << QVariant::fromValue<QString>(QString());
    Result enqueueResult(Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Daemon::ApiImpl::ModifyLockCodeRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Daemon::ApiImpl::SecretsRequestQueue::ModifyLockCodeCryptoApiHelperRequest);
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::provideCryptoPluginLockCode(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const QString &cryptoPluginName,
        const Sailfish::Secrets::InteractionParameters &uiParams)
{
    // perform the "provide lock code" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Secrets::LockCodeRequest::LockCodeTargetType>(Sailfish::Secrets::LockCodeRequest::ExtensionPlugin)
             << QVariant::fromValue<QString>(cryptoPluginName)
             << QVariant::fromValue<Sailfish::Secrets::InteractionParameters>(uiParams)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(Sailfish::Secrets::SecretManager::SystemInteraction)
             << QVariant::fromValue<QString>(QString());
    Result enqueueResult(Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Daemon::ApiImpl::ProvideLockCodeRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Daemon::ApiImpl::SecretsRequestQueue::ProvideLockCodeCryptoApiHelperRequest);
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::forgetCryptoPluginLockCode(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const QString &cryptoPluginName,
        const Sailfish::Secrets::InteractionParameters &uiParams)
{
    // perform the "forget lock code" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Secrets::LockCodeRequest::LockCodeTargetType>(Sailfish::Secrets::LockCodeRequest::ExtensionPlugin)
             << QVariant::fromValue<QString>(cryptoPluginName)
             << QVariant::fromValue<Sailfish::Secrets::InteractionParameters>(uiParams)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(Sailfish::Secrets::SecretManager::SystemInteraction)
             << QVariant::fromValue<QString>(QString());
    Result enqueueResult(Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Daemon::ApiImpl::ForgetLockCodeRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Daemon::ApiImpl::SecretsRequestQueue::ForgetLockCodeCryptoApiHelperRequest);
    return Result(Result::Pending);
}

void
Daemon::ApiImpl::SecretsRequestQueue::asynchronousCryptoRequestCompleted(
        quint64 cryptoRequestId,
        const Result &result,
        const QVariantList &parameters)
{
    if (!m_cryptoApiHelperRequests.contains(cryptoRequestId)) {
        qCWarning(lcSailfishSecretsCryptoHelpers) << "Unknown asynchronous secrets request finished for crypto request:" << cryptoRequestId;
        return;
    }

    Daemon::ApiImpl::SecretsRequestQueue::CryptoApiHelperRequestType type = m_cryptoApiHelperRequests.take(cryptoRequestId);
    switch (type) {
        case StoredKeyCryptoApiHelperRequest: {
            Secret secret = parameters.size() ? parameters.first().value<Secret>() : Secret();
            emit storedKeyCompleted(cryptoRequestId, result, secret.data(), secret.filterData());
            break;
        }
        case DeleteStoredKeyCryptoApiHelperRequest: {
            emit deleteStoredKeyCompleted(cryptoRequestId, result);
            break;
        }
        case StoreKeyPreCheckCryptoApiHelperRequest: {
            QByteArray collectionDecryptionKey = parameters.size() ? parameters.first().value<QByteArray>() : QByteArray();
            emit storeKeyPreCheckCompleted(cryptoRequestId, result, collectionDecryptionKey);
            break;
        }
        case StoreKeyCryptoApiHelperRequest: {
            emit storeKeyCompleted(cryptoRequestId, result);
            break;
        }
        case UserInputCryptoApiHelperRequest: {
            QByteArray input = parameters.size() ? parameters.first().value<QByteArray>() : QByteArray();
            emit userInputCompleted(cryptoRequestId, result, input);
            break;
        }
        case ModifyLockCodeCryptoApiHelperRequest:   // flow on
        case ProvideLockCodeCryptoApiHelperRequest:  // flow on
        case ForgetLockCodeCryptoApiHelperRequest: {
            emit cryptoPluginLockCodeRequestCompleted(cryptoRequestId, result);
            break;
        }
        default: {
            // this type of method shouldn't be asynchronous!  (may change in the future, in which case, new case needs to be added above)
            qCWarning(lcSailfishSecretsCryptoHelpers) << "Asynchronous secrets request finished for synchronous crypto request:" << cryptoRequestId;
            break;
        }
    }
}
