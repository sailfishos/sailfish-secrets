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

Result
Daemon::ApiImpl::RequestProcessor::confirmCollectionStoragePlugin(
        const QString &collectionName,
        const QString &storagePluginName) const
{
    QString collectionStoragePluginName;
    Result cspnResult = m_bkdb->collectionStoragePluginName(collectionName,
                                                            &collectionStoragePluginName);
    if (cspnResult.code() != Result::Succeeded) {
        return cspnResult;
    } else if (storagePluginName != collectionStoragePluginName) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("The identified collection is not stored by that plugin"));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::RequestProcessor::confirmKeyStoragePlugin(
        const QString &hashedKeyName,
        const QString &collectionName,
        const QString &storagePluginName) const
{
    QString keyStoragePluginName;
    Result kspnResult = m_bkdb->keyStoragePluginName(collectionName,
                                                     hashedKeyName,
                                                     &keyStoragePluginName);
    if (kspnResult.code() != Result::Succeeded) {
        return kspnResult;
    } else if (storagePluginName != keyStoragePluginName) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("The identified key is not stored by that plugin"));
    }

    return Result(Result::Succeeded);
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

QStringList
Daemon::ApiImpl::RequestProcessor::storagePluginNames() const
{
    return m_storagePlugins.keys();
}

Result
Daemon::ApiImpl::SecretsRequestQueue::storagePluginNames(
        pid_t callerPid,
        quint64 cryptoRequestId,
        QStringList *names) const
{
    // TODO: Access control
    Q_UNUSED(callerPid)
    Q_UNUSED(cryptoRequestId)

    *names = m_requestProcessor->storagePluginNames();
    return Result(Result::Succeeded);
}


Result
Daemon::ApiImpl::SecretsRequestQueue::confirmCollectionStoragePlugin(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const QString &collectionName,
        const QString &storagePluginName) const
{
    // TODO: Access control
    Q_UNUSED(callerPid)
    Q_UNUSED(cryptoRequestId)

    return m_requestProcessor->confirmCollectionStoragePlugin(collectionName, storagePluginName);
}


Result
Daemon::ApiImpl::SecretsRequestQueue::confirmKeyStoragePlugin(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const QString &hashedKeyName,
        const QString &collectionName,
        const QString &storagePluginName) const
{
    // TODO: Access control
    Q_UNUSED(callerPid)
    Q_UNUSED(cryptoRequestId)

    return m_requestProcessor->confirmKeyStoragePlugin(hashedKeyName, collectionName, storagePluginName);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::keyEntryIdentifiers(
        pid_t callerPid,
        quint64 cryptoRequestId,
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
{
    // TODO: access control
    Q_UNUSED(callerPid);
    Q_UNUSED(cryptoRequestId);

    return m_bkdb.keyIdentifiers(identifiers);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::keyEntry(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        QString *cryptoPluginName,
        QString *storagePluginName)
{
    // TODO: access control
    Q_UNUSED(callerPid);
    Q_UNUSED(cryptoRequestId);

    return m_bkdb.keyPluginNames(identifier.collectionName(),
                                 identifier.name(),
                                 cryptoPluginName,
                                 storagePluginName);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::addKeyEntry(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        const QString &cryptoPluginName,
        const QString &storagePluginName)
{
    // TODO: access control
    Q_UNUSED(callerPid);
    Q_UNUSED(cryptoRequestId);

    const QString hashedSecretName = Daemon::Util::generateHashedSecretName(
                identifier.collectionName(), identifier.name());
    return m_bkdb.addKeyEntry(identifier.collectionName(),
                              hashedSecretName,
                              identifier.name(),
                              cryptoPluginName,
                              storagePluginName);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::removeKeyEntry(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier)
{
    // TODO: access control
    Q_UNUSED(callerPid);
    Q_UNUSED(cryptoRequestId);

    return m_bkdb.removeKeyEntry(identifier.collectionName(),
                                 identifier.name());
}

// The crypto plugin can store keys, thus it is an EncryptedStoragePlugin.
// To prevent the daemon process from ever seeing the key data, the key
// is not stored through the normal setCollectionSecret() API, but instead
// is generated and stored directly by the Crypto plugin.
// However, we need to update the bookkeeping (main secrets metadata database)
// so that foreign key constraints etc continue to work appropriately.
Result
Daemon::ApiImpl::SecretsRequestQueue::storeKeyMetadata(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        const QString &storagePluginName)
{
    // step one: check if the Collection is stored in the storagePluginName, else return fail.
    Result confirmPluginResult = confirmCollectionStoragePlugin(
                callerPid,
                cryptoRequestId,
                identifier.collectionName(),
                storagePluginName);
    if (confirmPluginResult.code() != Result::Succeeded) {
        return confirmPluginResult;
    }

    // step two: perform the "set collection secret metadata" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret::Identifier>(Secret::Identifier(identifier.name(), identifier.collectionName()))
             << QVariant::fromValue<SecretManager::UserInteractionMode>(SecretManager::PreventInteraction)
             << QVariant::fromValue<QString>(QString());
    Result enqueueResult(Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Daemon::ApiImpl::SetCollectionSecretMetadataRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Daemon::ApiImpl::SecretsRequestQueue::StoreKeyMetadataCryptoApiHelperRequest);
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::SecretsRequestQueue::storeKey(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        const QByteArray &serialisedKey,
        const QMap<QString, QString> &filterData,
        const QString &storagePluginName)
{
    // step one: check if the Collection is stored in the storagePluginName, else return fail.
    Result confirmPluginResult = confirmCollectionStoragePlugin(
                callerPid,
                cryptoRequestId,
                identifier.collectionName(),
                storagePluginName);
    if (confirmPluginResult.code() != Result::Succeeded) {
        return confirmPluginResult;
    }

    // step two: perform the "set collection secret" request, as a secrets-for-crypto request.
    Secret secret(Secret::Identifier(identifier.name(), identifier.collectionName()));
    secret.setFilterData(filterData);
    secret.setType(Secret::TypeCryptoKey);
    secret.setData(serialisedKey);
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret>(secret)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(SecretManager::PreventInteraction)
             << QVariant::fromValue<QString>(QString());
    Result enqueueResult(Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Daemon::ApiImpl::SetCollectionSecretRequest,
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
    inParams << QVariant::fromValue<Secret::Identifier>(Secret::Identifier(identifier.name(), identifier.collectionName()))
             << QVariant::fromValue<SecretManager::UserInteractionMode>(SecretManager::PreventInteraction)
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

// This method is only called in the "cleanup a failed generatedStoredKey() attempt" codepath!
Result
Daemon::ApiImpl::SecretsRequestQueue::deleteStoredKeyMetadata(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier)
{
    // perform the "delete collection secret metadata" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret::Identifier>(Secret::Identifier(identifier.name(), identifier.collectionName()));
    Result enqueueResult(Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Daemon::ApiImpl::DeleteCollectionSecretMetadataRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Daemon::ApiImpl::SecretsRequestQueue::DeleteStoredKeyMetadataCryptoApiHelperRequest);
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
    inParams << QVariant::fromValue<Secret::Identifier>(Secret::Identifier(identifier.name(), identifier.collectionName()))
             << QVariant::fromValue<SecretManager::UserInteractionMode>(SecretManager::PreventInteraction)
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
        case StoreKeyCryptoApiHelperRequest: {
            emit storeKeyCompleted(cryptoRequestId, result);
            break;
        }
        case StoreKeyMetadataCryptoApiHelperRequest: {
            emit storeKeyMetadataCompleted(cryptoRequestId, result);
            break;
        }
        case DeleteStoredKeyMetadataCryptoApiHelperRequest: {
            emit deleteStoredKeyMetadataCompleted(cryptoRequestId, result);
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
