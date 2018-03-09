/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "secrets_p.h"
#include "secretsrequestprocessor_p.h"
#include "logging_p.h"

#include "Secrets/result.h"
#include "Secrets/secretmanager.h"
#include "Secrets/secretsdaemonconnection_p.h"
#include "Secrets/serialisation_p.h"

using namespace Sailfish::Secrets;

Daemon::ApiImpl::SecretsDBusObject::SecretsDBusObject(
        Daemon::ApiImpl::SecretsRequestQueue *parent)
    : QObject(parent)
    , m_requestQueue(parent)
{
}

// retrieve information about available plugins
void Daemon::ApiImpl::SecretsDBusObject::getPluginInfo(
        const QDBusMessage &message,
        Result &result,
        QVector<StoragePluginInfo> &storagePlugins,
        QVector<EncryptionPluginInfo> &encryptionPlugins,
        QVector<EncryptedStoragePluginInfo> &encryptedStoragePlugins,
        QVector<AuthenticationPluginInfo> &authenticationPlugins)
{
    Q_UNUSED(storagePlugins);           // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(encryptionPlugins);        // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(encryptedStoragePlugins);  // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(authenticationPlugins);    // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    m_requestQueue->handleRequest(Daemon::ApiImpl::GetPluginInfoRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// retrieve user input for the client (daemon)
void Daemon::ApiImpl::SecretsDBusObject::userInput(
        const InteractionParameters &uiParams,
        const QDBusMessage &message,
        Result &result,
        QByteArray &data)
{
    Q_UNUSED(data); // outparam, set in handlePendingRequest / handleFinishedRequest
    InteractionParameters modifiedParams(uiParams);
    modifiedParams.setOperation(InteractionParameters::RequestUserData);
    modifiedParams.setCollectionName(QString());
    modifiedParams.setSecretName(QString());
    modifiedParams.setPromptTrId(QString());
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<InteractionParameters>(modifiedParams);
    m_requestQueue->handleRequest(Daemon::ApiImpl::UserInputRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}



// retrieve the names of collections
void Daemon::ApiImpl::SecretsDBusObject::collectionNames(
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result,
        QStringList &names)
{
    Q_UNUSED(names); // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    m_requestQueue->handleRequest(Daemon::ApiImpl::CollectionNamesRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// create a DeviceLock-protected collection
void Daemon::ApiImpl::SecretsDBusObject::createCollection(
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(collectionName)
             << QVariant::fromValue<QString>(storagePluginName)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<SecretManager::DeviceLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode);
    m_requestQueue->handleRequest(Daemon::ApiImpl::CreateDeviceLockCollectionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// create a CustomLock-protected collection
void Daemon::ApiImpl::SecretsDBusObject::createCollection(
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        SecretManager::CustomLockUnlockSemantic unlockSemantic,
        int customLockTimeoutMs,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(collectionName)
             << QVariant::fromValue<QString>(storagePluginName)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<QString>(authenticationPluginName)
             << QVariant::fromValue<SecretManager::CustomLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<int>(customLockTimeoutMs)
             << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::CreateCustomLockCollectionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// delete a collection
void Daemon::ApiImpl::SecretsDBusObject::deleteCollection(
        const QString &collectionName,
        SecretManager::UserInteractionMode userInteractionMode,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(collectionName)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode);
    m_requestQueue->handleRequest(Daemon::ApiImpl::DeleteCollectionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// set a secret in a collection
void Daemon::ApiImpl::SecretsDBusObject::setSecret(
        const Secret &secret,
        const InteractionParameters &uiParams,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret>(secret)
             << QVariant::fromValue<InteractionParameters>(uiParams)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::SetCollectionSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// set a standalone DeviceLock-protected secret
void Daemon::ApiImpl::SecretsDBusObject::setSecret(
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const Secret &secret,
        const InteractionParameters &uiParams,
        SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(storagePluginName)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<Secret>(secret)
             << QVariant::fromValue<InteractionParameters>(uiParams)
             << QVariant::fromValue<SecretManager::DeviceLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::SetStandaloneDeviceLockSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// set a standalone CustomLock-protected secret
void Daemon::ApiImpl::SecretsDBusObject::setSecret(
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        const Secret &secret,
        const InteractionParameters &uiParams,
        SecretManager::CustomLockUnlockSemantic unlockSemantic,
        int customLockTimeoutMs,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(storagePluginName)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<QString>(authenticationPluginName)
             << QVariant::fromValue<Secret>(secret)
             << QVariant::fromValue<InteractionParameters>(uiParams)
             << QVariant::fromValue<SecretManager::CustomLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<int>(customLockTimeoutMs)
             << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::SetStandaloneCustomLockSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// get a secret
void Daemon::ApiImpl::SecretsDBusObject::getSecret(
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result,
        Secret &secret)
{
    Q_UNUSED(secret); // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret::Identifier>(identifier)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(identifier.identifiesStandaloneSecret()
                                      ? Daemon::ApiImpl::GetStandaloneSecretRequest
                                      : Daemon::ApiImpl::GetCollectionSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// find secrets via filter
void Daemon::ApiImpl::SecretsDBusObject::findSecrets(
        const QString &collectionName,
        const Secret::FilterData &filter,
        SecretManager::FilterOperator filterOperator,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result,
        QVector<Secret::Identifier> &identifiers)
{
    Q_UNUSED(identifiers); // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    if (!collectionName.isEmpty()) {
        inParams << QVariant::fromValue<QString>(collectionName);
    }
    inParams << QVariant::fromValue<Secret::FilterData>(filter)
             << QVariant::fromValue<SecretManager::FilterOperator>(filterOperator)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(collectionName.isEmpty()
                                      ? Daemon::ApiImpl::FindStandaloneSecretsRequest
                                      : Daemon::ApiImpl::FindCollectionSecretsRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// delete a secret
void Daemon::ApiImpl::SecretsDBusObject::deleteSecret(
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret::Identifier>(identifier)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(identifier.identifiesStandaloneSecret()
                                      ? Daemon::ApiImpl::DeleteStandaloneSecretRequest
                                      : Daemon::ApiImpl::DeleteCollectionSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

//-----------------------------------

Daemon::ApiImpl::SecretsRequestQueue::SecretsRequestQueue(
        Daemon::Controller *parent,
        const QString &pluginDir,
        bool autotestMode)
    : Daemon::ApiImpl::RequestQueue(
          QLatin1String("/Sailfish/Secrets"),
          QLatin1String("org.sailfishos.secrets"),
          parent,
          pluginDir,
          autotestMode)
{
    SecretsDaemonConnection::registerDBusTypes();
    if (!m_bkdb.initialise(autotestMode,
                           QByteArray("0000000000000000"
                                      "0000000000000000"
                                      "0000000000000000"
                                      "0000000000000001"))) {
        qCWarning(lcSailfishSecretsDaemon) << "Secrets: failed to open bookkeeping database!";
        return;
    }

    m_appPermissions = new Daemon::ApiImpl::ApplicationPermissions(this);
    m_requestProcessor = new Daemon::ApiImpl::RequestProcessor(&m_bkdb, m_appPermissions, autotestMode, this);
    if (!m_requestProcessor->loadPlugins(pluginDir)) {
        qCWarning(lcSailfishSecretsDaemon) << "Secrets: failed to load plugins!";
        return;
    }

    setDBusObject(new Daemon::ApiImpl::SecretsDBusObject(this));
    qCDebug(lcSailfishSecretsDaemon) << "Secrets: initialisation succeeded, awaiting client connections.";
}

Daemon::ApiImpl::SecretsRequestQueue::~SecretsRequestQueue()
{
}

QString Daemon::ApiImpl::SecretsRequestQueue::requestTypeToString(int type) const
{
    switch (type) {
        case InvalidRequest:                        return QLatin1String("InvalidRequest");
        case GetPluginInfoRequest:                  return QLatin1String("GetPluginInfoRequest");
        case UserInputRequest:                      return QLatin1String("UserInputRequest");
        case CollectionNamesRequest:                return QLatin1String("CollectionNamesRequest");
        case CreateDeviceLockCollectionRequest:     return QLatin1String("CreateDeviceLockCollectionRequest");
        case CreateCustomLockCollectionRequest:     return QLatin1String("CreateCustomLockCollectionRequest");
        case DeleteCollectionRequest:               return QLatin1String("DeleteCollectionRequest");
        case SetCollectionSecretRequest:            return QLatin1String("SetCollectionSecretRequest");
        case SetStandaloneDeviceLockSecretRequest:  return QLatin1String("SetStandaloneDeviceLockSecretRequest");
        case SetStandaloneCustomLockSecretRequest:  return QLatin1String("SetStandaloneCustomLockSecretRequest");
        case GetCollectionSecretRequest:            return QLatin1String("GetCollectionSecretRequest");
        case GetStandaloneSecretRequest:            return QLatin1String("GetStandaloneSecretRequest");
        case FindCollectionSecretsRequest:          return QLatin1String("FindCollectionSecretsRequest");
        case FindStandaloneSecretsRequest:          return QLatin1String("FindStandaloneSecretsRequest");
        case DeleteCollectionSecretRequest:         return QLatin1String("DeleteCollectionSecretRequest");
        case DeleteStandaloneSecretRequest:         return QLatin1String("DeleteStandaloneSecretRequest");
        case SetCollectionSecretMetadataRequest:    return QLatin1String("SetCollectionSecretMetadataRequest");
        case DeleteCollectionSecretMetadataRequest: return QLatin1String("DeleteCollectionSecretMetadataRequest");
        default: break;
    }
    return QLatin1String("Unknown Secrets Request!");
}

void Daemon::ApiImpl::SecretsRequestQueue::handlePendingRequest(
        Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling GetPluginInfoRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QVector<StoragePluginInfo> storagePlugins;
            QVector<EncryptionPluginInfo> encryptionPlugins;
            QVector<EncryptedStoragePluginInfo> encryptedStoragePlugins;
            QVector<AuthenticationPluginInfo> authenticationPlugins;
            Result result = m_requestProcessor->getPluginInfo(
                        request->remotePid,
                        request->requestId,
                        &storagePlugins,
                        &encryptionPlugins,
                        &encryptedStoragePlugins,
                        &authenticationPlugins);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QVector<StoragePluginInfo> >(storagePlugins)
                                                                            << QVariant::fromValue<QVector<EncryptionPluginInfo> >(encryptionPlugins)
                                                                            << QVariant::fromValue<QVector<EncryptedStoragePluginInfo> >(encryptedStoragePlugins)
                                                                            << QVariant::fromValue<QVector<AuthenticationPluginInfo> >(authenticationPlugins));
                }
                *completed = true;
            }
            break;
        }
        case CollectionNamesRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling CollectionNamesRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QStringList names;
            Result result = m_requestProcessor->collectionNames(
                        request->remotePid,
                        request->requestId,
                        &names);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QStringList>(names));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QStringList>(names));
                }
                *completed = true;
            }
            break;
        }
        case CreateDeviceLockCollectionRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling CreateDeviceLockCollectionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString collectionName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString storagePluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString encryptionPluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            SecretManager::DeviceLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::DeviceLockUnlockSemantic>()
                    : SecretManager::DeviceLockKeepUnlocked;
            SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::AccessControlMode>()
                    : SecretManager::OwnerOnlyMode;
            Result result = m_requestProcessor->createDeviceLockCollection(
                        request->remotePid,
                        request->requestId,
                        collectionName,
                        storagePluginName,
                        encryptionPluginName,
                        unlockSemantic,
                        accessControlMode);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case CreateCustomLockCollectionRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling CreateCustomLockCollectionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString collectionName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString storagePluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString encryptionPluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString authenticationPluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            SecretManager::CustomLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::CustomLockUnlockSemantic>()
                    : SecretManager::CustomLockKeepUnlocked;
            int customLockTimeoutMs = request->inParams.size() ? request->inParams.takeFirst().value<int>() : 0;
            SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::AccessControlMode>()
                    : SecretManager::OwnerOnlyMode;
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->createCustomLockCollection(
                        request->remotePid,
                        request->requestId,
                        collectionName,
                        storagePluginName,
                        encryptionPluginName,
                        authenticationPluginName,
                        unlockSemantic,
                        customLockTimeoutMs,
                        accessControlMode,
                        userInteractionMode,
                        interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling DeleteCollectionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString collectionName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            Result result = m_requestProcessor->deleteCollection(
                        request->remotePid,
                        request->requestId,
                        collectionName,
                        userInteractionMode);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetCollectionSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetCollectionSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret secret = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret>()
                    : Secret();
            InteractionParameters uiParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = m_requestProcessor->setCollectionSecret(
                        request->remotePid,
                        request->requestId,
                        secret,
                        uiParams,
                        userInteractionMode,
                        interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetStandaloneDeviceLockSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetStandaloneDeviceLockSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString storagePluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString encryptionPluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Secret secret = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret>()
                    : Secret();
            InteractionParameters uiParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            SecretManager::DeviceLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::DeviceLockUnlockSemantic>()
                    : SecretManager::DeviceLockKeepUnlocked;
            SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::AccessControlMode>()
                    : SecretManager::OwnerOnlyMode;
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = m_requestProcessor->setStandaloneDeviceLockSecret(
                        request->remotePid,
                        request->requestId,
                        storagePluginName,
                        encryptionPluginName,
                        secret,
                        uiParams,
                        unlockSemantic,
                        accessControlMode,
                        userInteractionMode,
                        interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetStandaloneCustomLockSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetStandaloneCustomLockSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString storagePluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString encryptionPluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString authenticationPluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Secret secret = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret>()
                    : Secret();
            InteractionParameters uiParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            SecretManager::CustomLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::CustomLockUnlockSemantic>()
                    : SecretManager::CustomLockKeepUnlocked;
            int customLockTimeoutMs = request->inParams.size() ? request->inParams.takeFirst().value<int>() : 0;
            SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::AccessControlMode>()
                    : SecretManager::OwnerOnlyMode;
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->setStandaloneCustomLockSecret(
                        request->remotePid,
                        request->requestId,
                        storagePluginName,
                        encryptionPluginName,
                        authenticationPluginName,
                        secret,
                        uiParams,
                        unlockSemantic,
                        customLockTimeoutMs,
                        accessControlMode,
                        userInteractionMode,
                        interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case GetCollectionSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling GetCollectionSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::Identifier>()
                    : Secret::Identifier();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Secret secret;
            Result result = m_requestProcessor->getCollectionSecret(
                        request->remotePid,
                        request->requestId,
                        identifier,
                        userInteractionMode,
                        interactionServiceAddress,
                        &secret);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<Secret>(secret));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<Secret>(secret));
                }
                *completed = true;
            }
            break;
        }
        case GetStandaloneSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling GetStandaloneSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::Identifier>()
                    : Secret::Identifier();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Secret secret;
            Result result = m_requestProcessor->getStandaloneSecret(
                        request->remotePid,
                        request->requestId,
                        identifier,
                        userInteractionMode,
                        interactionServiceAddress,
                        &secret);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<Secret>(secret));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<Secret>(secret));
                }
                *completed = true;
            }
            break;
        }
        case FindCollectionSecretsRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling FindCollectionSecretsRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString collectionName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Secret::FilterData filter = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::FilterData >()
                    : Secret::FilterData();
            SecretManager::FilterOperator filterOperator = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::FilterOperator>()
                    : SecretManager::OperatorOr;
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QVector<Secret::Identifier> identifiers;
            Result result = m_requestProcessor->findCollectionSecrets(
                        request->remotePid,
                        request->requestId,
                        collectionName,
                        filter,
                        filterOperator,
                        userInteractionMode,
                        interactionServiceAddress,
                        &identifiers);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                }
                *completed = true;
            }
            break;
        }
        case FindStandaloneSecretsRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling FindStandaloneSecretsRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::FilterData filter = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::FilterData >()
                    : Secret::FilterData();
            SecretManager::FilterOperator filterOperator = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::FilterOperator>()
                    : SecretManager::OperatorOr;
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QVector<Secret::Identifier> identifiers;
            Result result = m_requestProcessor->findStandaloneSecrets(
                        request->remotePid,
                        request->requestId,
                        filter,
                        filterOperator,
                        userInteractionMode,
                        interactionServiceAddress,
                        &identifiers);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling DeleteCollectionSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::Identifier>()
                    : Secret::Identifier();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->deleteCollectionSecret(
                        request->remotePid,
                        request->requestId,
                        identifier,
                        userInteractionMode,
                        interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteStandaloneSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling DeleteStandaloneSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::Identifier>()
                    : Secret::Identifier();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            Result result = m_requestProcessor->deleteStandaloneSecret(
                        request->remotePid,
                        request->requestId,
                        identifier,
                        userInteractionMode);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetCollectionSecretMetadataRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetCollectionSecretMetadataRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::Identifier>()
                    : Secret::Identifier();
            Result result = m_requestProcessor->setCollectionSecretMetadata(
                        request->remotePid,
                        request->requestId,
                        identifier);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                // This request type exists solely to implement Crypto API functionality.
                asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                *completed = true;
            }
            break;
        }
        case DeleteCollectionSecretMetadataRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling DeleteCollectionSecretMetadataRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::Identifier>()
                    : Secret::Identifier();
            Result result = m_requestProcessor->deleteCollectionSecretMetadata(
                        request->remotePid,
                        request->requestId,
                        identifier);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                // This request type exists solely to implement Crypto API functionality.
                asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                *completed = true;
            }
            break;
        }
        case UserInputRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling UserInputRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            InteractionParameters uiParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            Result result = m_requestProcessor->userInput(
                        request->remotePid,
                        request->requestId,
                        uiParams);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                // failed, return error immediately
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        default: {
            qCWarning(lcSailfishSecretsDaemon) << "Cannot handle request:" << request->requestId
                                               << "with invalid type:" << requestTypeToString(request->type);
            *completed = false;
            break;
        }
    }
}

void Daemon::ApiImpl::SecretsRequestQueue::handleFinishedRequest(
        Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GetPluginInfoRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "GetPluginInfoRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray secret = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QByteArray>(secret));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QByteArray>(secret));
                }
                *completed = true;
            }
            break;
        }
        case CollectionNamesRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of CollectionNamesRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "CollectionNamesRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QStringList names = request->outParams.size()
                                  ? request->outParams.takeFirst().value<QStringList>()
                                  : QStringList();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << names);
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QStringList>(names));
                }
                *completed = true;
            }
            break;
        }
        case CreateDeviceLockCollectionRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of CreateDeviceLockCollectionRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "CreateDeviceLockCollectionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case CreateCustomLockCollectionRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of CreateCustomLockCollectionRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "CreateCustomLockCollectionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of DeleteCollectionRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "DeleteCollectionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetCollectionSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SetCollectionSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetCollectionSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetStandaloneDeviceLockSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SetStandaloneDeviceLockSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetStandaloneDeviceLockSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetStandaloneCustomLockSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SetStandaloneCustomLockSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetStandaloneCustomLockSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case GetCollectionSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GetCollectionSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "GetCollectionSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray secret = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QByteArray>(secret));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QByteArray>(secret));
                }
                *completed = true;
            }
            break;
        }
        case GetStandaloneSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GetStandaloneSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "GetStandaloneSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray secret = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QByteArray>(secret));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QByteArray>(secret));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of DeleteCollectionSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "DeleteCollectionSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteStandaloneSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of DeleteStandaloneSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "DeleteStandaloneSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case UserInputRequest: {
            const Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of UserInputRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "UserInputRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                const QByteArray userInput = request->outParams.size()
                        ? request->outParams.takeFirst().value<QByteArray>()
                        : QByteArray();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << userInput);
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QByteArray>(userInput));
                }
                *completed = true;
            }
            break;
        }
        default: {
            qCWarning(lcSailfishSecretsDaemon) << "Cannot handle synchronous request:" << request->requestId << "with type:" << requestTypeToString(request->type) << "in an asynchronous fashion";
            *completed = false;
            break;
        }
    }
}

