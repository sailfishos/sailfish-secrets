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
#include "Secrets/secretsdaemonconnection.h"

#include "SecretsImpl/secretsdatabase_p.h"

Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject::SecretsDBusObject(
        Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *parent)
    : QObject(parent)
    , m_requestQueue(parent)
{
}

// retrieve information about available plugins
void Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject::getPluginInfo(
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result,
        QVector<Sailfish::Secrets::StoragePluginInfo> &storagePlugins,
        QVector<Sailfish::Secrets::EncryptionPluginInfo> &encryptionPlugins,
        QVector<Sailfish::Secrets::EncryptedStoragePluginInfo> &encryptedStoragePlugins,
        QVector<Sailfish::Secrets::AuthenticationPluginInfo> &authenticationPlugins)
{
    Q_UNUSED(storagePlugins);           // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(encryptionPlugins);        // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(encryptedStoragePlugins);  // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(authenticationPlugins);    // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    m_requestQueue->handleRequest(Sailfish::Secrets::Daemon::ApiImpl::GetPluginInfoRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// create a DeviceLock-protected collection
void Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject::createCollection(
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(collectionName)
             << QVariant::fromValue<QString>(storagePluginName)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::AccessControlMode>(accessControlMode);
    m_requestQueue->handleRequest(Sailfish::Secrets::Daemon::ApiImpl::CreateDeviceLockCollectionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// create a CustomLock-protected collection
void Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject::createCollection(
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic unlockSemantic,
        int customLockTimeoutMs,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(collectionName)
             << QVariant::fromValue<QString>(storagePluginName)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<QString>(authenticationPluginName)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<int>(customLockTimeoutMs)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::AccessControlMode>(accessControlMode)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Sailfish::Secrets::Daemon::ApiImpl::CreateCustomLockCollectionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// delete a collection
void Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject::deleteCollection(
        const QString &collectionName,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(collectionName)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode);
    m_requestQueue->handleRequest(Sailfish::Secrets::Daemon::ApiImpl::DeleteCollectionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// set a secret in a collection
void Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject::setSecret(
        const Sailfish::Secrets::Secret &secret,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Secrets::Secret>(secret)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Sailfish::Secrets::Daemon::ApiImpl::SetCollectionSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// set a standalone DeviceLock-protected secret
void Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject::setSecret(
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const Sailfish::Secrets::Secret &secret,
        Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(storagePluginName)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<Sailfish::Secrets::Secret>(secret)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::AccessControlMode>(accessControlMode)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode);
    m_requestQueue->handleRequest(Sailfish::Secrets::Daemon::ApiImpl::SetStandaloneDeviceLockSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// set a standalone CustomLock-protected secret
void Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject::setSecret(
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        const Sailfish::Secrets::Secret &secret,
        Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic unlockSemantic,
        int customLockTimeoutMs,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(storagePluginName)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<QString>(authenticationPluginName)
             << QVariant::fromValue<Sailfish::Secrets::Secret>(secret)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<int>(customLockTimeoutMs)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::AccessControlMode>(accessControlMode)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Sailfish::Secrets::Daemon::ApiImpl::SetStandaloneCustomLockSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// get a secret
void Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject::getSecret(
        const Sailfish::Secrets::Secret::Identifier &identifier,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result,
        Sailfish::Secrets::Secret &secret)
{
    Q_UNUSED(secret); // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Secrets::Secret::Identifier>(identifier)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(identifier.identifiesStandaloneSecret()
                                      ? Sailfish::Secrets::Daemon::ApiImpl::GetStandaloneSecretRequest
                                      : Sailfish::Secrets::Daemon::ApiImpl::GetCollectionSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// find secrets via filter
void Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject::findSecrets(
        const QString &collectionName,
        const Sailfish::Secrets::Secret::FilterData &filter,
        Sailfish::Secrets::SecretManager::FilterOperator filterOperator,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result,
        QVector<Sailfish::Secrets::Secret::Identifier> &identifiers)
{
    Q_UNUSED(identifiers); // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    if (!collectionName.isEmpty()) {
        inParams << QVariant::fromValue<QString>(collectionName);
    }
    inParams << QVariant::fromValue<Sailfish::Secrets::Secret::FilterData>(filter)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::FilterOperator>(filterOperator)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(collectionName.isEmpty()
                                      ? Sailfish::Secrets::Daemon::ApiImpl::FindStandaloneSecretsRequest
                                      : Sailfish::Secrets::Daemon::ApiImpl::FindCollectionSecretsRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// delete a secret
void Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject::deleteSecret(
        const Sailfish::Secrets::Secret::Identifier &identifier,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Secrets::Secret::Identifier>(identifier)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(identifier.identifiesStandaloneSecret()
                                      ? Sailfish::Secrets::Daemon::ApiImpl::DeleteStandaloneSecretRequest
                                      : Sailfish::Secrets::Daemon::ApiImpl::DeleteCollectionSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

//-----------------------------------

Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::SecretsRequestQueue(
        Sailfish::Secrets::Daemon::Controller *parent,
        const QString &pluginDir,
        bool autotestMode)
    : Sailfish::Secrets::Daemon::ApiImpl::RequestQueue(
          QLatin1String("/Sailfish/Secrets"),
          QLatin1String("org.sailfishos.secrets"),
          parent,
          pluginDir,
          autotestMode)
{
    Sailfish::Secrets::SecretsDaemonConnection::registerDBusTypes();
    if (!m_db.open(QLatin1String("QSQLITE"),
                   QLatin1String("sailfishsecretsd"),
                   QLatin1String("secrets.db"),
                   setupStatements,
                   createStatements,
                   upgradeVersions,
                   currentSchemaVersion,
                   QLatin1String("sailfishsecretsd"),
                   autotestMode)) {
        qCWarning(lcSailfishSecretsDaemon) << "Secrets: failed to open database!";
        return;
    }

    m_appPermissions = new Sailfish::Secrets::Daemon::ApiImpl::ApplicationPermissions(this);
    m_requestProcessor = new Sailfish::Secrets::Daemon::ApiImpl::RequestProcessor(&m_db, m_appPermissions, autotestMode, this);
    if (!m_requestProcessor->loadPlugins(pluginDir)) {
        qCWarning(lcSailfishSecretsDaemon) << "Secrets: failed to load plugins!";
        return;
    }

    setDBusObject(new Sailfish::Secrets::Daemon::ApiImpl::SecretsDBusObject(this));
    qCDebug(lcSailfishSecretsDaemon) << "Secrets: initialisation succeeded, awaiting client connections.";
}

Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::~SecretsRequestQueue()
{
}

QString Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::requestTypeToString(int type) const
{
    switch (type) {
        case InvalidRequest:                        return QLatin1String("InvalidRequest");
        case GetPluginInfoRequest:                  return QLatin1String("GetPluginInfoRequest");
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

void Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::handlePendingRequest(
        Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling GetPluginInfoRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QVector<Sailfish::Secrets::StoragePluginInfo> storagePlugins;
            QVector<Sailfish::Secrets::EncryptionPluginInfo> encryptionPlugins;
            QVector<Sailfish::Secrets::EncryptedStoragePluginInfo> encryptedStoragePlugins;
            QVector<Sailfish::Secrets::AuthenticationPluginInfo> authenticationPlugins;
            Sailfish::Secrets::Result result = m_requestProcessor->getPluginInfo(
                        request->remotePid,
                        request->requestId,
                        &storagePlugins,
                        &encryptionPlugins,
                        &encryptedStoragePlugins,
                        &authenticationPlugins);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result)
                                                                            << QVariant::fromValue<QVector<Sailfish::Secrets::StoragePluginInfo> >(storagePlugins)
                                                                            << QVariant::fromValue<QVector<Sailfish::Secrets::EncryptionPluginInfo> >(encryptionPlugins)
                                                                            << QVariant::fromValue<QVector<Sailfish::Secrets::EncryptedStoragePluginInfo> >(encryptedStoragePlugins)
                                                                            << QVariant::fromValue<QVector<Sailfish::Secrets::AuthenticationPluginInfo> >(authenticationPlugins));
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
            Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic>()
                    : Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked;
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::AccessControlMode>()
                    : Sailfish::Secrets::SecretManager::OwnerOnlyMode;
            Sailfish::Secrets::Result result = m_requestProcessor->createDeviceLockCollection(
                        request->remotePid,
                        request->requestId,
                        collectionName,
                        storagePluginName,
                        encryptionPluginName,
                        unlockSemantic,
                        accessControlMode);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
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
            Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic>()
                    : Sailfish::Secrets::SecretManager::CustomLockKeepUnlocked;
            int customLockTimeoutMs = request->inParams.size() ? request->inParams.takeFirst().value<int>() : 0;
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::AccessControlMode>()
                    : Sailfish::Secrets::SecretManager::OwnerOnlyMode;
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::UserInteractionMode>()
                    : Sailfish::Secrets::SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Secrets::Result result = m_requestProcessor->createCustomLockCollection(
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
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling DeleteCollectionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString collectionName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::UserInteractionMode>()
                    : Sailfish::Secrets::SecretManager::PreventInteraction;
            Sailfish::Secrets::Result result = m_requestProcessor->deleteCollection(
                        request->remotePid,
                        request->requestId,
                        collectionName,
                        userInteractionMode);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetCollectionSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetCollectionSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Sailfish::Secrets::Secret secret = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::Secret>()
                    : Sailfish::Secrets::Secret();
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::UserInteractionMode>()
                    : Sailfish::Secrets::SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Secrets::Result result = m_requestProcessor->setCollectionSecret(
                        request->remotePid,
                        request->requestId,
                        secret,
                        userInteractionMode,
                        interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetStandaloneDeviceLockSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetStandaloneDeviceLockSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString storagePluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString encryptionPluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Secrets::Secret secret = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::Secret>()
                    : Sailfish::Secrets::Secret();
            Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic>()
                    : Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked;
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::AccessControlMode>()
                    : Sailfish::Secrets::SecretManager::OwnerOnlyMode;
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::UserInteractionMode>()
                    : Sailfish::Secrets::SecretManager::PreventInteraction;
            Sailfish::Secrets::Result result = m_requestProcessor->setStandaloneDeviceLockSecret(
                        request->remotePid,
                        request->requestId,
                        storagePluginName,
                        encryptionPluginName,
                        secret,
                        unlockSemantic,
                        accessControlMode,
                        userInteractionMode);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
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
            Sailfish::Secrets::Secret secret = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::Secret>()
                    : Sailfish::Secrets::Secret();
            Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic>()
                    : Sailfish::Secrets::SecretManager::CustomLockKeepUnlocked;
            int customLockTimeoutMs = request->inParams.size() ? request->inParams.takeFirst().value<int>() : 0;
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::AccessControlMode>()
                    : Sailfish::Secrets::SecretManager::OwnerOnlyMode;
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::UserInteractionMode>()
                    : Sailfish::Secrets::SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Secrets::Result result = m_requestProcessor->setStandaloneCustomLockSecret(
                        request->remotePid,
                        request->requestId,
                        storagePluginName,
                        encryptionPluginName,
                        authenticationPluginName,
                        secret,
                        unlockSemantic,
                        customLockTimeoutMs,
                        accessControlMode,
                        userInteractionMode,
                        interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case GetCollectionSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling GetCollectionSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Sailfish::Secrets::Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::Secret::Identifier>()
                    : Sailfish::Secrets::Secret::Identifier();
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::UserInteractionMode>()
                    : Sailfish::Secrets::SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Secrets::Secret secret;
            Sailfish::Secrets::Result result = m_requestProcessor->getCollectionSecret(
                        request->remotePid,
                        request->requestId,
                        identifier,
                        userInteractionMode,
                        interactionServiceAddress,
                        &secret);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<Sailfish::Secrets::Secret>(secret));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result)
                                                                            << QVariant::fromValue<Sailfish::Secrets::Secret>(secret));
                }
                *completed = true;
            }
            break;
        }
        case GetStandaloneSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling GetStandaloneSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Sailfish::Secrets::Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::Secret::Identifier>()
                    : Sailfish::Secrets::Secret::Identifier();
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::UserInteractionMode>()
                    : Sailfish::Secrets::SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Secrets::Secret secret;
            Sailfish::Secrets::Result result = m_requestProcessor->getStandaloneSecret(
                        request->remotePid,
                        request->requestId,
                        identifier,
                        userInteractionMode,
                        interactionServiceAddress,
                        &secret);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<Sailfish::Secrets::Secret>(secret));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result)
                                                                            << QVariant::fromValue<Sailfish::Secrets::Secret>(secret));
                }
                *completed = true;
            }
            break;
        }
        case FindCollectionSecretsRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling FindCollectionSecretsRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString collectionName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Secrets::Secret::FilterData filter = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::Secret::FilterData >()
                    : Sailfish::Secrets::Secret::FilterData();
            Sailfish::Secrets::SecretManager::FilterOperator filterOperator = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::FilterOperator>()
                    : Sailfish::Secrets::SecretManager::OperatorOr;
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::UserInteractionMode>()
                    : Sailfish::Secrets::SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QVector<Sailfish::Secrets::Secret::Identifier> identifiers;
            Sailfish::Secrets::Result result = m_requestProcessor->findCollectionSecrets(
                        request->remotePid,
                        request->requestId,
                        collectionName,
                        filter,
                        filterOperator,
                        userInteractionMode,
                        interactionServiceAddress,
                        &identifiers);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QVector<Sailfish::Secrets::Secret::Identifier> >(identifiers));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result)
                                                                            << QVariant::fromValue<QVector<Sailfish::Secrets::Secret::Identifier> >(identifiers));
                }
                *completed = true;
            }
            break;
        }
        case FindStandaloneSecretsRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling FindStandaloneSecretsRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Sailfish::Secrets::Secret::FilterData filter = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::Secret::FilterData >()
                    : Sailfish::Secrets::Secret::FilterData();
            Sailfish::Secrets::SecretManager::FilterOperator filterOperator = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::FilterOperator>()
                    : Sailfish::Secrets::SecretManager::OperatorOr;
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::UserInteractionMode>()
                    : Sailfish::Secrets::SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QVector<Sailfish::Secrets::Secret::Identifier> identifiers;
            Sailfish::Secrets::Result result = m_requestProcessor->findStandaloneSecrets(
                        request->remotePid,
                        request->requestId,
                        filter,
                        filterOperator,
                        userInteractionMode,
                        interactionServiceAddress,
                        &identifiers);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QVector<Sailfish::Secrets::Secret::Identifier> >(identifiers));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result)
                                                                            << QVariant::fromValue<QVector<Sailfish::Secrets::Secret::Identifier> >(identifiers));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling DeleteCollectionSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Sailfish::Secrets::Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::Secret::Identifier>()
                    : Sailfish::Secrets::Secret::Identifier();
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::UserInteractionMode>()
                    : Sailfish::Secrets::SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Secrets::Result result = m_requestProcessor->deleteCollectionSecret(
                        request->remotePid,
                        request->requestId,
                        identifier,
                        userInteractionMode,
                        interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteStandaloneSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling DeleteStandaloneSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Sailfish::Secrets::Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::Secret::Identifier>()
                    : Sailfish::Secrets::Secret::Identifier();
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::SecretManager::UserInteractionMode>()
                    : Sailfish::Secrets::SecretManager::PreventInteraction;
            Sailfish::Secrets::Result result = m_requestProcessor->deleteStandaloneSecret(
                        request->remotePid,
                        request->requestId,
                        identifier,
                        userInteractionMode);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetCollectionSecretMetadataRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetCollectionSecretMetadataRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Sailfish::Secrets::Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::Secret::Identifier>()
                    : Sailfish::Secrets::Secret::Identifier();
            Sailfish::Secrets::Result result = m_requestProcessor->setCollectionSecretMetadata(
                        request->remotePid,
                        request->requestId,
                        identifier);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
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
            Sailfish::Secrets::Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Sailfish::Secrets::Secret::Identifier>()
                    : Sailfish::Secrets::Secret::Identifier();
            Sailfish::Secrets::Result result = m_requestProcessor->deleteCollectionSecretMetadata(
                        request->remotePid,
                        request->requestId,
                        identifier);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                // This request type exists solely to implement Crypto API functionality.
                asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
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

void Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::handleFinishedRequest(
        Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            Sailfish::Secrets::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Secrets::Result>()
                    : Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                QLatin1String("Unable to determine result of GetPluginInfoRequest request"));
            if (result.code() == Sailfish::Secrets::Result::Pending) {
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
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result)
                                                                            << QVariant::fromValue<QByteArray>(secret));
                }
                *completed = true;
            }
            break;
        }
        case CreateDeviceLockCollectionRequest: {
            Sailfish::Secrets::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Secrets::Result>()
                    : Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                QLatin1String("Unable to determine result of CreateDeviceLockCollectionRequest request"));
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "CreateDeviceLockCollectionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case CreateCustomLockCollectionRequest: {
            Sailfish::Secrets::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Secrets::Result>()
                    : Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                QLatin1String("Unable to determine result of CreateCustomLockCollectionRequest request"));
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "CreateCustomLockCollectionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionRequest: {
            Sailfish::Secrets::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Secrets::Result>()
                    : Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                QLatin1String("Unable to determine result of DeleteCollectionRequest request"));
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "DeleteCollectionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetCollectionSecretRequest: {
            Sailfish::Secrets::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Secrets::Result>()
                    : Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                QLatin1String("Unable to determine result of SetCollectionSecretRequest request"));
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetCollectionSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetStandaloneDeviceLockSecretRequest: {
            Sailfish::Secrets::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Secrets::Result>()
                    : Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                QLatin1String("Unable to determine result of SetStandaloneDeviceLockSecretRequest request"));
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetStandaloneDeviceLockSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetStandaloneCustomLockSecretRequest: {
            Sailfish::Secrets::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Secrets::Result>()
                    : Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                QLatin1String("Unable to determine result of SetStandaloneCustomLockSecretRequest request"));
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetStandaloneCustomLockSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case GetCollectionSecretRequest: {
            Sailfish::Secrets::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Secrets::Result>()
                    : Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                QLatin1String("Unable to determine result of GetCollectionSecretRequest request"));
            if (result.code() == Sailfish::Secrets::Result::Pending) {
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
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result)
                                                                            << QVariant::fromValue<QByteArray>(secret));
                }
                *completed = true;
            }
            break;
        }
        case GetStandaloneSecretRequest: {
            Sailfish::Secrets::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Secrets::Result>()
                    : Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                QLatin1String("Unable to determine result of GetStandaloneSecretRequest request"));
            if (result.code() == Sailfish::Secrets::Result::Pending) {
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
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result)
                                                                            << QVariant::fromValue<QByteArray>(secret));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionSecretRequest: {
            Sailfish::Secrets::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Secrets::Result>()
                    : Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                QLatin1String("Unable to determine result of DeleteCollectionSecretRequest request"));
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "DeleteCollectionSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteStandaloneSecretRequest: {
            Sailfish::Secrets::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Secrets::Result>()
                    : Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                                QLatin1String("Unable to determine result of DeleteStandaloneSecretRequest request"));
            if (result.code() == Sailfish::Secrets::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "DeleteStandaloneSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Secrets::Result>(result));
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

