/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/storesecretrequest.h"
#include "Secrets/storesecretrequest_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Secrets;

StoreSecretRequestPrivate::StoreSecretRequestPrivate(SecretManager *manager)
    : m_manager(manager)
    , m_secretStorageType(StoreSecretRequest::CollectionSecret)
    , m_deviceLockUnlockSemantic(SecretManager::DeviceLockKeepUnlocked)
    , m_customLockUnlockSemantic(SecretManager::CustomLockKeepUnlocked)
    , m_accessControlMode(SecretManager::OwnerOnlyMode)
    , m_userInteractionMode(SecretManager::PreventInteraction)
    , m_customLockTimeout(0)
    , m_status(Request::Inactive)
{
}

/*!
 * \class StoreSecretRequest
 * \brief Allows a client request that the system secrets service securely store a secret
 */

/*!
 * \brief Constructs a new StoreSecretRequest object which interfaces to the system
 *        crypto service via the given \a manager, with the given \a parent.
 */
StoreSecretRequest::StoreSecretRequest(SecretManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new StoreSecretRequestPrivate(manager))
{
}

/*!
 * \brief Destroys the StoreSecretRequest
 */
StoreSecretRequest::~StoreSecretRequest()
{
}

/*!
 * \brief Returns the type of storage which will apply to the stored secret
 *
 * A secret whose storage type is StoreSecretRequest::CollectionSecret will
 * be stored in the collection whose name is specified in the secret's
 * identifier's \l{Sailfish::Secrets::Secret::Identifier::collectionName()}
 * field.  The collection will have either a custom lock or device lock
 * depending on the semantics defined for it when it was created.
 *
 * A secret whose storage type is StoreSecretRequest::StandaloneCustomLockSecret
 * will be individually encrypted with the custom lock code, and then the
 * encrypted version will be stored in a standalone, unencrypted collection.
 *
 * A secret whose storage type is StoreSecretRequest::StandaloneDeviceLockSecret
 * will be individually encrypted with the device lock code, and then the
 * encrypted version will be stored in a standalone, unencrypted collection.
 */
StoreSecretRequest::SecretStorageType StoreSecretRequest::secretStorageType() const
{
    Q_D(const StoreSecretRequest);
    return d->m_secretStorageType;
}

/*!
 * \brief Sets the type of storage which will apply to the stored secret to \a type
 */
void StoreSecretRequest::setSecretStorageType(StoreSecretRequest::SecretStorageType type)
{
    Q_D(StoreSecretRequest);
    if (d->m_status != Request::Active && d->m_secretStorageType != type) {
        d->m_secretStorageType = type;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit secretStorageTypeChanged();
    }
}

/*!
 * \brief Returns the name of the storage plugin which the client wishes to use to store the standalone secret
 */
QString StoreSecretRequest::storagePluginName() const
{
    Q_D(const StoreSecretRequest);
    return d->m_storagePluginName;
}

/*!
 * \brief Sets the name of the storage plugin which the client wishes to use to store the standalone secret to \a pluginName
 *
 * Note: this will only apply to secrets whose secretStorageType() is
 * StoreSecretRequest::StandaloneCustomLockSecret or
 * StoreSecretRequest::StandaloneDeviceLockSecret.
 */
void StoreSecretRequest::setStoragePluginName(const QString &pluginName)
{
    Q_D(StoreSecretRequest);
    if (d->m_status != Request::Active && d->m_storagePluginName != pluginName) {
        d->m_storagePluginName = pluginName;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit storagePluginNameChanged();
    }
}

/*!
 * \brief Returns the name of the encryption plugin which the client wishes to use to encrypt the standalone secret
 */
QString StoreSecretRequest::encryptionPluginName() const
{
    Q_D(const StoreSecretRequest);
    return d->m_encryptionPluginName;
}

/*!
 * \brief Sets the name of the encryption plugin which the client wishes to use to encrypt the standalone secret to \a pluginName
 *
 * Note: this will only apply to secrets whose secretStorageType() is
 * StoreSecretRequest::StandaloneCustomLockSecret or
 * StoreSecretRequest::StandaloneDeviceLockSecret.
 */
void StoreSecretRequest::setEncryptionPluginName(const QString &pluginName)
{
    Q_D(StoreSecretRequest);
    if (d->m_status != Request::Active && d->m_encryptionPluginName != pluginName) {
        d->m_encryptionPluginName = pluginName;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit encryptionPluginNameChanged();
    }
}

/*!
 * \brief Returns the name of the authentication plugin which the client wishes to use to authenticate the user (in order to unlock the secret)
 */
QString StoreSecretRequest::authenticationPluginName() const
{
    Q_D(const StoreSecretRequest);
    return d->m_authenticationPluginName;
}

/*!
 * \brief Sets the name of the authentication plugin which the client wishes to use to authenticate the user (in order to unlock the secret) to \a pluginName
 *
 * Note: this will only apply to secrets whose secretStorageType() is StoreSecretRequest::StandaloneCustomLockSecret.
 */
void StoreSecretRequest::setAuthenticationPluginName(const QString &pluginName)
{
    Q_D(StoreSecretRequest);
    if (d->m_status != Request::Active && d->m_authenticationPluginName != pluginName) {
        d->m_authenticationPluginName = pluginName;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit authenticationPluginNameChanged();
    }
}

/*!
 * \brief Returns the secret which the client wishes to store securely
 */
Secret StoreSecretRequest::secret() const
{
    Q_D(const StoreSecretRequest);
    return d->m_secret;
}

/*!
 * \brief Sets the secret which the client wishes to store securely to \a secret
 *
 * Note: if the secretStorageType() is StoreSecretRequest::CollectionSecret, the
 * identifier of the secret must specify a valid collection name.
 * Conversely, if the secretStorageType() is either
 * StoreSecretRequest::StandaloneCustomLockSecret or
 * StoreSecretRequest::StandaloneDeviceLockSecret then the identifier of the
 * secret must not contain any collection name.
 */
void StoreSecretRequest::setSecret(const Secret &secret)
{
    Q_D(StoreSecretRequest);
    if (d->m_status != Request::Active && d->m_secret != secret) {
        d->m_secret = secret;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit secretChanged();
    }
}

/*!
 * \brief Returns the unlock semantic which will apply to the secret if it is protected by the device lock.
 */
SecretManager::DeviceLockUnlockSemantic StoreSecretRequest::deviceLockUnlockSemantic() const
{
    Q_D(const StoreSecretRequest);
    return d->m_deviceLockUnlockSemantic;
}

/*!
 * \brief Sets the unlock semantic which will apply to the secret if it is protected by the device lock to \a semantic.
 *
 * Note: this will only apply to secrets whose secretStorageType() is StoreSecretRequest::StandaloneDeviceLockSecret.
 */
void StoreSecretRequest::setDeviceLockUnlockSemantic(SecretManager::DeviceLockUnlockSemantic semantic)
{
    Q_D(StoreSecretRequest);
    if (d->m_status != Request::Active && d->m_deviceLockUnlockSemantic != semantic) {
        d->m_deviceLockUnlockSemantic = semantic;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit deviceLockUnlockSemanticChanged();
    }
}

/*!
 * \brief Returns the unlock semantic which will apply to the secret if it is protected by a custom lock.
 */
SecretManager::CustomLockUnlockSemantic StoreSecretRequest::customLockUnlockSemantic() const
{
    Q_D(const StoreSecretRequest);
    return d->m_customLockUnlockSemantic;
}

/*!
 * \brief Sets the unlock semantic which will apply to the secret if it is protected by a custom lock to \a semantic.
 *
 * Note: this will only apply to secrets whose secretStorageType() is StoreSecretRequest::StandaloneCustomLockSecret.
 */
void StoreSecretRequest::setCustomLockUnlockSemantic(SecretManager::CustomLockUnlockSemantic semantic)
{
    Q_D(StoreSecretRequest);
    if (d->m_status != Request::Active && d->m_customLockUnlockSemantic != semantic) {
        d->m_customLockUnlockSemantic = semantic;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit customLockUnlockSemanticChanged();
    }
}

/*!
 * \brief Returns the access control mode which will be enforced for the secret
 */
SecretManager::AccessControlMode StoreSecretRequest::accessControlMode() const
{
    Q_D(const StoreSecretRequest);
    return d->m_accessControlMode;
}

/*!
 * \brief Sets the access control mode which will be enforced for the secret to \a mode
 *
 * Note: this will only apply to secrets whose secretStorageType() is
 * StoreSecretRequest::StandaloneCustomLockSecret or
 * StoreSecretRequest::StandaloneDeviceLockSecret.
 */
void StoreSecretRequest::setAccessControlMode(SecretManager::AccessControlMode mode)
{
    Q_D(StoreSecretRequest);
    if (d->m_status != Request::Active && d->m_accessControlMode != mode) {
        d->m_accessControlMode = mode;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit accessControlModeChanged();
    }
}

/*!
 * \brief Returns the user interaction mode required when storing the secret (e.g. if a custom lock code must be requested from the user)
 */
SecretManager::UserInteractionMode StoreSecretRequest::userInteractionMode() const
{
    Q_D(const StoreSecretRequest);
    return d->m_userInteractionMode;
}

/*!
 * \brief Sets the user interaction mode required when storing the secret (e.g. if a custom lock code must be requested from the user) to \a mode
 *
 * Note: this will only apply to secrets whose secretStorageType() is StoreSecretRequest::StandaloneCustomLockSecret.
 */
void StoreSecretRequest::setUserInteractionMode(SecretManager::UserInteractionMode mode)
{
    Q_D(StoreSecretRequest);
    if (d->m_status != Request::Active && d->m_userInteractionMode != mode) {
        d->m_userInteractionMode = mode;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit userInteractionModeChanged();
    }
}

/*!
 * \brief Returns the lock timeout which should apply to the secret
 */
int StoreSecretRequest::customLockTimeout() const
{
    Q_D(const StoreSecretRequest);
    return d->m_customLockTimeout;
}

/*!
 * \brief Sets the lock timeout which should apply to the secret
 *
 * Note: this will only apply to secrets whose secretStorageType() is StoreSecretRequest::StandaloneCustomLockSecret,
 * and whose customLockUnlockSemantic() is SecretManager::CustomLockTimoutRelock.
 */
void StoreSecretRequest::setCustomLockTimeout(int timeout)
{
    Q_D(StoreSecretRequest);
    if (d->m_status != Request::Active && d->m_customLockTimeout != timeout) {
        d->m_customLockTimeout = timeout;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit customLockTimeoutChanged();
    }
}

Request::Status StoreSecretRequest::status() const
{
    Q_D(const StoreSecretRequest);
    return d->m_status;
}

Result StoreSecretRequest::result() const
{
    Q_D(const StoreSecretRequest);
    return d->m_result;
}

void StoreSecretRequest::startRequest()
{
    Q_D(StoreSecretRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result> reply;
        if (d->m_secretStorageType == StoreSecretRequest::CollectionSecret) {
            reply = d->m_manager->setSecret(d->m_secret,
                                            d->m_userInteractionMode);
        } else if (d->m_secretStorageType == StoreSecretRequest::StandaloneCustomLockSecret) {
            reply = d->m_manager->setSecret(d->m_storagePluginName,
                                            d->m_encryptionPluginName,
                                            d->m_authenticationPluginName,
                                            d->m_secret,
                                            d->m_customLockUnlockSemantic,
                                            d->m_customLockTimeout,
                                            d->m_accessControlMode,
                                            d->m_userInteractionMode);
        } else { // StandaloneDeviceLockSecret
            reply = d->m_manager->setSecret(d->m_storagePluginName,
                                            d->m_encryptionPluginName,
                                            d->m_secret,
                                            d->m_deviceLockUnlockSemantic,
                                            d->m_accessControlMode,
                                            d->m_userInteractionMode);
        }

        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            emit statusChanged();
            emit resultChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
            });
        }
    }
}

void StoreSecretRequest::waitForFinished()
{
    Q_D(StoreSecretRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
