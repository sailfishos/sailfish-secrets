/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/createcollectionrequest.h"
#include "Secrets/createcollectionrequest_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"
#include "Secrets/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Secrets;

CreateCollectionRequestPrivate::CreateCollectionRequestPrivate(SecretManager *manager)
    : m_manager(manager)
    , m_collectionLockType(CreateCollectionRequest::DeviceLock)
    , m_deviceLockUnlockSemantic(SecretManager::DeviceLockKeepUnlocked)
    , m_customLockUnlockSemantic(SecretManager::CustomLockKeepUnlocked)
    , m_accessControlMode(SecretManager::OwnerOnlyMode)
    , m_userInteractionMode(SecretManager::PreventInteraction)
    , m_customLockTimeout(0)
    , m_status(Request::Inactive)
{
}

/*!
 * \class CreateCollectionRequest
 * \brief Allows a client request that the system secrets service create a collection for secrets storage
 */

/*!
 * \brief Constructs a new CreateCollectionRequest object which interfaces to the system
 *        crypto service via the given \a manager, with the given \a parent.
 */
CreateCollectionRequest::CreateCollectionRequest(SecretManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new CreateCollectionRequestPrivate(manager))
{
}

/*!
 * \brief Destroys the CreateCollectionRequest
 */
CreateCollectionRequest::~CreateCollectionRequest()
{
}

/*!
 * \brief Returns the type of lock which will be applied to the created collection.
 *
 * A collection whose lock type is CreateCollectionRequest::DeviceLock will use the
 * device-lock code for its security, whereas a collection whose lock type is
 * CreateCollectionRequest::CustomLock will use a separate pass phrase, PIN code, or
 * other authentication method.
 */
CreateCollectionRequest::CollectionLockType CreateCollectionRequest::collectionLockType() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_collectionLockType;
}

/*!
 * \brief Sets the type of lock which will be applied to the created collection to \a type
 */
void CreateCollectionRequest::setCollectionLockType(CreateCollectionRequest::CollectionLockType type)
{
    Q_D(CreateCollectionRequest);
    if (d->m_status != Request::Active && d->m_collectionLockType != type) {
        d->m_collectionLockType = type;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit collectionLockTypeChanged();
    }
}

/*!
 * \brief Returns the name of the collection which the client wishes create
 */
QString CreateCollectionRequest::collectionName() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_collectionName;
}

/*!
 * \brief Sets the name of the collection which the client wishes to create to \a name
 */
void CreateCollectionRequest::setCollectionName(const QString &name)
{
    Q_D(CreateCollectionRequest);
    if (d->m_status != Request::Active && d->m_collectionName != name) {
        d->m_collectionName = name;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit collectionNameChanged();
    }
}

/*!
 * \brief Returns the name of the storage plugin which the client wishes to use to create the collection
 */
QString CreateCollectionRequest::storagePluginName() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_storagePluginName;
}

/*!
 * \brief Sets the name of the storage plugin which the client wishes to use to create the collection to \a pluginName
 */
void CreateCollectionRequest::setStoragePluginName(const QString &pluginName)
{
    Q_D(CreateCollectionRequest);
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
 * \brief Returns the name of the encryption plugin which the client wishes to use to encrypt secrets stored in the collection
 */
QString CreateCollectionRequest::encryptionPluginName() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_encryptionPluginName;
}

/*!
 * \brief Sets the name of the encryption plugin which the client wishes to use to encrypt secrets stored in the collection to \a pluginName
 */
void CreateCollectionRequest::setEncryptionPluginName(const QString &pluginName)
{
    Q_D(CreateCollectionRequest);
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
 * \brief Returns the name of the authentication plugin which the client wishes to use to authenticate the user (in order to unlock the collection)
 */
QString CreateCollectionRequest::authenticationPluginName() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_authenticationPluginName;
}

/*!
 * \brief Sets the name of the authentication plugin which the client wishes to use to authenticate the user (in order to unlock the collection) to \a pluginName
 *
 * Note: this will only apply to collections whose collectionLockType() is CreateCollectionRequest::CustomLock.
 */
void CreateCollectionRequest::setAuthenticationPluginName(const QString &pluginName)
{
    Q_D(CreateCollectionRequest);
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
 * \brief Returns the unlock semantic which will apply to the collection if it is protected by the device lock.
 */
SecretManager::DeviceLockUnlockSemantic CreateCollectionRequest::deviceLockUnlockSemantic() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_deviceLockUnlockSemantic;
}

/*!
 * \brief Sets the unlock semantic which will apply to the collection if it is protected by the device lock to \a semantic.
 *
 * Note: this will only apply to collections whose collectionLockType() is CreateCollectionRequest::DeviceLock.
 */
void CreateCollectionRequest::setDeviceLockUnlockSemantic(SecretManager::DeviceLockUnlockSemantic semantic)
{
    Q_D(CreateCollectionRequest);
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
 * \brief Returns the unlock semantic which will apply to the collection if it is protected by a custom lock.
 */
SecretManager::CustomLockUnlockSemantic CreateCollectionRequest::customLockUnlockSemantic() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_customLockUnlockSemantic;
}

/*!
 * \brief Sets the unlock semantic which will apply to the collection if it is protected by a custom lock to \a semantic.
 *
 * Note: this will only apply to collections whose collectionLockType() is CreateCollectionRequest::CustomLock.
 */
void CreateCollectionRequest::setCustomLockUnlockSemantic(SecretManager::CustomLockUnlockSemantic semantic)
{
    Q_D(CreateCollectionRequest);
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
 * \brief Returns the access control mode which will be enforced for the collection
 */
SecretManager::AccessControlMode CreateCollectionRequest::accessControlMode() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_accessControlMode;
}

/*!
 * \brief Sets the access control mode which will be enforced for the collection to \a mode
 */
void CreateCollectionRequest::setAccessControlMode(SecretManager::AccessControlMode mode)
{
    Q_D(CreateCollectionRequest);
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
 * \brief Returns the user interaction mode required when creating the collection (e.g. if a custom lock code must be requested from the user)
 */
SecretManager::UserInteractionMode CreateCollectionRequest::userInteractionMode() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_userInteractionMode;
}

/*!
 * \brief Sets the user interaction mode required when creating the collection (e.g. if a custom lock code must be requested from the user) to \a mode
 *
 * Note: this will only apply to collections whose collectionLockType() is CreateCollectionRequest::CustomLock.
 */
void CreateCollectionRequest::setUserInteractionMode(SecretManager::UserInteractionMode mode)
{
    Q_D(CreateCollectionRequest);
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
 * \brief Returns the lock timeout which should apply to the collection
 */
int CreateCollectionRequest::customLockTimeout() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_customLockTimeout;
}

/*!
 * \brief Sets the lock timeout which should apply to the collection
 *
 * Note: this will only apply to collections whose collectionLockType() is CreateCollectionRequest::CustomLock,
 * and whose customLockUnlockSemantic() is SecretManager::CustomLockTimoutRelock.
 */
void CreateCollectionRequest::setCustomLockTimeout(int timeout)
{
    Q_D(CreateCollectionRequest);
    if (d->m_status != Request::Active && d->m_customLockTimeout != timeout) {
        d->m_customLockTimeout = timeout;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit customLockTimeoutChanged();
    }
}

Request::Status CreateCollectionRequest::status() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_status;
}

Result CreateCollectionRequest::result() const
{
    Q_D(const CreateCollectionRequest);
    return d->m_result;
}

void CreateCollectionRequest::startRequest()
{
    Q_D(CreateCollectionRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result> reply;
        if (d->m_collectionLockType == CreateCollectionRequest::CustomLock) {
            reply = d->m_manager->d_ptr->createCollection(d->m_collectionName,
                                                          d->m_storagePluginName,
                                                          d->m_encryptionPluginName,
                                                          d->m_authenticationPluginName,
                                                          d->m_customLockUnlockSemantic,
                                                          d->m_customLockTimeout,
                                                          d->m_accessControlMode,
                                                          d->m_userInteractionMode);
        } else {
            reply = d->m_manager->d_ptr->createCollection(d->m_collectionName,
                                                          d->m_storagePluginName,
                                                          d->m_encryptionPluginName,
                                                          d->m_deviceLockUnlockSemantic,
                                                          d->m_accessControlMode);
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

void CreateCollectionRequest::waitForFinished()
{
    Q_D(CreateCollectionRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
