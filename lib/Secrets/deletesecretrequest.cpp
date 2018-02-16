/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/deletesecretrequest.h"
#include "Secrets/deletesecretrequest_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"
#include "Secrets/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Secrets;

DeleteSecretRequestPrivate::DeleteSecretRequestPrivate()
    : m_userInteractionMode(SecretManager::PreventInteraction)
    , m_status(Request::Inactive)
{
}

/*!
 * \class DeleteSecretRequest
 * \brief Allows a client request that a secret be deleted from the system's secure secret storage service
 *
 * If the calling application is the creator of the secret, or alternatively
 * if the user has granted the application permission to delete the secret,
 * then the Secrets service will instruct the storage plugin to delete the secret.
 *
 * If the application is not the creator of the secret and the user has not yet
 * been asked if the application should have permission to delete the secret,
 * then a system-mediated access control UI flow may be triggered
 * to obtain the user's permission (unless the given userInteractionMode() is
 * \c PreventInteraction in which case the request will fail).
 *
 * An example of deleting a secret follows:
 *
 * \code
 * Sailfish::Secrets::SecretManager sm;
 * Sailfish::Secrets::DeleteSecretRequest dsr;
 * dsr.setManager(&sm);
 * dsr.setIdentifier(Sailfish::Secrets::Secret::Identifier("ExampleSecret", "ExampleCollection"));
 * dsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
 * dsr.startRequest(); // status() will change to Finished when complete
 * \endcode
 */

/*!
 * \brief Constructs a new DeleteSecretRequest object with the given \a parent.
 */
DeleteSecretRequest::DeleteSecretRequest(QObject *parent)
    : Request(parent)
    , d_ptr(new DeleteSecretRequestPrivate)
{
}

/*!
 * \brief Destroys the DeleteSecretRequest
 */
DeleteSecretRequest::~DeleteSecretRequest()
{
}

/*!
 * \brief Returns the identifier of the secret which the client wishes to delete
 */
Secret::Identifier DeleteSecretRequest::identifier() const
{
    Q_D(const DeleteSecretRequest);
    return d->m_identifier;
}

/*!
 * \brief Sets the identifier of the secret which the client wishes to delete to \a ident
 */
void DeleteSecretRequest::setIdentifier(const Secret::Identifier &ident)
{
    Q_D(DeleteSecretRequest);
    if (d->m_status != Request::Active && d->m_identifier != ident) {
        d->m_identifier = ident;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit identifierChanged();
    }
}

/*!
 * \brief Returns the user interaction mode required when deleting the secret (e.g. if a custom lock code must be requested from the user)
 */
SecretManager::UserInteractionMode DeleteSecretRequest::userInteractionMode() const
{
    Q_D(const DeleteSecretRequest);
    return d->m_userInteractionMode;
}

/*!
 * \brief Sets the user interaction mode required when deleting the secret (e.g. if a custom lock code must be requested from the user) to \a mode
 */
void DeleteSecretRequest::setUserInteractionMode(SecretManager::UserInteractionMode mode)
{
    Q_D(DeleteSecretRequest);
    if (d->m_status != Request::Active && d->m_userInteractionMode != mode) {
        d->m_userInteractionMode = mode;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit userInteractionModeChanged();
    }
}

Request::Status DeleteSecretRequest::status() const
{
    Q_D(const DeleteSecretRequest);
    return d->m_status;
}

Result DeleteSecretRequest::result() const
{
    Q_D(const DeleteSecretRequest);
    return d->m_result;
}

SecretManager *DeleteSecretRequest::manager() const
{
    Q_D(const DeleteSecretRequest);
    return d->m_manager.data();
}

void DeleteSecretRequest::setManager(SecretManager *manager)
{
    Q_D(DeleteSecretRequest);
    if (d->m_manager.data() != manager) {
        d->m_manager = manager;
        emit managerChanged();
    }
}

void DeleteSecretRequest::startRequest()
{
    Q_D(DeleteSecretRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result> reply = d->m_manager->d_ptr->deleteSecret(
                                                        d->m_identifier,
                                                        d->m_userInteractionMode);
        if (reply.isFinished()
                // work around a bug in QDBusAbstractInterface / QDBusConnection...
                && reply.argumentAt<0>().code() != Sailfish::Secrets::Result::Succeeded) {
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

void DeleteSecretRequest::waitForFinished()
{
    Q_D(DeleteSecretRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
