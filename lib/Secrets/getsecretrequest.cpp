/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/getsecretrequest.h"
#include "Secrets/getsecretrequest_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"
#include "Secrets/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Secrets;

GetSecretRequestPrivate::GetSecretRequestPrivate(SecretManager *manager)
    : m_manager(manager)
    , m_userInteractionMode(SecretManager::PreventInteraction)
    , m_status(Request::Inactive)
{
}

/*!
 * \class GetSecretRequest
 * \brief Allows a client request a secret from the system's secure secret storage service
 */

/*!
 * \brief Constructs a new GetSecretRequest object which interfaces to the system
 *        crypto service via the given \a manager, with the given \a parent.
 */
GetSecretRequest::GetSecretRequest(SecretManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new GetSecretRequestPrivate(manager))
{
}

/*!
 * \brief Destroys the GetSecretRequest
 */
GetSecretRequest::~GetSecretRequest()
{
}

/*!
 * \brief Returns the identifier of the secret which the client wishes to retrieve
 */
Secret::Identifier GetSecretRequest::identifier() const
{
    Q_D(const GetSecretRequest);
    return d->m_identifier;
}

/*!
 * \brief Sets the identifier of the secret which the client wishes to retrieve to \a ident
 */
void GetSecretRequest::setIdentifier(const Secret::Identifier &ident)
{
    Q_D(GetSecretRequest);
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
 * \brief Returns the secret which was retrieved for the client
 */
Secret GetSecretRequest::secret() const
{
    Q_D(const GetSecretRequest);
    return d->m_secret;
}

/*!
 * \brief Returns the user interaction mode required when retrieving the secret (e.g. if a custom lock code must be requested from the user)
 */
SecretManager::UserInteractionMode GetSecretRequest::userInteractionMode() const
{
    Q_D(const GetSecretRequest);
    return d->m_userInteractionMode;
}

/*!
 * \brief Sets the user interaction mode required when retrieving the secret (e.g. if a custom lock code must be requested from the user) to \a mode
 */
void GetSecretRequest::setUserInteractionMode(SecretManager::UserInteractionMode mode)
{
    Q_D(GetSecretRequest);
    if (d->m_status != Request::Active && d->m_userInteractionMode != mode) {
        d->m_userInteractionMode = mode;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit userInteractionModeChanged();
    }
}

Request::Status GetSecretRequest::status() const
{
    Q_D(const GetSecretRequest);
    return d->m_status;
}

Result GetSecretRequest::result() const
{
    Q_D(const GetSecretRequest);
    return d->m_result;
}

void GetSecretRequest::startRequest()
{
    Q_D(GetSecretRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, Secret> reply = d->m_manager->d_ptr->getSecret(
                                                        d->m_identifier,
                                                        d->m_userInteractionMode);
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_secret = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit secretChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, Secret> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_secret = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->secretChanged();
            });
        }
    }
}

void GetSecretRequest::waitForFinished()
{
    Q_D(GetSecretRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
