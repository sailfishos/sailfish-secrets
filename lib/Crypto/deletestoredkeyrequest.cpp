/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/deletestoredkeyrequest.h"
#include "Crypto/deletestoredkeyrequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

DeleteStoredKeyRequestPrivate::DeleteStoredKeyRequestPrivate(CryptoManager *manager)
    : m_manager(manager)
    , m_status(Request::Inactive)
{
}

/*!
 * \class DeleteStoredKeyRequest
 * \brief Allows a client request that the system crypto service delete a stored key
 */

/*!
 * \brief Constructs a new DeleteStoredKeyRequest object which interfaces to the system
 *        crypto service via the given \a manager, with the given \a parent.
 */
DeleteStoredKeyRequest::DeleteStoredKeyRequest(CryptoManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new DeleteStoredKeyRequestPrivate(manager))
{
}

/*!
 * \brief Destroys the DeleteStoredKeyRequest
 */
DeleteStoredKeyRequest::~DeleteStoredKeyRequest()
{
}

/*!
 * \brief Returns the identifier of the stored key which the client wishes to be deleted
 */
Key::Identifier DeleteStoredKeyRequest::identifier() const
{
    Q_D(const DeleteStoredKeyRequest);
    return d->m_identifier;
}

/*!
 * \brief Sets the identifier of the stored key which the client wishes to be deleted to \a ident
 */
void DeleteStoredKeyRequest::setIdentifier(const Key::Identifier &ident)
{
    Q_D(DeleteStoredKeyRequest);
    if (d->m_status != Request::Active && d->m_identifier != ident) {
        d->m_identifier = ident;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit identifierChanged();
    }
}

Request::Status DeleteStoredKeyRequest::status() const
{
    Q_D(const DeleteStoredKeyRequest);
    return d->m_status;
}

Result DeleteStoredKeyRequest::result() const
{
    Q_D(const DeleteStoredKeyRequest);
    return d->m_result;
}

void DeleteStoredKeyRequest::startRequest()
{
    Q_D(DeleteStoredKeyRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result> reply =
                d->m_manager->d_ptr->deleteStoredKey(d->m_identifier);
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

void DeleteStoredKeyRequest::waitForFinished()
{
    Q_D(DeleteStoredKeyRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
