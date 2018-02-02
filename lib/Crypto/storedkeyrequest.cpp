/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/storedkeyrequest.h"
#include "Crypto/storedkeyrequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

StoredKeyRequestPrivate::StoredKeyRequestPrivate(CryptoManager *manager)
    : m_manager(manager)
    , m_status(Request::Inactive)
{
}

/*!
 * \class StoredKeyRequest
 * \brief Allows a client request a securely-stored key from the system crypto service.
 */

/*!
 * \brief Constructs a new StoredKeyRequest object which interfaces to the system
 *        crypto service via the given \a manager, with the given \a parent.
 */
StoredKeyRequest::StoredKeyRequest(CryptoManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new StoredKeyRequestPrivate(manager))
{
}

/*!
 * \brief Destroys the StoredKeyRequest
 */
StoredKeyRequest::~StoredKeyRequest()
{
}

/*!
 * \brief Returns the identifier of the securely-stored key which the client wishes to retrieve
 */
Key::Identifier StoredKeyRequest::identifier() const
{
    Q_D(const StoredKeyRequest);
    return d->m_identifier;
}


/*!
 * \brief Sets the identifier of the securely-stored key which the client wishes to retrieve to \a ident
 */
void StoredKeyRequest::setIdentifier(const Key::Identifier &ident)
{
    Q_D(StoredKeyRequest);
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
 * \brief Returns the retrieved key
 *
 * Note: this value is only valid if the status of the request is Request::Finished.
 */
Key StoredKeyRequest::storedKey() const
{
    Q_D(const StoredKeyRequest);
    return d->m_storedKey;
}

Request::Status StoredKeyRequest::status() const
{
    Q_D(const StoredKeyRequest);
    return d->m_status;
}

Result StoredKeyRequest::result() const
{
    Q_D(const StoredKeyRequest);
    return d->m_result;
}

void StoredKeyRequest::startRequest()
{
    Q_D(StoredKeyRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, Key> reply =
                d->m_manager->d_ptr->storedKey(d->m_identifier);
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_storedKey = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit storedKeyChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, Key> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_storedKey = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->storedKeyChanged();
            });
        }
    }
}

void StoredKeyRequest::waitForFinished()
{
    Q_D(StoredKeyRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
