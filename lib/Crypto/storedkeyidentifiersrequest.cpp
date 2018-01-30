/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/storedkeyidentifiersrequest.h"
#include "Crypto/storedkeyidentifiersrequest_p.h"

#include "Crypto/cryptomanager.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

StoredKeyIdentifiersRequestPrivate::StoredKeyIdentifiersRequestPrivate(CryptoManager *manager)
    : m_manager(manager)
    , m_status(Request::Inactive)
{
}

StoredKeyIdentifiersRequest::StoredKeyIdentifiersRequest(CryptoManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new StoredKeyIdentifiersRequestPrivate(manager))
{
}

StoredKeyIdentifiersRequest::~StoredKeyIdentifiersRequest()
{
}

QVector<Key::Identifier> StoredKeyIdentifiersRequest::identifiers() const
{
    Q_D(const StoredKeyIdentifiersRequest);
    return d->m_identifiers;
}

Request::Status StoredKeyIdentifiersRequest::status() const
{
    Q_D(const StoredKeyIdentifiersRequest);
    return d->m_status;
}

Result StoredKeyIdentifiersRequest::result() const
{
    Q_D(const StoredKeyIdentifiersRequest);
    return d->m_result;
}

void StoredKeyIdentifiersRequest::startRequest()
{
    Q_D(StoredKeyIdentifiersRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, QVector<Key::Identifier> > reply =
                d->m_manager->storedKeyIdentifiers();
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_identifiers = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit identifiersChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, QVector<Key::Identifier> > reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_identifiers = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->identifiersChanged();
            });
        }
    }
}

void StoredKeyIdentifiersRequest::waitForFinished()
{
    Q_D(StoredKeyIdentifiersRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
