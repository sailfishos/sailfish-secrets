/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/verifyrequest.h"
#include "Crypto/verifyrequest_p.h"

#include "Crypto/cryptomanager.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

VerifyRequestPrivate::VerifyRequestPrivate(CryptoManager *manager)
    : m_manager(manager)
    , m_verified(false)
    , m_status(Request::Inactive)
{
}

VerifyRequest::VerifyRequest(CryptoManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new VerifyRequestPrivate(manager))
{
}

VerifyRequest::~VerifyRequest()
{
}

QByteArray VerifyRequest::data() const
{
    Q_D(const VerifyRequest);
    return d->m_data;
}

void VerifyRequest::setData(const QByteArray &data)
{
    Q_D(VerifyRequest);
    if (d->m_status != Request::Active && d->m_data != data) {
        d->m_data = data;
        if (d->m_verified) {
            d->m_verified = false;
            emit verifiedChanged();
        }
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit dataChanged();
    }
}

Key VerifyRequest::key() const
{
    Q_D(const VerifyRequest);
    return d->m_key;
}

void VerifyRequest::setKey(const Key &key)
{
    Q_D(VerifyRequest);
    if (d->m_status != Request::Active && d->m_key != key) {
        d->m_key = key;
        if (d->m_verified) {
            d->m_verified = false;
            emit verifiedChanged();
        }
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit keyChanged();
    }
}

Sailfish::Crypto::Key::SignaturePadding VerifyRequest::padding() const
{
    Q_D(const VerifyRequest);
    return d->m_padding;
}

void VerifyRequest::setPadding(Sailfish::Crypto::Key::SignaturePadding padding)
{
    Q_D(VerifyRequest);
    if (d->m_status != Request::Active && d->m_padding != padding) {
        d->m_padding = padding;
        if (d->m_verified) {
            d->m_verified = false;
            emit verifiedChanged();
        }
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit paddingChanged();
    }
}

Sailfish::Crypto::Key::Digest VerifyRequest::digest() const
{
    Q_D(const VerifyRequest);
    return d->m_digest;
}

void VerifyRequest::setDigest(Sailfish::Crypto::Key::Digest digest)
{
    Q_D(VerifyRequest);
    if (d->m_status != Request::Active && d->m_digest != digest) {
        d->m_digest = digest;
        if (d->m_verified) {
            d->m_verified = false;
            emit verifiedChanged();
        }
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit digestChanged();
    }
}

QString VerifyRequest::cryptoPluginName() const
{
    Q_D(const VerifyRequest);
    return d->m_cryptoPluginName;
}

void VerifyRequest::setCryptoPluginName(const QString &pluginName)
{
    Q_D(VerifyRequest);
    if (d->m_status != Request::Active && d->m_cryptoPluginName != pluginName) {
        d->m_cryptoPluginName = pluginName;
        if (d->m_verified) {
            d->m_verified = false;
            emit verifiedChanged();
        }
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit cryptoPluginNameChanged();
    }
}

bool VerifyRequest::verified() const
{
    Q_D(const VerifyRequest);
    return d->m_verified;
}

Request::Status VerifyRequest::status() const
{
    Q_D(const VerifyRequest);
    return d->m_status;
}

Result VerifyRequest::result() const
{
    Q_D(const VerifyRequest);
    return d->m_result;
}

void VerifyRequest::startRequest()
{
    Q_D(VerifyRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, bool> reply =
                d->m_manager->verify(d->m_data,
                                     d->m_key,
                                     d->m_padding,
                                     d->m_digest,
                                     d->m_cryptoPluginName);
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_verified = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit verifiedChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, bool> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_verified = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->verifiedChanged();
            });
        }
    }
}

void VerifyRequest::waitForFinished()
{
    Q_D(VerifyRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
