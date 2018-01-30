/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/signrequest.h"
#include "Crypto/signrequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

SignRequestPrivate::SignRequestPrivate(CryptoManager *manager)
    : m_manager(manager)
    , m_status(Request::Inactive)
{
}

SignRequest::SignRequest(CryptoManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new SignRequestPrivate(manager))
{
}

SignRequest::~SignRequest()
{
}

QByteArray SignRequest::data() const
{
    Q_D(const SignRequest);
    return d->m_data;
}

void SignRequest::setData(const QByteArray &data)
{
    Q_D(SignRequest);
    if (d->m_status != Request::Active && d->m_data != data) {
        d->m_data = data;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit dataChanged();
    }
}

Key SignRequest::key() const
{
    Q_D(const SignRequest);
    return d->m_key;
}

void SignRequest::setKey(const Key &key)
{
    Q_D(SignRequest);
    if (d->m_status != Request::Active && d->m_key != key) {
        d->m_key = key;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit keyChanged();
    }
}

Sailfish::Crypto::Key::SignaturePadding SignRequest::padding() const
{
    Q_D(const SignRequest);
    return d->m_padding;
}

void SignRequest::setPadding(Sailfish::Crypto::Key::SignaturePadding padding)
{
    Q_D(SignRequest);
    if (d->m_status != Request::Active && d->m_padding != padding) {
        d->m_padding = padding;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit paddingChanged();
    }
}

Sailfish::Crypto::Key::Digest SignRequest::digest() const
{
    Q_D(const SignRequest);
    return d->m_digest;
}

void SignRequest::setDigest(Sailfish::Crypto::Key::Digest digest)
{
    Q_D(SignRequest);
    if (d->m_status != Request::Active && d->m_digest != digest) {
        d->m_digest = digest;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit digestChanged();
    }
}

QString SignRequest::cryptoPluginName() const
{
    Q_D(const SignRequest);
    return d->m_cryptoPluginName;
}

void SignRequest::setCryptoPluginName(const QString &pluginName)
{
    Q_D(SignRequest);
    if (d->m_status != Request::Active && d->m_cryptoPluginName != pluginName) {
        d->m_cryptoPluginName = pluginName;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit cryptoPluginNameChanged();
    }
}

QByteArray SignRequest::signature() const
{
    Q_D(const SignRequest);
    return d->m_signature;
}

Request::Status SignRequest::status() const
{
    Q_D(const SignRequest);
    return d->m_status;
}

Result SignRequest::result() const
{
    Q_D(const SignRequest);
    return d->m_result;
}

void SignRequest::startRequest()
{
    Q_D(SignRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, QByteArray> reply =
                d->m_manager->d_ptr->sign(d->m_data,
                                          d->m_key,
                                          d->m_padding,
                                          d->m_digest,
                                          d->m_cryptoPluginName);
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_signature = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit signatureChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, QByteArray> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_signature = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->signatureChanged();
            });
        }
    }
}

void SignRequest::waitForFinished()
{
    Q_D(SignRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
