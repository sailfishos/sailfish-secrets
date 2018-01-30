/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/encryptrequest.h"
#include "Crypto/encryptrequest_p.h"

#include "Crypto/cryptomanager.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

EncryptRequestPrivate::EncryptRequestPrivate(CryptoManager *manager)
    : m_manager(manager)
    , m_status(Request::Inactive)
{
}

EncryptRequest::EncryptRequest(CryptoManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new EncryptRequestPrivate(manager))
{
}

EncryptRequest::~EncryptRequest()
{
}

QByteArray EncryptRequest::data() const
{
    Q_D(const EncryptRequest);
    return d->m_data;
}

void EncryptRequest::setData(const QByteArray &data)
{
    Q_D(EncryptRequest);
    if (d->m_status != Request::Active && d->m_data != data) {
        d->m_data = data;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit dataChanged();
    }
}

Key EncryptRequest::key() const
{
    Q_D(const EncryptRequest);
    return d->m_key;
}

void EncryptRequest::setKey(const Key &key)
{
    Q_D(EncryptRequest);
    if (d->m_status != Request::Active && d->m_key != key) {
        d->m_key = key;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit keyChanged();
    }
}

Sailfish::Crypto::Key::BlockMode EncryptRequest::blockMode() const
{
    Q_D(const EncryptRequest);
    return d->m_blockMode;
}

void EncryptRequest::setBlockMode(Sailfish::Crypto::Key::BlockMode mode)
{
    Q_D(EncryptRequest);
    if (d->m_status != Request::Active && d->m_blockMode != mode) {
        d->m_blockMode = mode;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit blockModeChanged();
    }
}

Sailfish::Crypto::Key::EncryptionPadding EncryptRequest::padding() const
{
    Q_D(const EncryptRequest);
    return d->m_padding;
}

void EncryptRequest::setPadding(Sailfish::Crypto::Key::EncryptionPadding padding)
{
    Q_D(EncryptRequest);
    if (d->m_status != Request::Active && d->m_padding != padding) {
        d->m_padding = padding;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit paddingChanged();
    }
}

Sailfish::Crypto::Key::Digest EncryptRequest::digest() const
{
    Q_D(const EncryptRequest);
    return d->m_digest;
}

void EncryptRequest::setDigest(Sailfish::Crypto::Key::Digest digest)
{
    Q_D(EncryptRequest);
    if (d->m_status != Request::Active && d->m_digest != digest) {
        d->m_digest = digest;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit digestChanged();
    }
}

QString EncryptRequest::cryptoPluginName() const
{
    Q_D(const EncryptRequest);
    return d->m_cryptoPluginName;
}

void EncryptRequest::setCryptoPluginName(const QString &pluginName)
{
    Q_D(EncryptRequest);
    if (d->m_status != Request::Active && d->m_cryptoPluginName != pluginName) {
        d->m_cryptoPluginName = pluginName;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit cryptoPluginNameChanged();
    }
}

QByteArray EncryptRequest::ciphertext() const
{
    Q_D(const EncryptRequest);
    return d->m_ciphertext;
}

Request::Status EncryptRequest::status() const
{
    Q_D(const EncryptRequest);
    return d->m_status;
}

Result EncryptRequest::result() const
{
    Q_D(const EncryptRequest);
    return d->m_result;
}

void EncryptRequest::startRequest()
{
    Q_D(EncryptRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, QByteArray> reply =
                d->m_manager->encrypt(d->m_data,
                                      d->m_key,
                                      d->m_blockMode,
                                      d->m_padding,
                                      d->m_digest,
                                      d->m_cryptoPluginName);
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_ciphertext = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit ciphertextChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, QByteArray> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_ciphertext = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->ciphertextChanged();
            });
        }
    }
}

void EncryptRequest::waitForFinished()
{
    Q_D(EncryptRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
