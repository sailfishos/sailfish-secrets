/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/decryptrequest.h"
#include "Crypto/decryptrequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

DecryptRequestPrivate::DecryptRequestPrivate(CryptoManager *manager)
    : m_manager(manager)
    , m_status(Request::Inactive)
{
}

/*!
 * \class DecryptRequest
 * \brief Allows a client request that the system crypto service decrypt data with a specific key.
 */

/*!
 * \brief Constructs a new DecryptRequest object which interfaces to the system
 *        crypto service via the given \a manager, with the given \a parent.
 */
DecryptRequest::DecryptRequest(CryptoManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new DecryptRequestPrivate(manager))
{
}

/*!
 * \brief Destroys the DecryptRequest
 */
DecryptRequest::~DecryptRequest()
{
}

/*!
 * \brief Returns the data which the client wishes to decrypt
 */
QByteArray DecryptRequest::data() const
{
    Q_D(const DecryptRequest);
    return d->m_data;
}

/*!
 * \brief Sets the data which the client wishes to decrypt to \a data
 */
void DecryptRequest::setData(const QByteArray &data)
{
    Q_D(DecryptRequest);
    if (d->m_status != Request::Active && d->m_data != data) {
        d->m_data = data;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit dataChanged();
    }
}

/*!
 * \brief Returns the key the client wishes to be used to decrypt data
 */
Key DecryptRequest::key() const
{
    Q_D(const DecryptRequest);
    return d->m_key;
}

/*!
 * \brief Sets the key the client wishes to be used to decrypt data to \a key
 */
void DecryptRequest::setKey(const Key &key)
{
    Q_D(DecryptRequest);
    if (d->m_status != Request::Active && d->m_key != key) {
        d->m_key = key;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit keyChanged();
    }
}

/*!
 * \brief Returns the block mode to be used when decrypting the data
 */
Sailfish::Crypto::Key::BlockMode DecryptRequest::blockMode() const
{
    Q_D(const DecryptRequest);
    return d->m_blockMode;
}

/*!
 * \brief Sets the block mode to be used when decrypting the data to the given \a mode
 */
void DecryptRequest::setBlockMode(Sailfish::Crypto::Key::BlockMode mode)
{
    Q_D(DecryptRequest);
    if (d->m_status != Request::Active && d->m_blockMode != mode) {
        d->m_blockMode = mode;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit blockModeChanged();
    }
}

/*!
 * \brief Returns the encryption padding mode to be used when decrypting the data
 */
Sailfish::Crypto::Key::EncryptionPadding DecryptRequest::padding() const
{
    Q_D(const DecryptRequest);
    return d->m_padding;
}

/*!
 * \brief Sets the encryption padding mode to be used when decrypting the data to the given \a padding
 */
void DecryptRequest::setPadding(Sailfish::Crypto::Key::EncryptionPadding padding)
{
    Q_D(DecryptRequest);
    if (d->m_status != Request::Active && d->m_padding != padding) {
        d->m_padding = padding;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit paddingChanged();
    }
}

/*!
 * \brief Returns the digest used to hash the encrypted data
 */
Sailfish::Crypto::Key::Digest DecryptRequest::digest() const
{
    Q_D(const DecryptRequest);
    return d->m_digest;
}

/*!
 * \brief Sets the digest used to hash the encrypted data to the given \a digest
 */
void DecryptRequest::setDigest(Sailfish::Crypto::Key::Digest digest)
{
    Q_D(DecryptRequest);
    if (d->m_status != Request::Active && d->m_digest != digest) {
        d->m_digest = digest;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit digestChanged();
    }
}

/*!
 * \brief Returns the name of the crypto plugin which the client wishes to perform the decryption operation
 */
QString DecryptRequest::cryptoPluginName() const
{
    Q_D(const DecryptRequest);
    return d->m_cryptoPluginName;
}

/*!
 * \brief Sets the name of the crypto plugin which the client wishes to perform the decryption operation to \a pluginName
 */
void DecryptRequest::setCryptoPluginName(const QString &pluginName)
{
    Q_D(DecryptRequest);
    if (d->m_status != Request::Active && d->m_cryptoPluginName != pluginName) {
        d->m_cryptoPluginName = pluginName;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit cryptoPluginNameChanged();
    }
}

/*!
 * \brief Returns the plaintext result of the decryption operation.
 *
 * Note: this value is only valid if the status of the request is Request::Finished.
 */
QByteArray DecryptRequest::plaintext() const
{
    Q_D(const DecryptRequest);
    return d->m_plaintext;
}

Request::Status DecryptRequest::status() const
{
    Q_D(const DecryptRequest);
    return d->m_status;
}

Result DecryptRequest::result() const
{
    Q_D(const DecryptRequest);
    return d->m_result;
}

void DecryptRequest::startRequest()
{
    Q_D(DecryptRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, QByteArray> reply =
                d->m_manager->d_ptr->decrypt(d->m_data,
                                             d->m_key,
                                             d->m_blockMode,
                                             d->m_padding,
                                             d->m_digest,
                                             d->m_cryptoPluginName);
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_plaintext = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit plaintextChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, QByteArray> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_plaintext = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->plaintextChanged();
            });
        }
    }
}

void DecryptRequest::waitForFinished()
{
    Q_D(DecryptRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
