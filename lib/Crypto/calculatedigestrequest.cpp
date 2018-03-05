/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/calculatedigestrequest.h"
#include "Crypto/calculatedigestrequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

CalculateDigestRequestPrivate::CalculateDigestRequestPrivate()
    : m_status(Request::Inactive)
{
}

/*!
 * \class CalculateDigestRequest
 * \brief Allows a client request the system crypto service to calculate a digest from data
 *
 * A digest is calculated using a digest function.  Unlike a signature
 * (see SignRequest) no key is required to calculate a digest.
 * A digest can be used to verify that data has not been changed,
 * however it cannot be used to verify the provenance of the data
 * (that is, it can be used to ensure integrity but not authenticity
 * or non-repudiation).
 */

/*!
 * \brief Constructs a new CalculateDigestRequest object with the given \a parent.
 */
CalculateDigestRequest::CalculateDigestRequest(QObject *parent)
    : Request(parent)
    , d_ptr(new CalculateDigestRequestPrivate)
{
}

/*!
 * \brief Destroys the CalculateDigestRequest
 */
CalculateDigestRequest::~CalculateDigestRequest()
{
}

/*!
 * \brief Returns the data which the client wishes the system service to calculate the digest from
 */
QByteArray CalculateDigestRequest::data() const
{
    Q_D(const CalculateDigestRequest);
    return d->m_data;
}

/*!
 * \brief Sets the data which the client wishes the system service to calculate the digest from to \a data
 */
void CalculateDigestRequest::setData(const QByteArray &data)
{
    Q_D(CalculateDigestRequest);
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
 * \brief Returns the signature padding mode which should be used when calculating the digest of the data
 */
Sailfish::Crypto::CryptoManager::SignaturePadding CalculateDigestRequest::padding() const
{
    Q_D(const CalculateDigestRequest);
    return d->m_padding;
}

/*!
 * \brief Sets the signature padding mode which should be used when calculating the digest of the data to \a padding
 */
void CalculateDigestRequest::setPadding(Sailfish::Crypto::CryptoManager::SignaturePadding padding)
{
    Q_D(CalculateDigestRequest);
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
 * \brief Returns the digest function which should be used to generate the digest
 */
Sailfish::Crypto::CryptoManager::DigestFunction CalculateDigestRequest::digestFunction() const
{
    Q_D(const CalculateDigestRequest);
    return d->m_digestFunction;
}

/*!
 * \brief Sets the digest function which should be used to generate the digest to \a digestFunction
 */
void CalculateDigestRequest::setDigestFunction(Sailfish::Crypto::CryptoManager::DigestFunction digestFunction)
{
    Q_D(CalculateDigestRequest);
    if (d->m_status != Request::Active && d->m_digestFunction != digestFunction) {
        d->m_digestFunction = digestFunction;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit digestFunctionChanged();
    }
}

/*!
 * \brief Returns the name of the crypto plugin which the client wishes to perform the digest calculation operation
 */
QString CalculateDigestRequest::cryptoPluginName() const
{
    Q_D(const CalculateDigestRequest);
    return d->m_cryptoPluginName;
}

/*!
 * \brief Sets the name of the crypto plugin which the client wishes to perform the digest calculation operation to \a pluginName
 */
void CalculateDigestRequest::setCryptoPluginName(const QString &pluginName)
{
    Q_D(CalculateDigestRequest);
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
 * \brief Returns the digest result of the calculate digest operation.
 *
 * Note: this value is only valid if the status of the request is Request::Finished.
 */
QByteArray CalculateDigestRequest::digest() const
{
    Q_D(const CalculateDigestRequest);
    return d->m_digest;
}

Request::Status CalculateDigestRequest::status() const
{
    Q_D(const CalculateDigestRequest);
    return d->m_status;
}

Result CalculateDigestRequest::result() const
{
    Q_D(const CalculateDigestRequest);
    return d->m_result;
}

CryptoManager *CalculateDigestRequest::manager() const
{
    Q_D(const CalculateDigestRequest);
    return d->m_manager.data();
}

void CalculateDigestRequest::setManager(CryptoManager *manager)
{
    Q_D(CalculateDigestRequest);
    if (d->m_manager.data() != manager) {
        d->m_manager = manager;
        emit managerChanged();
    }
}

void CalculateDigestRequest::startRequest()
{
    Q_D(CalculateDigestRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, QByteArray> reply =
                d->m_manager->d_ptr->calculateDigest(d->m_data,
                                                     d->m_padding,
                                                     d->m_digestFunction,
                                                     d->m_cryptoPluginName);
        if (!reply.isValid() && !reply.error().message().isEmpty()) {
            d->m_status = Request::Finished;
            d->m_result = Result(Result::CryptoManagerNotInitialisedError,
                                 reply.error().message());
            emit statusChanged();
            emit resultChanged();
        } else if (reply.isFinished()
                // work around a bug in QDBusAbstractInterface / QDBusConnection...
                && reply.argumentAt<0>().code() != Sailfish::Crypto::Result::Succeeded) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_digest = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit digestChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, QByteArray> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_digest = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->digestChanged();
            });
        }
    }
}

void CalculateDigestRequest::waitForFinished()
{
    Q_D(CalculateDigestRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
