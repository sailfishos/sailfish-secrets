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
#include "Crypto/serialization_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

SignRequestPrivate::SignRequestPrivate()
    : m_padding(CryptoManager::SignaturePaddingUnknown)
    , m_digestFunction(CryptoManager::DigestUnknown)
    , m_status(Request::Inactive)
{
}

/*!
  \class SignRequest
  \brief Allows a client request the system crypto service to sign data with a specific key
 */

/*!
  \brief Constructs a new SignRequest object with the given \a parent.
 */
SignRequest::SignRequest(QObject *parent)
    : Request(parent)
    , d_ptr(new SignRequestPrivate)
{
}

/*!
  \brief Destroys the SignRequest
 */
SignRequest::~SignRequest()
{
}

/*!
  \brief Returns the data which the client wishes the system service to sign
 */
QByteArray SignRequest::data() const
{
    Q_D(const SignRequest);
    return d->m_data;
}

/*!
  \brief Sets the data which the client wishes the system service to sign to \a data
 */
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

/*!
  \brief Returns the key which the client wishes the system service to use to sign the data
 */
Key SignRequest::key() const
{
    Q_D(const SignRequest);
    return d->m_key;
}

/*!
  \brief Sets the key which the client wishes the system service to use to sign the data to \a key
 */
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

/*!
  \brief Returns the signature padding mode which should be used when signing the data
 */
Sailfish::Crypto::CryptoManager::SignaturePadding SignRequest::padding() const
{
    Q_D(const SignRequest);
    return d->m_padding;
}

/*!
  \brief Sets the signature padding mode which should be used when signing the data to \a padding
 */
void SignRequest::setPadding(Sailfish::Crypto::CryptoManager::SignaturePadding padding)
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

/*!
  \brief Returns the digest which should be used to generate the signature
 */
Sailfish::Crypto::CryptoManager::DigestFunction SignRequest::digestFunction() const
{
    Q_D(const SignRequest);
    return d->m_digestFunction;
}

/*!
  \brief Sets the digest which should be used to generate the signature to \a digestFn
 */
void SignRequest::setDigestFunction(Sailfish::Crypto::CryptoManager::DigestFunction digestFn)
{
    Q_D(SignRequest);
    if (d->m_status != Request::Active && d->m_digestFunction != digestFn) {
        d->m_digestFunction = digestFn;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit digestFunctionChanged();
    }
}

/*!
  \brief Returns the name of the crypto plugin which the client wishes to perform the sign operation
 */
QString SignRequest::cryptoPluginName() const
{
    Q_D(const SignRequest);
    return d->m_cryptoPluginName;
}

/*!
  \brief Sets the name of the crypto plugin which the client wishes to perform the sign operation to \a pluginName
 */
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

/*!
  \brief Returns the signature result of the sign operation.

  Note: this value is only valid if the status of the request is Request::Finished.
 */
QByteArray SignRequest::signature() const
{
    Q_D(const SignRequest);
    return d->m_signature;
}

/*!
  \brief Returns the length of the signature result of the sign operation.

  Note: this value is only valid if the status of the request is Request::Finished.
 */
int SignRequest::signatureLength() const
{
    Q_D(const SignRequest);
    return d->m_signature.length();
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

QVariantMap SignRequest::customParameters() const
{
    Q_D(const SignRequest);
    return d->m_customParameters;
}

void SignRequest::setCustomParameters(const QVariantMap &params)
{
    Q_D(SignRequest);
    if (d->m_customParameters != params) {
        d->m_customParameters = params;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit customParametersChanged();
    }
}

CryptoManager *SignRequest::manager() const
{
    Q_D(const SignRequest);
    return d->m_manager.data();
}

void SignRequest::setManager(CryptoManager *manager)
{
    Q_D(SignRequest);
    if (d->m_manager.data() != manager) {
        d->m_manager = manager;
        emit managerChanged();
    }
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
                                          d->m_digestFunction,
                                          d->m_customParameters,
                                          d->m_cryptoPluginName);
        if (!reply.isValid() && !reply.error().message().isEmpty()) {
            d->m_status = Request::Finished;
            d->m_result = Result(Result::CryptoManagerNotInitializedError,
                                 reply.error().message());
            emit statusChanged();
            emit resultChanged();
        } else if (reply.isFinished()
                // work around a bug in QDBusAbstractInterface / QDBusConnection...
                && reply.argumentAt<0>().code() != Sailfish::Crypto::Result::Succeeded) {
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
                if (reply.isError()) {
                    this->d_ptr->m_result = Result(Result::DaemonError,
                                                   reply.error().message());
                } else {
                    this->d_ptr->m_result = reply.argumentAt<0>();
                    this->d_ptr->m_signature = reply.argumentAt<1>();
                }
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
