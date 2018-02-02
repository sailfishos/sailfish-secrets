/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/validatecertificatechainrequest.h"
#include "Crypto/validatecertificatechainrequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"
#include "Crypto/certificate.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

ValidateCertificateChainRequestPrivate::ValidateCertificateChainRequestPrivate()
    : m_validated(false)
    , m_status(Request::Inactive)
{
}

/*!
 * \class ValidateCertificateChainRequest
 * \brief Allows a client to request the system crypto service to validate a certificate chain's authenticity and validity.
 *
 * The cryptosystem provider identified by the given cryptoPluginName() will perform
 * any cryptographic operations required to validate the authenticity of the certificates.
 */

/*!
 * \brief Constructs a new ValidateCertificateChainRequest object with the given \a parent.
 */
ValidateCertificateChainRequest::ValidateCertificateChainRequest(QObject *parent)
    : Request(parent)
    , d_ptr(new ValidateCertificateChainRequestPrivate)
{
}

/*!
 * \brief Destroys the ValidateCertificateChainRequest
 */
ValidateCertificateChainRequest::~ValidateCertificateChainRequest()
{
}

/*!
 * \brief Returns the name of the crypto plugin which the client wishes to perform the encryption operation
 */
QString ValidateCertificateChainRequest::cryptoPluginName() const
{
    Q_D(const ValidateCertificateChainRequest);
    return d->m_cryptoPluginName;
}

/*!
 * \brief Sets the name of the crypto plugin which the client wishes to perform the encryption operation to \a name
 */
void ValidateCertificateChainRequest::setCryptoPluginName(const QString &name)
{
    Q_D(ValidateCertificateChainRequest);
    if (d->m_status != Request::Active && d->m_cryptoPluginName != name) {
        d->m_cryptoPluginName = name;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit cryptoPluginNameChanged();
    }
}

/*!
 * \brief Returns the chain of certificates that the client wishes to validate
 */
QVector<Certificate> ValidateCertificateChainRequest::certificateChain() const
{
    Q_D(const ValidateCertificateChainRequest);
    return d->m_certificateChain;
}

/*!
 * \brief Sets the chain of certificates that the client wishes to validate to \a chain
 */
void ValidateCertificateChainRequest::setCertificateChain(const QVector<Certificate> &chain)
{
    Q_D(ValidateCertificateChainRequest);
    if (d->m_status != Request::Active && d->m_certificateChain != chain) {
        d->m_certificateChain = chain;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit certificateChainChanged();
    }
}

/*!
 * \brief Returns true if the validity and authenticity of the certificate chain was able to be verified, otherwise false.
 *
 * Note: this value is only valid if the status of the request is Request::Finished.
 */
bool ValidateCertificateChainRequest::validated() const
{
    Q_D(const ValidateCertificateChainRequest);
    return d->m_validated;
}

Request::Status ValidateCertificateChainRequest::status() const
{
    Q_D(const ValidateCertificateChainRequest);
    return d->m_status;
}

Result ValidateCertificateChainRequest::result() const
{
    Q_D(const ValidateCertificateChainRequest);
    return d->m_result;
}

CryptoManager *ValidateCertificateChainRequest::manager() const
{
    Q_D(const ValidateCertificateChainRequest);
    return d->m_manager.data();
}

void ValidateCertificateChainRequest::setManager(CryptoManager *manager)
{
    Q_D(ValidateCertificateChainRequest);
    if (d->m_manager.data() != manager) {
        d->m_manager = manager;
        emit managerChanged();
    }
}

void ValidateCertificateChainRequest::startRequest()
{
    Q_D(ValidateCertificateChainRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, bool> reply =
                d->m_manager->d_ptr->validateCertificateChain(d->m_certificateChain,
                                                              d->m_cryptoPluginName);
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_validated = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit validatedChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, bool> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_validated = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->validatedChanged();
            });
        }
    }
}

void ValidateCertificateChainRequest::waitForFinished()
{
    Q_D(ValidateCertificateChainRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
