/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/validatecertificatechainrequest.h"
#include "Crypto/validatecertificatechainrequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/certificate.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

ValidateCertificateChainRequestPrivate::ValidateCertificateChainRequestPrivate(CryptoManager *manager)
    : m_manager(manager)
    , m_validated(false)
    , m_status(Request::Inactive)
{
}

ValidateCertificateChainRequest::ValidateCertificateChainRequest(CryptoManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new ValidateCertificateChainRequestPrivate(manager))
{
}

ValidateCertificateChainRequest::~ValidateCertificateChainRequest()
{
}

QString ValidateCertificateChainRequest::cryptoPluginName() const
{
    Q_D(const ValidateCertificateChainRequest);
    return d->m_cryptoPluginName;
}

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

QVector<Certificate> ValidateCertificateChainRequest::certificateChain() const
{
    Q_D(const ValidateCertificateChainRequest);
    return d->m_certificateChain;
}

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
                d->m_manager->validateCertificateChain(d->m_certificateChain,
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
