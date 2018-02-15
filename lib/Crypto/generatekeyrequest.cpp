/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/generatekeyrequest.h"
#include "Crypto/generatekeyrequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

GenerateKeyRequestPrivate::GenerateKeyRequestPrivate()
    : m_status(Request::Inactive)
{
}

/*!
 * \class GenerateKeyRequest
 * \brief Allows a client request that the system crypto service generate a key based on a template.
 *
 * This key will not be stored securely by the crypto daemon, but instead will
 * be returned in its complete form to the caller.
 */

/*!
 * \brief Constructs a new GenerateKeyRequest object with the given \a parent.
 */
GenerateKeyRequest::GenerateKeyRequest(QObject *parent)
    : Request(parent)
    , d_ptr(new GenerateKeyRequestPrivate)
{
}

/*!
 * \brief Destroys the GenerateKeyRequest
 */
GenerateKeyRequest::~GenerateKeyRequest()
{
}

/*!
 * \brief Returns the name of the crypto plugin which the client wishes to perform the key generation operation
 */
QString GenerateKeyRequest::cryptoPluginName() const
{
    Q_D(const GenerateKeyRequest);
    return d->m_cryptoPluginName;
}

/*!
 * \brief Sets the name of the crypto plugin which the client wishes to perform the key generation operation to \a pluginName
 */
void GenerateKeyRequest::setCryptoPluginName(const QString &pluginName)
{
    Q_D(GenerateKeyRequest);
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
 * \brief Returns the symmetric key derivation parameters which should be used to generate the secret key data
 *
 * These interaction parameters are only meaningful if the template key
 * algorithm is a symmetric cipher algorithm.
 */
Sailfish::Crypto::KeyDerivationParameters
GenerateKeyRequest::keyDerivationParameters() const
{
    Q_D(const GenerateKeyRequest);
    return d->m_skdfParams;
}

/*!
 * \brief Sets the symmetric key derivation parameters which should be used to generate the secret key data to \a params
 */
void GenerateKeyRequest::setKeyDerivationParameters(
        const Sailfish::Crypto::KeyDerivationParameters &params)
{
    Q_D(GenerateKeyRequest);
    if (d->m_status != Request::Active && d->m_skdfParams != params) {
        d->m_skdfParams = params;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit keyDerivationParametersChanged();
    }
}

/*!
 * \brief Returns the key which should be used as a template when generating the full key
 */
Key GenerateKeyRequest::keyTemplate() const
{
    Q_D(const GenerateKeyRequest);
    return d->m_keyTemplate;
}

/*!
 * \brief Sets the key which should be used as a template when generating the full key to \a key
 */
void GenerateKeyRequest::setKeyTemplate(const Key &key)
{
    Q_D(GenerateKeyRequest);
    if (d->m_status != Request::Active && d->m_keyTemplate != key) {
        d->m_keyTemplate = key;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit keyTemplateChanged();
    }
}

/*!
 * \brief Returns the generated key
 *
 * Note: this value is only valid if the status of the request is Request::Finished.
 */
Key GenerateKeyRequest::generatedKey() const
{
    Q_D(const GenerateKeyRequest);
    return d->m_generatedKey;
}

Request::Status GenerateKeyRequest::status() const
{
    Q_D(const GenerateKeyRequest);
    return d->m_status;
}

Result GenerateKeyRequest::result() const
{
    Q_D(const GenerateKeyRequest);
    return d->m_result;
}

CryptoManager *GenerateKeyRequest::manager() const
{
    Q_D(const GenerateKeyRequest);
    return d->m_manager.data();
}

void GenerateKeyRequest::setManager(CryptoManager *manager)
{
    Q_D(GenerateKeyRequest);
    if (d->m_manager.data() != manager) {
        d->m_manager = manager;
        emit managerChanged();
    }
}

void GenerateKeyRequest::startRequest()
{
    Q_D(GenerateKeyRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, Key> reply =
                d->m_manager->d_ptr->generateKey(d->m_keyTemplate,
                                                 d->m_skdfParams,
                                                 d->m_cryptoPluginName);
        if (reply.isFinished()
                // work around a bug in QDBusAbstractInterface / QDBusConnection...
                && reply.argumentAt<0>().code() != Sailfish::Crypto::Result::Succeeded) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_generatedKey = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit generatedKeyChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, Key> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_generatedKey = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->generatedKeyChanged();
            });
        }
    }
}

void GenerateKeyRequest::waitForFinished()
{
    Q_D(GenerateKeyRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
