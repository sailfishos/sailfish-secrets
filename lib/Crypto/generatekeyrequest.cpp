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

GenerateKeyRequestPrivate::GenerateKeyRequestPrivate(CryptoManager *manager)
    : m_manager(manager)
    , m_status(Request::Inactive)
{
}

/*!
 * \class GenerateKeyRequest
 * \brief Allows a client request that the system crypto service generate a key based on a template.
 */

/*!
 * \brief Constructs a new GenerateKeyRequest object which interfaces to the system
 *        crypto service via the given \a manager, with the given \a parent.
 */
GenerateKeyRequest::GenerateKeyRequest(CryptoManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new GenerateKeyRequestPrivate(manager))
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
                                                 d->m_cryptoPluginName);
        if (reply.isFinished()) {
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
