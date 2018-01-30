/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/generatestoredkeyrequest.h"
#include "Crypto/generatestoredkeyrequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

GenerateStoredKeyRequestPrivate::GenerateStoredKeyRequestPrivate(CryptoManager *manager)
    : m_manager(manager)
    , m_status(Request::Inactive)
{
}

GenerateStoredKeyRequest::GenerateStoredKeyRequest(CryptoManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new GenerateStoredKeyRequestPrivate(manager))
{
}

GenerateStoredKeyRequest::~GenerateStoredKeyRequest()
{
}

QString GenerateStoredKeyRequest::cryptoPluginName() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_cryptoPluginName;
}

void GenerateStoredKeyRequest::setCryptoPluginName(const QString &pluginName)
{
    Q_D(GenerateStoredKeyRequest);
    if (d->m_status != Request::Active && d->m_cryptoPluginName != pluginName) {
        d->m_cryptoPluginName = pluginName;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit cryptoPluginNameChanged();
    }
}

QString GenerateStoredKeyRequest::storagePluginName() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_storagePluginName;
}

void GenerateStoredKeyRequest::setStoragePluginName(const QString &pluginName)
{
    Q_D(GenerateStoredKeyRequest);
    if (d->m_status != Request::Active && d->m_storagePluginName != pluginName) {
        d->m_storagePluginName = pluginName;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit storagePluginNameChanged();
    }
}

Key GenerateStoredKeyRequest::keyTemplate() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_keyTemplate;
}

void GenerateStoredKeyRequest::setKeyTemplate(const Key &key)
{
    Q_D(GenerateStoredKeyRequest);
    if (d->m_status != Request::Active && d->m_keyTemplate != key) {
        d->m_keyTemplate = key;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit keyTemplateChanged();
    }
}

Key GenerateStoredKeyRequest::generatedKeyReference() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_generatedKeyReference;
}

Request::Status GenerateStoredKeyRequest::status() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_status;
}

Result GenerateStoredKeyRequest::result() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_result;
}

void GenerateStoredKeyRequest::startRequest()
{
    Q_D(GenerateStoredKeyRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, Key> reply =
                d->m_manager->d_ptr->generateStoredKey(d->m_keyTemplate,
                                                       d->m_cryptoPluginName,
                                                       d->m_storagePluginName);
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_generatedKeyReference = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit generatedKeyReferenceChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, Key> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_generatedKeyReference = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->generatedKeyReferenceChanged();
            });
        }
    }
}

void GenerateStoredKeyRequest::waitForFinished()
{
    Q_D(GenerateStoredKeyRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
