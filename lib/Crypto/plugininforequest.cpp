/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/plugininforequest.h"
#include "Crypto/plugininforequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

PluginInfoRequestPrivate::PluginInfoRequestPrivate(CryptoManager *manager)
    : m_manager(manager)
    , m_status(Request::Inactive)
{
}

PluginInfoRequest::PluginInfoRequest(CryptoManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new PluginInfoRequestPrivate(manager))
{
}

PluginInfoRequest::~PluginInfoRequest()
{
}

QVector<Sailfish::Crypto::CryptoPluginInfo> PluginInfoRequest::cryptoPlugins() const
{
    Q_D(const PluginInfoRequest);
    return d->m_cryptoPlugins;
}

QStringList PluginInfoRequest::storagePlugins() const
{
    Q_D(const PluginInfoRequest);
    return d->m_storagePlugins;
}

Request::Status PluginInfoRequest::status() const
{
    Q_D(const PluginInfoRequest);
    return d->m_status;
}

Result PluginInfoRequest::result() const
{
    Q_D(const PluginInfoRequest);
    return d->m_result;
}

void PluginInfoRequest::startRequest()
{
    Q_D(PluginInfoRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, QVector<CryptoPluginInfo>, QStringList> reply =
                d->m_manager->d_ptr->getPluginInfo();
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_cryptoPlugins = reply.argumentAt<1>();
            d->m_storagePlugins = reply.argumentAt<2>();
            emit statusChanged();
            emit resultChanged();
            emit cryptoPluginsChanged();
            emit storagePluginsChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, QVector<CryptoPluginInfo>, QStringList> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_cryptoPlugins = reply.argumentAt<1>();
                this->d_ptr->m_storagePlugins = reply.argumentAt<2>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->cryptoPluginsChanged();
                emit this->storagePluginsChanged();
            });
        }
    }
}

void PluginInfoRequest::waitForFinished()
{
    Q_D(PluginInfoRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
