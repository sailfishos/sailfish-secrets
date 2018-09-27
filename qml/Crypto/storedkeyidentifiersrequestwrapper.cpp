/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "storedkeyidentifiersrequestwrapper.h"

#include <QtCore/QVariant>
#include <QtCore/QVariantList>

Sailfish::Crypto::Plugin::KeyIdentifier::KeyIdentifier(const QString &name, const QString &collectionName)
    : m_name(name), m_collectionName(collectionName)
{
}

QString Sailfish::Crypto::Plugin::KeyIdentifier::name() const
{
    return m_name;
}

QString Sailfish::Crypto::Plugin::KeyIdentifier::collectionName() const
{
    return m_collectionName;
}

Sailfish::Crypto::Plugin::StoredKeyIdentifiersRequestWrapper::StoredKeyIdentifiersRequestWrapper(QObject *parent) : Sailfish::Crypto::StoredKeyIdentifiersRequest(parent)
{
    connect(this, &Sailfish::Crypto::StoredKeyIdentifiersRequest::identifiersChanged, this, &Sailfish::Crypto::Plugin::StoredKeyIdentifiersRequestWrapper::identifiersChanged);
}

QVariantList Sailfish::Crypto::Plugin::StoredKeyIdentifiersRequestWrapper::identifiers() const
{
    auto resultsFromBase = Sailfish::Crypto::StoredKeyIdentifiersRequest::identifiers();
    QVariantList results;

    for (auto i : resultsFromBase) {
        results.append(QVariant::fromValue(KeyIdentifier(i.name(), i.collectionName())));
    }

    return results;
}

Sailfish::Crypto::Plugin::PluginInfoRequestWrapper::PluginInfoRequestWrapper(QObject *parent) : Sailfish::Crypto::PluginInfoRequest(parent)
{
    connect(this, &Sailfish::Crypto::PluginInfoRequest::cryptoPluginsChanged, this, &Sailfish::Crypto::Plugin::PluginInfoRequestWrapper::cryptoPluginsChanged);
    connect(this, &Sailfish::Crypto::PluginInfoRequest::storagePluginsChanged, this, &Sailfish::Crypto::Plugin::PluginInfoRequestWrapper::storagePluginsChanged);
}

QVariantList Sailfish::Crypto::Plugin::PluginInfoRequestWrapper::cryptoPlugins() const
{
    auto resultsFromBase = Sailfish::Crypto::PluginInfoRequest::cryptoPlugins();
    QVariantList results;

    for (auto i : resultsFromBase) {
        results.append(QVariant::fromValue(i));
    }

    return results;
}

QVariantList Sailfish::Crypto::Plugin::PluginInfoRequestWrapper::storagePlugins() const
{
    auto resultsFromBase = Sailfish::Crypto::PluginInfoRequest::storagePlugins();
    QVariantList results;

    for (auto i : resultsFromBase) {
        results.append(QVariant::fromValue(i));
    }

    return results;
}
