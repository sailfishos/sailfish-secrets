/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "findsecretsrequestwrapper.h"

#include <QtCore/QVariant>
#include <QtCore/QVariantList>

Sailfish::Secrets::Plugin::KeyIdentifier::KeyIdentifier(const QString &name, const QString &collectionName)
    : m_name(name), m_collectionName(collectionName)
{
}

QString Sailfish::Secrets::Plugin::KeyIdentifier::name() const
{
    return m_name;
}

QString Sailfish::Secrets::Plugin::KeyIdentifier::collectionName() const
{
    return m_collectionName;
}

Sailfish::Secrets::Plugin::FindSecretsRequestWrapper::FindSecretsRequestWrapper(QObject *parent) : Sailfish::Secrets::FindSecretsRequest(parent)
{
    connect(this, &Sailfish::Secrets::FindSecretsRequest::identifiersChanged, this, &Sailfish::Secrets::Plugin::FindSecretsRequestWrapper::identifiersChanged);
}

QVariantList Sailfish::Secrets::Plugin::FindSecretsRequestWrapper::identifiers() const
{
    auto resultsFromBase = Sailfish::Secrets::FindSecretsRequest::identifiers();
    QVariantList results;

    for (auto i : resultsFromBase) {
        results.append(QVariant::fromValue(KeyIdentifier(i.name(), i.collectionName())));
    }

    return results;
}

Sailfish::Secrets::Plugin::PluginInfoRequestWrapper::PluginInfoRequestWrapper(QObject *parent) : Sailfish::Secrets::PluginInfoRequest(parent)
{
    connect(this, &Sailfish::Secrets::PluginInfoRequest::storagePluginsChanged, this, &Sailfish::Secrets::Plugin::PluginInfoRequestWrapper::storagePluginsChanged);
    connect(this, &Sailfish::Secrets::PluginInfoRequest::encryptionPluginsChanged, this, &Sailfish::Secrets::Plugin::PluginInfoRequestWrapper::encryptionPluginsChanged);
    connect(this, &Sailfish::Secrets::PluginInfoRequest::encryptedStoragePluginsChanged, this, &Sailfish::Secrets::Plugin::PluginInfoRequestWrapper::encryptedStoragePluginsChanged);
    connect(this, &Sailfish::Secrets::PluginInfoRequest::authenticationPluginsChanged, this, &Sailfish::Secrets::Plugin::PluginInfoRequestWrapper::authenticationPluginsChanged);
}

QVariantList Sailfish::Secrets::Plugin::PluginInfoRequestWrapper::storagePlugins() const
{
    auto resultsFromBase = Sailfish::Secrets::PluginInfoRequest::storagePlugins();
    QVariantList results;

    for (auto i : resultsFromBase) {
        results.append(QVariant::fromValue(i));
    }

    return results;
}

QVariantList Sailfish::Secrets::Plugin::PluginInfoRequestWrapper::encryptionPlugins() const
{
    auto resultsFromBase = Sailfish::Secrets::PluginInfoRequest::encryptionPlugins();
    QVariantList results;

    for (auto i : resultsFromBase) {
        results.append(QVariant::fromValue(i));
    }

    return results;
}

QVariantList Sailfish::Secrets::Plugin::PluginInfoRequestWrapper::encryptedStoragePlugins() const
{
    auto resultsFromBase = Sailfish::Secrets::PluginInfoRequest::encryptedStoragePlugins();
    QVariantList results;

    for (auto i : resultsFromBase) {
        results.append(QVariant::fromValue(i));
    }

    return results;
}

QVariantList Sailfish::Secrets::Plugin::PluginInfoRequestWrapper::authenticationPlugins() const
{
    auto resultsFromBase = Sailfish::Secrets::PluginInfoRequest::authenticationPlugins();
    QVariantList results;

    for (auto i : resultsFromBase) {
        results.append(QVariant::fromValue(i));
    }

    return results;
}
