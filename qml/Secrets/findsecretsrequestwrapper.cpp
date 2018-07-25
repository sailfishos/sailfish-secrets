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
