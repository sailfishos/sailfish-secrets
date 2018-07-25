/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_QML_FINDSECRETSREQUESTWRAPPER_H
#define SAILFISHSECRETS_QML_FINDSECRETSREQUESTWRAPPER_H

#include "Secrets/result.h"
#include "Secrets/secret.h"

#include "Secrets/findsecretsrequest.h"

#include <QtCore/QVariant>
#include <QtCore/QVariantList>

namespace Sailfish {

namespace Secrets {

namespace Plugin {

class KeyIdentifier {
    Q_GADGET
    Q_PROPERTY(QString name READ name CONSTANT)
    Q_PROPERTY(QString collectionName READ collectionName CONSTANT)

public:
    KeyIdentifier() = default;
    KeyIdentifier(const QString &name, const QString &collectionName);
    QString name() const;
    QString collectionName() const;

private:
    QString m_name;
    QString m_collectionName;
};

class FindSecretsRequestWrapper : public Sailfish::Secrets::FindSecretsRequest {
    Q_OBJECT
    Q_PROPERTY(QVariantList identifiers READ identifiers NOTIFY identifiersChanged)

public:
    FindSecretsRequestWrapper(QObject *parent = Q_NULLPTR);
    QVariantList identifiers() const;

Q_SIGNALS:
    void identifiersChanged();
};

} // Plugin

} // Secrets

} // Sailfish

Q_DECLARE_METATYPE(Sailfish::Secrets::Plugin::KeyIdentifier)

#endif // SAILFISHSECRETS_QML_FINDSECRETSREQUESTWRAPPER_H
