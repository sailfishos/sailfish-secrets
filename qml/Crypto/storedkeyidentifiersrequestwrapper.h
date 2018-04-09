/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHCRYPTO_QML_STOREDKEYIDENTIFIERSREQUESTWRAPPER_H
#define SAILFISHCRYPTO_QML_STOREDKEYIDENTIFIERSREQUESTWRAPPER_H

#include "Crypto/result.h"
#include "Crypto/key.h"

#include "Crypto/storedkeyidentifiersrequest.h"


namespace Sailfish {

namespace Crypto {

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

class StoredKeyIdentifiersRequestWrapper : public Sailfish::Crypto::StoredKeyIdentifiersRequest {
    Q_OBJECT
    Q_PROPERTY(QVariantList identifiers READ identifiers NOTIFY identifiersChanged)

public:
    StoredKeyIdentifiersRequestWrapper(QObject *parent = Q_NULLPTR);
    QVariantList identifiers() const;

Q_SIGNALS:
    void identifiersChanged();
};

} // Plugin

} // Crypto

} // Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::Plugin::KeyIdentifier)

#endif // SAILFISHCRYPTO_QML_STOREDKEYIDENTIFIERSREQUESTWRAPPER_H
