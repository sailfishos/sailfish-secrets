/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_PLUGININFO_H
#define LIBSAILFISHCRYPTO_PLUGININFO_H

#include "Crypto/cryptoglobal.h"

#include <QtCore/QString>
#include <QtCore/QMetaType>
#include <QtCore/QSharedDataPointer>

namespace Sailfish {

namespace Crypto {

class PluginInfoPrivate;
class SAILFISH_CRYPTO_API PluginInfo
{
    Q_GADGET
    Q_PROPERTY(QString name READ name WRITE setName)
    Q_PROPERTY(int version READ version WRITE setVersion)

public:
    PluginInfo(const QString &name = QString(), int version = 0);
    PluginInfo(const PluginInfo &other);
    ~PluginInfo();

    PluginInfo &operator=(const Sailfish::Crypto::PluginInfo &other);

    void setName(const QString &name);
    QString name() const;

    void setVersion(int version);
    int version() const;

private:
    QSharedDataPointer<PluginInfoPrivate> d_ptr;
    friend class PluginInfoPrivate;
};

bool operator==(const Sailfish::Crypto::PluginInfo &lhs, const Sailfish::Crypto::PluginInfo &rhs) SAILFISH_CRYPTO_API;
bool operator!=(const Sailfish::Crypto::PluginInfo &lhs, const Sailfish::Crypto::PluginInfo &rhs) SAILFISH_CRYPTO_API;
bool operator<(const Sailfish::Crypto::PluginInfo &lhs, const Sailfish::Crypto::PluginInfo &rhs) SAILFISH_CRYPTO_API;

} // Crypto

} // Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::PluginInfo);
Q_DECLARE_TYPEINFO(Sailfish::Crypto::PluginInfo, Q_MOVABLE_TYPE);

#endif // LIBSAILFISHCRYPTO_PLUGININFO_H
