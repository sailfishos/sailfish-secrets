/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_PLUGININFO_H
#define LIBSAILFISHSECRETS_PLUGININFO_H

#include "Secrets/secretsglobal.h"

#include <QtCore/QString>
#include <QtCore/QMetaType>
#include <QtCore/QSharedDataPointer>

namespace Sailfish {

namespace Secrets {

class PluginInfoPrivate;
class SAILFISH_SECRETS_API PluginInfo
{
    Q_GADGET
    Q_PROPERTY(QString name READ name WRITE setName)
    Q_PROPERTY(int version READ version WRITE setVersion)

public:
    PluginInfo(const QString &name = QString(), int version = 0);
    PluginInfo(const PluginInfo &other);
    ~PluginInfo();

    PluginInfo &operator=(const Sailfish::Secrets::PluginInfo &other);

    void setName(const QString &name);
    QString name() const;

    void setVersion(int version);
    int version() const;

private:
    QSharedDataPointer<PluginInfoPrivate> d_ptr;
    friend class PluginInfoPrivate;
};

bool operator==(const Sailfish::Secrets::PluginInfo &lhs, const Sailfish::Secrets::PluginInfo &rhs) SAILFISH_SECRETS_API;
bool operator!=(const Sailfish::Secrets::PluginInfo &lhs, const Sailfish::Secrets::PluginInfo &rhs) SAILFISH_SECRETS_API;
bool operator<(const Sailfish::Secrets::PluginInfo &lhs, const Sailfish::Secrets::PluginInfo &rhs) SAILFISH_SECRETS_API;

} // Secrets

} // Sailfish

Q_DECLARE_METATYPE(Sailfish::Secrets::PluginInfo);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::PluginInfo, Q_MOVABLE_TYPE);

#endif // LIBSAILFISHSECRETS_PLUGININFO_H
