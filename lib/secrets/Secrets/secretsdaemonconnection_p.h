/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_SECRETSDAEMONCONNECTION_P_H
#define LIBSAILFISHSECRETS_SECRETSDAEMONCONNECTION_P_H

#include "Secrets/secretsdaemonconnection.h"

#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>

#include <QtCore/QObject>
#include <QtCore/QPointer>

namespace Sailfish {

namespace Secrets {

class SecretsDaemonConnection;
class SecretsDaemonConnectionPrivate : public QObject
{
    Q_OBJECT

public:
    SecretsDaemonConnectionPrivate(SecretsDaemonConnection *parent = Q_NULLPTR);
    QDBusConnection *connection() { return &m_connection; }
    bool connect();

public Q_SLOTS:
    void disconnected();

private:
    friend class SecretsDaemonConnection;
    QDBusConnection m_connection;
    QPointer<SecretsDaemonConnection> m_parent;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_SECRETSDAEMONCONNECTION_P_H
