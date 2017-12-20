/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_DAEMON_DISCOVERYOBJECT_P_H
#define SAILFISHSECRETS_DAEMON_DISCOVERYOBJECT_P_H

#include <QtDBus/QDBusConnection>

#include <QtCore/QObject>
#include <QtCore/QString>

#include "controller_p.h"
#include "logging_p.h"

namespace Sailfish {

namespace Secrets {

namespace Daemon {

// The DiscoveryObject exposes to clients the address of the peer to peer object
// via the DBus session bus.
class DiscoveryObject : public QObject
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.sailfishos.secrets.daemon.discovery")
    Q_CLASSINFO("D-Bus Introspection", ""
    "  <interface name=\"org.sailfishos.secrets.daemon.discovery\">\n"
    "      <method name=\"peerToPeerAddress\">\n"
    "          <arg name=\"address\" type=\"s\" direction=\"out\" />\n"
    "      </method>\n"
    "  </interface>\n"
    "")

public:
    DiscoveryObject(Sailfish::Secrets::Daemon::Controller *parent)
        : QObject(parent)
        , m_parent(parent)
        , m_registered(false) {}

    void setPeerToPeerAddress(const QString &p2pAddress) { m_p2pAddress = p2pAddress; }
    bool registerObject(const QString &serviceName, const QString &objectPath) {
        if (m_registered) {
            return true;
        }

        if (!QDBusConnection::sessionBus().registerObject(objectPath, this, QDBusConnection::ExportAllSlots)) {
            qCWarning(lcSailfishSecretsDaemonDBus) << "Unable to register session bus service:" << serviceName << "at path:" << objectPath;
            return false;
        }

        if (!QDBusConnection::sessionBus().registerService(serviceName)) {
            qCWarning(lcSailfishSecretsDaemonDBus) << "Unable to register session bus service:" << serviceName;
            return false;
        }

        m_registered = true;
        return true;
    }

public Q_SLOTS:
    QString peerToPeerAddress() const { return m_p2pAddress; }

private:
    Sailfish::Secrets::Daemon::Controller *m_parent;
    QString m_p2pAddress;
    bool m_registered;
};

} // Daemon

} // Secrets

namespace Crypto {

namespace Daemon {

// The DiscoveryObject exposes to clients the address of the peer to peer object
// via the DBus session bus.
class DiscoveryObject : public QObject
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.sailfishos.crypto.daemon.discovery")
    Q_CLASSINFO("D-Bus Introspection", ""
    "  <interface name=\"org.sailfishos.crypto.daemon.discovery\">\n"
    "      <method name=\"peerToPeerAddress\">\n"
    "          <arg name=\"address\" type=\"s\" direction=\"out\" />\n"
    "      </method>\n"
    "  </interface>\n"
    "")

public:
    DiscoveryObject(Sailfish::Secrets::Daemon::Controller *parent)
        : QObject(parent)
        , m_parent(parent)
        , m_registered(false) {}

    void setPeerToPeerAddress(const QString &p2pAddress) { m_p2pAddress = p2pAddress; }
    bool registerObject(const QString &serviceName, const QString &objectPath) {
        if (m_registered) {
            return true;
        }

        if (!QDBusConnection::sessionBus().registerObject(objectPath, this, QDBusConnection::ExportAllSlots)) {
            qCWarning(lcSailfishCryptoDaemonDBus) << "Unable to register session bus service:" << serviceName << "at path:" << objectPath;
            return false;
        }

        if (!QDBusConnection::sessionBus().registerService(serviceName)) {
            qCWarning(lcSailfishCryptoDaemonDBus) << "Unable to register session bus service:" << serviceName;
            return false;
        }

        m_registered = true;
        return true;
    }

public Q_SLOTS:
    QString peerToPeerAddress() const { return m_p2pAddress; }

private:
    Sailfish::Secrets::Daemon::Controller *m_parent;
    QString m_p2pAddress;
    bool m_registered;
};

} // Daemon

} // Crypto

} // Sailfish

#endif // SAILFISHSECRETS_DAEMON_DISCOVERYOBJECT_P_H
