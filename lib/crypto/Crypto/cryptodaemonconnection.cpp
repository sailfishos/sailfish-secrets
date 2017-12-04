/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/cryptodaemonconnection.h"
#include "Crypto/cryptodaemonconnection_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/result.h"
#include "Crypto/key.h"
#include "Crypto/certificate.h"
#include "Crypto/extensionplugins.h"

#include <QtDBus/QDBusReply>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusMetaType>

Q_LOGGING_CATEGORY(lcSailfishCryptoDaemonConnection, "org.sailfishos.crypto.daemon.connection", QtWarningMsg)

Sailfish::Crypto::CryptoDaemonConnectionPrivate::CryptoDaemonConnectionPrivate(CryptoDaemonConnection *parent)
    : QObject(parent)
    , m_connection(QLatin1String("org.sailfishos.crypto.daemon.invalidConnection"))
    , m_parent(parent)
{
}

bool Sailfish::Crypto::CryptoDaemonConnectionPrivate::connect()
{
    if (m_connection.isConnected()) {
        return true;
    }

    // Step one: query the crypto daemon's "discovery" SessionBusObject for the PeerToPeer address.
    QDBusInterface iface("org.sailfishos.crypto.daemon.discovery",
                         "/Sailfish/Crypto/Discovery",
                         "org.sailfishos.crypto.daemon.discovery",
                         QDBusConnection::sessionBus());
    if (!iface.isValid()) {
        qCWarning(lcSailfishCryptoDaemonConnection) << "Unable to connect to the crypto daemon discovery service!";
        return false;
    }

    QDBusReply<QString> reply = iface.call("peerToPeerAddress");
    if (!reply.isValid()) {
        qCWarning(lcSailfishCryptoDaemonConnection) << "Unable to query the peer to peer socket address from the crypto daemon!";
        return false;
    }

    // Step two: connect to the PeerToPeer address.
    static int connectionCount = 0;
    const QString address = reply.value();
    const QString name = QString::fromLatin1("sailfishcryptod-connection-%1").arg(connectionCount++);

    qCDebug(lcSailfishCryptoDaemonConnection) << "Connecting to crypto daemon via p2p address:" << address
                                               << "with connection name:" << name;

    QDBusConnection p2pc = QDBusConnection::connectToPeer(address, name);
    if (!p2pc.isConnected()) {
        qCWarning(lcSailfishCryptoDaemonConnection) << "Unable to connect to crypto daemon:" << p2pc.lastError()
                                                     << p2pc.lastError().type() << p2pc.lastError().name();
        return false;
    }

    m_connection = p2pc;
    m_connection.connect(QString(), // any service
                         QLatin1String("/org/freedesktop/DBus/Local"),
                         QLatin1String("org.freedesktop.DBus.Local"),
                         QLatin1String("Disconnected"),
                         this, SLOT(disconnected()));

    qCDebug(lcSailfishCryptoDaemonConnection) << "Connected to crypto daemon via connection:" << m_connection.name();

    return true;
}

void Sailfish::Crypto::CryptoDaemonConnectionPrivate::disconnected()
{
    qCDebug(lcSailfishCryptoDaemonConnection) << "Disconnected from crypto daemon via connection:" << m_connection.name();
    if (!m_parent.isNull()) {
        emit m_parent->disconnected();
    }
}

// -------------------------------------------

Sailfish::Crypto::CryptoDaemonConnection::CryptoDaemonConnection()
    : m_data(Q_NULLPTR)
    , m_refCount(0)
{
    registerDBusTypes();
}

static Sailfish::Crypto::CryptoDaemonConnection *connectionInstance = Q_NULLPTR;
Sailfish::Crypto::CryptoDaemonConnection* Sailfish::Crypto::CryptoDaemonConnection::instance()
{
    if (!connectionInstance) {
        connectionInstance = new Sailfish::Crypto::CryptoDaemonConnection;
    }

    (void)connectionInstance->m_refCount.ref();
    if (!connectionInstance->m_refCount.deref()) {
        connectionInstance->m_data = new Sailfish::Crypto::CryptoDaemonConnectionPrivate(connectionInstance);
    }
    connectionInstance->m_refCount.ref();
    return connectionInstance;
}

void Sailfish::Crypto::CryptoDaemonConnection::releaseInstance()
{
    if (connectionInstance) {
        if (!connectionInstance->m_refCount.deref()) {
            connectionInstance->m_data->deleteLater();
            connectionInstance->m_data = Q_NULLPTR;
            connectionInstance->deleteLater();
        }
    }
}

bool Sailfish::Crypto::CryptoDaemonConnection::connect()
{
    (void)m_refCount.ref();
    if (m_refCount.deref()) {
        return m_data->connect();
    }
    return false;
}

QDBusConnection *Sailfish::Crypto::CryptoDaemonConnection::connection()
{
    (void)m_refCount.ref();
    if (m_refCount.deref()) {
        return m_data->connection();
    }
    return Q_NULLPTR;
}

// caller takes ownership of the returned instance, alternatively it is parented to the given \a parent object.
QDBusInterface *Sailfish::Crypto::CryptoDaemonConnection::createInterface(const QString &objectPath, const QString &interface, QObject *parent)
{
    QDBusInterface *retn = new QDBusInterface("org.sailfishos.crypto.daemon", objectPath, interface, m_data->m_connection, parent);
    retn->setTimeout(180000); // some of the permission flows can take arbitrarily long (user input)
    return retn;
}

void Sailfish::Crypto::CryptoDaemonConnection::registerDBusTypes()
{
    qRegisterMetaType<Sailfish::Crypto::Key::Origin>("Sailfish::Crypto::Key::Origin");
    qRegisterMetaType<Sailfish::Crypto::Key::Algorithm>("Sailfish::Crypto::Key::Algorithm");
    qRegisterMetaType<Sailfish::Crypto::Key::BlockMode>("Sailfish::Crypto::Key::BlockMode");
    qRegisterMetaType<Sailfish::Crypto::Key::EncryptionPadding>("Sailfish::Crypto::Key::EncryptionPadding");
    qRegisterMetaType<Sailfish::Crypto::Key::SignaturePadding>("Sailfish::Crypto::Key::SignaturePadding");
    qRegisterMetaType<Sailfish::Crypto::Key::Digest>("Sailfish::Crypto::Key::Digest");
    qRegisterMetaType<Sailfish::Crypto::Key::Operation>("Sailfish::Crypto::Key::Operation");
    qRegisterMetaType<Sailfish::Crypto::Key::BlockModes>("Sailfish::Crypto::Key::BlockModes");
    qRegisterMetaType<Sailfish::Crypto::Key::EncryptionPaddings>("Sailfish::Crypto::Key::EncryptionPaddings");
    qRegisterMetaType<Sailfish::Crypto::Key::SignaturePaddings>("Sailfish::Crypto::Key::SignaturePaddings");
    qRegisterMetaType<Sailfish::Crypto::Key::Digests>("Sailfish::Crypto::Key::Digests");
    qRegisterMetaType<Sailfish::Crypto::Key::Operations>("Sailfish::Crypto::Key::Operations");
    qRegisterMetaType<Sailfish::Crypto::Key::Identifier>("Sailfish::Crypto::Key::Identifier");
    qRegisterMetaType<QVector<Sailfish::Crypto::Key::Identifier> >("QVector<Sailfish::Crypto::Key::Identifier>");
    qRegisterMetaType<Sailfish::Crypto::Key::FilterData>("Sailfish::Crypto::Key::FilterData");
    qRegisterMetaType<Sailfish::Crypto::Key>("Sailfish::Crypto::Key");
    qRegisterMetaType<Sailfish::Crypto::Certificate>("Sailfish::Crypto::Certificate");
    qRegisterMetaType<QVector<Sailfish::Crypto::Certificate> >("QVector<Sailfish::Crypto::Certificate>");
    qRegisterMetaType<Sailfish::Crypto::Result>("Sailfish::Crypto::Result");
    qRegisterMetaType<Sailfish::Crypto::CryptoPluginInfo>("Sailfish::Crypto::CryptoPluginInfo");
    qRegisterMetaType<QVector<Sailfish::Crypto::CryptoPluginInfo> >("QVector<Sailfish::Crypto::CryptoPluginInfo>");

    qDBusRegisterMetaType<Sailfish::Crypto::Key::Origin>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::Algorithm>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::BlockMode>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::EncryptionPadding>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::SignaturePadding>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::Digest>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::Operation>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::BlockModes>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::EncryptionPaddings>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::SignaturePaddings>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::Digests>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::Operations>();
    qDBusRegisterMetaType<Sailfish::Crypto::Key::Identifier>();
    qDBusRegisterMetaType<QVector<Sailfish::Crypto::Key::Identifier> >();
    qDBusRegisterMetaType<Sailfish::Crypto::Key>();
    qDBusRegisterMetaType<Sailfish::Crypto::Certificate>();
    qDBusRegisterMetaType<QVector<Sailfish::Crypto::Certificate> >();
    qDBusRegisterMetaType<Sailfish::Crypto::Result>();
    qDBusRegisterMetaType<Sailfish::Crypto::CryptoPluginInfo>();
    qDBusRegisterMetaType<QVector<Sailfish::Crypto::CryptoPluginInfo> >();
}
