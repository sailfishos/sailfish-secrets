/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/secretsdaemonconnection_p.h"
#include "Secrets/secretsdaemonconnection_p_p.h"
#include "Secrets/serialisation_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/interactionrequest.h"
#include "Secrets/extensionplugins.h"
#include "Secrets/result.h"
#include "Secrets/secret.h"

#include <QtDBus/QDBusReply>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusMetaType>

Q_LOGGING_CATEGORY(lcSailfishSecretsDaemonConnection, "org.sailfishos.secrets.daemon.connection", QtWarningMsg)

Sailfish::Secrets::SecretsDaemonConnectionPrivate::SecretsDaemonConnectionPrivate(SecretsDaemonConnection *parent)
    : QObject(parent)
    , m_connection(QLatin1String("org.sailfishos.secrets.daemon.invalidConnection"))
    , m_parent(parent)
{
}

bool Sailfish::Secrets::SecretsDaemonConnectionPrivate::connect()
{
    if (m_connection.isConnected()) {
        return true;
    }

    // Step one: query the secret daemon's "discovery" SessionBusObject for the PeerToPeer address.
    QDBusInterface iface("org.sailfishos.secrets.daemon.discovery",
                         "/Sailfish/Secrets/Discovery",
                         "org.sailfishos.secrets.daemon.discovery",
                         QDBusConnection::sessionBus());
    if (!iface.isValid()) {
        qCWarning(lcSailfishSecretsDaemonConnection) << "Unable to connect to the secrets daemon discovery service!";
        return false;
    }

    QDBusReply<QString> reply = iface.call("peerToPeerAddress");
    if (!reply.isValid()) {
        qCWarning(lcSailfishSecretsDaemonConnection) << "Unable to query the peer to peer socket address from the secrets daemon!";
        return false;
    }

    // Step two: connect to the PeerToPeer address.
    static int connectionCount = 0;
    const QString address = reply.value();
    const QString name = QString::fromLatin1("sailfishsecretsd-connection-%1").arg(connectionCount++);

    qCDebug(lcSailfishSecretsDaemonConnection) << "Connecting to secrets daemon via p2p address:" << address
                                               << "with connection name:" << name;

    QDBusConnection p2pc = QDBusConnection::connectToPeer(address, name);
    if (!p2pc.isConnected()) {
        qCWarning(lcSailfishSecretsDaemonConnection) << "Unable to connect to secrets daemon:" << p2pc.lastError()
                                                     << p2pc.lastError().type() << p2pc.lastError().name();
        return false;
    }

    m_connection = p2pc;
    m_connection.connect(QString(), // any service
                         QLatin1String("/org/freedesktop/DBus/Local"),
                         QLatin1String("org.freedesktop.DBus.Local"),
                         QLatin1String("Disconnected"),
                         this, SLOT(disconnected()));

    qCDebug(lcSailfishSecretsDaemonConnection) << "Connected to secrets daemon via connection:" << m_connection.name();

    return true;
}

void Sailfish::Secrets::SecretsDaemonConnectionPrivate::disconnected()
{
    qCDebug(lcSailfishSecretsDaemonConnection) << "Disconnected from secrets daemon via connection:" << m_connection.name();
    if (!m_parent.isNull()) {
        emit m_parent->disconnected();
    }
}

// -------------------------------------------

Sailfish::Secrets::SecretsDaemonConnection::SecretsDaemonConnection()
    : m_data(Q_NULLPTR)
    , m_refCount(0)
{
    registerDBusTypes();
}

static Sailfish::Secrets::SecretsDaemonConnection *connectionInstance = Q_NULLPTR;
Sailfish::Secrets::SecretsDaemonConnection* Sailfish::Secrets::SecretsDaemonConnection::instance()
{
    if (!connectionInstance) {
        connectionInstance = new Sailfish::Secrets::SecretsDaemonConnection;
    }

    (void)connectionInstance->m_refCount.ref();
    if (!connectionInstance->m_refCount.deref()) {
        connectionInstance->m_data = new Sailfish::Secrets::SecretsDaemonConnectionPrivate(connectionInstance);
    }
    connectionInstance->m_refCount.ref();
    return connectionInstance;
}

void Sailfish::Secrets::SecretsDaemonConnection::releaseInstance()
{
    if (connectionInstance) {
        if (!connectionInstance->m_refCount.deref()) {
            connectionInstance->m_data->deleteLater();
            connectionInstance->m_data = Q_NULLPTR;
            connectionInstance->deleteLater();
        }
    }
}

bool Sailfish::Secrets::SecretsDaemonConnection::connect()
{
    (void)m_refCount.ref();
    if (m_refCount.deref()) {
        return m_data->connect();
    }
    return false;
}

QDBusConnection *Sailfish::Secrets::SecretsDaemonConnection::connection()
{
    (void)m_refCount.ref();
    if (m_refCount.deref()) {
        return m_data->connection();
    }
    return Q_NULLPTR;
}

// caller takes ownership of the returned instance, alternatively it is parented to the given \a parent object.
QDBusInterface *Sailfish::Secrets::SecretsDaemonConnection::createInterface(const QString &objectPath, const QString &interface, QObject *parent)
{
    QDBusInterface *retn = new QDBusInterface("org.sailfishos.secrets.daemon", objectPath, interface, m_data->m_connection, parent);
    retn->setTimeout(180000); // some of the permission flows can take arbitrarily long (user input)
    return retn;
}

void Sailfish::Secrets::SecretsDaemonConnection::registerDBusTypes()
{
    qRegisterMetaType<Sailfish::Secrets::SecretManager::UserInteractionMode>("Sailfish::Secrets::SecretManager::UserInteractionMode");
    qRegisterMetaType<Sailfish::Secrets::SecretManager::AccessControlMode>("Sailfish::Secrets::SecretManager::AccessControlMode");
    qRegisterMetaType<Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic>("Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic");
    qRegisterMetaType<Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic>("Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic");
    qRegisterMetaType<Sailfish::Secrets::SecretManager::FilterOperator>("Sailfish::Secrets::SecretManager::FilterOperator");
    qRegisterMetaType<Sailfish::Secrets::EncryptionPluginInfo>("Sailfish::Secrets::EncryptionPluginInfo");
    qRegisterMetaType<QVector<Sailfish::Secrets::EncryptionPluginInfo> >("QVector<Sailfish::Secrets::EncryptionPluginInfo>");
    qRegisterMetaType<Sailfish::Secrets::StoragePluginInfo>("Sailfish::Secrets::StoragePluginInfo");
    qRegisterMetaType<QVector<Sailfish::Secrets::StoragePluginInfo> >("QVector<Sailfish::Secrets::StoragePluginInfo>");
    qRegisterMetaType<Sailfish::Secrets::EncryptedStoragePluginInfo>("Sailfish::Secrets::EncryptedStoragePluginInfo");
    qRegisterMetaType<QVector<Sailfish::Secrets::EncryptedStoragePluginInfo> >("QVector<Sailfish::Secrets::EncryptedStoragePluginInfo>");
    qRegisterMetaType<Sailfish::Secrets::AuthenticationPluginInfo>("Sailfish::Secrets::AuthenticationPluginInfo");
    qRegisterMetaType<QVector<Sailfish::Secrets::AuthenticationPluginInfo> >("QVector<Sailfish::Secrets::AuthenticationPluginInfo>");
    qRegisterMetaType<Sailfish::Secrets::Result>("Sailfish::Secrets::Result");
    qRegisterMetaType<Sailfish::Secrets::Secret>("Sailfish::Secrets::Secret");
    qRegisterMetaType<Sailfish::Secrets::Secret::Identifier>("Sailfish::Secrets::Secret::Identifier");
    qRegisterMetaType<Sailfish::Secrets::Secret::FilterData>("Sailfish::Secrets::Secret::FilterData");
    qRegisterMetaType<Sailfish::Secrets::InteractionRequest>("Sailfish::Secrets::InteractionRequest");
    qRegisterMetaType<Sailfish::Secrets::InteractionResponse>("Sailfish::Secrets::InteractionResponse");

    qDBusRegisterMetaType<Sailfish::Secrets::SecretManager::UserInteractionMode>();
    qDBusRegisterMetaType<Sailfish::Secrets::SecretManager::AccessControlMode>();
    qDBusRegisterMetaType<Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic>();
    qDBusRegisterMetaType<Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic>();
    qDBusRegisterMetaType<Sailfish::Secrets::SecretManager::FilterOperator>();
    qDBusRegisterMetaType<Sailfish::Secrets::EncryptionPluginInfo>();
    qDBusRegisterMetaType<QVector<Sailfish::Secrets::EncryptionPluginInfo> >();
    qDBusRegisterMetaType<Sailfish::Secrets::StoragePluginInfo>();
    qDBusRegisterMetaType<QVector<Sailfish::Secrets::StoragePluginInfo> >();
    qDBusRegisterMetaType<Sailfish::Secrets::EncryptedStoragePluginInfo>();
    qDBusRegisterMetaType<QVector<Sailfish::Secrets::EncryptedStoragePluginInfo> >();
    qDBusRegisterMetaType<Sailfish::Secrets::AuthenticationPluginInfo>();
    qDBusRegisterMetaType<QVector<Sailfish::Secrets::AuthenticationPluginInfo> >();
    qDBusRegisterMetaType<Sailfish::Secrets::Result>();
    qDBusRegisterMetaType<Sailfish::Secrets::Secret>();
    qDBusRegisterMetaType<Sailfish::Secrets::Secret::Identifier>();
    qDBusRegisterMetaType<QVector<Sailfish::Secrets::Secret::Identifier> >();
    qDBusRegisterMetaType<Sailfish::Secrets::Secret::FilterData>();
    qDBusRegisterMetaType<Sailfish::Secrets::InteractionRequest>();
    qDBusRegisterMetaType<Sailfish::Secrets::InteractionResponse>();
}
