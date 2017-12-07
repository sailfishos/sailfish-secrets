/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "controller_p.h"
#include "discoveryobject_p.h"
#include "logging_p.h"

#include "SecretsImpl/secrets_p.h"
#include "CryptoImpl/crypto_p.h"

#include <QtCore/QString>
#include <QtCore/QDir>
#include <QtCore/QStandardPaths>

namespace {
    QString p2pSocketAddress()
    {
        const QString path = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
        if (path.isEmpty()) {
            qCWarning(lcSailfishSecretsDaemonDBus) << "No writable runtime directory found, cannot create socket file";
            return QString();
        }

        QDir dir(path);
        if (!dir.mkpath(dir.absolutePath())) {
            qCWarning(lcSailfishSecretsDaemonDBus) << "Could not create socket file directory";
            return QString();
        }

        const QString socketFile = QString::fromUtf8("%1/%2").arg(dir.absolutePath(), QLatin1String("sailfishsecretsd-p2pSocket"));
        const QString address = QString::fromUtf8("unix:path=%1").arg(socketFile);

        return address;
    }
}

Sailfish::Secrets::Daemon::Controller::Controller(const QString &secretsPluginDir,
                                                  const QString &cryptoPluginDir,
                                                  bool autotestMode, QObject *parent)
    : QObject(parent)
    , m_secretsPluginDir(secretsPluginDir)
    , m_cryptoPluginDir(cryptoPluginDir)
    , m_autotestMode(autotestMode)
    , m_isValid(false)
{
    // Initialise the various API implementation objects.
    // These objects provide Peer-To-Peer DBus API.
    m_secrets = new Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue(this, secretsPluginDir, autotestMode);
    m_crypto = new Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue(this, m_secrets, cryptoPluginDir, autotestMode);

    // Determine the p2p socket address.
    const QString p2pDBusSocketAddress = p2pSocketAddress();
    if (p2pDBusSocketAddress.isEmpty()) {
        qCWarning(lcSailfishSecretsDaemon) << "Failed to determine p2p socket file location!";
        return;
    }

    // Initialise the discovery objects and register them on the session bus.
    // This allows clients who don't know the P2P socket file path to discover it via DBus.
    m_secretsDiscoveryObject  = new Sailfish::Secrets::Daemon::DiscoveryObject(this);
    if (!m_secretsDiscoveryObject->registerObject(QString::fromUtf8("org.sailfishos.secrets.daemon.discovery"),
                                                  QString::fromUtf8("/Sailfish/Secrets/Discovery"))) {
        qCWarning(lcSailfishSecretsDaemon) << "Failed to register secrets discovery object on session bus!"
                                           << "Clients won't be able to connect! (Is another instance already running?)";
        return;
    }

    m_cryptoDiscoveryObject  = new Sailfish::Crypto::Daemon::DiscoveryObject(this);
    if (!m_cryptoDiscoveryObject->registerObject(QString::fromUtf8("org.sailfishos.crypto.daemon.discovery"),
                                                 QString::fromUtf8("/Sailfish/Crypto/Discovery"))) {
        qCWarning(lcSailfishSecretsDaemon) << "Failed to register crypto discovery object on session bus!"
                                           << "Clients won't be able to connect! (Is another instance already running?)";
        return;
    }

    m_secretsDiscoveryObject->setPeerToPeerAddress(p2pDBusSocketAddress);
    m_cryptoDiscoveryObject->setPeerToPeerAddress(p2pDBusSocketAddress);

    // Initialise the Peer-To-Peer DBus server.
    m_dbusServer = new QDBusServer(p2pDBusSocketAddress, this);
    connect(m_dbusServer, &QDBusServer::newConnection,
            this, &Sailfish::Secrets::Daemon::Controller::handleClientConnection);

    m_isValid = true;
}

Sailfish::Secrets::Daemon::Controller::~Controller()
{
}

void Sailfish::Secrets::Daemon::Controller::handleClientConnection(const QDBusConnection &connection)
{
    qCDebug(lcSailfishSecretsDaemon) << "New client p2p connection received!" << connection.name();

    // Each API implementation needs to register its DBus API object with the connection.
    m_secrets->handleClientConnection(connection);
    m_crypto->handleClientConnection(connection);
}
