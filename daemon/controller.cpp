/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "controller_p.h"
#include "discoveryobject_p.h"
#include "logging_p.h"

#include "CryptoImpl/crypto_p.h"
#include "SecretsImpl/secrets_p.h"
#include "SecretsImpl/metadatadb_p.h"
#include "SecretsImpl/pluginfunctionwrappers_p.h"

#include <QtCore/QString>
#include <QtCore/QDir>
#include <QtCore/QStandardPaths>

#include <QtConcurrent>

namespace {
    QString p2pSocketAddress()
    {
        const QString path = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
        if (path.isEmpty()) {
            qCWarning(lcSailfishSecretsDaemonDBus) << "No writable runtime directory found, cannot create socket file";
            return QString();
        }

        QDir dir(QDir(path).absoluteFilePath(QString::fromUtf8("sailfishsecretsd")));
        if (!dir.mkpath(dir.path())) {
            qCWarning(lcSailfishSecretsDaemonDBus) << "Could not create socket file directory";
            return QString();
        }

        const QString socketFile = dir.absoluteFilePath(QLatin1String("p2pSocket"));
        const QString address = QString::fromUtf8("unix:path=%1").arg(socketFile);

        return address;
    }
}

Sailfish::Secrets::Daemon::Controller::Controller(bool autotestMode, QObject *parent)
    : QObject(parent)
    , m_autotestMode(autotestMode)
    , m_isValid(false)
{
    qRegisterMetaType<Sailfish::Secrets::Daemon::ApiImpl::CollectionMetadata>();
    qRegisterMetaType<Sailfish::Secrets::Daemon::ApiImpl::SecretMetadata>();

    // Initialize the various API implementation objects.
    // These objects provide Peer-To-Peer DBus API.
    m_secrets = new Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue(this, autotestMode);
    m_crypto = new Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue(this, m_secrets, autotestMode);

    // We may need to do this again once we know the real lock code.
    // see the comment below for more details.
    // Unless the user has not provided a master-lock code, we don't expect
    // that we have the "correct" bookkeeping database lock key here,
    // but that's ok - we can unlock the database at some later point in
    // time after performing a UI flow asking the user to unlock.
    if (m_secrets->initialize(
                QByteArray(),
                Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::UnlockMode)) {
        m_secrets->initializePlugins();
    }

    // Determine the p2p socket address.
    const QString p2pDBusSocketAddress = p2pSocketAddress();
    if (p2pDBusSocketAddress.isEmpty()) {
        qCWarning(lcSailfishSecretsDaemon) << "Failed to determine p2p socket file location!";
        return;
    }

    // Initialize the discovery objects and register them on the session bus.
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

    // Initialize the Peer-To-Peer DBus server.
    m_dbusServer = new QDBusServer(p2pDBusSocketAddress, this);
    connect(m_dbusServer, &QDBusServer::newConnection,
            this, &Sailfish::Secrets::Daemon::Controller::handleClientConnection);

    m_isValid = true;
}

Sailfish::Secrets::Daemon::Controller::~Controller()
{
}

Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue*
Sailfish::Secrets::Daemon::Controller::secrets() const
{
    return m_secrets;
}

Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue*
Sailfish::Secrets::Daemon::Controller::crypto() const
{
    return m_crypto;
}

QWeakPointer<QThreadPool> Sailfish::Secrets::Daemon::Controller::threadPoolForPlugin(const QString &pluginName) const
{
    if (m_secrets->potentialCryptoStoragePlugins().contains(pluginName)) {
        return m_secrets->secretsThreadPool();
    } else if (m_crypto->plugins().contains(pluginName)) {
        return m_crypto->cryptoThreadPool();
    } else {
        return m_secrets->secretsThreadPool();
    }
}

QString Sailfish::Secrets::Daemon::Controller::displayNameForPlugin(const QString &pluginName) const
{
    if (m_crypto->plugins().contains(pluginName)) {
        return m_crypto->plugins().value(pluginName)->displayName();
    } else {
        return m_secrets->displayNameForStoragePlugin(pluginName);
    }
}

// If the given pluginName is a mappable identifier (like "plugin.storage.default")
// then we return the appropriate "real" plugin name for the given mappable identifier.
// The mapping is defined via environment variables, which can be set by
// environment conf files: /var/lib/environment/sailfish-secretsd/*.conf
QString Sailfish::Secrets::Daemon::Controller::mappedPluginName(const QString &pluginName) const
{
    static const QString testPluginSuffix(QStringLiteral(".test"));

    static const QString performMapping(
            (!QString::fromUtf8(qgetenv(ENV_PERFORM_PLUGIN_MAPPING)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_PERFORM_PLUGIN_MAPPING))
                    : QStringLiteral("true"));
    static const QString mappedCryptoPluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_CRYPTO_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_CRYPTO_PLUGIN))
                    : QStringLiteral("org.sailfishos.crypto.plugin.crypto.openssl"));
    static const QString mappedCryptoStoragePluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_CRYPTOSTORAGE_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_CRYPTOSTORAGE_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher"));
    static const QString mappedStoragePluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_STORAGE_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_STORAGE_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.storage.sqlite"));
    static const QString mappedEncryptionPluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_ENCRYPTION_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_ENCRYPTION_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.encryption.openssl"));
    static const QString mappedEncryptedStoragePluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_ENCRYPTEDSTORAGE_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_ENCRYPTEDSTORAGE_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher"));
    static const QString mappedAuthenticationPluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_AUTHENTICATION_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_AUTHENTICATION_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.authentication.passwordagent"));
    static const QString mappedInAppAuthenticationPluginName(
            (!QString::fromUtf8(qgetenv(ENV_INAPP_AUTHENTICATION_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_INAPP_AUTHENTICATION_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.authentication.inapp"));

    if (!pluginName.isEmpty()
            && (performMapping == QStringLiteral("1")
                || performMapping == QStringLiteral("true")
                || performMapping == QStringLiteral("yes"))) {
        if (pluginName.startsWith(Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedCryptoPluginName+testPluginSuffix)
                    : mappedCryptoPluginName;
        } else if (pluginName.startsWith(Sailfish::Crypto::CryptoManager::DefaultCryptoStoragePluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedCryptoStoragePluginName+testPluginSuffix)
                    : mappedCryptoStoragePluginName;
        } else if (pluginName.startsWith(Sailfish::Secrets::SecretManager::DefaultStoragePluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedStoragePluginName+testPluginSuffix)
                    : mappedStoragePluginName;
        } else if (pluginName.startsWith(Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedEncryptionPluginName+testPluginSuffix)
                    : mappedEncryptionPluginName;
        } else if (pluginName.startsWith(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedEncryptedStoragePluginName+testPluginSuffix)
                    : mappedEncryptedStoragePluginName;
        } else if (pluginName.startsWith(Sailfish::Secrets::SecretManager::DefaultAuthenticationPluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedAuthenticationPluginName+testPluginSuffix)
                    : mappedAuthenticationPluginName;
        } else if (pluginName.startsWith(Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedInAppAuthenticationPluginName+testPluginSuffix)
                    : mappedInAppAuthenticationPluginName;
        }
    }

    return pluginName;
}

QMap<QString, Sailfish::Secrets::PluginInfo>
Sailfish::Secrets::Daemon::Controller::pluginInfoForPlugins(
        QList<Sailfish::Secrets::PluginBase*> plugins,
        bool masterLocked)
{
    QMap<QString, Sailfish::Secrets::PluginInfo> infos;
    for (Sailfish::Secrets::PluginBase *plugin : plugins) {
        // metadata reporting occurs in main thread
        Sailfish::Secrets::PluginInfo::StatusFlags flags = Sailfish::Secrets::PluginInfo::Unknown;
        if (plugin->supportsLocking()) {
            flags |= Sailfish::Secrets::PluginInfo::PluginSupportsLocking;
        }
        if (plugin->supportsSetLockCode()) {
            flags |= Sailfish::Secrets::PluginInfo::PluginSupportsSetLockCode;
        }
        if (!masterLocked) {
            flags |= Sailfish::Secrets::PluginInfo::MasterUnlocked;
        }

        // lock state and availability reporting occurs in plugin thread
        // TODO: make this asynchronous instead of blocking the main thread!
        QFuture<Sailfish::Secrets::Daemon::ApiImpl::PluginState> future
                = QtConcurrent::run(
                        threadPoolForPlugin(plugin->name()).data(),
                        &Sailfish::Secrets::Daemon::ApiImpl::pluginState,
                        plugin);
        future.waitForFinished();
        Sailfish::Secrets::Daemon::ApiImpl::PluginState ps = future.result();
        if (ps.available) {
            flags |= Sailfish::Secrets::PluginInfo::Available;
        }
        if (!ps.locked) {
            flags |= Sailfish::Secrets::PluginInfo::PluginUnlocked;
        }

        infos.insert(plugin->name(),
                     Sailfish::Secrets::PluginInfo(plugin->displayName(),
                                                   plugin->name(),
                                                   plugin->version(),
                                                   flags));
    }

    return infos;
}

void Sailfish::Secrets::Daemon::Controller::handleClientConnection(const QDBusConnection &connection)
{
    qCDebug(lcSailfishSecretsDaemon) << "New client p2p connection received!" << connection.name();

    // Each API implementation needs to register its DBus API object with the connection.
    m_secrets->handleClientConnection(connection);
    m_crypto->handleClientConnection(connection);
}
