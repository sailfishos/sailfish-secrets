/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_DAEMON_CONTROLLER_P_H
#define SAILFISHSECRETS_DAEMON_CONTROLLER_P_H

#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusContext>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusServer>

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QThreadPool>
#include <QtCore/QSharedPointer>

#include <Secrets/Plugins/extensionplugins.h>
#include <Secrets/plugininfo.h>

// The environment variables which can be used to specify the name
// of the default Crypto and Secrets plugins.
// See Controller::mappedPluginName() for more information.
#define ENV_PERFORM_PLUGIN_MAPPING "SAILFISH_SECRETSD_PERFORM_PLUGIN_MAPPING"
#define ENV_DEFAULT_CRYPTO_PLUGIN "SAILFISH_SECRETSD_DEFAULT_CRYPTO_PLUGIN"
#define ENV_DEFAULT_CRYPTOSTORAGE_PLUGIN "SAILFISH_SECRETSD_DEFAULT_CRYPTOSTORAGE_PLUGIN"
#define ENV_DEFAULT_STORAGE_PLUGIN "SAILFISH_SECRETSD_DEFAULT_STORAGE_PLUGIN"
#define ENV_DEFAULT_ENCRYPTION_PLUGIN "SAILFISH_SECRETSD_DEFAULT_ENCRYPTION_PLUGIN"
#define ENV_DEFAULT_ENCRYPTEDSTORAGE_PLUGIN "SAILFISH_SECRETSD_DEFAULT_ENCRYPTEDSTORAGE_PLUGIN"
#define ENV_DEFAULT_AUTHENTICATION_PLUGIN "SAILFISH_SECRETSD_DEFAULT_AUTHENTICATION_PLUGIN"
#define ENV_INAPP_AUTHENTICATION_PLUGIN "SAILFISH_SECRETSD_INAPP_AUTHENTICATION_PLUGIN"

namespace Sailfish {

namespace Crypto {
    namespace Daemon {
        class DiscoveryObject;
        namespace ApiImpl {
            class CryptoRequestQueue;
        }
    }
}

namespace Secrets {

namespace Daemon {

class DiscoveryObject;
namespace ApiImpl {
    class SecretsRequestQueue;
}

class Controller : public QObject
{
    Q_OBJECT

public:
    Controller(bool autotest = false, QObject *parent = Q_NULLPTR);
    ~Controller();

    bool isValid() const { return m_isValid; }

    Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *secrets() const;
    Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue *crypto() const;
    QString mappedPluginName(const QString &pluginName) const;
    QWeakPointer<QThreadPool> threadPoolForPlugin(const QString &pluginName) const;
    QString displayNameForPlugin(const QString &pluginName) const;
    QMap<QString, Sailfish::Secrets::PluginInfo> pluginInfoForPlugins(
            QList<Sailfish::Secrets::PluginBase*> plugins,
            bool masterLocked);

public Q_SLOTS:
    void handleClientConnection(const QDBusConnection &connection);

private:
    QDBusServer *m_dbusServer;
    Sailfish::Secrets::Daemon::DiscoveryObject *m_secretsDiscoveryObject;
    Sailfish::Crypto::Daemon::DiscoveryObject *m_cryptoDiscoveryObject;
    Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *m_secrets;
    Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue *m_crypto;
    bool m_autotestMode;
    bool m_isValid;
};

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_DAEMON_CONTROLLER_P_H
