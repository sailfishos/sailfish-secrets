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
    QWeakPointer<QThreadPool> threadPoolForPlugin(const QString &pluginName) const;

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
