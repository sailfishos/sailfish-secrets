/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_PLUGIN_AUTHENTICATION_PASSWORDAGENT_H
#define SAILFISHSECRETS_PLUGIN_AUTHENTICATION_PASSWORDAGENT_H

#include "Secrets/extensionplugins.h"

#include <QHash>

QT_BEGIN_NAMESPACE
class QDBusPendingCallWatcher;
QT_END_NAMESPACE

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Plugins {

class PasswordAgentResponse;

class Q_DECL_EXPORT PasswordAgentPlugin : public Sailfish::Secrets::AuthenticationPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Secrets_AuthenticationPlugin_IID)
    Q_INTERFACES(Sailfish::Secrets::AuthenticationPlugin)

public:
    explicit PasswordAgentPlugin(QObject *parent = Q_NULLPTR);
    ~PasswordAgentPlugin();

    QString name() const Q_DECL_OVERRIDE {
#ifdef SAILFISHSECRETS_TESTPLUGIN
        return QLatin1String("org.sailfishos.secrets.plugin.authentication.passwordagent.test");
#else
        return QLatin1String("org.sailfishos.secrets.plugin.authentication.passwordagent");
#endif
    }
    Sailfish::Secrets::AuthenticationPlugin::AuthenticationType authenticationType() const Q_DECL_OVERRIDE { return Sailfish::Secrets::AuthenticationPlugin::PasswordAuthentication; }

    Sailfish::Secrets::Result beginAuthentication(
                uint callerPid,
                qint64 requestId,
                const QString &callerApplicationId,
                const QString &collectionName,
                const QString &secretName,
                const QString &interactionServiceAddress) Q_DECL_OVERRIDE;
private:
    inline void requestFinished(QDBusPendingCallWatcher *watcher);

    QHash<quint64, PasswordAgentResponse *> m_responses;
};

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_PLUGIN_AUTHENTICATION_PASSWORDAGENT_H
