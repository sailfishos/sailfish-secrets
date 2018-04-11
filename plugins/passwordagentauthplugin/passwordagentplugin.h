/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_PLUGIN_AUTHENTICATION_PASSWORDAGENT_H
#define SAILFISHSECRETS_PLUGIN_AUTHENTICATION_PASSWORDAGENT_H

#include "Secrets/extensionplugins.h"
#include "Secrets/interactionparameters.h"

#include <QtCore/QHash>
#include <QtCore/QString>

#include <QDBusConnection>
#include <QDBusContext>
#include <QDBusServer>

QT_BEGIN_NAMESPACE
class QDBusPendingCallWatcher;
class QDBusObjectPath;
QT_END_NAMESPACE

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Plugins {

class Q_DECL_EXPORT PasswordAgentPlugin : public AuthenticationPlugin, protected QDBusContext
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

    AuthenticationPlugin::AuthenticationTypes authenticationTypes() const Q_DECL_OVERRIDE;
    InteractionParameters::InputTypes inputTypes() const Q_DECL_OVERRIDE;

    Result beginAuthentication(
            uint callerPid,
            qint64 requestId) Q_DECL_OVERRIDE;

    Result beginUserInputInteraction(
            uint callerPid,
            qint64 requestId,
            const InteractionParameters &interactionParameters,
            const QString &interactionServiceAddress) Q_DECL_OVERRIDE;

    void addConnection(const QDBusConnection &connection);
    void removeConnection(const QString &name);

public Q_SLOTS:
    void RegisterSessionAgent(const QDBusObjectPath &agent);
    void UnregisterSessionAgent(const QDBusObjectPath &agent);
    void ValidatePassword(const QString &cookie, const QString &password);

private Q_SLOTS:
    void disconnected();

private:
    class Agent;
    class PasswordResponse;
    class PolkitResponse;

    QScopedPointer<Agent> m_sessionAgent;
    QDBusServer m_server;
    QHash<QString, PolkitResponse *> m_polkitResponses;

    inline void destroyAgent(Agent *agent);
};

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_PLUGIN_AUTHENTICATION_PASSWORDAGENT_H
