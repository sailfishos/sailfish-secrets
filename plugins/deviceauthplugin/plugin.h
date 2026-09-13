/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * BSD 3-Clause License, see LICENSE.
 */
#ifndef SAILFISH_SECRETS_DEVICEAUTHPLUGIN_H
#define SAILFISH_SECRETS_DEVICEAUTHPLUGIN_H
#include "Secrets/Plugins/extensionplugins.h"
#include <QHash>
class QTimer;
namespace Sailfish { namespace Secrets { namespace Daemon { namespace Plugins {
class DeviceAuthPlugin : public AuthenticationPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Secrets_AuthenticationPlugin_IID)
    Q_INTERFACES(Sailfish::Secrets::AuthenticationPlugin)
public:
    explicit DeviceAuthPlugin(QObject *parent = Q_NULLPTR) : AuthenticationPlugin(parent) {}
    QString displayName() const Q_DECL_OVERRIDE { return QStringLiteral("Device authentication"); }
    QString name() const Q_DECL_OVERRIDE { return QStringLiteral("org.sailfishos.secrets.plugin.authentication.deviceauth"); }
    int version() const Q_DECL_OVERRIDE { return 1; }
    AuthenticationTypes authenticationTypes() const Q_DECL_OVERRIDE { return PinCodeAuthentication | FingerprintAuthentication; }
    InteractionParameters::InputTypes inputTypes() const Q_DECL_OVERRIDE { return InteractionParameters::UnknownInput; }
    Result beginAuthentication(uint callerPid, qint64 requestId,
                               const InteractionParameters::PromptText &promptText) Q_DECL_OVERRIDE;
    void cancelAuthentication(uint callerPid, qint64 requestId) Q_DECL_OVERRIDE;
    Result beginUserInputInteraction(uint, qint64, const InteractionParameters &, const QString &) Q_DECL_OVERRIDE
    { return Result(Result::OperationNotSupportedError, QStringLiteral("Device authentication does not return credentials")); }
    void cancelUserInputInteraction(uint, qint64) Q_DECL_OVERRIDE {}
private:
    void finish(uint callerPid, qint64 requestId, const Result &result);
    QHash<QPair<uint, qint64>, QTimer *> m_requests;
};
} } } }
#endif
