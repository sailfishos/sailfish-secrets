/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_PLUGIN_AUTHENTICATION_INAPP_H
#define SAILFISHSECRETS_PLUGIN_AUTHENTICATION_INAPP_H

#include "Secrets/extensionplugins.h"
#include "Secrets/result.h"
#include "Secrets/interactionrequest.h"
#include "Secrets/interactionrequestwatcher.h"

#include <QObject>
#include <QVector>
#include <QString>
#include <QByteArray>
#include <QCryptographicHash>
#include <QMutexLocker>
#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(lcSailfishSecretsPluginSqlite)

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Plugins {

class Q_DECL_EXPORT InAppPlugin : public Sailfish::Secrets::AuthenticationPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Secrets_AuthenticationPlugin_IID)
    Q_INTERFACES(Sailfish::Secrets::AuthenticationPlugin)

public:
    InAppPlugin(QObject *parent = Q_NULLPTR);
    ~InAppPlugin();

    QString name() const Q_DECL_OVERRIDE {
#ifdef SAILFISHSECRETS_TESTPLUGIN
        return QLatin1String("org.sailfishos.secrets.plugin.authentication.inapp.test");
#else
        return QLatin1String("org.sailfishos.secrets.plugin.authentication.inapp");
#endif
    }
    Sailfish::Secrets::AuthenticationPlugin::AuthenticationType authenticationType() const Q_DECL_OVERRIDE { return Sailfish::Secrets::AuthenticationPlugin::ApplicationSpecificAuthentication; }

    Sailfish::Secrets::Result beginAuthentication(
                uint callerPid,
                qint64 requestId,
                const QString &callerApplicationId,
                const QString &collectionName,
                const QString &secretName,
                const QString &interactionServiceAddress) Q_DECL_OVERRIDE;

private Q_SLOTS:
    void interactionRequestFinished(quint64 requestId);
    void interactionRequestResponse(quint64 requestId,
                           const Sailfish::Secrets::Result &result,
                           const Sailfish::Secrets::InteractionResponse &response);

private:
    QMap<quint64, Sailfish::Secrets::InteractionRequestWatcher *> m_requests;
};

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_PLUGIN_AUTHENTICATION_INAPP_H
