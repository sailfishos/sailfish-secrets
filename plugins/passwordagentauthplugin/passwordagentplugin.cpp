/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "passwordagentplugin.h"

#include <QDBusAbstractAdaptor>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QLoggingCategory>

Q_PLUGIN_METADATA(IID Sailfish_Secrets_AuthenticationPlugin_IID)

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Plugins {

Q_DECLARE_LOGGING_CATEGORY(lcPasswordAgent)
Q_LOGGING_CATEGORY(lcPasswordAgent, "org.sailfishos.secrets.plugin.authentication.passwordagent", QtWarningMsg)

static QDBusMessage passwordAgentMethodCall(const QString &member)
{
    return QDBusMessage::createMethodCall(
                QStringLiteral("org.sailfishos.Lipstick.SecurityUi"),
                QStringLiteral("/org/sailfishos/Lipstick/SecurityUi/PasswordAgent"),
                QStringLiteral("org.sailfishos.Security.PasswordAgent"),
                member);
}

class PasswordAgentResponse : public QDBusPendingCallWatcher
{
public:
    PasswordAgentResponse(
            const QDBusObjectPath &object,
            const QDBusPendingCall &call,
            uint callerPid,
            qint64 requestId,
            const QString &callerApplicationId,
            const QString &collectionName,
            const QString &secretName,
            const QString &interactionServiceAddress,
            QObject *parent)
        : QDBusPendingCallWatcher(call, parent)
        , callerApplicationId(callerApplicationId)
        , collectionName(collectionName)
        , secretName(secretName)
        , serviceAddress(interactionServiceAddress)
        , requestId(requestId)
        , callerPid(callerPid)
    {
        QDBusConnection::systemBus().registerObject(
                    object.path(),
                    QStringLiteral("org.sailfishos.Security.PasswordClient"),
                    this,
                    QDBusConnection::ExportAllSlots);
    }

    void cancel()
    {
        QDBusConnection::systemBus().send(
                    passwordAgentMethodCall(QStringLiteral("Cancel")) << QVariant::fromValue(object));
    }

public slots:
    void VerifyPassword(const QString &password)
    {
        PasswordAgentResponse::password = password.toUtf8();
    }

public:
    const QDBusObjectPath object;
    const QString callerApplicationId;
    const QString collectionName;
    const QString secretName;
    const QString serviceAddress;
    QByteArray password;
    const qint64 requestId;
    const uint callerPid;
};

PasswordAgentPlugin::PasswordAgentPlugin(QObject *parent)
    : AuthenticationPlugin(parent)
{
}

PasswordAgentPlugin::~PasswordAgentPlugin()
{
    for (PasswordAgentResponse *response : m_responses) {
        response->cancel();
    }
}

Result PasswordAgentPlugin::beginAuthentication(
            uint callerPid,
            qint64 requestId,
            const QString &callerApplicationId,
            const QString &collectionName,
            const QString &secretName,
            const QString &interactionServiceAddress)
{
    static int objectCounter = 0;

    const QDBusObjectPath object(QStringLiteral("/org/sailfishos/Security/PasswordClient/%1").arg(++objectCounter));
    const QString message;
    const QVariantMap properties;

    QDBusPendingCall call = QDBusConnection::systemBus().asyncCall(passwordAgentMethodCall(
                QStringLiteral("VerifyPassword"))
            << QVariant::fromValue(object)
            << QVariant::fromValue(message)
            << QVariant::fromValue(properties), 10 * 60 * 10000);

    PasswordAgentResponse * const response = new PasswordAgentResponse(
                object,
                call,
                callerPid,
                requestId,
                callerApplicationId,
                collectionName,
                secretName,
                interactionServiceAddress,
                this);

    m_responses.insert(requestId, response);

    connect(response, &QDBusPendingCallWatcher::finished, this, &PasswordAgentPlugin::requestFinished);

    return Result(Result::Pending);
}

void PasswordAgentPlugin::requestFinished(QDBusPendingCallWatcher *watcher)
{
    watcher->deleteLater();

    PasswordAgentResponse *response = static_cast<PasswordAgentResponse *>(watcher);
    m_responses.remove(response->requestId);

    Result result;

    if (response->isError()) {
        const QDBusError error = response->error();

        switch (error.type()) {
        case QDBusError::Timeout:
        case QDBusError::TimedOut:
            response->cancel();
            break;
        default:
            break;
        }

        result = Result(Result::InteractionViewError, error.message());
    }

    emit authenticationCompleted(
                response->callerPid,
                response->requestId,
                response->callerApplicationId,
                response->collectionName,
                response->secretName,
                response->serviceAddress,
                result,
                response->password);
}

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish
