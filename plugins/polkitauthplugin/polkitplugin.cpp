/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "polkitplugin.h"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusPendingCallWatcher>
#include <QDBusReply>
#include <QLoggingCategory>

Q_PLUGIN_METADATA(IID Sailfish_Secrets_AuthenticationPlugin_IID)

struct PolkitSubject
{
    QString type;
    QHash<QString, QString> details;
};

Q_DECLARE_METATYPE(PolkitSubject)

QDBusArgument &operator <<(QDBusArgument &argument, const PolkitSubject &subject)
{
    return argument << subject.type << subject.details;
}

const QDBusArgument &operator >>(const QDBusArgument &argument, PolkitSubject &subject)
{
    return argument >> subject.type >> subject.details;
}

struct PolkitAuthorizationResult
{
    bool isAuthorized;
    bool isChallenge;
    QHash<QString, QString> details;
};

Q_DECLARE_METATYPE(PolkitAuthorizationResult)

QDBusArgument &operator <<(QDBusArgument &argument, const PolkitAuthorizationResult &result)
{
    return argument << result.isAuthorized << result.isChallenge << result.details;
}

const QDBusArgument &operator >>(const QDBusArgument &argument, PolkitAuthorizationResult &result)
{
    return argument >> result.isAuthorized >> result.isChallenge >> result.details;
}

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Plugins {

Q_DECLARE_LOGGING_CATEGORY(lcPolkit)
Q_LOGGING_CATEGORY(lcPolkit, "org.sailfishos.secrets.plugin.authentication.polkit", QtWarningMsg)

static QDBusMessage polkitAuthorityMethodCall(const QString &member)
{
    return QDBusMessage::createMethodCall(
                QStringLiteral("org.freedesktop.PolicyKit1"),
                QStringLiteral("/org/freedesktop/PolicyKit1/Authority"),
                QStringLiteral("org.freedesktop.PolicyKit1.Authority"),
                member);
}

class PolkitResponse : public QDBusPendingCallWatcher
{
public:
    PolkitResponse(
            const QDBusPendingCall &call,
            uint callerPid,
            qint64 requestId,
            const QString &callerApplicationId,
            const QString &collectionName,
            const QString &secretName,
            const QString &interactionServiceAddress,
            const QString &cancellationId,
            QObject *parent)
        : QDBusPendingCallWatcher(call, parent)
        , callerApplicationId(callerApplicationId)
        , collectionName(collectionName)
        , secretName(secretName)
        , serviceAddress(interactionServiceAddress)
        , cancellationId(cancellationId)
        , requestId(requestId)
        , callerPid(callerPid)
    {
    }

    void cancel()
    {
        QDBusConnection::systemBus().send(
                    polkitAuthorityMethodCall(QStringLiteral("CancelCheckAuthorization")) << cancellationId);
    }

    const QString callerApplicationId;
    const QString collectionName;
    const QString secretName;
    const QString serviceAddress;
    const QString cancellationId;
    const qint64 requestId;
    const uint callerPid;
};

PolkitPlugin::PolkitPlugin(QObject *parent)
    : AuthenticationPlugin(parent)
{
    static int subjectTypeId = qDBusRegisterMetaType<PolkitSubject>();
    static int resultTypeId = qDBusRegisterMetaType<PolkitAuthorizationResult>();
    Q_UNUSED(subjectTypeId);
    Q_UNUSED(resultTypeId);
}

PolkitPlugin::~PolkitPlugin()
{
    for (PolkitResponse *response : m_responses) {
        response->cancel();
    }
}

Result PolkitPlugin::beginAuthentication(
            uint callerPid,
            qint64 requestId,
            const QString &callerApplicationId,
            const QString &collectionName,
            const QString &secretName,
            const QString &interactionServiceAddress)
{
    static int cancellationCounter = 0;

    const PolkitSubject subject;
    const QString actionId;
    const QHash<QString, QString> details;
    const  uint authorizationFlags = 0x01;
    const QString cancellationId = QStringLiteral("sailfish-secrets-%1").arg(++cancellationCounter);

    QDBusPendingCall call = QDBusConnection::systemBus().asyncCall(polkitAuthorityMethodCall(
                QStringLiteral("CheckAuthorization"))
            << QVariant::fromValue(subject)
            << QVariant::fromValue(actionId)
            << QVariant::fromValue(details)
            << QVariant::fromValue(authorizationFlags)
            << QVariant::fromValue(cancellationId), 10 * 60 * 10000);

    PolkitResponse * const response = new PolkitResponse(
                call,
                callerPid,
                requestId,
                callerApplicationId,
                collectionName,
                secretName,
                interactionServiceAddress,
                cancellationId,
                this);

    m_responses.insert(requestId, response);

    connect(response, &QDBusPendingCallWatcher::finished, this, &PolkitPlugin::requestFinished);

    return Result(Result::Pending);
}

void PolkitPlugin::requestFinished(QDBusPendingCallWatcher *watcher)
{
    watcher->deleteLater();

    PolkitResponse *response = static_cast<PolkitResponse *>(watcher);
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
    } else {
        QDBusReply<PolkitAuthorizationResult> reply = *response;

        if (!reply.value().isAuthorized) {
            result = Result(Result::Failed);
        }
    }

    emit authenticationCompleted(
                response->callerPid,
                response->requestId,
                response->callerApplicationId,
                response->collectionName,
                response->secretName,
                response->serviceAddress,
                result,
                QByteArray());
}

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish
