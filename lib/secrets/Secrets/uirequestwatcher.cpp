/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/uirequestwatcher.h"
#include "Secrets/uirequest.h"
#include "Secrets/extensionplugins.h"

#include <QtDBus/QDBusServer>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusPendingCallWatcher>
#include <QtDBus/QDBusPendingReply>

Q_LOGGING_CATEGORY(lcSailfishSecretsUiServiceConnection, "org.sailfishos.secrets.uiservice.connection")

class Sailfish::Secrets::UiRequestWatcherPrivate
{
public:
    UiRequestWatcherPrivate()
        : m_watcher(Q_NULLPTR)
        , m_interface(Q_NULLPTR)
        , m_connection(QLatin1String("org.sailfishos.secrets.ui.invalidConnection"))
        , m_requestId(0)
        , m_callerPid(0)
    {
    }

    QDBusPendingCallWatcher *m_watcher;
    QDBusInterface *m_interface;
    QDBusConnection m_connection;

    quint64 m_requestId;
    pid_t m_callerPid;
    QString m_callerApplicationId;
    QString m_collectionName;
    QString m_secretName;
    QString m_uiServiceAddress;
    QString m_uiRequestId;
};

Sailfish::Secrets::UiRequestWatcher::UiRequestWatcher(Sailfish::Secrets::AuthenticationPlugin *parent)
    : QObject(parent)
    , m_data(new Sailfish::Secrets::UiRequestWatcherPrivate)
{
}

Sailfish::Secrets::UiRequestWatcher::~UiRequestWatcher()
{
    delete m_data;
}

void Sailfish::Secrets::UiRequestWatcher::setRequestId(quint64 id)
{
    m_data->m_requestId = id;
}

void Sailfish::Secrets::UiRequestWatcher::setCallerPid(pid_t pid)
{
    m_data->m_callerPid = pid;
}

void Sailfish::Secrets::UiRequestWatcher::setCallerApplicationId(const QString &applicationId)
{
    m_data->m_callerApplicationId = applicationId;
}

void Sailfish::Secrets::UiRequestWatcher::setCollectionName(const QString &name)
{
    m_data->m_collectionName = name;
}

void Sailfish::Secrets::UiRequestWatcher::setSecretName(const QString &name)
{
    m_data->m_secretName = name;
}

void Sailfish::Secrets::UiRequestWatcher::setUiServiceAddress(const QString &address)
{
    m_data->m_uiServiceAddress = address;
}

quint64 Sailfish::Secrets::UiRequestWatcher::requestId() const
{
    return m_data->m_requestId;
}

pid_t Sailfish::Secrets::UiRequestWatcher::callerPid() const
{
    return m_data->m_callerPid;
}

QString Sailfish::Secrets::UiRequestWatcher::callerApplicationId() const
{
    return m_data->m_callerApplicationId;
}

QString Sailfish::Secrets::UiRequestWatcher::collectionName() const
{
    return m_data->m_collectionName;
}

QString Sailfish::Secrets::UiRequestWatcher::secretName() const
{
    return m_data->m_secretName;
}

QString Sailfish::Secrets::UiRequestWatcher::uiServiceAddress() const
{
    return m_data->m_uiServiceAddress;
}

bool Sailfish::Secrets::UiRequestWatcher::connectToUiService()
{
    const QString name = QString::fromLatin1("sailfishsecretsd-ui-connection-%1").arg(m_data->m_requestId);

    qCDebug(lcSailfishSecretsUiServiceConnection) << "Connecting to ui service via p2p address:" << m_data->m_uiServiceAddress
                                                  << "with connection name:" << name;

    QDBusConnection p2pc = QDBusConnection::connectToPeer(m_data->m_uiServiceAddress, name);
    if (!p2pc.isConnected()) {
        qCWarning(lcSailfishSecretsUiServiceConnection) << "Unable to connect to ui service:"
                                                        << p2pc.lastError()
                                                        << p2pc.lastError().type()
                                                        << p2pc.lastError().name();
        return false;
    }

    m_data->m_connection = p2pc;
    m_data->m_connection.connect(
            QString(), // any service
            QString::fromUtf8("/org/freedesktop/DBus/Local"),
            QString::fromUtf8("org.freedesktop.DBus.Local"),
            QString::fromUtf8("Disconnected"),
            this, SLOT(uiServiceDisconnected()));

    m_data->m_interface = new QDBusInterface(
            QLatin1String("org.sailfishos.secrets.ui"),
            QLatin1String("/"),
            QLatin1String("org.sailfishos.secrets.ui"),
            m_data->m_connection,
            this);

    m_data->m_interface->setTimeout(120000); // 2 minutes timeout.  Sign-on flows require user input.
    qCDebug(lcSailfishSecretsUiServiceConnection) << "Connected to Ui service:" << m_data->m_connection.name();
    return true;
}

bool Sailfish::Secrets::UiRequestWatcher::sendUiRequest(const Sailfish::Secrets::UiRequest &request)
{
    if (m_data->m_watcher) {
        qCWarning(lcSailfishSecretsUiServiceConnection) << "Not sending Ui request: outstanding request in progress";
        return false; // outstanding request in progress!
    }

    // send the request, and instantiate the watcher to watch it.
    m_data->m_watcher = new QDBusPendingCallWatcher(m_data->m_interface->asyncCall(
                                                        "performUiRequest",
                                                        QVariant::fromValue<Sailfish::Secrets::UiRequest>(request)),
                                                    this);

    connect(m_data->m_watcher, &QDBusPendingCallWatcher::finished,
            this, static_cast<void (Sailfish::Secrets::UiRequestWatcher::*)(void)>(&Sailfish::Secrets::UiRequestWatcher::uiRequestFinished));

    return true;
}

bool Sailfish::Secrets::UiRequestWatcher::continueUiRequest(const Sailfish::Secrets::UiRequest &request)
{
    if (!m_data->m_watcher || m_data->m_uiRequestId.isEmpty()) {
        qCWarning(lcSailfishSecretsUiServiceConnection) << "Not continuing Ui request: no outstanding request in progress";
        return false; // no outstanding request in progress!
    }

    // send the request, and instantiate the watcher to watch it.
    m_data->m_watcher = new QDBusPendingCallWatcher(m_data->m_interface->asyncCall(
                                                        "continueUiRequest",
                                                        QVariant::fromValue<QString>(m_data->m_uiRequestId),
                                                        QVariant::fromValue<Sailfish::Secrets::UiRequest>(request)),
                                                    this);

    connect(m_data->m_watcher, &QDBusPendingCallWatcher::finished,
            this, &Sailfish::Secrets::UiRequestWatcher::uiContinuationRequestFinished);

    return true;
}

bool Sailfish::Secrets::UiRequestWatcher::cancelUiRequest()
{
    if (!m_data->m_watcher || m_data->m_uiRequestId.isEmpty()) {
        qCWarning(lcSailfishSecretsUiServiceConnection) << "Not cancelling Ui request: no outstanding request in progress";
        return false; // no outstanding request in progress!
    }

    // send the request, and instantiate the watcher to watch it.
    m_data->m_watcher = new QDBusPendingCallWatcher(m_data->m_interface->asyncCall(
                                                        "cancelUiRequest",
                                                        QVariant::fromValue<QString>(m_data->m_uiRequestId)),
                                                    this);

    connect(m_data->m_watcher, &QDBusPendingCallWatcher::finished,
            this, &Sailfish::Secrets::UiRequestWatcher::uiCancelFinished);

    return true;
}

bool Sailfish::Secrets::UiRequestWatcher::finishUiRequest()
{
    if (!m_data->m_watcher || m_data->m_uiRequestId.isEmpty()) {
        qCWarning(lcSailfishSecretsUiServiceConnection) << "Not finishing Ui request: no outstanding request in progress";
        return false; // no outstanding request in progress!
    }

    // send the request, and instantiate the watcher to watch it.
    m_data->m_watcher = new QDBusPendingCallWatcher(m_data->m_interface->asyncCall(
                                                        "finishUiRequest",
                                                        QVariant::fromValue<QString>(m_data->m_uiRequestId)),
                                                    this);

    connect(m_data->m_watcher, &QDBusPendingCallWatcher::finished,
            this, &Sailfish::Secrets::UiRequestWatcher::uiFinishFinished);

    return true;
}

void Sailfish::Secrets::UiRequestWatcher::uiRequestFinished()
{
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::UiResponse, QString> reply = *m_data->m_watcher;
    reply.waitForFinished();
    if (reply.isValid()) {
        Sailfish::Secrets::Result result = reply.argumentAt<0>();
        Sailfish::Secrets::UiResponse response = reply.argumentAt<1>();
        m_data->m_uiRequestId = reply.argumentAt<2>();
        if (result.code() != Sailfish::Secrets::Result::Succeeded) {
            qCWarning(lcSailfishSecretsUiServiceConnection) << "Ui request returned error:" << result.errorMessage();
        }
        emit uiRequestResponse(m_data->m_requestId, result, response);
    } else {
        qCWarning(lcSailfishSecretsUiServiceConnection) << "Invalid response to Ui request!";
        QString errorMessage = reply.isError() ? reply.error().message() : QLatin1String("Invalid response to Ui request");
        emit uiRequestResponse(m_data->m_requestId,
                               Sailfish::Secrets::Result(Sailfish::Secrets::Result::UiServiceResponseInvalidError, errorMessage),
                               Sailfish::Secrets::UiResponse());
    }
}

void Sailfish::Secrets::UiRequestWatcher::uiContinuationRequestFinished()
{
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::UiResponse> reply = *m_data->m_watcher;
    reply.waitForFinished();
    if (reply.isValid()) {
        Sailfish::Secrets::Result result = reply.argumentAt<0>();
        Sailfish::Secrets::UiResponse response = reply.argumentAt<1>();
        if (result.code() != Sailfish::Secrets::Result::Succeeded) {
            qCWarning(lcSailfishSecretsUiServiceConnection) << "Ui continuation request returned error:" << result.errorMessage();
        }
        emit uiRequestResponse(m_data->m_requestId, result, response);
    } else {
        qCWarning(lcSailfishSecretsUiServiceConnection) << "Invalid response to Ui continuation request!";
        QString errorMessage = reply.isError() ? reply.error().message() : QLatin1String("Invalid response to Ui continuation request");
        emit uiRequestResponse(m_data->m_requestId,
                               Sailfish::Secrets::Result(Sailfish::Secrets::Result::UiServiceResponseInvalidError, errorMessage),
                               Sailfish::Secrets::UiResponse());
    }
}

void Sailfish::Secrets::UiRequestWatcher::uiCancelFinished()
{
    QDBusPendingReply<Sailfish::Secrets::Result> reply = *m_data->m_watcher;
    if (reply.isValid()) {
        qCDebug(lcSailfishSecretsUiServiceConnection) << "Cancelled Ui request.";
    } else {
        qCDebug(lcSailfishSecretsUiServiceConnection) << "Unable to cleanly cancel Ui request!";
    }
    emit uiRequestFinished(m_data->m_requestId);
}

void Sailfish::Secrets::UiRequestWatcher::uiFinishFinished()
{
    QDBusPendingReply<Sailfish::Secrets::Result> reply = *m_data->m_watcher;
    if (reply.isValid()) {
        qCDebug(lcSailfishSecretsUiServiceConnection) << "Finished Ui request.";
    } else {
        qCDebug(lcSailfishSecretsUiServiceConnection) << "Unable to cleanly finish Ui request!";
    }
    emit uiRequestFinished(m_data->m_requestId);
}

void Sailfish::Secrets::UiRequestWatcher::uiServiceDisconnected()
{
    qCDebug(lcSailfishSecretsUiServiceConnection) << "Disconnected from Ui service:" << m_data->m_connection.name();
    // TODO: uncomment me?  depends on which event we receive first...
    //emit uiRequestResponse(m_data->m_requestId,
    //                       Sailfish::Secrets::Result(Sailfish::Secrets::Result::ErrorOccurred, "Disconnected from Ui service"),
    //                       Sailfish::Secrets::UiResponse());
}

void Sailfish::Secrets::UiRequestWatcher::disconnectFromUiService()
{
    qCDebug(lcSailfishSecretsUiServiceConnection) << "Finished sign-on-ui session, disconnecting from service:" << m_data->m_connection.name();
    QDBusConnection::disconnectFromPeer(m_data->m_connection.name());
    m_data->m_connection = QDBusConnection(QLatin1String("org.sailfishos.accounts.signonui.invalidConnection"));
}
