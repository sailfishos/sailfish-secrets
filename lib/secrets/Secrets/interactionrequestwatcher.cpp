/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/interactionrequestwatcher.h"
#include "Secrets/interactionrequest.h"
#include "Secrets/extensionplugins.h"

#include <QtDBus/QDBusServer>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusPendingCallWatcher>
#include <QtDBus/QDBusPendingReply>

Q_LOGGING_CATEGORY(lcSailfishSecretsInteractionServiceConnection, "org.sailfishos.secrets.interactionservice.connection")

class Sailfish::Secrets::InteractionRequestWatcherPrivate
{
public:
    InteractionRequestWatcherPrivate()
        : m_watcher(Q_NULLPTR)
        , m_interface(Q_NULLPTR)
        , m_connection(QLatin1String("org.sailfishos.secrets.interaction.invalidConnection"))
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
    QString m_interactionServiceAddress;
    QString m_uiRequestId;
};

Sailfish::Secrets::InteractionRequestWatcher::InteractionRequestWatcher(Sailfish::Secrets::AuthenticationPlugin *parent)
    : QObject(parent)
    , m_data(new Sailfish::Secrets::InteractionRequestWatcherPrivate)
{
}

Sailfish::Secrets::InteractionRequestWatcher::~InteractionRequestWatcher()
{
    delete m_data;
}

void Sailfish::Secrets::InteractionRequestWatcher::setRequestId(quint64 id)
{
    m_data->m_requestId = id;
}

void Sailfish::Secrets::InteractionRequestWatcher::setCallerPid(pid_t pid)
{
    m_data->m_callerPid = pid;
}

void Sailfish::Secrets::InteractionRequestWatcher::setCallerApplicationId(const QString &applicationId)
{
    m_data->m_callerApplicationId = applicationId;
}

void Sailfish::Secrets::InteractionRequestWatcher::setCollectionName(const QString &name)
{
    m_data->m_collectionName = name;
}

void Sailfish::Secrets::InteractionRequestWatcher::setSecretName(const QString &name)
{
    m_data->m_secretName = name;
}

void Sailfish::Secrets::InteractionRequestWatcher::setInteractionServiceAddress(const QString &address)
{
    m_data->m_interactionServiceAddress = address;
}

quint64 Sailfish::Secrets::InteractionRequestWatcher::requestId() const
{
    return m_data->m_requestId;
}

pid_t Sailfish::Secrets::InteractionRequestWatcher::callerPid() const
{
    return m_data->m_callerPid;
}

QString Sailfish::Secrets::InteractionRequestWatcher::callerApplicationId() const
{
    return m_data->m_callerApplicationId;
}

QString Sailfish::Secrets::InteractionRequestWatcher::collectionName() const
{
    return m_data->m_collectionName;
}

QString Sailfish::Secrets::InteractionRequestWatcher::secretName() const
{
    return m_data->m_secretName;
}

QString Sailfish::Secrets::InteractionRequestWatcher::interactionServiceAddress() const
{
    return m_data->m_interactionServiceAddress;
}

bool Sailfish::Secrets::InteractionRequestWatcher::connectToInteractionService()
{
    const QString name = QString::fromLatin1("sailfishsecretsd-ui-connection-%1").arg(m_data->m_requestId);

    qCDebug(lcSailfishSecretsInteractionServiceConnection) << "Connecting to ui service via p2p address:" << m_data->m_interactionServiceAddress
                                                  << "with connection name:" << name;

    QDBusConnection p2pc = QDBusConnection::connectToPeer(m_data->m_interactionServiceAddress, name);
    if (!p2pc.isConnected()) {
        qCWarning(lcSailfishSecretsInteractionServiceConnection) << "Unable to connect to ui service:"
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
            this, SLOT(interactionServiceDisconnected()));

    m_data->m_interface = new QDBusInterface(
            QLatin1String("org.sailfishos.secrets.interaction"),
            QLatin1String("/"),
            QLatin1String("org.sailfishos.secrets.interaction"),
            m_data->m_connection,
            this);

    m_data->m_interface->setTimeout(120000); // 2 minutes timeout.  Sign-on flows require user input.
    qCDebug(lcSailfishSecretsInteractionServiceConnection) << "Connected to Ui service:" << m_data->m_connection.name();
    return true;
}

bool Sailfish::Secrets::InteractionRequestWatcher::sendInteractionRequest(const Sailfish::Secrets::InteractionRequest &request)
{
    if (m_data->m_watcher) {
        qCWarning(lcSailfishSecretsInteractionServiceConnection) << "Not sending Ui request: outstanding request in progress";
        return false; // outstanding request in progress!
    }

    // send the request, and instantiate the watcher to watch it.
    m_data->m_watcher = new QDBusPendingCallWatcher(m_data->m_interface->asyncCall(
                                                        "performInteractionRequest",
                                                        QVariant::fromValue<Sailfish::Secrets::InteractionRequest>(request)),
                                                    this);

    connect(m_data->m_watcher, &QDBusPendingCallWatcher::finished,
            this, static_cast<void (Sailfish::Secrets::InteractionRequestWatcher::*)(void)>(&Sailfish::Secrets::InteractionRequestWatcher::interactionRequestFinished));

    return true;
}

bool Sailfish::Secrets::InteractionRequestWatcher::continueInteractionRequest(const Sailfish::Secrets::InteractionRequest &request)
{
    if (!m_data->m_watcher || m_data->m_uiRequestId.isEmpty()) {
        qCWarning(lcSailfishSecretsInteractionServiceConnection) << "Not continuing Ui request: no outstanding request in progress";
        return false; // no outstanding request in progress!
    }

    // send the request, and instantiate the watcher to watch it.
    m_data->m_watcher = new QDBusPendingCallWatcher(m_data->m_interface->asyncCall(
                                                        "continueInteractionRequest",
                                                        QVariant::fromValue<QString>(m_data->m_uiRequestId),
                                                        QVariant::fromValue<Sailfish::Secrets::InteractionRequest>(request)),
                                                    this);

    connect(m_data->m_watcher, &QDBusPendingCallWatcher::finished,
            this, &Sailfish::Secrets::InteractionRequestWatcher::interactionContinuationRequestFinished);

    return true;
}

bool Sailfish::Secrets::InteractionRequestWatcher::cancelInteractionRequest()
{
    if (!m_data->m_watcher || m_data->m_uiRequestId.isEmpty()) {
        qCWarning(lcSailfishSecretsInteractionServiceConnection) << "Not cancelling Ui request: no outstanding request in progress";
        return false; // no outstanding request in progress!
    }

    // send the request, and instantiate the watcher to watch it.
    m_data->m_watcher = new QDBusPendingCallWatcher(m_data->m_interface->asyncCall(
                                                        "cancelInteractionRequest",
                                                        QVariant::fromValue<QString>(m_data->m_uiRequestId)),
                                                    this);

    connect(m_data->m_watcher, &QDBusPendingCallWatcher::finished,
            this, &Sailfish::Secrets::InteractionRequestWatcher::interactionCancelFinished);

    return true;
}

bool Sailfish::Secrets::InteractionRequestWatcher::finishInteractionRequest()
{
    if (!m_data->m_watcher || m_data->m_uiRequestId.isEmpty()) {
        qCWarning(lcSailfishSecretsInteractionServiceConnection) << "Not finishing Ui request: no outstanding request in progress";
        return false; // no outstanding request in progress!
    }

    // send the request, and instantiate the watcher to watch it.
    m_data->m_watcher = new QDBusPendingCallWatcher(m_data->m_interface->asyncCall(
                                                        "finishInteractionRequest",
                                                        QVariant::fromValue<QString>(m_data->m_uiRequestId)),
                                                    this);

    connect(m_data->m_watcher, &QDBusPendingCallWatcher::finished,
            this, &Sailfish::Secrets::InteractionRequestWatcher::interactionFinishFinished);

    return true;
}

void Sailfish::Secrets::InteractionRequestWatcher::interactionRequestFinished()
{
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::InteractionResponse, QString> reply = *m_data->m_watcher;
    reply.waitForFinished();
    if (reply.isValid()) {
        Sailfish::Secrets::Result result = reply.argumentAt<0>();
        Sailfish::Secrets::InteractionResponse response = reply.argumentAt<1>();
        m_data->m_uiRequestId = reply.argumentAt<2>();
        if (result.code() != Sailfish::Secrets::Result::Succeeded) {
            qCWarning(lcSailfishSecretsInteractionServiceConnection) << "Ui request returned error:" << result.errorMessage();
        }
        emit interactionRequestResponse(m_data->m_requestId, result, response);
    } else {
        qCWarning(lcSailfishSecretsInteractionServiceConnection) << "Invalid response to Ui request!";
        QString errorMessage = reply.isError() ? reply.error().message() : QLatin1String("Invalid response to Ui request");
        emit interactionRequestResponse(m_data->m_requestId,
                               Sailfish::Secrets::Result(Sailfish::Secrets::Result::InteractionServiceResponseInvalidError, errorMessage),
                               Sailfish::Secrets::InteractionResponse());
    }
}

void Sailfish::Secrets::InteractionRequestWatcher::interactionContinuationRequestFinished()
{
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::InteractionResponse> reply = *m_data->m_watcher;
    reply.waitForFinished();
    if (reply.isValid()) {
        Sailfish::Secrets::Result result = reply.argumentAt<0>();
        Sailfish::Secrets::InteractionResponse response = reply.argumentAt<1>();
        if (result.code() != Sailfish::Secrets::Result::Succeeded) {
            qCWarning(lcSailfishSecretsInteractionServiceConnection) << "Ui continuation request returned error:" << result.errorMessage();
        }
        emit interactionRequestResponse(m_data->m_requestId, result, response);
    } else {
        qCWarning(lcSailfishSecretsInteractionServiceConnection) << "Invalid response to Ui continuation request!";
        QString errorMessage = reply.isError() ? reply.error().message() : QLatin1String("Invalid response to Ui continuation request");
        emit interactionRequestResponse(m_data->m_requestId,
                               Sailfish::Secrets::Result(Sailfish::Secrets::Result::InteractionServiceResponseInvalidError, errorMessage),
                               Sailfish::Secrets::InteractionResponse());
    }
}

void Sailfish::Secrets::InteractionRequestWatcher::interactionCancelFinished()
{
    QDBusPendingReply<Sailfish::Secrets::Result> reply = *m_data->m_watcher;
    if (reply.isValid()) {
        qCDebug(lcSailfishSecretsInteractionServiceConnection) << "Cancelled Ui request.";
    } else {
        qCDebug(lcSailfishSecretsInteractionServiceConnection) << "Unable to cleanly cancel Ui request!";
    }
    emit interactionRequestFinished(m_data->m_requestId);
}

void Sailfish::Secrets::InteractionRequestWatcher::interactionFinishFinished()
{
    QDBusPendingReply<Sailfish::Secrets::Result> reply = *m_data->m_watcher;
    if (reply.isValid()) {
        qCDebug(lcSailfishSecretsInteractionServiceConnection) << "Finished Ui request.";
    } else {
        qCDebug(lcSailfishSecretsInteractionServiceConnection) << "Unable to cleanly finish Ui request!";
    }
    emit interactionRequestFinished(m_data->m_requestId);
}

void Sailfish::Secrets::InteractionRequestWatcher::interactionServiceDisconnected()
{
    qCDebug(lcSailfishSecretsInteractionServiceConnection) << "Disconnected from Ui service:" << m_data->m_connection.name();
    // TODO: uncomment me?  depends on which event we receive first...
    //emit interactionRequestResponse(m_data->m_requestId,
    //                       Sailfish::Secrets::Result(Sailfish::Secrets::Result::ErrorOccurred, "Disconnected from Ui service"),
    //                       Sailfish::Secrets::InteractionResponse());
}

void Sailfish::Secrets::InteractionRequestWatcher::disconnectFromInteractionService()
{
    qCDebug(lcSailfishSecretsInteractionServiceConnection) << "Finished sign-on-ui session, disconnecting from service:" << m_data->m_connection.name();
    QDBusConnection::disconnectFromPeer(m_data->m_connection.name());
    m_data->m_connection = QDBusConnection(QLatin1String("org.sailfishos.accounts.signonui.invalidConnection"));
}
