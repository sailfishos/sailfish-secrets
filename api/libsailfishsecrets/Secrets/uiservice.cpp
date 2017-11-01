/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "uiservice_p.h"
#include "secretmanager.h"
#include "secretmanager_p.h"
#include "uiview.h"
#include "uirequest.h"

#include <QtCore/QDir>
#include <QtCore/QUuid>
#include <QtCore/QPointer>
#include <QtCore/QStandardPaths>
#include <QtCore/QLoggingCategory>

// for getpid()
#include <sys/types.h>
#include <unistd.h>

Q_LOGGING_CATEGORY(lcSailfishSecretsUi, "org.sailfishos.secrets.ui")

const QString Sailfish::Secrets::UiRequest::UiViewQmlFileUrl = QStringLiteral("UiViewQmlFileUrl");
const QString Sailfish::Secrets::UiResponse::ResultCode = QStringLiteral("ResultCode");
const QString Sailfish::Secrets::UiResponse::ErrorMessage = QStringLiteral("ErrorMessage");
const QString Sailfish::Secrets::UiResponse::Confirmation = QStringLiteral("Confirmation");
const QString Sailfish::Secrets::UiResponse::AuthenticationKey = QStringLiteral("AuthenticationKey");

void Sailfish::Secrets::SecretManagerPrivate::handleUiConnection(const QDBusConnection &connection)
{
    qCDebug(lcSailfishSecretsUi) << "UiService received new client p2p connection:" << connection.name();
    QDBusConnection clientConnection(connection);
    if (!clientConnection.registerObject(QLatin1String("/"),
#if QT_VERSION >= QT_VERSION_CHECK(5, 5, 0)
                                         QLatin1String("org.sailfishos.secrets.ui"),
#endif
                                         m_uiService,
                                         QDBusConnection::ExportAllSlots | QDBusConnection::ExportAllSignals)) {
        qCWarning(lcSailfishSecretsUi) << "Could not register object for ui connection!";
    } else {
        qCDebug(lcSailfishSecretsUi) << "Registered ui object with the client connection!";
    }
}

Sailfish::Secrets::UiService::UiService(SecretManagerPrivate *parent)
    : QObject(parent)
    , m_parent(parent)
    , m_dbusServer(Q_NULLPTR)
    , m_activeConnection(QLatin1String("org.sailfishos.secrets.ui.invalidConnection"))
    , m_activeRequestState(Inactive)
{
}

bool Sailfish::Secrets::UiService::registerServer()
{
    if (!m_address.isEmpty()) {
        // already registered.
        return true;
    }

    const QString path = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
    if (path.isEmpty()) {
        qCWarning(lcSailfishSecretsUi) << "No writable runtime dir found, cannot create socket file";
        return false;
    }

    QDir dir(path);
    if (!dir.mkpath(dir.absolutePath())) {
        qCWarning(lcSailfishSecretsUi) << "Could not create socket file directory";
        return false;
    }

    const QString file = QString::fromUtf8("%1/%2-%3").arg(dir.absolutePath(), QLatin1String("sailfishsecretsd-uiSocket"), QString::number(getpid()));
    const QString address = QString::fromUtf8("unix:path=%1").arg(file);

    m_dbusServer = new QDBusServer(address, this);
    connect(m_dbusServer, &QDBusServer::newConnection,
            m_parent, &Sailfish::Secrets::SecretManagerPrivate::handleUiConnection);

    m_address = address;
    qCDebug(lcSailfishSecretsUi) << "UiService listening for ui p2p connections on address:" << m_address;
    return true;
}

void Sailfish::Secrets::UiService::sendResponse(
        const Sailfish::Secrets::Result &result,
        const Sailfish::Secrets::UiResponse &response)
{
    if (m_activeRequestId.isEmpty()) {
        qCDebug(lcSailfishSecretsUi) << "Refusing to send response for cancelled or finished request";
        return;
    }

    // transition to waiting state, we need sailfishsecretsd to tell us whether we're finished or not.
    m_activeRequestState = Sailfish::Secrets::UiService::Waiting;

    // send the response.
    m_activeReply << QVariant::fromValue<Sailfish::Secrets::Result>(result);
    m_activeReply << QVariant::fromValue<Sailfish::Secrets::UiResponse>(response);
    m_activeReply << QVariant::fromValue<QString>(m_activeRequestId);
    m_activeConnection.send(m_activeReply);
}

void Sailfish::Secrets::UiService::performUiRequest(
        const Sailfish::Secrets::UiRequest &request,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result,
        Sailfish::Secrets::UiResponse &response,
        QString &requestId)
{
    Q_UNUSED(response)  // outparam, will be set in sendResponse().
    Q_UNUSED(requestId) // outparam, will be set in sendResponse().
    qCDebug(lcSailfishSecretsUi) << "UiService received performUiRequest...";
    if (!m_activeRequestId.isEmpty()) {
        result = Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiServiceRequestBusyError,
                    QLatin1String("Ui service is busy handling another request"));
    } else if (!m_parent->m_uiView || !m_parent->m_uiView->performRequest(this, request)) {
        result = Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiViewUnavailableError,
                    QLatin1String("Cannot perform ui request: view busy or no view registered"));
    } else {
        // successfully triggered the request in the view.
        if (m_activeConnection.isConnected()) {
            m_activeConnection.disconnect(QString(), // any service
                                          QLatin1String("/org/freedesktop/DBus/Local"),
                                          QLatin1String("org.freedesktop.DBus.Local"),
                                          QLatin1String("Disconnected"),
                                          this, SLOT(clientDisconnected()));
        }
        m_activeRequestId = QUuid::createUuid().toString();
        m_activeConnection = connection();
        m_activeConnection.connect(QString(), // any service
                                   QLatin1String("/org/freedesktop/DBus/Local"),
                                   QLatin1String("org.freedesktop.DBus.Local"),
                                   QLatin1String("Disconnected"),
                                   this, SLOT(clientDisconnected()));
        m_activeReply = message.createReply();
        message.setDelayedReply(true);
    }
}

// The sailfishsecretsd process is telling us that more user-interaction is
// required before the request is complete.
void Sailfish::Secrets::UiService::continueUiRequest(
        const QString &requestId,
        const Sailfish::Secrets::UiRequest &request,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result,
        Sailfish::Secrets::UiResponse &response)
{
    Q_UNUSED(response) // outparam, will be set in sendResponse().
    qCDebug(lcSailfishSecretsUi) << "UiService received continueUiRequest...";
    if (requestId != m_activeRequestId) {
        result = Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiServiceRequestInvalidError,
                    QString::fromLatin1("Cannot continue non-active ui request: %1").arg(requestId));
    } else if (m_activeRequestState != Sailfish::Secrets::UiService::Waiting) {
        result = Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiServiceRequestBusyError,
                    QString::fromLatin1("Cannot continue non-waiting ui request: %1").arg(requestId));
    } else if (!m_parent->m_uiView || !m_parent->m_uiView->continueRequest(this, request)) {
        result = Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiViewUnavailableError,
                    QLatin1String("Cannot continue ui request: view busy or no view registered"));
    } else {
        // successfully triggered the sign on request in the view.
        m_activeConnection = connection();
        m_activeReply = message.createReply();
        message.setDelayedReply(true);
    }
}

// The sailfishsecretsd process is telling us to cancel the request.
void Sailfish::Secrets::UiService::cancelUiRequest(
        const QString &requestId,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result)
{
    Q_UNUSED(message);
    qCDebug(lcSailfishSecretsUi) << "UiService received cancelUiRequest...";
    if (requestId != m_activeRequestId) {
        result = Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiServiceRequestInvalidError,
                    QString::fromLatin1("Cannot cancel non-active ui request: %1").arg(requestId));
    } else if (!m_parent->m_uiView || !m_parent->m_uiView->cancelRequest(this)) {
        result = Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiViewUnavailableError,
                    QLatin1String("Cannot cancel ui request: view busy or no view registered"));
    } else {
        // don't destroy the connection yet (wait for client disconnection first)
        // but set the connection state to inactive, so that we can accept new clients.
        m_activeRequestState = Sailfish::Secrets::UiService::Inactive;
        m_activeRequestId = QString();
        result = Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
    }
}

// The sailfishsecretsd process is telling us that it has finished
// handling the response, and no further user interaction is required.
void Sailfish::Secrets::UiService::finishUiRequest(
        const QString &requestId,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result)
{
    Q_UNUSED(message);
    qCDebug(lcSailfishSecretsUi) << "UiService received finishUiRequest...";
    if (requestId != m_activeRequestId) {
        result = Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiServiceRequestInvalidError,
                    QString::fromLatin1("Cannot finish non-active ui request: %1").arg(requestId));
    } else if (m_activeRequestState != Sailfish::Secrets::UiService::Waiting) {
        result = Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiServiceRequestBusyError,
                    QString::fromLatin1("Cannot finish non-waiting ui request: %1").arg(requestId));
    } else if (!m_parent->m_uiView || !m_parent->m_uiView->finishRequest(this)) {
        result = Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiViewUnavailableError,
                    QLatin1String("Cannot finish ui request: view busy or no view registered"));
    } else {
        // don't destroy the connection yet (wait for client disconnection first)
        // but set the connection state to inactive, so that we can accept new clients.
        m_activeRequestState = Sailfish::Secrets::UiService::Inactive;
        m_activeRequestId = QString();
        result = Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
    }
}

void Sailfish::Secrets::UiService::clientDisconnected()
{
    qCDebug(lcSailfishSecretsUi) << "Active connection client disconnected from UiService!";
    m_activeConnection = QDBusConnection(QLatin1String("org.sailfishos.secrets.ui.invalidConnection"));
    m_activeReply = QDBusMessage();
    m_activeRequestId = QString();
    m_activeRequestState = Sailfish::Secrets::UiService::Inactive;
}

// -------------- View:

class Sailfish::Secrets::UiViewData
{
public:
    UiViewData() : m_uiService(Q_NULLPTR) {}
    QPointer<QObject> m_uiService;
    QPointer<SecretManager> m_secretManager;
};

Sailfish::Secrets::UiView::UiView()
    : data(new UiViewData)
{
}

Sailfish::Secrets::UiView::~UiView()
{
    delete data;
}

void Sailfish::Secrets::UiView::registerWithSecretManager(Sailfish::Secrets::SecretManager *manager)
{
    data->m_secretManager = manager;
    manager->registerUiView(this);
}

Sailfish::Secrets::SecretManager *Sailfish::Secrets::UiView::registeredWithSecretManager() const
{
    return data->m_secretManager.data();
}

void Sailfish::Secrets::UiView::sendResponse(
        const Sailfish::Secrets::Result &result,
        const Sailfish::Secrets::UiResponse &response)
{
    if (data->m_uiService) {
        qobject_cast<Sailfish::Secrets::UiService*>(data->m_uiService)->sendResponse(result, response);
        data->m_uiService = Q_NULLPTR;
    }
}

bool Sailfish::Secrets::UiView::performRequest(QObject *sender, const Sailfish::Secrets::UiRequest &request)
{
    if (data->m_uiService) {
        qCDebug(lcSailfishSecretsUi) << "Refusing to perform ui request: view already active with another request";
        return false;
    }

    data->m_uiService = qobject_cast<Sailfish::Secrets::UiService*>(sender);
    performRequest(request);
    return true;
}

bool Sailfish::Secrets::UiView::continueRequest(QObject *sender, const Sailfish::Secrets::UiRequest &request)
{
    if (data->m_uiService) {
        qCDebug(lcSailfishSecretsUi) << "Refusing to continue ui request: view already active with another request";
        return false;
    }

    data->m_uiService = qobject_cast<Sailfish::Secrets::UiService*>(sender);
    continueRequest(request);
    return true;
}

bool Sailfish::Secrets::UiView::cancelRequest(QObject *sender)
{
    if (data->m_uiService && data->m_uiService == qobject_cast<Sailfish::Secrets::UiService*>(sender)) {
        data->m_uiService = Q_NULLPTR;
        cancelRequest();
        return true;
    } else if (!data->m_uiService) {
        // already cancelled
        return true;
    }

    // otherwise, attempting to cancel while busy with a different request - error.
    qCDebug(lcSailfishSecretsUi) << "Refusing to cancel ui request: view already active with another request";
    return false;
}

bool Sailfish::Secrets::UiView::finishRequest(QObject *sender)
{
    if (data->m_uiService && data->m_uiService == qobject_cast<Sailfish::Secrets::UiService*>(sender)) {
        qCDebug(lcSailfishSecretsUi) << "Refusing to finish active ui request: use cancel instead";
        return false;
    } else if (data->m_uiService) {
        qCDebug(lcSailfishSecretsUi) << "Refusing to finish ui request: view already active with another request";
        return false;
    }
    finishRequest();
    return true;
}
