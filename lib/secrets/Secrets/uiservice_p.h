/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_UISERVICE_P_H
#define LIBSAILFISHSECRETS_UISERVICE_P_H

#include "Secrets/secretmanager_p.h"
#include "Secrets/uirequest.h"
#include "Secrets/result.h"

#include <QtDBus/QDBusServer>
#include <QtDBus/QDBusContext>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusPendingCallWatcher>

#include <QtCore/QObject>
#include <QtCore/QVariantMap>
#include <QtCore/QList>
#include <QtCore/QString>

namespace Sailfish {

namespace Secrets {

class SecretManagerPrivate;

/*
 *  The UiService instance lives within the client process.
 *  It is instantiated if the client attempts to perform a secrets request
 *  with the UserInteractionMode set to ApplicationInteraction.
 *  It talks to the sailfishsecretsd via P2P DBus connection, and triggers
 *  interaction within the UiView registered with the manager.
 */
class UiService : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.sailfishos.secrets.ui")
    Q_CLASSINFO("D-Bus Introspection", ""
    "  <interface name=\"org.sailfishos.secrets.ui\">\n"
    "      <method name=\"performUiRequest\" />\n"
    "          <arg name=\"request\" type=\"(iba{sv})\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(is)\" direction=\"out\" />\n"
    "          <arg name=\"response\" type=\"(ia{sv})\" direction=\"out\" />\n"
    "          <arg name=\"requestId\" type=\"s\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Secrets::UiRequest\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Secrets::UiResponse\" />\n"
    "      </method>\n"
    "      <method name=\"continueUiRequest\" />\n"
    "          <arg name=\"requestId\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"request\" type=\"(iba{sv})\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(is)\" direction=\"out\" />\n"
    "          <arg name=\"response\" type=\"(ia{sv})\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Secrets::UiRequest\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Secrets::UiResponse\" />\n"
    "      </method>\n"
    "      <method name=\"cancelUiRequest\" />\n"
    "          <arg name=\"requestId\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(is)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"finishUiRequest\" />\n"
    "          <arg name=\"requestId\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(is)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "  </interface>\n"
    "")

public:
    UiService(SecretManagerPrivate *parent = Q_NULLPTR);
    QString address() const { return m_address; }
    bool registerServer();
    void sendResponse(const Sailfish::Secrets::Result &error,
                      const Sailfish::Secrets::UiResponse &response);

public Q_SLOTS:
    void performUiRequest(const Sailfish::Secrets::UiRequest &request,
                          const QDBusMessage &message,
                          Sailfish::Secrets::Result &result,
                          Sailfish::Secrets::UiResponse &response,
                          QString &requestId);
    void continueUiRequest(const QString &requestId,
                           const Sailfish::Secrets::UiRequest &request,
                           const QDBusMessage &message,
                           Sailfish::Secrets::Result &result,
                           Sailfish::Secrets::UiResponse &response);
    void cancelUiRequest(const QString &requestId,
                         const QDBusMessage &message,
                         Sailfish::Secrets::Result &result);
    void finishUiRequest(const QString &requestId,
                         const QDBusMessage &message,
                         Sailfish::Secrets::Result &result);

private Q_SLOTS:
    void clientDisconnected();

private:
    SecretManagerPrivate *m_parent;
    QDBusServer *m_dbusServer;
    QString m_address;

    QDBusConnection m_activeConnection;
    QDBusMessage m_activeReply;
    QString m_activeRequestId;
    enum ActiveRequestState {
        Inactive = 0,
        Started,
        Waiting
    };
    ActiveRequestState m_activeRequestState;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_UISERVICE_P_H
