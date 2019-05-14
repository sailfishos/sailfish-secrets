/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_DAEMON_REQUESTQUEUE_P_H
#define SAILFISHSECRETS_DAEMON_REQUESTQUEUE_P_H

#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusContext>

#include <QtCore/QObject>
#include <QtCore/QString>

#include "controller_p.h"

#include "Secrets/result.h"
#include "Crypto/result.h"

// forward declare the QDBusConnection::internalPointer() return type.
class DBusConnection;

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace ApiImpl {

class RequestQueue;
class DBusObject : public QObject, protected QDBusContext
{
    Q_OBJECT

public:
    DBusObject(RequestQueue *parent);

public Q_SLOTS:
    void onDisconnection();

protected:
    RequestQueue *m_requestQueue;
};

// Encapsulates the various things required to implement one of the APIs
// which are exposed via the Peer-To-Peer DBus interface, and provides
// an asynchronous queue of API requests.
class RequestQueue : public QObject
{
    Q_OBJECT

public:
    enum RequestStatus {
        RequestPending = 0,
        RequestInProgress,
        RequestFinished
    };

    struct RequestData {
        RequestData()
            : requestId(0)
            , remotePid(0)
            , type(0) // InvalidRequest
            , status(RequestPending)
            , connection(QString::fromUtf8("org.sailfishos.secrets.daemon.invalidConnection"))
            , cryptoRequestId(0)
            , isSecretsCryptoRequest(false) {}
        quint64 requestId;
        pid_t remotePid;
        int type;
        RequestStatus status;
        QList<QVariant> inParams;
        QList<QVariant> outParams;
        QDBusMessage message;
        QDBusConnection connection;

        // These are only set if the request is a Sailfish::Secrets request
        // which is being performed as part of a Sailfish::Crypto request.
        quint64 cryptoRequestId;
        bool isSecretsCryptoRequest;
    };

public:
    RequestQueue(const QString &dbusObjectPath,
                 const QString &dbusInterfaceName,
                 Controller *parent,
                 bool autotestMode);

    virtual ~RequestQueue();

    void setDBusObject(DBusObject *dbusObject) { m_dbusObject = dbusObject; }

    void handleRequest(int requestType,
                       const QVariantList &inParams,
                       const QDBusConnection &connection,
                       const QDBusMessage &message,
                       Sailfish::Secrets::Result &result);
    void handleRequest(pid_t callerPid,
                       quint64 cryptoRequestId,
                       int requestType,
                       const QVariantList &inParams,
                       Sailfish::Secrets::Result &result);
    void handleRequest(int requestType,
                       const QVariantList &inParams,
                       const QDBusConnection &connection,
                       const QDBusMessage &message,
                       Sailfish::Crypto::Result &result);

    Sailfish::Secrets::Result enqueueRequest(Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request);
    void requestFinished(quint64 requestId, const QList<QVariant> &outParams);

    virtual void handleCancelation(Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request) = 0;
    virtual void handlePendingRequest(Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request, bool *completed) = 0;
    virtual void handleFinishedRequest(Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request, bool *completed) = 0;
    virtual QString requestTypeToString(int type) const = 0;

public Q_SLOTS:
    void handleRequests();
    void handleClientConnection(const QDBusConnection &connection);
    void handleClientDisconnection(const QDBusConnection &connection);

private Q_SLOTS:
    void finishEnqueueRequest(quint64 requestId);

protected:
    Controller *m_controller;
    DBusObject *m_dbusObject;
    QString m_dbusObjectPath;
    QString m_dbusInterfaceName;
    QList<RequestData*> m_requests;
    QMap<quint64, RequestData*> m_enqueuingRequests;

    bool m_autotestMode;
};

} // ApiImpl

} // Daemon

} // Secrets

} // Sailfish

#endif // SAILFISHSECRETS_DAEMON_REQUESTQUEUE_P_H

