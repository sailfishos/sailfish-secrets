/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_UIREQUESTWATCHER_H
#define SAILFISHSECRETS_UIREQUESTWATCHER_H

#include "Secrets/uirequest.h"
#include "Secrets/result.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(lcSailfishSecretsUiServiceConnection)

namespace Sailfish {

namespace Secrets {

// The UiRequestWatcher class holds the state
// of a particular ui request which is being
// serviced by a particular ui service on behalf
// of a particular authenticatoin plugin, as a
// result of a client request being processed by the
// RequestProcessor.
class AuthenticationPlugin;
class UiRequestWatcherPrivate;
class UiRequestWatcher : public QObject
{
    Q_OBJECT

public:
    UiRequestWatcher(Sailfish::Secrets::AuthenticationPlugin *parent = Q_NULLPTR);
    ~UiRequestWatcher();

    void setRequestId(quint64 id);
    void setCallerPid(pid_t pid);
    void setCallerApplicationId(const QString &applicationId);
    void setCollectionName(const QString &name);
    void setSecretName(const QString &name);
    void setUiServiceAddress(const QString &address);

    quint64 requestId() const;
    pid_t callerPid() const;
    QString callerApplicationId() const;
    QString collectionName() const;
    QString secretName() const;
    QString uiServiceAddress() const;

    bool connectToUiService();
    void disconnectFromUiService();

    bool sendUiRequest(const Sailfish::Secrets::UiRequest &request);
    bool continueUiRequest(const Sailfish::Secrets::UiRequest &request);
    bool cancelUiRequest();
    bool finishUiRequest();

Q_SIGNALS:
    void uiRequestFinished(quint64 requestId);
    void uiRequestResponse(quint64 requestId,
                           const Sailfish::Secrets::Result &result,
                           const Sailfish::Secrets::UiResponse &response);

private Q_SLOTS:
    void uiServiceDisconnected();
    void uiRequestFinished();
    void uiContinuationRequestFinished();
    void uiCancelFinished();
    void uiFinishFinished();

private:
    Sailfish::Secrets::UiRequestWatcherPrivate *m_data;
};

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_DAEMON_UIREQUESTWATCHER_H
