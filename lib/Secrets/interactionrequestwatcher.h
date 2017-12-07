/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_INTERACTIONREQUESTWATCHER_H
#define SAILFISHSECRETS_INTERACTIONREQUESTWATCHER_H

#include "Secrets/interactionrequest.h"
#include "Secrets/result.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(lcSailfishSecretsInteractionServiceConnection)

namespace Sailfish {

namespace Secrets {

// The InteractionRequestWatcher class holds the state
// of a particular ui request which is being
// serviced by a particular interaction service on
// behalf of a particular authentication plugin, as a
// result of a client request being processed by the
// RequestProcessor.
class AuthenticationPlugin;
class InteractionRequestWatcherPrivate;
class InteractionRequestWatcher : public QObject
{
    Q_OBJECT

public:
    InteractionRequestWatcher(Sailfish::Secrets::AuthenticationPlugin *parent = Q_NULLPTR);
    ~InteractionRequestWatcher();

    void setRequestId(quint64 id);
    void setCallerPid(pid_t pid);
    void setCallerApplicationId(const QString &applicationId);
    void setCollectionName(const QString &name);
    void setSecretName(const QString &name);
    void setInteractionServiceAddress(const QString &address);

    quint64 requestId() const;
    pid_t callerPid() const;
    QString callerApplicationId() const;
    QString collectionName() const;
    QString secretName() const;
    QString interactionServiceAddress() const;

    bool connectToInteractionService();
    void disconnectFromInteractionService();

    bool sendInteractionRequest(const Sailfish::Secrets::InteractionRequest &request);
    bool continueInteractionRequest(const Sailfish::Secrets::InteractionRequest &request);
    bool cancelInteractionRequest();
    bool finishInteractionRequest();

Q_SIGNALS:
    void interactionRequestFinished(quint64 requestId);
    void interactionRequestResponse(quint64 requestId,
                                    const Sailfish::Secrets::Result &result,
                                    const Sailfish::Secrets::InteractionResponse &response);

private Q_SLOTS:
    void interactionServiceDisconnected();
    void interactionRequestFinished();
    void interactionContinuationRequestFinished();
    void interactionCancelFinished();
    void interactionFinishFinished();

private:
    Sailfish::Secrets::InteractionRequestWatcherPrivate *m_data;
};

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_INTERACTIONREQUESTWATCHER_H
