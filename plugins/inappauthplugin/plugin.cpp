/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"

Q_PLUGIN_METADATA(IID Sailfish_Secrets_AuthenticationPlugin_IID)

Q_LOGGING_CATEGORY(lcSailfishSecretsPluginInapp, "org.sailfishos.secrets.plugin.authentication.inapp", QtWarningMsg)

Sailfish::Secrets::Daemon::Plugins::InAppPlugin::InAppPlugin(QObject *parent)
    : Sailfish::Secrets::AuthenticationPlugin(parent)
{
}

Sailfish::Secrets::Daemon::Plugins::InAppPlugin::~InAppPlugin()
{
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::InAppPlugin::beginAuthentication(
            uint callerPid,
            qint64 requestId,
            const QString &callerApplicationId,
            const QString &collectionName,
            const QString &secretName,
            const QString &interactionServiceAddress)
{
    Sailfish::Secrets::InteractionRequestWatcher *watcher = new Sailfish::Secrets::InteractionRequestWatcher(this);
    watcher->setRequestId(requestId);
    watcher->setCallerPid(callerPid);
    watcher->setCallerApplicationId(callerApplicationId);
    watcher->setCollectionName(collectionName);
    watcher->setSecretName(secretName);
    watcher->setInteractionServiceAddress(interactionServiceAddress);
    connect(watcher, static_cast<void (Sailfish::Secrets::InteractionRequestWatcher::*)(quint64)>(&Sailfish::Secrets::InteractionRequestWatcher::interactionRequestFinished),
            this, &Sailfish::Secrets::Daemon::Plugins::InAppPlugin::interactionRequestFinished);
    connect(watcher, &Sailfish::Secrets::InteractionRequestWatcher::interactionRequestResponse,
            this, &Sailfish::Secrets::Daemon::Plugins::InAppPlugin::interactionRequestResponse);

    if (!watcher->connectToInteractionService()) {
        watcher->deleteLater();
        return Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::InteractionServiceUnavailableError,
                    QString::fromUtf8("Unable to connect to ui service"));
    }

    // TODO: include the collectionName + secretName + in the future operation type (read/update/insert/delete)
    if (!watcher->sendInteractionRequest(Sailfish::Secrets::InteractionRequest(Sailfish::Secrets::InteractionRequest::AuthenticationKeyRequest))) {
        watcher->deleteLater();
        return Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::InteractionServiceRequestFailedError,
                    QString::fromUtf8("Unable to send authentication key request to ui service"));
    }

    m_requests.insert(requestId, watcher);
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Pending);
}

void
Sailfish::Secrets::Daemon::Plugins::InAppPlugin::interactionRequestResponse(
        quint64 requestId,
        const Sailfish::Secrets::Result &result,
        const Sailfish::Secrets::InteractionResponse &response)
{
    Sailfish::Secrets::InteractionRequestWatcher *watcher = m_requests.value(requestId);
    if (watcher == Q_NULLPTR) {
        qCDebug(lcSailfishSecretsPluginInapp) << "Unknown ui request response:" << requestId;
        return;
    }

    emit authenticationCompleted(
                watcher->callerPid(),
                watcher->requestId(),
                watcher->callerApplicationId(),
                watcher->collectionName(),
                watcher->secretName(),
                watcher->interactionServiceAddress(),
                result,
                response.authenticationKey());

    watcher->finishInteractionRequest();
}

void
Sailfish::Secrets::Daemon::Plugins::InAppPlugin::interactionRequestFinished(
        quint64 requestId)
{
    Sailfish::Secrets::InteractionRequestWatcher *watcher = m_requests.value(requestId);
    if (watcher == Q_NULLPTR) {
        qCDebug(lcSailfishSecretsPluginInapp) << "Unknown ui request finished:" << requestId;
        return;
    }
    watcher->disconnectFromInteractionService();
    watcher->deleteLater();
}
