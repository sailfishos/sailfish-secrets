/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"

Q_PLUGIN_METADATA(IID Sailfish_Secrets_AuthenticationPlugin_IID)

Q_LOGGING_CATEGORY(lcSailfishSecretsPluginInapp, "org.sailfishos.secrets.plugin.authentication.inapp")

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
            const QString &uiServiceAddress)
{
    Sailfish::Secrets::UiRequestWatcher *watcher = new Sailfish::Secrets::UiRequestWatcher(this);
    watcher->setRequestId(requestId);
    watcher->setCallerPid(callerPid);
    watcher->setCallerApplicationId(callerApplicationId);
    watcher->setCollectionName(collectionName);
    watcher->setSecretName(secretName);
    watcher->setUiServiceAddress(uiServiceAddress);
    connect(watcher, static_cast<void (Sailfish::Secrets::UiRequestWatcher::*)(quint64)>(&Sailfish::Secrets::UiRequestWatcher::uiRequestFinished),
            this, &Sailfish::Secrets::Daemon::Plugins::InAppPlugin::uiRequestFinished);
    connect(watcher, &Sailfish::Secrets::UiRequestWatcher::uiRequestResponse,
            this, &Sailfish::Secrets::Daemon::Plugins::InAppPlugin::uiRequestResponse);

    if (!watcher->connectToUiService()) {
        watcher->deleteLater();
        return Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiServiceUnavailableError,
                    QString::fromUtf8("Unable to connect to ui service"));
    }

    // TODO: include the collectionName + secretName + in the future operation type (read/update/insert/delete)
    if (!watcher->sendUiRequest(Sailfish::Secrets::UiRequest(Sailfish::Secrets::UiRequest::AuthenticationKeyRequest))) {
        watcher->deleteLater();
        return Sailfish::Secrets::Result(
                    Sailfish::Secrets::Result::UiServiceRequestFailedError,
                    QString::fromUtf8("Unable to send authentication key request to ui service"));
    }

    m_requests.insert(requestId, watcher);
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Pending);
}

void
Sailfish::Secrets::Daemon::Plugins::InAppPlugin::uiRequestResponse(
        quint64 requestId,
        const Sailfish::Secrets::Result &result,
        const Sailfish::Secrets::UiResponse &response)
{
    Sailfish::Secrets::UiRequestWatcher *watcher = m_requests.value(requestId);
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
                watcher->uiServiceAddress(),
                result,
                response.authenticationKey());

    watcher->finishUiRequest();
}

void
Sailfish::Secrets::Daemon::Plugins::InAppPlugin::uiRequestFinished(
        quint64 requestId)
{
    Sailfish::Secrets::UiRequestWatcher *watcher = m_requests.value(requestId);
    if (watcher == Q_NULLPTR) {
        qCDebug(lcSailfishSecretsPluginInapp) << "Unknown ui request finished:" << requestId;
        return;
    }
    watcher->disconnectFromUiService();
    watcher->deleteLater();
}
