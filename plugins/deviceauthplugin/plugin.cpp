/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * BSD 3-Clause License, see LICENSE.
 */
#include "plugin.h"
#include <nemo-devicelock/authenticator.h>
#include <QTimer>
using namespace Sailfish::Secrets;
using namespace Sailfish::Secrets::Daemon::Plugins;
using NemoDeviceLock::Authenticator;

Result DeviceAuthPlugin::beginAuthentication(uint callerPid, qint64 requestId,
                                            const InteractionParameters::PromptText &promptText)
{
    const auto key = qMakePair(callerPid, requestId);
    if (m_requests.contains(key)) {
        return Result(Result::DaemonError, QStringLiteral("Duplicate authentication request"));
    }
    QTimer *timeout = new QTimer(this);
    timeout->setSingleShot(true);
    m_requests.insert(key, timeout);
    Authenticator *authenticator = new Authenticator(timeout);
    connect(timeout, &QTimer::timeout, this, [this, callerPid, requestId] {
        finish(callerPid, requestId, Result(Result::AuthenticationTimeoutError,
                                          QStringLiteral("Device authentication timed out")));
    });
    connect(authenticator, &Authenticator::permissionGranted, this,
            [this, callerPid, requestId](Authenticator::Method method) {
        // Never accept simple confirmation or an unauthenticated result.
        finish(callerPid, requestId,
               method == Authenticator::SecurityCode || method == Authenticator::Fingerprint
               ? Result(Result::Succeeded)
               : Result(Result::IncorrectAuthenticationCodeError,
                        QStringLiteral("A security code or fingerprint is required")));
    });
    connect(authenticator, &Authenticator::aborted, this, [this, callerPid, requestId] {
        finish(callerPid, requestId, Result(Result::InteractionViewUserCanceledError,
                                          QStringLiteral("Device authentication canceled")));
    });
    timeout->start(120000);
    // Allow the daemon to register its pending request before any completion.
    QTimer::singleShot(0, authenticator, [authenticator, callerPid, promptText] {
        authenticator->requestPermission(promptText.message(),
                {{QStringLiteral("authenticatingPid"), QVariant::fromValue(callerPid)}},
                Authenticator::SecurityCode | Authenticator::Fingerprint);
    });
    return Result(Result::Pending);
}

void DeviceAuthPlugin::finish(uint callerPid, qint64 requestId, const Result &result)
{
    QTimer *timeout = m_requests.take(qMakePair(callerPid, requestId));
    if (timeout) {
        timeout->stop();
        timeout->deleteLater();
        emit authenticationCompleted(callerPid, requestId, result);
    }
}

void DeviceAuthPlugin::cancelAuthentication(uint callerPid, qint64 requestId)
{
    QTimer *timeout = m_requests.take(qMakePair(callerPid, requestId));
    if (timeout) {
        timeout->stop();
        timeout->deleteLater();
    }
}
