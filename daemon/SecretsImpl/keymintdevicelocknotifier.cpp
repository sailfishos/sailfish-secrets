/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "keymintdevicelocknotifier_p.h"

#include "Crypto/Plugins/extensionplugins.h"

using namespace Sailfish::Secrets::Daemon::ApiImpl;

KeyMintDeviceLockNotifier::KeyMintDeviceLockNotifier()
    : m_provider(Q_NULLPTR)
    , m_haveState(false)
    , m_retryRequired(false)
{
}

void KeyMintDeviceLockNotifier::setProvider(
        Sailfish::Crypto::KeyMintOperationExtension *provider)
{
    m_provider = provider;
}

bool KeyMintDeviceLockNotifier::notify(bool passwordOnly, QString *errorMessage)
{
    if (!m_provider) {
        m_retryRequired = true;
        if (errorMessage) {
            *errorMessage = QStringLiteral("No KeyMint device-lock provider is available");
        }
        return false;
    }

    qint32 keyMintError = 0;
    const Sailfish::Crypto::Result result = m_provider->keyMintDeviceLocked(
                passwordOnly, &keyMintError);
    if (result.code() != Sailfish::Crypto::Result::Succeeded || keyMintError != 0) {
        m_retryRequired = true;
        if (errorMessage) {
            *errorMessage = result.errorMessage().isEmpty()
                    ? QStringLiteral("KeyMint deviceLocked failed (%1)").arg(keyMintError)
                    : result.errorMessage();
        }
        return false;
    }

    m_retryRequired = false;
    if (errorMessage) {
        errorMessage->clear();
    }
    return true;
}

bool KeyMintDeviceLockNotifier::startup(QString *errorMessage)
{
    m_haveState = false;
    return notify(true, errorMessage);
}

bool KeyMintDeviceLockNotifier::brokerUnavailable(QString *errorMessage)
{
    m_haveState = false;
    return notify(true, errorMessage);
}

bool KeyMintDeviceLockNotifier::stateChanged(
        const DeviceLockBrokerClient::State &state,
        bool *identityChanged,
        QString *errorMessage)
{
    const bool firstState = !m_haveState;
    const bool changedIdentity = m_haveState
            && (state.sailfishUserId != m_state.sailfishUserId
                || state.gatekeeperUserId != m_state.gatekeeperUserId
                || state.secureUserId != m_state.secureUserId
                || state.identityEpoch != m_state.identityEpoch);
    const bool locked = state.flags & DeviceLockBrokerClient::DeviceLocked;
    const bool pinRequired = state.flags & DeviceLockBrokerClient::PinRequired;
    const bool becameLocked = locked
            && (firstState
                || !(m_state.flags & DeviceLockBrokerClient::DeviceLocked));
    const bool pinRequiredAsserted = pinRequired
            && (firstState
                || !(m_state.flags & DeviceLockBrokerClient::PinRequired));
    const bool stateUnavailable = state.status != DeviceLockBrokerClient::Ok;
    const bool becameUnavailable = stateUnavailable
            && (firstState || m_state.status == DeviceLockBrokerClient::Ok);

    m_state = state;
    m_haveState = true;
    if (identityChanged) {
        *identityChanged = changedIdentity;
    }

    if (m_retryRequired || becameUnavailable || becameLocked
            || pinRequiredAsserted || changedIdentity) {
        return notify(stateUnavailable || pinRequired, errorMessage);
    }
    if (errorMessage) {
        errorMessage->clear();
    }
    return true;
}

bool KeyMintDeviceLockNotifier::lifecycleEvent(
        DeviceLockBrokerClient::LifecycleEvent event,
        QString *errorMessage)
{
    switch (event) {
    case DeviceLockBrokerClient::Provisioned:
    case DeviceLockBrokerClient::Changed:
    case DeviceLockBrokerClient::RemovePending:
    case DeviceLockBrokerClient::Removed:
    case DeviceLockBrokerClient::IdentityInvalidated:
    case DeviceLockBrokerClient::UserChanged:
        // Every lifecycle event changes or invalidates the authentication
        // identity.  Require the next unlock to include a PIN HAT.
        return notify(true, errorMessage);
    }
    if (errorMessage) {
        errorMessage->clear();
    }
    return true;
}
