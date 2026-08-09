/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "keymintdevicelocknotifier_p.h"

#include "Crypto/Plugins/extensionplugins.h"

using namespace Sailfish::Secrets::Daemon::ApiImpl;

namespace {

const quint32 AndroidBiometricStrong = 0x000f;

bool validIdentity(const DeviceLockBrokerClient::State &state)
{
    const quint32 required = DeviceLockBrokerClient::SecurityCodeEnabled
            | DeviceLockBrokerClient::GatekeeperSelected
            | DeviceLockBrokerClient::IdentityValid
            | DeviceLockBrokerClient::BootstrapAllowed;
    return state.status == DeviceLockBrokerClient::Ok
            && (state.flags & required) == required
            && state.secureUserId != 0;
}

quint64 activeFingerprintAuthenticatorId(
        const DeviceLockBrokerClient::State &state)
{
    return validIdentity(state)
            && (state.flags & DeviceLockBrokerClient::FingerprintEnrolled)
            && (state.supportedMethods & DeviceLockBrokerClient::Fingerprint)
            && state.fingerprintStrength == AndroidBiometricStrong
            ? state.fingerprintAuthenticatorId : 0;
}

}

KeyMintDeviceLockNotifier::KeyMintDeviceLockNotifier()
    : m_provider(Q_NULLPTR)
    , m_haveState(false)
    , m_lockRetryRequired(false)
    , m_stateRetryRequired(false)
{
}

void KeyMintDeviceLockNotifier::setProvider(
        Sailfish::Crypto::KeyMintOperationExtension *provider)
{
    m_provider = provider;
}

bool KeyMintDeviceLockNotifier::notifyLocked(
        bool passwordOnly,
        QString *errorMessage)
{
    if (!m_provider) {
        m_lockRetryRequired = true;
        if (errorMessage) {
            *errorMessage = QStringLiteral("No KeyMint device-lock provider is available");
        }
        return false;
    }

    qint32 keyMintError = 0;
    const Sailfish::Crypto::Result result = m_provider->keyMintDeviceLocked(
                passwordOnly, &keyMintError);
    if (result.code() != Sailfish::Crypto::Result::Succeeded || keyMintError != 0) {
        m_lockRetryRequired = true;
        if (errorMessage) {
            *errorMessage = result.errorMessage().isEmpty()
                    ? QStringLiteral("KeyMint deviceLocked failed (%1)").arg(keyMintError)
                    : result.errorMessage();
        }
        return false;
    }

    m_lockRetryRequired = false;
    if (errorMessage) {
        errorMessage->clear();
    }
    return true;
}

bool KeyMintDeviceLockNotifier::updateAuthenticationState(
        quint64 secureUserId,
        quint64 fingerprintAuthenticatorId,
        QString *errorMessage)
{
    if (!m_provider) {
        m_stateRetryRequired = true;
        if (errorMessage) {
            *errorMessage = QStringLiteral(
                        "No KeyMint authentication-state provider is available");
        }
        return false;
    }

    qint32 keyMintError = 0;
    const Sailfish::Crypto::Result result
            = m_provider->keyMintSetAuthenticationState(
                secureUserId, fingerprintAuthenticatorId, &keyMintError);
    if (result.code() != Sailfish::Crypto::Result::Succeeded || keyMintError != 0) {
        m_stateRetryRequired = true;
        if (errorMessage) {
            *errorMessage = result.errorMessage().isEmpty()
                    ? QStringLiteral("KeyMint authentication-state update failed (%1)")
                        .arg(keyMintError)
                    : result.errorMessage();
        }
        return false;
    }

    m_stateRetryRequired = false;
    if (errorMessage) {
        errorMessage->clear();
    }
    return true;
}

bool KeyMintDeviceLockNotifier::startup(QString *errorMessage)
{
    m_haveState = false;
    QString stateError;
    QString lockError;
    const bool stateUpdated = updateAuthenticationState(0, 0, &stateError);
    const bool lockUpdated = notifyLocked(true, &lockError);
    if (errorMessage) {
        *errorMessage = stateUpdated ? lockError : stateError;
    }
    return stateUpdated && lockUpdated;
}

bool KeyMintDeviceLockNotifier::brokerUnavailable(QString *errorMessage)
{
    m_haveState = false;
    QString stateError;
    QString lockError;
    const bool stateUpdated = updateAuthenticationState(0, 0, &stateError);
    const bool lockUpdated = notifyLocked(true, &lockError);
    if (errorMessage) {
        *errorMessage = stateUpdated ? lockError : stateError;
    }
    return stateUpdated && lockUpdated;
}

bool KeyMintDeviceLockNotifier::stateChanged(
        const DeviceLockBrokerClient::State &state,
        bool *identityChanged,
        QString *errorMessage)
{
    const bool firstState = !m_haveState;
    const quint64 previousSecureUserId = m_haveState && validIdentity(m_state)
            ? m_state.secureUserId : 0;
    const quint64 previousFingerprintAuthenticatorId = m_haveState
            ? activeFingerprintAuthenticatorId(m_state) : 0;
    const quint64 secureUserId = validIdentity(state) ? state.secureUserId : 0;
    const quint64 fingerprintAuthenticatorId
            = activeFingerprintAuthenticatorId(state);
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

    QString stateError;
    QString lockError;
    bool stateUpdated = true;
    bool lockUpdated = true;
    if (m_stateRetryRequired || firstState
            || previousSecureUserId != secureUserId
            || previousFingerprintAuthenticatorId
                    != fingerprintAuthenticatorId) {
        stateUpdated = updateAuthenticationState(
                    secureUserId, fingerprintAuthenticatorId, &stateError);
    }
    if (m_lockRetryRequired || becameUnavailable || becameLocked
            || pinRequiredAsserted || changedIdentity) {
        lockUpdated = notifyLocked(stateUnavailable || pinRequired, &lockError);
    }
    if (errorMessage) {
        *errorMessage = stateUpdated ? lockError : stateError;
    }
    return stateUpdated && lockUpdated;
}

bool KeyMintDeviceLockNotifier::lifecycleEvent(
        DeviceLockBrokerClient::LifecycleEvent event,
        QString *errorMessage)
{
    m_haveState = false;
    QString stateError;
    QString lockError;
    const bool stateUpdated = updateAuthenticationState(0, 0, &stateError);
    bool lockUpdated = true;
    switch (event) {
    case DeviceLockBrokerClient::Provisioned:
    case DeviceLockBrokerClient::Changed:
    case DeviceLockBrokerClient::RemovePending:
    case DeviceLockBrokerClient::Removed:
    case DeviceLockBrokerClient::IdentityInvalidated:
    case DeviceLockBrokerClient::UserChanged:
        // Every lifecycle event changes or invalidates the authentication
        // identity.  Require the next unlock to include a PIN HAT.
        lockUpdated = notifyLocked(true, &lockError);
        break;
    }
    if (errorMessage) {
        *errorMessage = stateUpdated ? lockError : stateError;
    }
    return stateUpdated && lockUpdated;
}
