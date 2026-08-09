/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "../../../daemon/SecretsImpl/keymintdevicelocknotifier_p.h"
#include "Crypto/Plugins/extensionplugins.h"

#include <QtCore/QVector>
#include <QtTest/QTest>

using namespace Sailfish::Secrets::Daemon::ApiImpl;

class FakeKeyMintProvider : public Sailfish::Crypto::KeyMintOperationExtension
{
public:
    FakeKeyMintProvider()
        : keyMintError(0)
        , authenticationStateError(0)
        , result(Sailfish::Crypto::Result::Succeeded)
    {
    }

    Sailfish::Crypto::Result keyMintOneShot(
            quint32, const QByteArray &, qint32 *, QByteArray *) Q_DECL_OVERRIDE
    {
        return Sailfish::Crypto::Result(
                    Sailfish::Crypto::Result::OperationNotSupportedError,
                    QStringLiteral("not used"));
    }

    Sailfish::Crypto::Result keyMintBegin(
            const QByteArray &, qint32 *, quint64 *, QByteArray *) Q_DECL_OVERRIDE
    {
        return Sailfish::Crypto::Result(
                    Sailfish::Crypto::Result::OperationNotSupportedError,
                    QStringLiteral("not used"));
    }

    Sailfish::Crypto::Result keyMintUpdate(
            quint64, const QByteArray &, qint32 *, QByteArray *) Q_DECL_OVERRIDE
    {
        return Sailfish::Crypto::Result(
                    Sailfish::Crypto::Result::OperationNotSupportedError,
                    QStringLiteral("not used"));
    }

    Sailfish::Crypto::Result keyMintFinish(
            quint64, const QByteArray &, qint32 *, QByteArray *) Q_DECL_OVERRIDE
    {
        return Sailfish::Crypto::Result(
                    Sailfish::Crypto::Result::OperationNotSupportedError,
                    QStringLiteral("not used"));
    }

    Sailfish::Crypto::Result keyMintAbort(quint64, qint32 *) Q_DECL_OVERRIDE
    {
        return Sailfish::Crypto::Result(
                    Sailfish::Crypto::Result::OperationNotSupportedError,
                    QStringLiteral("not used"));
    }

    Sailfish::Crypto::Result keyMintDeviceLocked(
            bool passwordOnly, qint32 *error) Q_DECL_OVERRIDE
    {
        lockCalls.append(passwordOnly);
        if (error) {
            *error = keyMintError;
        }
        return result;
    }

    Sailfish::Crypto::Result keyMintSetAuthenticationState(
            quint64 secureUserId,
            quint64 fingerprintAuthenticatorId,
            qint32 *error) Q_DECL_OVERRIDE
    {
        secureUserIds.append(secureUserId);
        fingerprintAuthenticatorIds.append(fingerprintAuthenticatorId);
        if (error) {
            *error = authenticationStateError;
        }
        return result;
    }

    QVector<bool> lockCalls;
    QVector<quint64> secureUserIds;
    QVector<quint64> fingerprintAuthenticatorIds;
    qint32 keyMintError;
    qint32 authenticationStateError;
    Sailfish::Crypto::Result result;
};

class tst_keymintdevicelock : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void startupAndBrokerLossFailClosed();
    void stateTransitionsPropagate();
    void fingerprintIdentityTransitionsPropagate();
    void lifecycleEventsRequirePin();
    void providerFailureIsRetried();
    void authenticationStateFailureIsRetried();
};

static DeviceLockBrokerClient::State unlockedState()
{
    DeviceLockBrokerClient::State state;
    state.status = DeviceLockBrokerClient::Ok;
    state.sailfishUserId = 100000;
    state.gatekeeperUserId = 100000;
    state.flags = DeviceLockBrokerClient::SecurityCodeEnabled
            | DeviceLockBrokerClient::GatekeeperSelected
            | DeviceLockBrokerClient::IdentityValid
            | DeviceLockBrokerClient::BootstrapAllowed;
    state.secureUserId = Q_UINT64_C(0x1020304050607080);
    state.identityEpoch = QByteArray::fromHex(
                "00112233445566778899aabbccddeeff");
    state.flags |= DeviceLockBrokerClient::FingerprintEnrolled;
    state.fingerprintAuthenticatorId = Q_UINT64_C(0x2122232425262728);
    state.supportedMethods = DeviceLockBrokerClient::Pin
            | DeviceLockBrokerClient::Fingerprint;
    state.fingerprintStrength = 0x000f;
    return state;
}

void tst_keymintdevicelock::startupAndBrokerLossFailClosed()
{
    FakeKeyMintProvider provider;
    KeyMintDeviceLockNotifier notifier;
    notifier.setProvider(&provider);

    QString error;
    QVERIFY(notifier.startup(&error));
    QVERIFY(error.isEmpty());
    QCOMPARE(provider.lockCalls, QVector<bool>() << true);
    QCOMPARE(provider.secureUserIds, QVector<quint64>() << 0);
    QCOMPARE(provider.fingerprintAuthenticatorIds, QVector<quint64>() << 0);

    QVERIFY(notifier.stateChanged(unlockedState(), Q_NULLPTR, &error));
    QCOMPARE(provider.lockCalls.size(), 1);
    QCOMPARE(provider.secureUserIds.last(), unlockedState().secureUserId);
    QCOMPARE(provider.fingerprintAuthenticatorIds.last(),
             unlockedState().fingerprintAuthenticatorId);

    QVERIFY(notifier.brokerUnavailable(&error));
    QCOMPARE(provider.lockCalls, QVector<bool>() << true << true);
    QCOMPARE(provider.secureUserIds.last(), quint64(0));
    QCOMPARE(provider.fingerprintAuthenticatorIds.last(), quint64(0));
}

void tst_keymintdevicelock::stateTransitionsPropagate()
{
    FakeKeyMintProvider provider;
    KeyMintDeviceLockNotifier notifier;
    notifier.setProvider(&provider);

    DeviceLockBrokerClient::State state = unlockedState();
    bool identityChanged = true;
    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QVERIFY(!identityChanged);
    QVERIFY(provider.lockCalls.isEmpty());
    QCOMPARE(provider.secureUserIds, QVector<quint64>() << state.secureUserId);
    QCOMPARE(provider.fingerprintAuthenticatorIds,
             QVector<quint64>() << state.fingerprintAuthenticatorId);

    state.flags |= DeviceLockBrokerClient::DeviceLocked;
    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QVERIFY(!identityChanged);
    QCOMPARE(provider.lockCalls, QVector<bool>() << false);

    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QCOMPARE(provider.lockCalls.size(), 1);

    state.flags |= DeviceLockBrokerClient::PinRequired;
    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QCOMPARE(provider.lockCalls, QVector<bool>() << false << true);

    state.flags &= ~(DeviceLockBrokerClient::DeviceLocked
                     | DeviceLockBrokerClient::PinRequired);
    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QCOMPARE(provider.lockCalls.size(), 2);

    ++state.secureUserId;
    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QVERIFY(identityChanged);
    QCOMPARE(provider.lockCalls, QVector<bool>() << false << true << false);
    QCOMPARE(provider.secureUserIds.last(), state.secureUserId);

    state.status = DeviceLockBrokerClient::Unavailable;
    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QCOMPARE(provider.lockCalls,
             QVector<bool>() << false << true << false << true);
    QCOMPARE(provider.secureUserIds.last(), quint64(0));
    QCOMPARE(provider.fingerprintAuthenticatorIds.last(), quint64(0));
}

void tst_keymintdevicelock::fingerprintIdentityTransitionsPropagate()
{
    FakeKeyMintProvider provider;
    KeyMintDeviceLockNotifier notifier;
    notifier.setProvider(&provider);

    DeviceLockBrokerClient::State state = unlockedState();
    QVERIFY(notifier.stateChanged(state));
    QCOMPARE(provider.fingerprintAuthenticatorIds,
             QVector<quint64>() << state.fingerprintAuthenticatorId);

    ++state.fingerprintAuthenticatorId;
    QVERIFY(notifier.stateChanged(state));
    QCOMPARE(provider.fingerprintAuthenticatorIds.last(),
             state.fingerprintAuthenticatorId);
    QVERIFY(provider.lockCalls.isEmpty());

    state.flags |= DeviceLockBrokerClient::PinRequired;
    QVERIFY(notifier.stateChanged(state));
    QCOMPARE(provider.fingerprintAuthenticatorIds.last(),
             state.fingerprintAuthenticatorId);
    QCOMPARE(provider.lockCalls, QVector<bool>() << true);

    state.flags &= ~DeviceLockBrokerClient::FingerprintEnrolled;
    QVERIFY(notifier.stateChanged(state));
    QCOMPARE(provider.fingerprintAuthenticatorIds.last(), quint64(0));

    state.flags |= DeviceLockBrokerClient::FingerprintEnrolled;
    state.fingerprintStrength = 0x00ff;
    QVERIFY(notifier.stateChanged(state));
    QCOMPARE(provider.fingerprintAuthenticatorIds.last(), quint64(0));
}

void tst_keymintdevicelock::lifecycleEventsRequirePin()
{
    FakeKeyMintProvider provider;
    KeyMintDeviceLockNotifier notifier;
    notifier.setProvider(&provider);
    QVERIFY(notifier.stateChanged(unlockedState()));

    QVERIFY(notifier.lifecycleEvent(DeviceLockBrokerClient::Provisioned));
    QVERIFY(notifier.lifecycleEvent(DeviceLockBrokerClient::Changed));
    QVERIFY(notifier.lifecycleEvent(DeviceLockBrokerClient::RemovePending));
    QVERIFY(notifier.lifecycleEvent(DeviceLockBrokerClient::Removed));
    QVERIFY(notifier.lifecycleEvent(DeviceLockBrokerClient::IdentityInvalidated));
    QVERIFY(notifier.lifecycleEvent(DeviceLockBrokerClient::UserChanged));
    QCOMPARE(provider.lockCalls.size(), 6);
    for (bool passwordOnly : provider.lockCalls) {
        QVERIFY(passwordOnly);
    }
    QCOMPARE(provider.secureUserIds.last(), quint64(0));
    QCOMPARE(provider.fingerprintAuthenticatorIds.last(), quint64(0));
}

void tst_keymintdevicelock::providerFailureIsRetried()
{
    FakeKeyMintProvider provider;
    provider.keyMintError = -49;
    KeyMintDeviceLockNotifier notifier;
    notifier.setProvider(&provider);

    QString error;
    QVERIFY(!notifier.startup(&error));
    QVERIFY(error.contains(QStringLiteral("-49")));
    QCOMPARE(provider.lockCalls, QVector<bool>() << true);

    provider.keyMintError = 0;
    QVERIFY(notifier.stateChanged(unlockedState(), Q_NULLPTR, &error));
    QVERIFY(error.isEmpty());
    QCOMPARE(provider.lockCalls, QVector<bool>() << true << false);

    provider.result = Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::DaemonError,
                QStringLiteral("transport failed"));
    QVERIFY(!notifier.brokerUnavailable(&error));
    QCOMPARE(error, QStringLiteral("transport failed"));
}

void tst_keymintdevicelock::authenticationStateFailureIsRetried()
{
    FakeKeyMintProvider provider;
    provider.authenticationStateError = -49;
    KeyMintDeviceLockNotifier notifier;
    notifier.setProvider(&provider);

    const DeviceLockBrokerClient::State state = unlockedState();
    QString error;
    QVERIFY(!notifier.stateChanged(state, Q_NULLPTR, &error));
    QVERIFY(error.contains(QStringLiteral("-49")));
    QCOMPARE(provider.secureUserIds, QVector<quint64>() << state.secureUserId);
    QVERIFY(provider.lockCalls.isEmpty());

    provider.authenticationStateError = 0;
    QVERIFY(notifier.stateChanged(state, Q_NULLPTR, &error));
    QVERIFY(error.isEmpty());
    QCOMPARE(provider.secureUserIds,
             QVector<quint64>() << state.secureUserId << state.secureUserId);
    QVERIFY(provider.lockCalls.isEmpty());
}

QTEST_APPLESS_MAIN(tst_keymintdevicelock)

#include "tst_keymintdevicelock.moc"
