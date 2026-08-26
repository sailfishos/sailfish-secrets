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
        calls.append(passwordOnly);
        if (error) {
            *error = keyMintError;
        }
        return result;
    }

    QVector<bool> calls;
    qint32 keyMintError;
    Sailfish::Crypto::Result result;
};

class tst_keymintdevicelock : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void startupAndBrokerLossFailClosed();
    void stateTransitionsPropagate();
    void lifecycleEventsRequirePin();
    void providerFailureIsRetried();
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
    QCOMPARE(provider.calls, QVector<bool>() << true);

    QVERIFY(notifier.stateChanged(unlockedState(), Q_NULLPTR, &error));
    QCOMPARE(provider.calls.size(), 1);

    QVERIFY(notifier.brokerUnavailable(&error));
    QCOMPARE(provider.calls, QVector<bool>() << true << true);
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
    QVERIFY(provider.calls.isEmpty());

    state.flags |= DeviceLockBrokerClient::DeviceLocked;
    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QVERIFY(!identityChanged);
    QCOMPARE(provider.calls, QVector<bool>() << false);

    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QCOMPARE(provider.calls.size(), 1);

    state.flags |= DeviceLockBrokerClient::PinRequired;
    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QCOMPARE(provider.calls, QVector<bool>() << false << true);

    state.flags &= ~(DeviceLockBrokerClient::DeviceLocked
                     | DeviceLockBrokerClient::PinRequired);
    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QCOMPARE(provider.calls.size(), 2);

    ++state.secureUserId;
    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QVERIFY(identityChanged);
    QCOMPARE(provider.calls, QVector<bool>() << false << true << false);

    state.status = DeviceLockBrokerClient::Unavailable;
    QVERIFY(notifier.stateChanged(state, &identityChanged));
    QCOMPARE(provider.calls, QVector<bool>() << false << true << false << true);
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
    QCOMPARE(provider.calls.size(), 6);
    for (bool passwordOnly : provider.calls) {
        QVERIFY(passwordOnly);
    }
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
    QCOMPARE(provider.calls, QVector<bool>() << true);

    provider.keyMintError = 0;
    QVERIFY(notifier.stateChanged(unlockedState(), Q_NULLPTR, &error));
    QVERIFY(error.isEmpty());
    QCOMPARE(provider.calls, QVector<bool>() << true << false);

    provider.result = Sailfish::Crypto::Result(
                Sailfish::Crypto::Result::DaemonError,
                QStringLiteral("transport failed"));
    QVERIFY(!notifier.brokerUnavailable(&error));
    QCOMPARE(error, QStringLiteral("transport failed"));
}

QTEST_APPLESS_MAIN(tst_keymintdevicelock)

#include "tst_keymintdevicelock.moc"
