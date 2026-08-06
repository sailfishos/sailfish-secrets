/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_DEVICELOCKBROKERCLIENT_P_H
#define SAILFISHSECRETS_DEVICELOCKBROKERCLIENT_P_H

#include <QtCore/QByteArray>
#include <QtCore/QHash>
#include <QtCore/QObject>
#include <QtCore/QSet>

class QLocalSocket;

namespace Sailfish {
namespace Secrets {
namespace Daemon {
namespace ApiImpl {

class DeviceLockBrokerClient : public QObject
{
    Q_OBJECT

public:
    enum Status {
        Ok = 0,
        Accepted = 1,
        Unavailable = -1,
        InvalidArgument = -2,
        PermissionDenied = -3,
        Canceled = -4,
        Timeout = -5,
        Busy = -6,
        AuthenticationFailed = -7,
        LockedOut = -8,
        NotSupported = -9,
        ProtocolError = -10,
        NotProvisioned = -11,
        BackendError = -12
    };

    enum Method {
        Pin = 0x1,
        Fingerprint = 0x2
    };
    Q_DECLARE_FLAGS(Methods, Method)

    enum Purpose {
        UnlockPurpose = 1,
        KeyStorePurpose = 2,
        SecretsBootstrapPurpose = 3
    };

    enum StateFlag {
        SecurityCodeEnabled = 0x0001,
        DeviceLocked = 0x0002,
        PinRequired = 0x0004,
        FingerprintEnrolled = 0x0008,
        TemporarilyLocked = 0x0010,
        GatekeeperSelected = 0x0020,
        IdentityValid = 0x0040,
        BootstrapAllowed = 0x0080
    };

    enum LifecycleEvent {
        Provisioned = 1,
        Changed = 2,
        RemovePending = 3,
        Removed = 4,
        IdentityInvalidated = 5,
        UserChanged = 6
    };

    struct State {
        qint32 status = Unavailable;
        quint32 sailfishUserId = 0;
        quint32 gatekeeperUserId = 0;
        quint32 flags = 0;
        quint64 secureUserId = 0;
        QByteArray identityEpoch;
        quint64 fingerprintAuthenticatorId = 0;
        quint32 supportedMethods = 0;
        quint32 fingerprintStrength = 0;
        qint64 lockoutDeadlineBootMs = 0;
    };

    struct AuthenticationResult {
        qint32 status = Unavailable;
        quint32 actualMethod = 0;
        quint64 challenge = 0;
        quint64 secureUserId = 0;
        QByteArray identityEpoch;
        QByteArray serializedHardwareAuthToken;
    };

    explicit DeviceLockBrokerClient(QObject *parent = Q_NULLPTR);
    ~DeviceLockBrokerClient();

    void connectToBroker();
    quint64 getState();
    quint64 registerBootstrap(quint64 challenge);
    quint64 subscribeLifecycle();
    quint64 acknowledgeLifecycle(const QByteArray &transactionId,
                                 LifecycleEvent event);
    quint64 cancel(quint64 targetRequestId);

Q_SIGNALS:
    void connected();
    void unavailable();
    void stateChanged(const Sailfish::Secrets::Daemon::ApiImpl::DeviceLockBrokerClient::State &state);
    void authenticationCompleted(quint64 requestId,
                                 const Sailfish::Secrets::Daemon::ApiImpl::DeviceLockBrokerClient::AuthenticationResult &result);
    void lifecycleEvent(Sailfish::Secrets::Daemon::ApiImpl::DeviceLockBrokerClient::LifecycleEvent event,
                        quint32 sailfishUserId,
                        quint64 secureUserId,
                        const QByteArray &identityEpoch,
                        const QByteArray &transactionId);
    void commandCompleted(quint64 requestId, qint32 status);

private Q_SLOTS:
    void socketConnected();
    void socketReadyRead();
    void socketDisconnected();

private:
    enum Message {
        GetStateMessage = 1,
        AuthenticateMessage = 2,
        RegisterBootstrapMessage = 3,
        CancelMessage = 4,
        SubscribeLifecycleMessage = 5,
        AckLifecycleMessage = 6,
        StateResponse = 0x8001,
        AuthenticateResponse = 0x8002,
        RegisterBootstrapResponse = 0x8003,
        CancelResponse = 0x8004,
        SubscribeLifecycleResponse = 0x8005,
        AckLifecycleResponse = 0x8006,
        AuthenticationEvent = 0x9001,
        StateChangedEvent = 0x9002,
        LifecycleEventMessage = 0x9003
    };

    quint64 sendRequest(Message message, const QByteArray &payload);
    void processFrames();
    bool processFrame(quint16 message, quint64 requestId,
                      const QByteArray &payload);
    bool verifySocketPath() const;
    bool verifyPeer() const;
    void failClosed();

    QLocalSocket *m_socket;
    QByteArray m_input;
    quint64 m_nextRequestId;
    QHash<quint64, Message> m_pending;
    QSet<quint64> m_authenticationRequests;
};

} // namespace ApiImpl
} // namespace Daemon
} // namespace Secrets
} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Secrets::Daemon::ApiImpl::DeviceLockBrokerClient::State)
Q_DECLARE_METATYPE(Sailfish::Secrets::Daemon::ApiImpl::DeviceLockBrokerClient::AuthenticationResult)
Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Secrets::Daemon::ApiImpl::DeviceLockBrokerClient::Methods)

#endif // SAILFISHSECRETS_DEVICELOCKBROKERCLIENT_P_H
