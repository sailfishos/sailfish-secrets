/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "devicelockbrokerclient_p.h"

#include "logging_p.h"

#include <QtCore/QtEndian>
#include <QtNetwork/QLocalSocket>

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

const char BrokerPath[] = "/run/nemo-devicelock/security-broker-v1";
const char ProtocolMagic[] = "DLB1";
const quint16 ProtocolVersion = 1;
const int HeaderSize = 24;
const quint32 MaximumPayloadSize = 4096;

template<typename T>
void appendLittleEndian(QByteArray *output, T value)
{
    const T encoded = qToLittleEndian(value);
    output->append(reinterpret_cast<const char *>(&encoded), sizeof(encoded));
}

template<typename T>
bool takeLittleEndian(const QByteArray &input, int *offset, T *value)
{
    if (!offset || !value || *offset < 0 || input.size() - *offset < static_cast<int>(sizeof(T))) {
        return false;
    }
    *value = qFromLittleEndian<T>(
                reinterpret_cast<const uchar *>(input.constData() + *offset));
    *offset += sizeof(T);
    return true;
}

bool takeBytes(const QByteArray &input, int *offset, int size, QByteArray *value)
{
    if (!offset || !value || size < 0 || *offset < 0 || input.size() - *offset < size) {
        return false;
    }
    *value = input.mid(*offset, size);
    *offset += size;
    return true;
}

} // namespace

using namespace Sailfish::Secrets::Daemon::ApiImpl;

DeviceLockBrokerClient::DeviceLockBrokerClient(QObject *parent)
    : QObject(parent)
    , m_socket(new QLocalSocket(this))
    , m_nextRequestId(1)
{
    qRegisterMetaType<DeviceLockBrokerClient::State>();
    qRegisterMetaType<DeviceLockBrokerClient::AuthenticationResult>();
    connect(m_socket, &QLocalSocket::connected,
            this, &DeviceLockBrokerClient::socketConnected);
    connect(m_socket, &QLocalSocket::readyRead,
            this, &DeviceLockBrokerClient::socketReadyRead);
    connect(m_socket, &QLocalSocket::disconnected,
            this, &DeviceLockBrokerClient::socketDisconnected);
    connect(m_socket,
            static_cast<void (QLocalSocket::*)(QLocalSocket::LocalSocketError)>(
                &QLocalSocket::error),
            this, [this](QLocalSocket::LocalSocketError) { failClosed(); });
}

DeviceLockBrokerClient::~DeviceLockBrokerClient()
{
}

void DeviceLockBrokerClient::connectToBroker()
{
    if (m_socket->state() != QLocalSocket::UnconnectedState) {
        return;
    }
    if (!verifySocketPath()) {
        failClosed();
        return;
    }
    m_socket->connectToServer(QString::fromLatin1(BrokerPath), QIODevice::ReadWrite);
}

quint64 DeviceLockBrokerClient::getState()
{
    return sendRequest(GetStateMessage, QByteArray());
}

quint64 DeviceLockBrokerClient::registerBootstrap(quint64 challenge)
{
    QByteArray payload;
    appendLittleEndian(&payload, challenge);
    appendLittleEndian(&payload, quint32(Pin));
    appendLittleEndian(&payload, quint32(SecretsBootstrapPurpose));
    return sendRequest(RegisterBootstrapMessage, payload);
}

quint64 DeviceLockBrokerClient::subscribeLifecycle()
{
    return sendRequest(SubscribeLifecycleMessage, QByteArray());
}

quint64 DeviceLockBrokerClient::acknowledgeLifecycle(
        const QByteArray &transactionId,
        DeviceLockBrokerClient::LifecycleEvent event)
{
    if (transactionId.size() != 16) {
        return 0;
    }
    QByteArray payload(transactionId);
    appendLittleEndian(&payload, quint32(event));
    return sendRequest(AckLifecycleMessage, payload);
}

quint64 DeviceLockBrokerClient::cancel(quint64 targetRequestId)
{
    QByteArray payload;
    appendLittleEndian(&payload, targetRequestId);
    return sendRequest(CancelMessage, payload);
}

void DeviceLockBrokerClient::socketConnected()
{
    if (!verifyPeer()) {
        qCWarning(lcSailfishSecretsDaemon) << "Rejected DeviceLock broker with unexpected peer credentials";
        failClosed();
        return;
    }
    emit connected();
}

void DeviceLockBrokerClient::socketReadyRead()
{
    m_input.append(m_socket->readAll());
    processFrames();
}

void DeviceLockBrokerClient::socketDisconnected()
{
    failClosed();
}

quint64 DeviceLockBrokerClient::sendRequest(Message message, const QByteArray &payload)
{
    if (m_socket->state() != QLocalSocket::ConnectedState
            || payload.size() > static_cast<int>(MaximumPayloadSize)) {
        return 0;
    }

    quint64 requestId = m_nextRequestId++;
    if (requestId == 0) {
        requestId = m_nextRequestId++;
    }
    QByteArray frame;
    frame.reserve(HeaderSize + payload.size());
    frame.append(ProtocolMagic, 4);
    appendLittleEndian(&frame, ProtocolVersion);
    appendLittleEndian(&frame, quint16(message));
    appendLittleEndian(&frame, requestId);
    appendLittleEndian(&frame, quint32(payload.size()));
    appendLittleEndian(&frame, quint32(0));
    frame.append(payload);
    if (frame.size() != HeaderSize + payload.size()
            || m_socket->write(frame) != frame.size()) {
        failClosed();
        return 0;
    }
    m_pending.insert(requestId, message);
    return requestId;
}

void DeviceLockBrokerClient::processFrames()
{
    while (m_input.size() >= HeaderSize) {
        if (m_input.left(4) != QByteArray(ProtocolMagic, 4)) {
            failClosed();
            return;
        }
        int offset = 4;
        quint16 version = 0;
        quint16 message = 0;
        quint64 requestId = 0;
        quint32 payloadSize = 0;
        quint32 flags = 0;
        if (!takeLittleEndian(m_input, &offset, &version)
                || !takeLittleEndian(m_input, &offset, &message)
                || !takeLittleEndian(m_input, &offset, &requestId)
                || !takeLittleEndian(m_input, &offset, &payloadSize)
                || !takeLittleEndian(m_input, &offset, &flags)
                || version != ProtocolVersion || flags != 0
                || payloadSize > MaximumPayloadSize) {
            failClosed();
            return;
        }
        if (m_input.size() < HeaderSize + static_cast<int>(payloadSize)) {
            return;
        }
        const QByteArray payload = m_input.mid(HeaderSize, payloadSize);
        m_input.remove(0, HeaderSize + payloadSize);
        if (!processFrame(message, requestId, payload)) {
            failClosed();
            return;
        }
    }
}

bool DeviceLockBrokerClient::processFrame(
        quint16 message,
        quint64 requestId,
        const QByteArray &payload)
{
    int offset = 0;
    if (message >= AuthenticateResponse && message <= AckLifecycleResponse) {
        qint32 status = 0;
        if (!takeLittleEndian(payload, &offset, &status) || offset != payload.size()
                || !m_pending.contains(requestId)) {
            return false;
        }
        const Message request = m_pending.value(requestId);
        if (message != (quint16(request) | 0x8000)) {
            return false;
        }
        m_pending.remove(requestId);
        if (status == Accepted && (request == AuthenticateMessage
                                   || request == RegisterBootstrapMessage)) {
            m_authenticationRequests.insert(requestId);
        }
        emit commandCompleted(requestId, status);
        return true;
    }

    if (message == StateResponse || message == StateChangedEvent) {
        if ((message == StateChangedEvent && requestId != 0)
                || (message == StateResponse && requestId == 0)) {
            return false;
        }
        State state;
        if (!takeLittleEndian(payload, &offset, &state.status)
                || !takeLittleEndian(payload, &offset, &state.sailfishUserId)
                || !takeLittleEndian(payload, &offset, &state.gatekeeperUserId)
                || !takeLittleEndian(payload, &offset, &state.flags)
                || !takeLittleEndian(payload, &offset, &state.secureUserId)
                || !takeBytes(payload, &offset, 16, &state.identityEpoch)
                || !takeLittleEndian(payload, &offset, &state.fingerprintAuthenticatorId)
                || !takeLittleEndian(payload, &offset, &state.supportedMethods)
                || !takeLittleEndian(payload, &offset, &state.fingerprintStrength)
                || !takeLittleEndian(payload, &offset, &state.lockoutDeadlineBootMs)
                || offset != payload.size()) {
            return false;
        }
        if (message == StateResponse) {
            if (m_pending.value(requestId) != GetStateMessage) {
                return false;
            }
            m_pending.remove(requestId);
        }
        emit stateChanged(state);
        return true;
    }

    if (message == AuthenticationEvent) {
        AuthenticationResult result;
        quint8 hatVersion = 0;
        QByteArray reserved;
        quint64 hatChallenge = 0;
        quint64 hatUserId = 0;
        quint64 hatAuthenticatorId = 0;
        quint32 hatAuthenticatorType = 0;
        quint32 hatReserved = 0;
        quint64 hatTimestamp = 0;
        QByteArray hmac;
        if (!m_authenticationRequests.contains(requestId)
                || !takeLittleEndian(payload, &offset, &result.status)
                || !takeLittleEndian(payload, &offset, &result.actualMethod)
                || !takeLittleEndian(payload, &offset, &result.challenge)
                || !takeLittleEndian(payload, &offset, &result.secureUserId)
                || !takeBytes(payload, &offset, 16, &result.identityEpoch)
                || !takeLittleEndian(payload, &offset, &hatVersion)
                || !takeBytes(payload, &offset, 3, &reserved)
                || !takeLittleEndian(payload, &offset, &hatChallenge)
                || !takeLittleEndian(payload, &offset, &hatUserId)
                || !takeLittleEndian(payload, &offset, &hatAuthenticatorId)
                || !takeLittleEndian(payload, &offset, &hatAuthenticatorType)
                || !takeLittleEndian(payload, &offset, &hatReserved)
                || !takeLittleEndian(payload, &offset, &hatTimestamp)
                || !takeBytes(payload, &offset, 32, &hmac)
                || offset != payload.size() || hatReserved != 0
                || reserved != QByteArray(3, '\0')) {
            return false;
        }
        m_authenticationRequests.remove(requestId);
        QByteArray serializedHat;
        appendLittleEndian(&serializedHat, quint32(hatVersion));
        appendLittleEndian(&serializedHat, hatChallenge);
        appendLittleEndian(&serializedHat, hatUserId);
        appendLittleEndian(&serializedHat, hatAuthenticatorId);
        appendLittleEndian(&serializedHat, hatAuthenticatorType);
        appendLittleEndian(&serializedHat, hatTimestamp);
        serializedHat.append(hmac);
        result.serializedHardwareAuthToken = serializedHat;
        emit authenticationCompleted(requestId, result);
        return true;
    }

    if (message == LifecycleEventMessage) {
        if (requestId != 0) {
            return false;
        }
        quint32 event = 0;
        quint32 sailfishUserId = 0;
        quint64 secureUserId = 0;
        QByteArray identityEpoch;
        QByteArray transactionId;
        if (!takeLittleEndian(payload, &offset, &event)
                || !takeLittleEndian(payload, &offset, &sailfishUserId)
                || !takeLittleEndian(payload, &offset, &secureUserId)
                || !takeBytes(payload, &offset, 16, &identityEpoch)
                || !takeBytes(payload, &offset, 16, &transactionId)
                || offset != payload.size()
                || event < Provisioned || event > UserChanged) {
            return false;
        }
        emit lifecycleEvent(static_cast<LifecycleEvent>(event), sailfishUserId,
                            secureUserId, identityEpoch, transactionId);
        return true;
    }

    return false;
}

bool DeviceLockBrokerClient::verifySocketPath() const
{
    struct stat info;
    if (::lstat(BrokerPath, &info) != 0 || !S_ISSOCK(info.st_mode)
            || (info.st_mode & 0777) != 0600 || info.st_uid != ::getuid()) {
        qCWarning(lcSailfishSecretsDaemon) << "Unsafe or unavailable DeviceLock broker socket";
        return false;
    }
    return true;
}

bool DeviceLockBrokerClient::verifyPeer() const
{
    const int descriptor = static_cast<int>(m_socket->socketDescriptor());
    if (descriptor < 0) {
        return false;
    }
    struct ucred credentials = {};
    socklen_t size = sizeof(credentials);
    return ::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &size) == 0
            && credentials.uid == 0;
}

void DeviceLockBrokerClient::failClosed()
{
    m_pending.clear();
    m_authenticationRequests.clear();
    m_input.clear();
    if (m_socket->state() != QLocalSocket::UnconnectedState) {
        m_socket->abort();
    }
    emit unavailable();
}
