/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "appsupportkeystoreserver_p.h"

#include "applicationpermissions_p.h"
#include "logging_p.h"
#include "masterkeymanager_p.h"

#include "Crypto/Plugins/extensionplugins.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QSocketNotifier>
#include <QtCore/QStandardPaths>
#include <QtCore/QtEndian>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusConnectionInterface>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusObjectPath>
#include <QtDBus/QDBusReply>

#include <errno.h>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

const quint32 ProtocolMagic = 0x31534b41; // "AKS1" when little-endian.
const quint16 ProtocolMajor = 1;
const quint16 HeaderSize = 32;
const quint32 MaximumPayloadSize = 1024 * 1024;
const quint32 MaximumAuthSetEntries = 1024;
const int MaximumPendingRequests = 32;
const int MaximumRecentBeginRequests = 32;
const char ProductionPeerExecutable[] = "/usr/libexec/appsupport/apkd-bridge";
const char ProductionPeerBusName[] = "com.jolla.apkd";
const char ProductionPeerUnit[] = "apkd-bridge.service";
const char ProductionPeerUnitFile[] = "/usr/lib/systemd/user/apkd-bridge.service";
const char UserManagerBusName[] = "org.freedesktop.systemd1";
const char UserManagerInterface[] = "org.freedesktop.systemd1.Manager";
const char UserManagerPath[] = "/org/freedesktop/systemd1";
const char UserServiceInterface[] = "org.freedesktop.systemd1.Service";
const char UserUnitInterface[] = "org.freedesktop.systemd1.Unit";

QDBusConnection securityUserBus()
{
    static const QDBusConnection connection = QDBusConnection::connectToBus(
                QStringLiteral("unix:path=/run/user/%1/dbus/user_bus_socket")
                    .arg(::getuid()),
                QStringLiteral("sailfish-secrets-appsupport-peer-validation"));
    return connection;
}

pid_t parentProcessId(pid_t pid)
{
    QFile statusFile(QStringLiteral("/proc/%1/status").arg(pid));
    if (!statusFile.open(QIODevice::ReadOnly)) {
        return 0;
    }
    const QList<QByteArray> lines = statusFile.readAll().split('\n');
    for (const QByteArray &line : lines) {
        if (line.startsWith("PPid:")) {
            bool ok = false;
            const qlonglong parent = line.mid(5).trimmed().toLongLong(&ok);
            return ok && parent > 0 ? static_cast<pid_t>(parent) : 0;
        }
    }
    return 0;
}

bool processIsAncestor(uint expectedPid)
{
    pid_t ancestor = ::getppid();
    for (int depth = 0; ancestor > 0 && depth < 32; ++depth) {
        if (static_cast<uint>(ancestor) == expectedPid) {
            return true;
        }
        const pid_t parent = parentProcessId(ancestor);
        if (parent == ancestor) {
            return false;
        }
        ancestor = parent;
    }
    return false;
}

bool processIsProductionPeer(pid_t pid)
{
    // AppSupport 15 on the Jolla Phone runs the bridge from this root-installed
    // user unit.  Bind all property calls to the verified unique manager owner
    // so that a replacement well-known D-Bus name cannot answer them.
    const QDBusConnection connection = securityUserBus();
    QDBusConnectionInterface *busInterface = connection.interface();
    if (!busInterface) {
        return false;
    }

    const QDBusReply<QString> managerOwner = busInterface->serviceOwner(
                QString::fromLatin1(UserManagerBusName));
    if (!managerOwner.isValid() || managerOwner.value().isEmpty()) {
        return false;
    }
    const QDBusReply<uint> managerPid = busInterface->servicePid(managerOwner.value());
    if (!managerPid.isValid() || !managerPid.value()
            || !processIsAncestor(managerPid.value())) {
        return false;
    }

    const QString expectedManagerCgroup = QStringLiteral(
                "/user.slice/user-%1.slice/user@%1.service/init.scope")
            .arg(::getuid());
    const QByteArray expectedManagerCgroupSuffix = QByteArray(":")
            + expectedManagerCgroup.toLocal8Bit();
    QFile cgroupFile(QStringLiteral("/proc/%1/cgroup").arg(managerPid.value()));
    bool managerCgroupMatches = false;
    if (cgroupFile.open(QIODevice::ReadOnly)) {
        const QList<QByteArray> cgroups = cgroupFile.readAll().split('\n');
        for (const QByteArray &cgroup : cgroups) {
            if (cgroup.endsWith(expectedManagerCgroupSuffix)) {
                managerCgroupMatches = true;
                break;
            }
        }
    }
    if (!managerCgroupMatches) {
        return false;
    }

    QDBusInterface manager(managerOwner.value(), QString::fromLatin1(UserManagerPath),
                           QString::fromLatin1(UserManagerInterface), connection);
    const QDBusReply<QDBusObjectPath> unitReply = manager.call(
                QStringLiteral("GetUnit"), QString::fromLatin1(ProductionPeerUnit));
    if (!unitReply.isValid()) {
        return false;
    }

    const QString unitPath = unitReply.value().path();
    QDBusInterface unit(managerOwner.value(), unitPath,
                        QString::fromLatin1(UserUnitInterface), connection);
    QDBusInterface service(managerOwner.value(), unitPath,
                           QString::fromLatin1(UserServiceInterface), connection);
    const QVariant dropInPaths = unit.property("DropInPaths");
    return unit.isValid() && service.isValid()
            && unit.property("LoadState").toString() == QStringLiteral("loaded")
            && unit.property("ActiveState").toString() == QStringLiteral("active")
            && unit.property("FragmentPath").toString()
                    == QString::fromLatin1(ProductionPeerUnitFile)
            && dropInPaths.isValid() && dropInPaths.toStringList().isEmpty()
            && service.property("Type").toString() == QStringLiteral("dbus")
            && service.property("BusName").toString()
                    == QString::fromLatin1(ProductionPeerBusName)
            && service.property("MainPID").toUInt() == static_cast<uint>(pid);
}

template<typename T>
void appendLittleEndian(QByteArray *output, T value)
{
    const T encoded = qToLittleEndian(value);
    output->append(reinterpret_cast<const char *>(&encoded), sizeof(encoded));
}

void appendBlob(QByteArray *output, const QByteArray &blob)
{
    appendLittleEndian(output, quint32(blob.size()));
    output->append(blob);
}

class Cursor
{
public:
    explicit Cursor(const QByteArray &data)
        : m_data(data), m_offset(0) {}

    template<typename T>
    bool take(T *value)
    {
        if (!value || remaining() < static_cast<int>(sizeof(T))) {
            return false;
        }
        *value = qFromLittleEndian<T>(
                    reinterpret_cast<const uchar *>(m_data.constData() + m_offset));
        m_offset += sizeof(T);
        return true;
    }

    bool takeBlob(QByteArray *blob, quint32 maximumSize = MaximumPayloadSize)
    {
        quint32 size = 0;
        if (!take(&size) || size > maximumSize || remaining() < static_cast<int>(size)) {
            return false;
        }
        *blob = m_data.mid(m_offset, size);
        m_offset += size;
        return true;
    }

    bool atEnd() const { return m_offset == m_data.size(); }
    int offset() const { return m_offset; }
    int remaining() const { return m_data.size() - m_offset; }

private:
    const QByteArray &m_data;
    int m_offset;
};

bool validAuthSet(const QByteArray &serialized)
{
    Cursor cursor(serialized);
    quint32 version = 0;
    quint32 count = 0;
    if (!cursor.take(&version) || version != 1
            || !cursor.take(&count) || count > MaximumAuthSetEntries) {
        return false;
    }
    for (quint32 i = 0; i < count; ++i) {
        quint32 tag = 0;
        quint32 type = 0;
        quint64 scalar = 0;
        QByteArray bytes;
        if (!cursor.take(&tag) || tag == 0 || !cursor.take(&type)
                || type < 1 || type > 4 || !cursor.take(&scalar)
                || !cursor.takeBlob(&bytes)) {
            return false;
        }
        if ((type == 1 && (scalar > 1 || !bytes.isEmpty()))
                || ((type == 2 || type == 3) && !bytes.isEmpty())
                || (type == 2 && scalar > 0xffffffffULL)
                || (type == 4 && scalar != 0)) {
            return false;
        }
    }
    return cursor.atEnd();
}

bool validCharacteristics(const QByteArray &serialized)
{
    Cursor cursor(serialized);
    quint32 version = 0;
    QByteArray hardware;
    QByteArray software;
    return cursor.take(&version) && version == 1
            && cursor.takeBlob(&hardware) && validAuthSet(hardware)
            && cursor.takeBlob(&software) && validAuthSet(software)
            && cursor.atEnd();
}

bool takeHardwareAuthToken(Cursor *cursor)
{
    quint32 present = 0;
    if (!cursor->take(&present) || present > 1) {
        return false;
    }
    if (!present) {
        return true;
    }
    quint32 version = 0;
    quint64 challenge = 0;
    quint64 userId = 0;
    quint64 authenticatorId = 0;
    quint32 authenticatorType = 0;
    quint64 timestamp = 0;
    QByteArray mac;
    return cursor->take(&version) && version == 1
            && cursor->take(&challenge) && cursor->take(&userId)
            && cursor->take(&authenticatorId) && cursor->take(&authenticatorType)
            && cursor->take(&timestamp) && cursor->takeBlob(&mac, 32)
            && mac.size() == 32;
}

bool takeVerificationToken(Cursor *cursor)
{
    QByteArray token;
    if (!cursor->takeBlob(&token)) {
        return false;
    }
    if (token.isEmpty()) {
        return true;
    }
    Cursor nested(token);
    quint32 version = 0;
    quint64 challenge = 0;
    quint64 timestamp = 0;
    quint32 securityLevel = 0;
    QByteArray parameters;
    QByteArray mac;
    return nested.take(&version) && version == 1
            && nested.take(&challenge) && nested.take(&timestamp)
            && nested.take(&securityLevel)
            && nested.takeBlob(&parameters) && validAuthSet(parameters)
            && nested.takeBlob(&mac, 32) && (mac.isEmpty() || mac.size() == 32)
            && nested.atEnd();
}

bool parseGeneratedResponse(const QByteArray &serialized,
                            QByteArray *keyMintBlob,
                            QByteArray *characteristics)
{
    Cursor cursor(serialized);
    return cursor.takeBlob(keyMintBlob) && !keyMintBlob->isEmpty()
            && cursor.takeBlob(characteristics) && validCharacteristics(*characteristics)
            && cursor.atEnd();
}

} // namespace

using namespace Sailfish::Secrets::Daemon::ApiImpl;

AppSupportKeyStoreServer::AppSupportKeyStoreServer(bool autotestMode, QObject *parent)
    : QObject(parent)
    , m_serverDescriptor(-1)
    , m_serverNotifier(Q_NULLPTR)
    , m_store(autotestMode)
    , m_keyMint(Q_NULLPTR)
    , m_masterKeyStore(Q_NULLPTR)
    , m_autotestMode(autotestMode)
    , m_resetPending(false)
    , m_provisioned(false)
    , m_generation(0)
    , m_nextConnectionId(1)
{
}

AppSupportKeyStoreServer::~AppSupportKeyStoreServer()
{
    stop();
}

bool AppSupportKeyStoreServer::start(QString *errorMessage)
{
    if (m_serverDescriptor >= 0) {
        return true;
    }
    const QString path = socketPath();
    if (path.isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unsafe AppSupport key-store runtime directory");
        }
        return false;
    }
    const QFileInfo pathInfo(path);
    if (!QDir().mkpath(pathInfo.absolutePath())) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to create AppSupport key-store socket directory");
        }
        return false;
    }
    ::chmod(pathInfo.absolutePath().toUtf8().constData(), 0700);
    ::unlink(path.toUtf8().constData());

    m_serverDescriptor = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (m_serverDescriptor < 0) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to create AppSupport key-store socket");
        }
        return false;
    }
    struct sockaddr_un address = {};
    address.sun_family = AF_UNIX;
    const QByteArray encodedPath = QFile::encodeName(path);
    if (encodedPath.size() >= static_cast<int>(sizeof(address.sun_path))) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("AppSupport key-store socket path is too long");
        }
        stop();
        return false;
    }
    memcpy(address.sun_path, encodedPath.constData(), encodedPath.size() + 1);
    if (::bind(m_serverDescriptor, reinterpret_cast<struct sockaddr *>(&address),
               sizeof(address)) != 0
            || ::chmod(encodedPath.constData(), 0600) != 0
            || ::listen(m_serverDescriptor, 4) != 0) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to bind AppSupport key-store socket");
        }
        stop();
        return false;
    }
    m_serverNotifier = new QSocketNotifier(m_serverDescriptor,
                                           QSocketNotifier::Read, this);
    connect(m_serverNotifier, &QSocketNotifier::activated,
            this, &AppSupportKeyStoreServer::acceptConnections);
    return true;
}

void AppSupportKeyStoreServer::stop()
{
    const QList<Client *> clients = m_clients.values();
    for (Client *client : clients) {
        closeClient(client);
    }
    delete m_serverNotifier;
    m_serverNotifier = Q_NULLPTR;
    if (m_serverDescriptor >= 0) {
        ::close(m_serverDescriptor);
        m_serverDescriptor = -1;
    }
    ::unlink(QFile::encodeName(socketPath()).constData());
}

void AppSupportKeyStoreServer::setKeyMintProvider(QObject *provider)
{
    m_keyMint = provider
            ? qobject_cast<Sailfish::Crypto::KeyMintOperationExtension *>(provider)
            : Q_NULLPTR;
}

bool AppSupportKeyStoreServer::unlock(
        const QByteArray &bookkeepingDatabaseKey,
        quint32 sailfishUserId,
        QString *errorMessage)
{
    return m_store.open(bookkeepingDatabaseKey, sailfishUserId,
                        QStringLiteral("pending"),
                        QStringLiteral("pending"), errorMessage);
}

void AppSupportKeyStoreServer::lock()
{
    for (Client *client : m_clients) {
        const QSet<quint64> handles = client->operationHandles;
        for (quint64 handle : handles) {
            callAbort(handle);
        }
        client->operationHandles.clear();
        client->completedBeginHandles.clear();
        client->completedBeginRequestIds.clear();
    }
    m_store.close();
}

void AppSupportKeyStoreServer::setMasterKeyStore(MasterKeyStore *store)
{
    m_masterKeyStore = store;
}

void AppSupportKeyStoreServer::setStoreState(
        bool provisioned,
        quint64 generation,
        const QByteArray &resetTransactionId)
{
    m_provisioned = provisioned;
    m_generation = generation;
    m_resetTransactionId = resetTransactionId;
    m_resetPending = resetTransactionId.size() == 16;
    if (m_resetPending) {
        const QList<Client *> clients = m_clients.values();
        for (Client *client : clients) {
            if (!sendResetEvent(client)) {
                closeClient(client);
            }
        }
    }
}

AppSupportKeyStore *AppSupportKeyStoreServer::store()
{
    return &m_store;
}

bool AppSupportKeyStoreServer::destroyStoredKeys(QString *errorMessage)
{
    if (!m_store.isOpen()) {
        return true;
    }
    QVector<AppSupportKeyStore::Record> records;
    if (!m_store.records(&records, errorMessage)) {
        return false;
    }
    bool succeeded = true;
    for (const AppSupportKeyStore::Record &record : records) {
        QByteArray request;
        QByteArray response;
        appendBlob(&request, record.keyMintBlob);
        const qint32 status = callOneShot(Delete, request, &response);
        if ((status != KmOk && status != KmInvalidKeyBlob)
                || !response.isEmpty()) {
            succeeded = false;
        }
    }
    if (!succeeded && errorMessage) {
        *errorMessage = QStringLiteral("Unable to destroy every AppSupport KeyMint key");
    }
    return succeeded;
}

void AppSupportKeyStoreServer::acceptConnections()
{
    while (m_serverDescriptor >= 0) {
        struct sockaddr_un address;
        socklen_t addressSize = sizeof(address);
        const int descriptor = ::accept4(m_serverDescriptor,
                                         reinterpret_cast<struct sockaddr *>(&address),
                                         &addressSize, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (descriptor < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                qCWarning(lcSailfishSecretsDaemon) << "Unable to accept AppSupport key-store connection";
            }
            return;
        }
        struct ucred credentials = {};
        socklen_t credentialsSize = sizeof(credentials);
        const bool credentialsOk = ::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED,
                                                &credentials, &credentialsSize) == 0;
        const QString executable = credentialsOk
                ? peerExecutable(credentials.pid) : QString();
        const QString expectedExecutable = m_autotestMode
                ? QString::fromLocal8Bit(qgetenv("SAILFISH_SECRETSD_TEST_APPSUPPORT_PEER"))
                : QString::fromLatin1(ProductionPeerExecutable);
        const bool executableMatches = executable == expectedExecutable;
        const bool serviceMainPidMatches = credentialsOk && !m_autotestMode
                && executable.isEmpty()
                && processIsProductionPeer(credentials.pid);
        if (!credentialsOk || credentials.uid != ::getuid()
                || expectedExecutable.isEmpty()
                || (!executableMatches && !serviceMainPidMatches)) {
            ::close(descriptor);
            continue;
        }
        Client *client = new Client;
        client->descriptor = descriptor;
        client->connectionId = m_nextConnectionId++;
        if (m_nextConnectionId == 0) {
            m_nextConnectionId = 1;
        }
        ApplicationPermissions permissions;
        client->applicationId = permissions.exactApplicationId(
                    credentials.pid, credentials.uid, credentials.gid,
                    expectedExecutable);
        client->instance = peerInstance(credentials.pid);
        if (client->applicationId.isEmpty() || client->instance.isEmpty()
                || client->instance.size() > 128) {
            ::close(descriptor);
            delete client;
            continue;
        }
        client->notifier = new QSocketNotifier(descriptor, QSocketNotifier::Read, this);
        connect(client->notifier, &QSocketNotifier::activated,
                this, [this, client]() { clientReadyRead(client); });
        m_clients.insert(descriptor, client);
        if (m_resetPending && !sendResetEvent(client)) {
            closeClient(client);
        }
    }
}

void AppSupportKeyStoreServer::clientReadyRead(Client *client)
{
    QByteArray packet;
    packet.resize(HeaderSize + MaximumPayloadSize);
    struct iovec vector = { packet.data(), static_cast<size_t>(packet.size()) };
    struct msghdr message = {};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    const ssize_t size = ::recvmsg(client->descriptor, &message, 0);
    if (size <= 0 || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        closeClient(client);
        return;
    }
    packet.resize(static_cast<int>(size));
    if (!processPacket(client, packet)) {
        closeClient(client);
    }
}

void AppSupportKeyStoreServer::closeClient(Client *client)
{
    if (!client) {
        return;
    }
    m_clients.remove(client->descriptor);
    const QSet<quint64> handles = client->operationHandles;
    for (quint64 handle : handles) {
        callAbort(handle);
    }
    delete client->notifier;
    ::close(client->descriptor);
    delete client;
}

bool AppSupportKeyStoreServer::processPacket(Client *client, const QByteArray &packet)
{
    if (packet.size() < HeaderSize) {
        return false;
    }
    Cursor header(packet);
    quint32 magic = 0;
    quint16 major = 0;
    quint16 headerSize = 0;
    quint32 type = 0;
    quint32 operation = 0;
    quint64 requestId = 0;
    qint32 requestStatus = 0;
    quint32 payloadSize = 0;
    if (!header.take(&magic) || magic != ProtocolMagic
            || !header.take(&major) || major != ProtocolMajor
            || !header.take(&headerSize) || headerSize != HeaderSize
            || !header.take(&type)
            || !header.take(&operation) || operation < Capabilities || operation > AcknowledgeReset
            || !header.take(&requestId) || requestId == 0
            || !header.take(&requestStatus) || requestStatus != 0
            || !header.take(&payloadSize) || payloadSize > MaximumPayloadSize
            || packet.size() != HeaderSize + static_cast<int>(payloadSize)) {
        return false;
    }
    if (type == CancelFrame) {
        if (payloadSize != 0) {
            return false;
        }
        for (int i = 0; i < client->pendingRequests.size(); ++i) {
            const PendingRequest &request = client->pendingRequests.at(i);
            if (request.requestId == requestId) {
                if (request.operation != operation) {
                    return false;
                }
                client->pendingRequests.removeAt(i);
                client->requestIds.remove(requestId);
                return sendResponse(client, operation, requestId,
                                    KmOperationCancelled, QByteArray());
            }
        }
        const QHash<quint64, quint64>::iterator completed
                = client->completedBeginHandles.find(requestId);
        if (completed != client->completedBeginHandles.end()) {
            if (operation != Begin) {
                return false;
            }
            const quint64 handle = completed.value();
            client->completedBeginHandles.erase(completed);
            client->completedBeginRequestIds.removeAll(requestId);
            client->operationHandles.remove(handle);
            callAbort(handle);
            return true;
        }
        // A cancel may race a synchronous KeyMint call or its response.  Once
        // that request is no longer queued there is nothing left to cancel;
        // treating the frame as an idempotent no-op avoids dropping the
        // otherwise healthy bridge connection.
        return true;
    }
    if (type != RequestFrame || client->requestIds.contains(requestId)) {
        return false;
    }
    if (client->pendingRequests.size() >= MaximumPendingRequests) {
        return sendResponse(client, operation, requestId,
                            KmSecureHardwareCommunicationFailed, QByteArray());
    }

    client->requestIds.insert(requestId);
    PendingRequest request;
    request.operation = operation;
    request.requestId = requestId;
    request.payload = packet.mid(HeaderSize);
    client->pendingRequests.enqueue(request);
    scheduleNextRequest(client);
    return true;
}

void AppSupportKeyStoreServer::scheduleNextRequest(Client *client)
{
    if (!client || client->requestScheduled || client->pendingRequests.isEmpty()) {
        return;
    }
    client->requestScheduled = true;
    QMetaObject::invokeMethod(this, "processQueuedRequest", Qt::QueuedConnection,
                              Q_ARG(int, client->descriptor),
                              Q_ARG(quint64, client->connectionId));
}

void AppSupportKeyStoreServer::processQueuedRequest(
        int descriptor,
        quint64 connectionId)
{
    Client *client = m_clients.value(descriptor, Q_NULLPTR);
    if (!client || client->connectionId != connectionId) {
        return;
    }
    client->requestScheduled = false;
    if (client->pendingRequests.isEmpty()) {
        return;
    }

    const PendingRequest request = client->pendingRequests.dequeue();
    QByteArray response;
    const qint32 status = processRequest(client, request.operation,
                                         request.payload, &response);
    client->requestIds.remove(request.requestId);
    if (request.operation == Begin && status == KmOk
            && response.size() >= static_cast<int>(sizeof(quint64))) {
        Cursor beginResponse(response);
        quint64 handle = 0;
        if (beginResponse.take(&handle)
                && client->operationHandles.contains(handle)) {
            rememberCompletedBegin(client, request.requestId, handle);
        }
    }
    if (!sendResponse(client, request.operation, request.requestId,
                      status, response)) {
        closeClient(client);
        return;
    }
    scheduleNextRequest(client);
}

void AppSupportKeyStoreServer::rememberCompletedBegin(
        Client *client,
        quint64 requestId,
        quint64 operationHandle)
{
    if (!client || !requestId || !operationHandle) {
        return;
    }
    client->completedBeginHandles.insert(requestId, operationHandle);
    client->completedBeginRequestIds.enqueue(requestId);
    while (client->completedBeginRequestIds.size() > MaximumRecentBeginRequests) {
        client->completedBeginHandles.remove(
                    client->completedBeginRequestIds.dequeue());
    }
}

void AppSupportKeyStoreServer::forgetCompletedBeginHandle(
        Client *client,
        quint64 operationHandle)
{
    if (!client || !operationHandle) {
        return;
    }
    for (QHash<quint64, quint64>::iterator it
         = client->completedBeginHandles.begin();
         it != client->completedBeginHandles.end();) {
        if (it.value() == operationHandle) {
            client->completedBeginRequestIds.removeAll(it.key());
            it = client->completedBeginHandles.erase(it);
        } else {
            ++it;
        }
    }
}

qint32 AppSupportKeyStoreServer::processRequest(
        Client *client,
        quint32 operation,
        const QByteArray &payload,
        QByteArray *response)
{
    Cursor cursor(payload);
    QByteArray instanceData;
    quint32 androidUserId = ~quint32(0);
    if (!cursor.takeBlob(&instanceData, 128) || instanceData.isEmpty()
            || instanceData.contains('\0')
            || QString::fromUtf8(instanceData) != client->instance
            || !cursor.take(&androidUserId) || androidUserId != 0) {
        return KmSecureHardwareAccessDenied;
    }
    const int operationPayloadOffset = cursor.offset();
    const QByteArray operationPayload = payload.mid(operationPayloadOffset);
    if (operation == Status) {
        if (!cursor.atEnd()) {
            return KmInvalidArgument;
        }
        *response = statusPayload();
        return KmOk;
    }
    if (operation == AcknowledgeReset) {
        quint64 generation = 0;
        QByteArray transactionId;
        if (!cursor.take(&generation) || cursor.remaining() != 16) {
            return KmInvalidArgument;
        }
        transactionId = payload.right(16);
        if (!m_masterKeyStore || !m_resetPending
                || generation != m_generation
                || transactionId != m_resetTransactionId) {
            return KmInvalidArgument;
        }
        QString resetError;
        if (!m_masterKeyStore->acknowledgeAndroidReset(
                    generation, transactionId, &resetError)) {
            return KmUnknownError;
        }
        emit androidResetAcknowledged(generation, transactionId);
        return KmOk;
    }
    if (operation == Reset) {
        return KmSecureHardwareAccessDenied;
    }
    if (operation == Capabilities) {
        if (!cursor.atEnd()) {
            return KmInvalidArgument;
        }
        return callOneShot(operation, operationPayload, response);
    }
    if (!m_store.isOpen()) {
        return KmKeymasterNotConfigured;
    }
    QString storageError;
    if (!m_store.bindIdentity(client->applicationId, client->instance,
                              &storageError)) {
        return KmSecureHardwareAccessDenied;
    }
    if (m_resetPending) {
        return KmKeymasterNotConfigured;
    }

    if (operation == AddEntropy) {
        QByteArray entropy;
        if (!cursor.takeBlob(&entropy) || !cursor.atEnd()) {
            return KmInvalidArgument;
        }
        return callOneShot(operation, operationPayload, response);
    }

    if (operation == Generate || operation == Import || operation == ImportWrapped) {
        QByteArray policy;
        if (operation == Generate) {
            if (!cursor.takeBlob(&policy) || !validAuthSet(policy) || !cursor.atEnd()) {
                return KmInvalidArgument;
            }
        } else if (operation == Import) {
            quint32 format = 0;
            QByteArray keyData;
            if (!cursor.take(&format) || !cursor.takeBlob(&policy) || !validAuthSet(policy)
                    || !cursor.takeBlob(&keyData) || keyData.isEmpty() || !cursor.atEnd()) {
                return KmInvalidArgument;
            }
        } else {
            QByteArray wrapped;
            QByteArray wrappingReference;
            QByteArray maskingKey;
            QByteArray unwrappingParameters;
            quint64 passwordSid = 0;
            quint64 biometricSid = 0;
            AppSupportKeyStore::Record wrappingRecord;
            if (!cursor.takeBlob(&wrapped) || wrapped.isEmpty()
                    || !cursor.takeBlob(&wrappingReference)
                    || !cursor.takeBlob(&maskingKey)
                    || !cursor.takeBlob(&unwrappingParameters)
                    || !validAuthSet(unwrappingParameters)
                    || !cursor.take(&passwordSid) || !cursor.take(&biometricSid)
                    || !cursor.atEnd()
                    || !m_store.read(wrappingReference, &wrappingRecord, &storageError)) {
                return KmInvalidKeyBlob;
            }
            QByteArray internal;
            appendBlob(&internal, wrapped);
            appendBlob(&internal, wrappingRecord.keyMintBlob);
            appendBlob(&internal, maskingKey);
            appendBlob(&internal, unwrappingParameters);
            appendLittleEndian(&internal, passwordSid);
            appendLittleEndian(&internal, biometricSid);
            qint32 status = callOneShot(operation, internal, response);
            if (status != KmOk) {
                response->clear();
                return status;
            }
            policy = unwrappingParameters;
        }

        QByteArray backendResponse;
        if (operation != ImportWrapped) {
            const qint32 status = callOneShot(operation, operationPayload, &backendResponse);
            if (status != KmOk) {
                return status;
            }
        } else {
            backendResponse = *response;
            response->clear();
        }
        QByteArray keyMintBlob;
        QByteArray characteristics;
        if (!parseGeneratedResponse(backendResponse, &keyMintBlob, &characteristics)) {
            return KmSecureHardwareCommunicationFailed;
        }
        QByteArray opaqueReference;
        if (!m_store.insert(4, keyMintBlob, policy,
                            &opaqueReference, &storageError)) {
            QByteArray deleteRequest;
            QByteArray deleteResponse;
            appendBlob(&deleteRequest, keyMintBlob);
            callOneShot(Delete, deleteRequest, &deleteResponse);
            return KmUnknownError;
        }
        appendBlob(response, opaqueReference);
        appendBlob(response, characteristics);
        return KmOk;
    }

    if (operation == Delete || operation == Export || operation == Characteristics
            || operation == Attest || operation == Upgrade || operation == Begin) {
        quint32 scalar = 0;
        QByteArray opaqueReference;
        QByteArray first;
        QByteArray second;
        quint64 operationHandle = 0;
        int suffixOffset = 0;
        if (operation == Export) {
            if (!cursor.take(&scalar) || !cursor.takeBlob(&opaqueReference)
                    || !cursor.takeBlob(&first) || !cursor.takeBlob(&second)
                    || !cursor.atEnd()) {
                return KmInvalidArgument;
            }
        } else if (operation == Characteristics || operation == Attest || operation == Upgrade) {
            if (!cursor.takeBlob(&opaqueReference) || !cursor.takeBlob(&first)
                    || ((operation == Characteristics) && !cursor.takeBlob(&second))
                    || !cursor.atEnd()) {
                return KmInvalidArgument;
            }
            if ((operation == Attest || operation == Upgrade) && !validAuthSet(first)) {
                return KmInvalidArgument;
            }
        } else if (operation == Begin) {
            if (!cursor.take(&scalar) || !cursor.takeBlob(&opaqueReference)
                    || !cursor.takeBlob(&first)) {
                return KmInvalidArgument;
            }
            suffixOffset = cursor.offset() - operationPayloadOffset;
            if (!validAuthSet(first) || !takeHardwareAuthToken(&cursor) || !cursor.atEnd()) {
                return KmInvalidArgument;
            }
        } else if (!cursor.takeBlob(&opaqueReference) || !cursor.atEnd()) {
            return KmInvalidArgument;
        }

        AppSupportKeyStore::Record record;
        if (!m_store.read(opaqueReference, &record, &storageError)) {
            return KmInvalidKeyBlob;
        }
        QByteArray internal;
        if (operation == Export) {
            appendLittleEndian(&internal, scalar);
            appendBlob(&internal, record.keyMintBlob);
            appendBlob(&internal, first);
            appendBlob(&internal, second);
        } else if (operation == Characteristics) {
            appendBlob(&internal, record.keyMintBlob);
            appendBlob(&internal, first);
            appendBlob(&internal, second);
        } else if (operation == Attest || operation == Upgrade) {
            appendBlob(&internal, record.keyMintBlob);
            appendBlob(&internal, first);
        } else if (operation == Begin) {
            appendLittleEndian(&internal, scalar);
            appendBlob(&internal, record.keyMintBlob);
            appendBlob(&internal, first);
            internal.append(operationPayload.mid(suffixOffset));
        } else {
            appendBlob(&internal, record.keyMintBlob);
        }

        if (operation == Begin) {
            const qint32 status = callBegin(internal, &operationHandle, response);
            if (status == KmOk) {
                client->operationHandles.insert(operationHandle);
                QByteArray beginResponse;
                appendLittleEndian(&beginResponse, operationHandle);
                appendBlob(&beginResponse, *response);
                *response = beginResponse;
            }
            return status;
        }
        QByteArray backendResponse;
        const qint32 status = callOneShot(operation, internal, &backendResponse);
        if (status != KmOk && !(operation == Delete && status == KmInvalidKeyBlob)) {
            return status;
        }
        if (operation == Delete) {
            if (!backendResponse.isEmpty()
                    || !m_store.remove(opaqueReference, Q_NULLPTR, &storageError)) {
                return KmUnknownError;
            }
            return KmOk;
        }
        if (operation == Upgrade) {
            Cursor upgraded(backendResponse);
            QByteArray upgradedBlob;
            if (!upgraded.takeBlob(&upgradedBlob) || upgradedBlob.isEmpty()
                    || !upgraded.atEnd()
                    || !m_store.updateKeyMintBlob(opaqueReference, 4,
                                                  upgradedBlob, &storageError)) {
                return KmUnknownError;
            }
            appendBlob(response, opaqueReference);
            return KmOk;
        }
        *response = backendResponse;
        return KmOk;
    }

    if (operation == DeleteAll) {
        if (!cursor.atEnd()) {
            return KmInvalidArgument;
        }
        QVector<AppSupportKeyStore::Record> records;
        if (!m_store.records(&records, &storageError)) {
            return KmUnknownError;
        }
        for (const AppSupportKeyStore::Record &record : records) {
            QByteArray internal;
            QByteArray backendResponse;
            appendBlob(&internal, record.keyMintBlob);
            const qint32 status = callOneShot(Delete, internal, &backendResponse);
            if ((status != KmOk && status != KmInvalidKeyBlob)
                    || !backendResponse.isEmpty()) {
                return status == KmOk ? KmSecureHardwareCommunicationFailed : status;
            }
        }
        if (!m_store.removeAll(Q_NULLPTR, &storageError)) {
            return KmUnknownError;
        }
        return KmOk;
    }

    if (operation == Update || operation == Finish || operation == Abort) {
        quint64 handle = 0;
        if (!cursor.take(&handle) || !client->operationHandles.contains(handle)) {
            return KmInvalidArgument;
        }
        forgetCompletedBeginHandle(client, handle);
        if (operation == Abort) {
            if (!cursor.atEnd()) {
                return KmInvalidArgument;
            }
            const qint32 status = callAbort(handle);
            client->operationHandles.remove(handle);
            return status;
        }
        QByteArray inParameters;
        QByteArray input;
        if (!cursor.takeBlob(&inParameters) || !validAuthSet(inParameters)
                || !cursor.takeBlob(&input)) {
            return KmInvalidArgument;
        }
        if (operation == Finish) {
            QByteArray signature;
            if (!cursor.takeBlob(&signature) || !takeHardwareAuthToken(&cursor)
                    || !takeVerificationToken(&cursor) || !cursor.atEnd()) {
                return KmInvalidArgument;
            }
        } else if (!takeHardwareAuthToken(&cursor)
                   || !takeVerificationToken(&cursor) || !cursor.atEnd()) {
            return KmInvalidArgument;
        }
        const qint32 status = operation == Finish
                ? callFinish(handle, operationPayload.mid(sizeof(quint64)), response)
                : callUpdate(handle, operationPayload.mid(sizeof(quint64)), response);
        if (operation == Finish) {
            client->operationHandles.remove(handle);
            if (status != KmOk) {
                callAbort(handle);
            }
        }
        return status;
    }

    return KmUnimplemented;
}

bool AppSupportKeyStoreServer::sendResponse(
        Client *client,
        quint32 operation,
        quint64 requestId,
        qint32 status,
        const QByteArray &payload)
{
    if (!client || payload.size() > static_cast<int>(MaximumPayloadSize)) {
        return false;
    }
    QByteArray packet;
    packet.reserve(HeaderSize + payload.size());
    appendLittleEndian(&packet, ProtocolMagic);
    appendLittleEndian(&packet, ProtocolMajor);
    appendLittleEndian(&packet, HeaderSize);
    appendLittleEndian(&packet, quint32(ResponseFrame));
    appendLittleEndian(&packet, operation);
    appendLittleEndian(&packet, requestId);
    appendLittleEndian(&packet, status);
    appendLittleEndian(&packet, quint32(payload.size()));
    packet.append(payload);
    return ::send(client->descriptor, packet.constData(), packet.size(), MSG_NOSIGNAL)
            == packet.size();
}

bool AppSupportKeyStoreServer::sendResetEvent(Client *client)
{
    if (!client || !m_resetPending || m_generation == 0
            || m_resetTransactionId.size() != 16) {
        return false;
    }
    QByteArray payload;
    appendLittleEndian(&payload, quint32(1)); // RESET_COMMITTED
    appendLittleEndian(&payload, m_generation);
    payload.append(m_resetTransactionId);

    QByteArray packet;
    packet.reserve(HeaderSize + payload.size());
    appendLittleEndian(&packet, ProtocolMagic);
    appendLittleEndian(&packet, ProtocolMajor);
    appendLittleEndian(&packet, HeaderSize);
    appendLittleEndian(&packet, quint32(EventFrame));
    appendLittleEndian(&packet, quint32(Status));
    appendLittleEndian(&packet, quint64(0));
    appendLittleEndian(&packet, qint32(KmOk));
    appendLittleEndian(&packet, quint32(payload.size()));
    packet.append(payload);
    return ::send(client->descriptor, packet.constData(), packet.size(), MSG_NOSIGNAL)
            == packet.size();
}

QByteArray AppSupportKeyStoreServer::statusPayload() const
{
    quint32 flags = 0;
    if (m_provisioned) {
        flags |= 0x1;
    }
    if (m_store.isOpen()) {
        flags |= 0x2;
    }
    if (m_resetPending) {
        flags |= 0x4;
    }
    QByteArray payload;
    appendLittleEndian(&payload, flags);
    appendLittleEndian(&payload, quint32(1));
    appendLittleEndian(&payload, m_generation);
    return payload;
}

qint32 AppSupportKeyStoreServer::callOneShot(
        quint32 operation,
        const QByteArray &request,
        QByteArray *response) const
{
    if (!m_keyMint) {
        return KmHardwareTypeUnavailable;
    }
    qint32 keyMintStatus = KmUnknownError;
    const Sailfish::Crypto::Result result = m_keyMint->keyMintOneShot(
                operation, request, &keyMintStatus, response);
    return resultStatus(result, keyMintStatus);
}

qint32 AppSupportKeyStoreServer::callBegin(
        const QByteArray &request,
        quint64 *operationHandle,
        QByteArray *response) const
{
    if (!m_keyMint) {
        return KmHardwareTypeUnavailable;
    }
    qint32 keyMintStatus = KmUnknownError;
    const Sailfish::Crypto::Result result = m_keyMint->keyMintBegin(
                request, &keyMintStatus, operationHandle, response);
    return resultStatus(result, keyMintStatus);
}

qint32 AppSupportKeyStoreServer::callUpdate(
        quint64 operationHandle,
        const QByteArray &request,
        QByteArray *response) const
{
    if (!m_keyMint) {
        return KmHardwareTypeUnavailable;
    }
    qint32 keyMintStatus = KmUnknownError;
    const Sailfish::Crypto::Result result = m_keyMint->keyMintUpdate(
                operationHandle, request, &keyMintStatus, response);
    return resultStatus(result, keyMintStatus);
}

qint32 AppSupportKeyStoreServer::callFinish(
        quint64 operationHandle,
        const QByteArray &request,
        QByteArray *response) const
{
    if (!m_keyMint) {
        return KmHardwareTypeUnavailable;
    }
    qint32 keyMintStatus = KmUnknownError;
    const Sailfish::Crypto::Result result = m_keyMint->keyMintFinish(
                operationHandle, request, &keyMintStatus, response);
    return resultStatus(result, keyMintStatus);
}

qint32 AppSupportKeyStoreServer::callAbort(quint64 operationHandle) const
{
    if (!m_keyMint) {
        return KmHardwareTypeUnavailable;
    }
    qint32 keyMintStatus = KmUnknownError;
    const Sailfish::Crypto::Result result = m_keyMint->keyMintAbort(
                operationHandle, &keyMintStatus);
    return resultStatus(result, keyMintStatus);
}

qint32 AppSupportKeyStoreServer::resultStatus(
        const Sailfish::Crypto::Result &result,
        qint32 keyMintStatus) const
{
    if (result.code() == Sailfish::Crypto::Result::Succeeded) {
        return keyMintStatus;
    }
    if (result.errorCode() == Sailfish::Crypto::Result::OperationNotSupportedError) {
        return KmUnimplemented;
    }
    if (result.errorCode() == Sailfish::Crypto::Result::CryptoManagerNotInitializedError) {
        return KmHardwareTypeUnavailable;
    }
    return KmUnknownError;
}

QString AppSupportKeyStoreServer::socketPath() const
{
    const QString runtimePath = QDir::cleanPath(
                QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation));
    if (runtimePath.isEmpty() || runtimePath == QStringLiteral(".")) {
        return QString();
    }
    if (!m_autotestMode
            && runtimePath != QStringLiteral("/run/user/%1").arg(::getuid())) {
        return QString();
    }
    return QDir(runtimePath)
            .absoluteFilePath(QStringLiteral("sailfishsecretsd/appsupport-keystore-v1.socket"));
}

QString AppSupportKeyStoreServer::peerExecutable(pid_t pid) const
{
    return QFileInfo(QStringLiteral("/proc/%1/exe").arg(pid)).symLinkTarget();
}

QString AppSupportKeyStoreServer::peerInstance(pid_t pid) const
{
    QFile commandLine(QStringLiteral("/proc/%1/cmdline").arg(pid));
    if (!commandLine.open(QIODevice::ReadOnly)) {
        return QString();
    }
    const QList<QByteArray> arguments = commandLine.readAll().split('\0');
    if (arguments.size() < 2 || arguments.at(1).isEmpty()
            || arguments.at(1).size() > 128 || arguments.at(1).contains('\0')) {
        return QString();
    }
    return QString::fromUtf8(arguments.at(1));
}
