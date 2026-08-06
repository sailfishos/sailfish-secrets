/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APPSUPPORTKEYSTORESERVER_P_H
#define SAILFISHSECRETS_APPSUPPORTKEYSTORESERVER_P_H

#include "appsupportkeystore_p.h"

#include <QtCore/QHash>
#include <QtCore/QObject>
#include <QtCore/QQueue>
#include <QtCore/QSet>

class QSocketNotifier;

namespace Sailfish {
namespace Crypto {
class KeyMintOperationExtension;
class Result;
}
namespace Secrets {
namespace Daemon {
namespace ApiImpl {

class MasterKeyStore;

class AppSupportKeyStoreServer : public QObject
{
    Q_OBJECT

public:
    explicit AppSupportKeyStoreServer(bool autotestMode,
                                      QObject *parent = Q_NULLPTR);
    ~AppSupportKeyStoreServer();

    bool start(QString *errorMessage);
    void stop();
    void setKeyMintProvider(QObject *provider);
    bool unlock(const QByteArray &bookkeepingDatabaseKey,
                quint32 sailfishUserId,
                QString *errorMessage);
    void lock();
    void setMasterKeyStore(MasterKeyStore *store);
    void setStoreState(bool provisioned,
                       quint64 generation,
                       const QByteArray &resetTransactionId);
    bool destroyStoredKeys(QString *errorMessage);
    AppSupportKeyStore *store();

Q_SIGNALS:
    void androidResetAcknowledged(quint64 generation,
                                  const QByteArray &transactionId);

private Q_SLOTS:
    void acceptConnections();
    void processQueuedRequest(int descriptor, quint64 connectionId);

private:
    struct PendingRequest {
        quint32 operation = 0;
        quint64 requestId = 0;
        QByteArray payload;
    };

    struct Client {
        int descriptor = -1;
        quint64 connectionId = 0;
        QString applicationId;
        QString instance;
        QSocketNotifier *notifier = Q_NULLPTR;
        QSet<quint64> requestIds;
        QSet<quint64> operationHandles;
        QHash<quint64, quint64> completedBeginHandles;
        QQueue<quint64> completedBeginRequestIds;
        QQueue<PendingRequest> pendingRequests;
        bool requestScheduled = false;
    };

    enum FrameType {
        RequestFrame = 1,
        ResponseFrame = 2,
        EventFrame = 3,
        CancelFrame = 4
    };

    enum Operation {
        Capabilities = 1,
        Generate = 2,
        Import = 3,
        Export = 4,
        Characteristics = 5,
        Delete = 6,
        DeleteAll = 7,
        Begin = 8,
        Update = 9,
        Finish = 10,
        Abort = 11,
        AddEntropy = 12,
        Upgrade = 13,
        Attest = 14,
        ImportWrapped = 15,
        Status = 16,
        Reset = 17,
        AcknowledgeReset = 18
    };

    enum KeyMintStatus {
        KmOk = 0,
        KmInvalidKeyBlob = -33,
        KmInvalidArgument = -38,
        KmSecureHardwareAccessDenied = -45,
        KmOperationCancelled = -46,
        KmSecureHardwareCommunicationFailed = -49,
        KmKeymasterNotConfigured = -64,
        KmHardwareTypeUnavailable = -68,
        KmUnimplemented = -100,
        KmUnknownError = -1000
    };

    void clientReadyRead(Client *client);
    void closeClient(Client *client);
    void scheduleNextRequest(Client *client);
    void rememberCompletedBegin(Client *client,
                                quint64 requestId,
                                quint64 operationHandle);
    void forgetCompletedBeginHandle(Client *client,
                                    quint64 operationHandle);
    bool processPacket(Client *client, const QByteArray &packet);
    qint32 processRequest(Client *client, quint32 operation,
                          const QByteArray &payload, QByteArray *response);
    bool sendResponse(Client *client, quint32 operation, quint64 requestId,
                      qint32 status, const QByteArray &payload);
    bool sendResetEvent(Client *client);
    QByteArray statusPayload() const;
    qint32 callOneShot(quint32 operation, const QByteArray &request,
                       QByteArray *response) const;
    qint32 callBegin(const QByteArray &request, quint64 *operationHandle,
                     QByteArray *response) const;
    qint32 callUpdate(quint64 operationHandle, const QByteArray &request,
                      QByteArray *response) const;
    qint32 callFinish(quint64 operationHandle, const QByteArray &request,
                      QByteArray *response) const;
    qint32 callAbort(quint64 operationHandle) const;
    qint32 resultStatus(const Sailfish::Crypto::Result &result,
                        qint32 keyMintStatus) const;
    QString socketPath() const;
    QString peerExecutable(pid_t pid) const;
    QString peerInstance(pid_t pid) const;

    int m_serverDescriptor;
    QSocketNotifier *m_serverNotifier;
    QHash<int, Client *> m_clients;
    AppSupportKeyStore m_store;
    Sailfish::Crypto::KeyMintOperationExtension *m_keyMint;
    MasterKeyStore *m_masterKeyStore;
    bool m_autotestMode;
    bool m_resetPending;
    bool m_provisioned;
    quint64 m_generation;
    quint64 m_nextConnectionId;
    QByteArray m_resetTransactionId;
};

} // namespace ApiImpl
} // namespace Daemon
} // namespace Secrets
} // namespace Sailfish

#endif // SAILFISHSECRETS_APPSUPPORTKEYSTORESERVER_P_H
