/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_MASTERKEYCONTROLLER_P_H
#define SAILFISHSECRETS_MASTERKEYCONTROLLER_P_H

#include "appsupportkeystoreserver_p.h"
#include "devicelockbrokerclient_p.h"
#include "keymintdevicelocknotifier_p.h"
#include "masterkeymanager_p.h"

#include <QtCore/QObject>
#include <QtCore/QSet>

namespace Sailfish {
namespace Crypto {
class KeyMintOperationExtension;
class MasterKeyPluginExtension;
namespace Daemon {
namespace ApiImpl {
class CryptoRequestQueue;
}
}
}
namespace Secrets {
namespace Daemon {
namespace ApiImpl {

class SecretsRequestQueue;

class MasterKeyController : public QObject
{
    Q_OBJECT

public:
    MasterKeyController(SecretsRequestQueue *secrets,
                        Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue *crypto,
                        bool autotestMode,
                        QObject *parent = Q_NULLPTR);
    ~MasterKeyController();

    bool start(QString *errorMessage);

private Q_SLOTS:
    void brokerConnected();
    void brokerUnavailable();
    void retryBrokerConnection();
    void brokerStateChanged(const DeviceLockBrokerClient::State &state);
    void brokerAuthenticationCompleted(
            quint64 requestId,
            const DeviceLockBrokerClient::AuthenticationResult &result);
    void brokerLifecycleEvent(DeviceLockBrokerClient::LifecycleEvent event,
                              quint32 sailfishUserId,
                              quint64 secureUserId,
                              const QByteArray &identityEpoch,
                              const QByteArray &transactionId);
    void brokerCommandCompleted(quint64 requestId, qint32 status);
    void androidResetAcknowledged(quint64 generation,
                                  const QByteArray &transactionId);
    void sessionExplicitlyLocked();

private:
    enum PendingOperation {
        NoPendingOperation,
        CreateMasterKeyOperation,
        OpenMasterKeyOperation
    };

    bool findKeyMintProvider();
    bool restoreReset(QString *errorMessage);
    bool performReset(const QByteArray &transactionId,
                      MasterKeyStore::ResetReason reason,
                      DeviceLockBrokerClient::LifecycleEvent event,
                      QString *errorMessage);
    bool resumeReset(DeviceLockBrokerClient::LifecycleEvent event,
                     bool acknowledgeBroker,
                     QString *errorMessage);
    void processState();
    bool stateCanBootstrap() const;
    void beginCreateMasterKey();
    void beginOpenMasterKey(const MasterKeyEnvelope &envelope);
    bool unlockWithRoot(const QByteArray &rootKey,
                        const MasterKeyEnvelope &envelope);
    void updateAppSupportState();
    void lockSession();
    void abortPendingOperation();
    bool setPendingRoot(const QByteArray &rootKey);
    void clearPendingRoot();
    void sendLifecycleAcknowledgement(
            const QByteArray &transactionId,
            DeviceLockBrokerClient::LifecycleEvent event);

    SecretsRequestQueue *m_secrets;
    Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue *m_crypto;
    MasterKeyStore m_store;
    DeviceLockBrokerClient m_broker;
    KeyMintDeviceLockNotifier m_keyMintDeviceLock;
    AppSupportKeyStoreServer m_appSupport;
    Sailfish::Crypto::MasterKeyPluginExtension *m_masterKey;
    Sailfish::Crypto::KeyMintOperationExtension *m_keyMint;
    DeviceLockBrokerClient::State m_state;
    bool m_haveState;
    bool m_sessionUnlocked;
    bool m_reconnectScheduled;
    PendingOperation m_pendingOperation;
    quint64 m_pendingChallenge;
    quint64 m_bootstrapRequestId;
    QByteArray m_pendingContext;
    QByteArray m_pendingRoot;
    QByteArray m_removedTransactionId;
    QSet<quint64> m_lifecycleAcknowledgements;
};

} // namespace ApiImpl
} // namespace Daemon
} // namespace Secrets
} // namespace Sailfish

#endif // SAILFISHSECRETS_MASTERKEYCONTROLLER_P_H
