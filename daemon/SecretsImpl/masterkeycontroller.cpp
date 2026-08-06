/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "masterkeycontroller_p.h"

#include "CryptoImpl/crypto_p.h"
#include "SecretsImpl/secrets_p.h"
#include "logging_p.h"

#include "Crypto/Plugins/extensionplugins.h"

#include <QtCore/QDir>
#include <QtCore/QStandardPaths>
#include <QtCore/QTimer>

#include <openssl/crypto.h>
#include <sys/mman.h>
#include <unistd.h>

namespace {

QString secretsRootPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
            + QStringLiteral("/system/privileged/Secrets");
}

bool resultSucceeded(const Sailfish::Crypto::Result &result)
{
    return result.code() == Sailfish::Crypto::Result::Succeeded;
}

} // namespace

using namespace Sailfish::Secrets::Daemon::ApiImpl;

MasterKeyController::MasterKeyController(
        SecretsRequestQueue *secrets,
        Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue *crypto,
        bool autotestMode,
        QObject *parent)
    : QObject(parent)
    , m_secrets(secrets)
    , m_crypto(crypto)
    , m_store(secretsRootPath(), autotestMode)
    , m_broker(this)
    , m_appSupport(autotestMode, this)
    , m_masterKey(Q_NULLPTR)
    , m_keyMint(Q_NULLPTR)
    , m_haveState(false)
    , m_sessionUnlocked(false)
    , m_reconnectScheduled(false)
    , m_pendingOperation(NoPendingOperation)
    , m_pendingChallenge(0)
    , m_bootstrapRequestId(0)
{
    connect(&m_broker, &DeviceLockBrokerClient::connected,
            this, &MasterKeyController::brokerConnected);
    connect(&m_broker, &DeviceLockBrokerClient::unavailable,
            this, &MasterKeyController::brokerUnavailable);
    connect(&m_broker, &DeviceLockBrokerClient::stateChanged,
            this, &MasterKeyController::brokerStateChanged);
    connect(&m_broker, &DeviceLockBrokerClient::authenticationCompleted,
            this, &MasterKeyController::brokerAuthenticationCompleted);
    connect(&m_broker, &DeviceLockBrokerClient::lifecycleEvent,
            this, &MasterKeyController::brokerLifecycleEvent);
    connect(&m_broker, &DeviceLockBrokerClient::commandCompleted,
            this, &MasterKeyController::brokerCommandCompleted);
    connect(&m_appSupport, &AppSupportKeyStoreServer::androidResetAcknowledged,
            this, &MasterKeyController::androidResetAcknowledged);
    connect(m_secrets, &SecretsRequestQueue::masterKeyLocked,
            this, &MasterKeyController::sessionExplicitlyLocked);
}

MasterKeyController::~MasterKeyController()
{
    disconnect(m_secrets, &SecretsRequestQueue::masterKeyLocked,
               this, &MasterKeyController::sessionExplicitlyLocked);
    abortPendingOperation();
    m_appSupport.lock();
    if (m_sessionUnlocked) {
        m_secrets->lockPlugins();
    }
    if (!m_secrets->masterLocked()) {
        m_secrets->lockMasterKey();
    }
    clearPendingRoot();
}

bool MasterKeyController::start(QString *errorMessage)
{
    m_secrets->setKeyMintManaged(true);
    m_appSupport.setMasterKeyStore(&m_store);
    findKeyMintProvider();

    QString socketError;
    if (!m_appSupport.start(&socketError)) {
        if (errorMessage) {
            *errorMessage = socketError;
        }
        return false;
    }
    if (!m_store.prepare(errorMessage) || !restoreReset(errorMessage)) {
        return false;
    }
    updateAppSupportState();
    m_broker.connectToBroker();
    return true;
}

bool MasterKeyController::findKeyMintProvider()
{
    const QMap<QString, Sailfish::Crypto::CryptoPlugin *> plugins = m_crypto->plugins();
    for (Sailfish::Crypto::CryptoPlugin *plugin : plugins) {
        QObject *provider = dynamic_cast<QObject *>(plugin);
        if (!provider) {
            continue;
        }
        Sailfish::Crypto::MasterKeyPluginExtension *masterKey
                = qobject_cast<Sailfish::Crypto::MasterKeyPluginExtension *>(provider);
        Sailfish::Crypto::KeyMintOperationExtension *keyMint
                = qobject_cast<Sailfish::Crypto::KeyMintOperationExtension *>(provider);
        if (masterKey && keyMint) {
            m_masterKey = masterKey;
            m_keyMint = keyMint;
            m_appSupport.setKeyMintProvider(provider);
            return true;
        }
    }
    qCWarning(lcSailfishSecretsDaemon) << "No KeyMint master-key provider is available";
    return false;
}

void MasterKeyController::brokerConnected()
{
    m_reconnectScheduled = false;
    m_broker.subscribeLifecycle();
    m_broker.getState();
}

void MasterKeyController::brokerUnavailable()
{
    m_haveState = false;
    lockSession();
    updateAppSupportState();
    if (!m_reconnectScheduled) {
        m_reconnectScheduled = true;
        QTimer::singleShot(5000, this,
                           &MasterKeyController::retryBrokerConnection);
    }
}

void MasterKeyController::retryBrokerConnection()
{
    m_reconnectScheduled = false;
    m_broker.connectToBroker();
}

void MasterKeyController::brokerStateChanged(
        const DeviceLockBrokerClient::State &state)
{
    m_state = state;
    m_haveState = true;
    if (m_sessionUnlocked && !stateCanBootstrap()) {
        lockSession();
    }
    updateAppSupportState();
    processState();
}

bool MasterKeyController::stateCanBootstrap() const
{
    const quint32 required = DeviceLockBrokerClient::SecurityCodeEnabled
            | DeviceLockBrokerClient::GatekeeperSelected
            | DeviceLockBrokerClient::IdentityValid
            | DeviceLockBrokerClient::BootstrapAllowed;
    return m_haveState && m_state.status == DeviceLockBrokerClient::Ok
            && (m_state.flags & required) == required
            && m_state.sailfishUserId != 0
            && m_state.secureUserId != 0
            && m_state.identityEpoch.size() == MasterKeyEnvelope::IdentityEpochSize;
}

void MasterKeyController::processState()
{
    if (!stateCanBootstrap() || m_sessionUnlocked
            || m_pendingOperation != NoPendingOperation || !m_masterKey) {
        return;
    }

    QByteArray resetTransaction;
    QString resetError;
    MasterKeyStore::ResetReason resetReason = MasterKeyStore::CredentialRemovalReset;
    const MasterKeyStore::ResetStage resetStage = m_store.resetStage(
                &resetTransaction, &resetError, &resetReason);
    if (!resetError.isEmpty()) {
        qCWarning(lcSailfishSecretsDaemon) << resetError;
        return;
    }
    if (resetStage != MasterKeyStore::NoReset
            && resetReason != MasterKeyStore::AlphaMigrationReset) {
        return;
    }

    MasterKeyEnvelope envelope;
    QString error;
    if (!m_store.load(&envelope, &error)) {
        qCWarning(lcSailfishSecretsDaemon) << error;
        return;
    }
    if (envelope.isValid()) {
        if (envelope.sailfishUserId != m_state.sailfishUserId
                || envelope.secureUserId != m_state.secureUserId
                || envelope.identityEpoch != m_state.identityEpoch) {
            qCWarning(lcSailfishSecretsDaemon)
                    << "Refusing a Secrets master key for a different Gatekeeper identity";
            return;
        }
        beginOpenMasterKey(envelope);
    } else {
        beginCreateMasterKey();
    }
}

void MasterKeyController::beginCreateMasterKey()
{
    QByteArray rootKey = MasterKeyDerivation::randomRootKey();
    if (rootKey.size() != 32 || !setPendingRoot(rootKey)) {
        MasterKeyDerivation::clear(&rootKey);
        return;
    }
    MasterKeyDerivation::clear(&rootKey);

    quint64 challenge = 0;
    QByteArray context;
    const QByteArray rootView = QByteArray::fromRawData(
                m_pendingRoot.constData(), m_pendingRoot.size());
    const Sailfish::Crypto::Result result = m_masterKey->beginCreateMasterKey(
                rootView, m_state.sailfishUserId, m_state.secureUserId,
                m_state.identityEpoch, &challenge, &context);
    if (!resultSucceeded(result) || challenge == 0 || context.isEmpty()) {
        qCWarning(lcSailfishSecretsDaemon)
                << "KeyMint cannot create the Secrets master key:" << result.errorMessage();
        abortPendingOperation();
        return;
    }
    m_pendingOperation = CreateMasterKeyOperation;
    m_pendingChallenge = challenge;
    m_pendingContext = context;
    m_bootstrapRequestId = m_broker.registerBootstrap(challenge);
    if (!m_bootstrapRequestId) {
        abortPendingOperation();
    }
}

void MasterKeyController::beginOpenMasterKey(const MasterKeyEnvelope &envelope)
{
    quint64 challenge = 0;
    QByteArray context;
    const Sailfish::Crypto::Result result = m_masterKey->beginOpenMasterKey(
                envelope.serialize(), &challenge, &context);
    if (!resultSucceeded(result) || challenge == 0 || context.isEmpty()) {
        qCWarning(lcSailfishSecretsDaemon)
                << "KeyMint cannot open the Secrets master key:" << result.errorMessage();
        abortPendingOperation();
        return;
    }
    m_pendingOperation = OpenMasterKeyOperation;
    m_pendingChallenge = challenge;
    m_pendingContext = context;
    m_bootstrapRequestId = m_broker.registerBootstrap(challenge);
    if (!m_bootstrapRequestId) {
        abortPendingOperation();
    }
}

void MasterKeyController::brokerCommandCompleted(quint64 requestId, qint32 status)
{
    if (requestId == m_bootstrapRequestId
            && status != DeviceLockBrokerClient::Accepted) {
        qCWarning(lcSailfishSecretsDaemon)
                << "DeviceLock rejected Secrets bootstrap authentication:" << status;
        m_bootstrapRequestId = 0;
        abortPendingOperation();
        return;
    }
    if (m_lifecycleAcknowledgements.contains(requestId)) {
        if (status != DeviceLockBrokerClient::Ok) {
            qCWarning(lcSailfishSecretsDaemon)
                    << "DeviceLock rejected a Secrets lifecycle acknowledgement:" << status;
        }
        m_lifecycleAcknowledgements.remove(requestId);
    }
}

void MasterKeyController::brokerAuthenticationCompleted(
        quint64 requestId,
        const DeviceLockBrokerClient::AuthenticationResult &authentication)
{
    if (requestId != m_bootstrapRequestId
            || m_pendingOperation == NoPendingOperation) {
        return;
    }
    m_bootstrapRequestId = 0;
    if (authentication.status != DeviceLockBrokerClient::Ok
            || authentication.actualMethod != DeviceLockBrokerClient::Pin
            || authentication.challenge != m_pendingChallenge
            || authentication.secureUserId != m_state.secureUserId
            || authentication.identityEpoch != m_state.identityEpoch) {
        abortPendingOperation();
        return;
    }

    if (m_pendingOperation == CreateMasterKeyOperation) {
        QByteArray serializedEnvelope;
        const Sailfish::Crypto::Result result = m_masterKey->finishCreateMasterKey(
                    m_pendingContext, authentication.serializedHardwareAuthToken,
                    &serializedEnvelope);
        MasterKeyEnvelope envelope;
        QString error;
        if (!resultSucceeded(result)
                || !MasterKeyEnvelope::deserialize(serializedEnvelope, &envelope)
                || envelope.sailfishUserId != m_state.sailfishUserId
                || envelope.secureUserId != m_state.secureUserId
                || envelope.identityEpoch != m_state.identityEpoch
                || !m_store.store(envelope, &error)) {
            qCWarning(lcSailfishSecretsDaemon)
                    << "Unable to commit the KeyMint Secrets master key"
                    << result.errorMessage() << error;
            abortPendingOperation();
            return;
        }
        const QByteArray rootView = QByteArray::fromRawData(
                    m_pendingRoot.constData(), m_pendingRoot.size());
        if (!unlockWithRoot(rootView, envelope)) {
            abortPendingOperation();
            return;
        }
        m_pendingChallenge = 0;
    } else {
        QByteArray rootKey;
        const Sailfish::Crypto::Result result = m_masterKey->finishOpenMasterKey(
                    m_pendingContext, authentication.serializedHardwareAuthToken,
                    &rootKey);
        MasterKeyEnvelope envelope;
        QString error;
        const bool loaded = m_store.load(&envelope, &error);
        const bool unlocked = resultSucceeded(result) && rootKey.size() == 32
                && loaded && envelope.isValid()
                && unlockWithRoot(rootKey, envelope);
        MasterKeyDerivation::clear(&rootKey);
        if (!unlocked) {
            qCWarning(lcSailfishSecretsDaemon)
                    << "Unable to open the KeyMint Secrets master key"
                    << result.errorMessage() << error;
            abortPendingOperation();
            return;
        }
        m_pendingChallenge = 0;
    }
    abortPendingOperation();
    updateAppSupportState();
}

bool MasterKeyController::unlockWithRoot(
        const QByteArray &rootKey,
        const MasterKeyEnvelope &envelope)
{
    if (!m_secrets->initializeFromKeyMintRoot(rootKey, envelope)
            || !m_secrets->initializePlugins()) {
        lockSession();
        return false;
    }
    m_sessionUnlocked = true;

    QByteArray resetTransaction;
    QString resetError;
    const MasterKeyStore::ResetStage resetStage = m_store.resetStage(
                &resetTransaction, &resetError);
    if (resetError.isEmpty() && resetStage == MasterKeyStore::NoReset) {
        QString appSupportError;
        if (!m_appSupport.unlock(m_secrets->appSupportDatabaseKey(),
                                 m_state.sailfishUserId, &appSupportError)) {
            qCWarning(lcSailfishSecretsDaemon)
                    << "Unable to unlock the AppSupport key store:" << appSupportError;
        }
    }
    return true;
}

void MasterKeyController::brokerLifecycleEvent(
        DeviceLockBrokerClient::LifecycleEvent event,
        quint32 sailfishUserId,
        quint64 secureUserId,
        const QByteArray &identityEpoch,
        const QByteArray &transactionId)
{
    Q_UNUSED(sailfishUserId)
    Q_UNUSED(secureUserId)
    Q_UNUSED(identityEpoch)

    if (event == DeviceLockBrokerClient::RemovePending
            || event == DeviceLockBrokerClient::IdentityInvalidated) {
        QString error;
        const MasterKeyStore::ResetReason reason
                = event == DeviceLockBrokerClient::RemovePending
                ? MasterKeyStore::CredentialRemovalReset
                : MasterKeyStore::IdentityInvalidationReset;
        if (!performReset(transactionId, reason, event, &error)) {
            qCWarning(lcSailfishSecretsDaemon) << "Secrets reset failed:" << error;
        }
        return;
    }
    if (event == DeviceLockBrokerClient::Removed) {
        m_removedTransactionId = transactionId;
        lockSession();
        QByteArray resetTransaction;
        QString error;
        MasterKeyStore::ResetReason reason = MasterKeyStore::CredentialRemovalReset;
        const MasterKeyStore::ResetStage stage = m_store.resetStage(
                    &resetTransaction, &error, &reason);
        if (error.isEmpty() && stage == MasterKeyStore::AndroidAcknowledged
                && reason == MasterKeyStore::CredentialRemovalReset
                && resetTransaction == transactionId) {
            if (!m_store.finishReset(&error)) {
                qCWarning(lcSailfishSecretsDaemon)
                        << "Unable to finish the removed credential reset:" << error;
            }
        }
        updateAppSupportState();
        return;
    }
    if (event == DeviceLockBrokerClient::UserChanged) {
        lockSession();
    }
    m_broker.getState();
}

bool MasterKeyController::performReset(
        const QByteArray &transactionId,
        MasterKeyStore::ResetReason reason,
        DeviceLockBrokerClient::LifecycleEvent event,
        QString *errorMessage)
{
    if (reason == MasterKeyStore::CredentialRemovalReset
            && m_removedTransactionId != transactionId) {
        m_removedTransactionId.clear();
    }
    if (!m_store.beginReset(transactionId, errorMessage, reason)) {
        return false;
    }
    return resumeReset(event, true, errorMessage);
}

bool MasterKeyController::restoreReset(QString *errorMessage)
{
    QByteArray transactionId;
    MasterKeyStore::ResetReason reason = MasterKeyStore::CredentialRemovalReset;
    const MasterKeyStore::ResetStage stage = m_store.resetStage(
                &transactionId, errorMessage, &reason);
    if (errorMessage && !errorMessage->isEmpty()) {
        return false;
    }
    if (stage == MasterKeyStore::NoReset) {
        return true;
    }
    const DeviceLockBrokerClient::LifecycleEvent event
            = reason == MasterKeyStore::IdentityInvalidationReset
            ? DeviceLockBrokerClient::IdentityInvalidated
            : DeviceLockBrokerClient::RemovePending;
    return resumeReset(event, false, errorMessage);
}

bool MasterKeyController::resumeReset(
        DeviceLockBrokerClient::LifecycleEvent event,
        bool acknowledgeBroker,
        QString *errorMessage)
{
    QByteArray transactionId;
    MasterKeyStore::ResetReason reason = MasterKeyStore::CredentialRemovalReset;
    MasterKeyStore::ResetStage stage = m_store.resetStage(
                &transactionId, errorMessage, &reason);
    if (errorMessage && !errorMessage->isEmpty()) {
        return false;
    }
    if (stage == MasterKeyStore::NoReset) {
        return true;
    }

    if (stage == MasterKeyStore::ResetStarted) {
        QString destroyError;
        if (!m_appSupport.destroyStoredKeys(&destroyError)) {
            qCWarning(lcSailfishSecretsDaemon) << destroyError;
        }
        lockSession();
        if (!m_store.deleteForReset(errorMessage)) {
            return false;
        }
        stage = MasterKeyStore::StorageDeleted;
    }
    quint64 generation = 0;
    QByteArray generationTransaction;
    if (stage == MasterKeyStore::StorageDeleted) {
        if (!m_store.commitResetGeneration(&generation, errorMessage)) {
            return false;
        }
        generationTransaction = transactionId;
        stage = MasterKeyStore::GenerationCommitted;
    } else {
        generation = m_store.generation(errorMessage, &generationTransaction);
        if (errorMessage && !errorMessage->isEmpty()) {
            return false;
        }
    }
    if (stage == MasterKeyStore::GenerationCommitted) {
        if (!m_store.acknowledgeReset(errorMessage)) {
            return false;
        }
        stage = MasterKeyStore::LifecycleAcknowledged;
    }

    m_appSupport.setStoreState(false, generation, transactionId);
    if (acknowledgeBroker
            && reason == MasterKeyStore::CredentialRemovalReset
            && event == DeviceLockBrokerClient::RemovePending
            && stage >= MasterKeyStore::LifecycleAcknowledged) {
        sendLifecycleAcknowledgement(transactionId,
                                     DeviceLockBrokerClient::RemovePending);
    }
    if (stage == MasterKeyStore::AndroidAcknowledged
            && (reason == MasterKeyStore::AlphaMigrationReset
                || reason == MasterKeyStore::IdentityInvalidationReset
                || (reason == MasterKeyStore::CredentialRemovalReset
                    && (m_removedTransactionId == transactionId
                        // finishReset() first clears the generation's
                        // transaction id, then removes the reset marker.  An
                        // empty id therefore recovers a crash between those
                        // two durable steps without waiting for a one-shot
                        // Removed event to be replayed.
                        || generationTransaction.isEmpty())))) {
        if (!m_store.finishReset(errorMessage)) {
            return false;
        }
        updateAppSupportState();
    }
    return true;
}

void MasterKeyController::sendLifecycleAcknowledgement(
        const QByteArray &transactionId,
        DeviceLockBrokerClient::LifecycleEvent event)
{
    const quint64 requestId = m_broker.acknowledgeLifecycle(transactionId, event);
    if (requestId) {
        m_lifecycleAcknowledgements.insert(requestId);
    }
}

void MasterKeyController::androidResetAcknowledged(
        quint64 generation,
        const QByteArray &transactionId)
{
    Q_UNUSED(generation)
    Q_UNUSED(transactionId)
    QString error;
    if (!restoreReset(&error)) {
        qCWarning(lcSailfishSecretsDaemon)
                << "Unable to finish an acknowledged Secrets reset:" << error;
        return;
    }
    updateAppSupportState();
    processState();
}

void MasterKeyController::updateAppSupportState()
{
    QString error;
    QByteArray resetTransaction;
    const MasterKeyStore::ResetStage stage = m_store.resetStage(
                &resetTransaction, &error);
    const quint64 generation = m_store.generation(&error);
    if (!error.isEmpty()) {
        qCWarning(lcSailfishSecretsDaemon) << error;
        return;
    }
    const bool resetPending = stage != MasterKeyStore::NoReset;
    if (m_sessionUnlocked && !resetPending && !m_appSupport.store()->isOpen()) {
        QString appSupportError;
        if (!m_appSupport.unlock(m_secrets->appSupportDatabaseKey(),
                                 m_state.sailfishUserId, &appSupportError)) {
            qCWarning(lcSailfishSecretsDaemon)
                    << "Unable to unlock the AppSupport key store:" << appSupportError;
        }
    }
    m_appSupport.setStoreState(stateCanBootstrap(), generation,
                               resetPending ? resetTransaction : QByteArray());
}

void MasterKeyController::lockSession()
{
    abortPendingOperation();
    m_appSupport.lock();
    if (m_sessionUnlocked && !m_secrets->lockPlugins()) {
        qCWarning(lcSailfishSecretsDaemon) << "Unable to close every Secrets database";
    }
    m_sessionUnlocked = false;
    if (!m_secrets->masterLocked()) {
        m_secrets->lockMasterKey();
    }
}

void MasterKeyController::sessionExplicitlyLocked()
{
    m_appSupport.lock();
    m_sessionUnlocked = false;
    abortPendingOperation();
    updateAppSupportState();
}

void MasterKeyController::abortPendingOperation()
{
    if (m_bootstrapRequestId) {
        m_broker.cancel(m_bootstrapRequestId);
    }
    if (m_pendingChallenge && m_keyMint) {
        qint32 keyMintError = 0;
        m_keyMint->keyMintAbort(m_pendingChallenge, &keyMintError);
    }
    m_pendingOperation = NoPendingOperation;
    m_pendingChallenge = 0;
    m_bootstrapRequestId = 0;
    MasterKeyDerivation::clear(&m_pendingContext);
    clearPendingRoot();
}

bool MasterKeyController::setPendingRoot(const QByteArray &rootKey)
{
    clearPendingRoot();
    if (rootKey.size() != 32) {
        return false;
    }
    m_pendingRoot = rootKey;
    if (::mlock(m_pendingRoot.data(), m_pendingRoot.size()) != 0) {
        qCWarning(lcSailfishSecretsDaemon)
                << "Unable to mlock a pending Secrets master key";
    }
    return true;
}

void MasterKeyController::clearPendingRoot()
{
    if (!m_pendingRoot.isEmpty()) {
        OPENSSL_cleanse(m_pendingRoot.data(), m_pendingRoot.size());
        ::munlock(m_pendingRoot.data(), m_pendingRoot.size());
        m_pendingRoot.clear();
    }
}
