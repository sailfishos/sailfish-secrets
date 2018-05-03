/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "secrets_p.h"
#include "secretsrequestprocessor_p.h"
#include "logging_p.h"

#include "../CryptoImpl/crypto_p.h"

#include "Secrets/result.h"
#include "Secrets/secretmanager.h"
#include "Secrets/secretsdaemonconnection_p.h"
#include "Secrets/serialization_p.h"

#include "Crypto/keypairgenerationparameters.h"
#include "Crypto/keyderivationparameters.h"
#include "Crypto/plugininfo.h"
#include "Crypto/key.h"

#include <QtCore/QStandardPaths>
#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QCryptographicHash>

#include <sys/mman.h>

using namespace Sailfish::Secrets;

Daemon::ApiImpl::SecretsDBusObject::SecretsDBusObject(
        Daemon::ApiImpl::SecretsRequestQueue *parent)
    : QObject(parent)
    , m_requestQueue(parent)
{
}

// retrieve information about available plugins
void Daemon::ApiImpl::SecretsDBusObject::getPluginInfo(
        const QDBusMessage &message,
        Result &result,
        QVector<PluginInfo> &storagePlugins,
        QVector<PluginInfo> &encryptionPlugins,
        QVector<PluginInfo> &encryptedStoragePlugins,
        QVector<PluginInfo> &authenticationPlugins)
{
    Q_UNUSED(storagePlugins);           // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(encryptionPlugins);        // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(encryptedStoragePlugins);  // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(authenticationPlugins);    // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    m_requestQueue->handleRequest(Daemon::ApiImpl::GetPluginInfoRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// retrieve user input for the client (daemon)
void Daemon::ApiImpl::SecretsDBusObject::userInput(
        const InteractionParameters &uiParams,
        const QDBusMessage &message,
        Result &result,
        QByteArray &data)
{
    Q_UNUSED(data); // outparam, set in handlePendingRequest / handleFinishedRequest
    InteractionParameters modifiedParams(uiParams);
    modifiedParams.setOperation(InteractionParameters::RequestUserData);
    // Explicitly set the plugin name, collection name and secret name to empty.
    // This is to avoid a malicious application from attempting to trick the
    // user into providing data to it, under the pretense that it is for some
    // other cause.
    // Note that we also prepend an explicit warning to the prompt text (in
    // secretsrequestprocessor.cpp) that the data will be returned to the
    // application and thus cannot be considered confidential.
    modifiedParams.setPluginName(QString());
    modifiedParams.setCollectionName(QString());
    modifiedParams.setSecretName(QString());
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<InteractionParameters>(modifiedParams);
    m_requestQueue->handleRequest(Daemon::ApiImpl::UserInputRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}



// retrieve the names of collections
void Daemon::ApiImpl::SecretsDBusObject::collectionNames(
        const QString &storagePluginName,
        const QDBusMessage &message,
        Sailfish::Secrets::Result &result,
        QStringList &names)
{
    Q_UNUSED(names); // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << storagePluginName;
    m_requestQueue->handleRequest(Daemon::ApiImpl::CollectionNamesRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// create a DeviceLock-protected collection
void Daemon::ApiImpl::SecretsDBusObject::createCollection(
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(collectionName)
             << QVariant::fromValue<QString>(storagePluginName)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<SecretManager::DeviceLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode);
    m_requestQueue->handleRequest(Daemon::ApiImpl::CreateDeviceLockCollectionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// create a CustomLock-protected collection
void Daemon::ApiImpl::SecretsDBusObject::createCollection(
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        SecretManager::CustomLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(collectionName)
             << QVariant::fromValue<QString>(storagePluginName)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<QString>(authenticationPluginName)
             << QVariant::fromValue<SecretManager::CustomLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::CreateCustomLockCollectionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// delete a collection
void Daemon::ApiImpl::SecretsDBusObject::deleteCollection(
        const QString &collectionName,
        const QString &storagePluginName,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QString>(collectionName)
             << QVariant::fromValue<QString>(storagePluginName)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::DeleteCollectionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// set a secret in a collection
void Daemon::ApiImpl::SecretsDBusObject::setSecret(
        const Secret &secret,
        const InteractionParameters &uiParams,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret>(secret)
             << QVariant::fromValue<InteractionParameters>(uiParams)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::SetCollectionSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// set a standalone DeviceLock-protected secret
void Daemon::ApiImpl::SecretsDBusObject::setSecret(
        const Secret &secret,
        const QString &encryptionPluginName,
        const InteractionParameters &uiParams,
        SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret>(secret)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<InteractionParameters>(uiParams)
             << QVariant::fromValue<SecretManager::DeviceLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::SetStandaloneDeviceLockSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// set a standalone CustomLock-protected secret
void Daemon::ApiImpl::SecretsDBusObject::setSecret(
        const Secret &secret,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        const InteractionParameters &uiParams,
        SecretManager::CustomLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret>(secret)
             << QVariant::fromValue<QString>(encryptionPluginName)
             << QVariant::fromValue<QString>(authenticationPluginName)
             << QVariant::fromValue<InteractionParameters>(uiParams)
             << QVariant::fromValue<SecretManager::CustomLockUnlockSemantic>(unlockSemantic)
             << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::SetStandaloneCustomLockSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// get a secret
void Daemon::ApiImpl::SecretsDBusObject::getSecret(
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result,
        Secret &secret)
{
    Q_UNUSED(secret); // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret::Identifier>(identifier)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(identifier.identifiesStandaloneSecret()
                                      ? Daemon::ApiImpl::GetStandaloneSecretRequest
                                      : Daemon::ApiImpl::GetCollectionSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// find secrets via filter
void Daemon::ApiImpl::SecretsDBusObject::findSecrets(
        const QString &collectionName,
        const QString &storagePluginName,
        const Secret::FilterData &filter,
        SecretManager::FilterOperator filterOperator,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result,
        QVector<Secret::Identifier> &identifiers)
{
    Q_UNUSED(identifiers); // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    if (!collectionName.isEmpty()) {
        inParams << QVariant::fromValue<QString>(collectionName);
    }
    inParams << storagePluginName
             << QVariant::fromValue<Secret::FilterData>(filter)
             << QVariant::fromValue<SecretManager::FilterOperator>(filterOperator)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(collectionName.isEmpty()
                                      ? Daemon::ApiImpl::FindStandaloneSecretsRequest
                                      : Daemon::ApiImpl::FindCollectionSecretsRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// delete a secret
void Daemon::ApiImpl::SecretsDBusObject::deleteSecret(
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Secret::Identifier>(identifier)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(identifier.identifiesStandaloneSecret()
                                      ? Daemon::ApiImpl::DeleteStandaloneSecretRequest
                                      : Daemon::ApiImpl::DeleteCollectionSecretRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// modify a lock code (re-key a plugin, encrypted collection or standalone secret)
void Daemon::ApiImpl::SecretsDBusObject::modifyLockCode(
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParameters,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
             << QVariant::fromValue<QString>(lockCodeTarget)
             << QVariant::fromValue<InteractionParameters>(interactionParameters)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::ModifyLockCodeRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// provide a lock code (unlock a plugin, encrypted collection or standalone secret)
void Daemon::ApiImpl::SecretsDBusObject::provideLockCode(
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParameters,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
             << QVariant::fromValue<QString>(lockCodeTarget)
             << QVariant::fromValue<InteractionParameters>(interactionParameters)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::ProvideLockCodeRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

// forget a lock code (lock a plugin, encrypted collection or standalone secret)
void Daemon::ApiImpl::SecretsDBusObject::forgetLockCode(
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParameters,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
             << QVariant::fromValue<QString>(lockCodeTarget)
             << QVariant::fromValue<InteractionParameters>(interactionParameters)
             << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
             << QVariant::fromValue<QString>(interactionServiceAddress);
    m_requestQueue->handleRequest(Daemon::ApiImpl::ForgetLockCodeRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

//-----------------------------------

Daemon::ApiImpl::SecretsRequestQueue::SecretsRequestQueue(
        Daemon::Controller *parent,
        bool autotestMode)
    : Daemon::ApiImpl::RequestQueue(
          QLatin1String("/Sailfish/Secrets"),
          QLatin1String("org.sailfishos.secrets"),
          parent,
          autotestMode)
    , m_appPermissions(Q_NULLPTR)
    , m_requestProcessor(Q_NULLPTR)
    , m_controller(parent)
    , m_autotestMode(autotestMode)
    , m_bkdbLockKeyData(Q_NULLPTR)
    , m_deviceLockKeyData(Q_NULLPTR)
    , m_bkdbLockKeyLen(0)
    , m_deviceLockKeyLen(0)
    , m_noLockCode(false)
    , m_locked(true)
{
    SecretsDaemonConnection::registerDBusTypes();

    m_secretsThreadPool = QSharedPointer<QThreadPool>::create();
    m_secretsThreadPool->setMaxThreadCount(1);
    m_secretsThreadPool->setExpiryTimeout(-1);
    m_appPermissions = new Daemon::ApiImpl::ApplicationPermissions(this);
    m_requestProcessor = new Daemon::ApiImpl::RequestProcessor(m_appPermissions, autotestMode, this);

    setDBusObject(new Daemon::ApiImpl::SecretsDBusObject(this));
    qCDebug(lcSailfishSecretsDaemon) << "Secrets: initialization succeeded, awaiting client connections.";
}

Daemon::ApiImpl::SecretsRequestQueue::~SecretsRequestQueue()
{
    free(m_bkdbLockKeyData);
}

Sailfish::Secrets::Daemon::Controller *Daemon::ApiImpl::SecretsRequestQueue::controller()
{
    return m_controller;
}

QWeakPointer<QThreadPool> Daemon::ApiImpl::SecretsRequestQueue::secretsThreadPool()
{
    return m_secretsThreadPool.toWeakRef();
}

bool Daemon::ApiImpl::SecretsRequestQueue::generateKeyData(
        const QByteArray &lockCode,
        QByteArray *bkdbKey,
        QByteArray *deviceLockKey,
        QByteArray *testCipherText) const
{
    QByteArray salt = saltData();
    if (salt.isEmpty()) {
        return false;
    }

    Sailfish::Crypto::Key bookkeepingdbKey, devicelockKey;
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmAes);
    keyTemplate.setSize(256);
    Sailfish::Crypto::KeyDerivationParameters kdfParams;
    kdfParams.setKeyDerivationFunction(Sailfish::Crypto::CryptoManager::KdfPkcs5Pbkdf2);
    kdfParams.setKeyDerivationMac(Sailfish::Crypto::CryptoManager::MacHmac);
    kdfParams.setKeyDerivationDigestFunction(Sailfish::Crypto::CryptoManager::DigestSha512);
    kdfParams.setIterations(12000);
    if (lockCode.isEmpty()) {
        kdfParams.setInputData(QByteArray(1, '\0'));
    } else {
        kdfParams.setInputData(lockCode);
    }
    kdfParams.setSalt(salt);
    kdfParams.setOutputKeySize(256);

    Sailfish::Crypto::CryptoPlugin *cplugin = m_autotestMode
            ? m_controller->crypto()->plugins().value(Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"))
            : m_controller->crypto()->plugins().value(Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName);

    if (cplugin == Q_NULLPTR) {
        qCWarning(lcSailfishSecretsDaemon) << "Unable to find default crypto plugin for key initialization";
        return false;
    }

    Sailfish::Crypto::Result bkdbKeyResult = cplugin->generateKey(
                keyTemplate,
                Sailfish::Crypto::KeyPairGenerationParameters(),
                kdfParams,
                QVariantMap(),
                &bookkeepingdbKey);

    if (bkdbKeyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        qCWarning(lcSailfishSecretsDaemon) << "Unable to generate bookkeeping database key:" << bkdbKeyResult.errorMessage();
        return false;
    }

    kdfParams.setIterations(16000);
    Sailfish::Crypto::Result dlKeyResult = cplugin->generateKey(
                keyTemplate,
                Sailfish::Crypto::KeyPairGenerationParameters(),
                kdfParams,
                QVariantMap(),
                &devicelockKey);

    if (dlKeyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        qCWarning(lcSailfishSecretsDaemon) << "Unable to generate device lock key:" << dlKeyResult.errorMessage();
        return false;
    }

    // now generate the test cipher text with the new bkdbKey.
    // we will compare this to one stored on device, to see if
    // the given lockCode was "correct".
    QByteArray authenticationTag;
    const QByteArray plaintext("The quick brown fox jumps over the lazy dog");
    // TODO FIXME: is using a deterministically-generated IV here bad?
    const QByteArray iv = QCryptographicHash::hash(
                salt + bookkeepingdbKey.secretKey(),
                QCryptographicHash::Sha512).mid(0, 16);
    Sailfish::Crypto::Result testCipherResult = cplugin->encrypt(
                plaintext,
                iv,
                bookkeepingdbKey,
                Sailfish::Crypto::CryptoManager::BlockModeCbc,
                Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
                QByteArray(),
                QVariantMap(),
                testCipherText,
                &authenticationTag);
    if (testCipherResult.code() != Sailfish::Crypto::Result::Succeeded) {
        qCWarning(lcSailfishSecretsDaemon) << "Unable to generate key test data:"
                                           << testCipherResult.errorMessage();
        return false;
    }

    // we will use the first of these as the bookkeeping database lock
    // (after we hex-encode it as required by sqlcipher).
    *bkdbKey = bookkeepingdbKey.secretKey().toHex();
    // The second one will be used as the "device lock code" for
    // collections/secrets using DeviceLock semantics.
    // That one we don't hex encode, because we pass it to plugins
    // in raw form.
    *deviceLockKey = devicelockKey.secretKey();
    return true;
}

bool Daemon::ApiImpl::SecretsRequestQueue::initialize(
        const QByteArray &lockCode,
        SecretsRequestQueue::InitializationMode mode)
{
    QByteArray bkdbKey, deviceLockKey, testCipherText;
    // generate the keys and test cipher text
    if (!generateKeyData(lockCode, &bkdbKey, &deviceLockKey, &testCipherText)) {
        qCWarning(lcSailfishSecretsDaemon) << "Secrets: unable to generate keys from the lock code!";
        return false;
    }
    // test against or modify the test cipher text, depending on mode
    if (mode == SecretsRequestQueue::ModifyLockMode) {
        if (!writeTestCipherText(testCipherText)) {
            qCWarning(lcSailfishSecretsDaemon) << "Secrets: unable to write new test cipher text file!";
            return false;
        }
    } else if (mode == SecretsRequestQueue::UnlockMode && !compareTestCipherText(testCipherText, true)) {
        qCWarning(lcSailfishSecretsDaemon) << "Secrets: the given master lock code is incorrect!";
        return false;
    }
    // cache securely in mlock()ed memory
    if (!initializeKeyData(bkdbKey, deviceLockKey)) {
        qCWarning(lcSailfishSecretsDaemon) << "Secrets: failed to initialize key data!";
        return false;
    }

    if (mode == SecretsRequestQueue::UnlockMode || mode == SecretsRequestQueue::ModifyLockMode) {
        m_locked = false;
        if (lockCode.isEmpty()) {
            m_noLockCode = true; // we initialized the key data with a null lock code, which worked.
        } else {
            m_noLockCode = false; // we initialize the key data with non-null lock code.
        }
    } else {
        m_locked = true;
    }

    return true;
}

bool Daemon::ApiImpl::SecretsRequestQueue::initializePlugins()
{
    return m_requestProcessor->initializePlugins();
}

bool Daemon::ApiImpl::SecretsRequestQueue::masterLocked() const
{
    return m_locked;
}

bool Daemon::ApiImpl::SecretsRequestQueue::testLockCode(
        const QByteArray &lockCode) const
{
    QByteArray bkdbKey, deviceLockKey, testCipherText;
    if (!generateKeyData(lockCode, &bkdbKey, &deviceLockKey, &testCipherText)) {
        qCWarning(lcSailfishSecretsDaemon) << "Secrets: unable to generate keys from the lock code!";
        return false;
    }
    if (!compareTestCipherText(testCipherText, false)) {
        qCWarning(lcSailfishSecretsDaemon) << "Secrets: the given master lock code is incorrect!";
        return false;
    }
    return true;
}

bool Daemon::ApiImpl::SecretsRequestQueue::writeTestCipherText(
        const QByteArray &testCipherText) const
{
    // AES does not suffer from known-plaintext attacks
    // so this test should be safe.
    // TODO: check with crypto expert!
    // TODO: Should I just store a hash of the key instead?
    const QString systemDataDirPath(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/system/");
    const QString privilegedDataDirPath(systemDataDirPath + QLatin1String("privileged") + "/");
    const QString secretsDirPath(privilegedDataDirPath + QLatin1String("Secrets"));
    QDir secretsDir(secretsDirPath);
    if (!secretsDir.mkpath(secretsDirPath)) {
        qCWarning(lcSailfishSecretsDaemon) << "Permissions error: unable to create secrets directory:" << secretsDirPath;
        return false;
    }

    const QString lockCodeCheckFileName = m_autotestMode
            ? QLatin1String("lockcodecheck-test")
            : QLatin1String("lockcodecheck");
    const QString lockCodeCheckPath = secretsDir.absoluteFilePath(lockCodeCheckFileName);

    QFile lockCodeCheckFile(lockCodeCheckPath);
    if (!lockCodeCheckFile.open(QIODevice::WriteOnly)) {
        qCWarning(lcSailfishSecretsDaemon) << "Unable to write ciphertext data to lock code check file";
        return false;
    }
    lockCodeCheckFile.write(testCipherText);
    lockCodeCheckFile.close();
    return true;
}

bool Daemon::ApiImpl::SecretsRequestQueue::compareTestCipherText(
        const QByteArray &testCipherText,
        bool writeIfNotExists) const
{
    // AES does not suffer from known-plaintext attacks
    // so this test should be safe.
    // TODO: check with crypto expert!
    // TODO: Should I just store a hash of the key instead?
    const QString systemDataDirPath(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/system/");
    const QString privilegedDataDirPath(systemDataDirPath + QLatin1String("privileged") + "/");
    const QString secretsDirPath(privilegedDataDirPath + QLatin1String("Secrets"));
    QDir secretsDir(secretsDirPath);
    if (!secretsDir.mkpath(secretsDirPath)) {
        qCWarning(lcSailfishSecretsDaemon) << "Permissions error: unable to create secrets directory:" << secretsDirPath;
        return false;
    }

    const QString lockCodeCheckFileName = m_autotestMode
            ? QLatin1String("lockcodecheck-test")
            : QLatin1String("lockcodecheck");
    const QString lockCodeCheckPath = secretsDir.absoluteFilePath(lockCodeCheckFileName);
    if (!QFile::exists(lockCodeCheckPath)) {
        if (writeIfNotExists) {
            // first time, write the file.
            return writeTestCipherText(testCipherText);
        } else {
            qCWarning(lcSailfishSecretsDaemon) << "Unable to read ciphertext data from nonexistent lock code check file";
            return false;
        }
    } else {
        QFile lockCodeCheckFile(lockCodeCheckPath);
        if (!lockCodeCheckFile.open(QIODevice::ReadOnly)) {
            qCWarning(lcSailfishSecretsDaemon) << "Unable to read ciphertext data from lock code check file";
            return false;
        }
        QByteArray previousData = lockCodeCheckFile.readAll();
        lockCodeCheckFile.close();
        if (previousData != testCipherText) {
            return false;
        }
    }
    return true;
}

bool Daemon::ApiImpl::SecretsRequestQueue::initializeKeyData(
        const QByteArray &bkdbKey,
        const QByteArray &deviceLockKey)
{
    // now we want to malloc a contiguous chunk of memory large enough
    // to contain both keys data, then mlock() it.
    if (m_bkdbLockKeyData == Q_NULLPTR) {
        m_bkdbLockKeyData = (char*)malloc(bkdbKey.size()+deviceLockKey.size());
        if (mlock(m_bkdbLockKeyData, bkdbKey.size()+deviceLockKey.size()) < 0) {
            qCWarning(lcSailfishSecretsDaemon) << "Warning: unable to mlock secretsd key memory!";
        }
        m_deviceLockKeyData = m_bkdbLockKeyData + bkdbKey.size();
    }

    memcpy(m_bkdbLockKeyData, bkdbKey.constData(), bkdbKey.size());
    memcpy(m_deviceLockKeyData, deviceLockKey.constData(), deviceLockKey.size());
    m_bkdbLockKeyLen = bkdbKey.size();
    m_deviceLockKeyLen = deviceLockKey.size();

    return true;
}

QByteArray Daemon::ApiImpl::SecretsRequestQueue::saltData() const
{
    if (!m_saltData.isEmpty()) {
        return m_saltData;
    }

    QByteArray saltData;

    const QString systemDataDirPath(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/system/");
    const QString privilegedDataDirPath(systemDataDirPath + QLatin1String("privileged") + "/");
    const QString secretsDirPath(privilegedDataDirPath + QLatin1String("Secrets"));
    QDir secretsDir(secretsDirPath);
    if (!secretsDir.mkpath(secretsDirPath)) {
        qCWarning(lcSailfishSecretsDaemon) << "Permissions error: unable to create secrets directory:" << secretsDirPath;
        return QByteArray();
    }

    const QString saltFileName = m_autotestMode
            ? QLatin1String("initialsalt-test")
            : QLatin1String("initialsalt");
    const QString saltPath = secretsDir.absoluteFilePath(saltFileName);
    if (!QFile::exists(saltPath)) {
        // first run, need to write the initial salt data file.
        QByteArray dateData = QDateTime::currentDateTime().toString(Qt::ISODate).toUtf8();
        QFile urandom(QLatin1String("/dev/urandom"));
        if (!urandom.open(QIODevice::ReadOnly)) {
            qCWarning(lcSailfishSecretsDaemon) << "Unable to read salt data from /dev/urandom";
            return QByteArray();
        }
        saltData = urandom.read(1024);
        urandom.close();
        for (int i = 0; i < dateData.size() && i < saltData.size(); ++i) {
            saltData[i] = saltData[i] ^ dateData[i];
        }

        QFile saltFile(saltPath);
        if (!saltFile.open(QIODevice::WriteOnly)) {
            qCWarning(lcSailfishSecretsDaemon) << "Unable to write salt data to salt file";
            return QByteArray();
        }
        saltFile.write(saltData);
        saltFile.close();
    } else {
        QFile saltFile(saltPath);
        if (!saltFile.open(QIODevice::ReadOnly)) {
            qCWarning(lcSailfishSecretsDaemon) << "Unable to read salt data from salt file";
            return QByteArray();
        }
        saltData = saltFile.readAll();
        saltFile.close();
    }

    m_saltData = saltData;
    return saltData;
}

bool Daemon::ApiImpl::SecretsRequestQueue::noLockCode() const
{
    return m_noLockCode;
}

void Daemon::ApiImpl::SecretsRequestQueue::setNoLockCode(bool value)
{
    m_noLockCode = value;
}

const QByteArray Daemon::ApiImpl::SecretsRequestQueue::bkdbLockKey() const
{
    return QByteArray::fromRawData(m_bkdbLockKeyData, m_bkdbLockKeyLen);
}

const QByteArray Daemon::ApiImpl::SecretsRequestQueue::deviceLockKey() const
{
    return QByteArray::fromRawData(m_deviceLockKeyData, m_deviceLockKeyLen);
}

Result Daemon::ApiImpl::SecretsRequestQueue::lockCryptoPlugin(
        const QString &pluginName)
{
    QMap<QString, Sailfish::Crypto::CryptoPlugin*> cryptoPlugins
            = m_controller && m_controller->crypto()
            ? m_controller->crypto()->plugins()
            : QMap<QString, Sailfish::Crypto::CryptoPlugin*>();
    Sailfish::Crypto::CryptoPlugin *cryptoPlugin = cryptoPlugins.value(pluginName);
    if (!cryptoPlugin) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("No such extension plugin exists: %1").arg(pluginName));
    }

    if (!cryptoPlugin->supportsLocking()) {
        return Result(Result::OperationNotSupportedError,
                      QStringLiteral("Crypto plugin %1 does not support locking").arg(pluginName));
    }

    if (!m_controller || !m_controller->crypto()) {
        return Result(Result::UnknownError,
                      QStringLiteral("Unable to lock crypto plugin"));
    }

    if (!m_controller->crypto()->lockPlugin(pluginName)) {
        return Result(Result::UnknownError,
                      QStringLiteral("Failed to lock crypto plugin %1").arg(pluginName));
    }

    return Result(Result::Succeeded);
}

Result Daemon::ApiImpl::SecretsRequestQueue::unlockCryptoPlugin(
        const QString &pluginName,
        const QByteArray &lockCode)
{
    QMap<QString, Sailfish::Crypto::CryptoPlugin*> cryptoPlugins
            = m_controller && m_controller->crypto()
            ? m_controller->crypto()->plugins()
            : QMap<QString, Sailfish::Crypto::CryptoPlugin*>();
    Sailfish::Crypto::CryptoPlugin *cryptoPlugin = cryptoPlugins.value(pluginName);
    if (!cryptoPlugin) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("No such extension plugin exists: %1").arg(pluginName));
    }

    if (!cryptoPlugin->supportsLocking()) {
        return Result(Result::OperationNotSupportedError,
                      QStringLiteral("Crypto plugin %1 does not support locking").arg(pluginName));
    }

    if (!m_controller || !m_controller->crypto()) {
        return Result(Result::UnknownError,
                      QStringLiteral("Unable to unlock crypto plugin"));
    }

    if (!m_controller->crypto()->unlockPlugin(pluginName, lockCode)) {
        return Result(Result::UnknownError,
                      QStringLiteral("Failed to unlock crypto plugin %1").arg(pluginName));
    }

    return Result(Result::Succeeded);
}

Result Daemon::ApiImpl::SecretsRequestQueue::setLockCodeCryptoPlugin(
        const QString &pluginName,
        const QByteArray &oldCode,
        const QByteArray &newCode)
{
    QMap<QString, Sailfish::Crypto::CryptoPlugin*> cryptoPlugins
            = m_controller && m_controller->crypto()
            ? m_controller->crypto()->plugins()
            : QMap<QString, Sailfish::Crypto::CryptoPlugin*>();
    Sailfish::Crypto::CryptoPlugin *cryptoPlugin = cryptoPlugins.value(pluginName);
    if (!cryptoPlugin) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("No such extension plugin exists: %1").arg(pluginName));
    }

    if (!cryptoPlugin->supportsLocking()) {
        return Result(Result::OperationNotSupportedError,
                      QStringLiteral("Crypto plugin %1 does not support locking").arg(pluginName));
    }

    if (!m_controller || !m_controller->crypto()) {
        return Result(Result::UnknownError,
                      QStringLiteral("Unable to set lock code for crypto plugin"));
    }

    if (!m_controller->crypto()->setLockCodePlugin(pluginName, oldCode, newCode)) {
        return Result(Result::UnknownError,
                      QStringLiteral("Failed to set lock code for crypto plugin %1").arg(pluginName));
    }

    return Result(Result::Succeeded);
}

QString Daemon::ApiImpl::SecretsRequestQueue::requestTypeToString(int type) const
{
    switch (type) {
        case InvalidRequest:                        return QLatin1String("InvalidRequest");
        case GetPluginInfoRequest:                  return QLatin1String("GetPluginInfoRequest");
        case UserInputRequest:                      return QLatin1String("UserInputRequest");
        case CollectionNamesRequest:                return QLatin1String("CollectionNamesRequest");
        case CreateDeviceLockCollectionRequest:     return QLatin1String("CreateDeviceLockCollectionRequest");
        case CreateCustomLockCollectionRequest:     return QLatin1String("CreateCustomLockCollectionRequest");
        case DeleteCollectionRequest:               return QLatin1String("DeleteCollectionRequest");
        case SetCollectionSecretRequest:            return QLatin1String("SetCollectionSecretRequest");
        case SetStandaloneDeviceLockSecretRequest:  return QLatin1String("SetStandaloneDeviceLockSecretRequest");
        case SetStandaloneCustomLockSecretRequest:  return QLatin1String("SetStandaloneCustomLockSecretRequest");
        case GetCollectionSecretRequest:            return QLatin1String("GetCollectionSecretRequest");
        case GetStandaloneSecretRequest:            return QLatin1String("GetStandaloneSecretRequest");
        case FindCollectionSecretsRequest:          return QLatin1String("FindCollectionSecretsRequest");
        case FindStandaloneSecretsRequest:          return QLatin1String("FindStandaloneSecretsRequest");
        case DeleteCollectionSecretRequest:         return QLatin1String("DeleteCollectionSecretRequest");
        case DeleteStandaloneSecretRequest:         return QLatin1String("DeleteStandaloneSecretRequest");
        case ModifyLockCodeRequest:                 return QLatin1String("ModifyLockCodeRequest");
        case ProvideLockCodeRequest:                return QLatin1String("ProvideLockCodeRequest");
        case ForgetLockCodeRequest:                 return QLatin1String("ForgetLockCodeRequest");
        case SetCollectionKeyPreCheckRequest:       return QLatin1String("SetCollectionKeyPreCheckRequest");
        case SetCollectionKeyRequest:               return QLatin1String("SetCollectionKeyRequest");
        case StoredKeyIdentifiersRequest:           return QLatin1String("StoredKeyIdentifiersRequest");
        default: break;
    }
    return QLatin1String("Unknown Secrets Request!");
}

void Daemon::ApiImpl::SecretsRequestQueue::handlePendingRequest(
        Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling GetPluginInfoRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QVector<PluginInfo> storagePlugins;
            QVector<PluginInfo> encryptionPlugins;
            QVector<PluginInfo> encryptedStoragePlugins;
            QVector<PluginInfo> authenticationPlugins;
            Result result = m_requestProcessor->getPluginInfo(
                        request->remotePid,
                        request->requestId,
                        &storagePlugins,
                        &encryptionPlugins,
                        &encryptedStoragePlugins,
                        &authenticationPlugins);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QVector<PluginInfo> >(storagePlugins)
                                                                            << QVariant::fromValue<QVector<PluginInfo> >(encryptionPlugins)
                                                                            << QVariant::fromValue<QVector<PluginInfo> >(encryptedStoragePlugins)
                                                                            << QVariant::fromValue<QVector<PluginInfo> >(authenticationPlugins));
                }
                *completed = true;
            }
            break;
        }
        case CollectionNamesRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling CollectionNamesRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString storagePluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QStringList names;
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->collectionNames(
                                      request->remotePid,
                                      request->requestId,
                                      storagePluginName,
                                      &names);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QStringList>(names));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QStringList>(names));
                }
                *completed = true;
            }
            break;
        }
        case CreateDeviceLockCollectionRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling CreateDeviceLockCollectionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString collectionName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString storagePluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString encryptionPluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            SecretManager::DeviceLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::DeviceLockUnlockSemantic>()
                    : SecretManager::DeviceLockKeepUnlocked;
            SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::AccessControlMode>()
                    : SecretManager::OwnerOnlyMode;
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->createDeviceLockCollection(
                                      request->remotePid,
                                      request->requestId,
                                      collectionName,
                                      storagePluginName,
                                      encryptionPluginName,
                                      unlockSemantic,
                                      accessControlMode);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case CreateCustomLockCollectionRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling CreateCustomLockCollectionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString collectionName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString storagePluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString encryptionPluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString authenticationPluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            SecretManager::CustomLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::CustomLockUnlockSemantic>()
                    : SecretManager::CustomLockKeepUnlocked;
            SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::AccessControlMode>()
                    : SecretManager::OwnerOnlyMode;
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->createCustomLockCollection(
                                      request->remotePid,
                                      request->requestId,
                                      collectionName,
                                      storagePluginName,
                                      encryptionPluginName,
                                      authenticationPluginName,
                                      unlockSemantic,
                                      accessControlMode,
                                      userInteractionMode,
                                      interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling DeleteCollectionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString collectionName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString storagePluginName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->deleteCollection(
                                      request->remotePid,
                                      request->requestId,
                                      collectionName,
                                      storagePluginName,
                                      userInteractionMode,
                                      interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetCollectionSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetCollectionSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret secret = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret>()
                    : Secret();
            InteractionParameters uiParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->setCollectionSecret(
                                      request->remotePid,
                                      request->requestId,
                                      secret,
                                      uiParams,
                                      userInteractionMode,
                                      interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetStandaloneDeviceLockSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetStandaloneDeviceLockSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret secret = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret>()
                    : Secret();
            QString encryptionPluginName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            InteractionParameters uiParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            SecretManager::DeviceLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::DeviceLockUnlockSemantic>()
                    : SecretManager::DeviceLockKeepUnlocked;
            SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::AccessControlMode>()
                    : SecretManager::OwnerOnlyMode;
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->setStandaloneDeviceLockSecret(
                                      request->remotePid,
                                      request->requestId,
                                      secret,
                                      encryptionPluginName,
                                      uiParams,
                                      unlockSemantic,
                                      accessControlMode,
                                      userInteractionMode,
                                      interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetStandaloneCustomLockSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetStandaloneCustomLockSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret secret = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret>()
                    : Secret();
            QString encryptionPluginName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            QString authenticationPluginName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            InteractionParameters uiParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            SecretManager::CustomLockUnlockSemantic unlockSemantic = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::CustomLockUnlockSemantic>()
                    : SecretManager::CustomLockKeepUnlocked;
            SecretManager::AccessControlMode accessControlMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::AccessControlMode>()
                    : SecretManager::OwnerOnlyMode;
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->setStandaloneCustomLockSecret(
                                      request->remotePid,
                                      request->requestId,
                                      secret,
                                      encryptionPluginName,
                                      authenticationPluginName,
                                      uiParams,
                                      unlockSemantic,
                                      accessControlMode,
                                      userInteractionMode,
                                      interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case GetCollectionSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling GetCollectionSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::Identifier>()
                    : Secret::Identifier();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Secret secret;
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->getCollectionSecret(
                                      request->remotePid,
                                      request->requestId,
                                      identifier,
                                      userInteractionMode,
                                      interactionServiceAddress,
                                      &secret);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<Secret>(secret));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<Secret>(secret));
                }
                *completed = true;
            }
            break;
        }
        case GetStandaloneSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling GetStandaloneSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::Identifier>()
                    : Secret::Identifier();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Secret secret;
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->getStandaloneSecret(
                                      request->remotePid,
                                      request->requestId,
                                      identifier,
                                      userInteractionMode,
                                      interactionServiceAddress,
                                      &secret);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<Secret>(secret));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<Secret>(secret));
                }
                *completed = true;
            }
            break;
        }
        case FindCollectionSecretsRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling FindCollectionSecretsRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString collectionName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            QString storagePluginName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Secret::FilterData filter = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::FilterData >()
                    : Secret::FilterData();
            SecretManager::FilterOperator filterOperator = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::FilterOperator>()
                    : SecretManager::OperatorOr;
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QVector<Secret::Identifier> identifiers;
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->findCollectionSecrets(
                                      request->remotePid,
                                      request->requestId,
                                      collectionName,
                                      storagePluginName,
                                      filter,
                                      filterOperator,
                                      userInteractionMode,
                                      interactionServiceAddress,
                                      &identifiers);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                }
                *completed = true;
            }
            break;
        }
        case FindStandaloneSecretsRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling FindStandaloneSecretsRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString storagePluginName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Secret::FilterData filter = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::FilterData >()
                    : Secret::FilterData();
            SecretManager::FilterOperator filterOperator = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::FilterOperator>()
                    : SecretManager::OperatorOr;
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QVector<Secret::Identifier> identifiers;
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->findStandaloneSecrets(
                                      request->remotePid,
                                      request->requestId,
                                      storagePluginName,
                                      filter,
                                      filterOperator,
                                      userInteractionMode,
                                      interactionServiceAddress,
                                      &identifiers);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling DeleteCollectionSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::Identifier>()
                    : Secret::Identifier();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->deleteCollectionSecret(
                                      request->remotePid,
                                      request->requestId,
                                      identifier,
                                      userInteractionMode,
                                      interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteStandaloneSecretRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling DeleteStandaloneSecretRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::Identifier>()
                    : Secret::Identifier();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->deleteStandaloneSecret(
                                      request->remotePid,
                                      request->requestId,
                                      identifier,
                                      userInteractionMode);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case ModifyLockCodeRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling ModifyLockCodeRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            LockCodeRequest::LockCodeTargetType lockCodeTargetType = request->inParams.size()
                    ? request->inParams.takeFirst().value<LockCodeRequest::LockCodeTargetType>()
                    : LockCodeRequest::MetadataDatabase;
            QString lockCodeTarget = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            InteractionParameters interactionParameters = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = masterLocked() && lockCodeTargetType != LockCodeRequest::MetadataDatabase
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->modifyLockCode(
                                      request->remotePid,
                                      request->requestId,
                                      lockCodeTargetType,
                                      lockCodeTarget,
                                      interactionParameters,
                                      userInteractionMode,
                                      interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case ProvideLockCodeRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling ProvideLockCodeRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            LockCodeRequest::LockCodeTargetType lockCodeTargetType = request->inParams.size()
                    ? request->inParams.takeFirst().value<LockCodeRequest::LockCodeTargetType>()
                    : LockCodeRequest::MetadataDatabase;
            QString lockCodeTarget = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            InteractionParameters interactionParameters = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = masterLocked() && lockCodeTargetType != LockCodeRequest::MetadataDatabase
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->provideLockCode(
                                      request->remotePid,
                                      request->requestId,
                                      lockCodeTargetType,
                                      lockCodeTarget,
                                      interactionParameters,
                                      userInteractionMode,
                                      interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case ForgetLockCodeRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling ForgetLockCodeRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            LockCodeRequest::LockCodeTargetType lockCodeTargetType = request->inParams.size()
                    ? request->inParams.takeFirst().value<LockCodeRequest::LockCodeTargetType>()
                    : LockCodeRequest::MetadataDatabase;
            QString lockCodeTarget = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            InteractionParameters interactionParameters = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->forgetLockCode(
                                      request->remotePid,
                                      request->requestId,
                                      lockCodeTargetType,
                                      lockCodeTarget,
                                      interactionParameters,
                                      userInteractionMode,
                                      interactionServiceAddress);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetCollectionKeyPreCheckRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetCollectionKeyPreCheckRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret::Identifier identifier = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret::Identifier>()
                    : Secret::Identifier();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QByteArray collectionDecryptionKey;
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->setCollectionKeyPreCheck(
                                      request->remotePid,
                                      request->requestId,
                                      identifier,
                                      userInteractionMode,
                                      &collectionDecryptionKey);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                // This request type exists solely to implement Crypto API functionality.
                asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << collectionDecryptionKey);
                *completed = true;
            }
            break;
        }
        case SetCollectionKeyRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling SetCollectionKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Secret secret = request->inParams.size()
                    ? request->inParams.takeFirst().value<Secret>()
                    : Secret();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QByteArray collectionDecryptionKey = request->inParams.size()
                    ? request->inParams.takeFirst().value<QByteArray>()
                    : QByteArray();
            Q_UNUSED(collectionDecryptionKey); // TODO: use the collectionDecryptionKey to avoid doing an extra prompt?
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->setCollectionSecret(
                                      request->remotePid,
                                      request->requestId,
                                      secret,
                                      InteractionParameters(),
                                      userInteractionMode,
                                      QString());
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                // This request type exists solely to implement Crypto API functionality.
                asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                *completed = true;
            }
            break;
        }
        case StoredKeyIdentifiersRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling StoredKeyIdentifiersRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString collectionName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            QString storagePluginName = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            SecretManager::UserInteractionMode userInteractionMode = request->inParams.size()
                    ? request->inParams.takeFirst().value<SecretManager::UserInteractionMode>()
                    : SecretManager::PreventInteraction;
            QString interactionServiceAddress = request->inParams.size()
                    ? request->inParams.takeFirst().value<QString>()
                    : QString();
            QVector<Secret::Identifier> identifiers;
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->storedKeyIdentifiers(
                                      request->remotePid,
                                      request->requestId,
                                      collectionName,
                                      storagePluginName,
                                      userInteractionMode,
                                      interactionServiceAddress,
                                      &identifiers);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                // This request type exists solely to implement Crypto API functionality.
                asynchronousCryptoRequestCompleted(request->cryptoRequestId, result,
                                                   QVariantList() << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                *completed = true;
            }
            break;
        }
        case UserInputRequest: {
            qCDebug(lcSailfishSecretsDaemon) << "Handling UserInputRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            InteractionParameters uiParams = request->inParams.size()
                    ? request->inParams.takeFirst().value<InteractionParameters>()
                    : InteractionParameters();
            Result result = masterLocked()
                    ? Result(Result::SecretsDaemonLockedError,
                             QLatin1String("The secrets database is locked"))
                    : m_requestProcessor->userInput(
                                      request->remotePid,
                                      request->requestId,
                                      uiParams);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                // failed, return error immediately
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        default: {
            qCWarning(lcSailfishSecretsDaemon) << "Cannot handle request:" << request->requestId
                                               << "with invalid type:" << requestTypeToString(request->type);
            *completed = false;
            break;
        }
    }
}

void Daemon::ApiImpl::SecretsRequestQueue::handleFinishedRequest(
        Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GetPluginInfoRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "GetPluginInfoRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QVector<PluginInfo> storagePlugins = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<PluginInfo> >()
                        : QVector<PluginInfo>();
                QVector<PluginInfo> encryptionPlugins = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<PluginInfo> >()
                        : QVector<PluginInfo>();
                QVector<PluginInfo> encryptedStoragePlugins = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<PluginInfo> >()
                        : QVector<PluginInfo>();
                QVector<PluginInfo> authenticationPlugins = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<PluginInfo> >()
                        : QVector<PluginInfo>();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result,
                                                       QVariantList() << QVariant::fromValue<QVector<PluginInfo> >(storagePlugins)
                                                                      << QVariant::fromValue<QVector<PluginInfo> >(encryptionPlugins)
                                                                      << QVariant::fromValue<QVector<PluginInfo> >(encryptedStoragePlugins)
                                                                      << QVariant::fromValue<QVector<PluginInfo> >(authenticationPlugins));
                } else {
                    request->connection.send(request->message.createReply()
                                                << QVariant::fromValue<QVector<PluginInfo> >(storagePlugins)
                                                << QVariant::fromValue<QVector<PluginInfo> >(encryptionPlugins)
                                                << QVariant::fromValue<QVector<PluginInfo> >(encryptedStoragePlugins)
                                                << QVariant::fromValue<QVector<PluginInfo> >(authenticationPlugins));
                }
                *completed = true;
            }
            break;
        }
        case CollectionNamesRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of CollectionNamesRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "CollectionNamesRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QStringList names = request->outParams.size()
                                  ? request->outParams.takeFirst().value<QStringList>()
                                  : QStringList();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << names);
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QStringList>(names));
                }
                *completed = true;
            }
            break;
        }
        case CreateDeviceLockCollectionRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of CreateDeviceLockCollectionRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "CreateDeviceLockCollectionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case CreateCustomLockCollectionRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of CreateCustomLockCollectionRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "CreateCustomLockCollectionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of DeleteCollectionRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "DeleteCollectionRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetCollectionSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SetCollectionSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetCollectionSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetStandaloneDeviceLockSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SetStandaloneDeviceLockSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetStandaloneDeviceLockSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case SetStandaloneCustomLockSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SetStandaloneCustomLockSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetStandaloneCustomLockSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case GetCollectionSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GetCollectionSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "GetCollectionSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Secret secret = request->outParams.size()
                        ? request->outParams.takeFirst().value<Secret>()
                        : Secret();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<Secret>(secret));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<Secret>(secret));
                }
                *completed = true;
            }
            break;
        }
        case GetStandaloneSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GetStandaloneSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "GetStandaloneSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Secret secret = request->outParams.size()
                        ? request->outParams.takeFirst().value<Secret>()
                        : Secret();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<Secret>(secret));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<Secret>(secret));
                }
                *completed = true;
            }
            break;
        }
        case FindCollectionSecretsRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of FindCollectionSecretsRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "FindCollectionSecretsRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QVector<Secret::Identifier> identifiers = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<Secret::Identifier> >()
                        : QVector<Secret::Identifier>();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                }
                *completed = true;
            }
            break;
        }
        case FindStandaloneSecretsRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of FindStandaloneSecretsRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "FindStandaloneSecretsRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QVector<Secret::Identifier> identifiers = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<Secret::Identifier> >()
                        : QVector<Secret::Identifier>();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                }
                *completed = true;
            }
            break;
        }
        case DeleteCollectionSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of DeleteCollectionSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "DeleteCollectionSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case DeleteStandaloneSecretRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of DeleteStandaloneSecretRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "DeleteStandaloneSecretRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case ModifyLockCodeRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of ModifyLockCodeRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "ModifyLockCodeRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case ProvideLockCodeRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of ProvideLockCodeRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "ProvideLockCodeRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case ForgetLockCodeRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of ForgetLockCodeRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "ForgetLockCodeRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                }
                *completed = true;
            }
            break;
        }
        case UserInputRequest: {
            const Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of UserInputRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "UserInputRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                const QByteArray userInput = request->outParams.size()
                        ? request->outParams.takeFirst().value<QByteArray>()
                        : QByteArray();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList() << userInput);
                } else {
                    request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                            << QVariant::fromValue<QByteArray>(userInput));
                }
                *completed = true;
            }
            break;
        }
        case SetCollectionKeyPreCheckRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SetCollectionKeyPreCheckRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetCollectionKeyPreCheckRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray collectionDecryptionKey = request->outParams.size()
                        ? request->outParams.takeFirst().value<QByteArray>()
                        : QByteArray();
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result,
                                                       QVariantList() << QVariant::fromValue<QByteArray>(collectionDecryptionKey));
                } else {
                    // shouldn't happen!
                    qCWarning(lcSailfishSecretsDaemon) << "SetCollectionKeyPreCheckRequest:" << request->requestId << "finished as non-crypto request!";
                    *completed = true;
                }
                *completed = true;
            }
            break;
        }
        case SetCollectionKeyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SetCollectionKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetCollectionKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result, QVariantList());
                } else {
                    // shouldn't happen!
                    qCWarning(lcSailfishSecretsDaemon) << "SetCollectionKeyRequest:" << request->requestId << "finished as non-crypto request!";
                    *completed = true;
                }
                *completed = true;
            }
            break;
        }
        case StoredKeyIdentifiersRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SetCollectionKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishSecretsDaemon) << "SetCollectionKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                if (request->isSecretsCryptoRequest) {
                    QVector<Secret::Identifier> identifiers = request->outParams.size()
                            ? request->outParams.takeFirst().value<QVector<Secret::Identifier> >()
                            : QVector<Secret::Identifier>();
                    asynchronousCryptoRequestCompleted(request->cryptoRequestId, result,
                                                       QVariantList() << QVariant::fromValue<QVector<Secret::Identifier> >(identifiers));
                } else {
                    // shouldn't happen!
                    qCWarning(lcSailfishSecretsDaemon) << "SetCollectionKeyRequest:" << request->requestId << "finished as non-crypto request!";
                    *completed = true;
                }
                *completed = true;
            }
            break;
        }
        default: {
            qCWarning(lcSailfishSecretsDaemon) << "Cannot handle synchronous request:" << request->requestId << "with type:" << requestTypeToString(request->type) << "in an asynchronous fashion";
            *completed = false;
            break;
        }
    }
}

