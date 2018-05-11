/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "secretsrequestprocessor_p.h"
#include "applicationpermissions_p.h"
#include "pluginfunctionwrappers_p.h"
#include "logging_p.h"
#include "util_p.h"
#include "plugin_p.h"

#include "Secrets/result.h"
#include "Secrets/secretmanager.h"
#include "Secrets/secret.h"
#include "Secrets/plugininfo.h"

#include "CryptoImpl/cryptopluginwrapper_p.h"

#include <QtCore/QPluginLoader>
#include <QtCore/QDataStream>
#include <QtCore/QVariant>
#include <QtCore/QString>
#include <QtCore/QList>
#include <QtCore/QHash>
#include <QtCore/QSet>
#include <QtCore/QDir>
#include <QtCore/QCoreApplication>
#include <QtConcurrent>

using namespace Sailfish::Secrets;

namespace {
    QString calculateSecretNameHash(const Secret::Identifier &ident) {
        return QString::fromLatin1(
                QCryptographicHash::hash(
                    QStringLiteral("%1%2%3")
                        .arg(ident.storagePluginName(),
                             ident.collectionName(),
                             ident.name()).toUtf8(),
                    QCryptographicHash::Sha512).toBase64());
    }

    QString determineAuthPlugin(const QString &ownerApplicationId,
                                const QString &callerApplicationId,
                                bool callerIsPlatformApplication,
                                const QString &authPluginName,
                                const QString &interactionServiceAddress,
                                bool autotestMode) {
        const QString defaultPluginName = autotestMode
                ? Sailfish::Secrets::SecretManager::DefaultAuthenticationPluginName + QStringLiteral(".test")
                : Sailfish::Secrets::SecretManager::DefaultAuthenticationPluginName;
        if (authPluginName == Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName
                && (interactionServiceAddress.isEmpty()
                    || (ownerApplicationId != callerApplicationId && !callerIsPlatformApplication))) {
            return defaultPluginName;
        }
        return authPluginName;
    }
}

Daemon::ApiImpl::RequestProcessor::RequestProcessor(
        Daemon::ApiImpl::ApplicationPermissions *appPermissions,
        bool autotestMode,
        Daemon::ApiImpl::SecretsRequestQueue *parent)
    : QObject(parent), m_requestQueue(parent), m_appPermissions(appPermissions), m_autotestMode(autotestMode)
{
    m_authenticationPlugins = Daemon::ApiImpl::PluginManager::instance()->getPlugins<AuthenticationPlugin>();
    for (AuthenticationPlugin *authenticationPlugin : m_authenticationPlugins) {
        connect(authenticationPlugin, &AuthenticationPlugin::authenticationCompleted,
                this, &Daemon::ApiImpl::RequestProcessor::authenticationCompleted);
        connect(authenticationPlugin, &AuthenticationPlugin::userInputInteractionCompleted,
                this, &Daemon::ApiImpl::RequestProcessor::userInputInteractionCompleted);
    }
    qCDebug(lcSailfishSecretsDaemon) << "Using the following authentication plugins:" << m_authenticationPlugins.keys();

    m_encryptionPlugins = Daemon::ApiImpl::PluginManager::instance()->getPlugins<EncryptionPlugin>();
    qCDebug(lcSailfishSecretsDaemon) << "Using the following encryption plugins:" << m_encryptionPlugins.keys();

    QMap<QString, StoragePlugin*> storagePlugins = Daemon::ApiImpl::PluginManager::instance()->getPlugins<StoragePlugin>();
    qCDebug(lcSailfishSecretsDaemon) << "Using the following storage plugins:" << storagePlugins.keys();

    QMap<QString, EncryptedStoragePlugin*> encryptedStoragePlugins = Daemon::ApiImpl::PluginManager::instance()->getPlugins<EncryptedStoragePlugin>();
    qCDebug(lcSailfishSecretsDaemon) << "Using the following encrypted storage plugins:" << encryptedStoragePlugins.keys();

    m_potentialCryptoStoragePlugins = Daemon::ApiImpl::PluginManager::instance()->getMultiPlugins<Sailfish::Crypto::CryptoPlugin, EncryptedStoragePlugin>();
    qCDebug(lcSailfishSecretsDaemon) << "Using the following crypto storage plugins:" << m_potentialCryptoStoragePlugins.keys();

    // construct the appropriate wrappers for storage plugins.
    // these wrappers ensure metadata is updated transactionally with plugin-stored data.
    for (const QString &spn : storagePlugins.keys()) {
        m_storagePlugins.insert(
                    spn,
                    new StoragePluginWrapper(
                        storagePlugins.value(spn),
                        autotestMode));
    }

    for (const QString &cspn : m_potentialCryptoStoragePlugins.keys()) {
        m_cryptoStoragePlugins.insert(
                    cspn,
                    new Sailfish::Crypto::Daemon::ApiImpl::CryptoStoragePluginWrapper(
                        qobject_cast<Sailfish::Crypto::CryptoPlugin*>(m_potentialCryptoStoragePlugins.value(cspn)),
                        encryptedStoragePlugins.value(cspn),
                        autotestMode));
    }

    for (const QString &espn : encryptedStoragePlugins.keys()) {
        if (m_cryptoStoragePlugins.contains(espn)) {
            m_encryptedStoragePlugins.insert(espn, m_cryptoStoragePlugins.value(espn));
        } else {
            m_encryptedStoragePlugins.insert(
                        espn,
                        new EncryptedStoragePluginWrapper(
                            encryptedStoragePlugins.value(espn),
                            autotestMode));
        }
    }
}

bool Daemon::ApiImpl::RequestProcessor::initializePlugins()
{
    QFuture<bool> future = QtConcurrent::run(
                m_requestQueue->secretsThreadPool().data(),
                &Daemon::ApiImpl::masterUnlockPlugins,
                m_storagePlugins.values(),
                m_encryptedStoragePlugins.values(),
                m_requestQueue->bkdbLockKey());
    future.waitForFinished();
    if (!future.result()) {
        // TODO: FIXME: how can we recover from this?
        // This is symptomatic of a power-loss halfway through previous re-encryption,
        // meaning that some metadata databases will have been encrypted with
        // the OLD lock code, and some with the NEW lock code...
        qCWarning(lcSailfishSecretsDaemon) << "Critical Error! Failed to initialize metadata plugins";
    }
    return future.result();
}

// retrieve information about available plugins
Result
Daemon::ApiImpl::RequestProcessor::getPluginInfo(
        pid_t callerPid,
        quint64 requestId,
        QVector<PluginInfo> *storagePlugins,
        QVector<PluginInfo> *encryptionPlugins,
        QVector<PluginInfo> *encryptedStoragePlugins,
        QVector<PluginInfo> *authenticationPlugins)
{
    Q_UNUSED(callerPid); // TODO: perform access control request to see if the application has permission to read secure storage metadata.
    Q_UNUSED(requestId); // The request is synchronous, so don't need the requestId.

    QList<PluginBase*> allPlugins;
    for (StoragePluginWrapper *plugin : m_storagePlugins.values()) {
        allPlugins.append(plugin);
    }
    for (EncryptedStoragePluginWrapper *plugin : m_encryptedStoragePlugins.values()) {
        allPlugins.append(plugin);
    }
    for (EncryptionPlugin *plugin : m_encryptionPlugins.values()) {
        allPlugins.append(plugin);
    }
    for (AuthenticationPlugin *plugin : m_authenticationPlugins.values()) {
        allPlugins.append(plugin);
    }

    QMap<QString, PluginInfo> pluginInfos = m_requestQueue->controller()->pluginInfoForPlugins(
                allPlugins, m_requestQueue->masterLocked());

    for (const QString &pluginName : m_storagePlugins.keys()) {
        storagePlugins->append(pluginInfos.value(pluginName));
    }
    for (const QString &pluginName : m_encryptionPlugins.keys()) {
        encryptionPlugins->append(pluginInfos.value(pluginName));
    }
    for (const QString &pluginName : m_encryptedStoragePlugins.keys()) {
        encryptedStoragePlugins->append(pluginInfos.value(pluginName));
    }
    for (const QString &pluginName : m_authenticationPlugins.keys()) {
        authenticationPlugins->append(pluginInfos.value(pluginName));
    }

    return Result(Result::Succeeded);
}


Result
Daemon::ApiImpl::RequestProcessor::collectionNames(
        pid_t callerPid,
        quint64 requestId,
        const QString &storagePluginName,
        QStringList *names)
{
    Q_UNUSED(names); // asynchronous out-parameter.

    // TODO: perform access control request to see if the application has permission to read collection names.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);
    Q_UNUSED(requestId);
    Q_UNUSED(callerApplicationId);

    if (storagePluginName.isEmpty()) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Empty storage plugin name given"));
    } else if (!m_encryptedStoragePlugins.contains(storagePluginName)
               && !m_storagePlugins.contains(storagePluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown storage plugin name given"));
    }

    QFutureWatcher<CollectionNamesResult> *watcher = new QFutureWatcher<CollectionNamesResult>(this);
    QFuture<CollectionNamesResult> future;
    if (m_encryptedStoragePlugins.contains(storagePluginName)) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::collectionNames,
                    m_encryptedStoragePlugins[storagePluginName]);
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::collectionNames,
                    m_storagePlugins[storagePluginName]);
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<CollectionNamesResult>::finished, [=] {
        watcher->deleteLater();
        CollectionNamesResult cnr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(cnr.result);
        outParams << QVariant::fromValue<QStringList>(cnr.collectionNames);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

// create a DeviceLock-protected collection
Result
Daemon::ApiImpl::RequestProcessor::createDeviceLockCollection(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode)
{
    Q_UNUSED(requestId); // the request would only be asynchronous if we needed to perform the access control request, so until then it's always synchronous.

    if (collectionName.compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Reserved collection name given"));
    } else if (storagePluginName == encryptionPluginName && !m_encryptedStoragePlugins.contains(storagePluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such encrypted storage plugin exists: %1").arg(storagePluginName));
    } else if (storagePluginName != encryptionPluginName && !m_storagePlugins.contains(storagePluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such storage plugin exists: %1").arg(storagePluginName));
    } else if (storagePluginName != encryptionPluginName && !m_encryptionPlugins.contains(encryptionPluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such encryption plugin exists: %1").arg(encryptionPluginName));
    }

    // TODO: perform access control request to see if the application has permission to write secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    CollectionMetadata metadata;
    metadata.collectionName = collectionName;
    metadata.ownerApplicationId = callerApplicationId;
    metadata.usesDeviceLockKey = true;
    metadata.encryptionPluginName = encryptionPluginName;
    metadata.authenticationPluginName = m_autotestMode
            ? (SecretManager::DefaultAuthenticationPluginName + QLatin1String(".test"))
            : SecretManager::DefaultAuthenticationPluginName;
    metadata.unlockSemantic = static_cast<int>(unlockSemantic);
    metadata.accessControlMode = accessControlMode;

    QFutureWatcher<Result> *watcher = new QFutureWatcher<Result>(this);
    QFuture<Result> future;
    if (storagePluginName == encryptionPluginName) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::createCollection,
                    m_encryptedStoragePlugins[storagePluginName],
                    metadata,
                    m_requestQueue->deviceLockKey());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::createCollection,
                    m_storagePlugins[storagePluginName],
                    metadata);
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<Result>::finished, [=] {
        watcher->deleteLater();
        Result pluginResult = watcher->future().result();
        if (pluginResult.code() == Result::Succeeded) {
            if (storagePluginName != encryptionPluginName && unlockSemantic == SecretManager::DeviceLockKeepUnlocked) {
                const QString hashedCollectionName = calculateSecretNameHash(Secret::Identifier(QString(), collectionName, storagePluginName));
                m_collectionEncryptionKeys.insert(hashedCollectionName, m_requestQueue->deviceLockKey());
            }

            if (accessControlMode == SecretManager::SystemAccessControlMode) {
                // TODO: tell AccessControl daemon to add this datum from its database.
            }
        }

        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(pluginResult);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

// create a CustomLock-protected collection
Result
Daemon::ApiImpl::RequestProcessor::createCustomLockCollection(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        SecretManager::CustomLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress)
{
    Q_UNUSED(requestId); // the request would only be asynchronous if we needed to perform the access control request, so until then it's always synchronous.

    if (collectionName.compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Reserved collection name given"));
    } else if (storagePluginName == encryptionPluginName && !m_encryptedStoragePlugins.contains(storagePluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such encrypted storage plugin exists: %1").arg(storagePluginName));
    } else if (storagePluginName != encryptionPluginName && !m_storagePlugins.contains(storagePluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such storage plugin exists: %1").arg(storagePluginName));
    } else if (storagePluginName != encryptionPluginName && !m_encryptionPlugins.contains(encryptionPluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such encryption plugin exists: %1").arg(encryptionPluginName));
    } else if (!m_authenticationPlugins.contains(authenticationPluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such authentication plugin exists: %1").arg(authenticationPluginName));
    } else if (m_authenticationPlugins[authenticationPluginName]->authenticationTypes() & AuthenticationPlugin::ApplicationSpecificAuthentication
               && (userInteractionMode != SecretManager::ApplicationInteraction || interactionServiceAddress.isEmpty())) {
        return Result(Result::OperationRequiresApplicationUserInteraction,
                      QString::fromLatin1("Authentication plugin %1 requires in-process user interaction").arg(authenticationPluginName));
    } else if (userInteractionMode == SecretManager::PreventInteraction) {
        return Result(Result::OperationRequiresUserInteraction,
                      QString::fromLatin1("Authentication plugin %1 requires user interaction").arg(authenticationPluginName));
    }

    // TODO: perform access control request to see if the application has permission to write secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    // perform the user input flow required to get the input key data which will be used
    // to encrypt the data in this collection.
    InteractionParameters promptParams;
    promptParams.setApplicationId(callerApplicationId);
    promptParams.setCollectionName(collectionName);
    promptParams.setOperation(InteractionParameters::CreateCollection);
    promptParams.setInputType(InteractionParameters::AlphaNumericInput);
    promptParams.setEchoMode(InteractionParameters::PasswordEcho);
    promptParams.setPromptText({
        //: This will be displayed to the user, prompting them to enter a passphrase which will be used to encrypt a collection. %1 is the application name, %2 is the collection name, %3 is the plugin name.
        //% "App %1 wants to create a new secrets collection %2 in plugin %3."
        { InteractionParameters::Message, qtTrId("sailfish_secrets-create_customlock_collection-la-message")
                    .arg(callerApplicationId, collectionName, m_requestQueue->controller()->displayNameForPlugin(storagePluginName)) },
        //% "Enter the passphrase which will be used to encrypt the collection."
        { InteractionParameters::NewInstruction, qtTrId("sailfish_secrets-create_customlock_collection-la-enter_new_collection_passphrase") },
       //% "Repeat the passphrase which will be used to encrypt the collection."
       { InteractionParameters::RepeatInstruction, qtTrId("sailfish_secrets-create_customlock_collection-la-repeat_new_collection_passphrase") }
    });
    Result interactionResult = m_authenticationPlugins[authenticationPluginName]->beginUserInputInteraction(
                callerPid,
                requestId,
                promptParams,
                interactionServiceAddress);
    if (interactionResult.code() == Result::Failed) {
        return interactionResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::CreateCustomLockCollectionRequest,
                                 QVariantList() << collectionName
                                                << storagePluginName
                                                << encryptionPluginName
                                                << authenticationPluginName
                                                << unlockSemantic
                                                << accessControlMode
                                                << userInteractionMode
                                                << interactionServiceAddress));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::createCustomLockCollectionWithAuthenticationCode(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        SecretManager::CustomLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QByteArray &authenticationCode)
{
    QFutureWatcher<DerivedKeyResult> *watcher
            = new QFutureWatcher<DerivedKeyResult>(this);
    QFuture<DerivedKeyResult> future;
    if (storagePluginName == encryptionPluginName) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptedStoragePlugins[encryptionPluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptionPluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptionPlugins[encryptionPluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DerivedKeyResult>::finished, [=] {
        watcher->deleteLater();
        DerivedKeyResult dkr = watcher->future().result();
        if (dkr.result.code() != Result::Succeeded) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(dkr.result);
            m_requestQueue->requestFinished(requestId, outParams);
        } else {
            createCustomLockCollectionWithEncryptionKey(
                        callerPid,
                        requestId,
                        collectionName,
                        storagePluginName,
                        encryptionPluginName,
                        authenticationPluginName,
                        unlockSemantic,
                        accessControlMode,
                        userInteractionMode,
                        interactionServiceAddress,
                        dkr.key);
        }
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::createCustomLockCollectionWithEncryptionKey(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        SecretManager::CustomLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QByteArray &encryptionKey)
{
    Q_UNUSED(userInteractionMode);
    Q_UNUSED(interactionServiceAddress);

    // TODO: perform access control request to see if the application has permission to write secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    CollectionMetadata metadata;
    metadata.collectionName = collectionName;
    metadata.ownerApplicationId = callerApplicationId;
    metadata.usesDeviceLockKey = false;
    metadata.encryptionPluginName = encryptionPluginName;
    metadata.authenticationPluginName = authenticationPluginName;
    metadata.unlockSemantic = static_cast<int>(unlockSemantic);
    metadata.accessControlMode = accessControlMode;

    QFutureWatcher<Result> *watcher = new QFutureWatcher<Result>(this);
    QFuture<Result> future;
    if (storagePluginName == encryptionPluginName) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::createCollection,
                    m_encryptedStoragePlugins[storagePluginName],
                    metadata,
                    encryptionKey);
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::createCollection,
                    m_storagePlugins[storagePluginName],
                    metadata);
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<Result>::finished, [=] {
        watcher->deleteLater();
        Result pluginResult = watcher->future().result();
        if (pluginResult.code() == Result::Succeeded) {
            if (storagePluginName != encryptionPluginName && unlockSemantic == SecretManager::CustomLockKeepUnlocked) {
                const QString hashedCollectionName = calculateSecretNameHash(
                            Secret::Identifier(QString(), collectionName, storagePluginName));
                m_collectionEncryptionKeys.insert(hashedCollectionName, encryptionKey);
                // TODO: also set CustomLockTimeoutMs, flag for "is custom key", etc.
            }

            if (accessControlMode == SecretManager::SystemAccessControlMode) {
                // TODO: tell AccessControl daemon to add this datum from its database.
            }
        }

        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(pluginResult);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

// delete a collection
Result
Daemon::ApiImpl::RequestProcessor::deleteCollection(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress)
{
    Q_UNUSED(userInteractionMode); // TODO: access control

    if (storagePluginName.isEmpty()) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Empty storage plugin name given"));
    } else if (!m_encryptedStoragePlugins.contains(storagePluginName)
            && !m_storagePlugins.contains(storagePluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown storage plugin name given"));
    } else if (collectionName.compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Reserved collection name given"));
    } else if (collectionName.isEmpty()) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Empty collection name given"));
    }

    // Read the metadata about the target collection
    QFutureWatcher<CollectionMetadataResult> *watcher
            = new QFutureWatcher<CollectionMetadataResult>(this);
    QFuture<CollectionMetadataResult> future;
    if (m_encryptedStoragePlugins.contains(storagePluginName)) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::collectionMetadata,
                    m_encryptedStoragePlugins[storagePluginName],
                    collectionName);
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::collectionMetadata,
                    m_storagePlugins[storagePluginName],
                    collectionName);
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<CollectionMetadataResult>::finished, [=] {
        watcher->deleteLater();
        CollectionMetadataResult cmr = watcher->future().result();
        Result result = cmr.result.code() != Result::Succeeded
                ? cmr.result
                : deleteCollectionWithMetadata(
                      callerPid,
                      requestId,
                      collectionName,
                      storagePluginName,
                      userInteractionMode,
                      interactionServiceAddress,
                      cmr.metadata);
        if (result.code() != Result::Pending) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::deleteCollectionWithMetadata(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata)
{
    // TODO: perform access control request to see if the application has permission to delete the collection.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    if (collectionMetadata.accessControlMode == SecretManager::SystemAccessControlMode) {
        // TODO: perform access control request, to ask for permission to set the secret in the collection.
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("Access control requests are not currently supported. TODO!"));
    } else if (collectionMetadata.accessControlMode == SecretManager::OwnerOnlyMode
               && collectionMetadata.ownerApplicationId != callerApplicationId) {
        return Result(Result::PermissionsError,
                      QString::fromLatin1("Collection %1 is owned by a different application")
                      .arg(collectionName));
    } else if (!m_authenticationPlugins.contains(collectionMetadata.authenticationPluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such authentication plugin available: %1")
                      .arg(collectionMetadata.authenticationPluginName));
    }

    bool locked = false;
    Result result(Result::Succeeded);
    if (m_encryptedStoragePlugins.contains(storagePluginName)) {
        // TODO: make this asynchronous instead of blocking the main thread!
        QFuture<LockedResult> future
                = QtConcurrent::run(
                        m_requestQueue->secretsThreadPool().data(),
                        EncryptedStoragePluginFunctionWrapper::isCollectionLocked,
                        m_encryptedStoragePlugins[storagePluginName],
                        collectionName);
        future.waitForFinished();
        LockedResult lr = future.result();
        result = lr.result;
        locked = lr.locked;
        if (result.code() != Result::Succeeded) {
            return result;
        }
    }

    if (locked) {
        const QString authPluginName = determineAuthPlugin(
                    collectionMetadata.ownerApplicationId,
                    callerApplicationId,
                    applicationIsPlatformApplication,
                    collectionMetadata.authenticationPluginName,
                    interactionServiceAddress,
                    m_autotestMode);

        if (collectionMetadata.usesDeviceLockKey) {
            // TODO: perform a "verify" UI flow (if the user interaction mode allows)
            //       If that succeeds, unlock the collection with the stored devicelock key and continue.
            return Result(Result::CollectionIsLockedError,
                          QString::fromLatin1("Collection %1 is locked and requires device lock authentication")
                          .arg(collectionName));
        } else if (userInteractionMode == SecretManager::PreventInteraction) {
            return Result(Result::OperationRequiresUserInteraction,
                          QString::fromLatin1("Authentication plugin %1 requires user interaction")
                          .arg(authPluginName));
        } else if (!m_authenticationPlugins.contains(authPluginName)) {
            // TODO: stale data in metadata db?
            return Result(Result::InvalidExtensionPluginError,
                          QStringLiteral("Unknown collection authentication plugin %1")
                          .arg(authPluginName));
        }

        // perform the user input flow required to get the input key data which will be used
        // to unlock this collection.
        InteractionParameters promptParams;
        promptParams.setApplicationId(callerApplicationId);
        promptParams.setPluginName(storagePluginName);
        promptParams.setCollectionName(collectionName);
        promptParams.setOperation(InteractionParameters::DeleteCollection);
        promptParams.setInputType(InteractionParameters::AlphaNumericInput);
        promptParams.setEchoMode(InteractionParameters::PasswordEcho);
        promptParams.setPromptText({
            //: This will be displayed to the user, prompting them to enter a passphrase which will be used to unlock a collection for deletion. %1 is the application name, %2 is the collection name, %3 is the plugin name.
            //% "App %1 wants to delete collection %2 in plugin %3."
            { InteractionParameters::Message, qtTrId("sailfish_secrets-delete_collection-la-message")
                        .arg(callerApplicationId, collectionName, m_requestQueue->controller()->displayNameForPlugin(storagePluginName)) },
           //% "Enter the passphrase which will be used to unlock the collection for deletion."
           { InteractionParameters::Instruction, qtTrId("sailfish_secrets-delete_collection-la-enter_collection_passphrase") }
        });
        Result result = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                    callerPid,
                    requestId,
                    promptParams,
                    interactionServiceAddress);
        if (result.code() == Result::Failed) {
            return result;
        }

        // calls deleteCollectionWithLockCode when finished
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::DeleteCollectionRequest,
                                     QVariantList() << collectionName
                                                    << storagePluginName
                                                    << userInteractionMode
                                                    << interactionServiceAddress
                                                    << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
    } else {
        deleteCollectionWithLockCode(
                    callerPid,
                    requestId,
                    collectionName,
                    storagePluginName,
                    userInteractionMode,
                    interactionServiceAddress,
                    collectionMetadata,
                    QByteArray());
    }

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::deleteCollectionWithLockCode(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &lockCode)
{
    Q_UNUSED(callerPid);
    Q_UNUSED(userInteractionMode);
    Q_UNUSED(interactionServiceAddress);

    QFutureWatcher<Result> *watcher = new QFutureWatcher<Result>(this);
    QFuture<Result> future;
    if (m_encryptedStoragePlugins.contains(storagePluginName)) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::deriveKeyUnlockAndRemoveCollection,
                    m_encryptedStoragePlugins[storagePluginName],
                    collectionName,
                    lockCode,
                    m_requestQueue->saltData());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::removeCollection,
                    m_storagePlugins[storagePluginName],
                    collectionName);
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<Result>::finished, [=] {
        watcher->deleteLater();
        Result pluginResult = watcher->future().result();
        if (pluginResult.code() == Result::Succeeded) {
            const QString hashedCollectionName = calculateSecretNameHash(
                        Secret::Identifier(QString(), collectionName, storagePluginName));
            m_collectionEncryptionKeys.remove(hashedCollectionName);
            if (collectionMetadata.accessControlMode == SecretManager::SystemAccessControlMode) {
                // TODO: tell AccessControl daemon to remove this datum from its database.
            }
        }

        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(pluginResult);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

// this method is a helper for the crypto API.
// Retrieve identifiers of stored keys from the plugin.
// If a collection name is given, attempt to unlock the collection first.
Result
Daemon::ApiImpl::RequestProcessor::storedKeyIdentifiers(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        QVector<Secret::Identifier> *identifiers)
{
    if (storagePluginName.isEmpty()) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Empty storage plugin name given"));
    } else if (!m_encryptedStoragePlugins.contains(storagePluginName)
            && !m_storagePlugins.contains(storagePluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown storage plugin name given"));
    } else if (collectionName.compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Reserved collection name given"));
    }

    if (collectionName.isEmpty()) {
        // return key identifiers from all collections in the plugin.
        // note that collections which are locked will NOT be represented.
        // TODO: make this one asynchronous.
        QFuture<IdentifiersResult> future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    &Daemon::ApiImpl::storedKeyIdentifiers,
                    m_storagePlugins.value(storagePluginName),
                    m_encryptedStoragePlugins.value(storagePluginName),
                    m_cryptoStoragePlugins.value(storagePluginName));
        future.waitForFinished();
        *identifiers = future.result().identifiers;
        return future.result().result;
    }

    // Read the metadata about the target collection
    QFutureWatcher<CollectionMetadataResult> *watcher
            = new QFutureWatcher<CollectionMetadataResult>(this);
    QFuture<CollectionMetadataResult> future;
    if (m_encryptedStoragePlugins.contains(storagePluginName)) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::collectionMetadata,
                    m_encryptedStoragePlugins[storagePluginName],
                    collectionName);
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::collectionMetadata,
                    m_storagePlugins[storagePluginName],
                    collectionName);
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<CollectionMetadataResult>::finished, [=] {
        watcher->deleteLater();
        CollectionMetadataResult cmr = watcher->future().result();
        Result result = cmr.result.code() != Result::Succeeded
                ? cmr.result
                : storedKeyIdentifiersWithMetadata(
                      callerPid,
                      requestId,
                      collectionName,
                      storagePluginName,
                      userInteractionMode,
                      interactionServiceAddress,
                      cmr.metadata);
        if (result.code() != Result::Pending) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::storedKeyIdentifiersWithMetadata(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata)
{
    // TODO: perform access control request to see if the application has permission to delete the collection.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    if (collectionMetadata.accessControlMode == SecretManager::SystemAccessControlMode) {
        // TODO: perform access control request, to ask for permission to set the secret in the collection.
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("Access control requests are not currently supported. TODO!"));
    } else if (collectionMetadata.accessControlMode == SecretManager::OwnerOnlyMode
               && collectionMetadata.ownerApplicationId != callerApplicationId) {
        return Result(Result::PermissionsError,
                      QString::fromLatin1("Collection %1 is owned by a different application")
                      .arg(collectionName));
    } else if (!m_authenticationPlugins.contains(collectionMetadata.authenticationPluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such authentication plugin available: %1")
                      .arg(collectionMetadata.authenticationPluginName));
    }

    bool locked = false;
    Result result(Result::Succeeded);
    if (m_encryptedStoragePlugins.contains(storagePluginName)) {
        // TODO: make this asynchronous instead of blocking the main thread!
        QFuture<LockedResult> future
                = QtConcurrent::run(
                        m_requestQueue->secretsThreadPool().data(),
                        EncryptedStoragePluginFunctionWrapper::isCollectionLocked,
                        m_encryptedStoragePlugins[storagePluginName],
                        collectionName);
        future.waitForFinished();
        LockedResult lr = future.result();
        result = lr.result;
        locked = lr.locked;
        if (result.code() != Result::Succeeded) {
            return result;
        }
    }

    if (locked) {
        const QString authPluginName = determineAuthPlugin(
                    collectionMetadata.ownerApplicationId,
                    callerApplicationId,
                    applicationIsPlatformApplication,
                    collectionMetadata.authenticationPluginName,
                    interactionServiceAddress,
                    m_autotestMode);

        if (collectionMetadata.usesDeviceLockKey) {
            // TODO: perform a "verify" UI flow (if the user interaction mode allows)
            //       If that succeeds, unlock the collection with the stored devicelock key and continue.
            return Result(Result::CollectionIsLockedError,
                          QString::fromLatin1("Collection %1 is locked and requires device lock authentication")
                          .arg(collectionName));
        } else if (userInteractionMode == SecretManager::PreventInteraction) {
            return Result(Result::OperationRequiresUserInteraction,
                          QString::fromLatin1("Authentication plugin %1 requires user interaction")
                          .arg(authPluginName));
        } else if (!m_authenticationPlugins.contains(authPluginName)) {
            // TODO: stale data in metadata db?
            return Result(Result::InvalidExtensionPluginError,
                          QStringLiteral("Unknown collection authentication plugin %1")
                          .arg(authPluginName));
        }

        // perform the user input flow required to get the input key data which will be used
        // to unlock this collection.
        InteractionParameters promptParams;
        promptParams.setApplicationId(callerApplicationId);
        promptParams.setPluginName(storagePluginName);
        promptParams.setCollectionName(collectionName);
        promptParams.setOperation(InteractionParameters::UnlockCollection);
        promptParams.setInputType(InteractionParameters::AlphaNumericInput);
        promptParams.setEchoMode(InteractionParameters::PasswordEcho);
        promptParams.setPromptText({
            //: This will be displayed to the user, prompting them to enter a passphrase which will be used to unlock a collection to read key identifiers. %1 is the application name, %2 is the collection name, %3 is the plugin name.
            //% "App %1 wants to read key identifiers from collection %2 in plugin %3."
            { InteractionParameters::Message, qtTrId("sailfish_secrets-unlock_collection-la-message")
                        .arg(callerApplicationId, collectionName, m_requestQueue->controller()->displayNameForPlugin(storagePluginName)) },
            //% "Enter the passphrase which will be used to unlock the collection."
            { InteractionParameters::Instruction, qtTrId("sailfish_secrets-unlock_collection-la-enter_collection_passphrase") }
        });
        Result result = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                    callerPid,
                    requestId,
                    promptParams,
                    interactionServiceAddress);
        if (result.code() == Result::Failed) {
            return result;
        }

        // calls storedKeyIdentifiersWithAuthenticationCode when finished
        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::StoredKeyIdentifiersRequest,
                                     QVariantList() << collectionName
                                                    << storagePluginName
                                                    << userInteractionMode
                                                    << interactionServiceAddress
                                                    << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
    } else {
        storedKeyIdentifiersWithEncryptionKey(
                    callerPid,
                    requestId,
                    collectionName,
                    storagePluginName,
                    userInteractionMode,
                    interactionServiceAddress,
                    collectionMetadata,
                    QByteArray(),
                    false);
    }

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::storedKeyIdentifiersWithAuthenticationCode(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &authenticationCode)
{
    QFutureWatcher<DerivedKeyResult> *watcher
            = new QFutureWatcher<DerivedKeyResult>(this);
    QFuture<DerivedKeyResult> future;
    if (storagePluginName == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptedStoragePlugins[storagePluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptionPluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptionPlugins[collectionMetadata.encryptionPluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DerivedKeyResult>::finished, [=] {
        watcher->deleteLater();
        DerivedKeyResult dkr = watcher->future().result();
        if (dkr.result.code() != Result::Succeeded) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(dkr.result);
            outParams << QVariant::fromValue<QVector<Secret::Identifier> >(QVector<Secret::Identifier>());
            m_requestQueue->requestFinished(requestId, outParams);
        } else {
            storedKeyIdentifiersWithEncryptionKey(
                        callerPid, requestId, collectionName, storagePluginName,
                        userInteractionMode, interactionServiceAddress,
                        collectionMetadata, dkr.key, true);
        }
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::storedKeyIdentifiersWithEncryptionKey(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &collectionKey,
        bool collectionWasLocked)
{
    Q_UNUSED(callerPid);
    Q_UNUSED(userInteractionMode);
    Q_UNUSED(interactionServiceAddress);

    bool requiresRelock = collectionWasLocked &&
            ((!collectionMetadata.usesDeviceLockKey
              && collectionMetadata.unlockSemantic != SecretManager::CustomLockKeepUnlocked)
            || (collectionMetadata.usesDeviceLockKey
              && collectionMetadata.unlockSemantic != SecretManager::DeviceLockKeepUnlocked));
    QFutureWatcher<IdentifiersResult> *watcher = new QFutureWatcher<IdentifiersResult>(this);
    QFuture<IdentifiersResult> future = QtConcurrent::run(
                m_requestQueue->secretsThreadPool().data(),
                &Daemon::ApiImpl::storedKeyIdentifiersFromCollection,
                m_storagePlugins.value(storagePluginName),
                m_encryptedStoragePlugins.value(storagePluginName),
                m_cryptoStoragePlugins.value(storagePluginName),
                CollectionInfo(collectionName, collectionKey, requiresRelock));

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<IdentifiersResult>::finished, [=] {
        watcher->deleteLater();
        IdentifiersResult identResult = watcher->future().result();
        Result pluginResult = identResult.result;
        if (pluginResult.code() == Result::Succeeded && !requiresRelock) {
            const QString hashedCollectionName = calculateSecretNameHash(
                        Secret::Identifier(QString(), collectionName, storagePluginName));
            m_collectionEncryptionKeys.insert(hashedCollectionName, collectionKey);
        }

        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(pluginResult);
        outParams << QVariant::fromValue<QVector<Secret::Identifier> >(identResult.identifiers);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

// this method is a helper for the crypto API.
// Get data from the user to use as input data to a key derivation function.
Result
Daemon::ApiImpl::RequestProcessor::userInput(
        pid_t callerPid,
        quint64 requestId,
        const InteractionParameters &uiParams)
{
    // TODO: perform access control request to see if the application has permission to request user input.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    QString userInputPlugin = uiParams.authenticationPluginName();
    if (uiParams.authenticationPluginName().isEmpty()) {
        // TODO: depending on type, choose the appropriate authentication plugin
        userInputPlugin = SecretManager::DefaultAuthenticationPluginName;
        if (m_autotestMode) {
            userInputPlugin.append(QLatin1String(".test"));
        }
    }
    if (!m_authenticationPlugins.contains(userInputPlugin)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("Cannot get user input from invalid authentication plugin: %1")
                      .arg(uiParams.authenticationPluginName()));
    }

    InteractionParameters promptParams(uiParams);
    promptParams.setApplicationId(callerApplicationId);
    if (promptParams.collectionName().isEmpty() && promptParams.secretName().isEmpty()) {
        // this is a request on behalf of a client application.
        // the user needs to be warned that the data they enter cannot
        // be considered to be "secure" in the secrets-storage sense.

        InteractionParameters::PromptText promptText = promptParams.promptText();
        //: Inform the user that the application is requesting data. %1 is the application name, %2 is the prompt text supplied by the application.
        //% "An application %1 is requesting input which will be returned to the application: %2"
        promptText.setMessage(qtTrId("sailfish_secrets-user_input-la-data_request")
                              .arg(callerApplicationId, promptText.message()));

        promptParams.setPromptText(promptText);
    }
    Result interactionResult = m_authenticationPlugins[userInputPlugin]->beginUserInputInteraction(
                callerPid,
                requestId,
                promptParams,
                QString());
    if (interactionResult.code() == Result::Failed) {
        return interactionResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::UserInputRequest,
                                 QVariantList() << QVariant::fromValue<InteractionParameters>(promptParams)));
    return Result(Result::Pending);
}

// set a secret in a collection
Result
Daemon::ApiImpl::RequestProcessor::setCollectionSecret(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        const Sailfish::Secrets::InteractionParameters &uiParams,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress)
{
    if (secret.identifier().name().isEmpty()) {
        return Result(Result::InvalidSecretError,
                      QLatin1String("Empty secret name given"));
    } else if (secret.identifier().collectionName().isEmpty()) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Empty collection name given"));
    } else if (secret.identifier().collectionName().compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Reserved collection name given"));
    } else if (secret.identifier().storagePluginName().isEmpty()) {
        return Result(Result::InvalidExtensionPluginError,
                      QLatin1String("Empty storage plugin name given"));
    } else if (!m_storagePlugins.contains(secret.identifier().storagePluginName())
               && !m_encryptedStoragePlugins.contains(secret.identifier().storagePluginName())) {
        return Result(Result::InvalidExtensionPluginError,
                      QLatin1String("Unknown storage plugin name given"));
    }

    // Read the metadata about the target collection
    QFutureWatcher<CollectionMetadataResult> *watcher
            = new QFutureWatcher<CollectionMetadataResult>(this);
    QFuture<CollectionMetadataResult> future;
    if (m_encryptedStoragePlugins.contains(secret.identifier().storagePluginName())) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::collectionMetadata,
                    m_encryptedStoragePlugins[secret.identifier().storagePluginName()],
                    secret.identifier().collectionName());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::collectionMetadata,
                    m_storagePlugins[secret.identifier().storagePluginName()],
                    secret.identifier().collectionName());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<CollectionMetadataResult>::finished, [=] {
        watcher->deleteLater();
        CollectionMetadataResult cmr = watcher->future().result();
        Result result = cmr.result.code() != Result::Succeeded
                ? cmr.result
                : setCollectionSecretWithMetadata(
                      callerPid,
                      requestId,
                      secret,
                      uiParams,
                      userInteractionMode,
                      interactionServiceAddress,
                      cmr.metadata);
        if (result.code() != Result::Pending) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::setCollectionSecretWithMetadata(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        const Sailfish::Secrets::InteractionParameters &uiParams,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata)
{
    // TODO: perform access control request to see if the application has permission to write secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    if (collectionMetadata.accessControlMode == SecretManager::SystemAccessControlMode) {
        // TODO: perform access control request, to ask for permission to set the secret in the collection.
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("Access control requests are not currently supported. TODO!"));
    } else if (collectionMetadata.accessControlMode == SecretManager::OwnerOnlyMode
               && collectionMetadata.ownerApplicationId != callerApplicationId) {
        return Result(Result::PermissionsError,
                      QString::fromLatin1("Collection %1 in plugin %2 is owned by a different application")
                      .arg(secret.identifier().collectionName(), secret.identifier().storagePluginName()));
    }

    // Check to see if we need to request the secret data from the user.
    if (!uiParams.isValid()) {
        // don't need to retrieve secret data from the user,
        // just store it directly.
        return setCollectionSecretGetAuthenticationCode(
                    callerPid,
                    requestId,
                    secret,
                    userInteractionMode,
                    interactionServiceAddress,
                    collectionMetadata);
    }

    // otherwise, we need to perform another asynchronous request,
    // to retrieve the secret data from the user.
    QString userInputPlugin = uiParams.authenticationPluginName();
    if (uiParams.authenticationPluginName().isEmpty()) {
        // TODO: depending on type, choose the appropriate authentication plugin
        userInputPlugin = SecretManager::DefaultAuthenticationPluginName;
        if (m_autotestMode) {
            userInputPlugin.append(QLatin1String(".test"));
        }
    }
    if (!m_authenticationPlugins.contains(userInputPlugin)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("Cannot get user input from invalid authentication plugin: %1")
                      .arg(uiParams.authenticationPluginName()));
    }

    // perform UI request to get the data for the secret
    InteractionParameters modifiedUiParams(uiParams);
    modifiedUiParams.setApplicationId(callerApplicationId);
    modifiedUiParams.setCollectionName(secret.identifier().collectionName());
    modifiedUiParams.setSecretName(secret.identifier().name());
    modifiedUiParams.setOperation(InteractionParameters::RequestUserData);
    modifiedUiParams.setPromptText({
        //: This will be displayed to the user, prompting them to enter the secret data which will be stored. %1 is the application name, %2 is the secret name, %3 is the collection name, %4 is the plugin name.
        //% "App %1 wants to store a new secret named %2 into collection %3 in plugin %4."
        { InteractionParameters::Message, qtTrId("sailfish_secrets-set_collection_secret-la-message")
                    .arg(callerApplicationId,
                            secret.identifier().name(),
                            secret.identifier().collectionName(),
                            m_requestQueue->controller()->displayNameForPlugin(secret.identifier().storagePluginName())) },
        //% "Enter the confidential data which will be stored."
        { InteractionParameters::Instruction, qtTrId("sailfish_secrets-set_collection_secret-la-enter_secret_data") }
    });
    Result authenticationResult = m_authenticationPlugins[userInputPlugin]->beginUserInputInteraction(
                callerPid,
                requestId,
                modifiedUiParams,
                interactionServiceAddress); // in most cases this last parameter will be ignored by the plugin.
    if (authenticationResult.code() == Result::Failed) {
        return authenticationResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::SetCollectionUserInputSecretRequest,
                                 QVariantList() << QVariant::fromValue<Secret>(secret)
                                                << QVariant::fromValue<InteractionParameters>(modifiedUiParams)
                                                << userInteractionMode
                                                << interactionServiceAddress
                                                << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::setCollectionSecretGetAuthenticationCode(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata)
{
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    const QString authPluginName = determineAuthPlugin(
                collectionMetadata.ownerApplicationId,
                callerApplicationId,
                applicationIsPlatformApplication,
                collectionMetadata.authenticationPluginName,
                interactionServiceAddress,
                m_autotestMode);

    if (m_encryptedStoragePlugins.contains(secret.identifier().storagePluginName())) {
        // TODO: make this asynchronous instead of blocking the main thread!
        QFuture<LockedResult> future
                = QtConcurrent::run(
                        m_requestQueue->secretsThreadPool().data(),
                        EncryptedStoragePluginFunctionWrapper::isCollectionLocked,
                        m_encryptedStoragePlugins[secret.identifier().storagePluginName()],
                        secret.identifier().collectionName());
        future.waitForFinished();
        LockedResult lr = future.result();
        Result pluginResult = lr.result;
        bool locked = lr.locked;
        if (pluginResult.code() != Result::Succeeded) {
            return pluginResult;
        }
        if (!locked) {
            setCollectionSecretWithEncryptionKey(
                        callerPid,
                        requestId,
                        secret,
                        userInteractionMode,
                        interactionServiceAddress,
                        collectionMetadata,
                        QByteArray());
            return Result(Result::Pending);
        }

        if (collectionMetadata.usesDeviceLockKey) {
            // TODO: perform a "verify" UI flow (if the user interaction mode allows)
            //       If that succeeds, unlock the collection with the stored devicelock key and continue.
            return Result(Result::CollectionIsLockedError,
                          QString::fromLatin1("Collection %1 is locked and requires device lock authentication").arg(secret.identifier().collectionName()));
        } else if (userInteractionMode == SecretManager::PreventInteraction) {
            return Result(Result::OperationRequiresUserInteraction,
                          QString::fromLatin1("Authentication plugin %1 requires user interaction")
                          .arg(authPluginName));
        } else if (!m_authenticationPlugins.contains(authPluginName)) {
            return Result(Result::InvalidExtensionPluginError,
                          QStringLiteral("Unknown collection authentication plugin: %1")
                          .arg(authPluginName));
        }

        // perform the user input flow required to get the input key data which will be used
        // to unlock this collection.
        InteractionParameters promptParams;
        promptParams.setApplicationId(callerApplicationId);
        promptParams.setPluginName(secret.identifier().storagePluginName());
        promptParams.setCollectionName(secret.identifier().collectionName());
        promptParams.setSecretName(secret.identifier().name());
        promptParams.setOperation(InteractionParameters::StoreSecret);
        promptParams.setInputType(InteractionParameters::AlphaNumericInput);
        promptParams.setEchoMode(InteractionParameters::PasswordEcho);
        promptParams.setPromptText({
            //: This will be displayed to the user, prompting them to enter the passphrase to unlock the collection in which a new secret will be stored. %1 is the application name, %2 is the  secret name, %3 is the collection name, %4 is the plugin name.
            //% "App %1 wants to store a new secret named %2 into collection %3 in plugin %4."
            { InteractionParameters::Message, qtTrId("sailfish_secrets-set_collection_secret-la-message")
                        .arg(callerApplicationId,
                                secret.identifier().name(),
                                secret.identifier().collectionName(),
                                m_requestQueue->controller()->displayNameForPlugin(secret.identifier().storagePluginName())) },
            //% "Enter the passphrase to unlock the collection."
            { InteractionParameters::Instruction, qtTrId("sailfish_secrets-set_collection_secret-la-enter_collection_passphrase") }
        });
        Result interactionResult = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                    callerPid,
                    requestId,
                    promptParams,
                    interactionServiceAddress);
        if (interactionResult.code() == Result::Failed) {
            return interactionResult;
        }

        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::SetCollectionSecretRequest,
                                     QVariantList() << QVariant::fromValue<Secret>(secret)
                                                    << userInteractionMode
                                                    << interactionServiceAddress
                                                    << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
        return Result(Result::Pending);
    }

    const QString hashedCollectionName = calculateSecretNameHash(
                Secret::Identifier(QString(), secret.identifier().collectionName(), secret.identifier().storagePluginName()));
    if (m_collectionEncryptionKeys.contains(hashedCollectionName)) {
        setCollectionSecretWithEncryptionKey(
                    callerPid,
                    requestId,
                    secret,
                    userInteractionMode,
                    interactionServiceAddress,
                    collectionMetadata,
                    m_collectionEncryptionKeys.value(hashedCollectionName));
        return Result(Result::Pending);
    }

    if (collectionMetadata.usesDeviceLockKey) {
        // TODO: perform a "verify" UI flow (if the user interaction mode allows)
        return Result(Result::CollectionIsLockedError,
                      QString::fromLatin1("Collection %1 is locked and requires device lock authentication").arg(secret.identifier().collectionName()));
    } else if (userInteractionMode == SecretManager::PreventInteraction) {
        return Result(Result::OperationRequiresUserInteraction,
                      QString::fromLatin1("Authentication plugin %1 requires user interaction")
                      .arg(authPluginName));
    } else if (!m_authenticationPlugins.contains(authPluginName)) {
        // TODO: stale data in metadata db?
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown collection authentication plugin: %1")
                      .arg(authPluginName));
    }

    // perform the user input flow required to get the input key data which will be used
    // to unlock this collection.
    InteractionParameters promptParams;
    promptParams.setApplicationId(callerApplicationId);
    promptParams.setPluginName(secret.identifier().storagePluginName());
    promptParams.setCollectionName(secret.identifier().collectionName());
    promptParams.setSecretName(secret.identifier().name());
    promptParams.setOperation(InteractionParameters::StoreSecret);
    promptParams.setInputType(InteractionParameters::AlphaNumericInput);
    promptParams.setEchoMode(InteractionParameters::PasswordEcho);
    promptParams.setPromptText({
        //: This will be displayed to the user, prompting them to enter the passphrase to unlock the collection in which a new secret will be stored. %1 is the application name, %2 is the  secret name, %3 is the collection name, %4 is the plugin name.
        //% "App %1 wants to store a new secret named %2 into collection %3 in plugin %4."
        { InteractionParameters::Message, qtTrId("sailfish_secrets-set_collection_secret-la-collection_message")
                    .arg(callerApplicationId,
                            secret.identifier().name(),
                            secret.identifier().collectionName(),
                            m_requestQueue->controller()->displayNameForPlugin(secret.identifier().storagePluginName())) },
        //% "Enter the passphrase to unlock the collection."
        { InteractionParameters::Instruction, qtTrId("sailfish_secrets-set_collection_secret-la-enter_collection_passphrase") }
    });
    Result interactionResult = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                callerPid,
                requestId,
                promptParams,
                interactionServiceAddress);
    if (interactionResult.code() == Result::Failed) {
        return interactionResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::SetCollectionSecretRequest,
                                 QVariantList() << QVariant::fromValue<Secret>(secret)
                                                << userInteractionMode
                                                << interactionServiceAddress
                                                << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::setCollectionSecretWithAuthenticationCode(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &authenticationCode)
{
    // generate the encryption key from the authentication code
    if (secret.identifier().storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        if (!m_encryptedStoragePlugins.contains(secret.identifier().storagePluginName())) {
            // TODO: stale data in the database?
            return Result(Result::InvalidExtensionPluginError,
                          QStringLiteral("Unknown collection encrypted storage plugin: %1")
                          .arg(secret.identifier().storagePluginName()));
        }
    } else if (!m_encryptionPlugins.contains(collectionMetadata.encryptionPluginName)) {
        // TODO: stale data in the database?
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown collection encryption plugin: %1").arg(collectionMetadata.encryptionPluginName));
    }

    QFutureWatcher<DerivedKeyResult> *watcher
            = new QFutureWatcher<DerivedKeyResult>(this);
    QFuture<DerivedKeyResult> future;
    if (secret.identifier().storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptedStoragePlugins[secret.identifier().storagePluginName()],
                    authenticationCode,
                    m_requestQueue->saltData());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptionPluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptionPlugins[collectionMetadata.encryptionPluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DerivedKeyResult>::finished, [=] {
        watcher->deleteLater();
        DerivedKeyResult dkr = watcher->future().result();
        if (dkr.result.code() != Result::Succeeded) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(dkr.result);
            m_requestQueue->requestFinished(requestId, outParams);
        } else {
            setCollectionSecretWithEncryptionKey(
                        callerPid, requestId, secret,
                        userInteractionMode, interactionServiceAddress,
                        collectionMetadata, dkr.key);
        }
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::setCollectionSecretWithEncryptionKey(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &encryptionKey)
{
    // In the future, we may need these for access control UI flows.
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);
    Q_UNUSED(userInteractionMode);
    Q_UNUSED(interactionServiceAddress);

    SecretMetadata secretMetadata;
    secretMetadata.collectionName = secret.identifier().collectionName();
    secretMetadata.secretName = secret.identifier().name();
    secretMetadata.ownerApplicationId = collectionMetadata.ownerApplicationId;
    secretMetadata.usesDeviceLockKey = collectionMetadata.usesDeviceLockKey;
    secretMetadata.encryptionPluginName = collectionMetadata.encryptionPluginName;
    secretMetadata.authenticationPluginName = collectionMetadata.authenticationPluginName;
    secretMetadata.unlockSemantic = collectionMetadata.unlockSemantic;
    secretMetadata.accessControlMode = collectionMetadata.accessControlMode;
    secretMetadata.secretType = secret.type();

    QFutureWatcher<Result> *watcher = new QFutureWatcher<Result>(this);
    QFuture<Result> future;
    if (secret.identifier().storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                m_requestQueue->secretsThreadPool().data(),
                EncryptedStoragePluginFunctionWrapper::unlockCollectionAndStoreSecret,
                m_encryptedStoragePlugins[secret.identifier().storagePluginName()],
                secretMetadata,
                secret,
                encryptionKey);
    } else {
        bool requiresRelock =
                ((!secretMetadata.usesDeviceLockKey
                  && secretMetadata.unlockSemantic != SecretManager::CustomLockKeepUnlocked)
                || (secretMetadata.usesDeviceLockKey
                  && secretMetadata.unlockSemantic != SecretManager::DeviceLockKeepUnlocked));
        const QString hashedCollectionName = calculateSecretNameHash(
                    Secret::Identifier(QString(), secret.identifier().collectionName(), secret.identifier().storagePluginName()));
        if (!m_collectionEncryptionKeys.contains(hashedCollectionName) && !requiresRelock) {
            // TODO: some way to "test" the encryptionKey!
            m_collectionEncryptionKeys.insert(hashedCollectionName, encryptionKey);
        }

        future = QtConcurrent::run(
                m_requestQueue->secretsThreadPool().data(),
                StoragePluginFunctionWrapper::encryptAndStoreSecret,
                m_encryptionPlugins[secretMetadata.encryptionPluginName],
                m_storagePlugins[secret.identifier().storagePluginName()],
                secretMetadata,
                secret,
                encryptionKey);
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<Result>::finished, [=] {
        watcher->deleteLater();
        Result pluginResult = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(pluginResult);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

// set a standalone DeviceLock-protected secret
Result
Daemon::ApiImpl::RequestProcessor::setStandaloneDeviceLockSecret(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        const QString &encryptionPluginName,
        const InteractionParameters &uiParams,
        SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress)
{
    // TODO: Access Control requests to see if the application is permitted to set the secret.
    Q_UNUSED(userInteractionMode);

    if (secret.identifier().name().isEmpty()) {
        return Result(Result::InvalidSecretError,
                      QLatin1String("Empty secret name given"));
    } else if (secret.identifier().storagePluginName() == encryptionPluginName
               && !m_encryptedStoragePlugins.contains(secret.identifier().storagePluginName())) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such encrypted storage plugin exists: %1")
                      .arg(secret.identifier().storagePluginName()));
    } else if (secret.identifier().storagePluginName() != encryptionPluginName
               && !m_storagePlugins.contains(secret.identifier().storagePluginName())) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such storage plugin exists: %1")
                      .arg(secret.identifier().storagePluginName()));
    } else if (secret.identifier().storagePluginName() != encryptionPluginName
               && !m_encryptionPlugins.contains(encryptionPluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such encryption plugin exists: %1").arg(encryptionPluginName));
    } else if (accessControlMode == SecretManager::SystemAccessControlMode) {
        // TODO: implement system access control mode.
        // TODO: in the meantime, change SystemAccessControlMode to OwnerOnlyMode?
        return Result(Result::OperationNotSupportedError,
                      QStringLiteral("System access control mode is currently not supported. TODO!"));
    } else if (uiParams.isValid() && userInteractionMode == SecretManager::PreventInteraction) {
        return Result(Result::OperationRequiresUserInteraction,
                      QStringLiteral("The specified interaction mode precludes requesting secret data from the user"));
    } else if (secret.identifier().storagePluginName() == encryptionPluginName
               || m_encryptedStoragePlugins.contains(secret.identifier().storagePluginName())) {
        // To support this use case, we'd need to add to the encrypted storage plugin:
        // re-encryptStandaloneSecrets (for when the device lock key changes).
        return Result(Result::OperationNotSupportedError,
                      QStringLiteral("Device-locked standalone secrets cannot be stored in encrypted storage plugins currently"));
    }

    // TODO: perform access control request to see if the application has permission to write secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    // this is the metadata which we want to store for the secret.
    SecretMetadata secretMetadata;
    secretMetadata.collectionName = QStringLiteral("standalone");
    secretMetadata.secretName = secret.identifier().name();
    secretMetadata.ownerApplicationId = callerApplicationId;
    secretMetadata.usesDeviceLockKey = true;
    secretMetadata.encryptionPluginName = encryptionPluginName;
    secretMetadata.authenticationPluginName = m_autotestMode
            ? (SecretManager::DefaultAuthenticationPluginName + QLatin1String(".test"))
            : SecretManager::DefaultAuthenticationPluginName;
    secretMetadata.unlockSemantic = unlockSemantic;
    secretMetadata.accessControlMode = accessControlMode;
    secretMetadata.secretType = secret.type();

    // Read the metadata about the target secret
    QFutureWatcher<SecretMetadataResult> *watcher
            = new QFutureWatcher<SecretMetadataResult>(this);
    QFuture<SecretMetadataResult> future;
    if (m_encryptedStoragePlugins.contains(secret.identifier().storagePluginName())) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::secretMetadata,
                    m_encryptedStoragePlugins[secret.identifier().storagePluginName()],
                    QStringLiteral("standalone"),
                    secret.identifier().name());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::secretMetadata,
                    m_storagePlugins[secret.identifier().storagePluginName()],
                    QStringLiteral("standalone"),
                    secret.identifier().name());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<SecretMetadataResult>::finished, [=] {
        watcher->deleteLater();
        SecretMetadataResult smr = watcher->future().result();
        Result result;
        if (smr.result.code() == Result::Failed
                // invalid secret means that it doesn't yet exist, which is what we want.
                && smr.result.errorCode() == Result::InvalidSecretError) {
            result = setStandaloneDeviceLockSecretWithMetadata(
                        callerPid,
                        requestId,
                        secret,
                        uiParams,
                        interactionServiceAddress,
                        secretMetadata);
        } else if (smr.result.code() == Result::Failed) {
            result = smr.result;
        } else {
            // TODO: allow overwrite if:
            //     - owner is the same
            //     - usesDeviceLock is the same
            //     - accessControlMode is the same
            //     - the customLockKey provided matches / is able to unlock the old secret.
            result = Result(Result::SecretAlreadyExistsError,
                            QStringLiteral("Cannot overwrite existing standalone secret"));
        }
        if (result.code() != Result::Pending) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::setStandaloneDeviceLockSecretWithMetadata(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        const InteractionParameters &uiParams,
        const QString &interactionServiceAddress,
        const SecretMetadata &newMetadata)
{
    // If the secret data is fully specified, we don't need to request it from the user.
    if (!uiParams.isValid()) {
        return writeStandaloneDeviceLockSecret(
                    callerPid,
                    requestId,
                    secret,
                    newMetadata);
    }

    // otherwise, we need to perform another asynchronous request,
    // to retrieve the secret data from the user.
    QString userInputPlugin = uiParams.authenticationPluginName();
    if (uiParams.authenticationPluginName().isEmpty()) {
        // TODO: depending on type, choose the appropriate authentication plugin
        userInputPlugin = SecretManager::DefaultAuthenticationPluginName;
        if (m_autotestMode) {
            userInputPlugin.append(QLatin1String(".test"));
        }
    }
    if (!m_authenticationPlugins.contains(userInputPlugin)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("Cannot get user input from invalid authentication plugin: %1")
                      .arg(uiParams.authenticationPluginName()));
    }

    // perform UI request to get the data for the secret
    InteractionParameters modifiedUiParams(uiParams);
    modifiedUiParams.setApplicationId(newMetadata.ownerApplicationId);
    modifiedUiParams.setPluginName(secret.identifier().storagePluginName());
    modifiedUiParams.setCollectionName(QStringLiteral("standalone"));
    modifiedUiParams.setSecretName(secret.identifier().name());
    modifiedUiParams.setOperation(InteractionParameters::RequestUserData);
    modifiedUiParams.setPromptText({
        //: This will be displayed to the user, prompting them to enter the standalone secret data which will be stored. %1 is the application name, %2 is the secret name, %3 is the plugin name.
        //% "App %1 wants to store a new secret named %2 into collection %3 in plugin %4."
        { InteractionParameters::Message, qtTrId("sailfish_secrets-set_standalone_secret-la-message")
                    .arg(newMetadata.ownerApplicationId,
                            secret.identifier().name(),
                            m_requestQueue->controller()->displayNameForPlugin(secret.identifier().storagePluginName())) },
        //% "Enter the confidential data which will be stored."
        { InteractionParameters::Instruction, qtTrId("sailfish_secrets-set_standalone_secret-la-enter_secret_data") }
    });
    Result authenticationResult = m_authenticationPlugins[userInputPlugin]->beginUserInputInteraction(
                callerPid,
                requestId,
                modifiedUiParams,
                interactionServiceAddress); // in most cases this last parameter will be ignored by the plugin.
    if (authenticationResult.code() == Result::Failed) {
        return authenticationResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::SetStandaloneDeviceLockUserInputSecretRequest,
                                 QVariantList() << QVariant::fromValue<Secret>(secret)
                                                << QVariant::fromValue<SecretMetadata>(newMetadata)));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::writeStandaloneDeviceLockSecret(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        const SecretMetadata &secretMetadata)
{
    Q_UNUSED(callerPid) // may be required in future.

    Secret identifiedSecret(secret);
    identifiedSecret.setCollectionName(QStringLiteral("standalone"));
    QFutureWatcher<Result> *watcher = new QFutureWatcher<Result>(this);
    QFuture<Result> future = QtConcurrent::run(
            m_requestQueue->secretsThreadPool().data(),
            StoragePluginFunctionWrapper::encryptAndStoreSecret,
            m_encryptionPlugins[secretMetadata.encryptionPluginName],
            m_storagePlugins[secret.identifier().storagePluginName()],
            secretMetadata,
            identifiedSecret,
            m_requestQueue->deviceLockKey());

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<Result>::finished, [=] {
        watcher->deleteLater();
        Result pluginResult = watcher->future().result();
        if (pluginResult.code() == Result::Succeeded) {
            const QString hashedSecretName = calculateSecretNameHash(
                        Secret::Identifier(secret.identifier().name(), QStringLiteral("standalone"), secret.identifier().storagePluginName()));
            m_standaloneSecretEncryptionKeys.insert(hashedSecretName, m_requestQueue->deviceLockKey());
        }
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(pluginResult);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

// set a standalone CustomLock-protected secret
Result
Daemon::ApiImpl::RequestProcessor::setStandaloneCustomLockSecret(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        const InteractionParameters &uiParams,
        SecretManager::CustomLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress)
{
    if (secret.identifier().name().isEmpty()) {
        return Result(Result::InvalidSecretError,
                      QLatin1String("Empty secret name given"));
    } else if (secret.identifier().storagePluginName() == encryptionPluginName
               && !m_encryptedStoragePlugins.contains(secret.identifier().storagePluginName())) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such encrypted storage plugin exists: %1")
                      .arg(secret.identifier().storagePluginName()));
    } else if (secret.identifier().storagePluginName() != encryptionPluginName
               && !m_storagePlugins.contains(secret.identifier().storagePluginName())) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such storage plugin exists: %1")
                      .arg(secret.identifier().storagePluginName()));
    } else if (secret.identifier().storagePluginName() != encryptionPluginName
               && !m_encryptionPlugins.contains(encryptionPluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such encryption plugin exists: %1")
                      .arg(encryptionPluginName));
    } else if (m_authenticationPlugins[authenticationPluginName]->authenticationTypes() & AuthenticationPlugin::ApplicationSpecificAuthentication
               && (userInteractionMode != SecretManager::ApplicationInteraction || interactionServiceAddress.isEmpty())) {
        return Result(Result::OperationRequiresApplicationUserInteraction,
                      QString::fromLatin1("Authentication plugin %1 requires in-process user interaction")
                      .arg(authenticationPluginName));
    } else if (userInteractionMode == SecretManager::PreventInteraction) {
        return Result(Result::OperationRequiresUserInteraction,
                      QString::fromLatin1("Authentication plugin %1 requires user interaction")
                      .arg(authenticationPluginName));
    } else if (accessControlMode == SecretManager::SystemAccessControlMode) {
        return Result(Result::OperationNotSupportedError,
                      QStringLiteral("System access control mode is currently not supported. TODO!"));
    }

    // TODO: perform access control request to see if the application has permission to write secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    // this is the metadata which we want to store for the secret.
    SecretMetadata secretMetadata;
    secretMetadata.collectionName = QStringLiteral("standalone");
    secretMetadata.secretName = secret.identifier().name();
    secretMetadata.ownerApplicationId = callerApplicationId;
    secretMetadata.usesDeviceLockKey = false;
    secretMetadata.encryptionPluginName = encryptionPluginName;
    secretMetadata.authenticationPluginName = authenticationPluginName;
    secretMetadata.unlockSemantic = unlockSemantic;
    secretMetadata.accessControlMode = accessControlMode;
    secretMetadata.secretType = secret.type();

    // Read the metadata about the target secret
    QFutureWatcher<SecretMetadataResult> *watcher
            = new QFutureWatcher<SecretMetadataResult>(this);
    QFuture<SecretMetadataResult> future;
    if (m_encryptedStoragePlugins.contains(secret.identifier().storagePluginName())) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::secretMetadata,
                    m_encryptedStoragePlugins[secret.identifier().storagePluginName()],
                    QStringLiteral("standalone"),
                    secret.identifier().name());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::secretMetadata,
                    m_storagePlugins[secret.identifier().storagePluginName()],
                    QStringLiteral("standalone"),
                    secret.identifier().name());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<SecretMetadataResult>::finished, [=] {
        watcher->deleteLater();
        SecretMetadataResult smr = watcher->future().result();
        Result result;
        if (smr.result.code() == Result::Failed
                // invalid secret means that it doesn't yet exist, which is what we want.
                && smr.result.errorCode() == Result::InvalidSecretError) {
            result = setStandaloneCustomLockSecretWithMetadata(
                        callerPid,
                        requestId,
                        secret,
                        uiParams,
                        userInteractionMode,
                        interactionServiceAddress,
                        secretMetadata);
        } else if (smr.result.code() == Result::Failed) {
            result = smr.result;
        } else {
            // TODO: allow overwrite if:
            //     - owner is the same
            //     - usesDeviceLock is the same
            //     - accessControlMode is the same
            //     - the customLockKey provided matches / is able to unlock the old secret.
            result = Result(Result::SecretAlreadyExistsError,
                            QStringLiteral("Cannot overwrite existing standalone secret"));
        }
        if (result.code() != Result::Pending) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::setStandaloneCustomLockSecretWithMetadata(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        const InteractionParameters &uiParams,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const SecretMetadata &newMetadata)
{
    // If the secret data is fully specified, we don't need to request it from the user.
    if (!uiParams.isValid()) {
        return setStandaloneCustomLockSecretGetAuthenticationCode(
                    callerPid,
                    requestId,
                    secret,
                    userInteractionMode,
                    interactionServiceAddress,
                    newMetadata);
    }

    // otherwise, we need to perform another asynchronous request,
    // to retrieve the secret data from the user.
    QString userInputPlugin = uiParams.authenticationPluginName();
    if (uiParams.authenticationPluginName().isEmpty()) {
        // TODO: depending on type, choose the appropriate authentication plugin
        userInputPlugin = SecretManager::DefaultAuthenticationPluginName;
        if (m_autotestMode) {
            userInputPlugin.append(QLatin1String(".test"));
        }
    }
    if (!m_authenticationPlugins.contains(userInputPlugin)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("Cannot get user input from invalid authentication plugin: %1")
                      .arg(uiParams.authenticationPluginName()));
    }

    // perform UI request to get the data for the secret
    InteractionParameters modifiedUiParams(uiParams);
    modifiedUiParams.setApplicationId(newMetadata.ownerApplicationId);
    modifiedUiParams.setPluginName(secret.identifier().storagePluginName());
    modifiedUiParams.setCollectionName(QStringLiteral("standalone"));
    modifiedUiParams.setSecretName(secret.identifier().name());
    modifiedUiParams.setOperation(InteractionParameters::RequestUserData);
    modifiedUiParams.setPromptText({
        //: This will be displayed to the user, prompting them to enter the standalone secret data which will be stored. %1 is the application name, %2 is the secret name, %3 is the plugin name.
        //% "App %1 wants to store a new secret named %2 into collection %3 in plugin %4."
        { InteractionParameters::Message, qtTrId("sailfish_secrets-set_standalone_secret-la-message")
                    .arg(newMetadata.ownerApplicationId,
                            secret.identifier().name(),
                            m_requestQueue->controller()->displayNameForPlugin(secret.identifier().storagePluginName())) },
        //% "Enter the confidential data which will be stored."
        { InteractionParameters::Instruction, qtTrId("sailfish_secrets-set_standalone_secret-la-enter_secret_data") }
    });
    Result authenticationResult = m_authenticationPlugins[userInputPlugin]->beginUserInputInteraction(
                callerPid,
                requestId,
                modifiedUiParams,
                interactionServiceAddress); // in most cases this last parameter will be ignored by the plugin.
    if (authenticationResult.code() == Result::Failed) {
        return authenticationResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::SetStandaloneCustomLockUserInputSecretRequest,
                                 QVariantList() << QVariant::fromValue<Secret>(secret)
                                                << userInteractionMode
                                                << interactionServiceAddress
                                                << QVariant::fromValue<SecretMetadata>(newMetadata)));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::setStandaloneCustomLockSecretGetAuthenticationCode(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const SecretMetadata &secretMetadata)
{
    // perform the user input flow required to get the input key data which will be used
    // to encrypt the secret
    InteractionParameters promptParams;
    promptParams.setApplicationId(secretMetadata.ownerApplicationId);
    promptParams.setPluginName(secret.identifier().storagePluginName());
    promptParams.setCollectionName(QStringLiteral("standalone"));
    promptParams.setSecretName(secret.identifier().name());
    promptParams.setOperation(InteractionParameters::StoreSecret);
    promptParams.setInputType(InteractionParameters::AlphaNumericInput);
    promptParams.setEchoMode(InteractionParameters::PasswordEcho);
    promptParams.setPromptText({
        //: This will be displayed to the user, prompting them to enter the passphrase to encrypt a standalone secret. %1 is the application name, %2 is the secret name, %3 is the plugin name.
        //% "App %1 wants to store a new standalone secret named %2 into plugin %3"
        { InteractionParameters::Message, qtTrId("sailfish_secrets-set_standalone_secret-la-message")
                    .arg(secretMetadata.ownerApplicationId,
                            secret.identifier().name(),
                            m_requestQueue->controller()->displayNameForPlugin(secret.identifier().storagePluginName())) },
        //% "Enter the passphrase which will be used to encrypt the secret."
        { InteractionParameters::NewInstruction, qtTrId("sailfish_secrets-set_standalone_secret-la-enter_secret_passphrase") },
       //% "Repeat the passphrase which will be used to encrypt the secret."
       { InteractionParameters::RepeatInstruction, qtTrId("sailfish_secrets-set_standalone_secret-la-repeat_secret_passphrase") }
    });
    Q_UNUSED(userInteractionMode); // TODO: ensure the auth plugin uses the appropriate mode?
    Result interactionResult = m_authenticationPlugins[secretMetadata.authenticationPluginName]->beginUserInputInteraction(
                callerPid,
                requestId,
                promptParams,
                interactionServiceAddress);
    if (interactionResult.code() == Result::Failed) {
        return interactionResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::SetStandaloneCustomLockSecretRequest,
                                 QVariantList() << QVariant::fromValue<Secret>(secret)
                                                << QVariant::fromValue<SecretMetadata>(secretMetadata)));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::setStandaloneCustomLockSecretWithAuthenticationCode(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        const SecretMetadata &secretMetadata,
        const QByteArray &authenticationCode)
{
    QFutureWatcher<DerivedKeyResult> *watcher
            = new QFutureWatcher<DerivedKeyResult>(this);
    QFuture<DerivedKeyResult> future;
    if (secret.identifier().storagePluginName() == secretMetadata.encryptionPluginName
            || secretMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptedStoragePlugins[secret.identifier().storagePluginName()],
                    authenticationCode,
                    m_requestQueue->saltData());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptionPluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptionPlugins[secretMetadata.encryptionPluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DerivedKeyResult>::finished, [=] {
        watcher->deleteLater();
        DerivedKeyResult dkr = watcher->future().result();
        if (dkr.result.code() != Result::Succeeded) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(dkr.result);
            m_requestQueue->requestFinished(requestId, outParams);
        } else {
            setStandaloneCustomLockSecretWithEncryptionKey(
                        callerPid, requestId, secret,
                        secretMetadata, dkr.key);
        }
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::setStandaloneCustomLockSecretWithEncryptionKey(
        pid_t callerPid,
        quint64 requestId,
        const Secret &secret,
        const SecretMetadata &secretMetadata,
        const QByteArray &encryptionKey)
{
    Q_UNUSED(callerPid);

    Secret identifiedSecret(secret);
    identifiedSecret.setCollectionName(QStringLiteral("standalone"));

    QFutureWatcher<Result> *watcher = new QFutureWatcher<Result>(this);
    QFuture<Result> future;
    if (secret.identifier().storagePluginName() == secretMetadata.encryptionPluginName
            || secretMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                m_requestQueue->secretsThreadPool().data(),
                EncryptedStoragePluginFunctionWrapper::setStandaloneSecret,
                m_encryptedStoragePlugins[secret.identifier().storagePluginName()],
                secretMetadata,
                identifiedSecret,
                encryptionKey);
    } else {
        Secret identifiedSecret(secret);
        identifiedSecret.setCollectionName(QStringLiteral("standalone"));
        future = QtConcurrent::run(
                m_requestQueue->secretsThreadPool().data(),
                StoragePluginFunctionWrapper::encryptAndStoreSecret,
                m_encryptionPlugins[secretMetadata.encryptionPluginName],
                m_storagePlugins[secret.identifier().storagePluginName()],
                secretMetadata,
                identifiedSecret,
                encryptionKey);
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<Result>::finished, [=] {
        watcher->deleteLater();
        Result pluginResult = watcher->future().result();
        if (pluginResult.code() == Result::Succeeded) {
            if (secret.identifier().storagePluginName() != secretMetadata.encryptionPluginName) {
                const QString hashedSecretName = calculateSecretNameHash(
                            Secret::Identifier(secret.identifier().name(),
                                               QStringLiteral("standalone"),
                                               secret.identifier().storagePluginName()));
                m_standaloneSecretEncryptionKeys.insert(hashedSecretName, encryptionKey);
            }
        }

        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(pluginResult);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

// get a secret in a collection
Result
Daemon::ApiImpl::RequestProcessor::getCollectionSecret(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        Secret *secret)
{
    Q_UNUSED(secret); // asynchronous out param.
    if (identifier.name().isEmpty()) {
        return Result(Result::InvalidSecretError,
                      QLatin1String("Empty secret name given"));
    } else if (identifier.collectionName().isEmpty()) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Empty collection name given"));
    } else if (identifier.collectionName().compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Reserved collection name given"));
    } else if (identifier.storagePluginName().isEmpty()) {
        return Result(Result::InvalidExtensionPluginError,
                      QLatin1String("Empty storage plugin name given"));
    } else if (!m_encryptedStoragePlugins.contains(identifier.storagePluginName())
               && !m_storagePlugins.contains(identifier.storagePluginName())) {
        return Result(Result::InvalidExtensionPluginError,
                      QLatin1String("Unknown storage plugin name given"));
    }

    // Read the metadata about the target collection
    QFutureWatcher<CollectionMetadataResult> *watcher
            = new QFutureWatcher<CollectionMetadataResult>(this);
    QFuture<CollectionMetadataResult> future;
    if (m_encryptedStoragePlugins.contains(identifier.storagePluginName())) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::collectionMetadata,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    identifier.collectionName());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::collectionMetadata,
                    m_storagePlugins[identifier.storagePluginName()],
                    identifier.collectionName());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<CollectionMetadataResult>::finished, [=] {
        watcher->deleteLater();
        CollectionMetadataResult cmr = watcher->future().result();
        Result result = cmr.result.code() != Result::Succeeded
                ? cmr.result
                : getCollectionSecretWithMetadata(
                      callerPid,
                      requestId,
                      identifier,
                      userInteractionMode,
                      interactionServiceAddress,
                      cmr.metadata);
        if (result.code() != Result::Pending) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::getCollectionSecretWithMetadata(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata)
{
    // TODO: perform access control request to see if the application has permission to write secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    const QString authPluginName = determineAuthPlugin(
                collectionMetadata.ownerApplicationId,
                callerApplicationId,
                applicationIsPlatformApplication,
                collectionMetadata.authenticationPluginName,
                interactionServiceAddress,
                m_autotestMode);

    if (collectionMetadata.accessControlMode == SecretManager::SystemAccessControlMode) {
        // TODO: perform access control request, to ask for permission to set the secret in the collection.
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("Access control requests are not currently supported. TODO!"));
    } else if (collectionMetadata.accessControlMode == SecretManager::OwnerOnlyMode
               && collectionMetadata.ownerApplicationId != callerApplicationId) {
        return Result(Result::PermissionsError,
                      QString::fromLatin1("Collection %1 in plugin %2 is owned by a different application")
                      .arg(identifier.collectionName(), identifier.storagePluginName()));
    }

    if (identifier.storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        // TODO: make this asynchronous instead of blocking the main thread!
        QFuture<LockedResult> future
                = QtConcurrent::run(
                        m_requestQueue->secretsThreadPool().data(),
                        EncryptedStoragePluginFunctionWrapper::isCollectionLocked,
                        m_encryptedStoragePlugins[identifier.storagePluginName()],
                        identifier.collectionName());
        future.waitForFinished();
        LockedResult lr = future.result();
        Result pluginResult = lr.result;
        bool locked = lr.locked;
        if (pluginResult.code() != Result::Succeeded) {
            return pluginResult;
        }

        if (locked) {
            if (collectionMetadata.usesDeviceLockKey) {
                // TODO: if the user interaction mode allows, perform a Verification auth request
                //       and if that succeeds, unlock the collection with the device lock key and continue.
                return Result(Result::CollectionIsLockedError,
                              QString::fromLatin1("Collection %1 is locked and requires device lock authentication")
                              .arg(identifier.collectionName()));
            } else {
                if (userInteractionMode == SecretManager::PreventInteraction) {
                    return Result(Result::OperationRequiresUserInteraction,
                                  QString::fromLatin1("Authentication plugin %1 requires user interaction")
                                  .arg(authPluginName));
                } else if (!m_authenticationPlugins.contains(authPluginName)) {
                    // TODO: stale data in the database?
                    return Result(Result::InvalidExtensionPluginError,
                                  QString::fromLatin1("Authentication plugin %1 for collection %2 in storage plugin %3 does not exist")
                                  .arg(authPluginName, collectionMetadata.collectionName, identifier.storagePluginName()));
                } else if (m_authenticationPlugins[authPluginName]->authenticationTypes() & AuthenticationPlugin::ApplicationSpecificAuthentication
                            && (userInteractionMode != SecretManager::ApplicationInteraction || interactionServiceAddress.isEmpty())) {
                    return Result(Result::OperationRequiresApplicationUserInteraction,
                                  QString::fromLatin1("Authentication plugin %1 requires in-process user interaction")
                                  .arg(authPluginName));
                }

                // perform the user input flow required to get the input key data which will be used
                // to unlock the collection.
                InteractionParameters promptParams;
                promptParams.setApplicationId(callerApplicationId);
                promptParams.setCollectionName(identifier.collectionName());
                promptParams.setSecretName(identifier.name());
                promptParams.setOperation(InteractionParameters::ReadSecret);
                promptParams.setInputType(InteractionParameters::AlphaNumericInput);
                promptParams.setEchoMode(InteractionParameters::PasswordEcho);
                promptParams.setPromptText({
                    //: This will be displayed to the user, prompting them to enter the passphrase to unlock the collection in order to retrieve a secret. %1 is the application name, %2 is the  secret name, %3 is the collection name, %4 is the plugin name.
                    //% "App %1 wants to retrieve secret %2 from collection %3 in plugin %4."
                    { InteractionParameters::Message, qtTrId("sailfish_secrets-get_collection_secret-la-message")
                                .arg(callerApplicationId,
                                        identifier.name(),
                                        identifier.collectionName(),
                                        m_requestQueue->controller()->displayNameForPlugin(identifier.storagePluginName())) },
                    //% "Enter the passphrase to unlock the collection."
                    { InteractionParameters::Instruction, qtTrId("sailfish_secrets-get_collection_secret-la-enter_collection_passphrase") }
                });
                Result interactionResult = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                            callerPid,
                            requestId,
                            promptParams,
                            interactionServiceAddress);
                if (interactionResult.code() == Result::Failed) {
                    return interactionResult;
                }

                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::GetCollectionSecretRequest,
                                             QVariantList() << QVariant::fromValue<Secret::Identifier>(identifier)
                                                            << userInteractionMode
                                                            << interactionServiceAddress
                                                            << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
                return Result(Result::Pending);
            }
        } else {
            getCollectionSecretWithEncryptionKey(
                        callerPid,
                        requestId,
                        identifier,
                        userInteractionMode,
                        interactionServiceAddress,
                        collectionMetadata,
                        QByteArray()); // no key required, it's unlocked already
            return Result(Result::Pending);
        }
    } else {
        const QString hashedCollectionName = calculateSecretNameHash(
                    Secret::Identifier(QString(), identifier.collectionName(), identifier.storagePluginName()));
        if (!m_collectionEncryptionKeys.contains(hashedCollectionName)) {
            if (collectionMetadata.usesDeviceLockKey) {
                // TODO: if the user interaction mode allows, perform a Verification auth request
                //       and if that succeeds, unlock the collection with the device lock key and continue.
                return Result(Result::CollectionIsLockedError,
                              QString::fromLatin1("Collection %1 is locked and requires device lock authentication")
                              .arg(identifier.collectionName()));
            } else {
                if (userInteractionMode == SecretManager::PreventInteraction) {
                    return Result(Result::OperationRequiresUserInteraction,
                                  QString::fromLatin1("Authentication plugin %1 requires user interaction")
                                  .arg(authPluginName));
                } else if (!m_authenticationPlugins.contains(authPluginName)) {
                    // TODO: stale data in the database?
                    return Result(Result::InvalidExtensionPluginError,
                                  QString::fromLatin1("Authentication plugin %1 for collection %2 in storage plugin %3 does not exist")
                                  .arg(authPluginName, collectionMetadata.collectionName, identifier.storagePluginName()));
                } else if (m_authenticationPlugins[authPluginName]->authenticationTypes() & AuthenticationPlugin::ApplicationSpecificAuthentication
                           && (userInteractionMode != SecretManager::ApplicationInteraction || interactionServiceAddress.isEmpty())) {
                    return Result(Result::OperationRequiresApplicationUserInteraction,
                                  QString::fromLatin1("Authentication plugin %1 requires in-process user interaction")
                                  .arg(authPluginName));
                }

                // perform the user input flow required to get the input key data which will be used
                // to unlock the collection.
                InteractionParameters promptParams;
                promptParams.setApplicationId(callerApplicationId);
                promptParams.setCollectionName(identifier.collectionName());
                promptParams.setSecretName(identifier.name());
                promptParams.setOperation(InteractionParameters::ReadSecret);
                promptParams.setInputType(InteractionParameters::AlphaNumericInput);
                promptParams.setEchoMode(InteractionParameters::PasswordEcho);
                promptParams.setPromptText({
                    //: This will be displayed to the user, prompting them to enter the passphrase to unlock the collection in order to retrieve a secret. %1 is the application name, %2 is the  secret name, %3 is the collection name, %4 is the plugin name.
                    //% "App %1 wants to retrieve secret %2 from collection %3 in plugin %4."
                    { InteractionParameters::Message, qtTrId("sailfish_secrets-get_collection_secret-la-message")
                                .arg(callerApplicationId,
                                        identifier.name(),
                                        identifier.collectionName(),
                                        m_requestQueue->controller()->displayNameForPlugin(identifier.storagePluginName())) },
                    //% "Enter the passphrase to unlock the collection."
                    { InteractionParameters::Instruction, qtTrId("sailfish_secrets-get_collection_secret-la-enter_collection_passphrase") }
                });
                Result interactionResult = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                            callerPid,
                            requestId,
                            promptParams,
                            interactionServiceAddress);
                if (interactionResult.code() == Result::Failed) {
                    return interactionResult;
                }

                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::GetCollectionSecretRequest,
                                             QVariantList() << QVariant::fromValue<Secret::Identifier>(identifier)
                                                            << userInteractionMode
                                                            << interactionServiceAddress
                                                            << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
                return Result(Result::Pending);
            }
        } else {
            getCollectionSecretWithEncryptionKey(
                        callerPid,
                        requestId,
                        identifier,
                        userInteractionMode,
                        interactionServiceAddress,
                        collectionMetadata,
                        m_collectionEncryptionKeys.value(hashedCollectionName));
            return Result(Result::Pending);
        }
    }
}

Result
Daemon::ApiImpl::RequestProcessor::getCollectionSecretWithAuthenticationCode(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &authenticationCode)
{
    // generate the encryption key from the authentication code
    if (identifier.storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        if (!m_encryptedStoragePlugins.contains(identifier.storagePluginName())) {
            // TODO: stale data in the database?
            return Result(Result::InvalidExtensionPluginError,
                          QStringLiteral("Unknown collection encrypted storage plugin: %1")
                          .arg(identifier.storagePluginName()));
        }
    } else if (!m_encryptionPlugins.contains(collectionMetadata.encryptionPluginName)) {
        // TODO: stale data in the database?
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown collection encryption plugin: %1")
                      .arg(collectionMetadata.encryptionPluginName));
    }

    QFutureWatcher<DerivedKeyResult> *watcher
            = new QFutureWatcher<DerivedKeyResult>(this);
    QFuture<DerivedKeyResult> future;
    if (identifier.storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    authenticationCode,
                    m_requestQueue->saltData());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptionPluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptionPlugins[collectionMetadata.encryptionPluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DerivedKeyResult>::finished, [=] {
        watcher->deleteLater();
        DerivedKeyResult dkr = watcher->future().result();
        if (dkr.result.code() != Result::Succeeded) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(dkr.result);
            m_requestQueue->requestFinished(requestId, outParams);
        } else {
            getCollectionSecretWithEncryptionKey(
                        callerPid, requestId, identifier,
                        userInteractionMode, interactionServiceAddress,
                        collectionMetadata, dkr.key);
        }
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::getCollectionSecretWithEncryptionKey(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &encryptionKey)
{
    // might be required in future for access control requests.
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);
    Q_UNUSED(userInteractionMode);
    Q_UNUSED(interactionServiceAddress);

    QFutureWatcher<SecretResult> *watcher
            = new QFutureWatcher<SecretResult>(this);
    QFuture<SecretResult> future;
    if (identifier.storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                m_requestQueue->secretsThreadPool().data(),
                EncryptedStoragePluginFunctionWrapper::unlockCollectionAndReadSecret,
                m_encryptedStoragePlugins[identifier.storagePluginName()],
                collectionMetadata,
                identifier,
                encryptionKey);
    } else {
        bool requiresRelock =
                ((!collectionMetadata.usesDeviceLockKey
                  && collectionMetadata.unlockSemantic != SecretManager::CustomLockKeepUnlocked)
                || (collectionMetadata.usesDeviceLockKey
                  && collectionMetadata.unlockSemantic != SecretManager::DeviceLockKeepUnlocked));
        const QString hashedCollectionName = calculateSecretNameHash(
                    Secret::Identifier(QString(), identifier.collectionName(), identifier.storagePluginName()));
        if (!m_collectionEncryptionKeys.contains(hashedCollectionName) && !requiresRelock) {
            // TODO: some way to "test" the encryptionKey!  also, if it's a custom lock, set the timeout, etc.
            m_collectionEncryptionKeys.insert(hashedCollectionName, encryptionKey);
        }

        future = QtConcurrent::run(
                m_requestQueue->secretsThreadPool().data(),
                StoragePluginFunctionWrapper::getAndDecryptSecret,
                m_encryptionPlugins[collectionMetadata.encryptionPluginName],
                m_storagePlugins[identifier.storagePluginName()],
                identifier,
                encryptionKey);
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<SecretResult>::finished, [=] {
        watcher->deleteLater();
        SecretResult sr = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(sr.result);
        outParams << QVariant::fromValue<Secret>(sr.secret);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

// get a standalone secret
Result
Daemon::ApiImpl::RequestProcessor::getStandaloneSecret(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        Secret *secret)
{
    Q_UNUSED(secret); // asynchronous out param.
    if (identifier.name().isEmpty()) {
        return Result(Result::InvalidSecretError,
                      QLatin1String("Empty secret name given"));
    } else if (!identifier.collectionName().isEmpty()) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Non-empty collection given for standalone secret request"));
    } else if (identifier.storagePluginName().isEmpty()) {
        return Result(Result::InvalidExtensionPluginError,
                      QLatin1String("Empty storage plugin name given"));
    } else if (!m_encryptedStoragePlugins.contains(identifier.storagePluginName())
               && !m_storagePlugins.contains(identifier.storagePluginName())) {
        return Result(Result::InvalidExtensionPluginError,
                      QLatin1String("Unknown storage plugin name given"));
    }

    // Read the metadata about the target secret
    QFutureWatcher<SecretMetadataResult> *watcher
            = new QFutureWatcher<SecretMetadataResult>(this);
    QFuture<SecretMetadataResult> future;
    if (m_encryptedStoragePlugins.contains(identifier.storagePluginName())) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::secretMetadata,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    QStringLiteral("standalone"),
                    identifier.name());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::secretMetadata,
                    m_storagePlugins[identifier.storagePluginName()],
                    QStringLiteral("standalone"),
                    identifier.name());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<SecretMetadataResult>::finished, [=] {
        watcher->deleteLater();
        SecretMetadataResult smr = watcher->future().result();
        Result result = smr.result.code() != Result::Succeeded
                ? smr.result
                : getStandaloneSecretWithMetadata(
                      callerPid,
                      requestId,
                      identifier,
                      userInteractionMode,
                      interactionServiceAddress,
                      smr.metadata);
        if (result.code() != Result::Pending) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::getStandaloneSecretWithMetadata(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const SecretMetadata &secretMetadata)
{
    // TODO: perform access control request to see if the application has permission to write secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    const QString authPluginName = determineAuthPlugin(
                secretMetadata.ownerApplicationId,
                callerApplicationId,
                applicationIsPlatformApplication,
                secretMetadata.authenticationPluginName,
                interactionServiceAddress,
                m_autotestMode);

    const QString hashedSecretName = calculateSecretNameHash(
                Secret::Identifier(identifier.name(),
                                   QStringLiteral("standalone"),
                                   identifier.storagePluginName()));
    if (m_standaloneSecretEncryptionKeys.contains(hashedSecretName)) {
        getStandaloneSecretWithEncryptionKey(
                    callerPid,
                    requestId,
                    identifier,
                    userInteractionMode,
                    interactionServiceAddress,
                    secretMetadata,
                    m_standaloneSecretEncryptionKeys.value(hashedSecretName));
        return Result(Result::Pending);
    }

    if (secretMetadata.usesDeviceLockKey) {
        // TODO: if the user interaction mode allows, perform a VerifyUser auth flow
        //       if that succeeds, unlock the collection with the device lock key and continue.
        return Result(Result::CollectionIsLockedError,
                      QString::fromLatin1("Secret %1 is locked and requires device lock authentication")
                      .arg(identifier.name()));
    } else if (userInteractionMode == SecretManager::PreventInteraction) {
        return Result(Result::OperationRequiresUserInteraction,
                      QString::fromLatin1("Authentication plugin %1 requires user interaction")
                      .arg(authPluginName));
    } else if (!m_authenticationPlugins.contains(authPluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown secret authentication plugin %2")
                      .arg(authPluginName));
    }

    // perform the user input flow required to get the input key data
    // (authentication code) which will be used to decrypt the secret.
    InteractionParameters promptParams;
    promptParams.setApplicationId(callerApplicationId);
    promptParams.setPluginName(identifier.storagePluginName());
    promptParams.setCollectionName(QString());
    promptParams.setSecretName(identifier.name());
    promptParams.setOperation(InteractionParameters::ReadSecret);
    promptParams.setInputType(InteractionParameters::AlphaNumericInput);
    promptParams.setEchoMode(InteractionParameters::PasswordEcho);
    promptParams.setPromptText({
        //: This will be displayed to the user, prompting them to enter the passphrase to unlock the standalone secret in order to retrieve it. %1 is the application name, %2 is the standalone secret name, %3 is the plugin name.
        //% "App %1 wants to retrieve standalone secret %2 from plugin %3."
        { InteractionParameters::Message, qtTrId("sailfish_secrets-get_standalone_secret-la-message")
                    .arg(callerApplicationId,
                            identifier.name(),
                            identifier.collectionName(),
                            m_requestQueue->controller()->displayNameForPlugin(identifier.storagePluginName())) },
        //% "Enter the passphrase to unlock the secret."
        { InteractionParameters::Instruction, qtTrId("sailfish_secrets-get_standalone_secret-la-enter_secret_passphrase") }
    });
    Result interactionResult = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                callerPid,
                requestId,
                promptParams,
                interactionServiceAddress);
    if (interactionResult.code() == Result::Failed) {
        return interactionResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::GetStandaloneSecretRequest,
                                 QVariantList() << QVariant::fromValue<Secret::Identifier>(identifier)
                                                << userInteractionMode
                                                << interactionServiceAddress
                                                << QVariant::fromValue<SecretMetadata>(secretMetadata)));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::getStandaloneSecretWithAuthenticationCode(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const SecretMetadata &secretMetadata,
        const QByteArray &authenticationCode)
{
    // generate the encryption key from the authentication code
    if (identifier.storagePluginName() == secretMetadata.encryptionPluginName
            || secretMetadata.encryptionPluginName.isEmpty()) {
        if (!m_encryptedStoragePlugins.contains(identifier.storagePluginName())) {
            // TODO: stale data in the database?
            return Result(Result::InvalidExtensionPluginError,
                          QStringLiteral("Unknown collection encrypted storage plugin: %1")
                          .arg(identifier.storagePluginName()));
        }
    } else if (!m_encryptionPlugins.contains(secretMetadata.encryptionPluginName)) {
        // TODO: stale data in the database?
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown collection encryption plugin: %1")
                      .arg(secretMetadata.encryptionPluginName));
    }

    QFutureWatcher<DerivedKeyResult> *watcher
            = new QFutureWatcher<DerivedKeyResult>(this);
    QFuture<DerivedKeyResult> future;
    if (identifier.storagePluginName() == secretMetadata.encryptionPluginName
            || secretMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    authenticationCode,
                    m_requestQueue->saltData());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptionPluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptionPlugins[secretMetadata.encryptionPluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DerivedKeyResult>::finished, [=] {
        watcher->deleteLater();
        DerivedKeyResult dkr = watcher->future().result();
        if (dkr.result.code() != Result::Succeeded) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(dkr.result);
            m_requestQueue->requestFinished(requestId, outParams);
        } else {
            getStandaloneSecretWithEncryptionKey(
                            callerPid, requestId, identifier,
                            userInteractionMode, interactionServiceAddress,
                            secretMetadata, dkr.key);
        }
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::getStandaloneSecretWithEncryptionKey(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const SecretMetadata &secretMetadata,
        const QByteArray &encryptionKey)
{
    // may be needed for access control requests in the future.
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);
    Q_UNUSED(userInteractionMode);
    Q_UNUSED(interactionServiceAddress);

    if (identifier.storagePluginName() == secretMetadata.encryptionPluginName
            || secretMetadata.encryptionPluginName.isEmpty()) {
        QFutureWatcher<SecretDataResult> *watcher
                = new QFutureWatcher<SecretDataResult>(this);
        QFuture<SecretDataResult> future
                = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::accessStandaloneSecret,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    identifier.name(),
                    encryptionKey);
        watcher->setFuture(future);
        connect(watcher, &QFutureWatcher<SecretDataResult>::finished, [=] {
            watcher->deleteLater();
            SecretDataResult sdr = watcher->future().result();
            Secret outputSecret(identifier.name(), QStringLiteral("standalone"), identifier.storagePluginName());
            outputSecret.setData(sdr.secretData);
            outputSecret.setFilterData(sdr.secretFilterData);
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(sdr.result);
            outParams << QVariant::fromValue<Secret>(outputSecret);
            m_requestQueue->requestFinished(requestId, outParams);
        });
    } else {
        const QString hashedSecretName = calculateSecretNameHash(
                    Secret::Identifier(identifier.name(), QStringLiteral("standalone"), identifier.storagePluginName()));
        if (!m_standaloneSecretEncryptionKeys.contains(hashedSecretName)) {
            m_standaloneSecretEncryptionKeys.insert(hashedSecretName, encryptionKey);
        }

        QFutureWatcher<SecretResult> *watcher
                = new QFutureWatcher<SecretResult>(this);
        QFuture<SecretResult>
        future = QtConcurrent::run(
                m_requestQueue->secretsThreadPool().data(),
                StoragePluginFunctionWrapper::getAndDecryptSecret,
                m_encryptionPlugins[secretMetadata.encryptionPluginName],
                m_storagePlugins[identifier.storagePluginName()],
                Secret::Identifier(identifier.name(), QStringLiteral("standalone"), identifier.storagePluginName()),
                m_standaloneSecretEncryptionKeys.value(hashedSecretName));

        watcher->setFuture(future);
        connect(watcher, &QFutureWatcher<SecretResult>::finished, [=] {
            watcher->deleteLater();
            SecretResult sr = watcher->future().result();
            sr.secret.setCollectionName(QString());
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(sr.result);
            outParams << QVariant::fromValue<Secret>(sr.secret);
            m_requestQueue->requestFinished(requestId, outParams);
        });
    }
}

// find collection secrets via filter
Result
Daemon::ApiImpl::RequestProcessor::findCollectionSecrets(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        const Secret::FilterData &filter,
        SecretManager::FilterOperator filterOperator,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        QVector<Secret::Identifier> *identifiers)
{
    Q_UNUSED(identifiers); // asynchronous out-param.
    if (storagePluginName.isEmpty()) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Empty storage plugin name given"));
    } else if (!m_encryptedStoragePlugins.contains(storagePluginName)
               && !m_storagePlugins.contains(storagePluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown storage plugin name given"));
    } else if (collectionName.isEmpty()) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Empty collection name given"));
    } else if (collectionName.compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Reserved collection name given"));
    } else if (filter.isEmpty()) {
        return Result(Result::InvalidFilterError,
                      QLatin1String("Empty filter given"));
    }

    // Read the metadata about the target collection
    QFutureWatcher<CollectionMetadataResult> *watcher
            = new QFutureWatcher<CollectionMetadataResult>(this);
    QFuture<CollectionMetadataResult> future;
    if (m_encryptedStoragePlugins.contains(storagePluginName)) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::collectionMetadata,
                    m_encryptedStoragePlugins[storagePluginName],
                    collectionName);
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::collectionMetadata,
                    m_storagePlugins[storagePluginName],
                    collectionName);
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<CollectionMetadataResult>::finished, [=] {
        watcher->deleteLater();
        CollectionMetadataResult cmr = watcher->future().result();
        Result result = cmr.result.code() != Result::Succeeded
                ? cmr.result
                : findCollectionSecretsWithMetadata(
                      callerPid,
                      requestId,
                      collectionName,
                      storagePluginName,
                      filter,
                      filterOperator,
                      userInteractionMode,
                      interactionServiceAddress,
                      cmr.metadata);
        if (result.code() != Result::Pending) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::findCollectionSecretsWithMetadata(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        const Secret::FilterData &filter,
        SecretManager::FilterOperator filterOperator,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata)
{
    // TODO: perform access control request to see if the application has permission to read secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    const QString authPluginName = determineAuthPlugin(
                collectionMetadata.ownerApplicationId,
                callerApplicationId,
                applicationIsPlatformApplication,
                collectionMetadata.authenticationPluginName,
                interactionServiceAddress,
                m_autotestMode);

    if (collectionMetadata.accessControlMode == SecretManager::SystemAccessControlMode) {
        // TODO: perform access control request, to ask for permission to set the secret in the collection.
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("Access control requests are not currently supported. TODO!"));
    } else if (collectionMetadata.accessControlMode == SecretManager::OwnerOnlyMode
               && collectionMetadata.ownerApplicationId != callerApplicationId) {
        return Result(Result::PermissionsError,
                      QString::fromLatin1("Collection %1 is owned by a different application")
                      .arg(collectionName));
    } else if (!m_authenticationPlugins.contains(authPluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such authentication plugin available: %1")
                      .arg(authPluginName));
    }

    if (storagePluginName == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        // TODO: make this asynchronous instead of blocking the main thread!
        QFuture<LockedResult> future
                = QtConcurrent::run(
                        m_requestQueue->secretsThreadPool().data(),
                        EncryptedStoragePluginFunctionWrapper::isCollectionLocked,
                        m_encryptedStoragePlugins[storagePluginName],
                        collectionName);
        future.waitForFinished();
        LockedResult lr = future.result();
        Result pluginResult = lr.result;
        bool locked = lr.locked;
        if (pluginResult.code() != Result::Succeeded) {
            return pluginResult;
        }

        if (locked) {
            if (collectionMetadata.usesDeviceLockKey) {
                // TODO: if user interaction mode allows, perform a VerifyUser auth request
                //       if that succeeds, unlock the collection with the device lock key and continue.
                return Result(Result::CollectionIsLockedError,
                              QString::fromLatin1("Collection %1 is locked and requires device lock authentication").arg(collectionName));
            } else {
                if (userInteractionMode == SecretManager::PreventInteraction) {
                    return Result(Result::OperationRequiresUserInteraction,
                                  QString::fromLatin1("Authentication plugin %1 requires user interaction")
                                  .arg(authPluginName));
                } else if (!m_authenticationPlugins.contains(authPluginName)) {
                    // TODO: stale data in metadata db?
                    return Result(Result::InvalidExtensionPluginError,
                                  QStringLiteral("Unknown authentication plugin for collection %1 in plugin %2")
                                  . arg(collectionName, storagePluginName));
                } else if (m_authenticationPlugins[authPluginName]->authenticationTypes() & AuthenticationPlugin::ApplicationSpecificAuthentication
                            && (userInteractionMode != SecretManager::ApplicationInteraction || interactionServiceAddress.isEmpty())) {
                    return Result(Result::OperationRequiresApplicationUserInteraction,
                                  QString::fromLatin1("Authentication plugin %1 requires in-process user interaction")
                                  .arg(authPluginName));
                }

                // perform the user input flow required to get the input key data which will be used
                // to unlock the collection.
                InteractionParameters promptParams;
                promptParams.setApplicationId(callerApplicationId);
                promptParams.setPluginName(storagePluginName);
                promptParams.setCollectionName(collectionName);
                promptParams.setSecretName(QString());
                promptParams.setOperation(InteractionParameters::UnlockCollection);
                promptParams.setInputType(InteractionParameters::AlphaNumericInput);
                promptParams.setEchoMode(InteractionParameters::PasswordEcho);
                promptParams.setPromptText({
                        //: This will be displayed to the user, prompting them to enter the passphrase to unlock the collection in order to filter secrets within it. %1 is the application name, %2 is the collection name, %3 is the plugin name.
                        //% "App %1 wants to search for secrets within collection %2 from plugin %3."
                        { InteractionParameters::Message, qtTrId("sailfish_secrets-find_collection_secrets-la-app_search")
                                         .arg(callerApplicationId,
                                              collectionName,
                                              m_requestQueue->controller()->displayNameForPlugin(storagePluginName)) },
                        //% "Enter the passphrase to unlock the collection."
                        { InteractionParameters::Instruction, qtTrId("sailfish_secrets-find_collection_secrets-la-enter_collection_passphrase") }
                });
                Result interactionResult = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                            callerPid,
                            requestId,
                            promptParams,
                            interactionServiceAddress);
                if (interactionResult.code() == Result::Failed) {
                    return interactionResult;
                }

                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::FindCollectionSecretsRequest,
                                             QVariantList() << collectionName
                                                            << storagePluginName
                                                            << QVariant::fromValue<Secret::FilterData >(filter)
                                                            << filterOperator
                                                            << userInteractionMode
                                                            << interactionServiceAddress
                                                            << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
                return Result(Result::Pending);
            }
        } else {
            findCollectionSecretsWithEncryptionKey(
                        callerPid,
                        requestId,
                        collectionName,
                        storagePluginName,
                        filter,
                        filterOperator,
                        userInteractionMode,
                        interactionServiceAddress,
                        collectionMetadata,
                        QByteArray()); // no key required, it's unlocked already.
            return Result(Result::Pending);
        }
    } else {
        const QString hashedCollectionName = calculateSecretNameHash(
                    Secret::Identifier(QString(), collectionName, storagePluginName));
        if (!m_collectionEncryptionKeys.contains(hashedCollectionName)) {
            if (collectionMetadata.usesDeviceLockKey) {
                // TODO: if the user interaction mode allows, perform a VerifyUser auth request
                //       if that succeeds, unlock the collection with the device lock key and continue.
                return Result(Result::CollectionIsLockedError,
                              QString::fromLatin1("Collection %1 is locked and requires device lock authentication")
                              .arg(collectionName));
            } else {
                if (userInteractionMode == SecretManager::PreventInteraction) {
                    return Result(Result::OperationRequiresUserInteraction,
                                  QString::fromLatin1("Authentication plugin %1 requires user interaction")
                                  .arg(authPluginName));
                } else if (!m_authenticationPlugins.contains(authPluginName)) {
                    // TODO: stale data in metadata db?
                    return Result(Result::InvalidExtensionPluginError,
                                  QString::fromLatin1("Unknown authentication plugin %1 specified in collection metadata")
                                  .arg(authPluginName));
                } else if (m_authenticationPlugins[authPluginName]->authenticationTypes() & AuthenticationPlugin::ApplicationSpecificAuthentication
                           && (userInteractionMode != SecretManager::ApplicationInteraction || interactionServiceAddress.isEmpty())) {
                    return Result(Result::OperationRequiresApplicationUserInteraction,
                                  QString::fromLatin1("Authentication plugin %1 requires in-process user interaction")
                                  .arg(authPluginName));
                }

                // perform the user input flow required to get the input key data which will be used
                // to decrypt the secret.
                InteractionParameters promptParams;
                promptParams.setApplicationId(callerApplicationId);
                promptParams.setPluginName(storagePluginName);
                promptParams.setCollectionName(collectionName);
                promptParams.setSecretName(QString());
                promptParams.setOperation(InteractionParameters::UnlockCollection);
                promptParams.setInputType(InteractionParameters::AlphaNumericInput);
                promptParams.setEchoMode(InteractionParameters::PasswordEcho);
                promptParams.setPromptText({
                        //: This will be displayed to the user, prompting them to enter the passphrase to unlock the collection in order to filter secrets within it. %1 is the application name, %2 is the collection name, %3 is the plugin name.
                        //% "App %1 wants to search for secrets within collection %2 from plugin %3."
                        { InteractionParameters::Message, qtTrId("sailfish_secrets-find_collection_secrets-la-app_search")
                                         .arg(callerApplicationId,
                                              collectionName,
                                              m_requestQueue->controller()->displayNameForPlugin(storagePluginName)) },
                        //% "Enter the passphrase to unlock the collection."
                        { InteractionParameters::Instruction, qtTrId("sailfish_secrets-find_collection_secrets-la-enter_collection_passphrase") }
                });
                Result interactionResult = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                            callerPid,
                            requestId,
                            promptParams,
                            interactionServiceAddress);
                if (interactionResult.code() == Result::Failed) {
                    return interactionResult;
                }

                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::FindCollectionSecretsRequest,
                                             QVariantList() << collectionName
                                                            << storagePluginName
                                                            << QVariant::fromValue<Secret::FilterData >(filter)
                                                            << filterOperator
                                                            << userInteractionMode
                                                            << interactionServiceAddress
                                                            << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
                return Result(Result::Pending);
            }
        } else {
            findCollectionSecretsWithEncryptionKey(
                        callerPid,
                        requestId,
                        collectionName,
                        storagePluginName,
                        filter,
                        filterOperator,
                        userInteractionMode,
                        interactionServiceAddress,
                        collectionMetadata,
                        m_collectionEncryptionKeys.value(hashedCollectionName));
            return Result(Result::Pending);
        }
    }
}

Result
Daemon::ApiImpl::RequestProcessor::findCollectionSecretsWithAuthenticationCode(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        const Secret::FilterData &filter,
        SecretManager::FilterOperator filterOperator,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &authenticationCode)
{
    // generate the encryption key from the authentication code
    if (!collectionMetadata.encryptionPluginName.isEmpty()
            && storagePluginName != collectionMetadata.encryptionPluginName
            && !m_encryptionPlugins.contains(collectionMetadata.encryptionPluginName)) {
        // TODO: stale data in the database?
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown collection encryption plugin: %1")
                      .arg(collectionMetadata.encryptionPluginName));
    }

    QFutureWatcher<DerivedKeyResult> *watcher
            = new QFutureWatcher<DerivedKeyResult>(this);
    QFuture<DerivedKeyResult> future;
    if (storagePluginName == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptedStoragePlugins[storagePluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptionPluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptionPlugins[collectionMetadata.encryptionPluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DerivedKeyResult>::finished, [=] {
        watcher->deleteLater();
        DerivedKeyResult dkr = watcher->future().result();
        if (dkr.result.code() != Result::Succeeded) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(dkr.result);
            m_requestQueue->requestFinished(requestId, outParams);
        } else {
            findCollectionSecretsWithEncryptionKey(
                        callerPid, requestId,
                        collectionName, storagePluginName,
                        filter, filterOperator,
                        userInteractionMode, interactionServiceAddress,
                        collectionMetadata, dkr.key);
        }
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::findCollectionSecretsWithEncryptionKey(
        pid_t callerPid,
        quint64 requestId,
        const QString &collectionName,
        const QString &storagePluginName,
        const Secret::FilterData &filter,
        SecretManager::FilterOperator filterOperator,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &encryptionKey)
{
    // might be required in future for access control requests.
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);
    Q_UNUSED(userInteractionMode);
    Q_UNUSED(interactionServiceAddress);

    QFutureWatcher<IdentifiersResult> *watcher
            = new QFutureWatcher<IdentifiersResult>(this);
    QFuture<IdentifiersResult> future;
    if (storagePluginName == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::unlockAndFindSecrets,
                    m_encryptedStoragePlugins[storagePluginName],
                    collectionMetadata,
                    filter,
                    static_cast<StoragePlugin::FilterOperator>(filterOperator),
                    encryptionKey);
    } else {
        bool requiresRelock =
                ((!collectionMetadata.usesDeviceLockKey
                  && collectionMetadata.unlockSemantic != SecretManager::CustomLockKeepUnlocked)
                || (collectionMetadata.usesDeviceLockKey
                  && collectionMetadata.unlockSemantic != SecretManager::DeviceLockKeepUnlocked));
        const QString hashedCollectionName = calculateSecretNameHash(Secret::Identifier(QString(), collectionName, storagePluginName));
        if (!m_collectionEncryptionKeys.contains(hashedCollectionName) && !requiresRelock) {
            // TODO: some way to "test" the encryptionKey!  also, if it's a custom lock, set the timeout, etc.
            m_collectionEncryptionKeys.insert(hashedCollectionName, encryptionKey);
        }

        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::findSecrets,
                    m_storagePlugins[storagePluginName],
                    collectionName,
                    filter,
                    static_cast<StoragePlugin::FilterOperator>(filterOperator));
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<IdentifiersResult>::finished, [=] {
        watcher->deleteLater();
        IdentifiersResult ir = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(ir.result);
        outParams << QVariant::fromValue<QVector<Secret::Identifier> >(ir.identifiers);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

// find standalone secrets via filter
Result
Daemon::ApiImpl::RequestProcessor::findStandaloneSecrets(
        pid_t callerPid,
        quint64 requestId,
        const QString &storagePluginName,
        const Secret::FilterData &filter,
        SecretManager::FilterOperator filterOperator,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        QVector<Secret::Identifier> *identifiers)
{
    // TODO!
    Q_UNUSED(callerPid)
    Q_UNUSED(requestId)
    Q_UNUSED(storagePluginName)
    Q_UNUSED(filter)
    Q_UNUSED(filterOperator)
    Q_UNUSED(userInteractionMode)
    Q_UNUSED(interactionServiceAddress)
    Q_UNUSED(identifiers)
    return Result(Result::OperationNotSupportedError,
                  QLatin1String("Filtering standalone secrets is not yet supported!"));
}

// delete a secret in a collection
Result
Daemon::ApiImpl::RequestProcessor::deleteCollectionSecret(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress)
{
    if (identifier.name().isEmpty()) {
        return Result(Result::InvalidSecretError,
                      QLatin1String("Empty secret name given"));
    } else if (identifier.collectionName().isEmpty()) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Empty collection name given"));
    } else if (identifier.collectionName().compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Reserved collection name given"));
    } else if (identifier.storagePluginName().isEmpty()) {
        return Result(Result::InvalidExtensionPluginError,
                      QLatin1String("Empty storage plugin name given"));
    } else if (!m_encryptedStoragePlugins.contains(identifier.storagePluginName())
               && !m_storagePlugins.contains(identifier.storagePluginName())) {
        return Result(Result::InvalidExtensionPluginError,
                      QLatin1String("Unknown storage plugin name given"));
    }

    // Read the metadata about the target collection
    QFutureWatcher<CollectionMetadataResult> *watcher
            = new QFutureWatcher<CollectionMetadataResult>(this);
    QFuture<CollectionMetadataResult> future;
    if (m_encryptedStoragePlugins.contains(identifier.storagePluginName())) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::collectionMetadata,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    identifier.collectionName());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::collectionMetadata,
                    m_storagePlugins[identifier.storagePluginName()],
                    identifier.collectionName());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<CollectionMetadataResult>::finished, [=] {
        watcher->deleteLater();
        CollectionMetadataResult cmr = watcher->future().result();
        Result result = cmr.result.code() != Result::Succeeded
                ? cmr.result
                : deleteCollectionSecretWithMetadata(
                      callerPid,
                      requestId,
                      identifier,
                      userInteractionMode,
                      interactionServiceAddress,
                      cmr.metadata);
        if (result.code() != Result::Pending) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::deleteCollectionSecretWithMetadata(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata)
{
    // TODO: perform access control request to see if the application has permission to write secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    const QString authPluginName = determineAuthPlugin(
                collectionMetadata.ownerApplicationId,
                callerApplicationId,
                applicationIsPlatformApplication,
                collectionMetadata.authenticationPluginName,
                interactionServiceAddress,
                m_autotestMode);

    if (collectionMetadata.accessControlMode == SecretManager::SystemAccessControlMode) {
        // TODO: perform access control request, to ask for permission to set the secret in the collection.
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("Access control requests are not currently supported. TODO!"));
    } else if (collectionMetadata.accessControlMode == SecretManager::OwnerOnlyMode
               && collectionMetadata.ownerApplicationId != callerApplicationId) {
        return Result(Result::PermissionsError,
                      QString::fromLatin1("Collection %1 is owned by a different application")
                      .arg(identifier.collectionName()));
    } else if (!collectionMetadata.encryptionPluginName.isEmpty()
               && identifier.storagePluginName() != collectionMetadata.encryptionPluginName
               && !m_encryptionPlugins.contains(collectionMetadata.encryptionPluginName)) {
        // TODO: this means we have "stale" data in the database; what should we do in this case?
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such encryption plugin exists: %1")
                      .arg(collectionMetadata.encryptionPluginName));
    }

    if (identifier.storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        // TODO: make this asynchronous instead of blocking the main thread!
        QFuture<LockedResult> future
                = QtConcurrent::run(
                        m_requestQueue->secretsThreadPool().data(),
                        EncryptedStoragePluginFunctionWrapper::isCollectionLocked,
                        m_encryptedStoragePlugins[identifier.storagePluginName()],
                        identifier.collectionName());
        future.waitForFinished();
        LockedResult lr = future.result();
        Result pluginResult = lr.result;
        bool locked = lr.locked;
        if (pluginResult.code() != Result::Succeeded) {
            return pluginResult;
        }
        if (locked) {
            if (collectionMetadata.usesDeviceLockKey) {
                // TODO: if user interaction mode allows, perform a VerifyUser authentication flow
                //       if that succeeds, unlock the collection with the device lock key and continue
                return Result(Result::CollectionIsLockedError,
                              QString::fromLatin1("Collection %1 is locked and requires device lock authentication")
                              .arg(identifier.collectionName()));
            } else if (!m_authenticationPlugins.contains(authPluginName)) {
                // TODO: stale data in metadata db?
                return Result(Result::InvalidExtensionPluginError,
                              QStringLiteral("Unknown collection authentication plugin"));
            } else if (userInteractionMode == SecretManager::PreventInteraction) {
                return Result(Result::OperationRequiresUserInteraction,
                              QString::fromLatin1("Authentication plugin %1 requires user interaction")
                              .arg(authPluginName));
            }

            // perform the user input flow required to get the input key data which will be used
            // to unlock the collection in order to delete the secret.
            InteractionParameters promptParams;
            promptParams.setApplicationId(callerApplicationId);
            promptParams.setPluginName(identifier.storagePluginName());
            promptParams.setCollectionName(identifier.collectionName());
            promptParams.setSecretName(identifier.name());
            promptParams.setOperation(InteractionParameters::DeleteSecret);
            promptParams.setInputType(InteractionParameters::AlphaNumericInput);
            promptParams.setEchoMode(InteractionParameters::PasswordEcho);
            promptParams.setPromptText({
                //: This will be displayed to the user, prompting them to enter the passphrase to unlock the collection in order to delete a secret within it. %1 is the application name, %2 is the secret name, %3 is the collection name, %4 is the plugin name.
                //% "App %1 wants to delete secret %2 within collection %3 in plugin %4."
                { InteractionParameters::Message, qtTrId("sailfish_secrets-delete_collection_secret-la-message")
                            .arg(callerApplicationId,
                                    identifier.name(),
                                    identifier.collectionName(),
                                    m_requestQueue->controller()->displayNameForPlugin(identifier.storagePluginName())) },
                //% "Enter the passphrase to unlock the collection."
                { InteractionParameters::Instruction, qtTrId("sailfish_secrets-delete_collection_secret-la-enter_collection_passphrase") }
            });
            Result interactionResult = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                        callerPid,
                        requestId,
                        promptParams,
                        interactionServiceAddress);
            if (interactionResult.code() == Result::Failed) {
                return interactionResult;
            }

            m_pendingRequests.insert(requestId,
                                     Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                         callerPid,
                                         requestId,
                                         Daemon::ApiImpl::DeleteCollectionSecretRequest,
                                         QVariantList() << QVariant::fromValue<Secret::Identifier>(identifier)
                                                        << userInteractionMode
                                                        << interactionServiceAddress
                                                        << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
        } else {
            deleteCollectionSecretWithEncryptionKey(
                        callerPid,
                        requestId,
                        identifier,
                        userInteractionMode,
                        interactionServiceAddress,
                        collectionMetadata,
                        m_requestQueue->deviceLockKey());
        }
    } else {
        const QString hashedCollectionName = calculateSecretNameHash(
                    Secret::Identifier(QString(), identifier.collectionName(), identifier.storagePluginName()));
        if (!m_collectionEncryptionKeys.contains(hashedCollectionName)) {
            if (collectionMetadata.usesDeviceLockKey) {
                // TODO: if user interaction mode allows, perform VerifyUser authentication flow
                //       if that succeeds, unlock the collection with the device lock key and continue.
                return Result(Result::CollectionIsLockedError,
                              QStringLiteral("Collection %1 is locked and requires device lock authentication")
                              .arg(identifier.collectionName()));
            } else {
                if (userInteractionMode == SecretManager::PreventInteraction) {
                    return Result(Result::OperationRequiresUserInteraction,
                                  QString::fromLatin1("Authentication plugin %1 requires user interaction")
                                  .arg(authPluginName));
                } else if (!m_authenticationPlugins.contains(authPluginName)) {
                    // TODO: stale metadata db data?
                    return Result(Result::InvalidExtensionPluginError,
                                  QStringLiteral("Unknown collection authentication plugin"));
                }

                // perform the user input flow required to get the input key data which will be used
                // to unlock the secret for deletion.
                InteractionParameters promptParams;
                promptParams.setApplicationId(callerApplicationId);
                promptParams.setPluginName(identifier.storagePluginName());
                promptParams.setCollectionName(identifier.collectionName());
                promptParams.setSecretName(identifier.name());
                promptParams.setOperation(InteractionParameters::DeleteSecret);
                promptParams.setInputType(InteractionParameters::AlphaNumericInput);
                promptParams.setEchoMode(InteractionParameters::PasswordEcho);
                promptParams.setPromptText({
                    //: This will be displayed to the user, prompting them to enter the passphrase to unlock the collection in order to delete a secret within it. %1 is the application name, %2 is the secret name, %3 is the collection name, %4 is the plugin name.
                    //% "App %1 wants to delete secret %2 within collection %3 in plugin %4."
                    { InteractionParameters::Message, qtTrId("sailfish_secrets-delete_collection_secret-la-message")
                                .arg(callerApplicationId,
                                        identifier.name(),
                                        identifier.collectionName(),
                                        m_requestQueue->controller()->displayNameForPlugin(identifier.storagePluginName())) },
                    //% "Enter the passphrase to unlock the collection."
                    { InteractionParameters::Instruction, qtTrId("sailfish_secrets-delete_collection_secret-la-enter_collection_passphrase") }
                });
                Result interactionResult = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                            callerPid,
                            requestId,
                            promptParams,
                            interactionServiceAddress);
                if (interactionResult.code() == Result::Failed) {
                    return interactionResult;
                }

                m_pendingRequests.insert(requestId,
                                         Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                             callerPid,
                                             requestId,
                                             Daemon::ApiImpl::DeleteCollectionSecretRequest,
                                             QVariantList() << QVariant::fromValue<Secret::Identifier>(identifier)
                                                            << userInteractionMode
                                                            << interactionServiceAddress
                                                            << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
            }
        } else {
            deleteCollectionSecretWithEncryptionKey(
                        callerPid,
                        requestId,
                        identifier,
                        userInteractionMode,
                        interactionServiceAddress,
                        collectionMetadata,
                        m_collectionEncryptionKeys.value(hashedCollectionName));
        }
    }

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::deleteCollectionSecretWithAuthenticationCode(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &authenticationCode)
{
    // generate the encryption key from the authentication code
    if (!collectionMetadata.encryptionPluginName.isEmpty()
            && collectionMetadata.encryptionPluginName != identifier.storagePluginName()
            && !m_encryptionPlugins.contains(collectionMetadata.encryptionPluginName)) {
        // TODO: stale data in the database?
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown collection encryption plugin: %1")
                      .arg(collectionMetadata.encryptionPluginName));
    }

    QFutureWatcher<DerivedKeyResult> *watcher
            = new QFutureWatcher<DerivedKeyResult>(this);
    QFuture<DerivedKeyResult> future;
    if (identifier.storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    authenticationCode,
                    m_requestQueue->saltData());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptionPluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptionPlugins[collectionMetadata.encryptionPluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DerivedKeyResult>::finished, [=] {
        watcher->deleteLater();
        DerivedKeyResult dkr = watcher->future().result();
        if (dkr.result.code() != Result::Succeeded) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(dkr.result);
            m_requestQueue->requestFinished(requestId, outParams);
        } else {
            deleteCollectionSecretWithEncryptionKey(
                            callerPid, requestId, identifier,
                            userInteractionMode, interactionServiceAddress,
                            collectionMetadata, dkr.key);
        }
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::deleteCollectionSecretWithEncryptionKey(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &encryptionKey)
{
    // may be needed for access control requests in the future.
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);
    Q_UNUSED(userInteractionMode);
    Q_UNUSED(interactionServiceAddress);

    QFutureWatcher<Result> *watcher = new QFutureWatcher<Result>(this);
    QFuture<Result> future;
    if (identifier.storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::unlockCollectionAndRemoveSecret,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    collectionMetadata,
                    identifier,
                    encryptionKey);
    } else {
        bool requiresRelock =
                ((!collectionMetadata.usesDeviceLockKey
                  && collectionMetadata.unlockSemantic != SecretManager::CustomLockKeepUnlocked)
                || (collectionMetadata.usesDeviceLockKey
                  && collectionMetadata.unlockSemantic != SecretManager::DeviceLockKeepUnlocked));
        const QString hashedCollectionName = calculateSecretNameHash(
                    Secret::Identifier(QString(), identifier.collectionName(), identifier.storagePluginName()));
        if (!m_collectionEncryptionKeys.contains(hashedCollectionName) && !requiresRelock) {
            // TODO: some way to "test" the encryptionKey!  also, if it's a custom lock, set the timeout, etc.
            // FIXME: in this case, if the user entered the "wrong" password, we will be caching an incorrect key...
            m_collectionEncryptionKeys.insert(hashedCollectionName, encryptionKey);
        }

        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::removeSecret,
                    m_storagePlugins[identifier.storagePluginName()],
                    identifier.collectionName(),
                    identifier.name());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<Result>::finished, [=] {
        watcher->deleteLater();
        Result pluginResult = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(pluginResult);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

// delete a standalone secret
Result
Daemon::ApiImpl::RequestProcessor::deleteStandaloneSecret(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode)
{
    // Read the metadata about the target secret
    QFutureWatcher<SecretMetadataResult> *watcher
            = new QFutureWatcher<SecretMetadataResult>(this);
    QFuture<SecretMetadataResult> future;
    if (m_encryptedStoragePlugins.contains(identifier.storagePluginName())) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::secretMetadata,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    QStringLiteral("standalone"),
                    identifier.name());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::secretMetadata,
                    m_storagePlugins[identifier.storagePluginName()],
                    QStringLiteral("standalone"),
                    identifier.name());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<SecretMetadataResult>::finished, [=] {
        watcher->deleteLater();
        SecretMetadataResult smr = watcher->future().result();
        Result result = smr.result.code() != Result::Succeeded
                ? smr.result
                : deleteStandaloneSecretWithMetadata(
                      callerPid,
                      requestId,
                      identifier,
                      userInteractionMode,
                      smr.metadata);
        if (result.code() != Result::Pending) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::deleteStandaloneSecretWithMetadata(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const SecretMetadata &secretMetadata)
{
    // TODO: perform access control request to see if the application has permission to write secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    if (secretMetadata.accessControlMode == SecretManager::SystemAccessControlMode) {
        // TODO: perform access control request, to ask for permission to set the secret in the collection.
        Q_UNUSED(userInteractionMode);
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("Access control requests are not currently supported. TODO!"));
    } else if (secretMetadata.accessControlMode == SecretManager::OwnerOnlyMode
               && secretMetadata.ownerApplicationId != callerApplicationId) {
        return Result(Result::PermissionsError,
                      QString::fromLatin1("Secret %1 from collection %2 in storage plugin %3 is owned by a different application")
                      .arg(identifier.name(), identifier.collectionName(), identifier.storagePluginName()));
    } else if (!secretMetadata.encryptionPluginName.isEmpty()
               && identifier.storagePluginName() != secretMetadata.encryptionPluginName
               && !m_encryptionPlugins.contains(secretMetadata.encryptionPluginName)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("No such encryption plugin exists: %1")
                      .arg(secretMetadata.encryptionPluginName));
    }

    QFutureWatcher<Result> *watcher = new QFutureWatcher<Result>(this);
    QFuture<Result> future;
    if (identifier.storagePluginName() == secretMetadata.encryptionPluginName
            || secretMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::removeSecret,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    identifier.collectionName(),
                    identifier.name());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::removeSecret,
                    m_storagePlugins[identifier.storagePluginName()],
                    QStringLiteral("standalone"),
                    identifier.name());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<Result>::finished, [=] {
        watcher->deleteLater();
        Result pluginResult = watcher->future().result();
        if (pluginResult.code() == Result::Succeeded) {
            if (identifier.storagePluginName() != secretMetadata.encryptionPluginName
                    && !secretMetadata.encryptionPluginName.isEmpty()) {
                const QString hashedSecretName = calculateSecretNameHash(
                            Secret::Identifier(identifier.name(), QStringLiteral("standalone"), identifier.storagePluginName()));
                m_standaloneSecretEncryptionKeys.remove(hashedSecretName);
            }
        }

        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(pluginResult);
        m_requestQueue->requestFinished(requestId, outParams);
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::modifyLockCode(
        pid_t callerPid,
        quint64 requestId,
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParams,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress)
{
    // TODO: perform access control request to see if the application has permission to modify plugin locks.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    if (lockCodeTargetType == LockCodeRequest::ExtensionPlugin) {
        // check that the application is system settings.
        // if not, some malicious app is trying to rekey the
        // plugin.
        if (!applicationIsPlatformApplication) {
            return Result(Result::PermissionsError,
                          QLatin1String("Only the system settings application can unlock the plugin"));
        }
    } else { // MetadataDatabase
        // check that the application is system settings.
        // if not, some malicious app is trying to rekey the
        // master (bookkeeping) database.
        if (!applicationIsPlatformApplication) {
            return Result(Result::PermissionsError,
                          QLatin1String("Only the system settings application can unlock the secrets database"));
        }

        // there is only one bookkeeping database, ensure that
        // the client hasn't attempted to set some other target.
        if (!lockCodeTarget.isEmpty()) {
            return Result(Result::OperationNotSupportedError,
                          QLatin1String("Invalid target name specified"));
        }
    }

    // Perform the first request "get old passphrase".
    // After it completes, perform the second request "get new passphrase"
    // Once both are complete, perform re-key operation.
    // If it was a master lock change, re-initialize crypto plugins.
    QString userInputPlugin = interactionParams.authenticationPluginName();
    if (interactionParams.authenticationPluginName().isEmpty()) {
        // TODO: depending on type, choose the appropriate authentication plugin
        userInputPlugin = SecretManager::DefaultAuthenticationPluginName;
        if (m_autotestMode) {
            userInputPlugin.append(QLatin1String(".test"));
        }
    }
    if (!m_authenticationPlugins.contains(userInputPlugin)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("Cannot get user input from invalid authentication plugin: %1")
                      .arg(interactionParams.authenticationPluginName()));
    }

    InteractionParameters modifyLockRequest(interactionParams);
    modifyLockRequest.setApplicationId(callerApplicationId);

    if (lockCodeTargetType == LockCodeRequest::ExtensionPlugin) {
        modifyLockRequest.setOperation(InteractionParameters::ModifyLockPlugin);
        modifyLockRequest.setPromptText({
            //: This will be displayed to the user, prompting them to enter the old passphrase to unlock the extension plugin in order to change its lock code. %1 is the application name, %2 is the plugin name.
            //% "App %1 wants to change the lock code for plugin %2."
            { InteractionParameters::Message, qtTrId("sailfish_secrets-modify_lock_code-la-message_old_plugin")
                        .arg(callerApplicationId) },
            //% "Enter the old passphrase to unlock the plugin."
            { InteractionParameters::Instruction, qtTrId("sailfish_secrets-modify_lock_code-la-enter_old_plugin_passphrase") }
        });
    } else {
        modifyLockRequest.setOperation(InteractionParameters::ModifyLockDatabase);
        modifyLockRequest.setPromptText({
            //: This will be displayed to the user, prompting them to enter the old passphrase to unlock the secrets service in order to change the master lock code. %1 is the application name.
            //% "App %1 wants to change the secrets service master lock code."
            { InteractionParameters::Message, qtTrId("sailfish_secrets-modify_lock_code-la-message_old_master")
                        .arg(callerApplicationId) },
            //% "Enter the old master passphrase."
            { InteractionParameters::Instruction, qtTrId("sailfish_secrets-modify_lock_code-la-enter_old_master_passphrase") }
        });
    }

    Result interactionResult = m_authenticationPlugins[userInputPlugin]->beginUserInputInteraction(
                callerPid,
                requestId,
                modifyLockRequest,
                interactionServiceAddress);
    if (interactionResult.code() == Result::Failed) {
        return interactionResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::ModifyLockCodeRequest,
                                 QVariantList() << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
                                                << QVariant::fromValue<QString>(lockCodeTarget)
                                                << QVariant::fromValue<InteractionParameters>(modifyLockRequest)
                                                << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
                                                << QVariant::fromValue<QString>(interactionServiceAddress)));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::modifyLockCodeWithLockCode(
        pid_t callerPid,
        quint64 requestId,
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParams,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QByteArray &oldLockCode)
{
    // TODO: access control, check the application is allowed to modify plugin locks.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    QString userInputPlugin = interactionParams.authenticationPluginName();
    if (interactionParams.authenticationPluginName().isEmpty()) {
        // TODO: depending on type, choose the appropriate authentication plugin
        userInputPlugin = SecretManager::DefaultAuthenticationPluginName;
        if (m_autotestMode) {
            userInputPlugin.append(QLatin1String(".test"));
        }
    }
    if (!m_authenticationPlugins.contains(userInputPlugin)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("Cannot get user input from invalid authentication plugin: %1")
                      .arg(interactionParams.authenticationPluginName()));
    }

    InteractionParameters modifyLockRequest(interactionParams);
    if (lockCodeTargetType == LockCodeRequest::ExtensionPlugin) {
        modifyLockRequest.setOperation(InteractionParameters::ModifyLockPlugin);
        modifyLockRequest.setPromptText({
            //: This will be displayed to the user, prompting them to enter the new passphrase for the plugin. %1 is the application name, %2 is the plugin name.
            //% "App %1 wants to change the lock code for plugin %2."
            { InteractionParameters::Message, qtTrId("sailfish_secrets-modify_lock_code-la-new_plugin_message")
                        .arg(callerApplicationId, m_requestQueue->controller()->displayNameForPlugin(lockCodeTarget)) },
            //% "Enter the new passphrase for the plugin."
            { InteractionParameters::NewInstruction, qtTrId("sailfish_secrets-modify_lock_code-la-enter_new_plugin_passphrase") },
            //% "Repeat the new passphrase for the plugin."
            { InteractionParameters::RepeatInstruction, qtTrId("sailfish_secrets-modify_lock_code-la-repeat_new_plugin_passphrase") }
        });
    } else {
        modifyLockRequest.setOperation(InteractionParameters::ModifyLockDatabase);
        modifyLockRequest.setPromptText({
            //: This will be displayed to the user, prompting them to enter the new master lock code for the secrets service. %1 is the application name.
            //% "App %1 wants to change the secrets service master lock code."
            { InteractionParameters::Message, qtTrId("sailfish_secrets-modify_lock_code-la-new_master_message")
                        .arg(callerApplicationId) },
            //% "Enter the new master passphrase."
            { InteractionParameters::NewInstruction, qtTrId("sailfish_secrets-modify_lock_code-la-enter_new_master_passphrase") },
            //% "Repeat the new master passphrase."
            { InteractionParameters::RepeatInstruction, qtTrId("sailfish_secrets-modify_lock_code-la-repeat_new_master_passphrase") }
        });
    }

    Result interactionResult = m_authenticationPlugins[userInputPlugin]->beginUserInputInteraction(
                callerPid,
                requestId,
                modifyLockRequest,
                interactionServiceAddress);
    if (interactionResult.code() == Result::Failed) {
        return interactionResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::ModifyLockCodeRequest,
                                 QVariantList() << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
                                                << QVariant::fromValue<QString>(lockCodeTarget)
                                                << QVariant::fromValue<InteractionParameters>(modifyLockRequest)
                                                << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
                                                << QVariant::fromValue<QString>(interactionServiceAddress)
                                                << QVariant::fromValue<QByteArray>(oldLockCode)));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::modifyLockCodeWithLockCodes(
        pid_t callerPid,
        quint64 requestId,
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParams,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QByteArray &oldLockCode,
        const QByteArray &newLockCode)
{
    // TODO: support secret/collection flows
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);
    Q_UNUSED(interactionParams);
    Q_UNUSED(userInteractionMode);
    Q_UNUSED(interactionServiceAddress);

    // see if the client is attempting to set the lock code for a plugin
    if (lockCodeTargetType == LockCodeRequest::ExtensionPlugin) {
        QFuture<FoundResult> future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    &Daemon::ApiImpl::modifyLockSpecificPlugin,
                    m_encryptionPlugins,
                    m_storagePlugins,
                    m_encryptedStoragePlugins,
                    lockCodeTarget,
                    LockCodes(oldLockCode, newLockCode));
        future.waitForFinished();
        FoundResult fr = future.result();
        if (fr.found) {
            // if the lock target was a plugin from the encryption/storage/encryptedStorage
            // maps, then return the lock result from the threaded plugin operation.
            return fr.result;
        } else if (m_authenticationPlugins.contains(lockCodeTarget)) {
            AuthenticationPlugin *p = m_authenticationPlugins.value(lockCodeTarget);
            if (!p->supportsLocking()) {
                return Result(Result::OperationNotSupportedError,
                              QStringLiteral("Authentication plugin %1 does not support locking").arg(lockCodeTarget));
            } else if (!p->setLockCode(oldLockCode, newLockCode)) {
                return Result(Result::UnknownError,
                              QStringLiteral("Failed to set the lock code for authentication plugin %1").arg(lockCodeTarget));
            }
            return Result(Result::Succeeded);
        } else {
            return m_requestQueue->setLockCodeCryptoPlugin(lockCodeTarget, oldLockCode, newLockCode);
        }
    }

    // otherwise, we are modifying the "master" lock code for the bookkeeping database.
    if (!m_requestQueue->testLockCode(oldLockCode)) {
        return Result(Result::SecretsDaemonLockedError,
                      QLatin1String("The given old lock code was incorrect"));
    }

    // pull the old bookkeeping database lock key and device lock key into memory via deep copy.
    QByteArray oldBkdbLockKey, oldDeviceLockKey;
    {
        QByteArray bkdbShallowCopy = m_requestQueue->bkdbLockKey();
        oldBkdbLockKey = QByteArray(bkdbShallowCopy.constData(), bkdbShallowCopy.size());
        QByteArray dlShallowCopy = m_requestQueue->deviceLockKey();
        oldDeviceLockKey = QByteArray(dlShallowCopy.constData(), dlShallowCopy.size());
    }

    // the old lock code was correct, initialize the new lock code.
    m_requestQueue->initialize(newLockCode, SecretsRequestQueue::ModifyLockMode);

    // re-encrypt the metadata (bookkeeping) databases for each storage plugin.
    QFuture<bool> reencryptMetadata = QtConcurrent::run(
                m_requestQueue->secretsThreadPool().data(),
                &Daemon::ApiImpl::modifyMasterLockPlugins,
                m_storagePlugins.values(),
                m_encryptedStoragePlugins.values(),
                oldBkdbLockKey,
                m_requestQueue->bkdbLockKey());
    reencryptMetadata.waitForFinished();
    if (!reencryptMetadata.result()) {
        // TODO: FIXME: how do we recover from this?  (Each plugin is modified serially, cannot be atomic...)
        qCWarning(lcSailfishSecretsDaemon) << "Critical Error! Failed to re-encrypt all metadata databases successfully!";
    }

    // Now re-encrypt all device-locked collections and secrets.
    for (EncryptedStoragePluginWrapper *plugin : m_encryptedStoragePlugins.values()) {
        // We don't allow storing device-locked standalone secrets in encryptedStoragePlugins,
        // so we just need to ensure that we re-encrypt collections here.
        QFuture<Result> future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::unlockDeviceLockedCollectionsAndReencrypt,
                    plugin,
                    oldDeviceLockKey,
                    m_requestQueue->deviceLockKey());
        future.waitForFinished();
        Result reencryptCollectionResult = future.result();
        if (reencryptCollectionResult.code() != Result::Succeeded) {
            // TODO: FIXME: how do we recover from this?
            qCWarning(lcSailfishSecretsDaemon) << "Critical Error! Failed to re-encrypt encrypted storage device-locked collections:"
                                               << plugin->name()
                                               << reencryptCollectionResult.code()
                                               << reencryptCollectionResult.errorMessage();
        }
    }
    for (StoragePluginWrapper *plugin : m_storagePlugins.values()) {
        QFuture<Result> future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::reencryptDeviceLockedCollectionsAndSecrets,
                    plugin,
                    m_encryptionPlugins,
                    oldDeviceLockKey,
                    m_requestQueue->deviceLockKey());
        future.waitForFinished();
        Result reencryptResult = future.result();
        if (reencryptResult.code() != Result::Succeeded) {
            // TODO: FIXME: how do we recover from this?
            qCWarning(lcSailfishSecretsDaemon) << "Critical Error! Failed to re-encrypt stored device-locked collections and secrets:"
                                               << plugin->name()
                                               << reencryptResult.code()
                                               << reencryptResult.errorMessage();
        }
    }

    // TODO: FIXME: handle per-plugin errors in a robust way?
    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::RequestProcessor::provideLockCode(
        pid_t callerPid,
        quint64 requestId,
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParams,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress)
{
    // TODO: perform access control request to see if the application has permission to access secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    if (lockCodeTargetType == LockCodeRequest::ExtensionPlugin) {
        // check that the application is system settings.
        // if not, some malicious app is trying to rekey the
        // plugin.
        if (!applicationIsPlatformApplication) {
            return Result(Result::PermissionsError,
                          QLatin1String("Only the system settings application can unlock the plugin"));
        }
    } else {
        // TODO: only allow system settings application or device lock daemon!
        if (!applicationIsPlatformApplication) {
            return Result(Result::PermissionsError,
                          QLatin1String("Only the system settings application can unlock the secrets database"));
        }

        // there is only one bookkeeping database, ensure that
        // the client hasn't attempted to set some other target.
        if (!lockCodeTarget.isEmpty()) {
            return Result(Result::OperationNotSupportedError,
                          QLatin1String("Invalid target name specified"));
        }

        // TODO: FIXME: should we skip this check?  e.g. to unlock each of the plugins?
        //if (!m_requestQueue->masterLocked()) {
        //    return Result(Result::SecretsDaemonNotLockedError,
        //                  QLatin1String("The secrets database is not locked"));
        //}

        if (m_requestQueue->noLockCode()) {
            // We successfully opened the database without a lock code
            // on startup, and the lock code hasn't been modified since
            // then (but may have been deliberately forgotten).
            // So, we can unlock the database with a null lock code.
            if (!m_requestQueue->initialize(
                        QByteArray(),
                        SecretsRequestQueue::UnlockMode)) {
                return Result(Result::UnknownError,
                              QLatin1String("Unable to initialize key data from null lock code"));
            }

            // unlock all of our plugins
            QFuture<bool> future = QtConcurrent::run(
                        m_requestQueue->secretsThreadPool().data(),
                        &Daemon::ApiImpl::masterUnlockPlugins,
                        m_storagePlugins.values(),
                        m_encryptedStoragePlugins.values(),
                        m_requestQueue->bkdbLockKey());
            future.waitForFinished();
            if (!future.result()) {
                // TODO: FIXME: how can we recover from this?
                // This is symptomatic of a power-loss halfway through previous re-encryption,
                // meaning that some metadata databases will have been encrypted with
                // the OLD lock code, and some with the NEW lock code...
                qCWarning(lcSailfishSecretsDaemon) << "Critical Error! Failed to unlock metadata plugins";
            }

            // TODO: FIXME: how can we handle plugin metadata decryption failures?
            return Result(Result::Succeeded);
        }
    }

    // retrieve the lock code from the user
    QString userInputPlugin = interactionParams.authenticationPluginName();
    if (interactionParams.authenticationPluginName().isEmpty()) {
        // TODO: depending on type, choose the appropriate authentication plugin
        userInputPlugin = SecretManager::DefaultAuthenticationPluginName;
        if (m_autotestMode) {
            userInputPlugin.append(QLatin1String(".test"));
        }
    }
    if (!m_authenticationPlugins.contains(userInputPlugin)) {
        return Result(Result::InvalidExtensionPluginError,
                      QString::fromLatin1("Cannot get user input from invalid authentication plugin: %1")
                      .arg(interactionParams.authenticationPluginName()));
    }

    InteractionParameters unlockRequest(interactionParams);
    unlockRequest.setApplicationId(callerApplicationId);

    if (lockCodeTargetType == LockCodeRequest::ExtensionPlugin) {
        unlockRequest.setOperation(InteractionParameters::UnlockPlugin);
        unlockRequest.setPromptText({
            //: This will be displayed to the user, prompting them to enter the passphrase to unlock the extension plugin. %1 is the application name, %2 is the plugin name.
            //% "App %1 wants to use plugin %2."
            { InteractionParameters::Message, qtTrId("sailfish_secrets-provide_lock_code-la-message_plugin")
                        .arg(callerApplicationId, m_requestQueue->controller()->displayNameForPlugin(lockCodeTarget)) },
            //% "Enter the passphrase to unlock the plugin."
            { InteractionParameters::Instruction, qtTrId("sailfish_secrets-provide_lock_code-la-enter_plugin_passphrase") }
        });
    } else {
        unlockRequest.setOperation(InteractionParameters::UnlockDatabase);
        unlockRequest.setPromptText({
            //: This will be displayed to the user, prompting them to enter the passphrase to unlock the secrets service. %1 is the application name.
            //% "App %1 wants to use the secrets service."
            { InteractionParameters::Message, qtTrId("sailfish_secrets-provide_lock_code-la-message_master")
                        .arg(callerApplicationId) },
            //% "Enter the master passphrase to unlock the secrets service."
            { InteractionParameters::Instruction, qtTrId("sailfish_secrets-provide_lock_code-la-enter_master_passphrase") }
        });
    }

    Result interactionResult = m_authenticationPlugins[userInputPlugin]->beginUserInputInteraction(
                callerPid,
                requestId,
                unlockRequest,
                interactionServiceAddress);
    if (interactionResult.code() == Result::Failed) {
        return interactionResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::ProvideLockCodeRequest,
                                 QVariantList() << QVariant::fromValue<LockCodeRequest::LockCodeTargetType>(lockCodeTargetType)
                                                << QVariant::fromValue<QString>(lockCodeTarget)
                                                << QVariant::fromValue<InteractionParameters>(unlockRequest)
                                                << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
                                                << QVariant::fromValue<QString>(interactionServiceAddress)));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::provideLockCodeWithLockCode(
        pid_t callerPid,
        quint64 requestId,
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParams,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress,
        const QByteArray &lockCode)
{
    // TODO: support the secret/collection flows.
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);
    Q_UNUSED(interactionParams);
    Q_UNUSED(userInteractionMode);
    Q_UNUSED(interactionServiceAddress);

    // check if the client is attempting to unlock an extension plugin
    if (lockCodeTargetType == LockCodeRequest::ExtensionPlugin) {
        QFuture<FoundResult> future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    &Daemon::ApiImpl::unlockSpecificPlugin,
                    m_encryptionPlugins,
                    m_storagePlugins,
                    m_encryptedStoragePlugins,
                    lockCodeTarget,
                    lockCode);
        future.waitForFinished();
        FoundResult fr = future.result();
        if (fr.found) {
            // if the lock target was a plugin from the encryption/storage/encryptedStorage
            // maps, then return the lock result from the threaded plugin operation.
            return fr.result;
        } else if (m_authenticationPlugins.contains(lockCodeTarget)) {
            AuthenticationPlugin *p = m_authenticationPlugins.value(lockCodeTarget);
            if (!p->supportsLocking()) {
                return Result(Result::OperationNotSupportedError,
                              QStringLiteral("Authentication plugin %1 does not support locking").arg(lockCodeTarget));
            } else if (!p->unlock(lockCode)) {
                return Result(Result::UnknownError,
                              QStringLiteral("Failed to unlock authentication plugin %1").arg(lockCodeTarget));
            }
            return Result(Result::Succeeded);
        } else {
            return m_requestQueue->unlockCryptoPlugin(lockCodeTarget, lockCode);
        }
    }

    // otherwise, the client is attempting to provide the "master" lock for the metadata (bookkeeping) databases.
    if (!m_requestQueue->testLockCode(lockCode)) {
        return Result(Result::SecretsDaemonLockedError,
                      QLatin1String("The given lock code was incorrect"));
    }
    if (!m_requestQueue->initialize(
                lockCode, SecretsRequestQueue::UnlockMode)) {
        return Result(Result::UnknownError,
                      QLatin1String("Unable to initialize key data to unlock metadata databases"));
    }

    // unlock all of our plugins
    QFuture<bool> future = QtConcurrent::run(
                m_requestQueue->secretsThreadPool().data(),
                &Daemon::ApiImpl::masterUnlockPlugins,
                m_storagePlugins.values(),
                m_encryptedStoragePlugins.values(),
                m_requestQueue->bkdbLockKey());
    future.waitForFinished();
    if (!future.result()) {
        // TODO: FIXME: how can we recover from this?
        // This is symptomatic of a power-loss halfway through previous re-encryption,
        // meaning that some metadata databases will have been encrypted with
        // the OLD lock code, and some with the NEW lock code...
        qCWarning(lcSailfishSecretsDaemon) << "Critical Error! Failed to unlock metadata plugins";
    }

    // TODO: FIXME: how can we handle plugin metadata decryption failures?
    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::RequestProcessor::forgetLockCode(
        pid_t callerPid,
        quint64 requestId,
        LockCodeRequest::LockCodeTargetType lockCodeTargetType,
        const QString &lockCodeTarget,
        const InteractionParameters &interactionParams,
        SecretManager::UserInteractionMode userInteractionMode,
        const QString &interactionServiceAddress)
{
    Q_UNUSED(requestId)
    Q_UNUSED(interactionParams)
    Q_UNUSED(userInteractionMode)
    Q_UNUSED(interactionServiceAddress)

    // TODO: perform access control request to see if the application has permission to access secure storage data.
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);
    Q_UNUSED(callerApplicationId); // TODO: access control?

    if (lockCodeTargetType == LockCodeRequest::ExtensionPlugin) {
        // check that the application is system settings.
        // if not, some malicious app is trying to lock the
        // plugin.
        if (!applicationIsPlatformApplication) {
            return Result(Result::PermissionsError,
                          QLatin1String("Only the system settings application can unlock the plugin"));
        }

        QFuture<FoundResult> future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    &Daemon::ApiImpl::lockSpecificPlugin,
                    m_encryptionPlugins,
                    m_storagePlugins,
                    m_encryptedStoragePlugins,
                    lockCodeTarget);
        future.waitForFinished();
        FoundResult fr = future.result();
        if (fr.found) {
            // if the lock target was a plugin from the encryption/storage/encryptedStorage
            // maps, then return the lock result from the threaded plugin operation.
            return fr.result;
        } else if (m_authenticationPlugins.contains(lockCodeTarget)) {
            AuthenticationPlugin *p = m_authenticationPlugins.value(lockCodeTarget);
            if (!p->supportsLocking()) {
                return Result(Result::OperationNotSupportedError,
                              QStringLiteral("Authentication plugin %1 does not support locking").arg(lockCodeTarget));
            } else if (!p->lock()) {
                return Result(Result::UnknownError,
                              QStringLiteral("Failed to lock authentication plugin %1").arg(lockCodeTarget));
            }
            return Result(Result::Succeeded);
        } else {
            return m_requestQueue->lockCryptoPlugin(lockCodeTarget);
        }
    } else {
        // TODO: only allow system settings application or device lock daemon!
        if (!applicationIsPlatformApplication) {
            return Result(Result::PermissionsError,
                          QLatin1String("Only the system settings application can lock the secrets database"));
        }

        // we always perform master-lock operations on ALL plugin metadata databases at once.
        if (!lockCodeTarget.isEmpty()) {
            return Result(Result::OperationNotSupportedError,
                          QLatin1String("Invalid target name specified"));
        }

        if (!m_requestQueue->initialize(
                    QByteArray("ffffffffffffffff"
                               "ffffffffffffffff"
                               "ffffffffffffffff"
                               "ffffffffffffffff"),
                    SecretsRequestQueue::LockMode)) {
            return Result(Result::UnknownError,
                          QLatin1String("Unable to re-initialize key data to lock the secrets service"));
        }

        // lock all of our plugins' metadata databases
        QFuture<bool> future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    &Daemon::ApiImpl::masterLockPlugins,
                    m_storagePlugins.values(),
                    m_encryptedStoragePlugins.values());
        future.waitForFinished();

        return Result(Result::Succeeded);
    }
}

Result
Daemon::ApiImpl::RequestProcessor::setCollectionKeyPreCheck(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        QByteArray *collectionDecryptionKey)
{
    Q_UNUSED(collectionDecryptionKey); // asynchronous out-params.
    if (identifier.name().isEmpty()) {
        return Result(Result::InvalidSecretError,
                      QLatin1String("Empty secret name given"));
    } else if (identifier.collectionName().isEmpty()) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Empty collection name given"));
    } else if (identifier.collectionName().compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("Reserved collection name given"));
    } else if (identifier.storagePluginName().isEmpty()) {
        return Result(Result::InvalidExtensionPluginError,
                      QLatin1String("Empty storage plugin name given"));
    } else if (!m_storagePlugins.contains(identifier.storagePluginName())
               && !m_encryptedStoragePlugins.contains(identifier.storagePluginName())) {
        return Result(Result::InvalidExtensionPluginError,
                      QLatin1String("Unknown storage plugin name given"));
    }

    // Read the metadata about the target collection
    QFutureWatcher<CollectionMetadataResult> *watcher
            = new QFutureWatcher<CollectionMetadataResult>(this);
    QFuture<CollectionMetadataResult> future;
    if (m_encryptedStoragePlugins.contains(identifier.storagePluginName())) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::collectionMetadata,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    identifier.collectionName());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::collectionMetadata,
                    m_storagePlugins[identifier.storagePluginName()],
                    identifier.collectionName());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<CollectionMetadataResult>::finished, [=] {
        watcher->deleteLater();
        CollectionMetadataResult cmr = watcher->future().result();
        Result result = cmr.result.code() != Result::Succeeded
                ? cmr.result
                : setCollectionKeyPreCheckWithMetadata(
                      callerPid,
                      requestId,
                      identifier,
                      userInteractionMode,
                      cmr.metadata);
        if (result.code() != Result::Pending) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(result);
            outParams << QVariant::fromValue<QByteArray>(QByteArray());
            m_requestQueue->requestFinished(requestId, outParams);
        }
    });

    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::setCollectionKeyPreCheckWithMetadata(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const CollectionMetadata &collectionMetadata)
{
    const bool applicationIsPlatformApplication = m_appPermissions->applicationIsPlatformApplication(callerPid);
    const QString callerApplicationId = applicationIsPlatformApplication
                ? m_appPermissions->platformApplicationId()
                : m_appPermissions->applicationId(callerPid);

    const QString authPluginName = determineAuthPlugin(
                collectionMetadata.ownerApplicationId,
                callerApplicationId,
                applicationIsPlatformApplication,
                collectionMetadata.authenticationPluginName,
                QString(),
                m_autotestMode);

    if (collectionMetadata.accessControlMode == SecretManager::SystemAccessControlMode) {
        // TODO: perform access control request, to ask for permission to set the secret in the collection.
        return Result(Result::OperationNotSupportedError,
                      QLatin1String("Access control requests are not currently supported. TODO!"));
    } else if (collectionMetadata.accessControlMode == SecretManager::OwnerOnlyMode
               && collectionMetadata.ownerApplicationId != callerApplicationId) {
        return Result(Result::PermissionsError,
                      QString::fromLatin1("Collection %1 in plugin %2 is owned by a different application")
                      .arg(identifier.collectionName(), identifier.storagePluginName()));
    }

    if (m_encryptedStoragePlugins.contains(identifier.storagePluginName())) {
        // TODO: make this asynchronous instead of blocking the main thread!
        QFuture<LockedResult> future
                = QtConcurrent::run(
                        m_requestQueue->secretsThreadPool().data(),
                        EncryptedStoragePluginFunctionWrapper::isCollectionLocked,
                        m_encryptedStoragePlugins[identifier.storagePluginName()],
                        identifier.collectionName());
        future.waitForFinished();
        LockedResult lr = future.result();
        Result pluginResult = lr.result;
        bool locked = lr.locked;
        if (pluginResult.code() != Result::Succeeded) {
            return pluginResult;
        }
        if (!locked) {
            setCollectionKeyPreCheckWithEncryptionKey(
                        callerPid,
                        requestId,
                        identifier,
                        collectionMetadata,
                        QByteArray());
            return Result(Result::Pending);
        }

        if (collectionMetadata.usesDeviceLockKey) {
            // TODO: perform a "verify" UI flow (if the user interaction mode allows)
            //       If that succeeds, unlock the collection with the stored devicelock key and continue.
            return Result(Result::CollectionIsLockedError,
                          QString::fromLatin1("Collection %1 is locked and requires device lock authentication")
                          .arg(identifier.collectionName()));
        } else if (userInteractionMode == SecretManager::PreventInteraction) {
            return Result(Result::OperationRequiresUserInteraction,
                          QString::fromLatin1("Authentication plugin %1 requires user interaction")
                          .arg(authPluginName));
        } else if (!m_authenticationPlugins.contains(authPluginName)) {
            return Result(Result::InvalidExtensionPluginError,
                          QStringLiteral("Unknown collection authentication plugin: %1")
                          .arg(authPluginName));
        }

        // perform the user input flow required to get the input key data which will be used
        // to unlock this collection.
        InteractionParameters promptParams;
        promptParams.setApplicationId(callerApplicationId);
        promptParams.setPluginName(identifier.storagePluginName());
        promptParams.setCollectionName(identifier.collectionName());
        promptParams.setSecretName(identifier.name());
        promptParams.setOperation(InteractionParameters::StoreKey);
        promptParams.setInputType(InteractionParameters::AlphaNumericInput);
        promptParams.setEchoMode(InteractionParameters::PasswordEcho);
        promptParams.setPromptText({
            //: This will be displayed to the user, prompting them to enter the passphrase to unlock the collection prior to key storage. %1 is the application name, %2 is the key name, %3 is the collection name, %4 is the plugin name.
            //% "App %1 wants to store a new key named %2 into collection %3 in plugin %4."
            { InteractionParameters::Message, qtTrId("sailfish_secrets-set_collection_key_precheck-la-message")
                        .arg(callerApplicationId,
                                identifier.name(),
                                identifier.collectionName(),
                                m_requestQueue->controller()->displayNameForPlugin(identifier.storagePluginName())) },
            //% "Enter the passphrase to unlock the collection."
            { InteractionParameters::Instruction, qtTrId("sailfish_secrets-set_collection_key_precheck-la-enter_collection_passphrase") }
        });
        Result interactionResult = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                    callerPid,
                    requestId,
                    promptParams,
                    QString());
        if (interactionResult.code() == Result::Failed) {
            return interactionResult;
        }

        m_pendingRequests.insert(requestId,
                                 Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                     callerPid,
                                     requestId,
                                     Daemon::ApiImpl::SetCollectionKeyPreCheckRequest,
                                     QVariantList() << QVariant::fromValue<Secret::Identifier>(identifier)
                                                    << userInteractionMode
                                                    << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
        return Result(Result::Pending);
    }

    const QString hashedCollectionName = calculateSecretNameHash(
                Secret::Identifier(QString(), identifier.collectionName(), identifier.storagePluginName()));
    if (m_collectionEncryptionKeys.contains(hashedCollectionName)) {
        setCollectionKeyPreCheckWithEncryptionKey(
                    callerPid,
                    requestId,
                    identifier,
                    collectionMetadata,
                    m_collectionEncryptionKeys.value(hashedCollectionName));
        return Result(Result::Pending);
    }

    if (collectionMetadata.usesDeviceLockKey) {
        // TODO: perform a "verify" UI flow (if the user interaction mode allows)
        return Result(Result::CollectionIsLockedError,
                      QString::fromLatin1("Collection %1 is locked and requires device lock authentication")
                      .arg(identifier.collectionName()));
    } else if (userInteractionMode == SecretManager::PreventInteraction) {
        return Result(Result::OperationRequiresUserInteraction,
                      QString::fromLatin1("Authentication plugin %1 requires user interaction")
                      .arg(authPluginName));
    } else if (!m_authenticationPlugins.contains(authPluginName)) {
        // TODO: stale data in metadata db?
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown collection authentication plugin: %1")
                      .arg(authPluginName));
    }

    // perform the user input flow required to get the input key data which will be used
    // to unlock this collection.
    InteractionParameters promptParams;
    promptParams.setApplicationId(callerApplicationId);
    promptParams.setPluginName(identifier.storagePluginName());
    promptParams.setCollectionName(identifier.collectionName());
    promptParams.setSecretName(identifier.name());
    promptParams.setOperation(InteractionParameters::StoreSecret);
    promptParams.setInputType(InteractionParameters::AlphaNumericInput);
    promptParams.setEchoMode(InteractionParameters::PasswordEcho);
    promptParams.setPromptText({
        //: This will be displayed to the user, prompting them to enter the passphrase to unlock the collection prior to key storage. %1 is the application name, %2 is the key name, %3 is the collection name, %4 is the plugin name.
        //% "App %1 wants to store a new key named %2 into collection %3 in plugin %4."
        { InteractionParameters::Message, qtTrId("sailfish_secrets-set_collection_key_precheck-la-message")
                    .arg(callerApplicationId,
                            identifier.name(),
                            identifier.collectionName(),
                            m_requestQueue->controller()->displayNameForPlugin(identifier.storagePluginName())) },
        //% "Enter the passphrase to unlock the collection."
        { InteractionParameters::Instruction, qtTrId("sailfish_secrets-set_collection_key_precheck-la-enter_collection_passphrase") }
    });
    Result interactionResult = m_authenticationPlugins[authPluginName]->beginUserInputInteraction(
                callerPid,
                requestId,
                promptParams,
                QString());
    if (interactionResult.code() == Result::Failed) {
        return interactionResult;
    }

    m_pendingRequests.insert(requestId,
                             Daemon::ApiImpl::RequestProcessor::PendingRequest(
                                 callerPid,
                                 requestId,
                                 Daemon::ApiImpl::SetCollectionKeyPreCheckRequest,
                                 QVariantList() << QVariant::fromValue<Secret::Identifier>(identifier)
                                                << userInteractionMode
                                                << QVariant::fromValue<CollectionMetadata>(collectionMetadata)));
    return Result(Result::Pending);
}

Result
Daemon::ApiImpl::RequestProcessor::setCollectionKeyPreCheckWithAuthenticationCode(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &authenticationCode)
{
    Q_UNUSED(userInteractionMode); // TODO: we may need to automatically unlock the plugin if plugin is locked?

    // generate the encryption key from the authentication code
    if (identifier.storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        if (!m_encryptedStoragePlugins.contains(identifier.storagePluginName())) {
            // TODO: stale data in the database?
            return Result(Result::InvalidExtensionPluginError,
                          QStringLiteral("Unknown collection encrypted storage plugin: %1")
                          .arg(identifier.storagePluginName()));
        }
    } else if (!m_encryptionPlugins.contains(collectionMetadata.encryptionPluginName)) {
        // TODO: stale data in the database?
        return Result(Result::InvalidExtensionPluginError,
                      QStringLiteral("Unknown collection encryption plugin: %1").arg(collectionMetadata.encryptionPluginName));
    }

    QFutureWatcher<DerivedKeyResult> *watcher
            = new QFutureWatcher<DerivedKeyResult>(this);
    QFuture<DerivedKeyResult> future;
    if (identifier.storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    authenticationCode,
                    m_requestQueue->saltData());
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptionPluginFunctionWrapper::deriveKeyFromCode,
                    m_encryptionPlugins[collectionMetadata.encryptionPluginName],
                    authenticationCode,
                    m_requestQueue->saltData());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<DerivedKeyResult>::finished, [=] {
        watcher->deleteLater();
        DerivedKeyResult dkr = watcher->future().result();
        if (dkr.result.code() != Result::Succeeded) {
            QVariantList outParams;
            outParams << QVariant::fromValue<Result>(dkr.result);
            m_requestQueue->requestFinished(requestId, outParams);
        } else {
            setCollectionKeyPreCheckWithEncryptionKey(
                        callerPid,
                        requestId,
                        identifier,
                        collectionMetadata,
                        dkr.key);
        }
    });

    return Result(Result::Pending);
}

void
Daemon::ApiImpl::RequestProcessor::setCollectionKeyPreCheckWithEncryptionKey(
        pid_t callerPid,
        quint64 requestId,
        const Secret::Identifier &identifier,
        const CollectionMetadata &collectionMetadata,
        const QByteArray &collectionDecryptionKey)
{
    Q_UNUSED(callerPid);
    QFutureWatcher<Result> *watcher
            = new QFutureWatcher<Result>(this);
    QFuture<Result> future;
    if (identifier.storagePluginName() == collectionMetadata.encryptionPluginName
            || collectionMetadata.encryptionPluginName.isEmpty()) {
        bool requiresRelock = !collectionDecryptionKey.isEmpty() &&
                ((!collectionMetadata.usesDeviceLockKey
                  && collectionMetadata.unlockSemantic != SecretManager::CustomLockKeepUnlocked)
                || (collectionMetadata.usesDeviceLockKey
                  && collectionMetadata.unlockSemantic != SecretManager::DeviceLockKeepUnlocked));
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    EncryptedStoragePluginFunctionWrapper::collectionSecretPreCheck,
                    m_encryptedStoragePlugins[identifier.storagePluginName()],
                    identifier.collectionName(),
                    identifier.name(),
                    collectionDecryptionKey,
                    requiresRelock);
    } else {
        future = QtConcurrent::run(
                    m_requestQueue->secretsThreadPool().data(),
                    StoragePluginFunctionWrapper::collectionSecretPreCheck,
                    m_storagePlugins[identifier.storagePluginName()],
                    identifier.collectionName(),
                    identifier.name());
    }

    watcher->setFuture(future);
    connect(watcher, &QFutureWatcher<Result>::finished, [=] {
        watcher->deleteLater();
        Result result = watcher->future().result();
        QVariantList outParams;
        outParams << QVariant::fromValue<Result>(result);
        outParams << QVariant::fromValue<QByteArray>(collectionDecryptionKey);
        m_requestQueue->requestFinished(requestId, outParams);
    });
}

void
Daemon::ApiImpl::RequestProcessor::userInputInteractionCompleted(
        uint callerPid,
        qint64 requestId,
        const InteractionParameters &interactionParameters,
        const QString &interactionServiceAddress,
        const Result &result,
        const QByteArray &userInput)
{
    // may be needed in the future for "multiple-step" flows.
    Q_UNUSED(callerPid);
    Q_UNUSED(interactionParameters)
    Q_UNUSED(interactionServiceAddress);

    bool returnUserInput = false;
    Secret secret;
    Result returnResult = result;
    if (result.code() == Result::Succeeded) {
        // look up the pending request in our list
        if (m_pendingRequests.contains(requestId)) {
            // call the appropriate method to complete the request
            Daemon::ApiImpl::RequestProcessor::PendingRequest pr = m_pendingRequests.take(requestId);
            switch (pr.requestType) {
                case CreateCustomLockCollectionRequest: {
                    if (pr.parameters.size() != 8) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        returnResult = createCustomLockCollectionWithAuthenticationCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<QString>(),
                                    static_cast<SecretManager::CustomLockUnlockSemantic>(pr.parameters.takeFirst().value<int>()),
                                    static_cast<SecretManager::AccessControlMode>(pr.parameters.takeFirst().value<int>()),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    userInput);
                    }
                    break;
                }
                case SetCollectionUserInputSecretRequest: {
                    if (pr.parameters.size() != 5) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        Secret secret = pr.parameters.takeFirst().value<Secret>();
                        secret.setData(userInput);
                        /*InteractionParameters uiParams = */pr.parameters.takeFirst().value<InteractionParameters>();
                        returnResult = setCollectionSecretGetAuthenticationCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    secret,
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<CollectionMetadata>());
                    }
                    break;
                }
                case SetCollectionSecretRequest: {
                    if (pr.parameters.size() != 4) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        returnResult = setCollectionSecretWithAuthenticationCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<Secret>(),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<CollectionMetadata>(),
                                    userInput);
                    }
                    break;
                }
                case SetStandaloneDeviceLockUserInputSecretRequest: {
                    if (pr.parameters.size() != 2) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        Secret secret = pr.parameters.takeFirst().value<Secret>();
                        secret.setData(userInput);
                        returnResult = writeStandaloneDeviceLockSecret(
                                    pr.callerPid,
                                    pr.requestId,
                                    secret,
                                    pr.parameters.takeFirst().value<SecretMetadata>());
                    }
                    break;
                }
                case SetStandaloneCustomLockUserInputSecretRequest: {
                    if (pr.parameters.size() != 4) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        Secret secret = pr.parameters.takeFirst().value<Secret>();
                        secret.setData(userInput);
                        returnResult = setStandaloneCustomLockSecretGetAuthenticationCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    secret,
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<SecretMetadata>());
                    }
                    break;
                }
                case SetStandaloneCustomLockSecretRequest: {
                    if (pr.parameters.size() != 2) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        returnResult = setStandaloneCustomLockSecretWithAuthenticationCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<Secret>(),
                                    pr.parameters.takeFirst().value<SecretMetadata>(),
                                    userInput);
                    }
                    break;
                }
                case GetCollectionSecretRequest: {
                    if (pr.parameters.size() != 4) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        returnResult = getCollectionSecretWithAuthenticationCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<Secret::Identifier>(),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<CollectionMetadata>(),
                                    userInput);
                    }
                    break;
                }
                case GetStandaloneSecretRequest: {
                    if (pr.parameters.size() != 4) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        returnResult = getStandaloneSecretWithAuthenticationCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<Secret::Identifier>(),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<SecretMetadata>(),
                                    userInput);
                    }
                    break;
                }
                case FindCollectionSecretsRequest: {
                    if (pr.parameters.size() != 7) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        returnResult = findCollectionSecretsWithAuthenticationCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<Secret::FilterData>(),
                                    static_cast<SecretManager::FilterOperator>(pr.parameters.takeFirst().value<int>()),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<CollectionMetadata>(),
                                    userInput);
                    }
                    break;
                }
                case DeleteCollectionRequest: {
                    if (pr.parameters.size() != 5) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        deleteCollectionWithLockCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<QString>(),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<CollectionMetadata>(),
                                    userInput);
                        returnResult = Result(Result::Pending);
                    }
                    break;
                }
                case DeleteCollectionSecretRequest: {
                    if (pr.parameters.size() != 4) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        returnResult = deleteCollectionSecretWithAuthenticationCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<Secret::Identifier>(),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<CollectionMetadata>(),
                                    userInput);
                    }
                    break;
                }
                case ModifyLockCodeRequest: {
                    if (pr.parameters.size() == 5) {
                        // we have the old lock code.  Now we need the new lock code.
                        returnResult = modifyLockCodeWithLockCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<LockCodeRequest::LockCodeTargetType>(),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<InteractionParameters>(),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    userInput);
                    } else if (pr.parameters.size() == 6) {
                        // we have both the old and new lock codes.
                        // attempt to update the encryption key from the lock code.
                        returnResult = modifyLockCodeWithLockCodes(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<LockCodeRequest::LockCodeTargetType>(),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<InteractionParameters>(),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<QByteArray>(),
                                    userInput);
                    } else {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    }
                    break;
                }
                case ProvideLockCodeRequest: {
                    if (pr.parameters.size() != 5) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        returnResult = provideLockCodeWithLockCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<LockCodeRequest::LockCodeTargetType>(),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<InteractionParameters>(),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    userInput);
                    }
                    break;
                }
                case UserInputRequest: {
                    if (pr.parameters.size() != 1) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        returnUserInput = true;
                        returnResult = result; // Succeeded.
                    }
                    break;
                }
                case SetCollectionKeyPreCheckRequest: {
                    if (pr.parameters.size() != 3) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        returnResult = setCollectionKeyPreCheckWithAuthenticationCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<Secret::Identifier>(),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<CollectionMetadata>(),
                                    userInput);
                    }
                    break;
                }
                case StoredKeyIdentifiersRequest: {
                    if (pr.parameters.size() != 5) {
                        returnResult = Result(Result::UnknownError,
                                              QLatin1String("Internal error: incorrect parameter count!"));
                    } else {
                        returnResult = storedKeyIdentifiersWithAuthenticationCode(
                                    pr.callerPid,
                                    pr.requestId,
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<QString>(),
                                    static_cast<SecretManager::UserInteractionMode>(pr.parameters.takeFirst().value<int>()),
                                    pr.parameters.takeFirst().value<QString>(),
                                    pr.parameters.takeFirst().value<CollectionMetadata>(),
                                    userInput);
                    }
                    break;
                }
                default: {
                    returnResult = Result(Result::UnknownError,
                                          QLatin1String("Internal error: unknown continuation for asynchronous request!"));
                    break;
                }
            }
        } else {
            returnResult = Result(Result::UnknownError,
                                  QLatin1String("Internal error: failed to finish unknown pending request!"));
        }
    }

    // finish the request unless another asynchronous request is required.
    if (returnResult.code() != Result::Pending) {
        QList<QVariant> outParams;
        outParams << QVariant::fromValue<Result>(returnResult);
        if (secret.identifier().isValid()) {
            outParams << QVariant::fromValue<Secret>(secret);
        } else if (returnUserInput) {
            outParams << QVariant::fromValue<QByteArray>(userInput);
        }
        m_requestQueue->requestFinished(requestId, outParams);
    }
}

void Daemon::ApiImpl::RequestProcessor::authenticationCompleted(
        uint callerPid,
        qint64 requestId,
        const Result &result)
{
    Q_UNUSED(callerPid);
    Q_UNUSED(requestId);
    Q_UNUSED(result);

    // the user has successfully authenticated themself.
    // in the future, use this to unlock device-locked collections.
}

