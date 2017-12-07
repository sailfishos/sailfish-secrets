/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_SECRETMANAGER_H
#define LIBSAILFISHSECRETS_SECRETMANAGER_H

#include "Secrets/secret.h"
#include "Secrets/secretsglobal.h"
#include "Secrets/extensionplugins.h"

#include <QtDBus/QDBusContext>
#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusMetaType>
#include <QtDBus/QDBusArgument>

#include <QtCore/QVector>
#include <QtCore/QObject>
#include <QtCore/QStringList>
#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QMap>

namespace Sailfish {

namespace Secrets {

class InteractionView;
class SecretManagerPrivate;
class SAILFISH_SECRETS_API SecretManager : public QObject
{
    Q_OBJECT

public:
    enum UserInteractionMode {
         PreventInteraction = 0,            // no user interaction allowed, operation will fail if interaction is required
         SystemInteraction,                 // system-mediated user interaction via system UI if required
         ApplicationInteraction             // in-process application UI will handle interaction, ApplicationSpecificAuthentication only.
    };
    Q_ENUM(UserInteractionMode)

    enum AccessControlMode {
        OwnerOnlyMode = 0,                  // no fine-grained access control necessary, only the creating application can access/write/delete.
        SystemAccessControlMode             // access control via system access control, other applications can access if user gives permission.
    };
    Q_ENUM(AccessControlMode)

    enum DeviceLockUnlockSemantic {
        DeviceLockKeepUnlocked = 0,         // unlock after first successful device unlock, stay unlocked.  e.g. background processes.
        DeviceLockRelock,                   // unlock on device unlock, relock on device lock.
    };
    Q_ENUM(DeviceLockUnlockSemantic)

    enum CustomLockUnlockSemantic {
        CustomLockKeepUnlocked = 8,         // unlock after first successful access (with UI flow), stay unlocked.  e.g. background processes.
        CustomLockDeviceLockRelock,         // unlock after successful access (with UI flow) after device unlock, relock on device lock.
        CustomLockTimoutRelock,             // unlock after successful access (with UI flow) after device unlock, relock after timeout.
        CustomLockAccessRelock,             // unlock and relock on every successful access (with UI flow).
    };
    Q_ENUM(CustomLockUnlockSemantic)

    enum InitialisationMode {
        AsynchronousInitialisationMode = 0, // initialise the in-memory cache of plugin info asynchronously after construction
        MinimalInitialisationMode,          // the application intends to use default or well-known values, no need to initialise cache
        SynchronousInitialisationMode       // initialise the in-memory cache of plugin info synchronously in constructor
    };
    Q_ENUM(InitialisationMode)

    enum FilterOperator {
        OperatorOr  = Sailfish::Secrets::StoragePlugin::OperatorOr,
        OperatorAnd = Sailfish::Secrets::StoragePlugin::OperatorAnd
    };
    Q_ENUM(FilterOperator)

    static const QString InAppAuthenticationPluginName;
    static const QString DefaultAuthenticationPluginName;
    static const QString DefaultStoragePluginName;
    static const QString DefaultEncryptionPluginName;
    static const QString DefaultEncryptedStoragePluginName;

    SecretManager(Sailfish::Secrets::SecretManager::InitialisationMode mode = AsynchronousInitialisationMode, QObject *parent = Q_NULLPTR);
    bool isInitialised() const;

    // for In-Process UI flows via ApplicationSpecificAuthentication plugins only.
    void registerInteractionView(Sailfish::Secrets::InteractionView *view);

    // cached information about available storage/encryption/encryptedstorage/authentication plugins.
    QMap<QString, Sailfish::Secrets::StoragePluginInfo> storagePluginInfo();
    QMap<QString, Sailfish::Secrets::EncryptionPluginInfo> encryptionPluginInfo();
    QMap<QString, Sailfish::Secrets::EncryptedStoragePluginInfo> encryptedStoragePluginInfo();
    QMap<QString, Sailfish::Secrets::AuthenticationPluginInfo> authenticationPluginInfo();

    // create a DeviceLock-protected collection
    QDBusPendingReply<Sailfish::Secrets::Result> createCollection(
            const QString &collectionName,
            const QString &storagePluginName,
            const QString &encryptionPluginName,
            Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic unlockSemantic,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode);

    // create a CustomLock-protected collection
    QDBusPendingReply<Sailfish::Secrets::Result> createCollection(
            const QString &collectionName,
            const QString &storagePluginName,
            const QString &encryptionPluginName,
            const QString &authenticationPluginName,
            Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic unlockSemantic,
            int customLockTimeoutMs,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode);

    // delete a collection
    QDBusPendingReply<Sailfish::Secrets::Result> deleteCollection(
            const QString &collectionName,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode);

    // set a secret in a collection.  Will immediately fail if the secret's identifier is standalone.
    QDBusPendingReply<Sailfish::Secrets::Result> setSecret(
            const Sailfish::Secrets::Secret &secret,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode);

    // set a standalone DeviceLock-protected secret
    QDBusPendingReply<Sailfish::Secrets::Result> setSecret(
            const QString &storagePluginName,
            const QString &encryptionPluginName,
            const Sailfish::Secrets::Secret &secret,
            Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic unlockSemantic,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode);

    // set a standalone CustomLock-protected secret
    QDBusPendingReply<Sailfish::Secrets::Result> setSecret(
            const QString &storagePluginName,
            const QString &encryptionPluginName,
            const QString &authenticationPluginName,
            const Sailfish::Secrets::Secret &secret,
            Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic unlockSemantic,
            int customLockTimeoutMs,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode);

    // get a secret (either from a collection or standalone, depending on the identifier)
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> getSecret(
            const Sailfish::Secrets::Secret::Identifier &identifier,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode);

    // find secrets from a collection via filter
    QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> > findSecrets(
            const QString &collectionName,
            const Sailfish::Secrets::Secret::FilterData &filter,
            Sailfish::Secrets::SecretManager::FilterOperator filterOperator,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode);

    // find standalone secrets via filter
    QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> > findSecrets(
            const Sailfish::Secrets::Secret::FilterData &filter,
            Sailfish::Secrets::SecretManager::FilterOperator filterOperator,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode);

    // delete a secret (either from a collection or standalone, depending on the identifier)
    QDBusPendingReply<Sailfish::Secrets::Result> deleteSecret(
            const Sailfish::Secrets::Secret::Identifier &identifier,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode);

Q_SIGNALS:
    void isInitialisedChanged();

private:
    Sailfish::Secrets::SecretManagerPrivate *m_data;
};

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::UserInteractionMode mode) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::UserInteractionMode &mode) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::AccessControlMode mode) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::AccessControlMode &mode) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic semantic) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic &semantic) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic semantic) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic &semantic) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::FilterOperator filterOperator) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::FilterOperator &filterOperator) SAILFISH_SECRETS_API;

} // namespace Secrets

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Secrets::SecretManager::UserInteractionMode)
Q_DECLARE_METATYPE(Sailfish::Secrets::SecretManager::AccessControlMode)
Q_DECLARE_METATYPE(Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic)
Q_DECLARE_METATYPE(Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic)

#endif // LIBSAILFISHSECRETS_SECRETMANAGER_H
