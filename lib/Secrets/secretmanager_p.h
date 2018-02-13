/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_SECRETMANAGER_P_H
#define LIBSAILFISHSECRETS_SECRETMANAGER_P_H

#include "Secrets/secretmanager.h"
#include "Secrets/secret.h"
#include "Secrets/interactionparameters.h"
#include "Secrets/secretsdaemonconnection_p.h"
#include "Secrets/extensionplugins.h"
#include "Secrets/interactionview.h"
#include "Secrets/interactionservice_p.h"

#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusContext>
#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusMetaType>
#include <QtDBus/QDBusArgument>

#include <QtCore/QObject>

namespace Sailfish {

namespace Secrets {

class SecretManager;
class SecretManagerPrivate : public QObject
{
    Q_OBJECT

public:
    SecretManagerPrivate(SecretManager *parent = Q_NULLPTR);
    ~SecretManagerPrivate();

    // ui communication happens via a peer-to-peer dbus connection in which the sailfishsecretsd process becomes the client.
    void handleUiConnection(const QDBusConnection &connection);

    // register the ui service if required, and return it's address.
    Sailfish::Secrets::Result registerInteractionService(Sailfish::Secrets::SecretManager::UserInteractionMode mode, QString *address);

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

private:
    friend class SecretManager;
    friend class InteractionService;
    SecretManager *m_parent;
    InteractionService *m_uiService;
    InteractionView *m_interactionView;
    Sailfish::Secrets::SecretsDaemonConnection *m_secrets;
    QDBusInterface *m_interface;
    bool m_initialised;

    QMap<QString, Sailfish::Secrets::StoragePluginInfo> m_storagePluginInfo;
    QMap<QString, Sailfish::Secrets::EncryptionPluginInfo> m_encryptionPluginInfo;
    QMap<QString, Sailfish::Secrets::EncryptedStoragePluginInfo> m_encryptedStoragePluginInfo;
    QMap<QString, Sailfish::Secrets::AuthenticationPluginInfo> m_authenticationPluginInfo;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_SECRETMANAGER_P_H
