/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APIIMPL_BOOKKEEPINGDB_P_H
#define SAILFISHSECRETS_APIIMPL_BOOKKEEPINGDB_P_H

#include "database_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/secret.h"
#include "Secrets/result.h"

#include "Crypto/key.h"

#include <QtCore/QStringList>
#include <QtCore/QString>
#include <QtCore/QVector>
#include <QtCore/QByteArray>

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace ApiImpl {

class BookkeepingDatabase
{
public:
    BookkeepingDatabase();
    ~BookkeepingDatabase();

    bool isInitialised() const;

    bool initialise(
            bool autotestMode,
            const QByteArray &hexKey);

    Sailfish::Secrets::Result isLocked(
            bool *locked) const;

    Sailfish::Secrets::Result lock();

    Sailfish::Secrets::Result unlock(
            const QByteArray &hexKey);

    Sailfish::Secrets::Result reencrypt(
            const QByteArray &oldHexKey,
            const QByteArray &newHexKey);

    // the following methods are for the secrets service
    Sailfish::Secrets::Result insertCollection(
            const QString &collectionName,
            const QString &callerApplicationId,
            bool usesDeviceLockKey,
            const QString &storagePluginName,
            const QString &encryptionPluginName,
            const QString &authenticationPluginName,
            int unlockSemantic,
            int customLockTimeoutMs,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode);

    Sailfish::Secrets::Result collectionNames(
            QStringList *names);

    Sailfish::Secrets::Result collectionAlreadyExists(
            const QString &collectionName,
            bool *exists);

    Sailfish::Secrets::Result collectionMetadata(
            const QString &collectionName,
            bool *exists,
            QString *applicationId,
            bool *usesDeviceLockKey,
            QString *storagePluginName,
            QString *encryptionPluginName,
            QString *authenticationPluginName,
            int *unlockSemantic,
            int *customLockTimeoutMs,
            SecretManager::AccessControlMode *accessControlMode);

    Sailfish::Secrets::Result deleteCollection(
            const QString &collectionName);

    Sailfish::Secrets::Result cleanupDeleteCollection(
            const QString &collectionName,
            const Sailfish::Secrets::Result &originalFailureResult);

    Sailfish::Secrets::Result secretAlreadyExists(
            const QString &collectionName,
            const QString &hashedSecretName,
            bool *exists);

    Sailfish::Secrets::Result insertSecret(
            const QString &collectionName,
            const QString &hashedSecretName,
            const QString &applicationId,
            bool usesDeviceLockKey,
            const QString &storagePluginName,
            const QString &encryptionPluginName,
            const QString &authenticationPluginName,
            int unlockSemantic,
            int customLockTimeoutMs,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode);

    Sailfish::Secrets::Result updateSecret(
            const QString &collectionName,
            const QString &hashedSecretName,
            const QString &applicationId,
            bool usesDeviceLockKey,
            const QString &storagePluginName,
            const QString &encryptionPluginName,
            const QString &authenticationPluginName,
            int unlockSemantic,
            int customLockTimeoutMs,
            SecretManager::AccessControlMode accessControlMode);

    Sailfish::Secrets::Result deleteSecret(
            const QString &collectionName,
            const QString &hashedSecretName);

    Sailfish::Secrets::Result cleanupDeleteSecret(
            const QString &collectionName,
            const QString &hashedSecretName,
            const Sailfish::Secrets::Result &originalFailureResult);

    Sailfish::Secrets::Result secretMetadata(
            const QString &collectionName,
            const QString &hashedSecretName,
            bool *exists,
            QString *applicationId,
            bool *usesDeviceLockKey,
            QString *storagePluginName,
            QString *encryptionPluginName,
            QString *authenticationPluginName,
            int *unlockSemantic,
            int *customLockTimeoutMs,
            Sailfish::Secrets::SecretManager::AccessControlMode *accessControlMode);

    Sailfish::Secrets::Result hashedSecretNames(
            const QString &collectionName,
            QStringList *names);

    // The following methods are for the crypto helper
    Sailfish::Secrets::Result collectionStoragePluginName(
            const QString &collectionName,
            QString *collectionStoragePluginName);

    Sailfish::Secrets::Result keyStoragePluginName(
            const QString &collectionName,
            const QString &hashedKeyName,
            QString *keyStoragePluginName);

    Sailfish::Secrets::Result keyIdentifiers(
            QVector<Sailfish::Crypto::Key::Identifier> *identifiers);

    Sailfish::Secrets::Result keyPluginNames(
            const QString &collectionName,
            const QString &keyName,
            QString *cryptoPluginName,
            QString *storagePluginName);

    Sailfish::Secrets::Result addKeyEntry(
            const QString &collectionName,
            const QString &hashedSecretName,
            const QString &keyName,
            const QString &cryptoPluginName,
            const QString &storagePluginName);

    Sailfish::Secrets::Result removeKeyEntry(
            const QString &collectionName,
            const QString &keyName);

private:
    Sailfish::Secrets::Daemon::Sqlite::Database m_db;
    bool m_initialised;
    bool m_autotestMode;
};

} // ApiImpl

} // Daemon

} // Secrets

} // Sailfish


#endif // SAILFISHSECRETS_APIIMPL_BOOKKEEPINGDB_P_H
