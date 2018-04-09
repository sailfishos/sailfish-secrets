/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APIIMPL_METADATADB_P_H
#define SAILFISHSECRETS_APIIMPL_METADATADB_P_H

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

class CollectionMetadata
{
public:
    QString collectionName;
    QString ownerApplicationId;
    bool usesDeviceLockKey;
    QString encryptionPluginName;
    QString authenticationPluginName;
    int unlockSemantic;
    Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode;
};

class SecretMetadata
{
public:
    QString collectionName;
    QString secretName;
    QString ownerApplicationId;
    bool usesDeviceLockKey;
    QString encryptionPluginName;
    QString authenticationPluginName;
    int unlockSemantic;
    Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode;
    QString secretType;
    QString cryptoPluginName; // empty if not a Key
};

class MetadataDatabase
{
public:
    MetadataDatabase(const QString &storagePluginName,
                     bool pluginIsEncryptedStorage,
                     bool autotestMode);
    ~MetadataDatabase();

    bool isOpen() const;
    bool openDatabase(const QByteArray &hexKey);

    bool beginTransaction();
    bool commitTransaction();
    bool rollbackTransaction();
    bool withinTransaction();

    Sailfish::Secrets::Result isLocked(
            bool *locked) const;

    Sailfish::Secrets::Result lock();

    Sailfish::Secrets::Result unlock(
            const QByteArray &masterLockKey);

    Sailfish::Secrets::Result reencrypt(
            const QByteArray &oldMasterLockKey,
            const QByteArray &newMasterLockKey);

    Sailfish::Secrets::Result insertCollectionMetadata(
            const CollectionMetadata &metadata);

    Sailfish::Secrets::Result collectionNames(
            QStringList *names);

    Sailfish::Secrets::Result collectionAlreadyExists(
            const QString &collectionName,
            bool *exists);

    Sailfish::Secrets::Result collectionMetadata(
            const QString &collectionName,
            CollectionMetadata *metadata,
            bool *exists);

    Sailfish::Secrets::Result deleteCollectionMetadata(
            const QString &collectionName);

    Sailfish::Secrets::Result secretAlreadyExists(
            const QString &collectionName,
            const QString &secretName,
            bool *exists);

    Sailfish::Secrets::Result insertSecretMetadata(
            const SecretMetadata &metadata);

    Sailfish::Secrets::Result updateSecretMetadata(
            const SecretMetadata &metadata);

    Sailfish::Secrets::Result deleteSecretMetadata(
            const QString &collectionName,
            const QString &secretName);

    Sailfish::Secrets::Result secretMetadata(
            const QString &collectionName,
            const QString &secretName,
            SecretMetadata *metadata,
            bool *exists);

    Sailfish::Secrets::Result secretNames(
            const QString &collectionName,
            QStringList *names);

    // only those secrets which have type = key.
    Sailfish::Secrets::Result keyNames(
            const QString &collectionName,
            QStringList *names);

    // These two methods are to allow us to "synchronize"
    // metadata db state with the plugin state
    bool initializeCollectionsFromPluginData(
            const QStringList &existingCollectionNames);
    bool initializeSecretsFromPluginData(
            const QVector<Secret::Identifier> &identifiers,
            const QStringList &lockedCollectionNames);

private:
    Sailfish::Secrets::Daemon::Sqlite::Database m_db;
    QString m_storagePluginName;
    bool m_pluginIsEncryptedStorage;
    bool m_autotestMode;

    QString databaseConnectionName() const;
    QString databaseFileName() const;
};

} // ApiImpl

} // Daemon

} // Secrets

} // Sailfish

Q_DECLARE_METATYPE(Sailfish::Secrets::Daemon::ApiImpl::CollectionMetadata);
Q_DECLARE_METATYPE(Sailfish::Secrets::Daemon::ApiImpl::SecretMetadata);

#endif // SAILFISHSECRETS_APIIMPL_METADATADB_P_H
