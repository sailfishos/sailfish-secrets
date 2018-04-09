/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APIIMPL_PLUGINWRAPPER_P_H
#define SAILFISHSECRETS_APIIMPL_PLUGINWRAPPER_P_H

#include "SecretsImpl/metadatadb_p.h"

#include "SecretsPluginApi/extensionplugins.h"

#include "Secrets/secret.h"
#include "Secrets/interactionparameters.h"
#include "Secrets/secretmanager.h"
#include "Secrets/result.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace ApiImpl {

// we wrap the storage plugins (StoragePlugin and EncryptedStoragePlugin)
// to allow metadata to be updated transactionally with plugin-stored data.
class PluginWrapper : public Sailfish::Secrets::PluginBase
{
public:
    PluginWrapper(Sailfish::Secrets::PluginBase *plugin, bool pluginIsEncryptedStorage, bool autotestMode);
    virtual ~PluginWrapper();

    bool isInitialized() const;
    virtual bool initialize(const QByteArray &masterLockKey = QByteArray()) = 0;
    Sailfish::Secrets::PluginInfo::StatusFlags status() const;

    virtual Sailfish::Secrets::Result collectionMetadata(const QString &collectionName, CollectionMetadata *metadata) = 0;
    virtual Sailfish::Secrets::Result secretMetadata(const QString &collectionName, const QString &secretName, SecretMetadata *metadata) = 0;
    virtual Sailfish::Secrets::Result keyNames(const QString &collectionName, QStringList *keyNames) = 0;
    virtual Sailfish::Secrets::Result collectionNames(QStringList *names) const = 0;
    virtual Sailfish::Secrets::Result secretNames(const QString &collectionName, QStringList *secretNames) const = 0;

    QString name() const Q_DECL_OVERRIDE;
    int version() const Q_DECL_OVERRIDE;

    // these are to lock/unlock/setlock on the plugin
    bool supportsLocking() const Q_DECL_OVERRIDE;
    bool isLocked() const Q_DECL_OVERRIDE;
    bool lock() Q_DECL_OVERRIDE;
    bool unlock(const QByteArray &lockCode) Q_DECL_OVERRIDE;
    bool setLockCode(const QByteArray &oldLockCode, const QByteArray &newLockCode) Q_DECL_OVERRIDE;

    // these are to lock/unlock/re-encrypt the per-plugin metadata databases
    bool isMasterLocked() const;
    bool masterLock();
    bool masterUnlock(const QByteArray &masterLockKey);
    bool setMasterLockKey(const QByteArray &oldMasterLockKey, const QByteArray &newMasterLockKey);

protected:
    MetadataDatabase m_metadataDb;
    bool m_initialized;

private:
    Sailfish::Secrets::PluginBase *m_plugin;
};

class StoragePluginWrapper : public PluginWrapper
{
public:
    StoragePluginWrapper(Sailfish::Secrets::StoragePlugin *plugin, bool autotestMode);
    ~StoragePluginWrapper();

    bool initialize(const QByteArray &masterLockKey = QByteArray()) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result collectionMetadata(const QString &collectionName, CollectionMetadata *metadata) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result secretMetadata(const QString &collectionName, const QString &secretName, SecretMetadata *metadata) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result keyNames(const QString &collectionName, QStringList *keyNames) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result collectionNames(QStringList *names) const Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result secretNames(const QString &collectionName, QStringList *secretNames) const Q_DECL_OVERRIDE;

    Sailfish::Secrets::StoragePlugin::StorageType storageType() const;

    Sailfish::Secrets::Result createCollection(const CollectionMetadata &metadata);
    Sailfish::Secrets::Result removeCollection(const QString &collectionName);
    Sailfish::Secrets::Result setSecret(const SecretMetadata &metadata, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData);
    Sailfish::Secrets::Result getSecret(const QString &collectionName, const QString &secretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData);
    Sailfish::Secrets::Result findSecrets(const QString &collectionName, const Sailfish::Secrets::Secret::FilterData &filter, Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator, QStringList *secretNames);
    Sailfish::Secrets::Result removeSecret(const QString &collectionName, const QString &secretName);

    Sailfish::Secrets::Result reencrypt(
            const QString &collectionName,  // if non-empty, all secrets in this collection will be re-encrypted
            const QString &secretName,      // otherwise this standalone secret will be encrypted
            const QByteArray &oldkey,
            const QByteArray &newkey,
            Sailfish::Secrets::EncryptionPlugin *plugin);
private:
    Sailfish::Secrets::StoragePlugin *m_storagePlugin;
};

class EncryptedStoragePluginWrapper : public PluginWrapper
{
public:
    EncryptedStoragePluginWrapper(Sailfish::Secrets::EncryptedStoragePlugin *plugin, bool autotestMode);
    ~EncryptedStoragePluginWrapper();

    bool initialize(const QByteArray &masterLockKey = QByteArray()) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result collectionMetadata(const QString &collectionName, CollectionMetadata *metadata) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result secretMetadata(const QString &collectionName, const QString &secretName, SecretMetadata *metadata) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result keyNames(const QString &collectionName, QStringList *keyNames) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result collectionNames(QStringList *names) const Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result secretNames(const QString &collectionName, QStringList *secretNames) const Q_DECL_OVERRIDE;

    Sailfish::Secrets::StoragePlugin::StorageType storageType() const;
    Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const;
    Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const;

    Sailfish::Secrets::Result createCollection(const CollectionMetadata &metadata, const QByteArray &key);
    Sailfish::Secrets::Result removeCollection(const QString &collectionName);

    Sailfish::Secrets::Result isCollectionLocked(const QString &collectionName, bool *locked);
    Sailfish::Secrets::Result deriveKeyFromCode(const QByteArray &authenticationCode, const QByteArray &salt, QByteArray *key);
    Sailfish::Secrets::Result setEncryptionKey(const QString &collectionName, const QByteArray &key);
    Sailfish::Secrets::Result reencrypt(const QString &collectionName, const QByteArray &oldkey, const QByteArray &newkey);

    Sailfish::Secrets::Result setSecret(const SecretMetadata &metadata, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData);
    Sailfish::Secrets::Result getSecret(const QString &collectionName, const QString &secretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData);
    Sailfish::Secrets::Result findSecrets(const QString &collectionName, const Sailfish::Secrets::Secret::FilterData &filter, Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator, QVector<Sailfish::Secrets::Secret::Identifier> *identifiers);
    Sailfish::Secrets::Result removeSecret(const QString &collectionName, const QString &secretName);

    Sailfish::Secrets::Result setSecret(const SecretMetadata &metadata, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData, const QByteArray &key);
    Sailfish::Secrets::Result accessSecret(const QString &secretName, const QByteArray &key, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData);

protected:
    Sailfish::Secrets::EncryptedStoragePlugin *m_encryptedStoragePlugin;
};

} // ApiImpl

} // Daemon

} // Secrets

} // Sailfish

#endif // SAILFISHSECRETS_APIIMPL_PLUGINWRAPPER_P_H
