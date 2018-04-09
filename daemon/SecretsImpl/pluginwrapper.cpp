/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "pluginwrapper_p.h"
#include "logging_p.h"

using namespace Sailfish::Secrets;
using namespace Sailfish::Secrets::Daemon::ApiImpl;

PluginWrapper::PluginWrapper(Sailfish::Secrets::PluginBase *plugin,
                             bool pluginIsEncryptedStorage,
                             bool autotestMode)
    : m_metadataDb(plugin->name(), pluginIsEncryptedStorage, autotestMode)
    , m_initialized(false)
    , m_plugin(plugin)
{
}

PluginWrapper::~PluginWrapper()
{
}

bool PluginWrapper::isInitialized() const
{
    return m_initialized;
}

QString PluginWrapper::name() const
{
    return m_plugin->name();
}

int PluginWrapper::version() const
{
    return m_plugin->version();
}

bool PluginWrapper::isMasterLocked() const
{
    bool locked = false;
    Result result = m_metadataDb.isLocked(&locked);
    if (result.code() != Result::Succeeded) {
        qCWarning(lcSailfishSecretsDaemon) << "Unable to determine metadata db lock state for plugin"
                                           << m_plugin->name()
                                           << result.errorCode()
                                           << result.errorMessage();
        return true; // assume locked.
    }
    return locked;
}

bool PluginWrapper::masterLock()
{
    Result result = m_metadataDb.lock();
    if (result.code() != Result::Succeeded) {
        qCWarning(lcSailfishSecretsDaemon) << "Unable to lock metadata for plugin"
                                           << m_plugin->name()
                                           << result.errorCode()
                                           << result.errorMessage();
        return false;
    }
    return true;
}

bool PluginWrapper::masterUnlock(const QByteArray &masterLockKey)
{
    Result result = m_metadataDb.unlock(masterLockKey);
    if (result.code() == Result::Failed) {
        qCWarning(lcSailfishSecretsDaemon) << "Unable to unlock metadata for plugin"
                                           << m_plugin->name()
                                           << result.errorCode()
                                           << result.errorMessage();
        return false;
    }
    return initialize(masterLockKey); // may need to synchronise data between metadataDb and plugin.
}

bool PluginWrapper::setMasterLockKey(const QByteArray &oldMasterLockKey, const QByteArray &newMasterLockKey)
{
    Result result = m_metadataDb.reencrypt(oldMasterLockKey, newMasterLockKey);
    if (result.code() == Result::Failed) {
        qCWarning(lcSailfishSecretsDaemon) << "Unable to reencrypt metadata for plugin"
                                           << m_plugin->name()
                                           << result.errorCode()
                                           << result.errorMessage();
        return false;
    }
    return initialize(newMasterLockKey); // may need to synchronise data between metadataDb and plugin.
}

bool PluginWrapper::supportsLocking() const
{
    return m_plugin->supportsLocking();
}

bool PluginWrapper::isLocked() const
{
    return m_plugin->isLocked();
}

bool PluginWrapper::lock()
{
    return m_plugin->lock();
}

bool PluginWrapper::unlock(const QByteArray &lockCode)
{
    bool ps = m_plugin->unlock(lockCode);
    initialize(); // may need to synchronise data between metadataDb and plugin.
    return ps;
}

bool PluginWrapper::setLockCode(const QByteArray &oldLockCode, const QByteArray &newLockCode)
{
    bool ps = m_plugin->setLockCode(oldLockCode, newLockCode);
    initialize(); // may need to synchronise data between metadataDb and plugin.
    return ps;
}

Sailfish::Secrets::PluginInfo::StatusFlags PluginWrapper::status() const
{
    Sailfish::Secrets::PluginInfo::StatusFlags s = Sailfish::Secrets::PluginInfo::Unknown;
    if (!isMasterLocked()) {
        s |= Sailfish::Secrets::PluginInfo::MasterUnlocked;
    }
    if (!m_plugin->supportsLocking() || !m_plugin->isLocked()) {
        s |= Sailfish::Secrets::PluginInfo::PluginUnlocked;
    }
    // TODO: if (m_plugin->isAvailable()) s|=PluginInfo::Available;
    return s;
}

// ---------------------------------------------------------------------------

StoragePluginWrapper::StoragePluginWrapper(
        Sailfish::Secrets::StoragePlugin *plugin,
        bool autotestMode)
    : PluginWrapper(plugin, false, autotestMode)
    , m_storagePlugin(plugin)
{
}

StoragePluginWrapper::~StoragePluginWrapper()
{
}

bool StoragePluginWrapper::initialize(const QByteArray &masterLockKey)
{
    if (m_initialized) {
        return true;
    }

    // step one: open the metadata database.
    if (!m_metadataDb.isOpen()) {
        if (!m_metadataDb.openDatabase(masterLockKey)) {
            return false;
        }
    }

    // step two: read current data from the plugin.
    if (m_storagePlugin->isLocked()) {
        return false;
    }

    QStringList cnames;
    Result result = collectionNames(&cnames);
    if (result.code() != Result::Succeeded) {
        return false;
    }

    QVector<Secret::Identifier> identifiers;
    for (const QString &cname : cnames) {
        QStringList snames;
        result = secretNames(cname, &snames);
        if (result.code() != Result::Succeeded) {
            return false;
        }
        for (const QString &sname : snames) {
            identifiers.append(Secret::Identifier(sname, cname, m_storagePlugin->name()));
        }
    }

    // step three: initialize the metadata db based on plugin data.
    // this ensures our data is in sync.
    if (!m_metadataDb.beginTransaction()) {
        return false;
    }

    bool initCollections = m_metadataDb.initializeCollectionsFromPluginData(cnames);
    bool initSecrets = m_metadataDb.initializeSecretsFromPluginData(identifiers, QStringList());

    m_metadataDb.commitTransaction();
    m_initialized = initCollections && initSecrets;
    return true;
}

StoragePlugin::StorageType StoragePluginWrapper::storageType() const
{
    return m_storagePlugin->storageType();
}

Result StoragePluginWrapper::collectionNames(
        QStringList *names) const
{
    return m_storagePlugin->collectionNames(names);
}

Result StoragePluginWrapper::secretNames(
        const QString &collectionName,
        QStringList *secretNames) const
{
    return m_storagePlugin->secretNames(collectionName, secretNames);
}

Result StoragePluginWrapper::keyNames(
        const QString &collectionName,
        QStringList *keyNames)
{
    return m_metadataDb.keyNames(collectionName, keyNames);
}

Result StoragePluginWrapper::getSecret(
        const QString &collectionName,
        const QString &secretName,
        QByteArray *secret,
        Secret::FilterData *filterData)
{
    return m_storagePlugin->getSecret(collectionName, secretName, secret, filterData);
}

Result StoragePluginWrapper::findSecrets(
        const QString &collectionName,
        const Secret::FilterData &filter,
        StoragePlugin::FilterOperator filterOperator,
        QStringList *secretNames)
{
    return m_storagePlugin->findSecrets(collectionName, filter, filterOperator, secretNames);
}

Result StoragePluginWrapper::reencrypt(
        const QString &collectionName,  // if non-empty, all secrets in this collection will be re-encrypted
        const QString &secretName,      // otherwise, reencrypt this standalone secret
        const QByteArray &oldkey,
        const QByteArray &newkey,
        EncryptionPlugin *plugin)
{
    return m_storagePlugin->reencrypt(collectionName,
                                      secretName,
                                      oldkey,
                                      newkey,
                                      plugin);
}

Result StoragePluginWrapper::collectionMetadata(
        const QString &collectionName,
        CollectionMetadata *metadata)
{
    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked").arg(m_storagePlugin->name()));
    }

    bool exists = false;
    Result result = m_metadataDb.collectionMetadata(collectionName, metadata, &exists);
    return exists ? result
                  : Result(Result::InvalidCollectionError,
                           QStringLiteral("Collection %1 does not exist").arg(collectionName));
}

Result StoragePluginWrapper::secretMetadata(
        const QString &collectionName,
        const QString &secretName,
        SecretMetadata *metadata)
{
    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked").arg(m_storagePlugin->name()));
    }

    bool exists = false;
    Result result = m_metadataDb.secretMetadata(collectionName, secretName, metadata, &exists);
    return exists ? result
                  : Result(Result::InvalidSecretError,
                           QStringLiteral("Secret %1 does not exist in collection %2").arg(secretName, collectionName));
}

Result StoragePluginWrapper::createCollection(
        const CollectionMetadata &metadata)
{
    if (m_storagePlugin->isLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is locked").arg(m_storagePlugin->name()));
    }

    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked").arg(m_storagePlugin->name()));
    }

    bool exists = false;
    CollectionMetadata existingMetadata;
    Result result = m_metadataDb.collectionMetadata(metadata.collectionName, &existingMetadata, &exists);
    if (exists) {
        return Result(Result::CollectionAlreadyExistsError,
                      QStringLiteral("Collection %1 already exists").arg(metadata.collectionName));
    } else if (result.code() != Result::Succeeded) {
        return result;
    }

    if (!m_metadataDb.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QStringLiteral("Unable to start metadata db transaction for createCollection"));
    }

    result = m_metadataDb.insertCollectionMetadata(metadata);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    result = m_storagePlugin->createCollection(metadata.collectionName);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    m_metadataDb.commitTransaction();
    return Result(Result::Succeeded);
}

Result StoragePluginWrapper::removeCollection(
        const QString &collectionName)
{
    if (m_storagePlugin->isLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is locked").arg(m_storagePlugin->name()));
    }

    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked").arg(m_storagePlugin->name()));
    }

    if (!m_metadataDb.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QStringLiteral("Unable to start metadata db transaction for deleteCollection"));
    }

    Result result = m_metadataDb.deleteCollectionMetadata(collectionName);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    result = m_storagePlugin->removeCollection(collectionName);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    m_metadataDb.commitTransaction();
    return Result(Result::Succeeded);
}

Result StoragePluginWrapper::setSecret(
        const SecretMetadata &metadata,
        const QByteArray &secret,
        const Secret::FilterData &filterData)
{
    if (m_storagePlugin->isLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is locked").arg(m_storagePlugin->name()));
    }

    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked").arg(m_storagePlugin->name()));
    }

    bool exists = false;
    CollectionMetadata collectionMetadata;
    Result result = m_metadataDb.collectionMetadata(metadata.collectionName,
                                                    &collectionMetadata,
                                                    &exists);
    if (result.code() != Result::Succeeded) {
        return result;
    } else if (!exists) {
        return Result(Result::InvalidCollectionError,
                      QStringLiteral("Collection %1 does not exist").arg(metadata.collectionName));
    }

    exists = false;
    SecretMetadata currentMetadata;
    result = m_metadataDb.secretMetadata(metadata.collectionName,
                                         metadata.secretName,
                                         &currentMetadata,
                                         &exists);
    if (result.code() != Result::Succeeded) {
        return result;
    }

    if (exists) {
        // don't allow overwriting existing secrets.
        // TODO: allow this, but only if the encryption key matches
        return Result(Result::SecretAlreadyExistsError,
                      QStringLiteral("Cannot overwrite existing secret"));
    }

    if (!m_metadataDb.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QStringLiteral("Unable to start metadata db transaction for createCollection"));
    }

    result = m_metadataDb.insertSecretMetadata(metadata);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    result = m_storagePlugin->setSecret(metadata.collectionName,
                                        metadata.secretName,
                                        secret,
                                        filterData);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    m_metadataDb.commitTransaction();
    return Result(Result::Succeeded);
}

Result StoragePluginWrapper::removeSecret(
        const QString &collectionName,
        const QString &secretName)
{
    if (m_storagePlugin->isLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is locked").arg(m_storagePlugin->name()));
    }

    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked").arg(m_storagePlugin->name()));
    }

    if (!m_metadataDb.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QStringLiteral("Unable to start metadata db transaction for removeSecret"));
    }

    Result result = m_metadataDb.deleteSecretMetadata(collectionName, secretName);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    result = m_storagePlugin->removeSecret(collectionName, secretName);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    m_metadataDb.commitTransaction();
    return Result(Result::Succeeded);
}

// ---------------------------------------------------------------------------

EncryptedStoragePluginWrapper::EncryptedStoragePluginWrapper(
        Sailfish::Secrets::EncryptedStoragePlugin *plugin, bool autotestMode)
    : PluginWrapper(plugin, true, autotestMode)
    , m_encryptedStoragePlugin(plugin)
{
}

EncryptedStoragePluginWrapper::~EncryptedStoragePluginWrapper()
{
}

bool EncryptedStoragePluginWrapper::initialize(const QByteArray &masterLockKey)
{
    if (m_initialized) {
        return true;
    }

    // step one: open the metadata database.
    if (!m_metadataDb.isOpen()) {
        if (!m_metadataDb.openDatabase(masterLockKey)) {
            return false;
        }
    }

    // step two: read current data from the plugin.
    if (m_encryptedStoragePlugin->isLocked()) {
        return false;
    }

    QStringList cnames, lockedCollections;
    Result result = collectionNames(&cnames);
    if (result.code() != Result::Succeeded) {
        return false;
    }

    QVector<Secret::Identifier> identifiers;
    for (const QString &cname : cnames) {
        bool locked = false;
        result = m_encryptedStoragePlugin->isCollectionLocked(cname, &locked);
        if (locked || result.code() != Result::Succeeded) {
            lockedCollections.append(cname);
        } else {
            QStringList snames;
            result = secretNames(cname, &snames);
            if (result.code() != Result::Succeeded) {
                return false;
            }
            for (const QString &sname : snames) {
                identifiers.append(Secret::Identifier(sname, cname, m_encryptedStoragePlugin->name()));
            }
        }
    }

    // step three: initialize the metadata db based on plugin data.
    // this ensures our data is in sync.
    if (!m_metadataDb.beginTransaction()) {
        return false;
    }

    bool initCollections = m_metadataDb.initializeCollectionsFromPluginData(cnames);
    bool initSecrets = m_metadataDb.initializeSecretsFromPluginData(identifiers, lockedCollections);

    m_metadataDb.commitTransaction();
    m_initialized = initCollections && initSecrets && lockedCollections.isEmpty();
    return true;
}

StoragePlugin::StorageType EncryptedStoragePluginWrapper::storageType() const
{
    return m_encryptedStoragePlugin->storageType();
}

EncryptionPlugin::EncryptionType EncryptedStoragePluginWrapper::encryptionType() const
{
    return m_encryptedStoragePlugin->encryptionType();
}

EncryptionPlugin::EncryptionAlgorithm EncryptedStoragePluginWrapper::encryptionAlgorithm() const
{
    return m_encryptedStoragePlugin->encryptionAlgorithm();
}

Result EncryptedStoragePluginWrapper::collectionNames(
        QStringList *names) const
{
    return m_encryptedStoragePlugin->collectionNames(names);
}

Result EncryptedStoragePluginWrapper::secretNames(
        const QString &collectionName,
        QStringList *secretNames) const
{
    return m_encryptedStoragePlugin->secretNames(collectionName, secretNames);
}

Result EncryptedStoragePluginWrapper::keyNames(
        const QString &collectionName,
        QStringList *keyNames)
{
    return m_metadataDb.keyNames(collectionName, keyNames);
}

Result EncryptedStoragePluginWrapper::isCollectionLocked(
        const QString &collectionName,
        bool *locked)
{
    return m_encryptedStoragePlugin->isCollectionLocked(collectionName, locked);
}

Result EncryptedStoragePluginWrapper::deriveKeyFromCode(
        const QByteArray &authenticationCode,
        const QByteArray &salt,
        QByteArray *key)
{
    return m_encryptedStoragePlugin->deriveKeyFromCode(authenticationCode, salt, key);
}

Result EncryptedStoragePluginWrapper::setEncryptionKey(
        const QString &collectionName,
        const QByteArray &key)
{
    // check the master lock, to avoid unlocking the collection
    // potentially for deletion without being able to delete its metadata also.
    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    Result result = m_encryptedStoragePlugin->setEncryptionKey(collectionName, key);
    // We have unlocked a collection, and may be able to retrieve more data
    // from the plugin.  Ensure that our metadata is in sync.
    initialize();
    return result;
}

Result EncryptedStoragePluginWrapper::reencrypt(
        const QString &collectionName,
        const QByteArray &oldkey,
        const QByteArray &newkey)
{
    return m_encryptedStoragePlugin->reencrypt(collectionName, oldkey, newkey);
}

Result EncryptedStoragePluginWrapper::getSecret(
        const QString &collectionName,
        const QString &secretName,
        QByteArray *secret,
        Secret::FilterData *filterData)
{
    return m_encryptedStoragePlugin->getSecret(collectionName, secretName, secret, filterData);
}

Result EncryptedStoragePluginWrapper::findSecrets(
        const QString &collectionName,
        const Secret::FilterData &filter,
        StoragePlugin::FilterOperator filterOperator,
        QVector<Secret::Identifier> *identifiers)
{
    return m_encryptedStoragePlugin->findSecrets(collectionName, filter, filterOperator, identifiers);
}

Result EncryptedStoragePluginWrapper::accessSecret(
        const QString &secretName,
        const QByteArray &key,
        QByteArray *secret,
        Secret::FilterData *filterData)
{
    return m_encryptedStoragePlugin->accessSecret(secretName, key, secret, filterData);
}

Result EncryptedStoragePluginWrapper::collectionMetadata(
        const QString &collectionName,
        CollectionMetadata *metadata)
{
    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    bool exists = false;
    Result result = m_metadataDb.collectionMetadata(collectionName, metadata, &exists);
    return exists ? result
                  : Result(Result::InvalidCollectionError,
                           QStringLiteral("Collection %1 does not exist")
                           .arg(collectionName));
}

Result EncryptedStoragePluginWrapper::secretMetadata(
        const QString &collectionName,
        const QString &secretName,
        SecretMetadata *metadata)
{
    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    bool exists = false;
    Result result = m_metadataDb.secretMetadata(collectionName, secretName, metadata, &exists);
    return exists ? result
                  : Result(Result::InvalidSecretError,
                           QStringLiteral("Secret %1 does not exist in collection %2")
                           .arg(secretName, collectionName));
}

Result EncryptedStoragePluginWrapper::createCollection(
        const CollectionMetadata &metadata,
        const QByteArray &key)
{
    if (m_encryptedStoragePlugin->isLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    bool exists = false;
    CollectionMetadata existingMetadata;
    Result result = m_metadataDb.collectionMetadata(
                metadata.collectionName, &existingMetadata, &exists);
    if (exists) {
        return Result(Result::CollectionAlreadyExistsError,
                      QStringLiteral("Collection %1 already exists")
                      .arg(metadata.collectionName));
    } else if (result.code() != Result::Succeeded) {
        return result;
    }

    if (!m_metadataDb.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QStringLiteral("Unable to start metadata db transaction for createCollection"));
    }

    result = m_metadataDb.insertCollectionMetadata(metadata);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    result = m_encryptedStoragePlugin->createCollection(metadata.collectionName, key);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    m_metadataDb.commitTransaction();
    return Result(Result::Succeeded);
}

Result EncryptedStoragePluginWrapper::removeCollection(
        const QString &collectionName)
{
    if (m_encryptedStoragePlugin->isLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    if (!m_metadataDb.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QStringLiteral("Unable to start metadata db transaction for deleteCollection"));
    }

    Result result = m_metadataDb.deleteCollectionMetadata(collectionName);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    result = m_encryptedStoragePlugin->removeCollection(collectionName);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    m_metadataDb.commitTransaction();
    return Result(Result::Succeeded);
}

Result EncryptedStoragePluginWrapper::setSecret(
        const SecretMetadata &metadata,
        const QByteArray &secret,
        const Secret::FilterData &filterData)
{
    if (m_encryptedStoragePlugin->isLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    bool locked = false;
    Result result = m_encryptedStoragePlugin->isCollectionLocked(metadata.collectionName, &locked);
    if (locked) {
        return Result(Result::CollectionIsLockedError,
                      QStringLiteral("Collection %1 from plugin %2 is locked")
                      .arg(metadata.collectionName, m_encryptedStoragePlugin->name()));
    } else if (result.code() != Result::Succeeded) {
        return result;
    }

    if (!m_metadataDb.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QStringLiteral("Unable to start metadata db transaction for createCollection"));
    }

    result = m_metadataDb.insertSecretMetadata(metadata);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    result = m_encryptedStoragePlugin->setSecret(
                metadata.collectionName, metadata.secretName, secret, filterData);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    m_metadataDb.commitTransaction();
    return Result(Result::Succeeded);
}

Result EncryptedStoragePluginWrapper::removeSecret(
        const QString &collectionName,
        const QString &secretName)
{
    if (m_encryptedStoragePlugin->isLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    bool locked = false;
    Result result = m_encryptedStoragePlugin->isCollectionLocked(collectionName, &locked);
    if (locked) {
        return Result(Result::CollectionIsLockedError,
                      QStringLiteral("Collection %1 in plugin %2 is locked")
                      .arg(collectionName, m_encryptedStoragePlugin->name()));
    } else if (result.code() != Result::Succeeded) {
        return result;
    }

    if (!m_metadataDb.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QStringLiteral("Unable to start metadata db transaction for removeSecret"));
    }

    result = m_metadataDb.deleteSecretMetadata(collectionName, secretName);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    result = m_encryptedStoragePlugin->removeSecret(collectionName, secretName);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    m_metadataDb.commitTransaction();
    return Result(Result::Succeeded);
}

Result EncryptedStoragePluginWrapper::setSecret(
        const SecretMetadata &metadata,
        const QByteArray &secret,
        const Secret::FilterData &filterData,
        const QByteArray &key)
{
    if (m_encryptedStoragePlugin->isLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    if (isMasterLocked()) {
        return Result(Result::SecretsPluginIsLockedError,
                      QStringLiteral("Plugin %1 is master-locked")
                      .arg(m_encryptedStoragePlugin->name()));
    }

    bool exists = false;
    CollectionMetadata collectionMetadata;
    Result result = m_metadataDb.collectionMetadata(metadata.collectionName,
                                                    &collectionMetadata,
                                                    &exists);
    if (result.code() != Result::Succeeded) {
        return result;
    } else if (!exists) {
        return Result(Result::InvalidCollectionError,
                      QStringLiteral("Collection %1 does not exist").arg(metadata.collectionName));
    }

    exists = false;
    SecretMetadata currentMetadata;
    result = m_metadataDb.secretMetadata(metadata.collectionName,
                                         metadata.secretName,
                                         &currentMetadata,
                                         &exists);
    if (result.code() != Result::Succeeded) {
        return result;
    }

    if (exists) {
        // don't allow overwriting existing secrets.
        // TODO: allow this, but only if the encryption key matches
        return Result(Result::SecretAlreadyExistsError,
                      QStringLiteral("Cannot overwrite existing secret"));
    }

    if (!m_metadataDb.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QStringLiteral("Unable to start metadata db transaction for removeSecret"));
    }

    result = m_metadataDb.insertSecretMetadata(metadata);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    result = m_encryptedStoragePlugin->setSecret(
                metadata.secretName, secret, filterData, key);
    if (result.code() != Result::Succeeded) {
        m_metadataDb.rollbackTransaction();
        return result;
    }

    m_metadataDb.commitTransaction();
    return Result(Result::Succeeded);
}
