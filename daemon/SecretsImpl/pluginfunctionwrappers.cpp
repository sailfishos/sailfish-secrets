/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "pluginfunctionwrappers_p.h"
#include "logging_p.h"

using namespace Sailfish::Secrets;
using namespace Sailfish::Secrets::Daemon::ApiImpl;

/* These methods are to be called via QtConcurrent */

FoundResult Daemon::ApiImpl::lockSpecificPlugin(
        const QMap<QString, EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, StoragePluginWrapper*> &storagePlugins,
        const QMap<QString, EncryptedStoragePluginWrapper*> &encryptedStoragePlugins,
        const QString &lockCodeTarget)
{
    auto lambda = [] (PluginBase *p,
                      const QString &type,
                      const QString &name,
                      Result *result) {
        if (!p->supportsLocking()) {
            *result = Result(Result::OperationNotSupportedError,
                             QStringLiteral("%1 plugin %2 does not support locking")
                             .arg(type, name));
        } else if (p->isLocked() && !p->lock()) {
            *result = Result(Result::UnknownError,
                             QStringLiteral("Failed to lock %1 plugin %2")
                             .arg(type, name));
        }
    };

    bool found = true;
    Result result(Result::Succeeded);
    if (storagePlugins.contains(lockCodeTarget)) {
        lambda(storagePlugins.value(lockCodeTarget),
               QStringLiteral("storage"),
               lockCodeTarget,
               &result);
    } else if (encryptedStoragePlugins.contains(lockCodeTarget)) {
        lambda(encryptedStoragePlugins.value(lockCodeTarget),
               QStringLiteral("encrypted storage"),
               lockCodeTarget,
               &result);
    } else if (encryptionPlugins.contains(lockCodeTarget)) {
        lambda(encryptionPlugins.value(lockCodeTarget),
               QStringLiteral("encryption"),
               lockCodeTarget,
               &result);
    } else {
        found = false;
    }

    return FoundResult(found, result);
}

FoundResult Daemon::ApiImpl::unlockSpecificPlugin(
        const QMap<QString, EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, StoragePluginWrapper*> &storagePlugins,
        const QMap<QString, EncryptedStoragePluginWrapper*> &encryptedStoragePlugins,
        const QString &lockCodeTarget,
        const QByteArray &lockCode)
{
    auto lambda = [] (PluginBase *p,
                      const QString &type,
                      const QString &name,
                      const QByteArray &lockCode,
                      Result *result) {
        if (!p->supportsLocking()) {
            *result = Result(Result::OperationNotSupportedError,
                             QStringLiteral("%1 plugin %2 does not support locking")
                             .arg(type, name));
        } else if (!p->isLocked() && !p->unlock(lockCode)) {
            *result = Result(Result::UnknownError,
                             QStringLiteral("Failed to unlock %1 plugin %2")
                             .arg(type, name));
        }
    };

    bool found = true;
    Result result(Result::Succeeded);
    if (storagePlugins.contains(lockCodeTarget)) {
        lambda(storagePlugins.value(lockCodeTarget),
               QStringLiteral("storage"),
               lockCodeTarget,
               lockCode,
               &result);
    } else if (encryptedStoragePlugins.contains(lockCodeTarget)) {
        lambda(encryptedStoragePlugins.value(lockCodeTarget),
               QStringLiteral("encrypted storage"),
               lockCodeTarget,
               lockCode,
               &result);
    } else if (encryptionPlugins.contains(lockCodeTarget)) {
        lambda(encryptionPlugins.value(lockCodeTarget),
               QStringLiteral("encryption"),
               lockCodeTarget,
               lockCode,
               &result);
    } else {
        found = false;
    }

    return FoundResult(found, result);
}

FoundResult Daemon::ApiImpl::modifyLockSpecificPlugin(
        const QMap<QString, EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, StoragePluginWrapper*> &storagePlugins,
        const QMap<QString, EncryptedStoragePluginWrapper*> &encryptedStoragePlugins,
        const QString &lockCodeTarget,
        const LockCodes &newAndOldLockCode)
{
    auto lambda = [] (PluginBase *p,
                      const QString &type,
                      const QString &name,
                      const QByteArray &oldLockCode,
                      const QByteArray &newLockCode,
                      Result *result) {
        if (!p->supportsLocking()) {
            *result = Result(Result::OperationNotSupportedError,
                             QStringLiteral("%1 plugin %2 does not support locking")
                             .arg(type, name));
        } else if (!p->setLockCode(oldLockCode, newLockCode)) {
            *result = Result(Result::UnknownError,
                             QStringLiteral("Failed to set lock code for %1 plugin %2")
                             .arg(type, name));
        }
    };

    bool found = true;
    Result result(Result::Succeeded);
    if (storagePlugins.contains(lockCodeTarget)) {
        lambda(storagePlugins.value(lockCodeTarget),
               QStringLiteral("storage"),
               lockCodeTarget,
               newAndOldLockCode.oldCode,
               newAndOldLockCode.newCode,
               &result);
    } else if (encryptedStoragePlugins.contains(lockCodeTarget)) {
        lambda(encryptedStoragePlugins.value(lockCodeTarget),
               QStringLiteral("encrypted storage"),
               lockCodeTarget,
               newAndOldLockCode.oldCode,
               newAndOldLockCode.newCode,
               &result);
    } else if (encryptionPlugins.contains(lockCodeTarget)) {
        lambda(encryptionPlugins.value(lockCodeTarget),
               QStringLiteral("encryption"),
               lockCodeTarget,
               newAndOldLockCode.oldCode,
               newAndOldLockCode.newCode,
               &result);
    } else {
        found = false;
    }

    return FoundResult(found, result);
}

bool Daemon::ApiImpl::masterLockPlugins(
        const QList<StoragePluginWrapper*> &storagePlugins,
        const QList<EncryptedStoragePluginWrapper*> &encryptedStoragePlugins)
{
    auto lambda = [] (PluginWrapper *p,
                      const QString &type,
                      bool *succeeded) {
        if (!p->isMasterLocked()) {
            if (!p->masterLock()) {
                qCWarning(lcSailfishSecretsDaemon) << "Failed to master-lock" << type << "plugin:" << p->name();
                *succeeded = false;
            }
        }
    };

    bool allSucceeded = true;
    for (StoragePluginWrapper *splugin : storagePlugins) {
        lambda(splugin, QStringLiteral("storage"), &allSucceeded);
    }
    for (EncryptedStoragePluginWrapper *esplugin : encryptedStoragePlugins) {
        lambda(esplugin, QStringLiteral("encrypted storage"), &allSucceeded);
    }
    return allSucceeded;
}

bool Daemon::ApiImpl::masterUnlockPlugins(
        const QList<StoragePluginWrapper*> &storagePlugins,
        const QList<EncryptedStoragePluginWrapper*> &encryptedStoragePlugins,
        const QByteArray &encryptionKey)
{
    auto lambda = [] (PluginWrapper *p,
                      const QByteArray &key,
                      const QString &type,
                      bool *succeeded) {
        if (p->isMasterLocked()) {
            if (!p->masterUnlock(key)) {
                qCWarning(lcSailfishSecretsDaemon) << "Failed to master-unlock" << type << "plugin:" << p->name();
                *succeeded = false;
            }
        }
    };

    bool allSucceeded = true;
    for (StoragePluginWrapper *splugin : storagePlugins) {
        lambda(splugin, encryptionKey, QStringLiteral("storage"), &allSucceeded);
    }
    for (EncryptedStoragePluginWrapper *esplugin : encryptedStoragePlugins) {
        lambda(esplugin, encryptionKey, QStringLiteral("encrypted storage"), &allSucceeded);
    }
    return allSucceeded;
}

bool Daemon::ApiImpl::modifyMasterLockPlugins(
        const QList<StoragePluginWrapper*> &storagePlugins,
        const QList<EncryptedStoragePluginWrapper*> &encryptedStoragePlugins,
        const QByteArray &oldEncryptionKey,
        const QByteArray &newEncryptionKey)
{
    auto lambda = [] (PluginWrapper *p,
                      const QByteArray &oldKey,
                      const QByteArray &newKey,
                      const QString &type,
                      bool *succeeded) {
        if (p->isMasterLocked()) {
            if (!p->masterUnlock(oldKey)) {
                qCWarning(lcSailfishSecretsDaemon) << "Failed to master-unlock" << type << "plugin:" << p->name();
            }
        }
        if (!p->setMasterLockKey(oldKey, newKey)) {
            qCWarning(lcSailfishSecretsDaemon) << "Failed to set master lock code for" << type << "plugin:" << p->name();
            *succeeded = false;
        }
    };

    bool allSucceeded = true;
    for (StoragePluginWrapper *splugin : storagePlugins) {
        lambda(splugin, oldEncryptionKey, newEncryptionKey, QStringLiteral("storage"), &allSucceeded);
    }
    for (EncryptedStoragePluginWrapper *esplugin : encryptedStoragePlugins) {
        lambda(esplugin, oldEncryptionKey, newEncryptionKey, QStringLiteral("encrypted storage"), &allSucceeded);
    }
    return allSucceeded;
}

IdentifiersResult Daemon::ApiImpl::storedKeyIdentifiers(
        StoragePluginWrapper *storagePlugin,
        EncryptedStoragePluginWrapper *encryptedStoragePlugin,
        Sailfish::Crypto::Daemon::ApiImpl::CryptoStoragePluginWrapper *cryptoStoragePlugin)
{
    auto lambda = [] (PluginWrapper *p,
                      Result *result,
                      QVector<Secret::Identifier> *idents) {
        QStringList cnames;
        QStringList knames;
        *result = p->collectionNames(&cnames);
        if (result->code() != Result::Succeeded) {
            return;
        }
        for (const QString &cname : cnames) {
            knames.clear();
            *result = p->keyNames(cname, &knames);
            if (result->code() != Result::Succeeded
                    && result->errorCode() != Result::CollectionIsLockedError) {
                return;
            }
            for (const QString &kname : knames) {
                idents->append(Secret::Identifier(
                        kname, cname, p->name()));
            }
        }
    };

    Result result = Result(Result::InvalidExtensionPluginError,
                           QStringLiteral("No storage plugin specified"));
    QVector<Secret::Identifier> idents;
    if (storagePlugin) {
        lambda(storagePlugin, &result, &idents);
    } else if (cryptoStoragePlugin) { // order of check is important!
        lambda(cryptoStoragePlugin, &result, &idents);
    } else if (encryptedStoragePlugin) {
        lambda(encryptedStoragePlugin, &result, &idents);
    }
    return IdentifiersResult(result, idents);
}

bool EncryptionPluginFunctionWrapper::isLocked(EncryptionPlugin *plugin)
{
    return plugin->isLocked();
}

bool EncryptionPluginFunctionWrapper::lock(EncryptionPlugin *plugin)
{
    return plugin->lock();
}

bool EncryptionPluginFunctionWrapper::unlock(EncryptionPlugin *plugin,
                                     const QByteArray &lockCode)
{
    return plugin->unlock(lockCode);
}

bool setLockCode(EncryptionPlugin *plugin,
                 const QByteArray &oldLockCode,
                 const QByteArray &newLockCode)
{
    return plugin->setLockCode(oldLockCode, newLockCode);
}

DerivedKeyResult
EncryptionPluginFunctionWrapper::deriveKeyFromCode(
        EncryptionPlugin *plugin,
        const QByteArray &authenticationCode,
        const QByteArray &salt)
{
    QByteArray key;
    Result result = plugin->deriveKeyFromCode(authenticationCode, salt, &key);
    return DerivedKeyResult(result, key);
}

EncryptionPluginFunctionWrapper::DataResult
EncryptionPluginFunctionWrapper::encryptSecret(
        EncryptionPlugin *plugin,
        const QByteArray &plaintext,
        const QByteArray &key)
{
    QByteArray ciphertext;
    Result result = plugin->encryptSecret(plaintext, key, &ciphertext);
    return EncryptionPluginFunctionWrapper::DataResult(result, ciphertext);
}

EncryptionPluginFunctionWrapper::DataResult
EncryptionPluginFunctionWrapper::decryptSecret(
        EncryptionPlugin *plugin,
        const QByteArray &encrypted,
        const QByteArray &key)
{
    QByteArray plaintext;
    Result result = plugin->decryptSecret(encrypted, key, &plaintext);
    return EncryptionPluginFunctionWrapper::DataResult(result, plaintext);
}

bool StoragePluginFunctionWrapper::isLocked(StoragePluginWrapper *plugin)
{
    return plugin->isLocked();
}

bool StoragePluginFunctionWrapper::lock(StoragePluginWrapper *plugin)
{
    return plugin->lock();
}

bool StoragePluginFunctionWrapper::unlock(
        StoragePluginWrapper *plugin,
        const QByteArray &lockCode)
{
    return plugin->unlock(lockCode);
}

bool StoragePluginFunctionWrapper::setLockCode(
        StoragePluginWrapper *plugin,
        const QByteArray &oldLockCode,
        const QByteArray &newLockCode)
{
    return plugin->setLockCode(oldLockCode, newLockCode);
}

CollectionMetadataResult StoragePluginFunctionWrapper::collectionMetadata(
        StoragePluginWrapper *plugin,
        const QString &collectionName)
{
    CollectionMetadata metadata;
    Result result = plugin->collectionMetadata(collectionName, &metadata);
    return CollectionMetadataResult(result, metadata);
}

SecretMetadataResult StoragePluginFunctionWrapper::secretMetadata(
        StoragePluginWrapper *plugin,
        const QString &collectionName,
        const QString &secretName)
{
    SecretMetadata metadata;
    Result result = plugin->secretMetadata(collectionName, secretName, &metadata);
    return SecretMetadataResult(result, metadata);
}

CollectionNamesResult StoragePluginFunctionWrapper::collectionNames(
        StoragePluginWrapper *plugin)
{
    QStringList cnames;
    Result result = plugin->collectionNames(&cnames);
    return CollectionNamesResult(result, cnames);
}

Result StoragePluginFunctionWrapper::createCollection(
        StoragePluginWrapper *plugin,
        const CollectionMetadata &metadata)
{
    return plugin->createCollection(metadata);
}

Result StoragePluginFunctionWrapper::removeCollection(
        StoragePluginWrapper *plugin,
        const QString &collectionName)
{
    return plugin->removeCollection(collectionName);
}

Result StoragePluginFunctionWrapper::setSecret(
        StoragePluginWrapper *plugin,
        const SecretMetadata &secretMetadata,
        const QByteArray &secret,
        const Secret::FilterData &filterData)
{
    return plugin->setSecret(secretMetadata,
                             secret,
                             filterData);
}

SecretDataResult
StoragePluginFunctionWrapper::getSecret(
        StoragePluginWrapper *plugin,
        const QString &collectionName,
        const QString &secretName)
{
    QByteArray secret;
    Secret::FilterData filterData;
    Result result = plugin->getSecret(collectionName,
                                      secretName,
                                      &secret,
                                      &filterData);
    return SecretDataResult(
                result, secret, filterData);
}

Result StoragePluginFunctionWrapper::removeSecret(
        StoragePluginWrapper *plugin,
        const QString &collectionName,
        const QString &secretName)
{
    return plugin->removeSecret(collectionName,
                                secretName);
}

Result StoragePluginFunctionWrapper::reencrypt(
        StoragePluginWrapper *plugin,
        const QString &collectionName,
        const QString &secretNames,
        const QByteArray &oldkey,
        const QByteArray &newkey,
        EncryptionPlugin *encryptionPlugin)
{
    return plugin->reencrypt(collectionName,
                             secretNames,
                             oldkey,
                             newkey,
                             encryptionPlugin);
}

Result StoragePluginFunctionWrapper::encryptAndStoreSecret(
        EncryptionPlugin *encryptionPlugin,
        StoragePluginWrapper *storagePlugin,
        const SecretMetadata &secretMetadata,
        const Secret &secret,
        const QByteArray &encryptionKey)
{
    QByteArray encrypted;
    Result pluginResult = encryptionPlugin->encryptSecret(
                secret.data(), encryptionKey, &encrypted);
    if (pluginResult.code() == Result::Succeeded) {
        pluginResult = storagePlugin->setSecret(
                    secretMetadata,
                    encrypted,
                    secret.filterData());
    }
    return pluginResult;
}

SecretResult StoragePluginFunctionWrapper::getAndDecryptSecret(
        EncryptionPlugin *encryptionPlugin,
        StoragePluginWrapper *storagePlugin,
        const Secret::Identifier &identifier,
        const QByteArray &encryptionKey)
{
    Secret secret;
    QByteArray encrypted;
    Secret::FilterData filterData;
    Result pluginResult = storagePlugin->getSecret(
                identifier.collectionName(),
                identifier.name(),
                &encrypted,
                &filterData);
    if (pluginResult.code() == Result::Succeeded) {
        QByteArray decrypted;
        pluginResult = encryptionPlugin->decryptSecret(encrypted, encryptionKey, &decrypted);
        secret.setData(decrypted);
        secret.setIdentifier(identifier);
        secret.setFilterData(filterData);
    }

    return SecretResult(pluginResult, secret);
}

IdentifiersResult
StoragePluginFunctionWrapper::findSecrets(
        StoragePluginWrapper *storagePlugin,
        const QString &collectionName,
        const Sailfish::Secrets::Secret::FilterData &filter,
        Sailfish::Secrets::StoragePlugin::FilterOperator filterOp)
{
    QVector<Secret::Identifier> identifiers;
    QStringList secretNames;
    Result pluginResult = storagePlugin->findSecrets(collectionName, filter, filterOp, &secretNames);
    for (const QString &secretName : secretNames) {
        identifiers.append(Secret::Identifier(secretName, collectionName, storagePlugin->name()));
    }

    return IdentifiersResult(pluginResult, identifiers);
}

Result
StoragePluginFunctionWrapper::reencryptDeviceLockedCollectionsAndSecrets(
        StoragePluginWrapper *plugin,
        const QMap<QString, EncryptionPlugin*> encryptionPlugins,
        const QByteArray &oldEncryptionKey,
        const QByteArray &newEncryptionKey)
{
    // get collection names
    // foreach collection, get metadata
    // if usesDeviceLockKey, re-encrypt
    QStringList cnames;
    Result result = plugin->collectionNames(&cnames);
    if (result.code() != Result::Succeeded) {
        return result;
    }
    QMap<QString, EncryptionPlugin*> reencryptCollections;
    for (const QString &cname : cnames) {
        CollectionMetadata metadata;
        result = plugin->collectionMetadata(cname, &metadata);
        if (result.code() != Result::Succeeded) {
            return result;
        }

        if (metadata.usesDeviceLockKey) {
            if (!encryptionPlugins.contains(metadata.encryptionPluginName)) {
                // TODO: stale data in metadata db?
                return Result(Result::InvalidExtensionPluginError,
                              QStringLiteral("Unknown collection encryption plugin %1")
                              .arg(metadata.encryptionPluginName));
            }
            reencryptCollections.insert(cname, encryptionPlugins.value(metadata.encryptionPluginName));
        }
    }

    // get standalone secret names
    // foreach secret, get metadata
    // if usesDeviceLockKey, re-encrypt
    QStringList snames;
    result = plugin->secretNames(QString(), &snames);
    if (result.code() != Result::Succeeded) {
        return result;
    }
    QMap<QString, EncryptionPlugin*> reencryptSecrets;
    for (const QString &sname : snames) {
        SecretMetadata metadata;
        result = plugin->secretMetadata(QString(), sname, &metadata);
        if (result.code() != Result::Succeeded) {
            return result;
        }

        if (metadata.usesDeviceLockKey) {
            if (!encryptionPlugins.contains(metadata.encryptionPluginName)) {
                // TODO: stale data in metadata db?
                return Result(Result::InvalidExtensionPluginError,
                              QStringLiteral("Unknown secret encryption plugin %1")
                              .arg(metadata.encryptionPluginName));
            }
            reencryptSecrets.insert(sname, encryptionPlugins.value(metadata.encryptionPluginName));
        }
    }

    // Now re-encrypt the collections and secrets.
    for (const QString &cname : reencryptCollections.keys()) {
        Result cresult =  plugin->reencrypt(
                    cname,
                    QString(),
                    oldEncryptionKey,
                    newEncryptionKey,
                    reencryptCollections.value(cname));
        if (!cresult.code() == Result::Succeeded) {
            result = cresult;
        }
    }
    for (const QString &sname : reencryptSecrets.keys()) {
        Result sresult = plugin->reencrypt(QString(),
                    sname,
                    oldEncryptionKey,
                    newEncryptionKey,
                    reencryptSecrets.value(sname));
        if (!sresult.code() == Result::Succeeded) {
            result = sresult;
        }
    }
    return result;
}

Result
StoragePluginFunctionWrapper::collectionSecretPreCheck(
        StoragePluginWrapper *plugin,
        const QString &collectionName,
        const QString &secretName)
{
    QStringList cnames;
    Result result = plugin->collectionNames(&cnames);
    if (result.code() != Result::Succeeded) {
        return result;
    }

    if (!cnames.contains(collectionName)) {
        return Result(Result::InvalidCollectionError,
                      QStringLiteral("No such collection %1 exists in plugin %2")
                      .arg(collectionName, plugin->name()));
    }

    SecretMetadata metadata;
    result = plugin->secretMetadata(collectionName, secretName, &metadata);
    if (result.code() == Result::Succeeded) {
        // this is bad, since it means that the secret already exists.
        return Result(Result::SecretAlreadyExistsError,
                      QStringLiteral("A secret with that name in this collection already exists"));
    } else if (result.errorCode() == Result::InvalidSecretError) {
        // this is good, the secret does not exist.
        return Result(Result::Succeeded);
    } else {
        // some database error occurred.
        return result;
    }
}

bool EncryptedStoragePluginFunctionWrapper::isLocked(EncryptedStoragePluginWrapper *plugin)
{
    return plugin->isLocked();
}

bool EncryptedStoragePluginFunctionWrapper::lock(EncryptedStoragePluginWrapper *plugin)
{
    return plugin->lock();
}

bool EncryptedStoragePluginFunctionWrapper::unlock(
        EncryptedStoragePluginWrapper *plugin,
        const QByteArray &lockCode)
{
    return plugin->unlock(lockCode);
}

bool EncryptedStoragePluginFunctionWrapper::setLockCode(
        EncryptedStoragePluginWrapper *plugin,
        const QByteArray &oldLockCode,
        const QByteArray &newLockCode)
{
    return plugin->setLockCode(oldLockCode, newLockCode);
}

CollectionMetadataResult EncryptedStoragePluginFunctionWrapper::collectionMetadata(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName)
{
    CollectionMetadata metadata;
    Result result = plugin->collectionMetadata(collectionName, &metadata);
    return CollectionMetadataResult(result, metadata);
}

SecretMetadataResult EncryptedStoragePluginFunctionWrapper::secretMetadata(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName,
        const QString &secretName)
{
    SecretMetadata metadata;
    Result result = plugin->secretMetadata(collectionName, secretName, &metadata);
    return SecretMetadataResult(result, metadata);
}

CollectionNamesResult EncryptedStoragePluginFunctionWrapper::collectionNames(
        EncryptedStoragePluginWrapper *plugin)
{
    QStringList cnames;
    Result result = plugin->collectionNames(&cnames);
    return CollectionNamesResult(result, cnames);
}

Result EncryptedStoragePluginFunctionWrapper::createCollection(
        EncryptedStoragePluginWrapper *plugin,
        const CollectionMetadata &metadata,
        const QByteArray &key)
{
    return plugin->createCollection(metadata, key);
}

Result EncryptedStoragePluginFunctionWrapper::removeCollection(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName)
{
    return plugin->removeCollection(collectionName);
}

LockedResult
EncryptedStoragePluginFunctionWrapper::isCollectionLocked(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName)
{
    bool locked = false;
    Result result = plugin->isCollectionLocked(collectionName, &locked);
    return LockedResult(result, locked);
}

DerivedKeyResult
EncryptedStoragePluginFunctionWrapper::deriveKeyFromCode(
        EncryptedStoragePluginWrapper *plugin,
        const QByteArray &authenticationCode,
        const QByteArray &salt)
{
    QByteArray key;
    Result result = plugin->deriveKeyFromCode(authenticationCode, salt, &key);
    return DerivedKeyResult(result, key);
}

Result EncryptedStoragePluginFunctionWrapper::setEncryptionKey(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName,
        const QByteArray &key)
{
    return plugin->setEncryptionKey(collectionName, key);
}

Result EncryptedStoragePluginFunctionWrapper::reencrypt(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName,
        const QByteArray &oldkey,
        const QByteArray &newkey)
{
    return plugin->reencrypt(collectionName,
                             oldkey,
                             newkey);
}

Result EncryptedStoragePluginFunctionWrapper::setSecret(
        EncryptedStoragePluginWrapper *plugin,
        const SecretMetadata &secretMetadata,
        const QByteArray &secret,
        const Secret::FilterData &filterData)
{
    return plugin->setSecret(secretMetadata,
                             secret,
                             filterData);
}

SecretDataResult
EncryptedStoragePluginFunctionWrapper::getSecret(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName,
        const QString &secretName)
{
    QByteArray secret;
    Secret::FilterData filterData;
    Result result = plugin->getSecret(collectionName,
                                      secretName,
                                      &secret,
                                      &filterData);
    return SecretDataResult(
                result, secret, filterData);
}

IdentifiersResult
EncryptedStoragePluginFunctionWrapper::findSecrets(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName,
        const Secret::FilterData &filter,
        StoragePlugin::FilterOperator filterOperator)
{
    QVector<Secret::Identifier> identifiers;
    Result result = plugin->findSecrets(collectionName,
                                        filter,
                                        filterOperator,
                                        &identifiers);
    return IdentifiersResult(result, identifiers);
}

Result EncryptedStoragePluginFunctionWrapper::removeSecret(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName,
        const QString &secretName)
{
    return plugin->removeSecret(collectionName,
                                secretName);
}

Result EncryptedStoragePluginFunctionWrapper::setStandaloneSecret(
        EncryptedStoragePluginWrapper *plugin,
        const SecretMetadata &secretMetadata,
        const Secret &secret,
        const QByteArray &key)
{
    return plugin->setSecret(secretMetadata,
                             secret.data(),
                             secret.filterData(),
                             key);
}

SecretDataResult
EncryptedStoragePluginFunctionWrapper::accessStandaloneSecret(
        EncryptedStoragePluginWrapper *plugin,
        const QString &secretName,
        const QByteArray &key)
{
    QByteArray secret;
    Secret::FilterData filterData;
    Result result = plugin->accessSecret(secretName,
                                         key,
                                         &secret,
                                         &filterData);
    return SecretDataResult(
                result, secret, filterData);
}

Result EncryptedStoragePluginFunctionWrapper::unlockCollectionAndStoreSecret(
        EncryptedStoragePluginWrapper *plugin,
        const SecretMetadata &secretMetadata,
        const Secret &secret,
        const QByteArray &encryptionKey)
{
    bool locked = false;
    Result pluginResult = plugin->isCollectionLocked(secret.identifier().collectionName(), &locked);
    if (pluginResult.code() == Result::Succeeded) {
        if (locked) {
            pluginResult = plugin->setEncryptionKey(secret.identifier().collectionName(), encryptionKey);
            if (pluginResult.code() != Result::Succeeded) {
                // unable to apply the new encryptionKey.
                plugin->setEncryptionKey(secret.identifier().collectionName(), QByteArray());
                return Result(Result::SecretsPluginDecryptionError,
                              QString::fromLatin1("Unable to decrypt collection %1 with the entered authentication key").arg(secret.identifier().collectionName()));

            }
            pluginResult = plugin->isCollectionLocked(secret.identifier().collectionName(), &locked);
            if (pluginResult.code() != Result::Succeeded) {
                plugin->setEncryptionKey(secret.identifier().collectionName(), QByteArray());
                return Result(Result::SecretsPluginDecryptionError,
                              QString::fromLatin1("Unable to check lock state of collection %1 after setting the entered authentication key").arg(secret.identifier().collectionName()));

            }
        }
        if (locked) {
            // still locked, even after applying the new encryptionKey?  The authenticationCode was wrong.
            plugin->setEncryptionKey(secret.identifier().collectionName(), QByteArray());
            return Result(Result::IncorrectAuthenticationCodeError,
                          QString::fromLatin1("The authentication code entered for collection %1 was incorrect").arg(secret.identifier().collectionName()));
        } else {
            // successfully unlocked the encrypted storage collection.  write the secret.
            pluginResult = plugin->setSecret(secretMetadata, secret.data(), secret.filterData());
        }
    }
    return pluginResult;
}

SecretResult EncryptedStoragePluginFunctionWrapper::unlockCollectionAndReadSecret(
        EncryptedStoragePluginWrapper *plugin,
        const Secret::Identifier &identifier,
        const QByteArray &encryptionKey)
{
    Secret secret;
    bool locked = false;
    Result pluginResult = plugin->isCollectionLocked(identifier.collectionName(), &locked);
    if (pluginResult.code() != Result::Succeeded) {
        return SecretResult(pluginResult, secret);
    }

    // if it's locked, attempt to unlock it
    if (locked) {
        pluginResult = plugin->setEncryptionKey(identifier.collectionName(), encryptionKey);
        if (pluginResult.code() != Result::Succeeded) {
            // unable to apply the new encryptionKey.
            plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
            return SecretResult(Result(Result::SecretsPluginDecryptionError,
                                       QString::fromLatin1("Unable to decrypt collection %1 with the entered authentication key")
                                       .arg(identifier.collectionName())),
                                secret);

        }
        pluginResult = plugin->isCollectionLocked(identifier.collectionName(), &locked);
        if (pluginResult.code() != Result::Succeeded) {
            plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
            return SecretResult(Result(Result::SecretsPluginDecryptionError,
                                       QString::fromLatin1("Unable to check lock state of collection %1 after setting the entered authentication key")
                                       .arg(identifier.collectionName())),
                                secret);

        }
    }

    if (locked) {
        // still locked, even after applying the new encryptionKey?  The authenticationCode was wrong.
        plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
        return SecretResult(Result(Result::IncorrectAuthenticationCodeError,
                                   QString::fromLatin1("The authentication code entered for collection %1 was incorrect")
                                   .arg(identifier.collectionName())),
                            secret);
    }

    // successfully unlocked the encrypted storage collection.  read the secret.
    QByteArray secretData;
    Secret::FilterData secretFilterdata;
    pluginResult = plugin->getSecret(identifier.collectionName(), identifier.name(), &secretData, &secretFilterdata);
    secret.setData(secretData);
    secret.setFilterData(secretFilterdata);
    secret.setIdentifier(identifier);
    return SecretResult(pluginResult, secret);
}

Result EncryptedStoragePluginFunctionWrapper::unlockCollectionAndRemoveSecret(
        EncryptedStoragePluginWrapper *plugin,
        const Secret::Identifier &identifier,
        const QByteArray &encryptionKey)
{
    bool locked = false;
    Result pluginResult = plugin->isCollectionLocked(identifier.collectionName(), &locked);
    if (pluginResult.code() != Result::Succeeded) {
        return pluginResult;
    }

    // if it's locked, attempt to unlock it
    if (locked) {
        pluginResult = plugin->setEncryptionKey(identifier.collectionName(), encryptionKey);
        if (pluginResult.code() != Result::Succeeded) {
            // unable to apply the new encryptionKey.
            plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
            return Result(Result::SecretsPluginDecryptionError,
                          QString::fromLatin1("Unable to decrypt collection %1 with the entered authentication key").arg(identifier.collectionName()));

        }
        pluginResult = plugin->isCollectionLocked(identifier.collectionName(), &locked);
        if (pluginResult.code() != Result::Succeeded) {
            plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
            return Result(Result::SecretsPluginDecryptionError,
                          QString::fromLatin1("Unable to check lock state of collection %1 after setting the entered authentication key").arg(identifier.collectionName()));

        }
    }
    if (locked) {
        // still locked, even after applying the new encryptionKey?  The authenticationCode was wrong.
        plugin->setEncryptionKey(identifier.collectionName(), QByteArray());
        return Result(Result::IncorrectAuthenticationCodeError,
                      QString::fromLatin1("The authentication code entered for collection %1 was incorrect").arg(identifier.collectionName()));
    }

    // successfully unlocked the encrypted storage collection.  remove the secret.
    pluginResult = plugin->removeSecret(identifier.collectionName(), identifier.name());
    return pluginResult;
}

IdentifiersResult
EncryptedStoragePluginFunctionWrapper::unlockAndFindSecrets(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName,
        const Secret::FilterData &filter,
        StoragePlugin::FilterOperator filterOperator,
        const QByteArray &encryptionKey)
{
    QVector<Secret::Identifier> identifiers;
    bool locked = false;
    Result pluginResult = plugin->isCollectionLocked(collectionName, &locked);
    if (pluginResult.code() != Result::Succeeded) {
        return IdentifiersResult(pluginResult, identifiers);
    }

    // if it's locked, attempt to unlock it
    if (locked) {
        pluginResult = plugin->setEncryptionKey(collectionName, encryptionKey);
        if (pluginResult.code() != Result::Succeeded) {
            // unable to apply the new encryptionKey.
            plugin->setEncryptionKey(collectionName, QByteArray());
            return IdentifiersResult(Result(Result::SecretsPluginDecryptionError,
                                            QString::fromLatin1("Unable to decrypt collection %1 with the entered authentication key")
                                            .arg(collectionName)),
                                     identifiers);

        }
        pluginResult = plugin->isCollectionLocked(collectionName, &locked);
        if (pluginResult.code() != Result::Succeeded) {
            plugin->setEncryptionKey(collectionName, QByteArray());
            return IdentifiersResult(Result(Result::SecretsPluginDecryptionError,
                                            QString::fromLatin1("Unable to check lock state of collection %1 after setting the entered authentication key")
                                            .arg(collectionName)),
                                     identifiers);

        }
    }

    if (locked) {
        // still locked, even after applying the new encryptionKey?  The authenticationCode was wrong.
        plugin->setEncryptionKey(collectionName, QByteArray());
        return IdentifiersResult(Result(Result::IncorrectAuthenticationCodeError,
                                        QString::fromLatin1("The authentication code entered for collection %1 was incorrect")
                                        .arg(collectionName)),
                                 identifiers);
    }

    // successfully unlocked the encrypted storage collection.  perform the filtering operation.
    pluginResult = plugin->findSecrets(collectionName, filter, static_cast<StoragePlugin::FilterOperator>(filterOperator), &identifiers);
    return IdentifiersResult(pluginResult, identifiers);
}

Result EncryptedStoragePluginFunctionWrapper::unlockAndRemoveSecret(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName,
        const QString &secretName,
        bool secretUsesDeviceLockKey,
        const QByteArray &deviceLockKey)
{
    bool locked = false;
    Result pluginResult = plugin->isCollectionLocked(collectionName, &locked);
    if (pluginResult.code() == Result::Failed) {
        return pluginResult;
    }
    if (locked && secretUsesDeviceLockKey) {
        pluginResult = plugin->setEncryptionKey(collectionName, deviceLockKey);
        if (pluginResult.code() == Result::Failed) {
            return pluginResult;
        }
    }
    pluginResult = plugin->removeSecret(collectionName, secretName);
    if (locked) {
        // relock after delete-access.
        plugin->setEncryptionKey(collectionName, QByteArray());
    }

    return pluginResult;
}

Result EncryptedStoragePluginFunctionWrapper::unlockDeviceLockedCollectionsAndReencrypt(
        EncryptedStoragePluginWrapper *plugin,
        const QByteArray &oldEncryptionKey,
        const QByteArray &newEncryptionKey)
{
    // find out which collections are device-locked
    QStringList cnames;
    Result result = plugin->collectionNames(&cnames);
    if (result.code() != Result::Succeeded) {
        return result;
    }

    QStringList reencryptCNames;
    for (const QString &cname : cnames) {
        CollectionMetadata metadata;
        result = plugin->collectionMetadata(cname, &metadata);
        if (result.code() != Result::Succeeded) {
            return result;
        }
        if (metadata.usesDeviceLockKey) {
            reencryptCNames.append(cname);
        }
    }

    // re-encrypt every device-locked collection
    for (const QString &collectionName : reencryptCNames) {
        bool collectionLocked = true;
        plugin->isCollectionLocked(collectionName, &collectionLocked);
        if (collectionLocked) {
            Result collectionUnlockResult = plugin->setEncryptionKey(collectionName, oldEncryptionKey);
            if (collectionUnlockResult.code() != Result::Succeeded) {
                qCWarning(lcSailfishSecretsDaemon) << "Error unlocking collection:" << collectionName
                                                   << collectionUnlockResult.errorMessage();
            }
            plugin->isCollectionLocked(collectionName, &collectionLocked);
            if (collectionLocked) {
                qCWarning(lcSailfishSecretsDaemon) << "Failed to unlock collection:" << collectionName;
            }
        }
        Result collectionReencryptResult = plugin->reencrypt(
                    collectionName, oldEncryptionKey, newEncryptionKey);
        if (collectionReencryptResult.code() != Result::Succeeded) {
            qCWarning(lcSailfishSecretsDaemon) << "Failed to re-encrypt encrypted storage collection:"
                                               << collectionName
                                               << collectionReencryptResult.code()
                                               << collectionReencryptResult.errorMessage();
            result = collectionReencryptResult;
        }
    }

    return result;
}


Result EncryptedStoragePluginFunctionWrapper::deriveKeyUnlockAndRemoveCollection(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName,
        const QByteArray &lockCode,
        const QByteArray &salt)
{
    bool locked = false;
    Result result = plugin->isCollectionLocked(collectionName, &locked);
    if (result.code() != Result::Succeeded) {
        return result;
    }

    if (locked) {
        QByteArray derivedKey;
        result = plugin->deriveKeyFromCode(lockCode, salt, &derivedKey);
        if (result.code() != Result::Succeeded) {
            return result;
        }

        result = plugin->setEncryptionKey(collectionName, derivedKey);
        if (result.code() != Result::Succeeded) {
            return result;
        }

        locked = false;
        result = plugin->isCollectionLocked(collectionName, &locked);
        if (result.code() != Result::Succeeded) {
            return result;
        } else if (locked) {
            return Result(Result::CollectionIsLockedError,
                          QStringLiteral("Invalid lock code, unable to unlock collection to delete"));
        }
    }

    return plugin->removeCollection(collectionName);
}

Result EncryptedStoragePluginFunctionWrapper::collectionSecretPreCheck(
        EncryptedStoragePluginWrapper *plugin,
        const QString &collectionName,
        const QString &secretName,
        const QByteArray &collectionKey)
{
    QStringList cnames;
    Result result = plugin->collectionNames(&cnames);
    if (result.code() != Result::Succeeded) {
        return result;
    }

    if (!cnames.contains(collectionName)) {
        return Result(Result::InvalidCollectionError,
                      QStringLiteral("No such collection %1 exists in plugin %2")
                      .arg(collectionName, plugin->name()));
    }

    bool locked = false;
    result = plugin->isCollectionLocked(collectionName, &locked);
    if (result.code() != Result::Succeeded) {
        return result;
    }

    if (locked) {
        result = plugin->setEncryptionKey(collectionName, collectionKey);
        if (result.code() != Result::Succeeded) {
            return result;
        }

        locked = false;
        result = plugin->isCollectionLocked(collectionName, &locked);
        if (result.code() != Result::Succeeded) {
            return result;
        } else if (locked) {
            return Result(Result::CollectionIsLockedError,
                          QStringLiteral("Invalid lock code, unable to unlock collection"));
        }
    }

    SecretMetadata metadata;
    result = plugin->secretMetadata(collectionName, secretName, &metadata);
    if (result.code() == Result::Succeeded) {
        // this is bad, since it means that the secret already exists.
        return Result(Result::SecretAlreadyExistsError,
                      QStringLiteral("A secret with that name in this collection already exists"));
    } else if (result.errorCode() == Result::InvalidSecretError) {
        // this is good, the secret does not exist.
        return Result(Result::Succeeded);
    } else {
        // some database error occurred.
        return result;
    }
}
