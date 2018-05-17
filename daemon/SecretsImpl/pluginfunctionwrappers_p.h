/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APIIMPL_PLUGINFUNCTIONWRAPPERS_P_H
#define SAILFISHSECRETS_APIIMPL_PLUGINFUNCTIONWRAPPERS_P_H

#include "CryptoImpl/cryptopluginwrapper_p.h"
#include "SecretsImpl/pluginwrapper_p.h"
#include "SecretsImpl/metadatadb_p.h"

#include "SecretsPluginApi/extensionplugins.h"

#include "Secrets/secret.h"
#include "Secrets/interactionparameters.h"
#include "Secrets/secretmanager.h"
#include "Secrets/result.h"
#include "Secrets/lockcoderequest.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace ApiImpl {

struct SecretResult {
    SecretResult(const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result(),
                 const Sailfish::Secrets::Secret &s = Sailfish::Secrets::Secret())
        : result(r), secret(s) {}
    SecretResult(const SecretResult &other)
        : result(other.result), secret(other.secret) {}
    Sailfish::Secrets::Result result;
    Sailfish::Secrets::Secret secret;
};

struct SecretMetadataResult {
    SecretMetadataResult(const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result(),
                         const SecretMetadata &s = SecretMetadata())
        : result(r), metadata(s) {}
    SecretMetadataResult(const SecretMetadataResult &other)
        : result(other.result), metadata(other.metadata) {}
    Sailfish::Secrets::Result result;
    SecretMetadata metadata;
};

struct CollectionMetadataResult {
    CollectionMetadataResult(const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result(),
                             const CollectionMetadata &c = CollectionMetadata())
        : result(r), metadata(c) {}
    CollectionMetadataResult(const CollectionMetadataResult &other)
        : result(other.result), metadata(other.metadata) {}
    Sailfish::Secrets::Result result;
    CollectionMetadata metadata;
};

struct CollectionNamesResult {
    CollectionNamesResult(const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result(),
                      const QStringList &cns = QStringList())
        : result(r), collectionNames(cns) {}
    CollectionNamesResult(const CollectionNamesResult &other)
        : result(other.result), collectionNames(other.collectionNames) {}
    Sailfish::Secrets::Result result;
    QStringList collectionNames;
};

struct IdentifiersResult {
    IdentifiersResult(const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result(),
                      const QVector<Sailfish::Secrets::Secret::Identifier> &i = QVector<Sailfish::Secrets::Secret::Identifier>())
        : result(r), identifiers(i) {}
    IdentifiersResult(const IdentifiersResult &other)
        : result(other.result), identifiers(other.identifiers) {}
    Sailfish::Secrets::Result result;
    QVector<Sailfish::Secrets::Secret::Identifier> identifiers;
};

struct DerivedKeyResult {
    DerivedKeyResult(const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result(),
                     const QByteArray &k = QByteArray())
        : result(r), key(k) {}
    DerivedKeyResult(const DerivedKeyResult &other)
        : result(other.result), key(other.key) {}
    Sailfish::Secrets::Result result;
    QByteArray key;
};

struct FoundResult {
    FoundResult(bool f = false, const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result())
        : found(f), result(r) {}
    FoundResult(const FoundResult &other)
        : found(other.found), result(other.result) {}
    bool found;
    Sailfish::Secrets::Result result;
};

struct FoundLockStatusResult {
    FoundLockStatusResult(bool f = false,
                          Sailfish::Secrets::LockCodeRequest::LockStatus s = Sailfish::Secrets::LockCodeRequest::Unknown,
                          const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result())
        : found(f), lockStatus(s), result(r) {}
    FoundLockStatusResult(const FoundLockStatusResult &other)
        : found(other.found), lockStatus(other.lockStatus), result(other.result) {}
    bool found;
    Sailfish::Secrets::LockCodeRequest::LockStatus lockStatus;
    Sailfish::Secrets::Result result;
};

struct LockedResult {
    LockedResult(const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result(),
                 bool l = false)
        : result(r), locked(l) {}
    LockedResult(const LockedResult &other)
        : result(other.result), locked(other.locked) {}
    Sailfish::Secrets::Result result;
    bool locked;
};

struct SecretDataResult {
    SecretDataResult(const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result(),
                     const QByteArray &sd = QByteArray(),
                     const Sailfish::Secrets::Secret::FilterData &sfd = Sailfish::Secrets::Secret::FilterData())
        : result(r), secretData(sd), secretFilterData(sfd) {}
    SecretDataResult(const SecretDataResult &other)
        : result(other.result)
        , secretData(other.secretData)
        , secretFilterData(other.secretFilterData) {}
    Sailfish::Secrets::Result result;
    QByteArray secretData;
    Sailfish::Secrets::Secret::FilterData secretFilterData;
};

struct LockCodes {
    LockCodes(const QByteArray &o, const QByteArray &n)
        : oldCode(o), newCode(n) {}
    LockCodes(const LockCodes &other)
        : oldCode(other.oldCode)
        , newCode(other.newCode) {}
    QByteArray oldCode;
    QByteArray newCode;
};

struct CollectionInfo {
    CollectionInfo(const QString &name, const QByteArray &key, bool relock)
        : collectionName(name), collectionKey(key), relockRequired(relock) {}
    CollectionInfo(const CollectionInfo &other)
        : collectionName(other.collectionName)
        , collectionKey(other.collectionKey)
        , relockRequired(other.relockRequired) {}
    QString collectionName;
    QByteArray collectionKey;
    bool relockRequired;
};

struct PluginState {
    PluginState(bool a = false, bool l = false)
        : available(a), locked(l) {}
    PluginState(const PluginState &other)
        : available(other.available)
        , locked(other.locked) {}
    bool available;
    bool locked;
};

PluginState pluginState(PluginBase *plugin);

FoundLockStatusResult queryLockSpecificPlugin(
        const QMap<QString, Sailfish::Secrets::EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, StoragePluginWrapper*> &storagePlugins,
        const QMap<QString, EncryptedStoragePluginWrapper*> &encryptedStoragePlugins,
        const QString &lockCodeTarget);

FoundResult lockSpecificPlugin(
        const QMap<QString, Sailfish::Secrets::EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, StoragePluginWrapper*> &storagePlugins,
        const QMap<QString, EncryptedStoragePluginWrapper*> &encryptedStoragePlugins,
        const QString &lockCodeTarget);

FoundResult unlockSpecificPlugin(
        const QMap<QString, Sailfish::Secrets::EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, StoragePluginWrapper*> &storagePlugins,
        const QMap<QString, EncryptedStoragePluginWrapper*> &encryptedStoragePlugins,
        const QString &lockCodeTarget,
        const QByteArray &lockCode);

FoundResult modifyLockSpecificPlugin(
        const QMap<QString, Sailfish::Secrets::EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, StoragePluginWrapper*> &storagePlugins,
        const QMap<QString, EncryptedStoragePluginWrapper*> &encryptedStoragePlugins,
        const QString &lockCodeTarget,
        const LockCodes &newAndOldLockCode);

bool masterLockPlugins(
        const QList<StoragePluginWrapper*> &storagePlugins,
        const QList<EncryptedStoragePluginWrapper*> &encryptedStoragePlugins);

bool masterUnlockPlugins(
        const QList<StoragePluginWrapper*> &storagePlugins,
        const QList<EncryptedStoragePluginWrapper*> &encryptedStoragePlugins,
        const QByteArray &encryptionKey);

bool modifyMasterLockPlugins(
        const QList<StoragePluginWrapper*> &storagePlugins,
        const QList<EncryptedStoragePluginWrapper*> &encryptedStoragePlugins,
        const QByteArray &oldEncryptionKey,
        const QByteArray &newEncryptionKey);

IdentifiersResult storedKeyIdentifiers(
        StoragePluginWrapper *storagePlugin,
        EncryptedStoragePluginWrapper *encryptedStoragePlugin,
        Sailfish::Crypto::Daemon::ApiImpl::CryptoStoragePluginWrapper *cryptoStoragePlugin,
        const QVariantMap &customParameters);

IdentifiersResult storedKeyIdentifiersFromCollection(
        StoragePluginWrapper *storagePlugin,
        EncryptedStoragePluginWrapper *encryptedStoragePlugin,
        Sailfish::Crypto::Daemon::ApiImpl::CryptoStoragePluginWrapper *cryptoStoragePlugin,
        const CollectionInfo &collectionInfo,
        const QVariantMap &customParameters);

namespace EncryptionPluginFunctionWrapper {
    struct DataResult {
        DataResult(const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result(),
                   const QByteArray &d = QByteArray())
            : result(r), data(d) {}
        DataResult(const DataResult &other)
            : result(other.result), data(other.data) {}
        Sailfish::Secrets::Result result;
        QByteArray data;
    };

    bool isLocked(Sailfish::Secrets::EncryptionPlugin *plugin);
    bool lock(Sailfish::Secrets::EncryptionPlugin *plugin);
    bool unlock(Sailfish::Secrets::EncryptionPlugin *plugin,
                const QByteArray &lockCode);
    bool setLockCode(Sailfish::Secrets::EncryptionPlugin *plugin,
                     const QByteArray &oldLockCode,
                     const QByteArray &newLockCode);
    DerivedKeyResult deriveKeyFromCode(
            Sailfish::Secrets::EncryptionPlugin *plugin,
            const QByteArray &authenticationCode,
            const QByteArray &salt);
    DataResult encryptSecret(
            Sailfish::Secrets::EncryptionPlugin *plugin,
            const QByteArray &plaintext,
            const QByteArray &key);
    DataResult decryptSecret(
            Sailfish::Secrets::EncryptionPlugin *plugin,
            const QByteArray &encrypted,
            const QByteArray &key);
} // EncryptionPluginWrapper

namespace StoragePluginFunctionWrapper {
    struct SecretNamesResult {
        SecretNamesResult(const Sailfish::Secrets::Result &r,
                          const QStringList &sns)
            : result(r), secretNames(sns) {}
        SecretNamesResult(const SecretNamesResult &other)
            : result(other.result), secretNames(other.secretNames) {}
        Sailfish::Secrets::Result result;
        QStringList secretNames;
    };

    bool isLocked(StoragePluginWrapper *plugin);
    bool lock(StoragePluginWrapper *plugin);
    bool unlock(
            StoragePluginWrapper *plugin,
            const QByteArray &lockCode);
    bool setLockCode(
            StoragePluginWrapper *plugin,
            const QByteArray &oldLockCode,
            const QByteArray &newLockCode);

    CollectionMetadataResult collectionMetadata(
            StoragePluginWrapper *plugin,
            const QString &collectionName);

    SecretMetadataResult secretMetadata(
            StoragePluginWrapper *plugin,
            const QString &collectionName,
            const QString &secretName);

    CollectionNamesResult collectionNames(
            StoragePluginWrapper *plugin);

    Sailfish::Secrets::Result createCollection(
            StoragePluginWrapper *plugin,
            const CollectionMetadata &collectionMetadata);
    Sailfish::Secrets::Result removeCollection(
            StoragePluginWrapper *plugin,
            const QString &collectionName);
    Sailfish::Secrets::Result setSecret(
            StoragePluginWrapper *plugin,
            const SecretMetadata &secretMetadata,
            const QByteArray &secret,
            const Sailfish::Secrets::Secret::FilterData &filterData);
    SecretDataResult getSecret(
            StoragePluginWrapper *plugin,
            const QString &collectionName,
            const QString &secretName);
    IdentifiersResult findSecrets(
            StoragePluginWrapper *plugin,
            const QString &collectionName,
            const Sailfish::Secrets::Secret::FilterData &filter,
            Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator);
    Sailfish::Secrets::Result removeSecret(
            StoragePluginWrapper *plugin,
            const QString &collectionName,
            const QString &secretName);

    Sailfish::Secrets::Result reencrypt(
            StoragePluginWrapper *plugin,
            const QString &collectionName,
            const QString &secretNames,
            const QByteArray &oldkey,
            const QByteArray &newkey,
            Sailfish::Secrets::EncryptionPlugin *encryptionPlugin);

    // compound operations
    Sailfish::Secrets::Result encryptAndStoreSecret(
            Sailfish::Secrets::EncryptionPlugin *encryptionPlugin,
            StoragePluginWrapper *storagePlugin,
            const SecretMetadata &secretMetadata,
            const Secret &secret,
            const QByteArray &encryptionKey);

    SecretResult getAndDecryptSecret(
            Sailfish::Secrets::EncryptionPlugin *encryptionPlugin,
            StoragePluginWrapper *storagePlugin,
            const Sailfish::Secrets::Secret::Identifier &identifier,
            const QByteArray &encryptionKey);

    Sailfish::Secrets::Result reencryptDeviceLockedCollectionsAndSecrets(
            StoragePluginWrapper *plugin,
            const QMap<QString, EncryptionPlugin*> encryptionPlugins,
            const QByteArray &oldEncryptionKey,
            const QByteArray &newEncryptionKey);

    Sailfish::Secrets::Result collectionSecretPreCheck(
            StoragePluginWrapper *plugin,
            const QString &collectionName,
            const QString &secretName);

} // StoragePluginWrapper

namespace EncryptedStoragePluginFunctionWrapper {
    bool isLocked(EncryptedStoragePluginWrapper *plugin);
    bool lock(EncryptedStoragePluginWrapper *plugin);
    bool unlock(
            EncryptedStoragePluginWrapper *plugin,
            const QByteArray &lockCode);
    bool setLockCode(
            EncryptedStoragePluginWrapper *plugin,
            const QByteArray &oldLockCode,
            const QByteArray &newLockCode);

    CollectionMetadataResult collectionMetadata(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName);

    SecretMetadataResult secretMetadata(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName,
            const QString &secretName);

    CollectionNamesResult collectionNames(
            EncryptedStoragePluginWrapper *plugin);

    Sailfish::Secrets::Result createCollection(
            EncryptedStoragePluginWrapper *plugin,
            const CollectionMetadata &metadata,
            const QByteArray &key);
    Sailfish::Secrets::Result removeCollection(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName);

    LockedResult isCollectionLocked(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName);
    DerivedKeyResult deriveKeyFromCode(
            EncryptedStoragePluginWrapper *plugin,
            const QByteArray &authenticationCode,
            const QByteArray &salt);
    Sailfish::Secrets::Result setEncryptionKey(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName,
            const QByteArray &key);
    Sailfish::Secrets::Result reencrypt(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName,
            const QByteArray &oldkey,
            const QByteArray &newkey);

    Sailfish::Secrets::Result setSecret(
            EncryptedStoragePluginWrapper *plugin,
            const SecretMetadata &secretMetadata,
            const QByteArray &secret,
            const Sailfish::Secrets::Secret::FilterData &filterData);
    SecretDataResult getSecret(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName,
            const QString &secretName);
    IdentifiersResult findSecrets(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName,
            const Sailfish::Secrets::Secret::FilterData &filter,
            Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator);

    Sailfish::Secrets::Result removeSecret(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName,
            const QString &secretName);

    Sailfish::Secrets::Result setStandaloneSecret(
            EncryptedStoragePluginWrapper *plugin,
            const SecretMetadata &secretMetadata,
            const Sailfish::Secrets::Secret &secret,
            const QByteArray &key);
    SecretDataResult accessStandaloneSecret(
            EncryptedStoragePluginWrapper *plugin,
            const QString &secretName,
            const QByteArray &key);

    // compound operations.
    Sailfish::Secrets::Result unlockCollectionAndStoreSecret(
            EncryptedStoragePluginWrapper *plugin,
            const SecretMetadata &secretMetadata,
            const Sailfish::Secrets::Secret &secret,
            const QByteArray &encryptionKey);

    SecretResult unlockCollectionAndReadSecret(
            EncryptedStoragePluginWrapper *plugin,
            const CollectionMetadata &collectionMetadata,
            const Sailfish::Secrets::Secret::Identifier &identifier,
            const QByteArray &encryptionKey);

    Sailfish::Secrets::Result unlockCollectionAndRemoveSecret(
            EncryptedStoragePluginWrapper *plugin,
            const CollectionMetadata &collectionMetadata,
            const Sailfish::Secrets::Secret::Identifier &identifier,
            const QByteArray &encryptionKey);

    IdentifiersResult unlockAndFindSecrets(
            EncryptedStoragePluginWrapper *plugin,
            const CollectionMetadata &collectionMetadata,
            const Sailfish::Secrets::Secret::FilterData &filter,
            Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator,
            const QByteArray &encryptionKey);

    Sailfish::Secrets::Result unlockDeviceLockedCollectionsAndReencrypt(
            EncryptedStoragePluginWrapper *plugin,
            const QByteArray &oldEncryptionKey,
            const QByteArray &newEncryptionKey);

    Sailfish::Secrets::Result unlockAndRemoveCollection(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName,
            const QByteArray &encryptionKey);

    Sailfish::Secrets::Result deriveKeyUnlockAndRemoveCollection(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName,
            const QByteArray &lockCode,
            const QByteArray &salt);

    Sailfish::Secrets::Result collectionSecretPreCheck(
            EncryptedStoragePluginWrapper *plugin,
            const QString &collectionName,
            const QString &secretName,
            const QByteArray &collectionKey,
            bool requiresRelock);
}

} // ApiImpl

} // Daemon

} // Secrets

} // Sailfish

#endif // SAILFISHSECRETS_APIIMPL_PLUGINFUNCTIONWRAPPERS_P_H
