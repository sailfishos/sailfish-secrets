/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APIIMPL_PLUGINFUNCTIONWRAPPERS_P_H
#define SAILFISHSECRETS_APIIMPL_PLUGINFUNCTIONWRAPPERS_P_H

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

struct SecretResult {
    SecretResult(const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result(),
                 const Sailfish::Secrets::Secret &s = Sailfish::Secrets::Secret())
        : result(r), secret(s) {}
    SecretResult(const SecretResult &other)
        : result(other.result), secret(other.secret) {}
    Sailfish::Secrets::Result result;
    Sailfish::Secrets::Secret secret;
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

struct LockCodes {
    LockCodes(const QByteArray &o, const QByteArray &n)
        : oldCode(o), newCode(n) {}
    LockCodes(const LockCodes &other)
        : oldCode(other.oldCode)
        , newCode(other.newCode) {}
    QByteArray oldCode;
    QByteArray newCode;
};

FoundResult lockSpecificPlugin(
        const QMap<QString, Sailfish::Secrets::StoragePlugin*> &storagePlugins,
        const QMap<QString, Sailfish::Secrets::EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, Sailfish::Secrets::EncryptedStoragePlugin*> &encryptedStoragePlugins,
        const QString &lockCodeTarget);

FoundResult unlockSpecificPlugin(
        const QMap<QString, Sailfish::Secrets::StoragePlugin*> &storagePlugins,
        const QMap<QString, Sailfish::Secrets::EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, Sailfish::Secrets::EncryptedStoragePlugin*> &encryptedStoragePlugins,
        const QString &lockCodeTarget,
        const QByteArray &lockCode);

FoundResult modifyLockSpecificPlugin(
        const QMap<QString, Sailfish::Secrets::StoragePlugin*> &storagePlugins,
        const QMap<QString, Sailfish::Secrets::EncryptionPlugin*> &encryptionPlugins,
        const QMap<QString, Sailfish::Secrets::EncryptedStoragePlugin*> &encryptedStoragePlugins,
        const QString &lockCodeTarget,
        const LockCodes &newAndOldLockCode);

bool masterLockPlugins(
        const QList<Sailfish::Secrets::StoragePlugin*> &storagePlugins,
        const QList<Sailfish::Secrets::EncryptedStoragePlugin*> &encryptedStoragePlugins);

bool masterUnlockPlugins(
        const QList<Sailfish::Secrets::StoragePlugin*> &storagePlugins,
        const QList<Sailfish::Secrets::EncryptedStoragePlugin*> &encryptedStoragePlugins,
        const QByteArray &encryptionKey);

bool modifyMasterLockPlugins(
        const QList<Sailfish::Secrets::StoragePlugin*> &storagePlugins,
        const QList<Sailfish::Secrets::EncryptedStoragePlugin*> &encryptedStoragePlugins,
        const QByteArray &oldEncryptionKey,
        const QByteArray &newEncryptionKey);

namespace EncryptionPluginWrapper {
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

namespace StoragePluginWrapper {
    struct SecretDataResult {
        SecretDataResult(const Sailfish::Secrets::Result &r = Sailfish::Secrets::Result(),
                         const QByteArray &esn = QByteArray(),
                         const QByteArray &sd = QByteArray(),
                         const Sailfish::Secrets::Secret::FilterData &fd = Sailfish::Secrets::Secret::FilterData())
            : result(r), encryptedSecretName(esn), secretData(sd), secretFilterData(fd) {}
        SecretDataResult(const SecretDataResult &other)
            : result(other.result)
            , encryptedSecretName(other.encryptedSecretName)
            , secretData(other.secretData)
            , secretFilterData(other.secretFilterData) {}
        Sailfish::Secrets::Result result;
        QByteArray encryptedSecretName;
        QByteArray secretData;
        Sailfish::Secrets::Secret::FilterData secretFilterData;
    };

    struct EncryptedSecretNamesResult {
        EncryptedSecretNamesResult(const Sailfish::Secrets::Result &r,
                                   const QVector<QByteArray> &esns)
            : result(r), encryptedSecretNames(esns) {}
        EncryptedSecretNamesResult(const EncryptedSecretNamesResult &other)
            : result(other.result), encryptedSecretNames(other.encryptedSecretNames) {}
        Sailfish::Secrets::Result result;
        QVector<QByteArray> encryptedSecretNames;
    };

    bool isLocked(Sailfish::Secrets::StoragePlugin *plugin);
    bool lock(Sailfish::Secrets::StoragePlugin *plugin);
    bool unlock(
            Sailfish::Secrets::StoragePlugin *plugin,
            const QByteArray &lockCode);
    bool setLockCode(
            Sailfish::Secrets::StoragePlugin *plugin,
            const QByteArray &oldLockCode,
            const QByteArray &newLockCode);

    Sailfish::Secrets::Result createCollection(
            Sailfish::Secrets::StoragePlugin *plugin,
            const QString &collectionName);
    Sailfish::Secrets::Result removeCollection(
            Sailfish::Secrets::StoragePlugin *plugin,
            const QString &collectionName);
    Sailfish::Secrets::Result setSecret(
            Sailfish::Secrets::StoragePlugin *plugin,
            const QString &collectionName,
            const QString &hashedSecretName,
            const QByteArray &encryptedSecretName,
            const QByteArray &secret,
            const Sailfish::Secrets::Secret::FilterData &filterData);
    SecretDataResult getSecret(
            Sailfish::Secrets::StoragePlugin *plugin,
            const QString &collectionName,
            const QString &hashedSecretName);
    EncryptedSecretNamesResult findSecrets(
            Sailfish::Secrets::StoragePlugin *plugin,
            const QString &collectionName,
            const Sailfish::Secrets::Secret::FilterData &filter,
            Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator);
    Sailfish::Secrets::Result removeSecret(
            Sailfish::Secrets::StoragePlugin *plugin,
            const QString &collectionName,
            const QString &hashedSecretName);

    Sailfish::Secrets::Result reencryptSecrets(
            Sailfish::Secrets::StoragePlugin *plugin,
            const QString &collectionName,
            const QVector<QString> &hashedSecretNames,
            const QByteArray &oldkey,
            const QByteArray &newkey,
            Sailfish::Secrets::EncryptionPlugin *encryptionPlugin);

    // compound operations
    Sailfish::Secrets::Result encryptAndStoreSecret(
            Sailfish::Secrets::EncryptionPlugin *encryptionPlugin,
            Sailfish::Secrets::StoragePlugin *storagePlugin,
            const Secret &secret,
            const QString &hashedSecretName,
            const QByteArray &encryptionKey);

    SecretResult getAndDecryptSecret(
            Sailfish::Secrets::EncryptionPlugin *encryptionPlugin,
            Sailfish::Secrets::StoragePlugin *storagePlugin,
            const Sailfish::Secrets::Secret::Identifier &identifier,
            const QString &hashedSecretName,
            const QByteArray &encryptionKey);

    IdentifiersResult findAndDecryptSecretNames(
            Sailfish::Secrets::EncryptionPlugin *encryptionPlugin,
            Sailfish::Secrets::StoragePlugin *storagePlugin,
            const QString &collectionName,
            std::pair<Sailfish::Secrets::Secret::FilterData,
                      Sailfish::Secrets::StoragePlugin::FilterOperator> filter,
            const QByteArray &encryptionKey);

} // StoragePluginWrapper

namespace EncryptedStoragePluginWrapper {
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
                         const QString &sn = QString(),
                         const QByteArray &sd = QByteArray(),
                         const Sailfish::Secrets::Secret::FilterData &sfd = Sailfish::Secrets::Secret::FilterData())
            : result(r), secretName(sn), secretData(sd), secretFilterData(sfd) {}
        SecretDataResult(const SecretDataResult &other)
            : result(other.result)
            , secretName(other.secretName)
            , secretData(other.secretData)
            , secretFilterData(other.secretFilterData) {}
        Sailfish::Secrets::Result result;
        QString secretName;
        QByteArray secretData;
        Sailfish::Secrets::Secret::FilterData secretFilterData;
    };

    bool isLocked(Sailfish::Secrets::EncryptedStoragePlugin *plugin);
    bool lock(Sailfish::Secrets::EncryptedStoragePlugin *plugin);
    bool unlock(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QByteArray &lockCode);
    bool setLockCode(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QByteArray &oldLockCode,
            const QByteArray &newLockCode);

    Sailfish::Secrets::Result createCollection(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName,
            const QByteArray &key);
    Sailfish::Secrets::Result removeCollection(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName);

    LockedResult isCollectionLocked(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName);
    DerivedKeyResult deriveKeyFromCode(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QByteArray &authenticationCode,
            const QByteArray &salt);
    Sailfish::Secrets::Result setEncryptionKey(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName,
            const QByteArray &key);
    Sailfish::Secrets::Result reencrypt(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName,
            const QByteArray &oldkey,
            const QByteArray &newkey);

    Sailfish::Secrets::Result setSecret(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName,
            const QString &hashedSecretName,
            const QString &secretName,
            const QByteArray &secret,
            const Sailfish::Secrets::Secret::FilterData &filterData);
    SecretDataResult getSecret(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName,
            const QString &hashedSecretName);
    IdentifiersResult findSecrets(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName,
            const Sailfish::Secrets::Secret::FilterData &filter,
            Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator);

    Sailfish::Secrets::Result removeSecret(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName, const QString &hashedSecretName);

    Sailfish::Secrets::Result setSecret(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName,
            const QString &hashedSecretName,
            const Sailfish::Secrets::Secret &secret,
            const QByteArray &key);
    SecretDataResult accessSecret(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName,
            const QString &hashedSecretName,
            const QByteArray &key);

    // compound operations.
    Sailfish::Secrets::Result unlockCollectionAndStoreSecret(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const Sailfish::Secrets::Secret &secret,
            const QString &hashedSecretName,
            const QByteArray &encryptionKey);

    SecretResult unlockCollectionAndReadSecret(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const Sailfish::Secrets::Secret::Identifier &identifier,
            const QString &hashedSecretName,
            const QByteArray &encryptionKey);

    Sailfish::Secrets::Result unlockCollectionAndRemoveSecret(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const Sailfish::Secrets::Secret::Identifier &identifier,
            const QString &hashedSecretName,
            const QByteArray &encryptionKey);

    IdentifiersResult unlockAndFindSecrets(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName,
            const Sailfish::Secrets::Secret::FilterData &filter,
            Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator,
            const QByteArray &encryptionKey);

    Sailfish::Secrets::Result unlockAndRemoveSecret(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName,
            const QString &hashedSecretName,
            bool secretUsesDeviceLockKey,
            const QByteArray &deviceLockKey);

    Sailfish::Secrets::Result unlockCollectionAndReencrypt(
            Sailfish::Secrets::EncryptedStoragePlugin *plugin,
            const QString &collectionName,
            const QByteArray &oldEncryptionKey,
            const QByteArray &newEncryptionKey,
            bool isDeviceLocked);
}

} // ApiImpl

} // Daemon

} // Secrets

} // Sailfish

#endif // SAILFISHSECRETS_APIIMPL_PLUGINFUNCTIONWRAPPERS_P_H
