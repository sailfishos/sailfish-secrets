/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_PLUGIN_ENCRYPTEDSTORAGE_SQLCIPHER_H
#define SAILFISHSECRETS_PLUGIN_ENCRYPTEDSTORAGE_SQLCIPHER_H

#include "Secrets/extensionplugins.h"
#include "Secrets/secret.h"
#include "Secrets/result.h"

#include "database_p.h"

#include <QObject>
#include <QVector>
#include <QString>
#include <QByteArray>
#include <QCryptographicHash>
#include <QMutexLocker>

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Plugins {

class Q_DECL_EXPORT SqlCipherPlugin : public Sailfish::Secrets::EncryptedStoragePlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Secrets_EncryptedStoragePlugin_IID)
    Q_INTERFACES(Sailfish::Secrets::EncryptedStoragePlugin)

public:
    SqlCipherPlugin(QObject *parent = Q_NULLPTR);
    ~SqlCipherPlugin();

    bool isTestPlugin() const Q_DECL_OVERRIDE {
#ifdef SAILFISH_SECRETS_BUILD_TEST_PLUGIN
        return true;
#else
        return false;
#endif
    }

    QString name() const Q_DECL_OVERRIDE { return QLatin1String("org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher"); }
    Sailfish::Secrets::StoragePlugin::StorageType storageType() const Q_DECL_OVERRIDE { return Sailfish::Secrets::StoragePlugin::FileSystemStorage; }
    Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const Q_DECL_OVERRIDE { return Sailfish::Secrets::EncryptionPlugin::SoftwareEncryption; }
    Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const Q_DECL_OVERRIDE { return Sailfish::Secrets::EncryptionPlugin::AES_256_CBC; }

    Sailfish::Secrets::Result createCollection(const QString &collectionName, const QByteArray &key) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result removeCollection(const QString &collectionName) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result isLocked(const QString &collectionName, bool *locked) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result setEncryptionKey(const QString &collectionName, const QByteArray &key) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result reencrypt(const QString &collectionName, const QByteArray &oldkey, const QByteArray &newkey) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result setSecret(const QString &collectionName, const QString &hashedSecretName, const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result getSecret(const QString &collectionName, const QString &hashedSecretName, QString *secretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result findSecrets(const QString &collectionName, const Sailfish::Secrets::Secret::FilterData &filter, Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator, QVector<Sailfish::Secrets::Secret::Identifier> *identifiers) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result removeSecret(const QString &collectionName, const QString &hashedSecretName) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result setSecret(const QString &collectionName, const QString &hashedSecretName, const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData, const QByteArray &key) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result accessSecret(const QString &collectionName, const QString &hashedSecretName, const QByteArray &key, QString *secretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData) Q_DECL_OVERRIDE;

private:
    Sailfish::Secrets::Result openCollectionDatabase(const QString &collectionName, const QByteArray &key, bool createIfNotExists);
    QMap<QString, Sailfish::Secrets::Daemon::Sqlite::Database *> m_collectionDatabases;

    QString m_databaseSubdir;
    QString m_databaseDirPath;
};

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_PLUGIN_ENCRYPTEDSTORAGE_SQLCIPHER_H
