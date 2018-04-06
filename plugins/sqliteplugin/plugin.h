/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_PLUGIN_STORAGE_SQLITE_H
#define SAILFISHSECRETS_PLUGIN_STORAGE_SQLITE_H

#include "database_p.h"

#include "SecretsPluginApi/extensionplugins.h"

#include "Secrets/result.h"

#include <QObject>
#include <QVector>
#include <QMap>
#include <QString>
#include <QByteArray>
#include <QCryptographicHash>
#include <QMutexLocker>

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Plugins {

class Q_DECL_EXPORT SqlitePlugin : public QObject, public virtual Sailfish::Secrets::StoragePlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Secrets_StoragePlugin_IID)
    Q_INTERFACES(Sailfish::Secrets::StoragePlugin)

public:
    SqlitePlugin(QObject *parent = Q_NULLPTR);
    ~SqlitePlugin();

    QString name() const Q_DECL_OVERRIDE {
#ifdef SAILFISHSECRETS_TESTPLUGIN
        return QLatin1String("org.sailfishos.secrets.plugin.storage.sqlite.test");
#else
        return QLatin1String("org.sailfishos.secrets.plugin.storage.sqlite");
#endif
    }
    int version() const Q_DECL_OVERRIDE {
        return 1;
    }

    Sailfish::Secrets::StoragePlugin::StorageType storageType() const Q_DECL_OVERRIDE { return Sailfish::Secrets::StoragePlugin::FileSystemStorage; }

    Sailfish::Secrets::Result createCollection(const QString &collectionName) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result removeCollection(const QString &collectionName) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result setSecret(const QString &collectionName, const QString &hashedSecretName, const QByteArray &encryptedSecretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result getSecret(const QString &collectionName, const QString &hashedSecretName, QByteArray *encryptedSecretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result findSecrets(const QString &collectionName, const Sailfish::Secrets::Secret::FilterData &filter, Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator, QVector<QByteArray> *encryptedSecretNames) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result removeSecret(const QString &collectionName, const QString &hashedSecretName) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result reencryptSecrets(
            const QString &collectionName,             // non-empty, all secrets in this collection will be re-encrypted
            const QVector<QString> &hashedSecretNames, // if collectionName is empty, these standalone secrets will be re-encrypted.
            const QByteArray &oldkey,
            const QByteArray &newkey,
            Sailfish::Secrets::EncryptionPlugin *plugin) Q_DECL_OVERRIDE;

private:
    void openDatabaseIfNecessary();
    Sailfish::Secrets::Daemon::Sqlite::Database m_db;
};

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_PLUGIN_STORAGE_SQLITE_H
