/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_PLUGIN_ENCRYPTEDSTORAGE_SQLCIPHER_H
#define SAILFISHSECRETS_PLUGIN_ENCRYPTEDSTORAGE_SQLCIPHER_H

#include "Secrets/extensionplugins.h"
#include "Secrets/result.h"

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
    SqlCipherPlugin(QObject *parent = Q_NULLPTR)
        : Sailfish::Secrets::EncryptedStoragePlugin(parent) {}
    ~SqlCipherPlugin() {}

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

    Sailfish::Secrets::Result createCollection(const QString &collectionName, const QByteArray &key) Q_DECL_OVERRIDE
    {
        Q_UNUSED(collectionName);
        Q_UNUSED(key);
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                         QLatin1String("TODO: SQLCIPHER"));
    }

    Sailfish::Secrets::Result removeCollection(const QString &collectionName) Q_DECL_OVERRIDE
    {
        Q_UNUSED(collectionName);
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                         QLatin1String("TODO: SQLCIPHER"));
    }

    Sailfish::Secrets::Result isLocked(const QString &collectionName, bool *locked) Q_DECL_OVERRIDE
    {
        Q_UNUSED(collectionName);
        Q_UNUSED(locked);
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                         QLatin1String("TODO: SQLCIPHER"));
    }

    Sailfish::Secrets::Result setEncryptionKey(const QString &collectionName, const QByteArray &key) Q_DECL_OVERRIDE
    {
        Q_UNUSED(collectionName);
        Q_UNUSED(key);
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                         QLatin1String("TODO: SQLCIPHER"));
    }

    Sailfish::Secrets::Result reencrypt(const QString &collectionName, const QByteArray &oldkey, const QByteArray &newkey) Q_DECL_OVERRIDE
    {
        Q_UNUSED(collectionName);
        Q_UNUSED(oldkey);
        Q_UNUSED(newkey);
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                         QLatin1String("TODO: SQLCIPHER"));
    }

    Sailfish::Secrets::Result setSecret(const QString &collectionName, const QString &secretName, const QByteArray &secret) Q_DECL_OVERRIDE
    {
        Q_UNUSED(collectionName);
        Q_UNUSED(secretName);
        Q_UNUSED(secret);
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                         QLatin1String("TODO: SQLCIPHER"));
    }

    Sailfish::Secrets::Result getSecret(const QString &collectionName, const QString &secretName, QByteArray *secret) Q_DECL_OVERRIDE
    {
        Q_UNUSED(collectionName);
        Q_UNUSED(secretName);
        Q_UNUSED(secret);
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                         QLatin1String("TODO: SQLCIPHER"));
    }

    Sailfish::Secrets::Result removeSecret(const QString &collectionName, const QString &secretName) Q_DECL_OVERRIDE
    {
        Q_UNUSED(collectionName);
        Q_UNUSED(secretName);
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                         QLatin1String("TODO: SQLCIPHER"));
    }

    Sailfish::Secrets::Result setSecret(const QString &collectionName, const QString &secretName, const QByteArray &secret, const QByteArray &key) Q_DECL_OVERRIDE
    {
        Q_UNUSED(collectionName);
        Q_UNUSED(secretName);
        Q_UNUSED(secret);
        Q_UNUSED(key);
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                         QLatin1String("TODO: SQLCIPHER"));
    }

    Sailfish::Secrets::Result accessSecret(const QString &collectionName, const QString &secretName, const QByteArray &key, QByteArray *secret) Q_DECL_OVERRIDE
    {
        Q_UNUSED(collectionName);
        Q_UNUSED(secretName);
        Q_UNUSED(key);
        Q_UNUSED(secret);
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                         QLatin1String("TODO: SQLCIPHER"));
    }
};

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_PLUGIN_ENCRYPTEDSTORAGE_SQLCIPHER_H
