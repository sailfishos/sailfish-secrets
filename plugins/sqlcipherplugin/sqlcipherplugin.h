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

#include "Crypto/extensionplugins.h"
#include "Crypto/key.h"
#include "Crypto/result.h"

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

// we need to do some function renaming to override the appropriate methods correctly.
class EncryptedStoragePlugin : public Sailfish::Secrets::EncryptedStoragePlugin
{
public:
    EncryptedStoragePlugin(QObject *parent = Q_NULLPTR) : Sailfish::Secrets::EncryptedStoragePlugin(parent) {}
    virtual Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptedStorageEncryptionType() const = 0;
    Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const Q_DECL_OVERRIDE
    { return encryptedStorageEncryptionType(); }
};

class CryptoPlugin : public Sailfish::Crypto::CryptoPlugin
{
public:
    CryptoPlugin() : Sailfish::Crypto::CryptoPlugin() {}
    virtual Sailfish::Crypto::CryptoPlugin::EncryptionType cryptoEncryptionType() const = 0;
    Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType() const Q_DECL_OVERRIDE
    { return cryptoEncryptionType(); }
};

class Q_DECL_EXPORT SqlCipherPlugin : public EncryptedStoragePlugin, public CryptoPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Secrets_EncryptedStoragePlugin_IID)
    Q_INTERFACES(Sailfish::Secrets::EncryptedStoragePlugin Sailfish::Crypto::CryptoPlugin)

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

    // This plugin implements the EncryptedStoragePlugin interface
    Sailfish::Secrets::StoragePlugin::StorageType storageType() const Q_DECL_OVERRIDE { return Sailfish::Secrets::StoragePlugin::FileSystemStorage; }
    Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptedStorageEncryptionType() const Q_DECL_OVERRIDE { return Sailfish::Secrets::EncryptionPlugin::SoftwareEncryption; }
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

    // And it also implements the CryptoPlugin interface
    bool canStoreKeys() const Q_DECL_OVERRIDE { return true; }
    Sailfish::Crypto::CryptoPlugin::EncryptionType cryptoEncryptionType() const Q_DECL_OVERRIDE { return Sailfish::Crypto::CryptoPlugin::SoftwareEncryption; }

    QVector<Sailfish::Crypto::Key::Algorithm> supportedAlgorithms() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> supportedBlockModes() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> supportedEncryptionPaddings() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> supportedSignaturePaddings() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> supportedDigests() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> supportedOperations() const Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result validateCertificateChain(
            const QVector<Sailfish::Crypto::Certificate> &chain,
            bool *validated) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result generateKey(
            const Sailfish::Crypto::Key &keyTemplate,
            Sailfish::Crypto::Key *key) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result generateAndStoreKey(
            const Sailfish::Crypto::Key &keyTemplate,
            Sailfish::Crypto::Key *keyMetadata) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            Sailfish::Crypto::Key *key) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result storedKeyIdentifiers(
            QVector<Sailfish::Crypto::Key::Identifier> *identifiers) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            QByteArray *signature) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result verify(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            bool *verified) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result encrypt(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            Sailfish::Crypto::Key::Digest digest,
            QByteArray *encrypted) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result decrypt(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            Sailfish::Crypto::Key::Digest digest,
            QByteArray *decrypted) Q_DECL_OVERRIDE;

private:
    static QString databaseDirPath(bool isTestPlugin, const QString &databaseSubdir);
    void init_aes_encryption();
    QByteArray aes_encrypt_plaintext(const QByteArray &plaintext, const QByteArray &key, const QByteArray &init_vector);
    QByteArray aes_decrypt_ciphertext(const QByteArray &ciphertext, const QByteArray &key, const QByteArray &init_vector);
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
