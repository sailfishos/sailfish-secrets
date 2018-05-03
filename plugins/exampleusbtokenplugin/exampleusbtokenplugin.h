/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_PLUGIN_CRYPTOSTORAGE_EXAMPLEUSBTOKEN_H
#define SAILFISHSECRETS_PLUGIN_CRYPTOSTORAGE_EXAMPLEUSBTOKEN_H

#include "SecretsPluginApi/extensionplugins.h"

#include "Secrets/secret.h"
#include "Secrets/result.h"

#include "CryptoPluginApi/extensionplugins.h"

#include "Crypto/key.h"
#include "Crypto/result.h"

#include "opensslcryptoplugin.h"

#include <QObject>
#include <QVector>
#include <QString>
#include <QByteArray>
#include <QCryptographicHash>
#include <QMutexLocker>

class QTimer;
class CipherSessionData;

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Plugins {

// we need to do some function renaming to override the appropriate methods correctly.
class EncryptedStoragePlugin : public virtual Sailfish::Secrets::EncryptedStoragePlugin
{
public:
    EncryptedStoragePlugin() : Sailfish::Secrets::EncryptedStoragePlugin() {}
    virtual Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptedStorageEncryptionType() const = 0;
    Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const Q_DECL_OVERRIDE
    { return encryptedStorageEncryptionType(); }
};

class CryptoPlugin : public virtual Sailfish::Crypto::CryptoPlugin
{
public:
    CryptoPlugin() : Sailfish::Crypto::CryptoPlugin() {}
    virtual Sailfish::Crypto::CryptoPlugin::EncryptionType cryptoEncryptionType() const = 0;
    Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType() const Q_DECL_OVERRIDE
    { return cryptoEncryptionType(); }
};

class Q_DECL_EXPORT ExampleUsbTokenPlugin : public QObject
                                          , public virtual Sailfish::Secrets::Daemon::Plugins::EncryptedStoragePlugin
                                          , public virtual Sailfish::Secrets::Daemon::Plugins::CryptoPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Secrets_EncryptedStoragePlugin_IID)
    Q_INTERFACES(Sailfish::Secrets::EncryptedStoragePlugin Sailfish::Crypto::CryptoPlugin)

public:
    ExampleUsbTokenPlugin(QObject *parent = Q_NULLPTR);
    ~ExampleUsbTokenPlugin();

    QString displayName() const Q_DECL_OVERRIDE {
        //: The (human readable) display name of the Example USB Token plugin
        //% "Example USB Token"
        return qtTrId("example_usb_token-display_name");
    }
    QString name() const Q_DECL_OVERRIDE {
#ifdef SAILFISHSECRETS_TESTPLUGIN
        return QLatin1String("org.sailfishos.secrets.plugin.cryptostorage.exampleusbtoken.test");
#else
        return QLatin1String("org.sailfishos.secrets.plugin.cryptostorage.exampleusbtoken");
#endif
    }
    int version() const Q_DECL_OVERRIDE {
        return 1;
    }

    // Implement the PluginBase interface methods
    bool isAvailable() const Q_DECL_OVERRIDE;
    bool supportsLocking() const Q_DECL_OVERRIDE { return true; }
    bool supportsSetLockCode() const Q_DECL_OVERRIDE;
    bool isLocked() const Q_DECL_OVERRIDE;
    bool lock() Q_DECL_OVERRIDE;
    bool unlock(const QByteArray &lockCode) Q_DECL_OVERRIDE;
    bool setLockCode(const QByteArray &oldLockCode, const QByteArray &newLockCode) Q_DECL_OVERRIDE;

    // This plugin implements the EncryptedStoragePlugin interface
    Sailfish::Secrets::StoragePlugin::StorageType storageType() const Q_DECL_OVERRIDE { return Sailfish::Secrets::StoragePlugin::FileSystemStorage; }
    Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptedStorageEncryptionType() const Q_DECL_OVERRIDE { return Sailfish::Secrets::EncryptionPlugin::SoftwareEncryption; }
    Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const Q_DECL_OVERRIDE { return Sailfish::Secrets::EncryptionPlugin::AES_256_CBC; }

    Sailfish::Secrets::Result collectionNames(QStringList *names) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result createCollection(const QString &collectionName, const QByteArray &key) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result removeCollection(const QString &collectionName) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result isCollectionLocked(const QString &collectionName, bool *locked) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result deriveKeyFromCode(const QByteArray &authenticationCode, const QByteArray &salt, QByteArray *key) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result setEncryptionKey(const QString &collectionName, const QByteArray &key) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result reencrypt(const QString &collectionName, const QByteArray &oldkey, const QByteArray &newkey) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result setSecret(const QString &collectionName, const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result getSecret(const QString &collectionName, const QString &secretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result secretNames(const QString &collectionName, QStringList *secretNames) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result findSecrets(const QString &collectionName, const Sailfish::Secrets::Secret::FilterData &filter, Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator, QVector<Sailfish::Secrets::Secret::Identifier> *identifiers) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result removeSecret(const QString &collectionName, const QString &secretName) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result setSecret(const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData, const QByteArray &key) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result accessSecret(const QString &secretName, const QByteArray &key, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result removeSecret(const QString &secretName) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result reencryptSecret(const QString &secretName, const QByteArray &oldkey, const QByteArray &newkey) Q_DECL_OVERRIDE;

    // And it also implements the CryptoPlugin interface
    bool canStoreKeys() const Q_DECL_OVERRIDE { return true; }
    Sailfish::Crypto::CryptoPlugin::EncryptionType cryptoEncryptionType() const Q_DECL_OVERRIDE { return Sailfish::Crypto::CryptoPlugin::SoftwareEncryption; }

    Sailfish::Crypto::Result generateRandomData(
            quint64 callerIdent,
            const QString &csprngEngineName,
            quint64 numberBytes,
            const QVariantMap &customParameters,
            QByteArray *randomData) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result seedRandomDataGenerator(
            quint64 callerIdent,
            const QString &csprngEngineName,
            const QByteArray &seedData,
            double entropyEstimate,
            const QVariantMap &customParameters) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result generateInitializationVector(
            Sailfish::Crypto::CryptoManager::Algorithm algorithm,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            int keySize,
            const QVariantMap &customParameters,
            QByteArray *generatedIV) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result generateKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *key) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result generateAndStoreKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *keyMetadata) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result importKey(
            const QByteArray &data,
            const QByteArray &passphrase,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *importedKey) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result importAndStoreKey(
            const QByteArray &data,
            const Sailfish::Crypto::Key &keyTemplate,
            const QByteArray &passphrase,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *keyMetadata) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            Sailfish::Crypto::Key::Components keyComponents,
            Sailfish::Crypto::Key *key) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result storedKeyIdentifiers(
            const QString &collectionName,
            QVector<Sailfish::Crypto::Key::Identifier> *identifiers) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result calculateDigest(
            const QByteArray &data,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            QByteArray *digest) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            QByteArray *signature) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result verify(
            const QByteArray &signature,
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            bool *verified) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result encrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QVariantMap &customParameters,
            QByteArray *encrypted,
            QByteArray *authenticationTag) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result decrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QByteArray &authenticationTag,
            const QVariantMap &customParameters,
            QByteArray *decrypted,
            bool *verified);

    Sailfish::Crypto::Result initializeCipherSession(
            quint64 clientId,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::Operation operation,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
            Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            quint32 *cipherSessionToken) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result updateCipherSessionAuthentication(
            quint64 clientId,
            const QByteArray &authenticationData,
            const QVariantMap &customParameters,
            quint32 cipherSessionToken) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result updateCipherSession(
            quint64 clientId,
            const QByteArray &data,
            const QVariantMap &customParameters,
            quint32 cipherSessionToken,
            QByteArray *generatedData) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result finalizeCipherSession(
            quint64 clientId,
            const QByteArray &data,
            const QVariantMap &customParameters,
            quint32 cipherSessionToken,
            QByteArray *generatedData,
            bool *verified) Q_DECL_OVERRIDE;

private:
    Sailfish::Crypto::Key readDefaultKeyFromUsbToken() const;
    Sailfish::Crypto::Result getFullKey(const Sailfish::Crypto::Key &key,
                                        Sailfish::Crypto::Key *fullKey) const;
    Sailfish::Crypto::Key m_usbTokenKey;
    QMap<quint64, QMap<quint32, CipherSessionData*> > m_cipherSessions; // clientId to token to data
    struct CipherSessionLookup {
        CipherSessionData *csd = 0;
        quint32 sessionToken = 0;
        quint64 clientId = 0;
    };
    QMap<QTimer *, CipherSessionLookup> m_cipherSessionTimeouts;

    // A real USB-token-backed plugin would call the USB-token-provided Crypto
    // interface to perform crypto operations.  We emulate such an interface
    // by using OpenSSL.
    Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin m_usbInterface;
};

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_PLUGIN_CRYPTOSTORAGE_EXAMPLEUSBTOKEN_H
