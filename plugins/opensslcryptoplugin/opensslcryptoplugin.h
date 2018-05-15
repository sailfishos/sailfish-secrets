/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHCRYPTO_PLUGIN_CRYPTO_OPENSSL_H
#define SAILFISHCRYPTO_PLUGIN_CRYPTO_OPENSSL_H

#include "CryptoPluginApi/extensionplugins.h"

#include <QObject>
#include <QByteArray>
#include <QCryptographicHash>
#include <QMap>

// When building the actual plugin, export it.
// When just compiling into another plugin, don't.
#ifdef SAILFISHCRYPTO_BUILD_OPENSSLCRYPTOPLUGIN
#define OPENSSLCRYPTOPLUGIN_EXPORT Q_DECL_EXPORT
#else
#define OPENSSLCRYPTOPLUGIN_EXPORT Q_DECL_HIDDEN
#endif // SAILFISHCRYPTO_BUILD_OPENSSLCRYPTOPLUGIN

class CipherSessionData;
class QTimer;

namespace Sailfish {

namespace Crypto {

namespace Daemon {

namespace Plugins {

class OPENSSLCRYPTOPLUGIN_EXPORT OpenSslCryptoPlugin : public QObject, public virtual Sailfish::Crypto::CryptoPlugin
{
    Q_OBJECT
#ifdef SAILFISHCRYPTO_BUILD_OPENSSLCRYPTOPLUGIN
    Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)
#endif
    Q_INTERFACES(Sailfish::Crypto::CryptoPlugin)

public:
    OpenSslCryptoPlugin(QObject *parent = Q_NULLPTR);
    ~OpenSslCryptoPlugin();

    QString displayName() const Q_DECL_OVERRIDE {
        return QStringLiteral("OpenSSL Crypto");
    }
    QString name() const Q_DECL_OVERRIDE {
#ifdef SAILFISHCRYPTO_TESTPLUGIN
        return QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl.test");
#else
        return QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl");
#endif
    }
    int version() const Q_DECL_OVERRIDE {
        return 1;
    }

    bool canStoreKeys() const Q_DECL_OVERRIDE { return false; }
    Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType() const Q_DECL_OVERRIDE { return Sailfish::Crypto::CryptoPlugin::SoftwareEncryption; }

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
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *key) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result storedKeyIdentifiers(
            const QString &collectionName,
            const QVariantMap &customParameters,
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
            Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus) Q_DECL_OVERRIDE;

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
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QByteArray &authenticationTag,
            const QVariantMap &customParameters,
            QByteArray *decrypted,
            Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus) Q_DECL_OVERRIDE;

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
            Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus) Q_DECL_OVERRIDE;

private:
    QByteArray aes_encrypt_plaintext(Sailfish::Crypto::CryptoManager::BlockMode blockMode, const QByteArray &plaintext, const QByteArray &key, const QByteArray &init_vector);
    QByteArray aes_decrypt_ciphertext(Sailfish::Crypto::CryptoManager::BlockMode blockMode, const QByteArray &ciphertext, const QByteArray &key, const QByteArray &init_vector);

    QPair<QByteArray, QByteArray> aes_auth_encrypt_plaintext(Sailfish::Crypto::CryptoManager::BlockMode blockMode, const QByteArray &plaintext, const QByteArray &key, const QByteArray &init_vector, const QByteArray &auth, unsigned int authenticationTagLength);
    QPair<QByteArray, bool> aes_auth_decrypt_ciphertext(Sailfish::Crypto::CryptoManager::BlockMode blockMode, const QByteArray &ciphertext, const QByteArray &key, const QByteArray &init_vector, const QByteArray &auth, const QByteArray &authenticationTag);

    Sailfish::Crypto::Result generateRsaKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            Sailfish::Crypto::Key *key);

    Sailfish::Crypto::Result generateEcKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            Sailfish::Crypto::Key *key);

    Sailfish::Crypto::Result encryptAes(const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            QByteArray *encrypted,
            QByteArray *authenticationTag);

    Sailfish::Crypto::Result encryptAsymmetric(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            QByteArray *encrypted);

    Sailfish::Crypto::Result decryptAes(const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QByteArray &authenticationTag,
            QByteArray *decrypted,
            Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus);

    Sailfish::Crypto::Result decryptAsymmetric(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            QByteArray *decrypted);

    QMap<quint64, QMap<quint32, CipherSessionData*> > m_cipherSessions; // clientId to token to data
    struct CipherSessionLookup {
        CipherSessionData *csd = 0;
        quint32 sessionToken = 0;
        quint64 clientId = 0;
    };
    QMap<QTimer *, CipherSessionLookup> m_cipherSessionTimeouts;
};

} // namespace Plugins

} // namespace Daemon

} // namespace Crypto

} // namespace Sailfish

#endif // SAILFISHCRYPTO_PLUGIN_CRYPTO_OPENSSL_H
