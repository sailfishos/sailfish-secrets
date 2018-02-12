/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHCRYPTO_PLUGIN_CRYPTO_OPENSSL_H
#define SAILFISHCRYPTO_PLUGIN_CRYPTO_OPENSSL_H

#include "Crypto/extensionplugins.h"

#include <QObject>
#include <QByteArray>
#include <QCryptographicHash>

namespace Sailfish {

namespace Crypto {

namespace Daemon {

namespace Plugins {

class Q_DECL_EXPORT OpenSslCryptoPlugin : public QObject, public Sailfish::Crypto::CryptoPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)
    Q_INTERFACES(Sailfish::Crypto::CryptoPlugin)

public:
    OpenSslCryptoPlugin(QObject *parent = Q_NULLPTR);
    ~OpenSslCryptoPlugin();

    QString name() const Q_DECL_OVERRIDE {
#ifdef SAILFISHCRYPTO_TESTPLUGIN
        return QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl.test");
#else
        return QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl");
#endif
    }

    bool canStoreKeys() const Q_DECL_OVERRIDE { return false; }

    Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType() const Q_DECL_OVERRIDE { return Sailfish::Crypto::CryptoPlugin::SoftwareEncryption; }

    QVector<Sailfish::Crypto::Key::Algorithm> supportedAlgorithms() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> supportedBlockModes() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> supportedEncryptionPaddings() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> supportedSignaturePaddings() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> supportedDigests() const Q_DECL_OVERRIDE;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> supportedOperations() const Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result generateRandomData(
            quint64 callerIdent,
            const QString &csprngEngineName,
            quint64 numberBytes,
            QByteArray *randomData) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result seedRandomDataGenerator(
            quint64 callerIdent,
            const QString &csprngEngineName,
            const QByteArray &seedData,
            double entropyEstimate) Q_DECL_OVERRIDE;

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
            Sailfish::Crypto::StoredKeyRequest::KeyComponents keyComponents,
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
    QByteArray aes_encrypt_plaintext(const QByteArray &plaintext, const QByteArray &key, const QByteArray &init_vector);
    QByteArray aes_decrypt_ciphertext(const QByteArray &ciphertext, const QByteArray &key, const QByteArray &init_vector);
};

} // namespace Plugins

} // namespace Daemon

} // namespace Crypto

} // namespace Sailfish

#endif // SAILFISHCRYPTO_PLUGIN_CRYPTO_OPENSSL_H
