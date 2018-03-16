/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_PLUGIN_ENCRYPTION_OPENSSL_H
#define SAILFISHSECRETS_PLUGIN_ENCRYPTION_OPENSSL_H

#include "Secrets/extensionplugins.h"

#include <QObject>
#include <QByteArray>
#include <QCryptographicHash>

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Plugins {

class Q_DECL_EXPORT OpenSslPlugin : public QObject, public Sailfish::Secrets::EncryptionPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Secrets_EncryptionPlugin_IID)
    Q_INTERFACES(Sailfish::Secrets::EncryptionPlugin)

public:
    OpenSslPlugin(QObject *parent = Q_NULLPTR);
    ~OpenSslPlugin();
    QString name() const Q_DECL_OVERRIDE {
#ifdef SAILFISHSECRETS_TESTPLUGIN
        return QLatin1String("org.sailfishos.secrets.plugin.encryption.openssl.test");
#else
        return QLatin1String("org.sailfishos.secrets.plugin.encryption.openssl");
#endif
    }

    Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const Q_DECL_OVERRIDE { return Sailfish::Secrets::EncryptionPlugin::SoftwareEncryption; }
    Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const Q_DECL_OVERRIDE { return Sailfish::Secrets::EncryptionPlugin::AES_256_CBC; }

    Sailfish::Secrets::Result deriveKeyFromCode(const QByteArray &authenticationCode, const QByteArray &salt, QByteArray *key) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result encryptSecret(const QByteArray &plaintext, const QByteArray &key, QByteArray *encrypted) Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result decryptSecret(const QByteArray &encrypted, const QByteArray &key, QByteArray *plaintext) Q_DECL_OVERRIDE;

private:
    QByteArray aes_encrypt_plaintext(const QByteArray &plaintext, const QByteArray &key, const QByteArray &init_vector);
    QByteArray aes_decrypt_ciphertext(const QByteArray &ciphertext, const QByteArray &key, const QByteArray &init_vector);
};

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_PLUGIN_ENCRYPTION_OPENSSL_H
