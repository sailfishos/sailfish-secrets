/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"
#include "evp_p.h"

#include "Crypto/key.h"
#include "Crypto/certificate.h"

#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>
#include <QtCore/QUuid>
#include <QtCore/QCryptographicHash>

Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)

Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::OpenSslCryptoPlugin(QObject *parent)
    : Sailfish::Crypto::CryptoPlugin(parent)
{
    osslevp_init();
}

Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::~OpenSslCryptoPlugin()
{
}

QVector<Sailfish::Crypto::Key::Algorithm>
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::supportedAlgorithms() const
{
    QVector<Sailfish::Crypto::Key::Algorithm> retn;
    retn.append(Sailfish::Crypto::Key::Aes256);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes>
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::supportedBlockModes() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::BlockModeCBC);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings>
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::supportedEncryptionPaddings() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::EncryptionPaddingNone);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings>
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::supportedSignaturePaddings() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::SignaturePaddingNone);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests>
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::supportedDigests() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::DigestSha256);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations>
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::supportedOperations() const
{
    // TODO: should this be algorithm specific?  not sure?
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::Encrypt | Sailfish::Crypto::Key::Decrypt);
    return retn;
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::validateCertificateChain(
        const QVector<Sailfish::Crypto::Certificate> &chain,
        bool *validated)
{
    Q_UNUSED(chain);
    Q_UNUSED(validated);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: OpenSslCryptoPlugin::validateCertificateChain"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::generateKey(
        const Sailfish::Crypto::Key &keyTemplate,
        Sailfish::Crypto::Key *key)
{
    if (keyTemplate.algorithm() != Sailfish::Crypto::Key::Aes256) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The OpenSslCryptoPlugin doesn't support algorithms other than Aes256 - TODO!!"));
    }

    const QUuid seed = QUuid::createUuid();
    const QByteArray hashed = QCryptographicHash::hash(seed.toByteArray(), QCryptographicHash::Sha256);
    *key = keyTemplate;
    key->setSecretKey(hashed);

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::generateAndStoreKey(
        const Sailfish::Crypto::Key &keyTemplate,
        Sailfish::Crypto::Key *keyMetadata)
{
    Q_UNUSED(keyTemplate);
    Q_UNUSED(keyMetadata);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The OpenSslCryptoPlugin doesn't support storing keys"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::storedKey(
        const Sailfish::Crypto::Key::Identifier &identifier,
        Sailfish::Crypto::Key *key)
{
    Q_UNUSED(identifier);
    Q_UNUSED(key);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The OpenSslCryptoPlugin doesn't support storing keys"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::storedKeyIdentifiers(
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
{
    Q_UNUSED(identifiers);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The OpenSslCryptoPlugin doesn't support storing keys"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::sign(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        QByteArray *signature)
{
    // TODO: support more operations and algorithms in this plugin!
    Q_UNUSED(data);
    Q_UNUSED(key);
    Q_UNUSED(padding);
    Q_UNUSED(digest);
    Q_UNUSED(signature);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: OpenSslCryptoPlugin::sign"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::verify(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        bool *verified)
{
    // TODO: support more operations and algorithms in this plugin!
    Q_UNUSED(data);
    Q_UNUSED(key);
    Q_UNUSED(padding);
    Q_UNUSED(digest);
    Q_UNUSED(verified);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: OpenSslCryptoPlugin::verify"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::encrypt(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        QByteArray *encrypted)
{
    if (key.algorithm() != Sailfish::Crypto::Key::Aes256) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The OpenSslCryptoPlugin doesn't support algorithms other than Aes256 - TODO!!"));
    }

    if (blockMode != Sailfish::Crypto::Key::BlockModeCBC) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The OpenSslCryptoPlugin doesn't support block modes other than CBC - TODO!!"));
    }

    if (padding != Sailfish::Crypto::Key::EncryptionPaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The OpenSslCryptoPlugin doesn't support encryption padding other than None - TODO!!"));
    }

    if (digest != Sailfish::Crypto::Key::DigestSha256) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The OpenSslCryptoPlugin doesn't support digests other than Sha256 - TODO!!"));
    }

    if (key.secretKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySecretKey,
                                        QLatin1String("Cannot encrypt with empty secret key"));
    }

    // generate initialisation vector and key hash
    QCryptographicHash keyHash(QCryptographicHash::Sha512);
    keyHash.addData(key.secretKey());
    QCryptographicHash ivHash(QCryptographicHash::Sha256);
    ivHash.addData(key.secretKey());
    QByteArray initVector = ivHash.result();
    if (initVector.size() > 16) {
        initVector.chop(initVector.size() - 16);
    } else while (initVector.size() < 16) {
        initVector.append('\0');
    }

    // encrypt plaintext
    QByteArray ciphertext = aes_encrypt_plaintext(data, keyHash.result(), initVector);

    // return result.
    if (ciphertext.size()) {
        *encrypted = ciphertext;
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    }

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginEncryptionError,
                                     QLatin1String("OpenSSL crypto plugin failed to encrypt the data"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::decrypt(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        QByteArray *decrypted)
{

    if (key.algorithm() != Sailfish::Crypto::Key::Aes256) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The OpenSslCryptoPlugin doesn't support algorithms other than Aes256 - TODO!!"));
    }

    if (blockMode != Sailfish::Crypto::Key::BlockModeCBC) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The OpenSslCryptoPlugin doesn't support block modes other than CBC - TODO!!"));
    }

    if (padding != Sailfish::Crypto::Key::EncryptionPaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The OpenSslCryptoPlugin doesn't support encryption padding other than None - TODO!!"));
    }

    if (digest != Sailfish::Crypto::Key::DigestSha256) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The OpenSslCryptoPlugin doesn't support digests other than Sha256 - TODO!!"));
    }

    if (key.secretKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySecretKey,
                                        QLatin1String("Cannot encrypt with empty secret key"));
    }

    // generate initialisation vector and key hash
    QCryptographicHash keyHash(QCryptographicHash::Sha512);
    keyHash.addData(key.secretKey());
    QCryptographicHash ivHash(QCryptographicHash::Sha256);
    ivHash.addData(key.secretKey());
    QByteArray initVector = ivHash.result();
    if (initVector.size() > 16) {
        initVector.chop(initVector.size() - 16);
    } else while (initVector.size() < 16) {
        initVector.append('\0');
    }

    // decrypt ciphertext
    QByteArray plaintext = aes_decrypt_ciphertext(data, keyHash.result(), initVector);
    if (!plaintext.size() || (plaintext.size() == 1 && plaintext.at(0) == 0)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginDecryptionError,
                                         QLatin1String("OpenSSL crypto plugin failed to decrypt the secret"));
    }

    // return result.
    *decrypted = plaintext;
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

QByteArray
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::aes_encrypt_plaintext(
        const QByteArray &plaintext,
        const QByteArray &key,
        const QByteArray &init_vector)
{
    QByteArray encryptedData;
    unsigned char *encrypted = NULL;
    int size = osslevp_aes_encrypt_plaintext((const unsigned char *)init_vector.constData(),
                                             (const unsigned char *)key.constData(),
                                             key.size(),
                                             (const unsigned char *)plaintext.constData(),
                                             plaintext.size(),
                                             &encrypted);
    if (size <= 0) {
        return encryptedData;
    }

    encryptedData = QByteArray((const char *)encrypted, size);
    free(encrypted);
    return encryptedData;
}

QByteArray
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::aes_decrypt_ciphertext(
        const QByteArray &ciphertext,
        const QByteArray &key,
        const QByteArray &init_vector)
{
    QByteArray decryptedData;
    unsigned char *decrypted = NULL;
    int size = osslevp_aes_decrypt_ciphertext((const unsigned char *)init_vector.constData(),
                                              (const unsigned char *)key.constData(),
                                              key.size(),
                                              (const unsigned char *)ciphertext.constData(),
                                              ciphertext.size(),
                                              &decrypted);
    if (size <= 0) {
        return decryptedData;
    }

    decryptedData = QByteArray((const char *)decrypted, size);
    free(decrypted);
    return decryptedData;
}
