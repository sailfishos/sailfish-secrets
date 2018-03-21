/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"
#include "../opensslcryptoplugin/evp_p.h"

#include "Crypto/cryptomanager.h"

Q_PLUGIN_METADATA(IID Sailfish_Secrets_EncryptionPlugin_IID)

using namespace Sailfish::Secrets;

Daemon::Plugins::OpenSslPlugin::OpenSslPlugin(QObject *parent)
    : QObject(parent), EncryptionPlugin()
{
    osslevp_init();
}

Daemon::Plugins::OpenSslPlugin::~OpenSslPlugin()
{
}

Result
Daemon::Plugins::OpenSslPlugin::encryptSecret(
        const QByteArray &plaintext,
        const QByteArray &key,
        QByteArray *encrypted)
{
    // generate initialisation vector and key hash
    QCryptographicHash keyHash(QCryptographicHash::Sha512);
    keyHash.addData(key);
    QCryptographicHash ivHash(QCryptographicHash::Sha256);
    ivHash.addData(key);
    QByteArray initVector = ivHash.result();
    if (initVector.size() > 16) {
        initVector.chop(initVector.size() - 16);
    } else while (initVector.size() < 16) {
        initVector.append('\0');
    }

    // encrypt plaintext
    QByteArray ciphertext = aes_encrypt_plaintext(plaintext, keyHash.result(), initVector);

    // return result
    if (ciphertext.size()) {
        *encrypted = ciphertext;
        return Result(Result::Succeeded);
    }

    return Result(Result::SecretsPluginEncryptionError,
                  QLatin1String("OpenSSL plugin failed to encrypt the secret"));
}

Result
Daemon::Plugins::OpenSslPlugin::decryptSecret(
        const QByteArray &encrypted,
        const QByteArray &key,
        QByteArray *plaintext)
{
    // generate initialisation vector and key hash
    QCryptographicHash keyHash(QCryptographicHash::Sha512);
    keyHash.addData(key);
    QCryptographicHash ivHash(QCryptographicHash::Sha256);
    ivHash.addData(key);
    QByteArray initVector = ivHash.result();
    if (initVector.size() > 16) {
        initVector.chop(initVector.size() - 16);
    } else while (initVector.size() < 16) {
        initVector.append('\0');
    }

    // decrypt ciphertext
    QByteArray decrypted = aes_decrypt_ciphertext(encrypted, keyHash.result(), initVector);
    if (!decrypted.size() || (decrypted.size() == 1 && decrypted.at(0) == 0)) {
        return Result(Result::SecretsPluginDecryptionError,
                      QLatin1String("OpenSSL plugin failed to decrypt the secret"));
    }

    // return result
    *plaintext = decrypted;
    return Result(Result::Succeeded);
}

QByteArray
Daemon::Plugins::OpenSslPlugin::aes_encrypt_plaintext(
        const QByteArray &plaintext,
        const QByteArray &key,
        const QByteArray &init_vector)
{
    QByteArray encryptedData;
    unsigned char *encrypted = NULL;
    int size = osslevp_aes_encrypt_plaintext(Sailfish::Crypto::CryptoManager::BlockModeCbc,
                                             (const unsigned char *)init_vector.constData(),
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
Daemon::Plugins::OpenSslPlugin::aes_decrypt_ciphertext(
        const QByteArray &ciphertext,
        const QByteArray &key,
        const QByteArray &init_vector)
{
    QByteArray decryptedData;
    unsigned char *decrypted = NULL;
    int size = osslevp_aes_decrypt_ciphertext(Sailfish::Crypto::CryptoManager::BlockModeCbc,
                                              (const unsigned char *)init_vector.constData(),
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
