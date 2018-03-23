/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"
#include "evp_p.h"
#include "evp_helpers_p.h"

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
Daemon::Plugins::OpenSslPlugin::deriveKeyFromCode(
        const QByteArray &authenticationCode,
        const QByteArray &salt,
        QByteArray *key)
{
    const QByteArray inputData = authenticationCode.isEmpty()
                         ? QByteArray(1, '\0')
                         : authenticationCode;
    const int nbytes = 32; // 256 bit
    QScopedArrayPointer<char> buf(new char[nbytes]);
    if (osslevp_pkcs5_pbkdf2_hmac(
            inputData.constData(),
            inputData.size(),
            salt.isEmpty()
                    ? NULL
                    : reinterpret_cast<const unsigned char*>(salt.constData()),
            salt.size(),
            10000, // iterations
            21, // CryptoManager::DigestSha256
            nbytes,
            reinterpret_cast<unsigned char*>(buf.data())) != 1) {
        return Result(Result::SecretsPluginKeyDerivationError,
                      QLatin1String("The OpenSSL plugin failed to derive the key data"));
    }

    *key = QByteArray(buf.data(), nbytes);
    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::OpenSslPlugin::encryptSecret(
        const QByteArray &plaintext,
        const QByteArray &key,
        QByteArray *encrypted)
{
    // generate initialisation vector
    QCryptographicHash ivHash(QCryptographicHash::Sha256);
    ivHash.addData(key);
    QByteArray initVector = ivHash.result();
    initVector.resize(16);

    // encrypt plaintext
    QByteArray ciphertext = aes_encrypt_plaintext(plaintext, key, initVector);

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
    // generate initialisation vector
    QCryptographicHash ivHash(QCryptographicHash::Sha256);
    ivHash.addData(key);
    QByteArray initVector = ivHash.result();
    initVector.resize(16);

    // decrypt ciphertext
    QByteArray decrypted = aes_decrypt_ciphertext(encrypted, key, initVector);
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
    int size = osslevp_aes_encrypt_plaintext(getEvpCipher(Sailfish::Crypto::CryptoManager::BlockModeCbc, key.size()),
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
    int size = osslevp_aes_decrypt_ciphertext(getEvpCipher(Sailfish::Crypto::CryptoManager::BlockModeCbc, key.size()),
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
