/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE *
 *
 * Copyright (C) 2017 Open Mobile Platform LLC.
 * Contact: Denis Semakin <d.semakin@omprussia.ru>
 * All rights reserved.
 */

#include "plugin.h"

#include "Crypto/key.h"
#include "Crypto/certificate.h"

#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>
#include <QtCore/QCryptographicHash>

Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)

Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::CryptokiPlugin(QObject *parent)
    : Sailfish::Crypto::CryptoPlugin(parent)
{
    //osslevp_init();
    //TODO: WIP
}

Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::~CryptokiPlugin()
{
}

QVector<Sailfish::Crypto::Key::Algorithm>
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::supportedAlgorithms() const
{
    QVector<Sailfish::Crypto::Key::Algorithm> retn;
    retn.append(Sailfish::Crypto::Key::Aes256);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes>
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::supportedBlockModes() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::BlockModeCBC);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings>
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::supportedEncryptionPaddings() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::EncryptionPaddingNone);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings>
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::supportedSignaturePaddings() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::SignaturePaddingNone);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests>
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::supportedDigests() const
{
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::DigestSha256);
    return retn;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations>
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::supportedOperations() const
{
    // TODO: should this be algorithm specific?  not sure?
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> retn;
    retn.insert(Sailfish::Crypto::Key::Aes256, Sailfish::Crypto::Key::Encrypt | Sailfish::Crypto::Key::Decrypt);
    return retn;
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::validateCertificateChain(
        const QVector<Sailfish::Crypto::Certificate> &chain,
        bool *validated)
{
    Q_UNUSED(chain);
    Q_UNUSED(validated);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: CryptokiPlugin::validateCertificateChain"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::generateKey(
        const Sailfish::Crypto::Key &keyTemplate,
        Sailfish::Crypto::Key *key)
{
    //WIP
    Q_UNUSED(key);
    Q_UNUSED(keyTemplate);

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::generateAndStoreKey(
        const Sailfish::Crypto::Key &keyTemplate,
        Sailfish::Crypto::Key *keyMetadata)
{
    Q_UNUSED(keyTemplate);
    Q_UNUSED(keyMetadata);
    //WIP
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The CryptokiPlugin doesn't support storing keys"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::storedKey(
        const Sailfish::Crypto::Key::Identifier &identifier,
        Sailfish::Crypto::Key *key)
{
    Q_UNUSED(identifier);
    Q_UNUSED(key);
    //WIP
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The CryptokiPlugin doesn't support storing keys"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::deleteStoredKey(
        const Sailfish::Crypto::Key::Identifier &identifier)
{
    Q_UNUSED(identifier);
    //WIP
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The CryptokiPlugin doesn't support storing keys"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::storedKeyIdentifiers(
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
{
    Q_UNUSED(identifiers);
    //WIP
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The CryptokiPlugin doesn't support storing keys"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::sign(
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
    //WIP
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: CryptokiPlugin::sign"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::verify(
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
                                    QLatin1String("TODO: CryptokiPlugin::verify"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::encrypt(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        QByteArray *encrypted)
{
    // WIP

    Q_UNUSED(data);
    Q_UNUSED(key);
    Q_UNUSED(blockMode);
    Q_UNUSED(digest);
    Q_UNUSED(padding);
    Q_UNUSED(encrypted);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::CryptokiPlugin::decrypt(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        QByteArray *decrypted)
{
    Q_UNUSED(data);
    Q_UNUSED(key);
    Q_UNUSED(blockMode);
    Q_UNUSED(digest);
    Q_UNUSED(padding);
    Q_UNUSED(decrypted);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    //WIP
}

