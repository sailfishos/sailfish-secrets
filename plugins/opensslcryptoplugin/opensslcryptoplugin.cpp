/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "opensslcryptoplugin.h"
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

using namespace Sailfish::Crypto;

Daemon::Plugins::OpenSslCryptoPlugin::OpenSslCryptoPlugin(QObject *parent)
    : QObject(parent), CryptoPlugin()
{
    osslevp_init();
}

Daemon::Plugins::OpenSslCryptoPlugin::~OpenSslCryptoPlugin()
{
}

Result
Daemon::Plugins::OpenSslCryptoPlugin::generateAndStoreKey(
        const Key &keyTemplate,
        Key *keyMetadata)
{
    Q_UNUSED(keyTemplate);
    Q_UNUSED(keyMetadata);
    return Result(Result::UnsupportedOperation,
                  QLatin1String("The OpenSSL crypto plugin doesn't support storing keys"));
}

Result
Daemon::Plugins::OpenSslCryptoPlugin::storedKey(
        const Key::Identifier &identifier,
        StoredKeyRequest::KeyComponents keyComponents,
        Key *key)
{
    Q_UNUSED(identifier);
    Q_UNUSED(keyComponents);
    Q_UNUSED(key);
    return Result(Result::UnsupportedOperation,
                  QLatin1String("The OpenSSL crypto plugin doesn't support storing keys"));
}

Result
Daemon::Plugins::OpenSslCryptoPlugin::storedKeyIdentifiers(
        QVector<Key::Identifier> *identifiers)
{
    Q_UNUSED(identifiers);
    return Result(Result::UnsupportedOperation,
                  QLatin1String("The OpenSSL crypto plugin doesn't support storing keys"));
}

#define CRYPTOPLUGINCOMMON_NAMESPACE Daemon::Plugins
#define CRYPTOPLUGINCOMMON_CLASS OpenSslCryptoPlugin
#include "cryptoplugin_common.cpp"
