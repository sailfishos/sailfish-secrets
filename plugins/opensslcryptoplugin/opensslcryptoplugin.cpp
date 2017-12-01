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

Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::OpenSslCryptoPlugin(QObject *parent)
    : QObject(parent), Sailfish::Crypto::CryptoPlugin()
{
    osslevp_init();
}

Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::~OpenSslCryptoPlugin()
{
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::generateAndStoreKey(
        const Sailfish::Crypto::Key &keyTemplate,
        Sailfish::Crypto::Key *keyMetadata)
{
    Q_UNUSED(keyTemplate);
    Q_UNUSED(keyMetadata);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The OpenSSL crypto plugin doesn't support storing keys"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::storedKey(
        const Sailfish::Crypto::Key::Identifier &identifier,
        Sailfish::Crypto::Key *key)
{
    Q_UNUSED(identifier);
    Q_UNUSED(key);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The OpenSSL crypto plugin doesn't support storing keys"));
}

Sailfish::Crypto::Result
Sailfish::Crypto::Daemon::Plugins::OpenSslCryptoPlugin::storedKeyIdentifiers(
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
{
    Q_UNUSED(identifiers);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The OpenSSL crypto plugin doesn't support storing keys"));
}

#define CRYPTOPLUGINCOMMON_NAMESPACE Sailfish::Crypto::Daemon::Plugins
#define CRYPTOPLUGINCOMMON_CLASS OpenSslCryptoPlugin
#include "cryptoplugin_common.cpp"
