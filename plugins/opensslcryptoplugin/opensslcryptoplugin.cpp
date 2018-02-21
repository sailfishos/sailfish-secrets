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
#include "Crypto/generaterandomdatarequest.h"
#include "Crypto/seedrandomdatageneratorrequest.h"

#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>
#include <QtCore/QUuid>
#include <QtCore/QCryptographicHash>

#include <fstream>
#include <cstdlib>

#include <openssl/rand.h>

Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)

using namespace Sailfish::Crypto;

Daemon::Plugins::OpenSslCryptoPlugin::OpenSslCryptoPlugin(QObject *parent)
    : QObject(parent), CryptoPlugin()
{
    // seed the RNG
    char seed[1024] = {0};
    std::ifstream rand("/dev/urandom");
    rand.read(seed, 1024);
    rand.close();
    RAND_add(seed, 1024, 1.0);

    // initialise EVP
    osslevp_init();
}

Daemon::Plugins::OpenSslCryptoPlugin::~OpenSslCryptoPlugin()
{
}

Result
Daemon::Plugins::OpenSslCryptoPlugin::seedRandomDataGenerator(
        quint64 callerIdent,
        const QString &csprngEngineName,
        const QByteArray &seedData,
        double entropyEstimate)
{
    Q_UNUSED(callerIdent)

    if (csprngEngineName != GenerateRandomDataRequest::DefaultCsprngEngineName) {
        return Result(Result::CryptoPluginRandomDataError,
                      QLatin1String("The OpenSSL crypto plugin doesn't currently support other RNG engines")); // TODO!
    }

    // Note: this will affect all clients, as we don't currently separate RNGs based on callerIdent.
    // TODO: initialise separate RNG engine instances for separate callers?
    RAND_add(seedData.constData(), seedData.size(), entropyEstimate);
    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::OpenSslCryptoPlugin::generateAndStoreKey(
        const Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        Key *keyMetadata)
{
    Q_UNUSED(keyTemplate);
    Q_UNUSED(kpgParams);
    Q_UNUSED(skdfParams);
    Q_UNUSED(keyMetadata);
    return Result(Result::UnsupportedOperation,
                  QLatin1String("The OpenSSL crypto plugin doesn't support storing keys"));
}

Result
Daemon::Plugins::OpenSslCryptoPlugin::storedKey(
        const Key::Identifier &identifier,
        Key::Components keyComponents,
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

Key
Daemon::Plugins::OpenSslCryptoPlugin::getFullKey(
        const Sailfish::Crypto::Key &key)
{
    return key; // OpenSSL Crypto Plugin doesn't store keys, so we get what we were given.
}

#define CRYPTOPLUGINCOMMON_NAMESPACE Daemon::Plugins
#define CRYPTOPLUGINCOMMON_CLASS OpenSslCryptoPlugin
#include "cryptoplugin_common.cpp"
