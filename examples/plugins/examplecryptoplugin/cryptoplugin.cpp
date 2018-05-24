/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"

#include <Crypto/key.h>
#include <Crypto/result.h>

#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>

#include <QtDebug>

using namespace Sailfish::Secrets::Daemon::Plugins;
using namespace Sailfish::Crypto;

namespace {
    void nullifyKeyFields(Key *key, Key::Components keep) {
        // Null-out fields if the client hasn't specified that they be kept,
        // or which the key component constraints don't allow to be read back.
        // Note that by default we treat CustomParameters as PublicKeyData.
        Key::Components kcc = key->componentConstraints();
        if (!(keep & Key::MetaData)
                || !(kcc & Key::MetaData)) {
            key->setIdentifier(Key::Identifier());
            key->setOrigin(Key::OriginUnknown);
            key->setAlgorithm(CryptoManager::AlgorithmUnknown);
            key->setOperations(CryptoManager::OperationUnknown);
            key->setComponentConstraints(Key::NoData);
            key->setFilterData(Key::FilterData());
        }

        if (!(keep & Key::PublicKeyData)
                || !(kcc & Key::PublicKeyData)) {
            key->setCustomParameters(QVector<QByteArray>());
            key->setPublicKey(QByteArray());
        }

        if (!(keep & Key::PrivateKeyData)
                || !(kcc & Key::PrivateKeyData)) {
            key->setPrivateKey(QByteArray());
            key->setSecretKey(QByteArray());
        }
    }
}

Result
ExampleCryptoPlugin::seedRandomDataGenerator(
        quint64 /* callerIdent */,
        const QString & /* csprngEngineName */,
        const QByteArray & /* seedData */,
        double /* entropyEstimate */,
        const QVariantMap & /* customParameters */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginRandomDataError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support client-provided seed data"));
}

Result
ExampleCryptoPlugin::generateAndStoreKey(
        const Key & /* keyTemplate */,
        const KeyPairGenerationParameters & /* kpgParams */,
        const KeyDerivationParameters & /* skdfParams */,
        const QVariantMap & /* customParameters */,
        Key * /* keyMetadata */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support generating or storing keys"));
}


Result
ExampleCryptoPlugin::importAndStoreKey(
        const QByteArray & /* data */,
        const Key & /* keyTemplate */,
        const QByteArray & /* passphrase */,
        const QVariantMap & /* customParameters */,
        Key * /* keyMetadata */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support importing or storing keys"));
}

Result
ExampleCryptoPlugin::storedKey(
        const Key::Identifier &,
        Key::Components ,
        const QVariantMap &,
        Key *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support importing or storing keys"));
}

Result
ExampleCryptoPlugin::storedKeyIdentifiers(
        const QString &,
        const QVariantMap &,
        QVector<Key::Identifier> *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support storing keys"));
}

Result
ExampleCryptoPlugin::generateRandomData(
        quint64 ,
        const QString & ,
        quint64 ,
        const QVariantMap & ,
        QByteArray *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}

Result
ExampleCryptoPlugin::generateInitializationVector(
        CryptoManager::Algorithm ,
        CryptoManager::BlockMode ,
        int ,
        const QVariantMap &,
        QByteArray *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}

Result
ExampleCryptoPlugin::generateKey(
        const Key & /* keyTemplate */,
        const KeyPairGenerationParameters & /* kpgParams */,
        const KeyDerivationParameters & /* skdfParams */,
        const QVariantMap & /* customParameters */,
        Key * /* key */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}

Result
ExampleCryptoPlugin::importKey(
        const QByteArray & /* keyData */,
        const QByteArray & /* passphrase */,
        const QVariantMap & /* customParameters */,
        Key * /* importedKey */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support importing or storing keys"));
}

Result
ExampleCryptoPlugin::calculateDigest(
        const QByteArray &,
        CryptoManager::SignaturePadding ,
        CryptoManager::DigestFunction ,
        const QVariantMap &,
        QByteArray *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}

Result
ExampleCryptoPlugin::sign(
        const QByteArray &,
        const Key &,
        CryptoManager::SignaturePadding ,
        CryptoManager::DigestFunction ,
        const QVariantMap &,
        QByteArray *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}

Result
ExampleCryptoPlugin::verify(
        const QByteArray &,
        const QByteArray &,
        const Key &,
        CryptoManager::SignaturePadding ,
        CryptoManager::DigestFunction ,
        const QVariantMap &,
        Sailfish::Crypto::CryptoManager::VerificationStatus *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}

Result
ExampleCryptoPlugin::encrypt(
        const QByteArray &,
        const QByteArray &,
        const Key &,
        CryptoManager::BlockMode ,
        CryptoManager::EncryptionPadding ,
        const QByteArray &,
        const QVariantMap &,
        QByteArray *,
        QByteArray *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}

Result
ExampleCryptoPlugin::decrypt(
        const QByteArray &,
        const QByteArray &,
        const Key &,
        CryptoManager::BlockMode ,
        CryptoManager::EncryptionPadding ,
        const QByteArray &,
        const QByteArray &,
        const QVariantMap &,
        QByteArray *,
        Sailfish::Crypto::CryptoManager::VerificationStatus *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}

Result
ExampleCryptoPlugin::initializeCipherSession(
        quint64 ,
        const QByteArray &,
        const Key &, // or keyreference, i.e. Key(keyName)
        CryptoManager::Operation ,
        CryptoManager::BlockMode ,
        CryptoManager::EncryptionPadding ,
        CryptoManager::SignaturePadding ,
        CryptoManager::DigestFunction ,
        const QVariantMap &,
        quint32 *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}

Result
ExampleCryptoPlugin::updateCipherSessionAuthentication(
        quint64 ,
        const QByteArray &,
        const QVariantMap &,
        quint32 )
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}

Result
ExampleCryptoPlugin::updateCipherSession(
        quint64 ,
        const QByteArray &,
        const QVariantMap &,
        quint32 ,
        QByteArray *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}

Result
ExampleCryptoPlugin::finalizeCipherSession(
        quint64 ,
        const QByteArray &,
        const QVariantMap &,
        quint32 ,
        QByteArray *,
        Sailfish::Crypto::CryptoManager::VerificationStatus *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoPlugin doesn't support anything"));
}
