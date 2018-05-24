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

Key
ExampleCryptoStoragePlugin::readDefaultKeyFromUsbToken() const
{
    // This is merely an example.  In a real USB token-backed plugin,
    // this method would read the key from the USB token.
    return m_builtInKey;
}

Result
ExampleCryptoStoragePlugin::seedRandomDataGenerator(
        quint64 /* callerIdent */,
        const QString & /* csprngEngineName */,
        const QByteArray & /* seedData */,
        double /* entropyEstimate */,
        const QVariantMap & /* customParameters */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginRandomDataError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support client-provided seed data"));
}

Result
ExampleCryptoStoragePlugin::generateAndStoreKey(
        const Key & /* keyTemplate */,
        const KeyPairGenerationParameters & /* kpgParams */,
        const KeyDerivationParameters & /* skdfParams */,
        const QVariantMap & /* customParameters */,
        Key * /* keyMetadata */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support generating or storing new keys"));
}


Result
ExampleCryptoStoragePlugin::importAndStoreKey(
        const QByteArray & /* data */,
        const Key & /* keyTemplate */,
        const QByteArray & /* passphrase */,
        const QVariantMap & /* customParameters */,
        Key * /* keyMetadata */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support importing or storing new keys"));
}

Result
ExampleCryptoStoragePlugin::storedKey(
        const Key::Identifier &identifier,
        Key::Components keyComponents,
        const QVariantMap &customParameters,
        Key *key)
{
    Q_UNUSED(keyComponents) // we only ever return metadata and public key data, not private key data.
    Q_UNUSED(customParameters)
    if (identifier.storagePluginName() == name()
            && identifier.collectionName() == QStringLiteral("Default")
            && identifier.name() == QStringLiteral("Default")) {
        *key = readDefaultKeyFromUsbToken();
        nullifyKeyFields(key, Key::MetaData | Key::PublicKeyData);
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                        QLatin1String("The ExampleCryptoStoragePlugin only stores the Default key in the Default collection"));
    }
}

Result
ExampleCryptoStoragePlugin::storedKeyIdentifiers(
        const QString &collectionName,
        const QVariantMap &customParameters,
        QVector<Key::Identifier> *identifiers)
{
    Q_UNUSED(customParameters)
    if (collectionName != QStringLiteral("Default")) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                        QLatin1String("The ExampleCryptoStoragePlugin has only a single Default collection"));
    }

    identifiers->clear();
    identifiers->append(Key::Identifier(QStringLiteral("Default"),
                                        QStringLiteral("Default"),
                                        name()));

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}


Result
ExampleCryptoStoragePlugin::getFullKey(
        const Key &key,
        Key *fullKey) const
{
    // we only allow clients to use the key stored in our storage for crypto operations.
    if (key.identifier().storagePluginName() != name()
            && key.identifier().collectionName() != QStringLiteral("Default")
            && key.identifier().name() != QStringLiteral("Default")) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                        QLatin1String("The ExampleCryptoStoragePlugin only stores the Default key in the Default collection"));
    }

    *fullKey = readDefaultKeyFromUsbToken();
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Result
ExampleCryptoStoragePlugin::generateRandomData(
        quint64 ,
        const QString & ,
        quint64 ,
        const QVariantMap & ,
        QByteArray *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}

Result
ExampleCryptoStoragePlugin::generateInitializationVector(
        CryptoManager::Algorithm ,
        CryptoManager::BlockMode ,
        int ,
        const QVariantMap &,
        QByteArray *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}

Result
ExampleCryptoStoragePlugin::generateKey(
        const Key & /* keyTemplate */,
        const KeyPairGenerationParameters & /* kpgParams */,
        const KeyDerivationParameters & /* skdfParams */,
        const QVariantMap & /* customParameters */,
        Key * /* key */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}

Result
ExampleCryptoStoragePlugin::importKey(
        const QByteArray & /* keyData */,
        const QByteArray & /* passphrase */,
        const QVariantMap & /* customParameters */,
        Key * /* importedKey */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support importing or storing new keys"));
}

Result
ExampleCryptoStoragePlugin::calculateDigest(
        const QByteArray &,
        CryptoManager::SignaturePadding ,
        CryptoManager::DigestFunction ,
        const QVariantMap &,
        QByteArray *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}

Result
ExampleCryptoStoragePlugin::sign(
        const QByteArray &,
        const Key &,
        CryptoManager::SignaturePadding ,
        CryptoManager::DigestFunction ,
        const QVariantMap &,
        QByteArray *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}

Result
ExampleCryptoStoragePlugin::verify(
        const QByteArray &,
        const QByteArray &,
        const Key &,
        CryptoManager::SignaturePadding ,
        CryptoManager::DigestFunction ,
        const QVariantMap &,
        Sailfish::Crypto::CryptoManager::VerificationStatus *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}

Result
ExampleCryptoStoragePlugin::encrypt(
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
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}

Result
ExampleCryptoStoragePlugin::decrypt(
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
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}

Result
ExampleCryptoStoragePlugin::initializeCipherSession(
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
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}

Result
ExampleCryptoStoragePlugin::updateCipherSessionAuthentication(
        quint64 ,
        const QByteArray &,
        const QVariantMap &,
        quint32 )
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}

Result
ExampleCryptoStoragePlugin::updateCipherSession(
        quint64 ,
        const QByteArray &,
        const QVariantMap &,
        quint32 ,
        QByteArray *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}

Result
ExampleCryptoStoragePlugin::finalizeCipherSession(
        quint64 ,
        const QByteArray &,
        const QVariantMap &,
        quint32 ,
        QByteArray *,
        Sailfish::Crypto::CryptoManager::VerificationStatus *)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::OperationNotSupportedError,
                                    QLatin1String("The ExampleCryptoStoragePlugin doesn't support anything"));
}
