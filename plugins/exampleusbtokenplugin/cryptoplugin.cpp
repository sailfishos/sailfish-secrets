/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "exampleusbtokenplugin.h"

#include "Crypto/key.h"
#include "Crypto/result.h"

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
ExampleUsbTokenPlugin::readDefaultKeyFromUsbToken() const
{
    // This is merely an example.  In a real USB token-backed plugin,
    // this method would read the key from the USB token.
    return m_usbTokenKey;
}

Result
ExampleUsbTokenPlugin::seedRandomDataGenerator(
        quint64 /* callerIdent */,
        const QString & /* csprngEngineName */,
        const QByteArray & /* seedData */,
        double /* entropyEstimate */,
        const QVariantMap & /* customParameters */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginRandomDataError,
                                    QLatin1String("The ExampleUsbToken plugin doesn't support client-provided seed data"));
}

Result
ExampleUsbTokenPlugin::generateAndStoreKey(
        const Key & /* keyTemplate */,
        const KeyPairGenerationParameters & /* kpgParams */,
        const KeyDerivationParameters & /* skdfParams */,
        const QVariantMap & /* customParameters */,
        Key * /* keyMetadata */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The ExampleUsbToken plugin doesn't support generating or storing new keys"));
}


Result
ExampleUsbTokenPlugin::importAndStoreKey(
        const Key & /* key */,
        const QByteArray & /* passphrase */,
        const QVariantMap & /* customParameters */,
        Key * /* keyMetadata */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The ExampleUsbToken plugin doesn't support importing or storing new keys"));
}

Result
ExampleUsbTokenPlugin::storedKey(
        const Key::Identifier &identifier,
        Key::Components keyComponents,
        Key *key)
{
    Q_UNUSED(keyComponents) // we only ever return metadata and public key data, not private key data.
    if (identifier.storagePluginName() == name()
            && identifier.collectionName() == QStringLiteral("Default")
            && identifier.name() == QStringLiteral("Default")) {
        *key = readDefaultKeyFromUsbToken();
        nullifyKeyFields(key, Key::MetaData | Key::PublicKeyData);
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                        QLatin1String("The ExampleUsbToken plugin only stores the Default key in the Default collection"));
    }
}

Result
ExampleUsbTokenPlugin::storedKeyIdentifiers(
        const QString &collectionName,
        QVector<Key::Identifier> *identifiers)
{
    if (collectionName != QStringLiteral("Default")) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                        QLatin1String("The ExampleUsbToken plugin has only a single Default collection"));
    }

    identifiers->clear();
    identifiers->append(Key::Identifier(QStringLiteral("Default"),
                                        QStringLiteral("Default"),
                                        name()));

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}


Result
ExampleUsbTokenPlugin::getFullKey(
        const Key &key,
        Key *fullKey) const
{
    // we only allow clients to use the key stored in our storage for crypto operations.
    if (key.identifier().storagePluginName() != name()
            && key.identifier().collectionName() != QStringLiteral("Default")
            && key.identifier().name() != QStringLiteral("Default")) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                        QLatin1String("The ExampleUsbToken plugin only stores the Default key in the Default collection"));
    }

    *fullKey = readDefaultKeyFromUsbToken();
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Result
ExampleUsbTokenPlugin::generateRandomData(
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes,
        const QVariantMap &customParameters,
        QByteArray *randomData)
{
    return m_usbInterface.generateRandomData(
                callerIdent,
                csprngEngineName,
                numberBytes,
                customParameters,
                randomData);
}

Result
ExampleUsbTokenPlugin::generateInitializationVector(
        CryptoManager::Algorithm algorithm,
        CryptoManager::BlockMode blockMode,
        int keySize,
        const QVariantMap &customParameters,
        QByteArray *generatedIV)
{
    return m_usbInterface.generateInitializationVector(
                algorithm,
                blockMode,
                keySize,
                customParameters,
                generatedIV);
}

Result
ExampleUsbTokenPlugin::generateKey(
        const Key & /* keyTemplate */,
        const KeyPairGenerationParameters & /* kpgParams */,
        const KeyDerivationParameters & /* skdfParams */,
        const QVariantMap & /* customParameters */,
        Key * /* key */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The ExampleUsbToken plugin doesn't support generating or storing new keys"));
}

Result
ExampleUsbTokenPlugin::importKey(
        const Key & /* key */,
        const QByteArray & /* passphrase */,
        const QVariantMap & /* customParameters */,
        Key * /* importedKey */)
{
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("The ExampleUsbToken plugin doesn't support importing or storing new keys"));
}

Result
ExampleUsbTokenPlugin::calculateDigest(
        const QByteArray &data,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        QByteArray *digest)
{
    return m_usbInterface.calculateDigest(
                data,
                padding,
                digestFunction,
                customParameters,
                digest);
}

Result
ExampleUsbTokenPlugin::sign(
        const QByteArray &data,
        const Key &key,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        QByteArray *signature)
{
    Key fullKey;
    Sailfish::Crypto::Result keyResult = getFullKey(key, &fullKey);
    if (keyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        return keyResult;
    }

    return m_usbInterface.sign(
                data,
                fullKey,
                padding,
                digestFunction,
                customParameters,
                signature);
}

Result
ExampleUsbTokenPlugin::verify(
        const QByteArray &signature,
        const QByteArray &data,
        const Key &key,
        CryptoManager::SignaturePadding padding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        bool *verified)
{
    Key fullKey;
    Sailfish::Crypto::Result keyResult = getFullKey(key, &fullKey);
    if (keyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        return keyResult;
    }

    return m_usbInterface.verify(
                signature,
                data,
                fullKey,
                padding,
                digestFunction,
                customParameters,
                verified);
}

Result
ExampleUsbTokenPlugin::encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
        QByteArray *encrypted,
        QByteArray *authenticationTag)
{
    Key fullKey;
    Sailfish::Crypto::Result keyResult = getFullKey(key, &fullKey);
    if (keyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        return keyResult;
    }

    return m_usbInterface.encrypt(
                data,
                iv,
                fullKey,
                blockMode,
                padding,
                authenticationData,
                customParameters,
                encrypted,
                authenticationTag);
}

Result
ExampleUsbTokenPlugin::decrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QByteArray &authenticationTag,
        const QVariantMap &customParameters,
        QByteArray *decrypted,
        bool *verified)
{
    Key fullKey;
    Sailfish::Crypto::Result keyResult = getFullKey(key, &fullKey);
    if (keyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        return keyResult;
    }

    return m_usbInterface.decrypt(
                data,
                iv,
                fullKey,
                blockMode,
                padding,
                authenticationData,
                authenticationTag,
                customParameters,
                decrypted,
                verified);
}

Result
ExampleUsbTokenPlugin::initialiseCipherSession(
        quint64 clientId,
        const QByteArray &iv,
        const Key &key, // or keyreference, i.e. Key(keyName)
        CryptoManager::Operation operation,
        CryptoManager::BlockMode blockMode,
        CryptoManager::EncryptionPadding encryptionPadding,
        CryptoManager::SignaturePadding signaturePadding,
        CryptoManager::DigestFunction digestFunction,
        const QVariantMap &customParameters,
        quint32 *cipherSessionToken)
{
    Key fullKey;
    Sailfish::Crypto::Result keyResult = getFullKey(key, &fullKey);
    if (keyResult.code() != Sailfish::Crypto::Result::Succeeded) {
        return keyResult;
    }

    return m_usbInterface.initialiseCipherSession(
                clientId,
                iv,
                fullKey,
                operation,
                blockMode,
                encryptionPadding,
                signaturePadding,
                digestFunction,
                customParameters,
                cipherSessionToken);
}

Result
ExampleUsbTokenPlugin::updateCipherSessionAuthentication(
        quint64 clientId,
        const QByteArray &authenticationData,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken)
{
    return m_usbInterface.updateCipherSessionAuthentication(
                clientId,
                authenticationData,
                customParameters,
                cipherSessionToken);
}

Result
ExampleUsbTokenPlugin::updateCipherSession(
        quint64 clientId,
        const QByteArray &data,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken,
        QByteArray *generatedData)
{
    return m_usbInterface.updateCipherSession(
                clientId,
                data,
                customParameters,
                cipherSessionToken,
                generatedData);
}

Result
ExampleUsbTokenPlugin::finaliseCipherSession(
        quint64 clientId,
        const QByteArray &data,
        const QVariantMap &customParameters,
        quint32 cipherSessionToken,
        QByteArray *generatedData,
        bool *verified)
{
    return m_usbInterface.finaliseCipherSession(
                clientId,
                data,
                customParameters,
                cipherSessionToken,
                generatedData,
                verified);
}
