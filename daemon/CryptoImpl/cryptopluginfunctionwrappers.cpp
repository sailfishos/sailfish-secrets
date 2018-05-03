/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "CryptoImpl/cryptopluginfunctionwrappers_p.h"
#include "SecretsImpl/metadatadb_p.h"
#include "logging_p.h"
#include "util_p.h"

using namespace Sailfish::Crypto;
using namespace Sailfish::Crypto::Daemon::ApiImpl;
using namespace Sailfish::Secrets::Daemon::Util;

/* These methods are to be called via QtConcurrent */

bool CryptoPluginFunctionWrapper::isLocked(
        CryptoPlugin *plugin)
{
    return plugin->isLocked();
}

bool CryptoPluginFunctionWrapper::lock(
        CryptoPlugin *plugin)
{
    return plugin->lock();
}

bool CryptoPluginFunctionWrapper::unlock(
        CryptoPlugin *plugin,
        const QByteArray &lockCode)
{
    return plugin->unlock(lockCode);
}

bool CryptoPluginFunctionWrapper::setLockCode(
        CryptoPlugin *plugin,
        const QByteArray &oldLockCode,
        const QByteArray &newLockCode)
{
    return plugin->setLockCode(oldLockCode, newLockCode);
}

DataResult CryptoPluginFunctionWrapper::generateRandomData(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes)
{
    QByteArray randomData;
    Result result = pluginAndCustomParams.plugin->generateRandomData(
                callerIdent,
                csprngEngineName,
                numberBytes,
                pluginAndCustomParams.customParameters,
                &randomData);
    return DataResult(result, randomData);
}

Result CryptoPluginFunctionWrapper::seedRandomDataGenerator(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 callerIdent,
        const QString &csprngEngineName,
        const QByteArray &seedData,
        double entropyEstimate)
{
    return pluginAndCustomParams.plugin->seedRandomDataGenerator(
                callerIdent,
                csprngEngineName,
                seedData,
                entropyEstimate,
                pluginAndCustomParams.customParameters);
}

DataResult CryptoPluginFunctionWrapper::generateInitializationVector(
        const PluginAndCustomParams &pluginAndCustomParams,
        CryptoManager::Algorithm algorithm,
        CryptoManager::BlockMode blockMode,
        int keySize)
{
    QByteArray iv;
    Result result = pluginAndCustomParams.plugin->generateInitializationVector(
                algorithm, blockMode, keySize,
                pluginAndCustomParams.customParameters,
                &iv);
    return DataResult(result, iv);
}

KeyResult CryptoPluginFunctionWrapper::importKey(
        const PluginAndCustomParams &pluginAndCustomParams,
        const QByteArray &keyData,
        const QByteArray &passphrase)
{
    Key key;
    Result result = pluginAndCustomParams.plugin->importKey(
                keyData, passphrase,
                pluginAndCustomParams.customParameters,
                &key);
    return KeyResult(result, key);
}

KeyResult CryptoPluginFunctionWrapper::importAndStoreKey(
        const PluginWrapperAndCustomParams &pluginAndCustomParams,
        const QByteArray &keyData,
        const Sailfish::Crypto::Key &keyTemplate,
        const QByteArray &passphrase,
        const QByteArray &collectionDecryptionKey)
{
    Sailfish::Secrets::Daemon::ApiImpl::CollectionMetadata collectionMetadata;
    Sailfish::Secrets::Result sresult = pluginAndCustomParams.plugin->collectionMetadata(
                keyTemplate.identifier().collectionName(),
                &collectionMetadata);
    if (sresult.code() != Sailfish::Secrets::Result::Succeeded) {
        return KeyResult(transformSecretsResult(sresult), keyTemplate);
    }

    Sailfish::Secrets::Daemon::ApiImpl::SecretMetadata metadata;
    metadata.collectionName = keyTemplate.identifier().collectionName();
    metadata.secretName = keyTemplate.identifier().name();
    metadata.ownerApplicationId = collectionMetadata.ownerApplicationId;
    metadata.usesDeviceLockKey = collectionMetadata.usesDeviceLockKey;
    metadata.encryptionPluginName = collectionMetadata.encryptionPluginName;
    metadata.authenticationPluginName = collectionMetadata.authenticationPluginName;
    metadata.unlockSemantic = collectionMetadata.unlockSemantic;
    metadata.accessControlMode = collectionMetadata.accessControlMode;
    metadata.secretType = Sailfish::Secrets::Secret::TypeCryptoKey;
    metadata.cryptoPluginName = pluginAndCustomParams.plugin->name();

    Key keyReference(keyTemplate);
    Result result = pluginAndCustomParams.plugin->importAndStoreKey(
                metadata,
                keyData,
                keyTemplate,
                passphrase,
                pluginAndCustomParams.customParameters,
                collectionDecryptionKey,
                &keyReference);
    return KeyResult(result, keyReference);
}

KeyResult CryptoPluginFunctionWrapper::generateKey(
        const PluginAndCustomParams &pluginAndCustomParams,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams)
{
    Key key(keyTemplate);
    Result result = pluginAndCustomParams.plugin->generateKey(
                keyTemplate, kpgParams, skdfParams,
                pluginAndCustomParams.customParameters,
                &key);
    return KeyResult(result, key);
}

KeyResult CryptoPluginFunctionWrapper::storedKey(
        CryptoPlugin *plugin,
        const Key::Identifier &identifier,
        Key::Components keyComponents)
{
    Key key;
    key.setIdentifier(identifier);
    Result result = plugin->storedKey(
                identifier, keyComponents, &key);
    return KeyResult(result, key);
}

IdentifiersResult CryptoPluginFunctionWrapper::storedKeyIdentifiers(
        CryptoPlugin *plugin,
        const QString &collectionName)
{
    QVector<Key::Identifier> identifiers;
    Result result = plugin->storedKeyIdentifiers(collectionName, &identifiers);
    return IdentifiersResult(result, identifiers);
}

DataResult CryptoPluginFunctionWrapper::calculateDigest(
        const PluginAndCustomParams &pluginAndCustomParams,
        const QByteArray &data,
        const SignatureOptions &options)
{
    QByteArray digest;
    Result result = pluginAndCustomParams.plugin->calculateDigest(
                data,
                options.signaturePadding,
                options.digestFunction,
                pluginAndCustomParams.customParameters,
                &digest);
    return DataResult(result, digest);
}

DataResult CryptoPluginFunctionWrapper::sign(
        const PluginAndCustomParams &pluginAndCustomParams,
        const QByteArray &data,
        const Key &key,
        const SignatureOptions &options)
{
    QByteArray signature;
    Result result = pluginAndCustomParams.plugin->sign(
                data, key,
                options.signaturePadding,
                options.digestFunction,
                pluginAndCustomParams.customParameters,
                &signature);
    return DataResult(result, signature);
}

ValidatedResult CryptoPluginFunctionWrapper::verify(
        const PluginAndCustomParams &pluginAndCustomParams,
        const QByteArray &signature,
        const QByteArray &data,
        const Key &key,
        const SignatureOptions &options)
{
    bool verified = false;
    Result result = pluginAndCustomParams.plugin->verify(
                signature, data, key,
                options.signaturePadding,
                options.digestFunction,
                pluginAndCustomParams.customParameters,
                &verified);
    return ValidatedResult(result, verified);
}

TagDataResult CryptoPluginFunctionWrapper::encrypt(
        const PluginAndCustomParams &pluginAndCustomParams,
        const DataAndIV &dataAndIv,
        const Sailfish::Crypto::Key &key,
        const EncryptionOptions &options,
        const QByteArray &authenticationData)
{
    QByteArray ciphertext;
    QByteArray authenticationTag;
    Result result = pluginAndCustomParams.plugin->encrypt(
                dataAndIv.data,
                dataAndIv.initVector,
                key,
                options.blockMode,
                options.encryptionPadding,
                authenticationData,
                pluginAndCustomParams.customParameters,
                &ciphertext, &authenticationTag);
    return TagDataResult(result, ciphertext, authenticationTag);
}

VerifiedDataResult CryptoPluginFunctionWrapper::decrypt(
        const PluginAndCustomParams &pluginAndCustomParams,
        const DataAndIV &dataAndIv,
        const Key &key, // or keyreference, i.e. Key(keyName)
        const EncryptionOptions &options,
        const AuthDataAndTag &authDataAndTag)
{
    QByteArray plaintext;
    bool verified = false;
    Result result = pluginAndCustomParams.plugin->decrypt(
                dataAndIv.data,
                dataAndIv.initVector,
                key,
                options.blockMode,
                options.encryptionPadding,
                authDataAndTag.authData,
                authDataAndTag.tag,
                pluginAndCustomParams.customParameters,
                &plaintext, &verified);
    return VerifiedDataResult(result, plaintext, verified);
}

CipherSessionTokenResult CryptoPluginFunctionWrapper::initializeCipherSession(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 clientId,
        const QByteArray &iv,
        const Key &key, // or keyreference, i.e. Key(keyName)
        const CipherSessionOptions &options)
{
    quint32 cipherSessionToken = 0;
    Result result = pluginAndCustomParams.plugin->initializeCipherSession(
                clientId,
                iv,
                key,
                options.operation,
                options.blockMode,
                options.encryptionPadding,
                options.signaturePadding,
                options.digestFunction,
                pluginAndCustomParams.customParameters,
                &cipherSessionToken);
    return CipherSessionTokenResult(result, cipherSessionToken);
}

Result CryptoPluginFunctionWrapper::updateCipherSessionAuthentication(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 clientId,
        const QByteArray &authenticationData,
        quint32 cipherSessionToken)
{
    return pluginAndCustomParams.plugin->updateCipherSessionAuthentication(
                clientId, authenticationData,
                pluginAndCustomParams.customParameters,
                cipherSessionToken);
}

DataResult CryptoPluginFunctionWrapper::updateCipherSession(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken)
{
    QByteArray generatedData;
    Result result = pluginAndCustomParams.plugin->updateCipherSession(
                clientId, data,
                pluginAndCustomParams.customParameters,
                cipherSessionToken,
                &generatedData);
    return DataResult(result, generatedData);
}

VerifiedDataResult CryptoPluginFunctionWrapper::finalizeCipherSession(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken)
{
    bool verified = false;
    QByteArray generatedData;
    Result result = pluginAndCustomParams.plugin->finalizeCipherSession(
                clientId, data,
                pluginAndCustomParams.customParameters,
                cipherSessionToken,
                &generatedData, &verified);
    return VerifiedDataResult(result, generatedData, verified);
}

KeyResult CryptoPluginFunctionWrapper::generateAndStoreKey(
        const PluginWrapperAndCustomParams &pluginAndCustomParams,
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        const QByteArray &collectionUnlockCode)
{
    Sailfish::Secrets::Daemon::ApiImpl::CollectionMetadata collectionMetadata;
    Sailfish::Secrets::Result sresult = pluginAndCustomParams.plugin->collectionMetadata(
                keyTemplate.identifier().collectionName(),
                &collectionMetadata);
    if (sresult.code() != Sailfish::Secrets::Result::Succeeded) {
        return KeyResult(transformSecretsResult(sresult), keyTemplate);
    }

    Sailfish::Secrets::Daemon::ApiImpl::SecretMetadata metadata;
    metadata.collectionName = keyTemplate.identifier().collectionName();
    metadata.secretName = keyTemplate.identifier().name();
    metadata.ownerApplicationId = collectionMetadata.ownerApplicationId;
    metadata.usesDeviceLockKey = collectionMetadata.usesDeviceLockKey;
    metadata.encryptionPluginName = collectionMetadata.encryptionPluginName;
    metadata.authenticationPluginName = collectionMetadata.authenticationPluginName;
    metadata.unlockSemantic = collectionMetadata.unlockSemantic;
    metadata.accessControlMode = collectionMetadata.accessControlMode;
    metadata.secretType = Sailfish::Secrets::Secret::TypeCryptoKey;
    metadata.cryptoPluginName = pluginAndCustomParams.plugin->name();

    Key keyReference(keyTemplate);
    Result result = pluginAndCustomParams.plugin->generateAndStoreKey(
                metadata,
                keyTemplate,
                kpgParams,
                skdfParams,
                pluginAndCustomParams.customParameters,
                collectionUnlockCode,
                &keyReference);
    return KeyResult(result, keyReference);
}
