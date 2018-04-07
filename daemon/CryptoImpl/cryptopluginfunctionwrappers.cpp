/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "cryptopluginfunctionwrappers_p.h"
#include "logging_p.h"

using namespace Sailfish::Crypto;
using namespace Sailfish::Crypto::Daemon::ApiImpl;

/* These methods are to be called via QtConcurrent */

bool CryptoPluginWrapper::isLocked(
        CryptoPlugin *plugin)
{
    return plugin->isLocked();
}

bool CryptoPluginWrapper::lock(
        CryptoPlugin *plugin)
{
    return plugin->lock();
}

bool CryptoPluginWrapper::unlock(
        CryptoPlugin *plugin,
        const QByteArray &lockCode)
{
    return plugin->unlock(lockCode);
}

bool CryptoPluginWrapper::setLockCode(
        CryptoPlugin *plugin,
        const QByteArray &oldLockCode,
        const QByteArray &newLockCode)
{
    return plugin->setLockCode(oldLockCode, newLockCode);
}

DataResult CryptoPluginWrapper::generateRandomData(
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

Result CryptoPluginWrapper::seedRandomDataGenerator(
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

DataResult CryptoPluginWrapper::generateInitializationVector(
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

KeyResult CryptoPluginWrapper::importKey(
        const PluginAndCustomParams &pluginAndCustomParams,
        const Sailfish::Crypto::Key &keyData,
        const QByteArray &passphrase)
{
    Key key;
    Result result = pluginAndCustomParams.plugin->importKey(
                keyData, passphrase,
                pluginAndCustomParams.customParameters,
                &key);
    return KeyResult(result, key);
}

KeyResult CryptoPluginWrapper::importAndStoreKey(
        const PluginAndCustomParams &pluginAndCustomParams,
        const Sailfish::Crypto::Key &keyData,
        const QByteArray &passphrase)
{
    Key key;
    Result result = pluginAndCustomParams.plugin->importAndStoreKey(
                keyData, passphrase,
                pluginAndCustomParams.customParameters,
                &key);
    return KeyResult(result, key);
}

KeyResult CryptoPluginWrapper::generateKey(
        const PluginAndCustomParams &pluginAndCustomParams,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams)
{
    Key key;
    Result result = pluginAndCustomParams.plugin->generateKey(
                keyTemplate, kpgParams, skdfParams,
                pluginAndCustomParams.customParameters,
                &key);
    return KeyResult(result, key);
}

KeyResult CryptoPluginWrapper::generateAndStoreKey(
        const PluginAndCustomParams &pluginAndCustomParams,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams)
{
    Key keyReference;
    Result result = pluginAndCustomParams.plugin->generateAndStoreKey(
                keyTemplate, kpgParams, skdfParams,
                pluginAndCustomParams.customParameters,
                &keyReference);
    return KeyResult(result, keyReference);
}

KeyResult CryptoPluginWrapper::storedKey(
        CryptoPlugin *plugin,
        const Key::Identifier &identifier,
        Key::Components keyComponents)
{
    Key key;
    Result result = plugin->storedKey(
                identifier, keyComponents, &key);
    return KeyResult(result, key);
}

IdentifiersResult CryptoPluginWrapper::storedKeyIdentifiers(
        CryptoPlugin *plugin)
{
    QVector<Key::Identifier> identifiers;
    Result result = plugin->storedKeyIdentifiers(&identifiers);
    return IdentifiersResult(result, identifiers);
}

DataResult CryptoPluginWrapper::calculateDigest(
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

DataResult CryptoPluginWrapper::sign(
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

ValidatedResult CryptoPluginWrapper::verify(
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

TagDataResult CryptoPluginWrapper::encrypt(
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

VerifiedDataResult CryptoPluginWrapper::decrypt(
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

CipherSessionTokenResult CryptoPluginWrapper::initialiseCipherSession(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 clientId,
        const QByteArray &iv,
        const Key &key, // or keyreference, i.e. Key(keyName)
        const CipherSessionOptions &options)
{
    quint32 cipherSessionToken = 0;
    Result result = pluginAndCustomParams.plugin->initialiseCipherSession(
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

Result CryptoPluginWrapper::updateCipherSessionAuthentication(
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

DataResult CryptoPluginWrapper::updateCipherSession(
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

VerifiedDataResult CryptoPluginWrapper::finaliseCipherSession(
        const PluginAndCustomParams &pluginAndCustomParams,
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken)
{
    bool verified = false;
    QByteArray generatedData;
    Result result = pluginAndCustomParams.plugin->finaliseCipherSession(
                clientId, data,
                pluginAndCustomParams.customParameters,
                cipherSessionToken,
                &generatedData, &verified);
    return VerifiedDataResult(result, generatedData, verified);
}
