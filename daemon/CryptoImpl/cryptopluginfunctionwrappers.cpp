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

namespace {
    Sailfish::Secrets::Result unlockCollection(CryptoStoragePluginWrapper *w,
                                               const QString &collectionName,
                                               const QByteArray &collectionKey,
                                               bool *wasLocked) {
        Sailfish::Secrets::Result lockedResult;
        bool locked = false;
        lockedResult = w->isCollectionLocked(
                    collectionName,
                    &locked);
        if (lockedResult.code() == Sailfish::Secrets::Result::Succeeded) {
            *wasLocked = locked;
            if (locked) {
                lockedResult = w->setEncryptionKey(
                            collectionName,
                            collectionKey);
                if (lockedResult.code() == Sailfish::Secrets::Result::Succeeded) {
                    lockedResult = w->isCollectionLocked(
                                collectionName,
                                &locked);
                    if (lockedResult.code() == Sailfish::Secrets::Result::Succeeded) {
                        if (locked) {
                            // still locked, unable to unlock.  return an error.
                            lockedResult = Sailfish::Secrets::Result(Sailfish::Secrets::Result::IncorrectAuthenticationCodeError,
                                          QString::fromLatin1("The authentication code entered for collection %1 was incorrect")
                                                         .arg(collectionName));
                        }
                    }
                }
            }
        }
        return lockedResult;
    }
}

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
    Sailfish::Secrets::Result sresult = pluginAndCustomParams.wrapper->collectionMetadata(
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
    Result result = pluginAndCustomParams.wrapper->importAndStoreKey(
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
        Key::Components keyComponents,
        const QVariantMap &customParameters)
{
    Key key;
    key.setIdentifier(identifier);
    Result result = plugin->storedKey(
                identifier, keyComponents, customParameters, &key);
    return KeyResult(result, key);
}

IdentifiersResult CryptoPluginFunctionWrapper::storedKeyIdentifiers(
        CryptoPlugin *plugin,
        const QString &collectionName,
        const QVariantMap &customParameters)
{
    QVector<Key::Identifier> identifiers;
    Result result = plugin->storedKeyIdentifiers(collectionName, customParameters, &identifiers);
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
        const PluginWrapperAndCustomParams &pluginAndCustomParams,
        const QByteArray &data,
        const KeyAndCollectionKey &keyAndCollectionKey,
        const SignatureOptions &options)
{
    QByteArray signature;
    Result result(Result::Succeeded);

    if (CryptoStoragePluginWrapper *w = pluginAndCustomParams.wrapper) {
        const QString collectionName = keyAndCollectionKey.key.identifier().collectionName();
        const QByteArray collectionKey = keyAndCollectionKey.collectionKey;
        bool wasLocked = false;

        // check to see if we need to unlock the collection in order to access the key.
        // we don't need to do this if the given key has the appropriate components already.
        if (keyAndCollectionKey.key.privateKey().isEmpty()
                && keyAndCollectionKey.key.secretKey().isEmpty()) {
            Sailfish::Secrets::Result lockedResult = unlockCollection(
                        w, collectionName, collectionKey, &wasLocked);
            if (lockedResult.code() == Sailfish::Secrets::Result::Failed) {
                result = transformSecretsResult(lockedResult);
            }
        }

        if (result.code() == Result::Succeeded) {
            result = w->cryptoPlugin()->sign(
                        data, keyAndCollectionKey.key,
                        options.signaturePadding,
                        options.digestFunction,
                        pluginAndCustomParams.customParameters,
                        &signature);
        }

        if (wasLocked) {
            // relock.
            Sailfish::Secrets::Result r = w->setEncryptionKey(
                        collectionName,
                        QByteArray());
            Q_UNUSED(r);
        }
    } else if (pluginAndCustomParams.plugin) {
        result = pluginAndCustomParams.plugin->sign(
                    data, keyAndCollectionKey.key,
                    options.signaturePadding,
                    options.digestFunction,
                    pluginAndCustomParams.customParameters,
                    &signature);
    } else {
        result = Result(Result::InvalidCryptographicServiceProvider,
                        QLatin1String("Internal error: wrapper and plugin null"));
    }

    return DataResult(result, signature);
}

ValidatedResult CryptoPluginFunctionWrapper::verify(
        const PluginWrapperAndCustomParams &pluginAndCustomParams,
        const QByteArray &signature,
        const QByteArray &data,
        const KeyAndCollectionKey &keyAndCollectionKey,
        const SignatureOptions &options)
{
    Sailfish::Crypto::CryptoManager::VerificationStatus verificationStatus = Sailfish::Crypto::CryptoManager::VerificationStatusUnknown;
    Result result(Result::Succeeded);

    if (CryptoStoragePluginWrapper *w = pluginAndCustomParams.wrapper) {
        const QString collectionName = keyAndCollectionKey.key.identifier().collectionName();
        const QByteArray collectionKey = keyAndCollectionKey.collectionKey;
        bool wasLocked = false;

        // check to see if we need to unlock the collection in order to access the key.
        // we don't need to do this if the given key has the appropriate components already.
        if (keyAndCollectionKey.key.publicKey().isEmpty()
                && keyAndCollectionKey.key.privateKey().isEmpty()
                && keyAndCollectionKey.key.secretKey().isEmpty()) {
            Sailfish::Secrets::Result lockedResult = unlockCollection(
                        w, collectionName, collectionKey, &wasLocked);

            if (lockedResult.code() == Sailfish::Secrets::Result::Failed) {
                result = transformSecretsResult(lockedResult);
            }
        }

        if (result.code() == Result::Succeeded) {
            result = w->cryptoPlugin()->verify(
                        signature, data, keyAndCollectionKey.key,
                        options.signaturePadding,
                        options.digestFunction,
                        pluginAndCustomParams.customParameters,
                        &verificationStatus);
        }

        if (wasLocked) {
            // relock.
            Sailfish::Secrets::Result r = w->setEncryptionKey(
                        collectionName,
                        QByteArray());
            Q_UNUSED(r);
        }
    } else if (pluginAndCustomParams.plugin) {
        result = pluginAndCustomParams.plugin->verify(
                signature, data, keyAndCollectionKey.key,
                options.signaturePadding,
                options.digestFunction,
                pluginAndCustomParams.customParameters,
                &verificationStatus);
    } else {
        result = Result(Result::InvalidCryptographicServiceProvider,
                        QLatin1String("Internal error: wrapper and plugin null"));
    }

    return ValidatedResult(result, verificationStatus);
}

TagDataResult CryptoPluginFunctionWrapper::encrypt(
        const PluginWrapperAndCustomParams &pluginAndCustomParams,
        const DataAndIV &dataAndIv,
        const KeyAndCollectionKey &keyAndCollectionKey,
        const EncryptionOptions &options,
        const QByteArray &authenticationData)
{
    QByteArray ciphertext;
    QByteArray authenticationTag;
    Result result(Result::Succeeded);

    if (CryptoStoragePluginWrapper *w = pluginAndCustomParams.wrapper) {
        const QString collectionName = keyAndCollectionKey.key.identifier().collectionName();
        const QByteArray collectionKey = keyAndCollectionKey.collectionKey;
        bool wasLocked = false;

        // check to see if we need to unlock the collection in order to access the key.
        // we don't need to do this if the given key has the appropriate components already.
        if (keyAndCollectionKey.key.publicKey().isEmpty()
                && keyAndCollectionKey.key.privateKey().isEmpty()
                && keyAndCollectionKey.key.secretKey().isEmpty()) {
            Sailfish::Secrets::Result lockedResult = unlockCollection(
                        w, collectionName, collectionKey, &wasLocked);

            if (lockedResult.code() == Sailfish::Secrets::Result::Failed) {
                result = transformSecretsResult(lockedResult);
            }
        }

        if (result.code() == Result::Succeeded) {
            result = w->cryptoPlugin()->encrypt(
                        dataAndIv.data,
                        dataAndIv.initVector,
                        keyAndCollectionKey.key,
                        options.blockMode,
                        options.encryptionPadding,
                        authenticationData,
                        pluginAndCustomParams.customParameters,
                        &ciphertext, &authenticationTag);
        }

        if (wasLocked) {
            // relock.
            Sailfish::Secrets::Result r = w->setEncryptionKey(
                        collectionName,
                        QByteArray());
            Q_UNUSED(r);
        }
    } else if (pluginAndCustomParams.plugin) {
        result = pluginAndCustomParams.plugin->encrypt(
                    dataAndIv.data,
                    dataAndIv.initVector,
                    keyAndCollectionKey.key,
                    options.blockMode,
                    options.encryptionPadding,
                    authenticationData,
                    pluginAndCustomParams.customParameters,
                    &ciphertext, &authenticationTag);
    } else {
        result = Result(Result::InvalidCryptographicServiceProvider,
                        QLatin1String("Internal error: wrapper and plugin null"));
    }

    return TagDataResult(result, ciphertext, authenticationTag);
}

VerifiedDataResult CryptoPluginFunctionWrapper::decrypt(
        const PluginWrapperAndCustomParams &pluginAndCustomParams,
        const DataAndIV &dataAndIv,
        const KeyAndCollectionKey &keyAndCollectionKey,
        const EncryptionOptions &options,
        const AuthDataAndTag &authDataAndTag)
{
    QByteArray plaintext;
    Sailfish::Crypto::CryptoManager::VerificationStatus verificationStatus = Sailfish::Crypto::CryptoManager::VerificationStatusUnknown;
    Result result(Result::Succeeded);

    if (CryptoStoragePluginWrapper *w = pluginAndCustomParams.wrapper) {
        const QString collectionName = keyAndCollectionKey.key.identifier().collectionName();
        const QByteArray collectionKey = keyAndCollectionKey.collectionKey;
        bool wasLocked = false;

        // check to see if we need to unlock the collection in order to access the key.
        // we don't need to do this if the given key has the appropriate components already.
        if (keyAndCollectionKey.key.privateKey().isEmpty()
                && keyAndCollectionKey.key.secretKey().isEmpty()) {
            Sailfish::Secrets::Result lockedResult = unlockCollection(
                        w, collectionName, collectionKey, &wasLocked);
            if (lockedResult.code() == Sailfish::Secrets::Result::Failed) {
                result = transformSecretsResult(lockedResult);
            }
        }

        if (result.code() == Result::Succeeded) {
            result = w->cryptoPlugin()->decrypt(
                        dataAndIv.data,
                        dataAndIv.initVector,
                        keyAndCollectionKey.key,
                        options.blockMode,
                        options.encryptionPadding,
                        authDataAndTag.authData,
                        authDataAndTag.tag,
                        pluginAndCustomParams.customParameters,
                        &plaintext, &verificationStatus);
        }

        if (wasLocked) {
            // relock.
            Sailfish::Secrets::Result r = w->setEncryptionKey(
                        collectionName,
                        QByteArray());
            Q_UNUSED(r);
        }
    } else if (pluginAndCustomParams.plugin) {
        result = pluginAndCustomParams.plugin->decrypt(
                    dataAndIv.data,
                    dataAndIv.initVector,
                    keyAndCollectionKey.key,
                    options.blockMode,
                    options.encryptionPadding,
                    authDataAndTag.authData,
                    authDataAndTag.tag,
                    pluginAndCustomParams.customParameters,
                    &plaintext, &verificationStatus);
    } else {
        result = Result(Result::InvalidCryptographicServiceProvider,
                        QLatin1String("Internal error: wrapper and plugin null"));
    }

    return VerifiedDataResult(result, plaintext, verificationStatus);
}

CipherSessionTokenResult CryptoPluginFunctionWrapper::initializeCipherSession(
        const PluginWrapperAndCustomParams &pluginAndCustomParams,
        quint64 clientId,
        const QByteArray &iv,
        const KeyAndCollectionKey &keyAndCollectionKey,
        const CipherSessionOptions &options)
{
    quint32 cipherSessionToken = 0;
    Result result(Result::Succeeded);

    if (CryptoStoragePluginWrapper *w = pluginAndCustomParams.wrapper) {
        const QString collectionName = keyAndCollectionKey.key.identifier().collectionName();
        const QByteArray collectionKey = keyAndCollectionKey.collectionKey;
        bool wasLocked = false;

        // check to see if we need to unlock the collection in order to access the key.
        // we don't need to do this if the given key has the appropriate components already.
        if (((options.operation == CryptoManager::OperationSign
             || options.operation == CryptoManager::OperationDecrypt)
                    && keyAndCollectionKey.key.privateKey().isEmpty()
                    && keyAndCollectionKey.key.secretKey().isEmpty())
         || ((options.operation == CryptoManager::OperationVerify
             || options.operation == CryptoManager::OperationEncrypt)
                    && keyAndCollectionKey.key.publicKey().isEmpty()
                    && keyAndCollectionKey.key.privateKey().isEmpty()
                    && keyAndCollectionKey.key.secretKey().isEmpty())) {
            Sailfish::Secrets::Result lockedResult = unlockCollection(
                        w, collectionName, collectionKey, &wasLocked);
            if (lockedResult.code() == Sailfish::Secrets::Result::Failed) {
                result = transformSecretsResult(lockedResult);
            }
        }

        if (result.code() == Result::Succeeded) {
            result = w->cryptoPlugin()->initializeCipherSession(
                        clientId,
                        iv,
                        keyAndCollectionKey.key,
                        options.operation,
                        options.blockMode,
                        options.encryptionPadding,
                        options.signaturePadding,
                        options.digestFunction,
                        pluginAndCustomParams.customParameters,
                        &cipherSessionToken);
        }

        if (wasLocked) {
            // relock.
            Sailfish::Secrets::Result r = w->setEncryptionKey(
                        collectionName,
                        QByteArray());
            Q_UNUSED(r);
        }
    } else if (pluginAndCustomParams.plugin) {
        result = pluginAndCustomParams.plugin->initializeCipherSession(
                    clientId,
                    iv,
                    keyAndCollectionKey.key,
                    options.operation,
                    options.blockMode,
                    options.encryptionPadding,
                    options.signaturePadding,
                    options.digestFunction,
                    pluginAndCustomParams.customParameters,
                    &cipherSessionToken);
    } else {
        result = Result(Result::InvalidCryptographicServiceProvider,
                        QLatin1String("Internal error: wrapper and plugin null"));
    }

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
    Sailfish::Crypto::CryptoManager::VerificationStatus verificationStatus = Sailfish::Crypto::CryptoManager::VerificationStatusUnknown;
    QByteArray generatedData;
    Result result = pluginAndCustomParams.plugin->finalizeCipherSession(
                clientId, data,
                pluginAndCustomParams.customParameters,
                cipherSessionToken,
                &generatedData, &verificationStatus);
    return VerifiedDataResult(result, generatedData, verificationStatus);
}

KeyResult CryptoPluginFunctionWrapper::generateAndStoreKey(
        const PluginWrapperAndCustomParams &pluginAndCustomParams,
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        const QByteArray &collectionUnlockCode)
{
    Sailfish::Secrets::Daemon::ApiImpl::CollectionMetadata collectionMetadata;
    Sailfish::Secrets::Result sresult = pluginAndCustomParams.wrapper->collectionMetadata(
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
    Result result = pluginAndCustomParams.wrapper->generateAndStoreKey(
                metadata,
                keyTemplate,
                kpgParams,
                skdfParams,
                pluginAndCustomParams.customParameters,
                collectionUnlockCode,
                &keyReference);
    return KeyResult(result, keyReference);
}
