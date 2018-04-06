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
        CryptoPlugin *plugin,
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes)
{
    QByteArray randomData;
    Result result = plugin->generateRandomData(
                callerIdent,
                csprngEngineName,
                numberBytes,
                &randomData);
    return DataResult(result, randomData);
}

Result CryptoPluginWrapper::seedRandomDataGenerator(
        CryptoPlugin *plugin,
        quint64 callerIdent,
        const QString &csprngEngineName,
        const QByteArray &seedData,
        double entropyEstimate)
{
    return plugin->seedRandomDataGenerator(
                callerIdent,
                csprngEngineName,
                seedData,
                entropyEstimate);
}

DataResult CryptoPluginWrapper::generateInitializationVector(
        CryptoPlugin *plugin,
        CryptoManager::Algorithm algorithm,
        CryptoManager::BlockMode blockMode,
        int keySize)
{
    QByteArray iv;
    Result result = plugin->generateInitializationVector(
                algorithm, blockMode, keySize, &iv);
    return DataResult(result, iv);
}

ValidatedResult CryptoPluginWrapper::validateCertificateChain(
        CryptoPlugin *plugin,
        const QVector<Certificate> &chain)
{
    bool validated = false;
    Result result = plugin->validateCertificateChain(chain, &validated);
    return ValidatedResult(result, validated);
}

KeyResult CryptoPluginWrapper::importKey(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const Sailfish::Crypto::Key &keyData,
        const QByteArray &passphrase)
{
    Key key;
    Result result = plugin->importKey(
                keyData, passphrase, &key);
    return KeyResult(result, key);
}

KeyResult CryptoPluginWrapper::importAndStoreKey(
        Sailfish::Crypto::CryptoPlugin *plugin,
        const Sailfish::Crypto::Key &keyData,
        const QByteArray &passphrase)
{
    Key key;
    Result result = plugin->importAndStoreKey(
                keyData, passphrase, &key);
    return KeyResult(result, key);
}

KeyResult CryptoPluginWrapper::generateKey(
        CryptoPlugin *plugin,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams)
{
    Key key;
    Result result = plugin->generateKey(
                keyTemplate, kpgParams, skdfParams, &key);
    return KeyResult(result, key);
}

KeyResult CryptoPluginWrapper::generateAndStoreKey(
        CryptoPlugin *plugin,
        const Key &keyTemplate,
        const KeyPairGenerationParameters &kpgParams,
        const KeyDerivationParameters &skdfParams)
{
    Key keyReference;
    Result result = plugin->generateAndStoreKey(
                keyTemplate, kpgParams, skdfParams, &keyReference);
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
        CryptoPlugin *plugin,
        const QByteArray &data,
        const SignatureOptions &options)
{
    QByteArray digest;
    Result result = plugin->calculateDigest(
                data,
                options.signaturePadding,
                options.digestFunction,
                &digest);
    return DataResult(result, digest);
}

DataResult CryptoPluginWrapper::sign(
        CryptoPlugin *plugin,
        const QByteArray &data,
        const Key &key,
        const SignatureOptions &options)
{
    QByteArray signature;
    Result result = plugin->sign(
                data, key,
                options.signaturePadding,
                options.digestFunction,
                &signature);
    return DataResult(result, signature);
}

ValidatedResult CryptoPluginWrapper::verify(
        CryptoPlugin *plugin,
        const QByteArray &signature,
        const QByteArray &data,
        const Key &key,
        const SignatureOptions &options)
{
    bool verified = false;
    Result result = plugin->verify(
                signature, data, key,
                options.signaturePadding,
                options.digestFunction,
                &verified);
    return ValidatedResult(result, verified);
}

TagDataResult CryptoPluginWrapper::encrypt(
        CryptoPlugin *plugin,
        const DataAndIV &dataAndIv,
        const Sailfish::Crypto::Key &key,
        const EncryptionOptions &options,
        const QByteArray &authenticationData)
{
    QByteArray ciphertext;
    QByteArray authenticationTag;
    Result result = plugin->encrypt(
                dataAndIv.data,
                dataAndIv.initVector,
                key,
                options.blockMode,
                options.encryptionPadding,
                authenticationData,
                &ciphertext, &authenticationTag);
    return TagDataResult(result, ciphertext, authenticationTag);
}

VerifiedDataResult CryptoPluginWrapper::decrypt(
        CryptoPlugin *plugin,
        const DataAndIV &dataAndIv,
        const Key &key, // or keyreference, i.e. Key(keyName)
        const EncryptionOptions &options,
        const AuthDataAndTag &authDataAndTag)
{
    QByteArray plaintext;
    bool verified = false;
    Result result = plugin->decrypt(
                dataAndIv.data,
                dataAndIv.initVector,
                key,
                options.blockMode,
                options.encryptionPadding,
                authDataAndTag.authData,
                authDataAndTag.tag,
                &plaintext, &verified);
    return VerifiedDataResult(result, plaintext, verified);
}

CipherSessionTokenResult CryptoPluginWrapper::initialiseCipherSession(
        CryptoPlugin *plugin,
        quint64 clientId,
        const QByteArray &iv,
        const Key &key, // or keyreference, i.e. Key(keyName)
        const CipherSessionOptions &options)
{
    quint32 cipherSessionToken = 0;
    Result result = plugin->initialiseCipherSession(
                clientId,
                iv,
                key,
                options.operation,
                options.blockMode,
                options.encryptionPadding,
                options.signaturePadding,
                options.digestFunction,
                &cipherSessionToken);
    return CipherSessionTokenResult(result, cipherSessionToken);
}

Result CryptoPluginWrapper::updateCipherSessionAuthentication(
        CryptoPlugin *plugin,
        quint64 clientId,
        const QByteArray &authenticationData,
        quint32 cipherSessionToken)
{
    return plugin->updateCipherSessionAuthentication(
                clientId, authenticationData, cipherSessionToken);
}

DataResult CryptoPluginWrapper::updateCipherSession(
        CryptoPlugin *plugin,
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken)
{
    QByteArray generatedData;
    Result result = plugin->updateCipherSession(
                clientId, data, cipherSessionToken, &generatedData);
    return DataResult(result, generatedData);
}

VerifiedDataResult CryptoPluginWrapper::finaliseCipherSession(
        CryptoPlugin *plugin,
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken)
{
    bool verified = false;
    QByteArray generatedData;
    Result result = plugin->finaliseCipherSession(
                clientId, data, cipherSessionToken, &generatedData, &verified);
    return VerifiedDataResult(result, generatedData, verified);
}
