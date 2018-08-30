/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugintypes.h"
#include "storedkeyidentifiersrequestwrapper.h"

#include <QtQml/QQmlEngine>
#include <QtQml>

void Sailfish::Crypto::Plugin::CryptoPlugin::initializeEngine(QQmlEngine *, const char *)
{
}

void Sailfish::Crypto::Plugin::CryptoPlugin::registerTypes(const char *uri)
{
    qRegisterMetaType<Sailfish::Crypto::Result>("Result");
    QMetaType::registerComparators<Sailfish::Crypto::Result>();
    qmlRegisterUncreatableType<Sailfish::Crypto::Result>(uri, 1, 0, "CryptoResult", QStringLiteral("Result objects cannot be constructed directly in QML"));

    qRegisterMetaType<Sailfish::Crypto::Key>("Key");
    QMetaType::registerComparators<Sailfish::Crypto::Key>();
    qmlRegisterUncreatableType<Sailfish::Crypto::Key>(uri, 1, 0, "Key", QStringLiteral("Key objects cannot be constructed directly in QML"));

    qmlRegisterUncreatableType<Sailfish::Crypto::Request>(uri, 1, 0, "CryptoRequest", QStringLiteral("Request is an abstract class, can't construct in QML"));
    qRegisterMetaType<Sailfish::Crypto::Request::Status>("CryptoRequestStatus");
    qmlRegisterUncreatableType<Sailfish::Crypto::PluginInfo>(uri, 1, 0, "PluginInfo", QStringLiteral("PluginInfo objects cannot be constructed directly in QML"));
    qmlRegisterType<Sailfish::Crypto::PluginInfoRequest>(uri, 1, 0, "PluginInfoRequest");
    qmlRegisterType<Sailfish::Crypto::SeedRandomDataGeneratorRequest>(uri, 1, 0, "SeedRandomDataGeneratorRequest");
    qmlRegisterType<Sailfish::Crypto::GenerateRandomDataRequest>(uri, 1, 0, "GenerateRandomDataRequest");
    qmlRegisterType<Sailfish::Crypto::GenerateKeyRequest>(uri, 1, 0, "GenerateKeyRequest");
    qmlRegisterType<Sailfish::Crypto::GenerateStoredKeyRequest>(uri, 1, 0, "GenerateStoredKeyRequest");
    qmlRegisterType<Sailfish::Crypto::ImportKeyRequest>(uri, 1, 0, "ImportKeyRequest");
    qmlRegisterType<Sailfish::Crypto::ImportStoredKeyRequest>(uri, 1, 0, "ImportStoredKeyRequest");
    qmlRegisterType<Sailfish::Crypto::StoredKeyRequest>(uri, 1, 0, "StoredKeyRequest");
    qmlRegisterType<Sailfish::Crypto::Plugin::StoredKeyIdentifiersRequestWrapper>(uri, 1, 0, "StoredKeyIdentifiersRequest");
    qmlRegisterType<Sailfish::Crypto::DeleteStoredKeyRequest>(uri, 1, 0, "DeleteStoredKeyRequest");
    qmlRegisterType<Sailfish::Crypto::EncryptRequest>(uri, 1, 0, "EncryptRequest");
    qmlRegisterType<Sailfish::Crypto::DecryptRequest>(uri, 1, 0, "DecryptRequest");
    qmlRegisterType<Sailfish::Crypto::CalculateDigestRequest>(uri, 1, 0, "CalculateDigestRequest");
    qmlRegisterType<Sailfish::Crypto::SignRequest>(uri, 1, 0, "SignRequest");
    qmlRegisterType<Sailfish::Crypto::VerifyRequest>(uri, 1, 0, "VerifyRequest");
    qmlRegisterType<Sailfish::Crypto::CipherRequest>(uri, 1, 0, "CipherRequest");

    qmlRegisterUncreatableType<Sailfish::Crypto::KeyPairGenerationParameters>(uri, 1, 0, "KeyPairGenerationParameters", QStringLiteral("Use CryptoManager.constructRsaKeygenParams, can't construct Q_GADGET type KeyPairGenerationParameters in QML"));
    qmlRegisterUncreatableType<Sailfish::Crypto::EcKeyPairGenerationParameters>(uri, 1, 0, "EcKeyPairGenerationParameters", QStringLiteral("Use CryptoManager.constructRsaKeygenParams, can't construct Q_GADGET type EcKeyPairGenerationParameters in QML"));
    qmlRegisterUncreatableType<Sailfish::Crypto::RsaKeyPairGenerationParameters>(uri, 1, 0, "RsaKeyPairGenerationParameters", QStringLiteral("Use CryptoManager.constructRsaKeygenParams, can't construct Q_GADGET type RsaKeyPairGenerationParameters in QML"));
    qmlRegisterUncreatableType<Sailfish::Crypto::DsaKeyPairGenerationParameters>(uri, 1, 0, "DsaKeyPairGenerationParameters", QStringLiteral("Use CryptoManager.constructRsaKeygenParams, can't construct Q_GADGET type DsaKeyPairGenerationParameters in QML"));
    qmlRegisterUncreatableType<Sailfish::Crypto::DhKeyPairGenerationParameters>(uri, 1, 0, "DhKeyPairGenerationParameters", QStringLiteral("Use CryptoManager.constructRsaKeygenParams, can't construct Q_GADGET type DhKeyPairGenerationParameters in QML"));

    qmlRegisterUncreatableType<Sailfish::Crypto::InteractionParameters>(uri, 1, 0, "InteractionParameters", QStringLiteral("Can't construct InteractionParameters in QML"));
    qmlRegisterUncreatableType<Sailfish::Crypto::InteractionParameters::PromptText>(uri, 1, 0, "PromptText", QStringLiteral("Can't construct PromptText in QML"));

    qmlRegisterType<Sailfish::Crypto::Plugin::CryptoManager>(uri, 1, 0, "CryptoManager");
}

Sailfish::Crypto::Plugin::CryptoManager::CryptoManager(QObject *parent)
    : Sailfish::Crypto::CryptoManager(parent)
{
}

Sailfish::Crypto::Plugin::CryptoManager::~CryptoManager()
{
}

Sailfish::Crypto::Result Sailfish::Crypto::Plugin::CryptoManager::constructResult() const
{
    return Sailfish::Crypto::Result();
}

Sailfish::Crypto::Key Sailfish::Crypto::Plugin::CryptoManager::constructKey() const
{
    return Sailfish::Crypto::Key();
}

Sailfish::Crypto::Key Sailfish::Crypto::Plugin::CryptoManager::constructKey(const QString &name, const QString &collectionName, const QString &storagePluginName) const
{
    return Sailfish::Crypto::Key(name, collectionName, storagePluginName);
}

Sailfish::Crypto::Key::Identifier Sailfish::Crypto::Plugin::CryptoManager::constructIdentifier(const QString &name, const QString &collectionName, const QString &storagePluginName) const
{
    return Sailfish::Crypto::Key::Identifier(name, collectionName, storagePluginName);
}

QVariant Sailfish::Crypto::Plugin::CryptoManager::constructRsaKeygenParams() const
{
    return QVariant::fromValue<KeyPairGenerationParameters>(RsaKeyPairGenerationParameters());
}

QVariant Sailfish::Crypto::Plugin::CryptoManager::constructRsaKeygenParams(const QVariantMap &args) const
{
    QVariantMap customParams;
    RsaKeyPairGenerationParameters params;
    for (QVariantMap::ConstIterator it = args.constBegin(); it != args.constEnd(); it++) {
        if (it.key().compare("modulusLength") == 0) {
            params.setModulusLength(it->toInt());
        } else if (it.key().compare("numberPrimes") == 0) {
            params.setNumberPrimes(it->toInt());
        } else if (it.key().compare("publicExponent") == 0) {
            params.setPublicExponent(it->value<quint64>());
        } else {
            customParams.insert(it.key(), it.value());
        }
    }
    params.setCustomParameters(customParams);
    return QVariant::fromValue<KeyPairGenerationParameters>(params);
}

QVariant Sailfish::Crypto::Plugin::CryptoManager::constructEcKeygenParams() const
{
    return QVariant::fromValue<KeyPairGenerationParameters>(EcKeyPairGenerationParameters());
}

QVariant Sailfish::Crypto::Plugin::CryptoManager::constructEcKeygenParams(const QVariantMap &args) const
{
    EcKeyPairGenerationParameters params;
    params.setCustomParameters(args);
    return QVariant::fromValue<KeyPairGenerationParameters>(params);
}

QVariant Sailfish::Crypto::Plugin::CryptoManager::constructDsaKeygenParams() const
{
    return QVariant::fromValue<KeyPairGenerationParameters>(DsaKeyPairGenerationParameters());
}

QVariant Sailfish::Crypto::Plugin::CryptoManager::constructDsaKeygenParams(const QVariantMap &args) const
{
    QVariantMap customParams;
    DsaKeyPairGenerationParameters params;
    for (QVariantMap::ConstIterator it = args.constBegin(); it != args.constEnd(); it++) {
        if (it.key().compare("modulusLength") == 0) {
            params.setModulusLength(it->toInt());
        } else if (it.key().compare("primeFactorLength") == 0) {
            params.setPrimeFactorLength(it->toInt());
        } else if (it.key().compare("base") == 0) {
            params.setBase(it->toByteArray());
        } else if (it.key().compare("modulus") == 0) {
            params.setModulus(it->toByteArray());
        } else if (it.key().compare("generateFamilyParameters") == 0) {
            params.setGenerateFamilyParameters(it->toBool());
        } else if (it.key().compare("primeFactor") == 0) {
            params.setPrimeFactor(it->toByteArray());
        } else {
            customParams.insert(it.key(), it.value());
        }
    }
    params.setCustomParameters(customParams);
    return QVariant::fromValue<KeyPairGenerationParameters>(params);
}

QVariant Sailfish::Crypto::Plugin::CryptoManager::constructDhKeygenParams() const
{
    return QVariant::fromValue<KeyPairGenerationParameters>(DhKeyPairGenerationParameters());
}

QVariant Sailfish::Crypto::Plugin::CryptoManager::constructDhKeygenParams(const QVariantMap &args) const
{
    QVariantMap customParams;
    DhKeyPairGenerationParameters params;
    for (QVariantMap::ConstIterator it = args.constBegin(); it != args.constEnd(); it++) {
        if (it.key().compare("modulusLength") == 0) {
            params.setModulusLength(it->toInt());
        } else if (it.key().compare("privateExponentLength") == 0) {
            params.setPrivateExponentLength(it->toInt());
        } else if (it.key().compare("base") == 0) {
            params.setBase(it->toByteArray());
        } else if (it.key().compare("modulus") == 0) {
            params.setModulus(it->toByteArray());
        } else if (it.key().compare("generateFamilyParameters") == 0) {
            params.setGenerateFamilyParameters(it->toBool());
        } else {
            customParams.insert(it.key(), it.value());
        }
    }
    params.setCustomParameters(customParams);
    return QVariant::fromValue<KeyPairGenerationParameters>(params);
}
