/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugintypes.h"

#include <QtQml/QQmlEngine>
#include <QtQml>

void Sailfish::Crypto::Plugin::CryptoPlugin::initializeEngine(QQmlEngine *, const char *)
{
}

void Sailfish::Crypto::Plugin::CryptoPlugin::registerTypes(const char *uri)
{
    qRegisterMetaType<Sailfish::Crypto::Result>("Result");
    QMetaType::registerComparators<Sailfish::Crypto::Result>();
    qmlRegisterUncreatableType<Sailfish::Crypto::Result>(uri, 1, 0, "Result", QLatin1String("Result objects cannot be constructed directly in QML"));

    qRegisterMetaType<Sailfish::Crypto::Key>("Key");
    QMetaType::registerComparators<Sailfish::Crypto::Key>();
    qmlRegisterUncreatableType<Sailfish::Crypto::Key>(uri, 1, 0, "Key", QLatin1String("Key objects cannot be constructed directly in QML"));

    qmlRegisterType<Sailfish::Crypto::PluginInfoRequest>(uri, 1, 0, "PluginInfoRequest");
    qmlRegisterType<Sailfish::Crypto::SeedRandomDataGeneratorRequest>(uri, 1, 0, "SeedRandomDataGeneratorRequest");
    qmlRegisterType<Sailfish::Crypto::GenerateRandomDataRequest>(uri, 1, 0, "GenerateRandomDataRequest");
    qmlRegisterType<Sailfish::Crypto::ValidateCertificateChainRequest>(uri, 1, 0, "ValidateCertificateChainRequest");
    qmlRegisterType<Sailfish::Crypto::GenerateKeyRequest>(uri, 1, 0, "GenerateKeyRequest");
    qmlRegisterType<Sailfish::Crypto::GenerateStoredKeyRequest>(uri, 1, 0, "GenerateStoredKeyRequest");
    qmlRegisterType<Sailfish::Crypto::StoredKeyRequest>(uri, 1, 0, "StoredKeyRequest");
    qmlRegisterType<Sailfish::Crypto::StoredKeyIdentifiersRequest>(uri, 1, 0, "StoredKeyIdentifiersRequest");
    qmlRegisterType<Sailfish::Crypto::DeleteStoredKeyRequest>(uri, 1, 0, "DeleteStoredKeyRequest");
    qmlRegisterType<Sailfish::Crypto::EncryptRequest>(uri, 1, 0, "EncryptRequest");
    qmlRegisterType<Sailfish::Crypto::DecryptRequest>(uri, 1, 0, "DecryptRequest");
    qmlRegisterType<Sailfish::Crypto::CalculateDigestRequest>(uri, 1, 0, "CalculateDigestRequest");
    qmlRegisterType<Sailfish::Crypto::SignRequest>(uri, 1, 0, "SignRequest");
    qmlRegisterType<Sailfish::Crypto::VerifyRequest>(uri, 1, 0, "VerifyRequest");
    qmlRegisterType<Sailfish::Crypto::CipherRequest>(uri, 1, 0, "CipherRequest");

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
