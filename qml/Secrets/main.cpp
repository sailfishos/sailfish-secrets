/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugintypes.h"
#include "applicationinteractionview.h"

#include <QtQml/QQmlEngine>
#include <QtQml>

void Sailfish::Secrets::Plugin::SecretsPlugin::initializeEngine(QQmlEngine *, const char *)
{
}

void Sailfish::Secrets::Plugin::SecretsPlugin::registerTypes(const char *uri)
{
    qRegisterMetaType<Sailfish::Secrets::InteractionParameters>("InteractionParameters");
    qRegisterMetaType<Sailfish::Secrets::InteractionParameters::InputType>("InteractionParameters::InputType");
    qRegisterMetaType<Sailfish::Secrets::InteractionParameters::EchoMode>("InteractionParameters::EchoMode");
    qRegisterMetaType<Sailfish::Secrets::InteractionParameters::Operation>("InteractionParameters::Operation");
    QMetaType::registerComparators<Sailfish::Secrets::InteractionParameters>();
    qmlRegisterUncreatableType<Sailfish::Secrets::InteractionParameters>(uri, 1, 0, "InteractionParameters", QStringLiteral("InteractionParameters objects cannot be constructed directly in QML"));

    qRegisterMetaType<Sailfish::Secrets::InteractionResponse>("InteractionResponse");
    QMetaType::registerComparators<Sailfish::Secrets::InteractionResponse>();
    qmlRegisterUncreatableType<Sailfish::Secrets::InteractionResponse>(uri, 1, 0, "InteractionResponse", QStringLiteral("InteractionResponse objects cannot be constructed directly in QML"));

    qRegisterMetaType<Sailfish::Secrets::Result>("SecretsResult");
    QMetaType::registerComparators<Sailfish::Secrets::Result>();
    qmlRegisterUncreatableType<Sailfish::Secrets::Result>(uri, 1, 0, "Result", QStringLiteral("Result objects cannot be constructed directly in QML"));

    qRegisterMetaType<Sailfish::Secrets::Secret>("Secret");
    QMetaType::registerComparators<Sailfish::Secrets::Secret>();
    qmlRegisterUncreatableType<Sailfish::Secrets::Secret>(uri, 1, 0, "Secret", QStringLiteral("Secret objects cannot be constructed directly in QML"));

    qmlRegisterUncreatableType<Sailfish::Secrets::Request>(uri, 1, 0, "SecretsRequest", QStringLiteral("Request is an abstract class, can't construct in QML"));
    qRegisterMetaType<Sailfish::Secrets::Request::Status>("SecretsRequestStatus");
    qmlRegisterType<Sailfish::Secrets::PluginInfoRequest>(uri, 1, 0, "PluginInfoRequest");
    qmlRegisterType<Sailfish::Secrets::CollectionNamesRequest>(uri, 1, 0, "CollectionNamesRequest");
    qmlRegisterType<Sailfish::Secrets::CreateCollectionRequest>(uri, 1, 0, "CreateCollectionRequest");
    qmlRegisterType<Sailfish::Secrets::DeleteCollectionRequest>(uri, 1, 0, "DeleteCollectionRequest");
    qmlRegisterType<Sailfish::Secrets::StoreSecretRequest>(uri, 1, 0, "StoreSecretRequest");
    qmlRegisterType<Sailfish::Secrets::StoredSecretRequest>(uri, 1, 0, "StoredSecretRequest");
    qmlRegisterType<Sailfish::Secrets::FindSecretsRequest>(uri, 1, 0, "FindSecretsRequest");
    qmlRegisterType<Sailfish::Secrets::DeleteSecretRequest>(uri, 1, 0, "DeleteSecretRequest");
    qmlRegisterType<Sailfish::Secrets::InteractionRequest>(uri, 1, 0, "InteractionRequest");

    qmlRegisterType<Sailfish::Secrets::Plugin::ApplicationInteractionView>(uri, 1, 0, "ApplicationInteractionView");
    qmlRegisterType<Sailfish::Secrets::Plugin::SecretManager>(uri, 1, 0, "SecretManager");
}

Sailfish::Secrets::Plugin::SecretManager::SecretManager(QObject *parent)
    : Sailfish::Secrets::SecretManager(parent)
{
}

Sailfish::Secrets::Plugin::SecretManager::~SecretManager()
{
}

QString Sailfish::Secrets::Plugin::SecretManager::inAppAuthenticationPluginName() const
{
    return InAppAuthenticationPluginName;
}

QString Sailfish::Secrets::Plugin::SecretManager::defaultAuthenticationPluginName() const
{
    return DefaultAuthenticationPluginName;
}

QString Sailfish::Secrets::Plugin::SecretManager::defaultStoragePluginName() const
{
    return DefaultStoragePluginName;
}

QString Sailfish::Secrets::Plugin::SecretManager::defaultEncryptionPluginName() const
{
    return DefaultEncryptionPluginName;
}

QString Sailfish::Secrets::Plugin::SecretManager::defaultEncryptedStoragePluginName() const
{
    return DefaultEncryptedStoragePluginName;
}

Sailfish::Secrets::Result Sailfish::Secrets::Plugin::SecretManager::constructResult() const
{
    return Sailfish::Secrets::Result();
}

Sailfish::Secrets::Secret Sailfish::Secrets::Plugin::SecretManager::constructSecret() const
{
    return Sailfish::Secrets::Secret();
}

Sailfish::Secrets::InteractionParameters Sailfish::Secrets::Plugin::SecretManager::constructInteractionParameters() const
{
    return Sailfish::Secrets::InteractionParameters();
}

Sailfish::Secrets::InteractionResponse Sailfish::Secrets::Plugin::SecretManager::constructInteractionResponse() const
{
    return Sailfish::Secrets::InteractionResponse();
}
