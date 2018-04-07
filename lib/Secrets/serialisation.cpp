/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/serialisation_p.h"
#include "Secrets/secretmanager.h"
#include "Secrets/secret.h"
#include "Secrets/result.h"
#include "Secrets/plugininfo.h"
#include "Secrets/interactionparameters.h"
#include "Secrets/interactionresponse.h"

#include <QtDBus/QDBusArgument>
#include <QtCore/QString>
#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishSecretsSerialisation, "org.sailfishos.secrets.serialisation", QtWarningMsg)

namespace Sailfish {

namespace Secrets {

QDBusArgument &operator<<(QDBusArgument &argument, const Result &result)
{
    argument.beginStructure();
    argument << static_cast<int>(result.code()) << result.errorCode() << result.errorMessage();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Result &result)
{
    int code;
    int errorCode;
    QString message;

    argument.beginStructure();
    argument >> code >> errorCode >> message;
    argument.endStructure();

    result.setCode(static_cast<Result::ResultCode>(code));
    result.setErrorCode(static_cast<Result::ErrorCode>(errorCode));
    result.setErrorMessage(message);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Secret::Identifier &identifier)
{
    argument.beginStructure();
    argument << identifier.name() << identifier.collectionName();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Secret::Identifier &identifier)
{
    QString name;
    QString collectionName;

    argument.beginStructure();
    argument >> name >> collectionName;
    argument.endStructure();

    identifier.setName(name);
    identifier.setCollectionName(collectionName);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Secret &secret)
{
    argument.beginStructure();
    argument << secret.identifier() << secret.data() << secret.filterData();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Secret &secret)
{
    Secret::Identifier identifier;
    QByteArray data;
    QMap<QString,QString> metadata;

    argument.beginStructure();
    argument >> identifier >> data >> metadata;
    argument.endStructure();

    secret.setIdentifier(identifier);
    secret.setData(data);
    secret.setFilterData(Secret::FilterData(metadata));
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const SecretManager::UserInteractionMode mode)
{
    int imode = static_cast<int>(mode);
    argument.beginStructure();
    argument << imode;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, SecretManager::UserInteractionMode &mode)
{
    int imode = 0;
    argument.beginStructure();
    argument >> imode;
    argument.endStructure();
    mode = static_cast<SecretManager::UserInteractionMode>(imode);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const SecretManager::AccessControlMode mode)
{
    int imode = static_cast<int>(mode);
    argument.beginStructure();
    argument << imode;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, SecretManager::AccessControlMode &mode)
{
    int imode = 0;
    argument.beginStructure();
    argument >> imode;
    argument.endStructure();
    mode = static_cast<SecretManager::AccessControlMode>(imode);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const SecretManager::DeviceLockUnlockSemantic semantic)
{
    int isemantic = static_cast<int>(semantic);
    argument.beginStructure();
    argument << isemantic;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, SecretManager::DeviceLockUnlockSemantic &semantic)
{
    int isemantic = 0;
    argument.beginStructure();
    argument >> isemantic;
    argument.endStructure();
    semantic = static_cast<SecretManager::DeviceLockUnlockSemantic>(isemantic);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const SecretManager::CustomLockUnlockSemantic semantic)
{
    int isemantic = static_cast<int>(semantic);
    argument.beginStructure();
    argument << isemantic;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, SecretManager::CustomLockUnlockSemantic &semantic)
{
    int isemantic = 0;
    argument.beginStructure();
    argument >> isemantic;
    argument.endStructure();
    semantic = static_cast<SecretManager::CustomLockUnlockSemantic>(isemantic);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const SecretManager::FilterOperator filterOperator)
{
    int iop = static_cast<int>(filterOperator);
    argument.beginStructure();
    argument << iop;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, SecretManager::FilterOperator &filterOperator)
{
    int iop = 0;
    argument.beginStructure();
    argument >> iop;
    argument.endStructure();
    filterOperator = static_cast<SecretManager::FilterOperator>(iop);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const PluginInfo &info)
{
    argument.beginStructure();
    argument << info.name() << info.name();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, PluginInfo &info)
{
    QString name;
    int version = 0;
    argument.beginStructure();
    argument >> name >> version;
    argument.endStructure();
    info.setName(name);
    info.setVersion(version);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::InteractionParameters::InputType &type)
{
    int itype = static_cast<int>(type);
    argument.beginStructure();
    argument << itype;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::InteractionParameters::InputType &type)
{
    int itype = 0;
    argument.beginStructure();
    argument >> itype;
    argument.endStructure();
    type = static_cast<InteractionParameters::InputType>(itype);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::InteractionParameters::EchoMode &mode)
{
    int imode = static_cast<int>(mode);
    argument.beginStructure();
    argument << imode;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::InteractionParameters::EchoMode &mode)
{
    int imode = 0;
    argument.beginStructure();
    argument >> imode;
    argument.endStructure();
    mode = static_cast<InteractionParameters::EchoMode>(imode);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::InteractionParameters::Operation &op)
{
    int iop = static_cast<int>(op);
    argument.beginStructure();
    argument << iop;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::InteractionParameters::Operation &op)
{
    int iop = 0;
    argument.beginStructure();
    argument >> iop;
    argument.endStructure();
    op = static_cast<InteractionParameters::Operation>(iop);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const InteractionParameters &request)
{
    argument.beginStructure();
    argument << request.secretName()
             << request.collectionName()
             << request.pluginName()
             << request.applicationId()
             << request.operation()
             << request.authenticationPluginName()
             << request.promptText()
             << request.inputType()
             << request.echoMode();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, InteractionParameters &request)
{
    QString secretName;
    QString collectionName;
    QString pluginName;
    QString applicationId;
    InteractionParameters::Operation operation = InteractionParameters::UnknownOperation;
    QString authenticationPluginName;
    QString promptText;
    InteractionParameters::InputType inputType = InteractionParameters::UnknownInput;
    InteractionParameters::EchoMode echoMode = InteractionParameters::PasswordEchoOnEdit;

    argument.beginStructure();
    argument >> secretName
             >> collectionName
             >> pluginName
             >> applicationId
             >> operation
             >> authenticationPluginName
             >> promptText
             >> inputType
             >> echoMode;
    argument.endStructure();

    request.setSecretName(secretName);
    request.setCollectionName(collectionName);
    request.setPluginName(pluginName);
    request.setApplicationId(applicationId);
    request.setOperation(operation);
    request.setAuthenticationPluginName(authenticationPluginName);
    request.setPromptText(promptText);
    request.setInputType(inputType);
    request.setEchoMode(echoMode);

    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const InteractionResponse &response)
{
    argument.beginStructure();
    argument << response.result();
    argument << response.responseData();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, InteractionResponse &response)
{
    Result result;
    QByteArray responseData;
    argument.beginStructure();
    argument >> result;
    argument >> responseData;
    argument.endStructure();
    response.setResult(result);
    response.setResponseData(responseData);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const LockCodeRequest::LockCodeTargetType &type)
{
    int itype = static_cast<int>(type);
    argument.beginStructure();
    argument << itype;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, LockCodeRequest::LockCodeTargetType &type)
{
    int itype = 0;
    argument.beginStructure();
    argument >> itype;
    argument.endStructure();
    type = static_cast<LockCodeRequest::LockCodeTargetType>(itype);
    return argument;
}

} // namespace Secrets

} // namespace Sailfish
