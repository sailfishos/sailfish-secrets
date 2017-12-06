/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/secretmanager.h"
#include "Secrets/secret.h"
#include "Secrets/result.h"
#include "Secrets/interactionrequest.h"

#include <QtDBus/QDBusArgument>
#include <QtCore/QString>
#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishSecretsSerialisation, "org.sailfishos.secrets.serialisation", QtWarningMsg)

namespace Sailfish {

namespace Secrets {

QDBusArgument &operator<<(QDBusArgument &argument, const InteractionResponse &response)
{
    argument.beginStructure();
    argument << response.type();
    argument << response.values();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, InteractionResponse &response)
{
    int type = 0;
    QVariantMap values;
    argument.beginStructure();
    argument >> type;
    argument >> values;
    argument.endStructure();
    response = InteractionResponse(static_cast<InteractionRequest::Type>(type), values);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const InteractionRequest &request)
{
    argument.beginStructure();
    argument << static_cast<int>(request.type());
    argument << request.isResponse();
    argument << request.values();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, InteractionRequest &request)
{
    int type = 0;
    bool isResponse = false;
    QVariantMap values;
    argument.beginStructure();
    argument >> type;
    argument >> isResponse;
    argument >> values;
    argument.endStructure();
    if (isResponse) {
        request = InteractionResponse(static_cast<InteractionRequest::Type>(type), values);
    } else {
        request = InteractionRequest(static_cast<InteractionRequest::Type>(type), values);
    }
    return argument;
}

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
    QVariantMap asv;
    const QMap<QString,QString> fd = secret.filterData();
    for (QMap<QString,QString>::const_iterator it = fd.constBegin(); it != fd.constEnd(); it++) {
        asv.insert(it.key(), it.value());
    }

    argument.beginStructure();
    argument << secret.identifier() << secret.data() << asv;
    argument.endStructure();

    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Secret &secret)
{
    Secret::Identifier identifier;
    QByteArray data;
    QVariantMap asv;

    argument.beginStructure();
    argument >> identifier >> data >> asv;
    argument.endStructure();

    QMap<QString, QString> filterData;
    for (QVariantMap::const_iterator it = asv.constBegin(); it != asv.constEnd(); it++) {
        filterData.insert(it.key(), it.value().toString());
    }

    secret.setIdentifier(identifier);
    secret.setData(data);
    secret.setFilterData(filterData);

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

QDBusArgument &operator<<(QDBusArgument &argument, const StoragePluginInfo &info)
{
    int type = static_cast<int>(info.storageType());
    argument.beginStructure();
    argument << info.name() << type;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, StoragePluginInfo &info)
{
    QString name;
    int itype = 0;
    argument.beginStructure();
    argument >> name >> itype;
    argument.endStructure();
    info.setName(name);
    info.setStorageType(static_cast<StoragePlugin::StorageType>(itype));
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const EncryptionPluginInfo &info)
{
    int type = static_cast<int>(info.encryptionType());
    int algo = static_cast<int>(info.encryptionAlgorithm());
    argument.beginStructure();
    argument << info.name() << type << algo;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, EncryptionPluginInfo &info)
{
    QString name;
    int itype = 0;
    int ialgo = 0;
    argument.beginStructure();
    argument >> name >> itype >> ialgo;
    argument.endStructure();
    info.setName(name);
    info.setEncryptionType(static_cast<EncryptionPlugin::EncryptionType>(itype));
    info.setEncryptionAlgorithm(static_cast<EncryptionPlugin::EncryptionAlgorithm>(ialgo));
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const EncryptedStoragePluginInfo &info)
{
    int stype = static_cast<int>(info.storageType());
    int type = static_cast<int>(info.encryptionType());
    int algo = static_cast<int>(info.encryptionAlgorithm());
    argument.beginStructure();
    argument << info.name() << stype << type << algo;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, EncryptedStoragePluginInfo &info)
{
    QString name;
    int istype = 0;
    int itype = 0;
    int ialgo = 0;
    argument.beginStructure();
    argument >> name >> istype >> itype >> ialgo;
    argument.endStructure();
    info.setName(name);
    info.setStorageType(static_cast<StoragePlugin::StorageType>(istype));
    info.setEncryptionType(static_cast<EncryptionPlugin::EncryptionType>(itype));
    info.setEncryptionAlgorithm(static_cast<EncryptionPlugin::EncryptionAlgorithm>(ialgo));
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const AuthenticationPluginInfo &info)
{
    int type = static_cast<int>(info.authenticationType());
    argument.beginStructure();
    argument << info.name() << type;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, AuthenticationPluginInfo &info)
{
    QString name;
    int itype = 0;
    argument.beginStructure();
    argument >> name >> itype;
    argument.endStructure();
    info.setName(name);
    info.setAuthenticationType(static_cast<AuthenticationPlugin::AuthenticationType>(itype));
    return argument;
}

} // namespace Secrets

} // namespace Sailfish
