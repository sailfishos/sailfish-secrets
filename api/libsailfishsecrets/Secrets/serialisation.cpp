/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/secretmanager.h"
#include "Secrets/result.h"
#include "Secrets/uirequest.h"

#include <QtDBus/QDBusArgument>
#include <QtCore/QString>
#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishSecretsSerialisation, "org.sailfishos.secrets.serialisation")

namespace Sailfish {

namespace Secrets {

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::UiResponse &response)
{
    argument.beginStructure();
    argument << response.type();
    argument << response.values();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::UiResponse &response)
{
    int type = 0;
    QVariantMap values;
    argument.beginStructure();
    argument >> type;
    argument >> values;
    argument.endStructure();
    response = Sailfish::Secrets::UiResponse(static_cast<Sailfish::Secrets::UiRequest::Type>(type), values);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::UiRequest &request)
{
    argument.beginStructure();
    argument << static_cast<int>(request.type());
    argument << request.isResponse();
    argument << request.values();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::UiRequest &request)
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
        request = Sailfish::Secrets::UiResponse(static_cast<Sailfish::Secrets::UiRequest::Type>(type), values);
    } else {
        request = Sailfish::Secrets::UiRequest(static_cast<Sailfish::Secrets::UiRequest::Type>(type), values);
    }
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::Result &result)
{
    argument.beginStructure();
    argument << static_cast<int>(result.code()) << result.errorCode() << result.errorMessage();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::Result &result)
{
    int code;
    int errorCode;
    QString message;

    argument.beginStructure();
    argument >> code >> errorCode >> message;
    argument.endStructure();

    result.setCode(static_cast<Sailfish::Secrets::Result::ResultCode>(code));
    result.setErrorCode(static_cast<Sailfish::Secrets::Result::ErrorCode>(errorCode));
    result.setErrorMessage(message);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::UserInteractionMode mode)
{
    int imode = static_cast<int>(mode);
    argument.beginStructure();
    argument << imode;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::UserInteractionMode &mode)
{
    int imode = 0;
    argument.beginStructure();
    argument >> imode;
    argument.endStructure();
    mode = static_cast<Sailfish::Secrets::SecretManager::UserInteractionMode>(imode);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::AccessControlMode mode)
{
    int imode = static_cast<int>(mode);
    argument.beginStructure();
    argument << imode;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::AccessControlMode &mode)
{
    int imode = 0;
    argument.beginStructure();
    argument >> imode;
    argument.endStructure();
    mode = static_cast<Sailfish::Secrets::SecretManager::AccessControlMode>(imode);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic semantic)
{
    int isemantic = static_cast<int>(semantic);
    argument.beginStructure();
    argument << isemantic;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic &semantic)
{
    int isemantic = 0;
    argument.beginStructure();
    argument >> isemantic;
    argument.endStructure();
    semantic = static_cast<Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic>(isemantic);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic semantic)
{
    int isemantic = static_cast<int>(semantic);
    argument.beginStructure();
    argument << isemantic;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic &semantic)
{
    int isemantic = 0;
    argument.beginStructure();
    argument >> isemantic;
    argument.endStructure();
    semantic = static_cast<Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic>(isemantic);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::StoragePluginInfo &info)
{
    int type = static_cast<int>(info.storageType());
    argument.beginStructure();
    argument << info.name() << type;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::StoragePluginInfo &info)
{
    QString name;
    int itype = 0;
    argument.beginStructure();
    argument >> name >> itype;
    argument.endStructure();
    info.setName(name);
    info.setStorageType(static_cast<Sailfish::Secrets::StoragePlugin::StorageType>(itype));
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::EncryptionPluginInfo &info)
{
    int type = static_cast<int>(info.encryptionType());
    int algo = static_cast<int>(info.encryptionAlgorithm());
    argument.beginStructure();
    argument << info.name() << type << algo;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::EncryptionPluginInfo &info)
{
    QString name;
    int itype = 0;
    int ialgo = 0;
    argument.beginStructure();
    argument >> name >> itype >> ialgo;
    argument.endStructure();
    info.setName(name);
    info.setEncryptionType(static_cast<Sailfish::Secrets::EncryptionPlugin::EncryptionType>(itype));
    info.setEncryptionAlgorithm(static_cast<Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm>(ialgo));
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::EncryptedStoragePluginInfo &info)
{
    int stype = static_cast<int>(info.storageType());
    int type = static_cast<int>(info.encryptionType());
    int algo = static_cast<int>(info.encryptionAlgorithm());
    argument.beginStructure();
    argument << info.name() << stype << type << algo;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::EncryptedStoragePluginInfo &info)
{
    QString name;
    int istype = 0;
    int itype = 0;
    int ialgo = 0;
    argument.beginStructure();
    argument >> name >> istype >> itype >> ialgo;
    argument.endStructure();
    info.setName(name);
    info.setStorageType(static_cast<Sailfish::Secrets::StoragePlugin::StorageType>(istype));
    info.setEncryptionType(static_cast<Sailfish::Secrets::EncryptionPlugin::EncryptionType>(itype));
    info.setEncryptionAlgorithm(static_cast<Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm>(ialgo));
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::AuthenticationPluginInfo &info)
{
    int type = static_cast<int>(info.authenticationType());
    argument.beginStructure();
    argument << info.name() << type;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::AuthenticationPluginInfo &info)
{
    QString name;
    int itype = 0;
    argument.beginStructure();
    argument >> name >> itype;
    argument.endStructure();
    info.setName(name);
    info.setAuthenticationType(static_cast<Sailfish::Secrets::AuthenticationPlugin::AuthenticationType>(itype));
    return argument;
}

} // namespace Secrets

} // namespace Sailfish
