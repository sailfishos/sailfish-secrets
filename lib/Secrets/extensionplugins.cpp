/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/extensionplugins.h"

#include <QObject>
#include <QString>
#include <QSharedData>

namespace Sailfish {
namespace Secrets {
    class EncryptionPluginInfoPrivate : public QSharedData
    {
    public:
        EncryptionPluginInfoPrivate()
            : QSharedData()
            , encryptionType(EncryptionPlugin::NoEncryption)
            , encryptionAlgorithm(EncryptionPlugin::NoAlgorithm) {}
        EncryptionPluginInfoPrivate(const EncryptionPlugin *plugin)
            : QSharedData()
            , name(plugin->name())
            , encryptionType(plugin->encryptionType())
            , encryptionAlgorithm(plugin->encryptionAlgorithm()) {}
        EncryptionPluginInfoPrivate(const EncryptionPluginInfoPrivate &other)
            : QSharedData(other)
            , name(other.name)
            , encryptionType(other.encryptionType)
            , encryptionAlgorithm(other.encryptionAlgorithm) {}
        QString name;
        EncryptionPlugin::EncryptionType encryptionType;
        EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm;
    };
    class StoragePluginInfoPrivate : public QSharedData
    {
    public:
        StoragePluginInfoPrivate()
            : QSharedData()
            , storageType(StoragePlugin::NoStorage) {}
        StoragePluginInfoPrivate(const StoragePlugin *plugin)
            : QSharedData()
            , name(plugin->name())
            , storageType(plugin->storageType()) {}
        StoragePluginInfoPrivate(const StoragePluginInfoPrivate &other)
            : QSharedData(other)
            , name(other.name)
            , storageType(other.storageType) {}
        QString name;
        StoragePlugin::StorageType storageType;
    };
    class EncryptedStoragePluginInfoPrivate : public QSharedData
    {
    public:
        EncryptedStoragePluginInfoPrivate()
            : QSharedData()
            , storageType(StoragePlugin::NoStorage)
            , encryptionType(EncryptionPlugin::NoEncryption)
            , encryptionAlgorithm(EncryptionPlugin::NoAlgorithm) {}
        EncryptedStoragePluginInfoPrivate(const EncryptedStoragePlugin *plugin)
            : QSharedData()
            , name(plugin->name())
            , storageType(plugin->storageType())
            , encryptionType(plugin->encryptionType())
            , encryptionAlgorithm(plugin->encryptionAlgorithm()) {}
        EncryptedStoragePluginInfoPrivate(const EncryptedStoragePluginInfoPrivate &other)
            : QSharedData(other)
            , name(other.name)
            , storageType(other.storageType)
            , encryptionType(other.encryptionType)
            , encryptionAlgorithm(other.encryptionAlgorithm) {}
        QString name;
        StoragePlugin::StorageType storageType;
        EncryptionPlugin::EncryptionType encryptionType;
        EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm;
    };
    class AuthenticationPluginInfoPrivate : public QSharedData
    {
    public:
        AuthenticationPluginInfoPrivate()
            : QSharedData()
            , authenticationTypes(AuthenticationPlugin::NoAuthentication)
            , inputTypes(InteractionParameters::UnknownInput) {}
        AuthenticationPluginInfoPrivate(const AuthenticationPlugin *plugin)
            : QSharedData()
            , name(plugin->name())
            , authenticationTypes(plugin->authenticationTypes())
            , inputTypes(plugin->inputTypes()) {}
        AuthenticationPluginInfoPrivate(const AuthenticationPluginInfoPrivate &other)
            : QSharedData(other)
            , name(other.name)
            , authenticationTypes(other.authenticationTypes)
            , inputTypes(other.inputTypes) {}
        QString name;
        AuthenticationPlugin::AuthenticationTypes authenticationTypes;
        InteractionParameters::InputTypes inputTypes;
    };
} // namespace Secrets
} // namespace Sailfish

using namespace Sailfish::Secrets;

EncryptionPluginInfo::EncryptionPluginInfo()
    : d_ptr(new EncryptionPluginInfoPrivate)
{
}

EncryptionPluginInfo::EncryptionPluginInfo(const EncryptionPluginInfo &other)
    : d_ptr(other.d_ptr)
{
}

EncryptionPluginInfo::EncryptionPluginInfo(const EncryptionPlugin *plugin)
    : d_ptr(new EncryptionPluginInfoPrivate(plugin))
{
}

EncryptionPluginInfo::~EncryptionPluginInfo()
{
}

EncryptionPluginInfo& EncryptionPluginInfo::operator=(
        const EncryptionPluginInfo &other)
{
    d_ptr = other.d_ptr;
    return *this;
}

QString EncryptionPluginInfo::name() const
{
    return d_ptr->name;
}

void EncryptionPluginInfo::setName(const QString &name)
{
    d_ptr->name = name;
}

EncryptionPlugin::EncryptionType EncryptionPluginInfo::encryptionType() const
{
    return d_ptr->encryptionType;
}

void EncryptionPluginInfo::setEncryptionType(EncryptionPlugin::EncryptionType type)
{
    d_ptr->encryptionType = type;
}

EncryptionPlugin::EncryptionAlgorithm EncryptionPluginInfo::encryptionAlgorithm() const
{
    return d_ptr->encryptionAlgorithm;
}

void EncryptionPluginInfo::setEncryptionAlgorithm(EncryptionPlugin::EncryptionAlgorithm algorithm)
{
    d_ptr->encryptionAlgorithm = algorithm;
}

StoragePluginInfo::StoragePluginInfo()
    : d_ptr(new StoragePluginInfoPrivate)
{
}

StoragePluginInfo::StoragePluginInfo(const StoragePluginInfo &other)
    : d_ptr(other.d_ptr)
{
}

StoragePluginInfo::StoragePluginInfo(const StoragePlugin *plugin)
    : d_ptr(new StoragePluginInfoPrivate(plugin))
{
}

StoragePluginInfo::~StoragePluginInfo()
{
}

StoragePluginInfo& StoragePluginInfo::operator=(
        const StoragePluginInfo &other)
{
    d_ptr = other.d_ptr;
    return *this;
}

QString StoragePluginInfo::name() const
{
    return d_ptr->name;
}

void StoragePluginInfo::setName(const QString &name)
{
    d_ptr->name = name;
}

StoragePlugin::StorageType StoragePluginInfo::storageType() const
{
    return d_ptr->storageType;
}

void StoragePluginInfo::setStorageType(StoragePlugin::StorageType type)
{
    d_ptr->storageType = type;
}

EncryptedStoragePluginInfo::EncryptedStoragePluginInfo()
    : d_ptr(new EncryptedStoragePluginInfoPrivate)
{
}

EncryptedStoragePluginInfo::EncryptedStoragePluginInfo(const EncryptedStoragePluginInfo &other)
    : d_ptr(other.d_ptr)
{
}

EncryptedStoragePluginInfo::EncryptedStoragePluginInfo(const EncryptedStoragePlugin *plugin)
    : d_ptr(new EncryptedStoragePluginInfoPrivate(plugin))
{
}

EncryptedStoragePluginInfo::~EncryptedStoragePluginInfo()
{
}

EncryptedStoragePluginInfo& EncryptedStoragePluginInfo::operator=(
        const EncryptedStoragePluginInfo &other)
{
    d_ptr = other.d_ptr;
    return *this;
}

QString EncryptedStoragePluginInfo::name() const
{
    return d_ptr->name;
}

void EncryptedStoragePluginInfo::setName(const QString &name)
{
    d_ptr->name = name;
}

StoragePlugin::StorageType EncryptedStoragePluginInfo::storageType() const
{
    return d_ptr->storageType;
}

void EncryptedStoragePluginInfo::setStorageType(StoragePlugin::StorageType type)
{
    d_ptr->storageType = type;
}

EncryptionPlugin::EncryptionType EncryptedStoragePluginInfo::encryptionType() const
{
    return d_ptr->encryptionType;
}

void EncryptedStoragePluginInfo::setEncryptionType(EncryptionPlugin::EncryptionType type)
{
    d_ptr->encryptionType = type;
}

EncryptionPlugin::EncryptionAlgorithm EncryptedStoragePluginInfo::encryptionAlgorithm() const
{
    return d_ptr->encryptionAlgorithm;
}

void EncryptedStoragePluginInfo::setEncryptionAlgorithm(EncryptionPlugin::EncryptionAlgorithm algorithm)
{
    d_ptr->encryptionAlgorithm = algorithm;
}

AuthenticationPluginInfo::AuthenticationPluginInfo()
    : d_ptr(new AuthenticationPluginInfoPrivate)
{
}

AuthenticationPluginInfo::AuthenticationPluginInfo(const AuthenticationPluginInfo &other)
    : d_ptr(other.d_ptr)
{
}

AuthenticationPluginInfo::AuthenticationPluginInfo(const AuthenticationPlugin *plugin)
    : d_ptr(new AuthenticationPluginInfoPrivate(plugin))
{
}

AuthenticationPluginInfo::~AuthenticationPluginInfo()
{
}

AuthenticationPluginInfo& AuthenticationPluginInfo::operator=(
        const AuthenticationPluginInfo &other)
{
    d_ptr = other.d_ptr;
    return *this;
}

QString AuthenticationPluginInfo::name() const
{
    return d_ptr->name;
}

void AuthenticationPluginInfo::setName(const QString &name)
{
    d_ptr->name = name;
}

AuthenticationPlugin::AuthenticationTypes AuthenticationPluginInfo::authenticationTypes() const
{
    return d_ptr->authenticationTypes;
}

void AuthenticationPluginInfo::setAuthenticationTypes(AuthenticationPlugin::AuthenticationTypes types)
{
    d_ptr->authenticationTypes = types;
}

InteractionParameters::InputTypes AuthenticationPluginInfo::inputTypes() const
{
    return d_ptr->inputTypes;
}

void AuthenticationPluginInfo::setInputTypes(InteractionParameters::InputTypes types)
{
    d_ptr->inputTypes = types;
}

EncryptionPlugin::EncryptionPlugin(QObject *parent)
    : QObject(parent)
{
}

EncryptionPlugin::~EncryptionPlugin()
{
}

StoragePlugin::StoragePlugin(QObject *parent)
    : QObject(parent)
{
}

StoragePlugin::~StoragePlugin()
{
}

EncryptedStoragePlugin::EncryptedStoragePlugin(QObject *parent)
    : QObject(parent)
{
}

EncryptedStoragePlugin::~EncryptedStoragePlugin()
{
}

AuthenticationPlugin::AuthenticationPlugin(QObject *parent)
    : QObject(parent)
{
}

AuthenticationPlugin::~AuthenticationPlugin()
{
}
