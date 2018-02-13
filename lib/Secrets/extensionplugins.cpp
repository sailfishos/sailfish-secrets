/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/extensionplugins.h"

#include <QObject>
#include <QString>

namespace Sailfish {
namespace Secrets {
    class EncryptionPluginInfoPrivate
    {
    public:
        EncryptionPluginInfoPrivate()
            : encryptionType(EncryptionPlugin::NoEncryption)
            , encryptionAlgorithm(EncryptionPlugin::NoAlgorithm) {}
        EncryptionPluginInfoPrivate(const EncryptionPlugin *plugin)
            : name(plugin->name())
            , encryptionType(plugin->encryptionType())
            , encryptionAlgorithm(plugin->encryptionAlgorithm()) {}
        EncryptionPluginInfoPrivate(const EncryptionPluginInfoPrivate &other)
            : name(other.name)
            , encryptionType(other.encryptionType)
            , encryptionAlgorithm(other.encryptionAlgorithm) {}
        QString name;
        EncryptionPlugin::EncryptionType encryptionType;
        EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm;
    };
    class StoragePluginInfoPrivate
    {
    public:
        StoragePluginInfoPrivate()
            : storageType(StoragePlugin::NoStorage) {}
        StoragePluginInfoPrivate(const StoragePlugin *plugin)
            : name(plugin->name())
            , storageType(plugin->storageType()) {}
        StoragePluginInfoPrivate(const StoragePluginInfoPrivate &other)
            : name(other.name)
            , storageType(other.storageType) {}
        QString name;
        StoragePlugin::StorageType storageType;
    };
    class EncryptedStoragePluginInfoPrivate
    {
    public:
        EncryptedStoragePluginInfoPrivate()
            : storageType(StoragePlugin::NoStorage)
            , encryptionType(EncryptionPlugin::NoEncryption)
            , encryptionAlgorithm(EncryptionPlugin::NoAlgorithm) {}
        EncryptedStoragePluginInfoPrivate(const EncryptedStoragePlugin *plugin)
            : name(plugin->name())
            , storageType(plugin->storageType())
            , encryptionType(plugin->encryptionType())
            , encryptionAlgorithm(plugin->encryptionAlgorithm()) {}
        EncryptedStoragePluginInfoPrivate(const EncryptedStoragePluginInfoPrivate &other)
            : name(other.name)
            , storageType(other.storageType)
            , encryptionType(other.encryptionType)
            , encryptionAlgorithm(other.encryptionAlgorithm) {}
        QString name;
        StoragePlugin::StorageType storageType;
        EncryptionPlugin::EncryptionType encryptionType;
        EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm;
    };
    class AuthenticationPluginInfoPrivate
    {
    public:
        AuthenticationPluginInfoPrivate()
            : authenticationTypes(AuthenticationPlugin::NoAuthentication)
            , inputTypes(InteractionParameters::UnknownInput) {}
        AuthenticationPluginInfoPrivate(const AuthenticationPlugin *plugin)
            : name(plugin->name())
            , authenticationTypes(plugin->authenticationTypes())
            , inputTypes(plugin->inputTypes()) {}
        AuthenticationPluginInfoPrivate(const AuthenticationPluginInfoPrivate &other)
            : name(other.name)
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
    : d(new EncryptionPluginInfoPrivate)
{
}

EncryptionPluginInfo::EncryptionPluginInfo(const EncryptionPluginInfo &other)
    : d(new EncryptionPluginInfoPrivate(*other.d))
{
}

EncryptionPluginInfo::EncryptionPluginInfo(const EncryptionPlugin *plugin)
    : d(new EncryptionPluginInfoPrivate(plugin))
{
}

EncryptionPluginInfo::~EncryptionPluginInfo()
{
    delete d;
}

QString EncryptionPluginInfo::name() const
{
    return d->name;
}

void EncryptionPluginInfo::setName(const QString &name)
{
    d->name = name;
}

EncryptionPlugin::EncryptionType EncryptionPluginInfo::encryptionType() const
{
    return d->encryptionType;
}

void EncryptionPluginInfo::setEncryptionType(EncryptionPlugin::EncryptionType type)
{
    d->encryptionType = type;
}

EncryptionPlugin::EncryptionAlgorithm EncryptionPluginInfo::encryptionAlgorithm() const
{
    return d->encryptionAlgorithm;
}

void EncryptionPluginInfo::setEncryptionAlgorithm(EncryptionPlugin::EncryptionAlgorithm algorithm)
{
    d->encryptionAlgorithm = algorithm;
}

StoragePluginInfo::StoragePluginInfo()
    : d(new StoragePluginInfoPrivate)
{
}

StoragePluginInfo::StoragePluginInfo(const StoragePluginInfo &other)
    : d(new StoragePluginInfoPrivate(*other.d))
{
}

StoragePluginInfo::StoragePluginInfo(const StoragePlugin *plugin)
    : d(new StoragePluginInfoPrivate(plugin))
{
}

StoragePluginInfo::~StoragePluginInfo()
{
    delete d;
}

QString StoragePluginInfo::name() const
{
    return d->name;
}

void StoragePluginInfo::setName(const QString &name)
{
    d->name = name;
}

StoragePlugin::StorageType StoragePluginInfo::storageType() const
{
    return d->storageType;
}

void StoragePluginInfo::setStorageType(StoragePlugin::StorageType type)
{
    d->storageType = type;
}

EncryptedStoragePluginInfo::EncryptedStoragePluginInfo()
    : d(new EncryptedStoragePluginInfoPrivate)
{
}

EncryptedStoragePluginInfo::EncryptedStoragePluginInfo(const EncryptedStoragePluginInfo &other)
    : d(new EncryptedStoragePluginInfoPrivate(*other.d))
{
}

EncryptedStoragePluginInfo::EncryptedStoragePluginInfo(const EncryptedStoragePlugin *plugin)
    : d(new EncryptedStoragePluginInfoPrivate(plugin))
{
}

EncryptedStoragePluginInfo::~EncryptedStoragePluginInfo()
{
    delete d;
}

QString EncryptedStoragePluginInfo::name() const
{
    return d->name;
}

void EncryptedStoragePluginInfo::setName(const QString &name)
{
    d->name = name;
}

StoragePlugin::StorageType EncryptedStoragePluginInfo::storageType() const
{
    return d->storageType;
}

void EncryptedStoragePluginInfo::setStorageType(StoragePlugin::StorageType type)
{
    d->storageType = type;
}

EncryptionPlugin::EncryptionType EncryptedStoragePluginInfo::encryptionType() const
{
    return d->encryptionType;
}

void EncryptedStoragePluginInfo::setEncryptionType(EncryptionPlugin::EncryptionType type)
{
    d->encryptionType = type;
}

EncryptionPlugin::EncryptionAlgorithm EncryptedStoragePluginInfo::encryptionAlgorithm() const
{
    return d->encryptionAlgorithm;
}

void EncryptedStoragePluginInfo::setEncryptionAlgorithm(EncryptionPlugin::EncryptionAlgorithm algorithm)
{
    d->encryptionAlgorithm = algorithm;
}

AuthenticationPluginInfo::AuthenticationPluginInfo()
    : d(new AuthenticationPluginInfoPrivate)
{
}

AuthenticationPluginInfo::AuthenticationPluginInfo(const AuthenticationPluginInfo &other)
    : d(new AuthenticationPluginInfoPrivate(*other.d))
{
}

AuthenticationPluginInfo::AuthenticationPluginInfo(const AuthenticationPlugin *plugin)
    : d(new AuthenticationPluginInfoPrivate(plugin))
{
}

AuthenticationPluginInfo::~AuthenticationPluginInfo()
{
    delete d;
}

QString AuthenticationPluginInfo::name() const
{
    return d->name;
}

void AuthenticationPluginInfo::setName(const QString &name)
{
    d->name = name;
}

AuthenticationPlugin::AuthenticationTypes AuthenticationPluginInfo::authenticationTypes() const
{
    return d->authenticationTypes;
}

void AuthenticationPluginInfo::setAuthenticationTypes(AuthenticationPlugin::AuthenticationTypes types)
{
    d->authenticationTypes = types;
}

InteractionParameters::InputTypes AuthenticationPluginInfo::inputTypes() const
{
    return d->inputTypes;
}

void AuthenticationPluginInfo::setInputTypes(InteractionParameters::InputTypes types)
{
    d->inputTypes = types;
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
