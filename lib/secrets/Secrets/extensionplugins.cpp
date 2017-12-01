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
            : encryptionType(Sailfish::Secrets::EncryptionPlugin::NoEncryption)
            , encryptionAlgorithm(Sailfish::Secrets::EncryptionPlugin::NoAlgorithm) {}
        EncryptionPluginInfoPrivate(const Sailfish::Secrets::EncryptionPlugin *plugin)
            : name(plugin->name())
            , encryptionType(plugin->encryptionType())
            , encryptionAlgorithm(plugin->encryptionAlgorithm()) {}
        EncryptionPluginInfoPrivate(const EncryptionPluginInfoPrivate &other)
            : name(other.name)
            , encryptionType(other.encryptionType)
            , encryptionAlgorithm(other.encryptionAlgorithm) {}
        QString name;
        Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType;
        Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm;
    };
    class StoragePluginInfoPrivate
    {
    public:
        StoragePluginInfoPrivate()
            : storageType(Sailfish::Secrets::StoragePlugin::NoStorage) {}
        StoragePluginInfoPrivate(const Sailfish::Secrets::StoragePlugin *plugin)
            : name(plugin->name())
            , storageType(plugin->storageType()) {}
        StoragePluginInfoPrivate(const StoragePluginInfoPrivate &other)
            : name(other.name)
            , storageType(other.storageType) {}
        QString name;
        Sailfish::Secrets::StoragePlugin::StorageType storageType;
    };
    class EncryptedStoragePluginInfoPrivate
    {
    public:
        EncryptedStoragePluginInfoPrivate()
            : storageType(Sailfish::Secrets::StoragePlugin::NoStorage)
            , encryptionType(Sailfish::Secrets::EncryptionPlugin::NoEncryption)
            , encryptionAlgorithm(Sailfish::Secrets::EncryptionPlugin::NoAlgorithm) {}
        EncryptedStoragePluginInfoPrivate(const Sailfish::Secrets::EncryptedStoragePlugin *plugin)
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
        Sailfish::Secrets::StoragePlugin::StorageType storageType;
        Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType;
        Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm;
    };
    class AuthenticationPluginInfoPrivate
    {
    public:
        AuthenticationPluginInfoPrivate()
            : authenticationType(Sailfish::Secrets::AuthenticationPlugin::NoAuthentication) {}
        AuthenticationPluginInfoPrivate(const Sailfish::Secrets::AuthenticationPlugin *plugin)
            : name(plugin->name())
            , authenticationType(plugin->authenticationType()) {}
        AuthenticationPluginInfoPrivate(const AuthenticationPluginInfoPrivate &other)
            : name(other.name)
            , authenticationType(other.authenticationType) {}
        QString name;
        Sailfish::Secrets::AuthenticationPlugin::AuthenticationType authenticationType;
    };
} // namespace Secrets
} // namespace Sailfish


Sailfish::Secrets::EncryptionPluginInfo::EncryptionPluginInfo()
    : d(new Sailfish::Secrets::EncryptionPluginInfoPrivate)
{
}

Sailfish::Secrets::EncryptionPluginInfo::EncryptionPluginInfo(const Sailfish::Secrets::EncryptionPluginInfo &other)
    : d(new Sailfish::Secrets::EncryptionPluginInfoPrivate(*other.d))
{
}

Sailfish::Secrets::EncryptionPluginInfo::EncryptionPluginInfo(const Sailfish::Secrets::EncryptionPlugin *plugin)
    : d(new Sailfish::Secrets::EncryptionPluginInfoPrivate(plugin))
{
}

Sailfish::Secrets::EncryptionPluginInfo::~EncryptionPluginInfo()
{
    delete d;
}

QString Sailfish::Secrets::EncryptionPluginInfo::name() const
{
    return d->name;
}

void Sailfish::Secrets::EncryptionPluginInfo::setName(const QString &name)
{
    d->name = name;
}

Sailfish::Secrets::EncryptionPlugin::EncryptionType Sailfish::Secrets::EncryptionPluginInfo::encryptionType() const
{
    return d->encryptionType;
}

void Sailfish::Secrets::EncryptionPluginInfo::setEncryptionType(Sailfish::Secrets::EncryptionPlugin::EncryptionType type)
{
    d->encryptionType = type;
}

Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm Sailfish::Secrets::EncryptionPluginInfo::encryptionAlgorithm() const
{
    return d->encryptionAlgorithm;
}

void Sailfish::Secrets::EncryptionPluginInfo::setEncryptionAlgorithm(Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm algorithm)
{
    d->encryptionAlgorithm = algorithm;
}

Sailfish::Secrets::StoragePluginInfo::StoragePluginInfo()
    : d(new Sailfish::Secrets::StoragePluginInfoPrivate)
{
}

Sailfish::Secrets::StoragePluginInfo::StoragePluginInfo(const Sailfish::Secrets::StoragePluginInfo &other)
    : d(new Sailfish::Secrets::StoragePluginInfoPrivate(*other.d))
{
}

Sailfish::Secrets::StoragePluginInfo::StoragePluginInfo(const Sailfish::Secrets::StoragePlugin *plugin)
    : d(new Sailfish::Secrets::StoragePluginInfoPrivate(plugin))
{
}

Sailfish::Secrets::StoragePluginInfo::~StoragePluginInfo()
{
    delete d;
}

QString Sailfish::Secrets::StoragePluginInfo::name() const
{
    return d->name;
}

void Sailfish::Secrets::StoragePluginInfo::setName(const QString &name)
{
    d->name = name;
}

Sailfish::Secrets::StoragePlugin::StorageType Sailfish::Secrets::StoragePluginInfo::storageType() const
{
    return d->storageType;
}

void Sailfish::Secrets::StoragePluginInfo::setStorageType(Sailfish::Secrets::StoragePlugin::StorageType type)
{
    d->storageType = type;
}

Sailfish::Secrets::EncryptedStoragePluginInfo::EncryptedStoragePluginInfo()
    : d(new Sailfish::Secrets::EncryptedStoragePluginInfoPrivate)
{
}

Sailfish::Secrets::EncryptedStoragePluginInfo::EncryptedStoragePluginInfo(const Sailfish::Secrets::EncryptedStoragePluginInfo &other)
    : d(new Sailfish::Secrets::EncryptedStoragePluginInfoPrivate(*other.d))
{
}

Sailfish::Secrets::EncryptedStoragePluginInfo::EncryptedStoragePluginInfo(const Sailfish::Secrets::EncryptedStoragePlugin *plugin)
    : d(new Sailfish::Secrets::EncryptedStoragePluginInfoPrivate(plugin))
{
}

Sailfish::Secrets::EncryptedStoragePluginInfo::~EncryptedStoragePluginInfo()
{
    delete d;
}

QString Sailfish::Secrets::EncryptedStoragePluginInfo::name() const
{
    return d->name;
}

void Sailfish::Secrets::EncryptedStoragePluginInfo::setName(const QString &name)
{
    d->name = name;
}

Sailfish::Secrets::StoragePlugin::StorageType Sailfish::Secrets::EncryptedStoragePluginInfo::storageType() const
{
    return d->storageType;
}

void Sailfish::Secrets::EncryptedStoragePluginInfo::setStorageType(Sailfish::Secrets::StoragePlugin::StorageType type)
{
    d->storageType = type;
}

Sailfish::Secrets::EncryptionPlugin::EncryptionType Sailfish::Secrets::EncryptedStoragePluginInfo::encryptionType() const
{
    return d->encryptionType;
}

void Sailfish::Secrets::EncryptedStoragePluginInfo::setEncryptionType(Sailfish::Secrets::EncryptionPlugin::EncryptionType type)
{
    d->encryptionType = type;
}

Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm Sailfish::Secrets::EncryptedStoragePluginInfo::encryptionAlgorithm() const
{
    return d->encryptionAlgorithm;
}

void Sailfish::Secrets::EncryptedStoragePluginInfo::setEncryptionAlgorithm(Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm algorithm)
{
    d->encryptionAlgorithm = algorithm;
}

Sailfish::Secrets::AuthenticationPluginInfo::AuthenticationPluginInfo()
    : d(new Sailfish::Secrets::AuthenticationPluginInfoPrivate)
{
}

Sailfish::Secrets::AuthenticationPluginInfo::AuthenticationPluginInfo(const Sailfish::Secrets::AuthenticationPluginInfo &other)
    : d(new Sailfish::Secrets::AuthenticationPluginInfoPrivate(*other.d))
{
}

Sailfish::Secrets::AuthenticationPluginInfo::AuthenticationPluginInfo(const Sailfish::Secrets::AuthenticationPlugin *plugin)
    : d(new Sailfish::Secrets::AuthenticationPluginInfoPrivate(plugin))
{
}

Sailfish::Secrets::AuthenticationPluginInfo::~AuthenticationPluginInfo()
{
    delete d;
}

QString Sailfish::Secrets::AuthenticationPluginInfo::name() const
{
    return d->name;
}

void Sailfish::Secrets::AuthenticationPluginInfo::setName(const QString &name)
{
    d->name = name;
}

Sailfish::Secrets::AuthenticationPlugin::AuthenticationType Sailfish::Secrets::AuthenticationPluginInfo::authenticationType() const
{
    return d->authenticationType;
}

void Sailfish::Secrets::AuthenticationPluginInfo::setAuthenticationType(Sailfish::Secrets::AuthenticationPlugin::AuthenticationType type)
{
    d->authenticationType = type;
}

Sailfish::Secrets::EncryptionPlugin::EncryptionPlugin(QObject *parent)
    : QObject(parent)
{
}

Sailfish::Secrets::EncryptionPlugin::~EncryptionPlugin()
{
}

Sailfish::Secrets::StoragePlugin::StoragePlugin(QObject *parent)
    : QObject(parent)
{
}

Sailfish::Secrets::StoragePlugin::~StoragePlugin()
{
}

Sailfish::Secrets::EncryptedStoragePlugin::EncryptedStoragePlugin(QObject *parent)
    : QObject(parent)
{
}

Sailfish::Secrets::EncryptedStoragePlugin::~EncryptedStoragePlugin()
{
}

Sailfish::Secrets::AuthenticationPlugin::AuthenticationPlugin(QObject *parent)
    : QObject(parent)
{
}

Sailfish::Secrets::AuthenticationPlugin::~AuthenticationPlugin()
{
}
