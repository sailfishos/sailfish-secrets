/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "extensionplugins.h"

#include <QObject>
#include <QString>
#include <QSharedData>

using namespace Sailfish::Secrets;

PluginBase::PluginBase()
{
}

PluginBase::~PluginBase()
{
}

bool PluginBase::supportsLocking() const
{
    return false;
}

bool PluginBase::isLocked() const
{
    return false;
}

bool PluginBase::lock()
{
    return false;
}

bool PluginBase::unlock(const QByteArray &)
{
    return false;
}

bool PluginBase::setLockCode(const QByteArray &, const QByteArray &)
{
    return false;
}

EncryptionPlugin::EncryptionPlugin()
    : PluginBase()
{
}

EncryptionPlugin::~EncryptionPlugin()
{
}

StoragePlugin::StoragePlugin()
    : PluginBase()
{
}

StoragePlugin::~StoragePlugin()
{
}

EncryptedStoragePlugin::EncryptedStoragePlugin()
    : PluginBase()
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
