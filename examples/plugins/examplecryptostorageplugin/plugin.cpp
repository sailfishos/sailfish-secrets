/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"

#include <QStandardPaths>
#include <QString>
#include <QByteArray>

#include <QtDebug>

Q_PLUGIN_METADATA(IID Sailfish_Secrets_EncryptedStoragePlugin_IID)

using namespace Sailfish::Secrets::Daemon::Plugins;

ExampleCryptoStoragePlugin::ExampleCryptoStoragePlugin(QObject *parent)
    : QObject(parent)
{
}

ExampleCryptoStoragePlugin::~ExampleCryptoStoragePlugin()
{
}

bool ExampleCryptoStoragePlugin::isAvailable() const
{
    // In a real USB token-backed plugin, this method would
    // detect whether the USB token is connected to the device
    // via USB, and return its availability status.

    // In this example, we always return true.
    return true;
}

bool ExampleCryptoStoragePlugin::supportsSetLockCode() const
{
    // we don't support changing the lock code in this example.
    return false;
}

bool ExampleCryptoStoragePlugin::isLocked() const
{
    return m_builtInKey.publicKey().isEmpty();
}

bool ExampleCryptoStoragePlugin::setLockCode(const QByteArray &oldLockCode, const QByteArray &newLockCode)
{
    // we don't support changing the lock code in this example.
    Q_UNUSED(oldLockCode)
    Q_UNUSED(newLockCode)
    return false;
}

bool ExampleCryptoStoragePlugin::lock()
{
    m_builtInKey = Sailfish::Crypto::Key();
    return true;
}

bool ExampleCryptoStoragePlugin::unlock(const QByteArray &lockCode)
{
    Q_UNUSED(lockCode);
    return false;
}
