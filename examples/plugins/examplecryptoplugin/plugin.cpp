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

Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)

using namespace Sailfish::Secrets::Daemon::Plugins;

ExampleCryptoPlugin::ExampleCryptoPlugin(QObject *parent)
    : QObject(parent)
{
}

ExampleCryptoPlugin::~ExampleCryptoPlugin()
{
}

bool ExampleCryptoPlugin::isAvailable() const
{
    // In a real USB token-backed plugin, this method would
    // detect whether the USB token is connected to the device
    // via USB, and return its availability status.

    return true;
}

bool ExampleCryptoPlugin::supportsSetLockCode() const
{
    return false;
}

bool ExampleCryptoPlugin::isLocked() const
{
    return false;
}

bool ExampleCryptoPlugin::setLockCode(const QByteArray &oldLockCode, const QByteArray &newLockCode)
{
    Q_UNUSED(oldLockCode)
    Q_UNUSED(newLockCode)
    return false;
}

bool ExampleCryptoPlugin::lock()
{
    return false;
}

bool ExampleCryptoPlugin::unlock(const QByteArray &lockCode)
{
    Q_UNUSED(lockCode);
    return false;
}
