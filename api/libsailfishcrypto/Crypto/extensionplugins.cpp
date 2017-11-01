/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/extensionplugins.h"
#include "Crypto/extensionplugins_p.h"
#include "Crypto/key.h"

#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>

Sailfish::Crypto::CryptoPluginInfoData::CryptoPluginInfoData()
    : m_pluginName(QLatin1String("org.sailfishos.crypto.cryptoplugin.invalid"))
    , m_canStoreKeys(false)
{
}

Sailfish::Crypto::CryptoPluginInfoData::CryptoPluginInfoData(
        const QString &pluginName,
        bool canStoreKeys,
        Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType,
        const QVector<Sailfish::Crypto::Key::Algorithm> &supportedAlgorithms,
        const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> &supportedBlockModes,
        const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> &supportedEncryptionPaddings,
        const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> &supportedSignaturePaddings,
        const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> &supportedDigests,
        const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> &supportedOperations)
    : m_pluginName(pluginName)
    , m_canStoreKeys(canStoreKeys)
    , m_encryptionType(encryptionType)
    , m_supportedAlgorithms(supportedAlgorithms)
    , m_supportedBlockModes(supportedBlockModes)
    , m_supportedEncryptionPaddings(supportedEncryptionPaddings)
    , m_supportedSignaturePaddings(supportedSignaturePaddings)
    , m_supportedDigests(supportedDigests)
    , m_supportedOperations(supportedOperations)
{
}

Sailfish::Crypto::CryptoPluginInfo::CryptoPluginInfo()
    : m_data(new Sailfish::Crypto::CryptoPluginInfoData)
{
}

Sailfish::Crypto::CryptoPluginInfo::CryptoPluginInfo(
        Sailfish::Crypto::CryptoPlugin *plugin)
    : m_data(new Sailfish::Crypto::CryptoPluginInfoData(
                 plugin->name(),
                 plugin->canStoreKeys(),
                 plugin->encryptionType(),
                 plugin->supportedAlgorithms(),
                 plugin->supportedBlockModes(),
                 plugin->supportedEncryptionPaddings(),
                 plugin->supportedSignaturePaddings(),
                 plugin->supportedDigests(),
                 plugin->supportedOperations()))
{
}

Sailfish::Crypto::CryptoPluginInfo::CryptoPluginInfo(const CryptoPluginInfo &other)
    : m_data(new Sailfish::Crypto::CryptoPluginInfoData(
                 other.name(),
                 other.canStoreKeys(),
                 other.encryptionType(),
                 other.supportedAlgorithms(),
                 other.supportedBlockModes(),
                 other.supportedEncryptionPaddings(),
                 other.supportedSignaturePaddings(),
                 other.supportedDigests(),
                 other.supportedOperations()))
{
}

Sailfish::Crypto::CryptoPluginInfo::~CryptoPluginInfo()
{
    delete m_data;
}

Sailfish::Crypto::CryptoPluginInfo&
Sailfish::Crypto::CryptoPluginInfo::operator=(const CryptoPluginInfo &other)
{
    if (this != &other) {
        delete m_data;
        m_data = new Sailfish::Crypto::CryptoPluginInfoData(
                         other.name(),
                         other.canStoreKeys(),
                         other.encryptionType(),
                         other.supportedAlgorithms(),
                         other.supportedBlockModes(),
                         other.supportedEncryptionPaddings(),
                         other.supportedSignaturePaddings(),
                         other.supportedDigests(),
                         other.supportedOperations());
    }

    return *this;
}

QString
Sailfish::Crypto::CryptoPluginInfo::name() const
{
    return m_data->m_pluginName;
}

bool
Sailfish::Crypto::CryptoPluginInfo::canStoreKeys() const
{
    return m_data->m_canStoreKeys;
}

Sailfish::Crypto::CryptoPlugin::EncryptionType
Sailfish::Crypto::CryptoPluginInfo::encryptionType() const
{
    return m_data->m_encryptionType;
}

QVector<Sailfish::Crypto::Key::Algorithm>
Sailfish::Crypto::CryptoPluginInfo::supportedAlgorithms() const
{
    return m_data->m_supportedAlgorithms;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes>
Sailfish::Crypto::CryptoPluginInfo::supportedBlockModes() const
{
    return m_data->m_supportedBlockModes;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings>
Sailfish::Crypto::CryptoPluginInfo::supportedEncryptionPaddings() const
{
    return m_data->m_supportedEncryptionPaddings;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings>
Sailfish::Crypto::CryptoPluginInfo::supportedSignaturePaddings() const
{
    return m_data->m_supportedSignaturePaddings;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests>
Sailfish::Crypto::CryptoPluginInfo::supportedDigests() const
{
    return m_data->m_supportedDigests;
}

QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations>
Sailfish::Crypto::CryptoPluginInfo::supportedOperations() const
{
    return m_data->m_supportedOperations;
}

void Sailfish::Crypto::CryptoPluginInfo::setName(
        const QString &name)
{
    m_data->m_pluginName = name;
}

void Sailfish::Crypto::CryptoPluginInfo::setCanStoreKeys(
        bool v)
{
    m_data->m_canStoreKeys = v;
}

void Sailfish::Crypto::CryptoPluginInfo::setEncryptionType(
        Sailfish::Crypto::CryptoPlugin::EncryptionType type)
{
    m_data->m_encryptionType = type;
}

void Sailfish::Crypto::CryptoPluginInfo::setSupportedAlgorithms(
        const QVector<Sailfish::Crypto::Key::Algorithm> &algorithms)
{
    m_data->m_supportedAlgorithms = algorithms;
}

void Sailfish::Crypto::CryptoPluginInfo::setSupportedBlockModes(
        const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> &modes)
{
    m_data->m_supportedBlockModes = modes;
}

void Sailfish::Crypto::CryptoPluginInfo::setSupportedEncryptionPaddings(
        const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> &paddings)
{
    m_data->m_supportedEncryptionPaddings = paddings;
}

void Sailfish::Crypto::CryptoPluginInfo::setSupportedSignaturePaddings(
        const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> &paddings)
{
    m_data->m_supportedSignaturePaddings = paddings;
}

void Sailfish::Crypto::CryptoPluginInfo::setSupportedDigests(
        const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> &digests)
{
    m_data->m_supportedDigests = digests;
}

void Sailfish::Crypto::CryptoPluginInfo::setSupportedOperations(
        const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> &operations)
{
    m_data->m_supportedOperations = operations;
}

//---------------------------------------------

Sailfish::Crypto::CryptoPlugin::CryptoPlugin(QObject *parent)
    : QObject(parent)
{
}

Sailfish::Crypto::CryptoPlugin::~CryptoPlugin()
{
}
