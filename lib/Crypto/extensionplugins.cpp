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

using namespace Sailfish::Crypto;

CryptoPluginInfoData::CryptoPluginInfoData()
    : m_pluginName(QLatin1String("org.sailfishos.crypto.cryptoplugin.invalid"))
    , m_canStoreKeys(false)
{
}

CryptoPluginInfoData::CryptoPluginInfoData(
        const QString &pluginName,
        bool canStoreKeys,
        CryptoPlugin::EncryptionType encryptionType,
        const QVector<Key::Algorithm> &supportedAlgorithms,
        const QMap<Key::Algorithm, Key::BlockModes> &supportedBlockModes,
        const QMap<Key::Algorithm, Key::EncryptionPaddings> &supportedEncryptionPaddings,
        const QMap<Key::Algorithm, Key::SignaturePaddings> &supportedSignaturePaddings,
        const QMap<Key::Algorithm, Key::Digests> &supportedDigests,
        const QMap<Key::Algorithm, Key::Operations> &supportedOperations)
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

CryptoPluginInfo::CryptoPluginInfo()
    : m_data(new CryptoPluginInfoData)
{
}

CryptoPluginInfo::CryptoPluginInfo(
        CryptoPlugin *plugin)
    : m_data(new CryptoPluginInfoData(
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

CryptoPluginInfo::CryptoPluginInfo(const CryptoPluginInfo &other)
    : m_data(new CryptoPluginInfoData(
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

CryptoPluginInfo::~CryptoPluginInfo()
{
    delete m_data;
}

CryptoPluginInfo&
CryptoPluginInfo::operator=(const CryptoPluginInfo &other)
{
    if (this != &other) {
        delete m_data;
        m_data = new CryptoPluginInfoData(
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
CryptoPluginInfo::name() const
{
    return m_data->m_pluginName;
}

bool
CryptoPluginInfo::canStoreKeys() const
{
    return m_data->m_canStoreKeys;
}

CryptoPlugin::EncryptionType
CryptoPluginInfo::encryptionType() const
{
    return m_data->m_encryptionType;
}

QVector<Key::Algorithm>
CryptoPluginInfo::supportedAlgorithms() const
{
    return m_data->m_supportedAlgorithms;
}

QMap<Key::Algorithm, Key::BlockModes>
CryptoPluginInfo::supportedBlockModes() const
{
    return m_data->m_supportedBlockModes;
}

QMap<Key::Algorithm, Key::EncryptionPaddings>
CryptoPluginInfo::supportedEncryptionPaddings() const
{
    return m_data->m_supportedEncryptionPaddings;
}

QMap<Key::Algorithm, Key::SignaturePaddings>
CryptoPluginInfo::supportedSignaturePaddings() const
{
    return m_data->m_supportedSignaturePaddings;
}

QMap<Key::Algorithm, Key::Digests>
CryptoPluginInfo::supportedDigests() const
{
    return m_data->m_supportedDigests;
}

QMap<Key::Algorithm, Key::Operations>
CryptoPluginInfo::supportedOperations() const
{
    return m_data->m_supportedOperations;
}

void CryptoPluginInfo::setName(
        const QString &name)
{
    m_data->m_pluginName = name;
}

void CryptoPluginInfo::setCanStoreKeys(
        bool v)
{
    m_data->m_canStoreKeys = v;
}

void CryptoPluginInfo::setEncryptionType(
        CryptoPlugin::EncryptionType type)
{
    m_data->m_encryptionType = type;
}

void CryptoPluginInfo::setSupportedAlgorithms(
        const QVector<Key::Algorithm> &algorithms)
{
    m_data->m_supportedAlgorithms = algorithms;
}

void CryptoPluginInfo::setSupportedBlockModes(
        const QMap<Key::Algorithm, Key::BlockModes> &modes)
{
    m_data->m_supportedBlockModes = modes;
}

void CryptoPluginInfo::setSupportedEncryptionPaddings(
        const QMap<Key::Algorithm, Key::EncryptionPaddings> &paddings)
{
    m_data->m_supportedEncryptionPaddings = paddings;
}

void CryptoPluginInfo::setSupportedSignaturePaddings(
        const QMap<Key::Algorithm, Key::SignaturePaddings> &paddings)
{
    m_data->m_supportedSignaturePaddings = paddings;
}

void CryptoPluginInfo::setSupportedDigests(
        const QMap<Key::Algorithm, Key::Digests> &digests)
{
    m_data->m_supportedDigests = digests;
}

void CryptoPluginInfo::setSupportedOperations(
        const QMap<Key::Algorithm, Key::Operations> &operations)
{
    m_data->m_supportedOperations = operations;
}

//---------------------------------------------

CryptoPlugin::CryptoPlugin()
{
}

CryptoPlugin::~CryptoPlugin()
{
}
