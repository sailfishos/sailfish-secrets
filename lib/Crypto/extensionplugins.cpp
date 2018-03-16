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

CryptoPluginInfoPrivate::CryptoPluginInfoPrivate()
    : QSharedData()
    , m_pluginName(QLatin1String("org.sailfishos.crypto.cryptoplugin.invalid"))
    , m_canStoreKeys(false)
{
}

CryptoPluginInfoPrivate::CryptoPluginInfoPrivate(const CryptoPluginInfoPrivate &other)
    : QSharedData(other)
    , m_pluginName(other.m_pluginName)
    , m_canStoreKeys(other.m_canStoreKeys)
    , m_encryptionType(other.m_encryptionType)
    , m_supportedAlgorithms(other.m_supportedAlgorithms)
    , m_supportedBlockModes(other.m_supportedBlockModes)
    , m_supportedEncryptionPaddings(other.m_supportedEncryptionPaddings)
    , m_supportedSignaturePaddings(other.m_supportedSignaturePaddings)
    , m_supportedDigests(other.m_supportedDigests)
    , m_supportedOperations(other.m_supportedOperations)
{
}

CryptoPluginInfoPrivate::CryptoPluginInfoPrivate(
        const QString &pluginName,
        bool canStoreKeys,
        CryptoPlugin::EncryptionType encryptionType,
        const QVector<CryptoManager::Algorithm> &supportedAlgorithms,
        const QMap<CryptoManager::Algorithm, QVector<CryptoManager::BlockMode> > &supportedBlockModes,
        const QMap<CryptoManager::Algorithm, QVector<CryptoManager::EncryptionPadding> > &supportedEncryptionPaddings,
        const QMap<CryptoManager::Algorithm, QVector<CryptoManager::SignaturePadding> > &supportedSignaturePaddings,
        const QMap<CryptoManager::Algorithm, QVector<CryptoManager::DigestFunction> > &supportedDigests,
        const QMap<CryptoManager::Algorithm, CryptoManager::Operations> &supportedOperations)
    : QSharedData()
    , m_pluginName(pluginName)
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

CryptoPluginInfoPrivate::~CryptoPluginInfoPrivate()
{
}

CryptoPluginInfo::CryptoPluginInfo()
    : d_ptr(new CryptoPluginInfoPrivate)
{
}

CryptoPluginInfo::CryptoPluginInfo(
        CryptoPlugin *plugin)
    : d_ptr(new CryptoPluginInfoPrivate(
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

CryptoPluginInfo::CryptoPluginInfo(
        const CryptoPluginInfo &other)
    : d_ptr(other.d_ptr)
{
}

CryptoPluginInfo::~CryptoPluginInfo()
{
}

CryptoPluginInfo& CryptoPluginInfo::operator=(
        const CryptoPluginInfo &other)
{
    d_ptr = other.d_ptr;
    return *this;
}

QString CryptoPluginInfo::name() const
{
    return d_ptr->m_pluginName;
}

bool CryptoPluginInfo::canStoreKeys() const
{
    return d_ptr->m_canStoreKeys;
}

CryptoPlugin::EncryptionType
CryptoPluginInfo::encryptionType() const
{
    return d_ptr->m_encryptionType;
}

QVector<CryptoManager::Algorithm>
CryptoPluginInfo::supportedAlgorithms() const
{
    return d_ptr->m_supportedAlgorithms;
}

QMap<CryptoManager::Algorithm, QVector<CryptoManager::BlockMode> >
CryptoPluginInfo::supportedBlockModes() const
{
    return d_ptr->m_supportedBlockModes;
}

QMap<CryptoManager::Algorithm, QVector<CryptoManager::EncryptionPadding> >
CryptoPluginInfo::supportedEncryptionPaddings() const
{
    return d_ptr->m_supportedEncryptionPaddings;
}

QMap<CryptoManager::Algorithm, QVector<CryptoManager::SignaturePadding> >
CryptoPluginInfo::supportedSignaturePaddings() const
{
    return d_ptr->m_supportedSignaturePaddings;
}

QMap<CryptoManager::Algorithm, QVector<CryptoManager::DigestFunction> >
CryptoPluginInfo::supportedDigests() const
{
    return d_ptr->m_supportedDigests;
}

QMap<CryptoManager::Algorithm, CryptoManager::Operations>
CryptoPluginInfo::supportedOperations() const
{
    return d_ptr->m_supportedOperations;
}

void CryptoPluginInfo::setName(
        const QString &name)
{
    d_ptr->m_pluginName = name;
}

void CryptoPluginInfo::setCanStoreKeys(
        bool v)
{
    d_ptr->m_canStoreKeys = v;
}

void CryptoPluginInfo::setEncryptionType(
        CryptoPlugin::EncryptionType type)
{
    d_ptr->m_encryptionType = type;
}

void CryptoPluginInfo::setSupportedAlgorithms(
        const QVector<CryptoManager::Algorithm> &algorithms)
{
    d_ptr->m_supportedAlgorithms = algorithms;
}

void CryptoPluginInfo::setSupportedBlockModes(
        const QMap<CryptoManager::Algorithm, QVector<CryptoManager::BlockMode> > &modes)
{
    d_ptr->m_supportedBlockModes = modes;
}

void CryptoPluginInfo::setSupportedEncryptionPaddings(
        const QMap<CryptoManager::Algorithm, QVector<CryptoManager::EncryptionPadding> > &paddings)
{
    d_ptr->m_supportedEncryptionPaddings = paddings;
}

void CryptoPluginInfo::setSupportedSignaturePaddings(
        const QMap<CryptoManager::Algorithm, QVector<CryptoManager::SignaturePadding> > &paddings)
{
    d_ptr->m_supportedSignaturePaddings = paddings;
}

void CryptoPluginInfo::setSupportedDigests(
        const QMap<CryptoManager::Algorithm, QVector<CryptoManager::DigestFunction> > &digests)
{
    d_ptr->m_supportedDigests = digests;
}

void CryptoPluginInfo::setSupportedOperations(
        const QMap<CryptoManager::Algorithm, CryptoManager::Operations> &operations)
{
    d_ptr->m_supportedOperations = operations;
}

//---------------------------------------------

CryptoPlugin::CryptoPlugin()
{
}

CryptoPlugin::~CryptoPlugin()
{
}

bool CryptoPlugin::supportsLocking() const
{
    return false;
}

bool CryptoPlugin::isLocked() const
{
    return false;
}

bool CryptoPlugin::lock()
{
    return false;
}

bool CryptoPlugin::unlock(const QByteArray &)
{
    return false;
}

bool CryptoPlugin::setLockCode(const QByteArray &, const QByteArray &)
{
    return false;
}
