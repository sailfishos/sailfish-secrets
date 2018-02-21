/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_EXTENSIONPLUGINS_P_H
#define LIBSAILFISHCRYPTO_EXTENSIONPLUGINS_P_H

#include "Crypto/key.h"
#include "Crypto/extensionplugins.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QMap>
#include <QtCore/QSharedData>

namespace Sailfish {

namespace Crypto {

class CryptoPluginInfoPrivate : public QSharedData
{
public:
    CryptoPluginInfoPrivate();
    CryptoPluginInfoPrivate(const CryptoPluginInfoPrivate &other);
    ~CryptoPluginInfoPrivate();

    CryptoPluginInfoPrivate(
            const QString &pluginName,
            bool canStoreKeys,
            Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType,
            const QVector<Sailfish::Crypto::CryptoManager::Algorithm> &supportedAlgorithms,
            const QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::BlockMode> > &supportedBlockModes,
            const QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::EncryptionPadding> > &supportedEncryptionPaddings,
            const QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::SignaturePadding> > &supportedSignaturePaddings,
            const QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::DigestFunction> > &supportedDigests,
            const QMap<Sailfish::Crypto::CryptoManager::Algorithm, Sailfish::Crypto::CryptoManager::Operations> &supportedOperations);

    QString m_pluginName;
    bool m_canStoreKeys;
    Sailfish::Crypto::CryptoPlugin::EncryptionType m_encryptionType;
    QVector<Sailfish::Crypto::CryptoManager::Algorithm> m_supportedAlgorithms;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::BlockMode> > m_supportedBlockModes;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::EncryptionPadding> > m_supportedEncryptionPaddings;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::SignaturePadding> > m_supportedSignaturePaddings;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::DigestFunction> > m_supportedDigests;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, Sailfish::Crypto::CryptoManager::Operations> m_supportedOperations;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_EXTENSIONPLUGINS_P_H
