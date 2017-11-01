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

namespace Sailfish {

namespace Crypto {

class CryptoPluginInfoData
{
public:
    CryptoPluginInfoData();
    CryptoPluginInfoData(
            const QString &pluginName,
            bool canStoreKeys,
            Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType,
            const QVector<Sailfish::Crypto::Key::Algorithm> &supportedAlgorithms,
            const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> &supportedBlockModes,
            const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> &supportedEncryptionPaddings,
            const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> &supportedSignaturePaddings,
            const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> &supportedDigests,
            const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> &supportedOperations);

    QString m_pluginName;
    bool m_canStoreKeys;
    Sailfish::Crypto::CryptoPlugin::EncryptionType m_encryptionType;
    QVector<Sailfish::Crypto::Key::Algorithm> m_supportedAlgorithms;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> m_supportedBlockModes;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> m_supportedEncryptionPaddings;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> m_supportedSignaturePaddings;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> m_supportedDigests;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> m_supportedOperations;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_EXTENSIONPLUGINS_P_H
