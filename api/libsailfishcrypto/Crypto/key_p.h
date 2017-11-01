/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_KEY_P_H
#define LIBSAILFISHCRYPTO_KEY_P_H

#include "Crypto/key.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QHash>
#include <QtCore/QDateTime>

namespace Sailfish {

namespace Crypto {

class KeyData
{
public:
    KeyData();
    KeyData(const KeyData &other);
    KeyData &operator=(const KeyData &other);

    bool identical(const Sailfish::Crypto::KeyData &other) const;
    bool keysEqual(const Sailfish::Crypto::KeyData &other) const;
    bool lessThan(const Sailfish::Crypto::KeyData &other) const;

    QVector<QByteArray> m_customParameters;
    QByteArray m_publicKey;
    QByteArray m_privateKey;
    QByteArray m_secretKey;
    QDateTime m_validityStart;
    QDateTime m_validityEnd;

    Sailfish::Crypto::Key::Identifier m_identifier;

    Sailfish::Crypto::Key::Origin m_origin;
    Sailfish::Crypto::Key::Algorithm m_algorithm;

    Sailfish::Crypto::Key::BlockModes m_blockModes;
    Sailfish::Crypto::Key::EncryptionPaddings m_encryptionPaddings;
    Sailfish::Crypto::Key::SignaturePaddings m_signaturePaddings;
    Sailfish::Crypto::Key::Digests m_digests;
    Sailfish::Crypto::Key::Operations m_operations;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_KEY_P_H
