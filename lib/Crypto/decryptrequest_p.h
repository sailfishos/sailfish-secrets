/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_DECRYPTREQUEST_P_H
#define LIBSAILFISHCRYPTO_DECRYPTREQUEST_P_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/decryptrequest.h"
#include "Crypto/cryptomanager.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Crypto {

class DecryptRequestPrivate
{
    Q_DISABLE_COPY(DecryptRequestPrivate)

public:
    explicit DecryptRequestPrivate();

    QPointer<Sailfish::Crypto::CryptoManager> m_manager;
    QByteArray m_data;
    QByteArray m_initialisationVector;
    Sailfish::Crypto::Key m_key;
    Sailfish::Crypto::CryptoManager::BlockMode m_blockMode;
    Sailfish::Crypto::CryptoManager::EncryptionPadding m_padding;
    QString m_cryptoPluginName;
    QByteArray m_plaintext;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Crypto::Request::Status m_status;
    Sailfish::Crypto::Result m_result;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_DECRYPTREQUEST_P_H
