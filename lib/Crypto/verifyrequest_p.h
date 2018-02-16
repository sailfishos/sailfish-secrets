/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_VERIFYREQUEST_P_H
#define LIBSAILFISHCRYPTO_VERIFYREQUEST_P_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/verifyrequest.h"
#include "Crypto/cryptomanager.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Crypto {

class VerifyRequestPrivate
{
    Q_DISABLE_COPY(VerifyRequestPrivate)

public:
    explicit VerifyRequestPrivate();

    QPointer<Sailfish::Crypto::CryptoManager> m_manager;
    QByteArray m_data;
    Sailfish::Crypto::Key m_key;
    Sailfish::Crypto::Key::SignaturePadding m_padding;
    Sailfish::Crypto::Key::Digest m_digest;
    QString m_cryptoPluginName;
    bool m_verified;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Crypto::Request::Status m_status;
    Sailfish::Crypto::Result m_result;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_VERIFYREQUEST_P_H
