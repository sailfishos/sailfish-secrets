/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_GENERATEKEYREQUEST_P_H
#define LIBSAILFISHCRYPTO_GENERATEKEYREQUEST_P_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/generatekeyrequest.h"
#include "Crypto/cryptomanager.h"
#include "Crypto/keyderivationparameters.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Crypto {

class GenerateKeyRequestPrivate
{
    Q_DISABLE_COPY(GenerateKeyRequestPrivate)

public:
    explicit GenerateKeyRequestPrivate();

    QPointer<Sailfish::Crypto::CryptoManager> m_manager;
    QString m_cryptoPluginName;
    Sailfish::Crypto::KeyDerivationParameters m_skdfParams;
    Sailfish::Crypto::Key m_keyTemplate;
    Sailfish::Crypto::Key m_generatedKey;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Crypto::Request::Status m_status;
    Sailfish::Crypto::Result m_result;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_GENERATEKEYREQUEST_P_H
