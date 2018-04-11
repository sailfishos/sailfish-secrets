/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_IMPORTKEYREQUEST_P_H
#define LIBSAILFISHCRYPTO_IMPORTKEYREQUEST_P_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/importkeyrequest.h"
#include "Crypto/cryptomanager.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Crypto {

class ImportKeyRequestPrivate
{
    Q_DISABLE_COPY(ImportKeyRequestPrivate)

public:
    explicit ImportKeyRequestPrivate();

    QPointer<Sailfish::Crypto::CryptoManager> m_manager;
    QString m_cryptoPluginName;
    Sailfish::Crypto::InteractionParameters m_uiParams;
    Sailfish::Crypto::Key m_key;
    Sailfish::Crypto::Key m_importedKey;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Crypto::Request::Status m_status;
    Sailfish::Crypto::Result m_result;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_GENERATEKEYREQUEST_P_H
