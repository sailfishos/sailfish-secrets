/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_STOREDKEYIDENTIFIERSREQUEST_P_H
#define LIBSAILFISHCRYPTO_STOREDKEYIDENTIFIERSREQUEST_P_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/storedkeyidentifiersrequest.h"
#include "Crypto/cryptomanager.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Crypto {

class StoredKeyIdentifiersRequestPrivate
{
    Q_DISABLE_COPY(StoredKeyIdentifiersRequestPrivate)

public:
    explicit StoredKeyIdentifiersRequestPrivate();

    QPointer<Sailfish::Crypto::CryptoManager> m_manager;
    QVariantMap m_customParameters;
    QVector<Sailfish::Crypto::Key::Identifier> m_identifiers;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Crypto::Request::Status m_status;
    Sailfish::Crypto::Result m_result;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_STOREDKEYIDENTIFIERSREQUEST_P_H
