/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_LOCKCODEREQUEST_P_H
#define LIBSAILFISHCRYPTO_LOCKCODEREQUEST_P_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/lockcoderequest.h"
#include "Crypto/cryptomanager.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Crypto {

class LockCodeRequestPrivate
{
    Q_DISABLE_COPY(LockCodeRequestPrivate)

public:
    explicit LockCodeRequestPrivate();

    QPointer<Sailfish::Crypto::CryptoManager> m_manager;
    Sailfish::Crypto::LockCodeRequest::LockStatus m_lockStatus;
    QVariantMap m_customParameters;
    Sailfish::Crypto::LockCodeRequest::LockCodeRequestType m_lockCodeRequestType;
    Sailfish::Crypto::LockCodeRequest::LockCodeTargetType m_lockCodeTargetType;
    Sailfish::Crypto::InteractionParameters m_interactionParameters;
    QString m_lockCodeTarget;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Crypto::Request::Status m_status;
    Sailfish::Crypto::Result m_result;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_LOCKCODEREQUEST_P_H
