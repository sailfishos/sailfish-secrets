/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_VALIDATECERTIFICATECHAINREQUEST_P_H
#define LIBSAILFISHCRYPTO_VALIDATECERTIFICATECHAINREQUEST_P_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/validatecertificatechainrequest.h"
#include "Crypto/cryptomanager.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Crypto {

class Certificate;

class ValidateCertificateChainRequestPrivate
{
    Q_DISABLE_COPY(ValidateCertificateChainRequestPrivate)

public:
    explicit ValidateCertificateChainRequestPrivate(Sailfish::Crypto::CryptoManager *manager);

    QPointer<Sailfish::Crypto::CryptoManager> m_manager;
    QString m_cryptoPluginName;
    QVector<Sailfish::Crypto::Certificate> m_certificateChain;
    bool m_validated;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Crypto::Request::Status m_status;
    Sailfish::Crypto::Result m_result;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_VALIDATECERTIFICATECHAINREQUEST_P_H
