/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_GENERATERANDOMDATAREQUEST_P_H
#define LIBSAILFISHCRYPTO_GENERATERANDOMDATAREQUEST_P_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/generatekeyrequest.h"
#include "Crypto/cryptomanager.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>
#include <QtCore/QByteArray>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Crypto {

class GenerateRandomDataRequestPrivate
{
    Q_DISABLE_COPY(GenerateRandomDataRequestPrivate)

public:
    explicit GenerateRandomDataRequestPrivate();

    QPointer<Sailfish::Crypto::CryptoManager> m_manager;
    QString m_cryptoPluginName;
    QString m_csprngEngineName;
    quint64 m_numberBytes;
    QByteArray m_generatedData;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Crypto::Request::Status m_status;
    Sailfish::Crypto::Result m_result;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_GENERATERANDOMDATAREQUEST_P_H
