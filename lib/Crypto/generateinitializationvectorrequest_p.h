/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Bea Lam <bea.lam@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_GENERATEDINITIALIZATIONVECTORREQUEST_P_H
#define LIBSAILFISHCRYPTO_GENERATEDINITIALIZATIONVECTORREQUEST_P_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/generateinitializationvectorrequest.h"
#include "Crypto/cryptomanager.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>
#include <QtCore/QQueue>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Crypto {

class GenerateInitializationVectorRequestPrivate
{
    Q_DISABLE_COPY(GenerateInitializationVectorRequestPrivate)

public:
    explicit GenerateInitializationVectorRequestPrivate();

    QPointer<Sailfish::Crypto::CryptoManager> m_manager;
    QScopedPointer<QDBusPendingCallWatcher> m_watcher;

    QByteArray m_generatedIv;
    QString m_cryptoPluginName;
    Sailfish::Crypto::CryptoManager::Algorithm m_algorithm;
    Sailfish::Crypto::CryptoManager::BlockMode m_blockMode;
    int m_keySize;

    Sailfish::Crypto::Request::Status m_status;
    Sailfish::Crypto::Result m_result;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_GENERATEDINITIALIZATIONVECTORREQUEST_P_H
