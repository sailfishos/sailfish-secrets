/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_CRYPTOMANAGER_P_H
#define LIBSAILFISHCRYPTO_CRYPTOMANAGER_P_H

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptodaemonconnection.h"

#include <QtDBus/QDBusInterface>
#include <QtCore/QObject>

namespace Sailfish {

namespace Crypto {

// may not need to be QObject, if we don't need to emit signals etc
class CryptoManagerPrivate : public QObject
{
    Q_OBJECT

public:
    CryptoManagerPrivate(CryptoManager *parent = Q_NULLPTR);
    ~CryptoManagerPrivate();

private:
    friend class CryptoManager;
    Sailfish::Crypto::CryptoManager *m_parent;
    Sailfish::Crypto::CryptoDaemonConnection *m_crypto;
    QDBusInterface *m_interface;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_CRYPTOMANAGER_P_H
