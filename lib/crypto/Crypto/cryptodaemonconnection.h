/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_CRYPTODAEMONCONNECTION_H
#define LIBSAILFISHCRYPTO_CRYPTODAEMONCONNECTION_H

#include "Crypto/cryptoglobal.h"

#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QAtomicInt>
#include <QtCore/QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(lcSailfishCryptoDaemonConnection)

namespace Sailfish {

namespace Crypto {

class CryptoDaemonConnectionPrivate;
class SAILFISH_CRYPTO_API CryptoDaemonConnection : public QObject
{
    Q_OBJECT

public:
    static CryptoDaemonConnection *instance();
    static void releaseInstance();

    bool connect();
    QDBusConnection *connection();
    QDBusInterface *createApiInterface(const QString &objectPath,
                                       const QString &interface,
                                       QObject *parent = Q_NULLPTR);

    static void registerDBusTypes();

signals:
    void disconnected();

private:
    Q_DISABLE_COPY(CryptoDaemonConnection)
    CryptoDaemonConnection();
    CryptoDaemonConnectionPrivate *m_data;
    QAtomicInt m_refCount;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_CRYPTODAEMONCONNECTION_H
