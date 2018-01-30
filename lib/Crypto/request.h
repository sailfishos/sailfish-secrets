/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_REQUEST_H
#define LIBSAILFISHCRYPTO_REQUEST_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/result.h"

#include <QtCore/QObject>

namespace Sailfish {

namespace Crypto {

class SAILFISH_CRYPTO_API Request : public QObject
{
    Q_OBJECT
    Q_PROPERTY(Request::Status status READ status NOTIFY statusChanged)
    Q_PROPERTY(Sailfish::Crypto::Result result READ result NOTIFY resultChanged)

public:
    enum Status {
        Inactive = 0,
        Active,
        Finished
    };

    Request(QObject *parent = Q_NULLPTR);
    virtual ~Request();
    virtual Sailfish::Crypto::Request::Status status() const = 0;
    virtual Sailfish::Crypto::Result result() const = 0;
    Q_INVOKABLE virtual void startRequest() = 0;
    Q_INVOKABLE virtual void waitForFinished() = 0;

Q_SIGNALS:
    void statusChanged();
    void resultChanged();
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_REQUEST_H
