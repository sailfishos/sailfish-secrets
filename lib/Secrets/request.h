/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_REQUEST_H
#define LIBSAILFISHSECRETS_REQUEST_H

#include "Secrets/secretsglobal.h"
#include "Secrets/result.h"

#include <QtCore/QObject>

namespace Sailfish {

namespace Secrets {

class SAILFISH_SECRETS_API Request : public QObject
{
    Q_OBJECT
    Q_PROPERTY(Request::Status status READ status NOTIFY statusChanged)
    Q_PROPERTY(Sailfish::Secrets::Result result READ result NOTIFY resultChanged)

public:
    enum Status {
        Inactive = 0,
        Active,
        Finished
    };

    Request(QObject *parent = Q_NULLPTR);
    virtual ~Request();
    virtual Sailfish::Secrets::Request::Status status() const = 0;
    virtual Sailfish::Secrets::Result result() const = 0;
    Q_INVOKABLE virtual void startRequest() = 0;
    Q_INVOKABLE virtual void waitForFinished() = 0;

Q_SIGNALS:
    void statusChanged();
    void resultChanged();
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_REQUEST_H
