/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_INTERACTIONRESPONSE_H
#define LIBSAILFISHSECRETS_INTERACTIONRESPONSE_H

#include "Secrets/secretsglobal.h"
#include "Secrets/result.h"

#include <QtCore/QByteArray>
#include <QtCore/QSharedDataPointer>
#include <QtCore/QMetaType>

namespace Sailfish {

namespace Secrets {

class InteractionResponsePrivate;
class SAILFISH_SECRETS_API InteractionResponse {
public:
    InteractionResponse();
    InteractionResponse(const InteractionResponse &other);
    ~InteractionResponse();
    InteractionResponse& operator=(const InteractionResponse &other);
    bool operator==(const InteractionResponse &other) const;
    bool operator!=(const InteractionResponse &other) const {
        return !operator==(other);
    }

    Sailfish::Secrets::Result result() const;
    void setResult(const Sailfish::Secrets::Result &result);

    QByteArray responseData() const;
    void setResponseData(const QByteArray &data);

private:
    QSharedDataPointer<InteractionResponsePrivate> d_ptr;
};

} // Secrets

} // Sailfish

Q_DECLARE_METATYPE(Sailfish::Secrets::InteractionResponse);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::InteractionResponse, Q_MOVABLE_TYPE);

#endif // LIBSAILFISHSECRETS_INTERACTIONRESPONSE_H

