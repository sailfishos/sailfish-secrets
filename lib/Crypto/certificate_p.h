/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_CERTIFICATE_P_H
#define LIBSAILFISHCRYPTO_CERTIFICATE_P_H

#include "Crypto/certificate.h"

namespace Sailfish {

namespace Crypto {

// exists solely so that Certificate-derived types can store arbitrary data
class CertificateData
{
public:
    CertificateData();
    CertificateData(Certificate::Type type);
    virtual ~CertificateData();
    virtual CertificateData *clone() const = 0;
    Certificate::Type m_type;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_CERTIFICATE_H
