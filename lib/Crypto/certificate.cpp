/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/certificate.h"
#include "Crypto/certificate_p.h"

Sailfish::Crypto::CertificateData::CertificateData()
    : m_type(Sailfish::Crypto::Certificate::Invalid)
{
}

Sailfish::Crypto::CertificateData::CertificateData(Certificate::Type type)
    : m_type(type)
{
}

Sailfish::Crypto::CertificateData::~CertificateData()
{
}

Sailfish::Crypto::Certificate::Certificate()
    : m_data(nullptr)
{
}

Sailfish::Crypto::Certificate::Certificate(Sailfish::Crypto::CertificateData *data)
    : m_data(data)
{
}


Sailfish::Crypto::Certificate::Certificate(const Sailfish::Crypto::Certificate &other)
    : m_data(other.m_data ? other.m_data->clone() : Q_NULLPTR)
{
}

Sailfish::Crypto::Certificate::~Certificate()
{
    delete m_data;
}

Sailfish::Crypto::Certificate &Sailfish::Crypto::Certificate::operator=(const Sailfish::Crypto::Certificate &other)
{
    if (this != &other) {
        delete m_data;
        if (other.m_data) {
            m_data = other.m_data->clone();
        } else {
            m_data = Q_NULLPTR;
        }
    }

    return *this;
}

Sailfish::Crypto::Certificate::Type Sailfish::Crypto::Certificate::type() const
{
    return m_data ? m_data->m_type : Sailfish::Crypto::Certificate::Invalid;
}

QByteArray Sailfish::Crypto::Certificate::publicKey() const
{
    // the default implementation always returns an invalid byte array.
    return QByteArray();
}

QByteArray Sailfish::Crypto::Certificate::toEncoded(Sailfish::Crypto::Certificate::Encoding encoding) const
{
    // the default implementation always returns an invalid byte array.
    Q_UNUSED(encoding);
    return QByteArray();
}

Sailfish::Crypto::Certificate
Sailfish::Crypto::Certificate::fromEncoded(
        const QByteArray &encoded,
        Sailfish::Crypto::Certificate::Type type,
        Sailfish::Crypto::Certificate::Encoding encoding)
{
    // TODO: parse the encoded certificate, return the constructed certificate of the appropriate type.
    Q_UNUSED(encoded);
    Q_UNUSED(type);
    Q_UNUSED(encoding);
    return Sailfish::Crypto::Certificate();
}
