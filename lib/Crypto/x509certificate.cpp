/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/x509certificate.h"
#include "Crypto/certificate_p.h"

namespace Sailfish {
    namespace Crypto {
        /*!
         * \internal
         */
        class X509CertificateData : public Sailfish::Crypto::CertificateData
        {
        public:
            X509CertificateData() : Sailfish::Crypto::CertificateData(Sailfish::Crypto::Certificate::X509) {}
            ~X509CertificateData() {}
            Sailfish::Crypto::CertificateData *clone() const {
                Sailfish::Crypto::X509CertificateData *retn = new Sailfish::Crypto::X509CertificateData;
                retn->tbsCertificate = this->tbsCertificate;
                retn->signatureAlgorithm = this->signatureAlgorithm;
                retn->signatureValue = this->signatureValue;
                return retn;
            }
            bool equals(const X509CertificateData * const other) const {
                return tbsCertificate == other->tbsCertificate
                        && signatureAlgorithm == other->signatureAlgorithm
                        && signatureValue == other->signatureValue;
            }
            bool equals(const CertificateData * const other) const {
                return m_type == other->m_type
                        && equals(static_cast<const X509CertificateData * const>(other));
            }
            Sailfish::Crypto::X509Certificate::TbsCertificate tbsCertificate;
            Sailfish::Crypto::X509Certificate::AlgorithmIdentifier signatureAlgorithm;
            QByteArray signatureValue;

            static X509CertificateData *clone(const X509CertificateData &other) {
                X509CertificateData *retn = new X509CertificateData;
                retn->tbsCertificate = other.tbsCertificate;
                retn->signatureAlgorithm = other.signatureAlgorithm;
                retn->signatureValue = other.signatureValue;
                return retn;
            }
        };
    }
}

namespace {
    /*!
     * \brief internal
     */
    Sailfish::Crypto::X509CertificateData *d_ptr(Sailfish::Crypto::CertificateData *data)
    {
        return static_cast<Sailfish::Crypto::X509CertificateData*>(data);
    }

    /*!
     * \brief internal
     */
    const Sailfish::Crypto::X509CertificateData *const_d_ptr(const Sailfish::Crypto::CertificateData *data)
    {
        return static_cast<const Sailfish::Crypto::X509CertificateData*>(data);
    }
}

/*!
 * \brief Returns an X509 certificate populated from the data contained in the given \a certificate.
 *
 * This creates a deep-copy of the underlying data.
 */
Sailfish::Crypto::X509Certificate
Sailfish::Crypto::X509Certificate::fromCertificate(
        const Sailfish::Crypto::Certificate &certificate)
{
    if (certificate.type() == Sailfish::Crypto::Certificate::X509) {
        //return Sailfish::Crypto::X509Certificate(certificate);
        return Sailfish::Crypto::X509Certificate(
                    Sailfish::Crypto::X509CertificateData::clone(
                        *(const_d_ptr(certificate.m_data))));
    } else {
        return Sailfish::Crypto::X509Certificate();
    }
}

/*!
 * \internal
 */
Sailfish::Crypto::X509Certificate::X509Certificate(Sailfish::Crypto::X509CertificateData *data)
    : Sailfish::Crypto::Certificate(data)
{
}

/*!
 * \internal
 */
Sailfish::Crypto::X509Certificate::X509Certificate(const Sailfish::Crypto::Certificate &certificate)
    : Sailfish::Crypto::Certificate(Sailfish::Crypto::X509CertificateData::clone(*(const_d_ptr(certificate.m_data))))
{
}

/*!
 * \brief Constructs an X509 certificate
 */
Sailfish::Crypto::X509Certificate::X509Certificate()
    : Sailfish::Crypto::Certificate(new Sailfish::Crypto::X509CertificateData)
{
}

/*!
 * \brief Constructs an X509 certificate populated from the data contained in the \a other X509 certificate.
 *
 * This creates a deep-copy of the underlying data.
 */
Sailfish::Crypto::X509Certificate::X509Certificate(const Sailfish::Crypto::X509Certificate &other)
    : Sailfish::Crypto::Certificate(Sailfish::Crypto::X509CertificateData::clone(*(const_d_ptr(other.m_data))))
{
}

/*!
 * \brief Destroys the X509 certificate
 */
Sailfish::Crypto::X509Certificate::~X509Certificate()
{
    // base class deletes m_data.
}

/*!
 * \brief Returns the subject's public key data contained within the X509 certificate
 */
QByteArray Sailfish::Crypto::X509Certificate::publicKey() const
{
    return const_d_ptr(m_data)->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey;
}

/*!
 * \brief Encodes the X509 certificate into a byte array with the specified \a encoding format
 */
QByteArray Sailfish::Crypto::X509Certificate::toEncoded(Sailfish::Crypto::Certificate::Encoding encoding) const
{
    // TODO!
    Q_UNUSED(encoding);
    return QByteArray();
}

/*!
 * \brief Returns the TbsCertificate section of the X509 certificate, as per RFC5280
 */
Sailfish::Crypto::X509Certificate::TbsCertificate
Sailfish::Crypto::X509Certificate::tbsCertificate() const
{
    return const_d_ptr(m_data)->tbsCertificate;
}

/*!
 * \brief Sets the TbsCertificate section of the X509 certificate to \a certificate
 */
void Sailfish::Crypto::X509Certificate::setTbsCertificate(
        const Sailfish::Crypto::X509Certificate::TbsCertificate &certificate)
{
    d_ptr(m_data)->tbsCertificate = certificate;
}

/*!
 * \brief Returns the identifier for the cryptographic algorithm used by the certificate authority to sign this certificate, as per RFC5280
 */
Sailfish::Crypto::X509Certificate::AlgorithmIdentifier
Sailfish::Crypto::X509Certificate::signatureAlgorithm() const
{
    return const_d_ptr(m_data)->signatureAlgorithm;
}

/*!
 * \brief Sets the signature of the algorithm used by the CA to sign the certificate to the given \a algorithm
 */
void Sailfish::Crypto::X509Certificate::setSignatureAlgorithm(
        const Sailfish::Crypto::X509Certificate::AlgorithmIdentifier &algorithm)
{
    d_ptr(m_data)->signatureAlgorithm = algorithm;
}

/*!
 * \brief Returns the signature value of the certificate, as per RFC5280
 */
QByteArray Sailfish::Crypto::X509Certificate::signatureValue() const
{
    return const_d_ptr(m_data)->signatureValue;
}

/*!
 * \brief Sets the signature value of the certificate to \a signature, as per RFC5280
 */
void Sailfish::Crypto::X509Certificate::setSignatureValue(const QByteArray &signature)
{
    d_ptr(m_data)->signatureValue = signature;
}
