/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_X509CERTIFICATE_H
#define LIBSAILFISHCRYPTO_X509CERTIFICATE_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/certificate.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QHash>
#include <QtCore/QVariantMap>
#include <QtCore/QDateTime>

namespace Sailfish {

namespace Crypto {

// Represents an X509 Certificate as per RFC5280
// TODO: do this properly, currently this is prototype only!
class X509CertificateData;
class SAILFISH_CRYPTO_API X509Certificate : public Sailfish::Crypto::Certificate
{
public:
    ~X509Certificate();
    X509Certificate();
    X509Certificate(const Sailfish::Crypto::X509Certificate &other);
    static X509Certificate fromCertificate(const Sailfish::Crypto::Certificate &certificate);

    QByteArray publicKey() const Q_DECL_OVERRIDE;
    QByteArray toEncoded(Encoding encoding = DistinguishedEncodingRules) const Q_DECL_OVERRIDE;

    struct AlgorithmIdentifier
    {
        AlgorithmIdentifier(const QString &algo = QString(), const QVariantMap &params = QVariantMap())
            : algorithm(algo), parameters(params) {}
        AlgorithmIdentifier(const AlgorithmIdentifier &other)
            : algorithm(other.algorithm), parameters(other.parameters) {}
        QString algorithm;
        QVariantMap parameters;
    };

    struct TbsCertificate
    {
        struct RelativeDistinguishedName
        {
            RelativeDistinguishedName(const QString &t = QString(), const QString &v = QString())
                : type(t), value(v) {}
            RelativeDistinguishedName(const RelativeDistinguishedName &other)
                : type(other.type), value(other.value) {}
            QString type;
            QString value;
        };

        struct EntityName
        {
            EntityName(const QString &commonName,
                       const QString &organizationalUnit = QString(),
                       const QString &organization = QString(),
                       const QString &locality = QString(),
                       const QString &stateOrProvince = QString(),
                       const QString &country = QString(),
                       const QString &qualifier = QString(),
                       const QString &serialNumber = QString()) {
                if (!commonName.isEmpty())
                    relativeDistinguishedNames.append(RelativeDistinguishedName(QLatin1String("CN"), commonName));
                if (!organizationalUnit.isEmpty())
                    relativeDistinguishedNames.append(RelativeDistinguishedName(QLatin1String("OU"), organizationalUnit));
                if (!organization.isEmpty())
                    relativeDistinguishedNames.append(RelativeDistinguishedName(QLatin1String("O"), organization));
                if (!locality.isEmpty())
                    relativeDistinguishedNames.append(RelativeDistinguishedName(QLatin1String("L"), locality));
                if (!stateOrProvince.isEmpty())
                    relativeDistinguishedNames.append(RelativeDistinguishedName(QLatin1String("S"), stateOrProvince));
                if (!country.isEmpty())
                    relativeDistinguishedNames.append(RelativeDistinguishedName(QLatin1String("C"), country));
                if (!qualifier.isEmpty())
                    relativeDistinguishedNames.append(RelativeDistinguishedName(QLatin1String("DNQualifier"), qualifier));
                if (!serialNumber.isEmpty())
                    relativeDistinguishedNames.append(RelativeDistinguishedName(QLatin1String("SerialNumber"), serialNumber));
            }
            EntityName(const QVector<RelativeDistinguishedName> rdns = QVector<RelativeDistinguishedName>())
                : relativeDistinguishedNames(rdns) {}
            EntityName(const EntityName &other)
                : relativeDistinguishedNames(other.relativeDistinguishedNames) {}
            QVector<RelativeDistinguishedName> relativeDistinguishedNames;
        };

        struct Validity
        {
            Validity(const QDateTime &nb = QDateTime(), const QDateTime &na = QDateTime())
                : notBefore(nb), notAfter(na) {}
            Validity(const Validity &other)
                : notBefore(other.notBefore), notAfter(other.notAfter) {}
            QDateTime notBefore;
            QDateTime notAfter;
        };

        struct SubjectPublicKeyInfo
        {
            SubjectPublicKeyInfo(const AlgorithmIdentifier &algo = AlgorithmIdentifier(), const QByteArray &key = QByteArray())
                : algorithm(algo), subjectPublicKey(key) {}
            SubjectPublicKeyInfo(const SubjectPublicKeyInfo &other)
                : algorithm(other.algorithm), subjectPublicKey(other.subjectPublicKey) {}
            AlgorithmIdentifier algorithm;
            QByteArray subjectPublicKey;
        };

        struct Extension
        {
            Extension() : critical(false) {}
            Extension(const QString &exId, bool crit, const QString &exVal)
                : extnID(exId), critical(crit), extnValue(exVal) {}
            Extension(const Extension &other)
                : extnID(other.extnID), critical(other.critical), extnValue(other.extnValue) {}
            QString extnID;
            bool critical;
            QString extnValue;
        };

        TbsCertificate() {}
        TbsCertificate(const TbsCertificate &other)
            : version(other.version)
            , serialNumber(other.serialNumber)
            , signature(other.signature)
            , issuer(other.issuer)
            , validity(other.validity)
            , subject(other.subject)
            , subjectPublicKeyInfo(other.subjectPublicKeyInfo)
            , issuerUniqueID(other.issuerUniqueID)
            , subjectUniqueID(other.subjectUniqueID)
            , extensions(other.extensions) {}

        QString version;
        QString serialNumber; // an integer, expressed as separated-octet string
        AlgorithmIdentifier signature;
        EntityName issuer;
        Validity validity;
        EntityName subject;
        SubjectPublicKeyInfo subjectPublicKeyInfo;
        QString issuerUniqueID;
        QString subjectUniqueID;
        QVector<Extension> extensions;
    };

    TbsCertificate tbsCertificate() const;
    void setTbsCertificate(const TbsCertificate &certificate);

    AlgorithmIdentifier signatureAlgorithm() const;
    void setSignatureAlgorithm(const AlgorithmIdentifier &algorithm);

    QByteArray signatureValue() const;
    void setSignatureValue(const QByteArray &signature);

private:
    explicit X509Certificate(const Sailfish::Crypto::Certificate &certificate);
    explicit X509Certificate(Sailfish::Crypto::X509CertificateData *data);
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_X509CERTIFICATE_H
