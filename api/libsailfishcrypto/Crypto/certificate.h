/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_CERTIFICATE_H
#define LIBSAILFISHCRYPTO_CERTIFICATE_H

#include "Crypto/cryptoglobal.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QHash>
#include <QtCore/QVariantMap>

#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusMetaType>

namespace Sailfish {

namespace Crypto {

class CertificateData;
class X509Certificate;

class SAILFISH_CRYPTO_API Certificate
{
public:
    enum Type {
        Invalid = 0,
        X509,
        OpenPGP,
        Spki,
        Sdsi,
        Cvc
    };

    enum Encoding {
        Unknown = 0,
        BasicEncodingRules,
        CanonicalEncodingRules,
        DistinguishedEncodingRules,
        XmlEncodingRules,
        ExtendedXmlEncodingRules,
        PackedEncodingRules,
        UnalignedPackedEncodingRules,
        CanonicalPackedEncodingRules,
        GenericStringEncodingRules
    };

    Certificate();
    Certificate(const Certificate &other);
    virtual ~Certificate();

    Certificate &operator=(const Certificate &other);

    Certificate::Type type() const;
    virtual QByteArray publicKey() const;
    virtual QByteArray toEncoded(Encoding encoding = DistinguishedEncodingRules) const;
    static Certificate fromEncoded(const QByteArray &encoded, Type type = X509, Encoding encoding = DistinguishedEncodingRules);

protected:
    friend class X509Certificate;
    Certificate(CertificateData *data);
    CertificateData *m_data;
};

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Certificate &certificate) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Certificate &certificate) SAILFISH_CRYPTO_API;

} // namespace Crypto

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::Certificate)
Q_DECLARE_METATYPE(QVector<Sailfish::Crypto::Certificate>)

#endif // LIBSAILFISHCRYPTO_CERTIFICATE_H
