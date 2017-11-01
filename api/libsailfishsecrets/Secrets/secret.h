/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_SECRET_H
#define LIBSAILFISHSECRETS_SECRET_H

#include "Secrets/secretsglobal.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QHash>

namespace Sailfish {

namespace Secrets {

class SAILFISH_SECRETS_API Secret {
public:
    enum Type {
        Unknown,
        Blob,
        Password,
        Certificate,
        PrivateKey,
    };

    virtual ~Secret() {}
    Secret(const Secret &other) : m_data(other.m_data) {}
    Secret(const QByteArray &blob = QByteArray()) {
        m_data.append(typeString(Blob).toUtf8());
        if (blob.size()) {
            m_data.append(blob);
        }
    }

    bool operator==(const Secret &other) const {
        return m_data == other.m_data;
    }
    bool operator<(const Secret &other) const {
        return m_data < other.m_data;
    }

    Type type() const { return typeFromString(QString::fromUtf8(m_data.value(0))); }
    QVector<QByteArray> data() const {
        return m_data.size() > 1 ? m_data.mid(1) : QVector<QByteArray>();
    }
    QByteArray blob() const {
        return m_data.size() > 1 ? m_data[1] : QByteArray();
    }

    QByteArray toByteArray() const {
        QByteArray retn;
        for (auto d : m_data) {
            retn.append(d.toBase64(QByteArray::Base64UrlEncoding));
            retn.append(':');
        }
        retn.chop(1);
        return retn;
    }

    static Secret fromByteArray(const QByteArray &data) {
        // data must be a : separated list of base64url-encoded byte arrays
        Secret retn;
        retn.m_data.clear();
        const QList<QByteArray> split = data.split(':');
        for (auto s : split) {
            retn.m_data.append(QByteArray::fromBase64(s, QByteArray::Base64UrlEncoding));
        }
        return retn;
    }

protected:
    static QString typeString(Type type) {
        static QHash<Type, QString> typeToString {
            { Unknown,      QLatin1String("Unknown") },
            { Blob,         QLatin1String("Blob") },
            { Password,     QLatin1String("Password") },
            { Certificate,  QLatin1String("Certificate") },
            { PrivateKey,   QLatin1String("PrivateKey") },
        };
        return typeToString.value(type, QStringLiteral("Unknown"));
    }

    static Type typeFromString(const QString &string) {
        static QHash<QString, Type> stringToType {
            { QLatin1String("Unknown"),        Unknown },
            { QLatin1String("Blob"),           Blob },
            { QLatin1String("Password"),       Password },
            { QLatin1String("Certificate"),    Certificate },
            { QLatin1String("PrivateKey"),     PrivateKey },
        };
        return stringToType.value(string, Unknown);
    }

    QVector<QByteArray> m_data;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_SECRET_H
