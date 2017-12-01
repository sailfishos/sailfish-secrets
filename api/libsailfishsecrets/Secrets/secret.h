/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_SECRET_H
#define LIBSAILFISHSECRETS_SECRET_H

#include "Secrets/secretsglobal.h"

#include <QtDBus/QDBusArgument>

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QHash>
#include <QtCore/QMap>

namespace Sailfish {

namespace Secrets {

class SAILFISH_SECRETS_API Secret {
public:
    static const QString FilterDataFieldType;
    static const QString TypeUnknown;
    static const QString TypeBlob;
    static const QString TypeCryptoKey;
    static const QString TypeCryptoCertificate;
    static const QString TypeUsernamePassword;

    class Identifier {
    public:
        Identifier() {} // invalid identifier
        Identifier(const QString &name) : m_name(name) {} // standalone secret identifier
        Identifier(const QString &name, const QString &collectionName)
            : m_name(name), m_collectionName(collectionName) {}
        Identifier(const Sailfish::Secrets::Secret::Identifier &other)
            : m_name(other.m_name), m_collectionName(other.m_collectionName) {}
        Identifier(Sailfish::Secrets::Secret::Identifier &&) = default;

        Identifier &operator=(const Sailfish::Secrets::Secret::Identifier &other) {
            m_name = other.m_name;
            m_collectionName = other.m_collectionName;
            return *this;
        }

        bool operator==(const Sailfish::Secrets::Secret::Identifier &other) const {
            return m_name == other.m_name && m_collectionName == other.m_collectionName;
        }

        bool operator<(const Sailfish::Secrets::Secret::Identifier &other) const {
            if (m_collectionName < other.m_collectionName)
                return true;
            return m_name < other.m_name;
        }

        QString name() const { return m_name; }
        void setName(const QString &name) { m_name = name; }

        QString collectionName() const { return m_collectionName; }
        void setCollectionName(const QString &collectionName) { m_collectionName = collectionName; }

        bool isValid() const { return !m_name.isEmpty(); }
        bool identifiesStandaloneSecret() const { return m_collectionName.isEmpty(); }

    private:
        QString m_name;
        QString m_collectionName;
    };

    class FilterData : public QMap<QString,QString> {
    // this exists solely to prevent Qt's metatype system from erroring on duplicate registration
    public:
        FilterData(const QMap<QString,QString> &v) : QMap<QString,QString>(v) {}
        FilterData() = default;
        FilterData(const Sailfish::Secrets::Secret::FilterData &) = default;
        FilterData(Sailfish::Secrets::Secret::FilterData &&) = default;
        FilterData &operator=(const Sailfish::Secrets::Secret::FilterData &) = default;
    };

    Secret(const Secret &other) : m_filterData(other.m_filterData), m_identifier(other.m_identifier), m_data(other.m_data) {}
    Secret(const Sailfish::Secrets::Secret::Identifier &identifier)
        : m_identifier(identifier) { setType(TypeUnknown); }
    Secret(const QByteArray &blob, const Sailfish::Secrets::Secret::FilterData &filterData = Sailfish::Secrets::Secret::FilterData())
        : m_filterData(filterData), m_data(blob) { setType(TypeBlob); }
    Secret() = default;
    Secret(Sailfish::Secrets::Secret &&) = default;

    Secret &operator=(const Sailfish::Secrets::Secret &other) {
        m_filterData = other.m_filterData;
        m_identifier = other.m_identifier;
        m_data = other.m_data;
        return *this;
    }

    bool operator==(const Sailfish::Secrets::Secret &other) const {
        return type() == other.type() && m_data == other.m_data;
    }

    bool operator<(const Sailfish::Secrets::Secret &other) const {
        if (type() < other.type())
            return true;
        if ( m_data < other.m_data)
            return true;
        return m_filterData.size() < other.m_filterData.size();
    }

    QString type() const { return m_filterData.value(FilterDataFieldType, TypeUnknown); }
    void setType(const QString &type) { m_filterData.insert(FilterDataFieldType, type); }

    Sailfish::Secrets::Secret::Identifier identifier() const { return m_identifier; }
    void setIdentifier(const Sailfish::Secrets::Secret::Identifier &identifier) { m_identifier = identifier; }

    QByteArray data() const { return m_data; }
    void setData(const QByteArray &data) { m_data = data; }

    Sailfish::Secrets::Secret::FilterData filterData() const { return m_filterData; }
    void setFilterData(const Sailfish::Secrets::Secret::FilterData &filterData) { m_filterData = filterData; }
    void setFilterData(const QString &field, const QString &value) { m_filterData.insert(field, value); }
    QString filterData(const QString &field) const { return m_filterData.value(field); }
    bool hasFilterData(const QString &field) const { return m_filterData.contains(field); }

private:
    Sailfish::Secrets::Secret::FilterData m_filterData;
    Sailfish::Secrets::Secret::Identifier m_identifier;
    QByteArray m_data;
};

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::Secret &secret) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::Secret &secret) SAILFISH_SECRETS_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::Secret::Identifier &identifier) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::Secret::Identifier &identifier) SAILFISH_SECRETS_API;

} // namespace Secrets

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Secrets::Secret::FilterData);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::Secret::FilterData, Q_MOVABLE_TYPE);
Q_DECLARE_METATYPE(Sailfish::Secrets::Secret::Identifier);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::Secret::Identifier, Q_MOVABLE_TYPE);
Q_DECLARE_METATYPE(Sailfish::Secrets::Secret);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::Secret, Q_MOVABLE_TYPE);

#endif // LIBSAILFISHSECRETS_SECRET_H
