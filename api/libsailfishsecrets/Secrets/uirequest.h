/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_UIREQUEST_H
#define LIBSAILFISHSECRETS_UIREQUEST_H

#include "Secrets/secretsglobal.h"
#include "Secrets/result.h"

#include <QtDBus/QDBusArgument>
#include <QtCore/QVariantMap>
#include <QtCore/QString>
#include <QtCore/QMetaType>
#include <QtGlobal>

namespace Sailfish {

namespace Secrets {

class SAILFISH_SECRETS_API UiRequest
{
public:
    enum Type {
        InvalidRequest = 0,
        DeleteSecretConfirmationRequest,
        ModifySecretConfirmationRequest,
        UserVerificationConfirmationRequest,
        AuthenticationKeyRequest
    };

    static const QString UiViewQmlFileUrl;

    UiRequest(Sailfish::Secrets::UiRequest::Type type = Sailfish::Secrets::UiRequest::InvalidRequest,
              const QVariantMap &values = QVariantMap())
        : m_values(values)
        , m_type(type)
        , m_isResponse(false) {}
    UiRequest(const Sailfish::Secrets::UiRequest &other)
        : m_values(other.m_values)
        , m_type(other.m_type)
        , m_isResponse(other.m_isResponse) {}
    virtual ~UiRequest() {}

    Sailfish::Secrets::UiRequest::Type type() const { return m_type; }
    bool isResponse() const { return m_isResponse; }

    QString uiViewQmlFileUrl() const { return m_values.value(UiViewQmlFileUrl).toString(); }
    void setUiViewQmlFileUrl(const QString &value) { m_values.insert(UiViewQmlFileUrl, value); }

    bool hasValue(const QString &key) const { return m_values.contains(key); }
    QVariant value(const QString &key) const { return m_values.value(key); }
    QVariantMap values() const { return m_values; }
    void setValue(const QString &key, const QVariant &value) { m_values.insert(key, value); }
    void removeValue(const QString &key) { m_values.remove(key); }
    void setValues(const QVariantMap &values) { m_values = values; }

protected:
    QVariantMap m_values;
    Sailfish::Secrets::UiRequest::Type m_type;
    bool m_isResponse;
};

class SAILFISH_SECRETS_API UiResponse : public UiRequest
{
public:
    static const QString ResultCode;
    static const QString ErrorMessage;
    static const QString Confirmation;
    static const QString AuthenticationKey;

    UiResponse()
        : Sailfish::Secrets::UiRequest(Sailfish::Secrets::UiRequest::InvalidRequest, QVariantMap()) { m_isResponse = true; }
    UiResponse(Sailfish::Secrets::UiRequest::Type type, const QVariantMap &values = QVariantMap())
        : Sailfish::Secrets::UiRequest::UiRequest(type, values) { m_isResponse = true; }
    UiResponse(const Sailfish::Secrets::UiResponse &other) : Sailfish::Secrets::UiRequest(other) {}

    Sailfish::Secrets::Result::ResultCode resultCode() const { return static_cast<Sailfish::Secrets::Result::ResultCode>(m_values.value(ResultCode).toInt()); }
    void setResultCode(Sailfish::Secrets::Result::ResultCode value) { m_values.insert(ResultCode, QVariant::fromValue<int>(static_cast<int>(value))); }

    QString errorMessage() const { return m_values.value(ErrorMessage).toString(); }
    void setErrorMessage(const QString &value) { m_values.insert(ErrorMessage, value); }

    bool confirmation() const { return m_values.value(Confirmation).toBool(); }
    void setConfirmation(bool value) { m_values.insert(Confirmation, value); }

    QByteArray authenticationKey() const { return m_values.value(AuthenticationKey).toByteArray(); }
    void setAuthenticationKey(const QByteArray &value) { m_values.insert(AuthenticationKey, value); }
};

QDBusArgument &operator<<(QDBusArgument &argument, const UiRequest &request) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, UiRequest &request) SAILFISH_SECRETS_API;

QDBusArgument &operator<<(QDBusArgument &argument, const UiResponse &response) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, UiResponse &response) SAILFISH_SECRETS_API;

} // namespace Secrets

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Secrets::UiRequest);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::UiRequest, Q_MOVABLE_TYPE);

Q_DECLARE_METATYPE(Sailfish::Secrets::UiResponse);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::UiResponse, Q_MOVABLE_TYPE);

#endif // LIBSAILFISHSECRETS_UIREQUEST_H
