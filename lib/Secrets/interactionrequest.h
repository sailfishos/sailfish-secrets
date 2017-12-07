/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_INTERACTIONREQUEST_H
#define LIBSAILFISHSECRETS_INTERACTIONREQUEST_H

#include "Secrets/secretsglobal.h"
#include "Secrets/result.h"

#include <QtDBus/QDBusArgument>
#include <QtCore/QVariantMap>
#include <QtCore/QString>
#include <QtCore/QMetaType>
#include <QtGlobal>

namespace Sailfish {

namespace Secrets {

class SAILFISH_SECRETS_API InteractionRequest
{
public:
    enum Type {
        InvalidRequest = 0,
        DeleteSecretConfirmationRequest,
        ModifySecretConfirmationRequest,
        UserVerificationConfirmationRequest,
        AuthenticationKeyRequest
    };

    static const QString InteractionViewQmlFileUrl;

    InteractionRequest(Sailfish::Secrets::InteractionRequest::Type type = Sailfish::Secrets::InteractionRequest::InvalidRequest,
              const QVariantMap &values = QVariantMap())
        : m_values(values)
        , m_type(type)
        , m_isResponse(false) {}
    InteractionRequest(const Sailfish::Secrets::InteractionRequest &other)
        : m_values(other.m_values)
        , m_type(other.m_type)
        , m_isResponse(other.m_isResponse) {}
    virtual ~InteractionRequest() {}

    Sailfish::Secrets::InteractionRequest::Type type() const { return m_type; }
    bool isResponse() const { return m_isResponse; }

    QString interactionViewQmlFileUrl() const { return m_values.value(InteractionViewQmlFileUrl).toString(); }
    void setInteractionViewQmlFileUrl(const QString &value) { m_values.insert(InteractionViewQmlFileUrl, value); }

    bool hasValue(const QString &key) const { return m_values.contains(key); }
    QVariant value(const QString &key) const { return m_values.value(key); }
    QVariantMap values() const { return m_values; }
    void setValue(const QString &key, const QVariant &value) { m_values.insert(key, value); }
    void removeValue(const QString &key) { m_values.remove(key); }
    void setValues(const QVariantMap &values) { m_values = values; }

protected:
    QVariantMap m_values;
    Sailfish::Secrets::InteractionRequest::Type m_type;
    bool m_isResponse;
};

class SAILFISH_SECRETS_API InteractionResponse : public InteractionRequest
{
public:
    static const QString ResultCode;
    static const QString ErrorMessage;
    static const QString Confirmation;
    static const QString AuthenticationKey;

    InteractionResponse()
        : Sailfish::Secrets::InteractionRequest(Sailfish::Secrets::InteractionRequest::InvalidRequest, QVariantMap()) { m_isResponse = true; }
    InteractionResponse(Sailfish::Secrets::InteractionRequest::Type type, const QVariantMap &values = QVariantMap())
        : Sailfish::Secrets::InteractionRequest::InteractionRequest(type, values) { m_isResponse = true; }
    InteractionResponse(const Sailfish::Secrets::InteractionResponse &other) : Sailfish::Secrets::InteractionRequest(other) {}

    Sailfish::Secrets::Result::ResultCode resultCode() const { return static_cast<Sailfish::Secrets::Result::ResultCode>(m_values.value(ResultCode).toInt()); }
    void setResultCode(Sailfish::Secrets::Result::ResultCode value) { m_values.insert(ResultCode, QVariant::fromValue<int>(static_cast<int>(value))); }

    QString errorMessage() const { return m_values.value(ErrorMessage).toString(); }
    void setErrorMessage(const QString &value) { m_values.insert(ErrorMessage, value); }

    bool confirmation() const { return m_values.value(Confirmation).toBool(); }
    void setConfirmation(bool value) { m_values.insert(Confirmation, value); }

    QByteArray authenticationKey() const { return m_values.value(AuthenticationKey).toByteArray(); }
    void setAuthenticationKey(const QByteArray &value) { m_values.insert(AuthenticationKey, value); }
};

QDBusArgument &operator<<(QDBusArgument &argument, const InteractionRequest &request) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, InteractionRequest &request) SAILFISH_SECRETS_API;

QDBusArgument &operator<<(QDBusArgument &argument, const InteractionResponse &response) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, InteractionResponse &response) SAILFISH_SECRETS_API;

} // namespace Secrets

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Secrets::InteractionRequest);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::InteractionRequest, Q_MOVABLE_TYPE);

Q_DECLARE_METATYPE(Sailfish::Secrets::InteractionResponse);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::InteractionResponse, Q_MOVABLE_TYPE);

#endif // LIBSAILFISHSECRETS_INTERACTIONREQUEST_H
