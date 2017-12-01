/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_RESULT_H
#define LIBSAILFISHSECRETS_RESULT_H

#include "Secrets/secretsglobal.h"

#include <QtDBus/QDBusArgument>
#include <QtCore/QString>

namespace Sailfish {

namespace Secrets {

class Result {
public:
    enum ResultCode {
        Succeeded = 0,
        Pending   = 1,
        Failed    = 2
    };

    enum ErrorCode {
        NoError = 0,
        UnknownError = 2,
        SerialisationError = 3,

        PermissionsError = 10,
        IncorrectAuthenticationKeyError,
        OperationNotSupportedError,
        OperationRequiresUserInteraction,
        OperationRequiresInProcessUserInteraction,
        SecretManagerNotInitialisedError,

        SecretsDaemonRequestPidError = 20,
        SecretsDaemonRequestQueueFullError,

        SecretsPluginEncryptionError = 30,
        SecretsPluginDecryptionError,

        InvalidSecretError = 40,
        InvalidSecretIdentifierError,
        InvalidFilterError,
        InvalidCollectionError,
        InvalidExtensionPluginError,
        InvalidApplicationIdError,
        CollectionAlreadyExistsError,
        SecretAlreadyExistsError,

        CollectionIsLockedError = 60,

        DatabaseQueryError = 70,
        DatabaseTransactionError,

        UiServiceUnknownError = 80,
        UiServiceUnavailableError,
        UiServiceRequestInvalidError,
        UiServiceRequestFailedError,
        UiServiceRequestBusyError,
        UiServiceResponseInvalidError,

        UiViewUnavailableError = 90,
        UiViewRequestError,
        UiViewParentError,
        UiViewChildError,
        UiViewError,

        NetworkError = 98,
        NetworkSslError = 99,
        HttpContinue = 100,
        HttpSwitchingProtocol = 101,
        HttpOk = 200,
        HttpCreated = 201,
        HttpAccepted = 202,
        HttpNonAuthoritativeInformation = 203,
        HttpNoContent = 204,
        HttpResetContent = 205,
        HttpPartialContent = 206,
        HttpMultipleChoice = 300,
        HttpMovedPermanently = 301,
        HttpFound = 302,
        HttpSeeOther = 303,
        HttpNotModified = 304,
        HttpUseProxy = 305,
        HttpUnused = 306,
        HttpTemporaryRedirect = 307,
        HttpPermanentRedirect = 308,
        HttpBadRequest = 400,
        HttpUnauthorized = 401,
        HttpPaymentRequired = 402,
        HttpForbidden = 403,
        HttpNotFound = 404,
        HttpMethodNotAllowed = 405,
        HttpNotAcceptable = 406,
        HttpProxyAuthenticationRequired = 407,
        HttpRequestTimeout = 408,
        HttpConflict = 409,
        HttpGone = 410,
        HttpLengthRequired = 411,
        HttpPreconditionFailed = 412,
        HttpPayloadTooLarge = 413,
        HttpUriTooLong = 414,
        HttpUnsupportedMediaType = 415,
        HttpRequestRangeNotSatisfiable = 416,
        HttpExpectationFailed = 417,
        HttpMisdirectedRequest = 421,
        HttpUpgradeRequired = 426,
        HttpPreconditionRequired = 428,
        HttpTooManyRequests = 429,
        HttpRequestHeaderFieldsTooLarge = 431,
        HttpUnavailableForLegalReasons = 451,
        HttpInternalServerError = 500,
        HttpNotImplemented = 501,
        HttpBadGateway = 502,
        HttpServiceUnavailable = 503,
        HttpGatewayTimeout = 504,
        HttpVersionNotSupported = 505,
        HttpVariantAlsoNegotiates = 506,
        HttpInsufficientStorage = 507,
        HttpNetworkAuthenticationRequired = 511,

        OtherError = 1024,
    };

    Result(Sailfish::Secrets::Result::ResultCode resultCode = Succeeded)
        : m_errorMessage(resultCode == Sailfish::Secrets::Result::Failed ? QString::fromLatin1("Unknown error") : QString())
        , m_errorCode(resultCode == Sailfish::Secrets::Result::Failed
                                 ? Sailfish::Secrets::Result::UnknownError
                                 : Sailfish::Secrets::Result::NoError)
        , m_code(resultCode) {}
    Result(Sailfish::Secrets::Result::ErrorCode errorCode, const QString &errorMessage)
        : m_errorMessage(errorMessage), m_errorCode(errorCode), m_code(errorCode >= Sailfish::Secrets::Result::UnknownError
                                                                                 ? Sailfish::Secrets::Result::Failed
                                                                                 : Sailfish::Secrets::Result::Succeeded) {}
    Result(const Sailfish::Secrets::Result &other)
        : m_errorMessage(other.m_errorMessage), m_errorCode(other.m_errorCode), m_code(other.m_code) {}
    Result(Sailfish::Secrets::Result &&) = default;

    Result &operator=(const Sailfish::Secrets::Result &other) {
        m_errorMessage = other.m_errorMessage;
        m_errorCode = other.m_errorCode;
        m_code = other.m_code;
        return *this;
    }

    void setErrorMessage(const QString &m) { m_errorMessage = m; }
    QString errorMessage() const { return m_errorMessage; }
    void setErrorCode(int c) { m_errorCode = static_cast<Sailfish::Secrets::Result::ErrorCode>(c); }
    void setErrorCode(Sailfish::Secrets::Result::ErrorCode c) { m_errorCode = c; }
    Sailfish::Secrets::Result::ErrorCode errorCode() const { return m_errorCode; }
    void setCode(int c) { m_code = static_cast<Sailfish::Secrets::Result::ResultCode>(c); }
    void setCode(Sailfish::Secrets::Result::ResultCode c) { m_code = c; }
    Sailfish::Secrets::Result::ResultCode code() const { return m_code; }

private:
    QString m_errorMessage;
    Sailfish::Secrets::Result::ErrorCode m_errorCode;
    Sailfish::Secrets::Result::ResultCode m_code;
};

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::Result &result) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::Result &result) SAILFISH_SECRETS_API;

} // Secrets

} // Sailfish

Q_DECLARE_METATYPE(Sailfish::Secrets::Result);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::Result, Q_MOVABLE_TYPE);

#endif // LIBSAILFISHSECRETS_RESULT_H
