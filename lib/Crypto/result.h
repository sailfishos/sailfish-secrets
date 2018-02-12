/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_RESULT_H
#define LIBSAILFISHCRYPTO_RESULT_H

#include "Crypto/cryptoglobal.h"

#include <QtCore/QString>
#include <QtCore/QMetaType>

namespace Sailfish {

namespace Crypto {

class SAILFISH_CRYPTO_API Result
{
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
        StorageError = 4,
        DaemonError = 5,

        InvalidCryptographicServiceProvider = 10,
        InvalidStorageProvider,
        InvalidKeyIdentifier,
        DuplicateKeyIdentifier,

        UnsupportedOperation = 20,
        UnsupportedBlockMode,
        UnsupportedEncryptionPadding,
        UnsupportedSignaturePadding,
        UnsupportedDigest,

        EmptySecretKey = 30,
        EmptyPrivateKey,
        EmptyPublicKey,

        CryptoPluginEncryptionError = 40,
        CryptoPluginDecryptionError,
        CryptoPluginRandomDataError,

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

    Result(Sailfish::Crypto::Result::ResultCode resultCode = Succeeded)
        : m_errorMessage(resultCode == Sailfish::Crypto::Result::Failed ? QString::fromLatin1("Unknown error") : QString())
        , m_storageErrorCode(0)
        , m_errorCode(resultCode == Sailfish::Crypto::Result::Failed
                                 ? Sailfish::Crypto::Result::UnknownError
                                 : Sailfish::Crypto::Result::NoError)
        , m_code(resultCode) {}
    Result(Sailfish::Crypto::Result::ErrorCode errorCode, const QString &errorMessage)
        : m_errorMessage(errorMessage)
        , m_storageErrorCode(0)
        , m_errorCode(errorCode)
        , m_code(errorCode >= Sailfish::Crypto::Result::UnknownError
                 ? Sailfish::Crypto::Result::Failed
                 : Sailfish::Crypto::Result::Succeeded) {}
    Result(const Result &other)
        : m_errorMessage(other.m_errorMessage)
        , m_storageErrorCode(other.m_storageErrorCode)
        , m_errorCode(other.m_errorCode)
        , m_code(other.m_code) {}
    Result(Sailfish::Crypto::Result &&) = default;

    Result &operator=(const Sailfish::Crypto::Result &other) {
        m_errorMessage = other.m_errorMessage;
        m_storageErrorCode = other.m_storageErrorCode;
        m_errorCode = other.m_errorCode;
        m_code = other.m_code;
        return *this;
    }

    void setErrorMessage(const QString &m) { m_errorMessage = m; }
    QString errorMessage() const { return m_errorMessage; }
    void setStorageErrorCode(int c) { m_storageErrorCode = c; }
    int storageErrorCode() const { return m_storageErrorCode; }
    void setErrorCode(int c) { m_errorCode = static_cast<Sailfish::Crypto::Result::ErrorCode>(c); }
    void setErrorCode(Sailfish::Crypto::Result::ErrorCode c) { m_errorCode = c; }
    Sailfish::Crypto::Result::ErrorCode errorCode() const { return m_errorCode; }
    void setCode(int c) { m_code = static_cast<Sailfish::Crypto::Result::ResultCode>(c); }
    void setCode(Sailfish::Crypto::Result::ResultCode c) { m_code = c; }
    Sailfish::Crypto::Result::ResultCode code() const { return m_code; }

private:
    QString m_errorMessage;
    int m_storageErrorCode;
    Sailfish::Crypto::Result::ErrorCode m_errorCode;
    Sailfish::Crypto::Result::ResultCode m_code;
};

} // Crypto

} // Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::Result);
Q_DECLARE_TYPEINFO(Sailfish::Crypto::Result, Q_MOVABLE_TYPE);

#endif // LIBSAILFISHCRYPTO_RESULT_H
