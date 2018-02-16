/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_INTERACTIONREQUEST_H
#define LIBSAILFISHCRYPTO_INTERACTIONREQUEST_H

#include "Crypto/cryptoglobal.h"

#include <QtCore/QString>
#include <QtCore/QSharedDataPointer>
#include <QtCore/QMetaType>

namespace Sailfish {

namespace Crypto {

class InteractionParametersPrivate;
class SAILFISH_CRYPTO_API InteractionParameters {
    Q_GADGET
    Q_PROPERTY(QString keyName READ keyName WRITE setKeyName)
    Q_PROPERTY(QString collectionName READ collectionName WRITE setCollectionName)
    Q_PROPERTY(QString applicationId READ applicationId WRITE setApplicationId)
    Q_PROPERTY(Operation operation READ operation WRITE setOperation)
    Q_PROPERTY(QString authenticationPluginName READ authenticationPluginName WRITE setAuthenticationPluginName)
    Q_PROPERTY(QString promptText READ promptText WRITE setPromptText)
    Q_PROPERTY(QString promptTrId READ promptTrId WRITE setPromptTrId)
    Q_PROPERTY(InputType inputType READ inputType WRITE setInputType)
    Q_PROPERTY(EchoMode echoMode READ echoMode WRITE setEchoMode)

public:
    enum InputType {
        UnknownInput        = 0,
        AuthenticationInput = 1,  // returns non-empty data if the user authenticates via system dialog
        ConfirmationInput   = 2,  // returns non-empty data if the user allows the operation
        NumericInput        = 4,  // returns the numeric (e.g. PIN) data from the user
        AlphaNumericInput   = 8,  // returns the alphanumeric (e.g. passphrase) data from the user
        FingerprintInput    = 16, // returns the fingerprint data from the user
        IrisInput           = 32, // returns the iris data from the user
        RetinaInput         = 64, // returns the retina data from the user
        // reserved
        LastInputType       = 65536
    };
    Q_ENUM(InputType)
    Q_DECLARE_FLAGS(InputTypes, InputType)

    enum EchoMode {
        UnknownEcho = 0,
        NormalEcho,
        PasswordEcho,
        NoEcho,
        PasswordEchoOnEdit,
        // reserved
        LastEchoMode = 63
    };
    Q_ENUM(EchoMode)

    enum Operation {
        UnknownOperation = 0,

        RequestUserData  = 1,   // usually used in conjunction with StoreSecret, i.e. store data requested from user.

        CreateCollection = 2,
        UnlockCollection = 4,
        DeleteCollection = 8,

        ReadSecret       = 16,
        StoreSecret      = 32,
        DeleteSecret     = 64,

        Encrypt          = 128,
        Decrypt          = 256,
        Sign             = 512,
        Verify           = 1024,
        DeriveDigest     = 2048,
        DeriveMac        = 4096,
        DeriveKey        = 8192,

        // reserved
        LastOperation    = 65536
    };
    Q_ENUM(Operation)
    Q_DECLARE_FLAGS(Operations, Operation)

    InteractionParameters();
    InteractionParameters(const InteractionParameters &other);
    ~InteractionParameters();
    InteractionParameters& operator=(const InteractionParameters &other);
    bool operator==(const InteractionParameters &other) const;
    bool operator!=(const InteractionParameters &other) const {
        return !operator==(other);
    }

    bool isValid() const;

    QString keyName() const;
    void setKeyName(const QString &name);

    QString collectionName() const;
    void setCollectionName(const QString &name);

    QString applicationId() const;
    void setApplicationId(const QString &id);

    Operation operation() const;
    void setOperation(Operation op);

    // TODO: do we need an "operationArgument" parameter?
    // e.g. a filename which the client application wishes to perform the operation on?

    QString authenticationPluginName() const;
    void setAuthenticationPluginName(const QString &pluginName);

    QString promptText() const;
    void setPromptText(const QString &prompt);

    QString promptTrId() const;
    void setPromptTrId(const QString &trId);

    InputType inputType() const;
    void setInputType(InputType type);

    EchoMode echoMode() const;
    void setEchoMode(EchoMode mode);

private:
    QSharedDataPointer<InteractionParametersPrivate> d_ptr;
    friend class InteractionParametersPrivate;
};

} // Crypto

} // Sailfish

Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::InteractionParameters::InputTypes);
Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::InteractionParameters::Operations);
Q_DECLARE_METATYPE(Sailfish::Crypto::InteractionParameters::InputType);
Q_DECLARE_METATYPE(Sailfish::Crypto::InteractionParameters::EchoMode);
Q_DECLARE_METATYPE(Sailfish::Crypto::InteractionParameters::Operation);
Q_DECLARE_METATYPE(Sailfish::Crypto::InteractionParameters);
Q_DECLARE_TYPEINFO(Sailfish::Crypto::InteractionParameters, Q_MOVABLE_TYPE);

inline bool operator<(const Sailfish::Crypto::InteractionParameters &/*lhs*/, const Sailfish::Crypto::InteractionParameters &/*rhs*/)
{
    qWarning("'<' operator not valid for InteractionParameters\n");
    return false;
}

#endif // LIBSAILFISHCRYPTO_INTERACTIONREQUEST_H
