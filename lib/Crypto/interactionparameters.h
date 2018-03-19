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
    Q_PROPERTY(QString pluginName READ pluginName WRITE setPluginName)
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
        UnknownOperation    = 0,

        RequestUserData     = 1 << 0,   // usually used in conjunction with StoreSecret, i.e. store data requested from user.

        UnlockDatabase      = 1 << 1,
        LockDatabase        = 1 << 2,
        ModifyLockDatabase  = 1 << 3,

        UnlockPlugin        = 1 << 4,
        LockPlugin          = 1 << 5,
        ModifyLockPlugin    = 1 << 6,

        CreateCollection    = 1 << 7,
        UnlockCollection    = 1 << 8,
        LockCollection      = 1 << 9,
        ModifyLockCollection= 1 << 10,
        DeleteCollection    = 1 << 11,

        ReadSecret          = 1 << 12,
        StoreSecret         = 1 << 13,
        UnlockSecret        = 1 << 14,
        LockSecret          = 1 << 15,
        ModifyLockSecret    = 1 << 16,
        DeleteSecret        = 1 << 17,

        Encrypt             = 1 << 18,
        Decrypt             = 1 << 19,
        Sign                = 1 << 20,
        Verify              = 1 << 21,
        DeriveDigest        = 1 << 22,
        DeriveMac           = 1 << 23,
        DeriveKey           = 1 << 24,

        // reserved
        LastOperation       = 1 << 30
    };
    Q_ENUM(Operation)
    Q_DECLARE_FLAGS(Operations, Operation)

    InteractionParameters();
    InteractionParameters(const InteractionParameters &other);
    ~InteractionParameters();
    InteractionParameters& operator=(const InteractionParameters &other);

    bool isValid() const;

    QString keyName() const;
    void setKeyName(const QString &name);

    QString collectionName() const;
    void setCollectionName(const QString &name);

    QString pluginName() const;
    void setPluginName(const QString &name);

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

bool operator==(const Sailfish::Crypto::InteractionParameters &lhs, const Sailfish::Crypto::InteractionParameters &rhs) SAILFISH_CRYPTO_API;
bool operator!=(const Sailfish::Crypto::InteractionParameters &lhs, const Sailfish::Crypto::InteractionParameters &rhs) SAILFISH_CRYPTO_API;
bool operator<(const Sailfish::Crypto::InteractionParameters &lhs, const Sailfish::Crypto::InteractionParameters &rhs) SAILFISH_CRYPTO_API;

} // Crypto

} // Sailfish

Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::InteractionParameters::InputTypes);
Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::InteractionParameters::Operations);
Q_DECLARE_METATYPE(Sailfish::Crypto::InteractionParameters::InputType);
Q_DECLARE_METATYPE(Sailfish::Crypto::InteractionParameters::EchoMode);
Q_DECLARE_METATYPE(Sailfish::Crypto::InteractionParameters::Operation);
Q_DECLARE_METATYPE(Sailfish::Crypto::InteractionParameters);
Q_DECLARE_TYPEINFO(Sailfish::Crypto::InteractionParameters, Q_MOVABLE_TYPE);

#endif // LIBSAILFISHCRYPTO_INTERACTIONREQUEST_H
