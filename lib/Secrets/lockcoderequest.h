/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_LOCKCODEREQUEST_H
#define LIBSAILFISHSECRETS_LOCKCODEREQUEST_H

#include "Secrets/secretsglobal.h"
#include "Secrets/request.h"
#include "Secrets/secret.h"
#include "Secrets/secretmanager.h"

#include <QtCore/QObject>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

namespace Sailfish {

namespace Secrets {

class LockCodeRequestPrivate;
class SAILFISH_SECRETS_API LockCodeRequest : public Sailfish::Secrets::Request
{
    Q_OBJECT
    Q_PROPERTY(LockCodeRequestType lockCodeRequestType READ lockCodeRequestType WRITE setLockCodeRequestType NOTIFY lockCodeRequestTypeChanged)
    Q_PROPERTY(QString secretName READ secretName WRITE setSecretName NOTIFY secretNameChanged)
    Q_PROPERTY(QString collectionName READ collectionName WRITE setCollectionName NOTIFY collectionNameChanged)
    Q_PROPERTY(Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode READ userInteractionMode WRITE setUserInteractionMode NOTIFY userInteractionModeChanged)
    Q_PROPERTY(Sailfish::Secrets::InteractionParameters interactionParameters READ interactionParameters WRITE setInteractionParameters NOTIFY interactionParametersChanged)

public:
    enum LockCodeRequestType {
        ModifyLockCode = 0,
        ProvideLockCode,
        ForgetLockCode
    };
    Q_ENUM(LockCodeRequestType)

    LockCodeRequest(QObject *parent = Q_NULLPTR);
    ~LockCodeRequest();

    LockCodeRequestType lockCodeRequestType() const;
    void setLockCodeRequestType(LockCodeRequestType type);

    QString secretName() const;
    void setSecretName(const QString &name);

    QString collectionName() const;
    void setCollectionName(const QString &name);

    Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode() const;
    void setUserInteractionMode(Sailfish::Secrets::SecretManager::UserInteractionMode mode);

    InteractionParameters interactionParameters() const;
    void setInteractionParameters(const InteractionParameters &params);

    Sailfish::Secrets::Request::Status status() const Q_DECL_OVERRIDE;
    Sailfish::Secrets::Result result() const Q_DECL_OVERRIDE;

    Sailfish::Secrets::SecretManager *manager() const Q_DECL_OVERRIDE;
    void setManager(Sailfish::Secrets::SecretManager *manager) Q_DECL_OVERRIDE;

    void startRequest() Q_DECL_OVERRIDE;
    void waitForFinished() Q_DECL_OVERRIDE;

Q_SIGNALS:
    void lockCodeRequestTypeChanged();
    void secretNameChanged();
    void collectionNameChanged();
    void userInteractionModeChanged();
    void interactionParametersChanged();

private:
    QScopedPointer<LockCodeRequestPrivate> const d_ptr;
    Q_DECLARE_PRIVATE(LockCodeRequest)
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_LOCKCODEREQUEST_H
