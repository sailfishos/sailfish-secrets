/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_QML_APPLICATIONINTERACTIONVIEW_H
#define SAILFISHSECRETS_QML_APPLICATIONINTERACTIONVIEW_H

#include "Secrets/interactionview.h"
#include "Secrets/interactionrequest.h"

#include <QtQuick/QQuickItem>

namespace Sailfish {

namespace Secrets {

namespace Plugin {

class ApplicationInteractionViewPrivate;
class ApplicationInteractionView : public QQuickItem, public InteractionView
{
    Q_OBJECT
    Q_PROPERTY(QObject *adapter READ adapter CONSTANT)
    Q_PROPERTY(QObject *secretManager READ secretManager WRITE setSecretManager NOTIFY secretManagerChanged)
    Q_ENUMS(ConfirmationValue)
    Q_ENUMS(RequestType)

public:
    enum ConfirmationValue {
        Unknown = 0,
        Allow,
        Deny
    };

    enum RequestType {
        InvalidRequest = Sailfish::Secrets::InteractionRequest::InvalidRequest,
        DeleteSecretConfirmationRequest = Sailfish::Secrets::InteractionRequest::DeleteSecretConfirmationRequest,
        ModifySecretConfirmationRequest = Sailfish::Secrets::InteractionRequest::ModifySecretConfirmationRequest,
        UserVerificationConfirmationRequest = Sailfish::Secrets::InteractionRequest::UserVerificationConfirmationRequest,
        AuthenticationKeyRequest = Sailfish::Secrets::InteractionRequest::AuthenticationKeyRequest
    };

    ApplicationInteractionView(QQuickItem *parent = Q_NULLPTR);
    ~ApplicationInteractionView();

    QObject *secretManager() const;
    Q_INVOKABLE void setSecretManager(QObject *manager);

Q_SIGNALS:
    void cancelled();
    void finished();
    void secretManagerChanged();

protected:
    void performRequest(const Sailfish::Secrets::InteractionRequest &request) Q_DECL_OVERRIDE;
    void continueRequest(const Sailfish::Secrets::InteractionRequest &request) Q_DECL_OVERRIDE;
    void cancelRequest() Q_DECL_OVERRIDE;
    void finishRequest() Q_DECL_OVERRIDE;

private Q_SLOTS:
    void parentSizeChanged();

public:
    QObject *adapter() const;

private:
    friend class ApplicationInteractionViewPrivate;
    Q_INVOKABLE void sendResponseHelper(const Sailfish::Secrets::Result &result,
                                        const Sailfish::Secrets::InteractionResponse &response);
    QQuickItem *m_childItem;
    ApplicationInteractionViewPrivate *m_adapter;
};

} // namespace Plugin

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_QML_APPLICATIONINTERACTIONVIEW_H
