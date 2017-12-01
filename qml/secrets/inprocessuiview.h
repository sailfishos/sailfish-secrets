/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_QML_INPROCESSUIVIEW_H
#define SAILFISHSECRETS_QML_INPROCESSUIVIEW_H

#include "Secrets/uiview.h"
#include "Secrets/uirequest.h"

#include <QtQuick/QQuickItem>

namespace Sailfish {

namespace Secrets {

namespace Plugin {

class InProcessUiViewPrivate;
class InProcessUiView : public QQuickItem, public UiView
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
        InvalidRequest = Sailfish::Secrets::UiRequest::InvalidRequest,
        DeleteSecretConfirmationRequest = Sailfish::Secrets::UiRequest::DeleteSecretConfirmationRequest,
        ModifySecretConfirmationRequest = Sailfish::Secrets::UiRequest::ModifySecretConfirmationRequest,
        UserVerificationConfirmationRequest = Sailfish::Secrets::UiRequest::UserVerificationConfirmationRequest,
        AuthenticationKeyRequest = Sailfish::Secrets::UiRequest::AuthenticationKeyRequest
    };

    InProcessUiView(QQuickItem *parent = Q_NULLPTR);
    ~InProcessUiView();

    QObject *secretManager() const;
    Q_INVOKABLE void setSecretManager(QObject *manager);

Q_SIGNALS:
    void cancelled();
    void finished();
    void secretManagerChanged();

protected:
    void performRequest(const Sailfish::Secrets::UiRequest &request) Q_DECL_OVERRIDE;
    void continueRequest(const Sailfish::Secrets::UiRequest &request) Q_DECL_OVERRIDE;
    void cancelRequest() Q_DECL_OVERRIDE;
    void finishRequest() Q_DECL_OVERRIDE;

private Q_SLOTS:
    void parentSizeChanged();

public:
    QObject *adapter() const;

private:
    friend class InProcessUiViewPrivate;
    Q_INVOKABLE void sendResponseHelper(const Sailfish::Secrets::Result &result,
                                        const Sailfish::Secrets::UiResponse &response);
    QQuickItem *m_childItem;
    InProcessUiViewPrivate *m_adapter;
};

} // namespace Plugin

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_QML_INPROCESSUIVIEW_H
