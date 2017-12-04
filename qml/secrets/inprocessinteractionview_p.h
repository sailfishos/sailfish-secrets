/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_QML_INPROCESSUIVIEW_P_H
#define SAILFISHSECRETS_QML_INPROCESSUIVIEW_P_H

#include "inprocessinteractionview.h"

#include "Secrets/secretmanager.h"
#include "Secrets/interactionrequest.h"

#include <QtCore/QObject>
#include <QtCore/QStringList>
#include <QtCore/QUrl>

#include <QtDebug>

namespace Sailfish {

namespace Secrets {

namespace Plugin {

// We have several different types of UI requests:
// 1) request confirmation to delete a secret
// 2) request confirmation to update/overwrite a secret
// 3) request the device lock code to verify the user
// 4) request a password (to use as an encryption/decryption key)

// So, the result will be one of:
// a) confirmationReceived (for 1/2/3)
// b) passwordReceived (for 4)

class InProcessInteractionView;
class InProcessInteractionViewPrivate : public QObject
{
    Q_OBJECT
    Q_PROPERTY(int confirmation READ confirmation WRITE setConfirmation NOTIFY confirmationChanged)
    Q_PROPERTY(QString password READ password WRITE setPassword NOTIFY passwordChanged)
    Q_PROPERTY(int requestType READ requestType NOTIFY requestTypeChanged)

public:
    InProcessInteractionViewPrivate(InProcessInteractionView *parent = Q_NULLPTR);

    int confirmation() const { return m_confirmation; }
    void setConfirmation(int v) {
        if (m_confirmation != v) {
            m_confirmation = v;
            emit confirmationChanged();
            if (m_ready && (m_requestType == Sailfish::Secrets::InteractionRequest::DeleteSecretConfirmationRequest
                            || m_requestType == Sailfish::Secrets::InteractionRequest::ModifySecretConfirmationRequest
                            || m_requestType == Sailfish::Secrets::InteractionRequest::UserVerificationConfirmationRequest)) {
                sendResponse(v == Sailfish::Secrets::Plugin::InProcessInteractionView::Allow);
                m_confirmation = Sailfish::Secrets::Plugin::InProcessInteractionView::Unknown; // reset.
            }
        }
    }

    QString password() const { return m_password; }
    void setPassword(const QString &v) {
        if (m_password != v) {
            m_password = v;
            emit passwordChanged();
            if (m_ready && m_requestType == Sailfish::Secrets::InteractionRequest::AuthenticationKeyRequest) {
                sendResponse(v.toUtf8());
                m_password.clear(); // reset.
            }
        }
    }

    int requestType() const { return m_requestType; }
    void setRequestType(Sailfish::Secrets::InteractionRequest::Type type) { m_ready = true; m_requestType = type; emit requestTypeChanged(); }

Q_SIGNALS:
    void confirmationChanged();
    void passwordChanged();
    void requestTypeChanged();

private Q_SLOTS:
    void sendResponse(bool confirmed);
    void sendResponse(const QByteArray &authenticationKey);

private:
    friend class InProcessInteractionView;
    InProcessInteractionView *m_parent;
    SecretManager *m_secretManager;
    QString m_password;
    int m_requestType;
    int m_confirmation;
    bool m_ready;
};

} // namespace Plugin

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_QML_INPROCESSUIVIEW_P_H
