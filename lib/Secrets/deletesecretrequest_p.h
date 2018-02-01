/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_DELETESECRETREQUEST_P_H
#define LIBSAILFISHSECRETS_DELETESECRETREQUEST_P_H

#include "Secrets/secretsglobal.h"
#include "Secrets/secretmanager.h"
#include "Secrets/secret.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Secrets {

class DeleteSecretRequestPrivate
{
    Q_DISABLE_COPY(DeleteSecretRequestPrivate)

public:
    explicit DeleteSecretRequestPrivate(Sailfish::Secrets::SecretManager *manager);

    QPointer<Sailfish::Secrets::SecretManager> m_manager;
    Sailfish::Secrets::Secret::Identifier m_identifier;
    Sailfish::Secrets::SecretManager::UserInteractionMode m_userInteractionMode;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Secrets::Request::Status m_status;
    Sailfish::Secrets::Result m_result;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_DELETESECRETREQUEST_P_H
