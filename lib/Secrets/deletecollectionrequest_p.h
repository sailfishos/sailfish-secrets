/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_DELETECOLLECTIONREQUEST_P_H
#define LIBSAILFISHSECRETS_DELETECOLLECTIONREQUEST_P_H

#include "Secrets/secretsglobal.h"
#include "Secrets/createcollectionrequest.h"
#include "Secrets/secretmanager.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Secrets {

class DeleteCollectionRequestPrivate
{
    Q_DISABLE_COPY(DeleteCollectionRequestPrivate)

public:
    explicit DeleteCollectionRequestPrivate();

    QPointer<Sailfish::Secrets::SecretManager> m_manager;
    QString m_collectionName;
    Sailfish::Secrets::SecretManager::UserInteractionMode m_userInteractionMode;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Secrets::Request::Status m_status;
    Sailfish::Secrets::Result m_result;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_DELETECOLLECTIONREQUEST_P_H
