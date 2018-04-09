/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_COLLECTIONNAMESREQUEST_P_H
#define LIBSAILFISHSECRETS_COLLECTIONNAMESREQUEST_P_H

#include "Secrets/secretsglobal.h"
#include "Secrets/secretmanager.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Secrets {

class CollectionNamesRequestPrivate
{
    Q_DISABLE_COPY(CollectionNamesRequestPrivate)

public:
    explicit CollectionNamesRequestPrivate();

    QPointer<Sailfish::Secrets::SecretManager> m_manager;
    QString m_storagePluginName;
    QStringList m_collectionNames;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Secrets::Request::Status m_status;
    Sailfish::Secrets::Result m_result;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_COLLECTIONNAMESREQUEST_P_H
