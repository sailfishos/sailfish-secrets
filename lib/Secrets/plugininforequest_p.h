/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_PLUGININFOREQUEST_P_H
#define LIBSAILFISHSECRETS_PLUGININFOREQUEST_P_H

#include "Secrets/secretsglobal.h"
#include "Secrets/secretmanager.h"
#include "Secrets/secret.h"
#include "Secrets/extensionplugins.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Secrets {

class PluginInfoRequestPrivate
{
    Q_DISABLE_COPY(PluginInfoRequestPrivate)

public:
    explicit PluginInfoRequestPrivate();

    QPointer<Sailfish::Secrets::SecretManager> m_manager;
    QVector<Sailfish::Secrets::StoragePluginInfo> m_storagePlugins;
    QVector<Sailfish::Secrets::EncryptionPluginInfo> m_encryptionPlugins;
    QVector<Sailfish::Secrets::EncryptedStoragePluginInfo> m_encryptedStoragePlugins;
    QVector<Sailfish::Secrets::AuthenticationPluginInfo> m_authenticationPlugins;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Secrets::Request::Status m_status;
    Sailfish::Secrets::Result m_result;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_PLUGININFOREQUEST_P_H
