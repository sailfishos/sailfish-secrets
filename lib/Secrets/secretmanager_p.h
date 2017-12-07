/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_SECRETMANAGER_P_H
#define LIBSAILFISHSECRETS_SECRETMANAGER_P_H

#include "Secrets/secretmanager.h"
#include "Secrets/secretsdaemonconnection.h"
#include "Secrets/extensionplugins.h"
#include "Secrets/interactionview.h"
#include "Secrets/interactionservice_p.h"

#include <QtDBus/QDBusInterface>

#include <QtCore/QObject>

namespace Sailfish {

namespace Secrets {

class SecretManager;
class SecretManagerPrivate : public QObject
{
    Q_OBJECT

public:
    SecretManagerPrivate(SecretManager *parent = Q_NULLPTR);
    ~SecretManagerPrivate();

    // ui communication happens via a peer-to-peer dbus connection in which the sailfishsecretsd process becomes the client.
    void handleUiConnection(const QDBusConnection &connection);

    // register the ui service if required, and return it's address.
    Sailfish::Secrets::Result registerInteractionService(Sailfish::Secrets::SecretManager::UserInteractionMode mode, QString *address);

private:
    friend class SecretManager;
    friend class InteractionService;
    SecretManager *m_parent;
    InteractionService *m_uiService;
    InteractionView *m_interactionView;
    Sailfish::Secrets::SecretsDaemonConnection *m_secrets;
    QDBusInterface *m_interface;
    bool m_initialised;

    QMap<QString, Sailfish::Secrets::StoragePluginInfo> m_storagePluginInfo;
    QMap<QString, Sailfish::Secrets::EncryptionPluginInfo> m_encryptionPluginInfo;
    QMap<QString, Sailfish::Secrets::EncryptedStoragePluginInfo> m_encryptedStoragePluginInfo;
    QMap<QString, Sailfish::Secrets::AuthenticationPluginInfo> m_authenticationPluginInfo;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_SECRETMANAGER_P_H
