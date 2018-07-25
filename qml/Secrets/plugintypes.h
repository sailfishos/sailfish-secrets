/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_QML_PLUGINTYPES_H
#define SAILFISHSECRETS_QML_PLUGINTYPES_H

#include "Secrets/result.h"
#include "Secrets/secret.h"
#include "Secrets/interactionparameters.h"
#include "Secrets/interactionresponse.h"
#include "Secrets/secretmanager.h"

#include "Secrets/plugininforequest.h"
#include "Secrets/interactionrequest.h"
#include "Secrets/collectionnamesrequest.h"
#include "Secrets/createcollectionrequest.h"
#include "Secrets/deletecollectionrequest.h"
#include "Secrets/storesecretrequest.h"
#include "Secrets/storedsecretrequest.h"
#include "Secrets/findsecretsrequest.h"
#include "Secrets/deletesecretrequest.h"
#include "Secrets/lockcoderequest.h"

#include <QQmlExtensionPlugin>
#include <QQmlParserStatus>
#include <QQmlEngine>

namespace Sailfish {

namespace Secrets {

namespace Plugin {

class SecretsPlugin : public QQmlExtensionPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "Sailfish.Secrets")

public:
    void initializeEngine(QQmlEngine *, const char *);
    virtual void registerTypes(const char *uri);
};

class SecretManager : public Sailfish::Secrets::SecretManager
{
    Q_OBJECT
    Q_PROPERTY(QString inAppAuthenticationPluginName READ inAppAuthenticationPluginName CONSTANT)
    Q_PROPERTY(QString defaultAuthenticationPluginName READ defaultAuthenticationPluginName CONSTANT)
    Q_PROPERTY(QString defaultStoragePluginName READ defaultStoragePluginName CONSTANT)
    Q_PROPERTY(QString defaultEncryptionPluginName READ defaultEncryptionPluginName CONSTANT)
    Q_PROPERTY(QString defaultEncryptedStoragePluginName READ defaultEncryptedStoragePluginName CONSTANT)

public:
    SecretManager(QObject *parent = Q_NULLPTR);
    ~SecretManager() Q_DECL_OVERRIDE;

    // QML API - allow clients to access static properties
    QString inAppAuthenticationPluginName() const;
    QString defaultAuthenticationPluginName() const;
    QString defaultStoragePluginName() const;
    QString defaultEncryptionPluginName() const;
    QString defaultEncryptedStoragePluginName() const;

    // QML API - allow clients to construct "uncreatable" value types
    Q_INVOKABLE Result constructResult() const;
    Q_INVOKABLE Secret constructSecret() const;
    Q_INVOKABLE InteractionParameters constructInteractionParameters() const;
    Q_INVOKABLE InteractionResponse constructInteractionResponse() const;
    Q_INVOKABLE Sailfish::Secrets::Secret::FilterData constructFilterData(const QVariantMap &v) const;
};

}

}

}

#endif // SAILFISHSECRETS_QML_PLUGINTYPES_H
