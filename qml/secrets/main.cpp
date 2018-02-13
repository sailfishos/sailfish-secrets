/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "applicationinteractionview.h"

#include "Secrets/interactionparameters.h"

#include <QQmlExtensionPlugin>
#include <QQmlParserStatus>
#include <QQmlEngine>

class InteractionViewPlugin : public QQmlExtensionPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "Sailfish.Secrets")

public:
    void initializeEngine(QQmlEngine *, const char *)
    {
    }

    virtual void registerTypes(const char *uri)
    {
        qRegisterMetaType<Sailfish::Secrets::InteractionParameters>("InteractionParameters");
        qRegisterMetaType<Sailfish::Secrets::InteractionParameters::InputType>("InteractionParameters::InputType");
        qRegisterMetaType<Sailfish::Secrets::InteractionParameters::EchoMode>("InteractionParameters::EchoMode");
        qRegisterMetaType<Sailfish::Secrets::InteractionParameters::Operation>("InteractionParameters::Operation");
        QMetaType::registerComparators<Sailfish::Secrets::InteractionParameters>();

        qmlRegisterUncreatableType<Sailfish::Secrets::InteractionParameters>(uri, 1, 0, "InteractionParameters", QLatin1String("InteractionParameters objects cannot be constructed directly in QML"));
        qmlRegisterType<Sailfish::Secrets::Plugin::ApplicationInteractionView>(uri, 1, 0, "ApplicationInteractionView");
    }
};

#include "main.moc"
