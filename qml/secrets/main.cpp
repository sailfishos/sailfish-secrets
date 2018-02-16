/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "applicationinteractionview.h"

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
        qmlRegisterType<Sailfish::Secrets::Plugin::ApplicationInteractionView>(uri, 1, 0, "ApplicationInteractionView");
    }
};

#include "main.moc"
