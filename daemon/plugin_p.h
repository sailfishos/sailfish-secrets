/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_DAEMON_PLUGIN_P_H
#define SAILFISHSECRETS_DAEMON_PLUGIN_P_H

#include <QtCore/QPluginLoader>
#include <QtCore/QString>
#include <QtCore/QMap>
#include <QtCore/QLoggingCategory>

#include "Secrets/extensionplugins.h"
#include "Crypto/extensionplugins.h"

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace ApiImpl {

class PluginHelper : public QPluginLoader
{
    Q_OBJECT
    Q_PROPERTY(PluginHelper::FailureType failureType READ failureType NOTIFY failureTypeChanged)

public:
    PluginHelper(const QString &fileName, const bool autotestMode, const QVariantMap &initialisationParameters);
    ~PluginHelper();

    enum FailureType {
        NoFailure = 0,
        PluginLoadFailure,
        PluginTypeFailure,
        DuplicateNameFailure,
        AutotestModeFailure
    };
    Q_ENUM(FailureType)
    FailureType failureType() const;

    template <typename Plugin>
    Plugin* storeAs(QObject *obj, QMap<QString, Plugin*> *store,
                    const QLoggingCategory &category())
    {
        if (!obj) {
            m_failureType = PluginLoadFailure;
            emit failureTypeChanged();
            return 0;
        }
        Plugin *plugin = qobject_cast<Plugin*>(obj);
        if (!plugin) {
            m_failureType = PluginTypeFailure;
            emit failureTypeChanged();
            return 0;
        }
        if (plugin->name().isEmpty() || store->contains(plugin->name())) {
            qCDebug(category) << "ignoring plugin:" << fileName() << "with duplicate name:" << plugin->name();
            unload();
            m_failureType = DuplicateNameFailure;
            emit failureTypeChanged();
            return 0;
        }
        if (plugin->name().endsWith(QStringLiteral(".test"), Qt::CaseInsensitive) != m_autotestMode) {
            qCDebug(category) << "ignoring plugin:" << fileName() << "due to mode";
            unload();
            m_failureType = AutotestModeFailure;
            emit failureTypeChanged();
            return 0;
        }
        qCDebug(category) << "loading plugin:" << fileName() << "with name:" << plugin->name();
        qCDebug(category) << "initialising plugin:" << fileName();

        if (!plugin->initialise(m_initialisationParameters)) {
            qCWarning(category) << "Could not initialize the plugin:" << fileName();
        }

        store->insert(plugin->name(), plugin);
        return plugin;
    }

    void reportFailure(const QLoggingCategory &category());

Q_SIGNALS:
    void failureTypeChanged();

private:
    FailureType m_failureType;
    bool m_autotestMode;
    QVariantMap m_initialisationParameters;
};

} // ApiImpl

} // Daemon

} // Secrets

} // Sailfish

#endif // SAILFISHSECRETS_DAEMON_PLUGIN_P_H
