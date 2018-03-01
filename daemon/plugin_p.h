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

class PluginHelper: public QPluginLoader
{
    Q_OBJECT

 public:
    PluginHelper(const QString &fileName, bool autotestMode)
        : QPluginLoader(fileName), m_autotestMode(autotestMode) {};
    ~PluginHelper() {};

    template <typename Plugin>
        Plugin* storeAs(QObject *obj, QMap<QString, Plugin*> *store,
                        const QLoggingCategory &category())
        {
            Plugin *plugin = qobject_cast<Plugin*>(obj);
            if (!plugin)
                return 0;
            if (plugin->name().isEmpty() || store->contains(plugin->name())) {
                qCDebug(category) << "ignoring plugin:" << fileName() << "with duplicate name:" << plugin->name();
                unload();
                return 0;
            }
            if (plugin->name().endsWith(QStringLiteral(".test"), Qt::CaseInsensitive) != m_autotestMode) {
                qCDebug(category) << "ignoring plugin:" << fileName() << "due to mode";
                unload();
                return 0;
            }
            qCDebug(category) << "loading plugin:" << fileName() << "with name:" << plugin->name();
            store->insert(plugin->name(), plugin);
            return plugin;
        };

    void reportFailure(const QLoggingCategory &category())
    {
        if (!isLoaded()) {
            qCWarning(category) << "cannot load plugin:" << fileName() << errorString();
            return;
        } else {
            qCWarning(category) << "ignoring plugin:" << fileName() << "- not a valid plugin or Qt version mismatch";
            unload();
            return;
        }
    }

 private:
    bool m_autotestMode;
};

#endif // SAILFISHSECRETS_DAEMON_PLUGIN_P_H
