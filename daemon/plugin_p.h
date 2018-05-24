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

#include "Secrets/Plugins/extensionplugins.h"
#include "Crypto/Plugins/extensionplugins.h"

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace ApiImpl {

namespace PluginHelpers {

struct PluginInfo {
    bool canUse;
    QString name;

    PluginInfo(bool c, QString n) : canUse(c), name(n) { }
};

template <typename TPlugin>
inline PluginInfo matchAnyPlugin(QObject *obj) {
    TPlugin *pluginInstance = qobject_cast<TPlugin*>(obj);
    if (pluginInstance != Q_NULLPTR) {
        auto name = pluginInstance->name();
        return PluginInfo(true, name);
    }

    return PluginInfo(false, "");
}

template <typename TPlugin, typename ... TOtherPlugins>
inline typename std::enable_if<sizeof...(TOtherPlugins), PluginInfo>::type matchAnyPlugin(QObject *obj) {
    auto match = matchAnyPlugin<TPlugin>(obj);
    if (match.canUse) {
        return match;
    }

    return matchAnyPlugin<TOtherPlugins...>(obj);
}

template <typename TPlugin>
inline PluginInfo matchAllPlugins(QObject *obj) {
    return matchAnyPlugin<TPlugin>(obj);
}

template <typename TPlugin, typename ... TOtherPlugins>
inline typename std::enable_if<sizeof...(TOtherPlugins), PluginInfo>::type matchAllPlugins(QObject *obj) {
    auto match = matchAnyPlugin<TPlugin>(obj);
    if (!match.canUse) {
        return match;
    }

    return matchAllPlugins<TOtherPlugins...>(obj);
}



} // namespace PluginHelpers

class PluginManager
{
private:
    QMap<QString, QObject*> m_plugins;
    bool m_autotestMode;

    explicit PluginManager();
    QVector<QPluginLoader *> loadPluginFiles();
    void addPlugin(QPluginLoader *loader, const PluginHelpers::PluginInfo &info, QObject *obj);

public:
    static PluginManager *instance();

    template<typename ... TPlugins>
    void loadPlugins() {
        auto loaders = loadPluginFiles();
        for (auto *loader : loaders) {
            auto *obj = loader->instance();
            auto info = PluginHelpers::matchAnyPlugin<TPlugins...>(obj);

            addPlugin(loader, info, obj);
        }
    }

    template<typename TPlugin>
    QMap<QString, TPlugin*> getPlugins() const {
        QMap<QString, TPlugin*> result;

        for (auto it = m_plugins.begin(); it != m_plugins.end(); ++it) {
            TPlugin *plugin = qobject_cast<TPlugin*>(it.value());
            if (plugin) {
                result.insert(it.key(), plugin);
            }
        }

        return result;
    }

    template<typename ... TPlugins>
    QMap<QString, QObject*> getMultiPlugins() const {
        QMap<QString, QObject*> result;

        for (auto it = m_plugins.begin(); it != m_plugins.end(); ++it) {
            auto info = PluginHelpers::matchAllPlugins<TPlugins...>(it.value());
            if (info.canUse) {
                result.insert(it.key(), it.value());
            }
        }

        return result;
    }

}; // class PluginManager

} // ApiImpl

} // Daemon

} // Secrets

} // Sailfish

#endif // SAILFISHSECRETS_DAEMON_PLUGIN_P_H
