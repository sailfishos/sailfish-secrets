/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin_p.h"
#include <QtCore/QCoreApplication>
#include <QtCore/QDir>

using namespace Sailfish::Secrets;

Q_LOGGING_CATEGORY(lcSailfishSecretsPlugins, "org.sailfishos.secrets.plugins", QtWarningMsg)

static Daemon::ApiImpl::PluginManager *pluginManagerInstance = Q_NULLPTR;

static bool isAutotestMode()
{
    auto &app = *QCoreApplication::instance();
    auto args = app.arguments();
    bool autotestMode = false;

    if (args.size() > 1 &&
        (args[1] == QLatin1String("test") ||
         args[1] == QLatin1String("-test") ||
         args[1] == QLatin1String("--test"))) {
        autotestMode = true;
    }

    return autotestMode;
}

Daemon::ApiImpl::PluginManager::PluginManager()
    : m_autotestMode(isAutotestMode())
{
}

Daemon::ApiImpl::PluginManager *Daemon::ApiImpl::PluginManager::instance()
{
    if (!pluginManagerInstance) {
        pluginManagerInstance = new PluginManager();
    }

    return pluginManagerInstance;
}

QVector<QPluginLoader*> Daemon::ApiImpl::PluginManager::loadPluginFiles()
{
    QVector<QPluginLoader*> result;
    QStringList paths = QCoreApplication::libraryPaths();

    Q_FOREACH(const QString &path, paths) {
        // Don't enumerate /usr/bin
        if (path == "/usr/bin")
            continue;

        QDir dir(path);
        Q_FOREACH (const QFileInfo &file, dir.entryInfoList(QDir::Files | QDir::NoDot | QDir::NoDotDot, QDir::Name)) {
            const QString fileName = file.fileName();

            // Don't even try to load files which don't look like libraries
            if (!fileName.startsWith("lib") || !fileName.contains(".so")) {
                continue;
            }

            // load the plugin
            auto *loader = new QPluginLoader(file.absoluteFilePath());
            if (!loader->load()) {
                qCWarning(lcSailfishSecretsPlugins) << "Could not load plugin:" << loader->fileName();
                delete loader;
                continue;
            }

            result.append(loader);
        }
    }

    return result;
}

bool Daemon::ApiImpl::PluginManager::addPlugin(QPluginLoader *loader, const PluginHelpers::PluginInfo &info, QObject *obj)
{
    bool use = true;

    if (!info.canUse) {
        qCWarning(lcSailfishSecretsPlugins) << "Not a usable crypto or secrets plugin:" << loader->fileName();
        use = false;
    }

    if (m_plugins.contains(info.name)) {
        qCWarning(lcSailfishSecretsPlugins) << "Not adding plugin with duplicate name:" << loader->fileName();
        use = false;
    }

    if (info.name.endsWith(QStringLiteral(".test"), Qt::CaseInsensitive) != m_autotestMode) {
        qCWarning(lcSailfishSecretsPlugins) << "Not adding plugin because of testing mode mismatch:" << loader->fileName();
        use = false;
    }

    if (!use) {
        if (!loader->unload()) {
            qCWarning(lcSailfishSecretsPlugins) << "Could not unload plugin:" << loader->fileName();
        }
    } else {
        qCDebug(lcSailfishSecretsPlugins) << "Adding plugin:" << info.name << "from:" << loader->fileName();
        m_plugins.insert(info.name, obj);
    }

    delete loader;
    return use;
}
