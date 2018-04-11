/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtCore/QCoreApplication>
#include <QtCore/QLoggingCategory>
#include <QtCore/QDir>

#include <QTimer>
#include <systemd/sd-daemon.h>
#include <getdef.h>

#include "controller_p.h"
#include "logging_p.h"
#include "plugin_p.h"
#include "Crypto/extensionplugins.h"
#include "Secrets/extensionplugins.h"

Q_LOGGING_CATEGORY(lcSailfishSecretsDaemon, "org.sailfishos.secrets.daemon", QtWarningMsg)
Q_LOGGING_CATEGORY(lcSailfishSecretsDaemonDBus, "org.sailfishos.secrets.daemon.dbus", QtWarningMsg)

Q_LOGGING_CATEGORY(lcSailfishCryptoDaemon, "org.sailfishos.crypto.daemon", QtWarningMsg)
Q_LOGGING_CATEGORY(lcSailfishCryptoDaemonDBus, "org.sailfishos.crypto.daemon.dbus", QtWarningMsg)

Q_DECL_EXPORT int main(int argc, char *argv[])
{
    // HACK: not part of actual session so hardcode the session bus socket
    int uid_min = getdef_num("UID_MIN", -1);
    QString bus_address = QString("unix:path=/run/user/%1/dbus/user_bus_socket").arg(uid_min);
    QByteArray bus_address_utf8 = bus_address.toUtf8();
    qputenv("DBUS_SESSION_BUS_ADDRESS", bus_address_utf8);

    QString xdg_runtime_dir = QString("/run/user/%1").arg(uid_min);
    QByteArray xdg_runtime_dir_utf8 = xdg_runtime_dir.toUtf8();
    qputenv("XDG_RUNTIME_DIR", xdg_runtime_dir_utf8);

    const QString secretsPluginDir = QLatin1String("/usr/lib/Sailfish/Secrets/");
    const QString cryptoPluginDir = QLatin1String("/usr/lib/Sailfish/Crypto/");
    QCoreApplication::addLibraryPath(secretsPluginDir);
    QCoreApplication::addLibraryPath(cryptoPluginDir);
    QCoreApplication app(argc, argv);

    bool autotestMode = false;
    QStringList args = app.arguments();
    if (args.size() > 1 &&
            (args[1] == QLatin1String("test") ||
             args[1] == QLatin1String("-test") ||
             args[1] == QLatin1String("--test"))) {
        autotestMode = true;
    }

    Sailfish::Secrets::Daemon::ApiImpl::PluginManager::instance()->loadPlugins<Sailfish::Secrets::AuthenticationPlugin,
                                                                               Sailfish::Secrets::EncryptedStoragePlugin,
                                                                               Sailfish::Secrets::StoragePlugin,
                                                                               Sailfish::Secrets::EncryptionPlugin,
                                                                               Sailfish::Crypto::CryptoPlugin>();

    Sailfish::Secrets::Daemon::Controller controller(autotestMode);
    if (controller.isValid()) {
        if (app.arguments().contains(QStringLiteral("--systemd"))) {
            QTimer::singleShot(0, []() {
                sd_notify(0, "READY=1");
            });
        }

        return app.exec();
    }
    return 1;
}
