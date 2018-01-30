/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtCore/QCoreApplication>
#include <QtCore/QLoggingCategory>
#include <QtCore/QDir>

#include "controller_p.h"
#include "logging_p.h"

Q_LOGGING_CATEGORY(lcSailfishSecretsDaemon, "org.sailfishos.secrets.daemon", QtWarningMsg)
Q_LOGGING_CATEGORY(lcSailfishSecretsDaemonDBus, "org.sailfishos.secrets.daemon.dbus", QtWarningMsg)

Q_LOGGING_CATEGORY(lcSailfishCryptoDaemon, "org.sailfishos.crypto.daemon", QtWarningMsg)
Q_LOGGING_CATEGORY(lcSailfishCryptoDaemonDBus, "org.sailfishos.crypto.daemon.dbus", QtWarningMsg)

Q_DECL_EXPORT int main(int argc, char *argv[])
{
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

    Sailfish::Secrets::Daemon::Controller controller(secretsPluginDir, cryptoPluginDir, autotestMode);
    if (controller.isValid()) {
        return app.exec();
    }
    return 1;
}
