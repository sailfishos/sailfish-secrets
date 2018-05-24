/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtCore/QCoreApplication>
#include <QtCore/QLoggingCategory>
#include <QtCore/QDir>
#include <QtCore/QTranslator>

#include "controller_p.h"
#include "logging_p.h"
#include "plugin_p.h"

#include "Crypto/Plugins/extensionplugins.h"
#include "Secrets/Plugins/extensionplugins.h"

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

    QScopedPointer<QTranslator> engineeringEnglish(new QTranslator);
    engineeringEnglish->load("sailfish-secrets_eng_en", "/usr/share/translations");
    QScopedPointer<QTranslator> translator(new QTranslator);
    translator->load(QLocale(), "sailfish-secrets", "-", "/usr/share/translations");

    app.installTranslator(engineeringEnglish.data());
    app.installTranslator(translator.data());

    Sailfish::Secrets::Daemon::ApiImpl::PluginManager::instance()->loadPlugins<Sailfish::Secrets::AuthenticationPlugin,
                                                                               Sailfish::Secrets::EncryptedStoragePlugin,
                                                                               Sailfish::Secrets::StoragePlugin,
                                                                               Sailfish::Secrets::EncryptionPlugin,
                                                                               Sailfish::Crypto::CryptoPlugin>();

    Sailfish::Secrets::Daemon::Controller controller(autotestMode);
    if (controller.isValid()) {
        return app.exec();
    }
    return 1;
}
