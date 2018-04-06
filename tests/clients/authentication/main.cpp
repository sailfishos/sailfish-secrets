/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Andrew den Exter <andrew.den.exter@jolla.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QPluginLoader>
#include <QtCore/QVarLengthArray>

#include "SecretsPluginApi/extensionplugins.h"

#include <unistd.h>

using namespace Sailfish::Secrets;

Q_DECL_EXPORT int main(int argc, char *argv[])
{
    if (argc < 2) {
        // A minimum of two arguments are required. Show usage
    } else if (qstrcmp(argv[1], "--invoked") != 0) {
        // Run the client as a silica boosted application to inject it into the graphical login session.
        QVarLengthArray<char *, 8> arguments;
        char invoker[] = "/usr/bin/invoker";
        char type[] = "--type=silica-qt5";
        char invoked[] = "--invoked";
        arguments.append(invoker);
        arguments.append(type);
        arguments.append(argv[0]);
        arguments.append(invoked);
        for (int i = 1; i < argc; ++i) {
            arguments.append(argv[i]);
        }
        arguments.append(nullptr);
        execve(invoker, arguments.data(), environ);
    } else if (argc == 3 && qstrcmp(argv[2], "--authenticate") == 0) {
        QCoreApplication application(argc, argv);

        // There's no internal usage of the authentication option yet, load the test plugin and access it that way.
        QPluginLoader plugin(QStringLiteral("/usr/lib/Sailfish/Secrets/libsailfishsecrets-testpasswordagentauth.so"));
        if (const auto authenticator = qobject_cast<AuthenticationPlugin *>(plugin.instance())) {
            Result result = authenticator->beginAuthentication(getpid(), 0);

            if (result.code() == Result::Pending) {
                QObject::connect(
                            authenticator,
                            &AuthenticationPlugin::authenticationCompleted,
                            [&](uint, qint64, const Result &asyncResult) {
                    result = asyncResult;
                    application.exit();
                });
                application.exec();
            }

            if (result.code() == Result::Succeeded) {
                qInfo() << "Permission given";
                return EXIT_SUCCESS;
            } else if (result.errorCode() == Result::NoError) {
                qInfo() << "Permission rejected";
            } else {
                qWarning() << "Authentication error" << result.errorMessage();
            }
        } else {
            qWarning() << "Plugin loading error:" << plugin.errorString();
        }
        return EXIT_FAILURE;
    }

    qInfo() << "Usage:" << argv[0] << "--authenticate";

    return EXIT_FAILURE;
}

