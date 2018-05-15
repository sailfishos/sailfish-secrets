/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QStringList>
#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtDebug>

#include "commandhelper.h"

void customMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    QByteArray localMsg = msg.toLocal8Bit();
    switch (type) {
    case QtDebugMsg:
        fprintf(stdout, "%s\n", localMsg.constData());
        break;
    case QtInfoMsg:
        fprintf(stdout, "%s\n", localMsg.constData());
        break;
    case QtWarningMsg:
        if (!context.file) {
            fprintf(stderr, "%s\n", localMsg.constData());
        } else if (!context.function) {
            fprintf(stderr, "Warning: %s (%s:%u)\n", localMsg.constData(), context.file, context.line);
        } else {
            fprintf(stderr, "Warning: %s (%s:%u, %s)\n", localMsg.constData(), context.file, context.line, context.function);
        }
        break;
    case QtCriticalMsg:
        fprintf(stderr, "Critical: %s (%s:%u, %s)\n", localMsg.constData(), context.file, context.line, context.function);
        break;
    case QtFatalMsg:
        fprintf(stderr, "Fatal: %s (%s:%u, %s)\n", localMsg.constData(), context.file, context.line, context.function);
        abort();
    }
}

Q_DECL_EXPORT int main(int argc, char *argv[])
{
    qInstallMessageHandler(customMessageHandler);
    QCoreApplication app(argc, argv);
    QStringList args(app.arguments());
    const QString appName = args.takeFirst();

    const QMap<QString, QString> paramDescriptions {
        {"--list-algorithms", "List supported algorithms for Crypto keys" },
        {"--list-digests", "List supported digests for sign and verify operations" },
        {"--list-plugins", "List available plugins, organized by category" },
        {"--list-collections", "List available collections (of secrets or keys) stored by a given storage plugin" },
        {"--create-collection", "Create a collection in a particular storage plugin, encrypted by a particular encryption plugin"},
        {"--delete-collection", "Delete a collection from a storage plugin" },
        {"--list-secrets", "List the secrets stored by a storage plugin, optionally limited to a single collection" },
        {"--store-standalone-secret", "Store a standalone secret in a particular storage plugin, encrypted by a particular encryption plugin" },
        {"--store-collection-secret", "Store a secret in a particular collection" },
        {"--get-standalone-secret", "Retrieve a specific standalone secret from the given storage plugin" },
        {"--get-collection-secret", "Retrieve a specific secret from the given collection within the given storage plugin" },
        {"--delete-standalone-secret", "Delete a particular standalone secret from a given storage plugin" },
        {"--delete-collection-secret", "Delete a particular secret from a given collection in a given storage plugin" },
        {"--list-keys", "List the Crypto keys stored by a paritcular storage plugin, optionally limited to a single collection" },
        {"--generate-stored-key", "Generate and store a key within a particular collection of a given storage plugin" },
        {"--derive-stored-key", "Derive a key from a user passphrase and store it within a particular collection of a given storage plugin" },
        {"--import-stored-key", "Import a key from a data file and store it within a particular collection of a given storage plugin" },
        {"--delete-key", "Delete a particular Crypto key from a given collection of a given storage plugin" },
        {"--sign", "Sign a particular file with a specified key, output to stdout" },
        {"--verify", "Verify that a particular signature file contains a valid signature with the specified key for the given input file" },
        {"--encrypt", "Encrypt a particular file with the specified key, output to stdout" },
        {"--decrypt", "Decrypt a particular file with the specified key, output to stdout" },
    };

    const QMap<QString, QString> paramOptions {
        {"--list-collections", "<storagePlugin>" },
        {"--create-collection", "[--devicelock] <storagePlugin> <collectionName> [<encryptionPlugin>]"},
        {"--delete-collection", "<storagePlugin> <collectionName>" },
        {"--list-secrets", "<storagePlugin> [<collectionName>]" },
        {"--store-standalone-secret", "[--devicelock] <storagePlugin> <encryptionPlugin> <secretName> [<secretData>]" },
        {"--store-collection-secret", "<storagePlugin> <collectionName> <secretName> [<secretData>]" },
        {"--get-standalone-secret", "<storagePlugin> <secretName>" },
        {"--get-collection-secret", "<storagePlugin> <collectionName> <secretName>" },
        {"--delete-standalone-secret", "<storagePlugin> <secretName>" },
        {"--delete-collection-secret", "<storagePlugin> <collectionName> <secretName>" },
        {"--list-keys", "<storagePlugin> [<collectionName>]" },
        {"--generate-stored-key", "<cryptoPlugin> <storagePlugin> <collectionName> <keyName> <algorithm> <size>" },
        {"--derive-stored-key", "<cryptoPlugin> <storagePlugin> <collectionName> <keyName> <algorithm> <size> <saltDataFile>" },
        {"--import-stored-key", "<cryptoPlugin> <storagePlugin> <collectionName> <keyName> <importFile>" },
        {"--delete-key", "<storagePlugin> <collectionName> <keyName>" },
        {"--sign", "<cryptoPlugin> <storagePlugin> <collectionName> <keyName> <digest> <fileName>" },
        {"--verify", "<cryptoPlugin> <storagePlugin> <collectionName> <keyName> <digest> <fileName> <signatureFileName>" },
        {"--encrypt", "<cryptoPlugin> <storagePlugin> <collectionName> <keyName> <fileName>" },
        {"--decrypt", "<cryptoPlugin> <storagePlugin> <collectionName> <keyName> <fileName>" },
    };

    const QMap<QString, int> paramOptionsMin {
        {"--list-algorithms", 0 },
        {"--list-digests", 0 },
        {"--list-plugins", 0 },
        {"--list-collections", 1 },
        {"--create-collection", 2 },
        {"--delete-collection", 2 },
        {"--list-secrets", 1 },
        {"--store-standalone-secret", 3 },
        {"--store-collection-secret", 3 },
        {"--get-standalone-secret", 2 },
        {"--get-collection-secret", 3 },
        {"--delete-standalone-secret", 2 },
        {"--delete-collection-secret", 3 },
        {"--list-keys", 1 },
        {"--generate-stored-key", 6 },
        {"--derive-stored-key", 7 },
        {"--import-stored-key", 5 },
        {"--delete-key", 3 },
        {"--sign", 6 },
        {"--verify", 7 },
        {"--encrypt", 5 },
        {"--decrypt", 5 },
    };

    const QMap<QString, int> paramOptionsMax {
        {"--list-algorithms", 0 },
        {"--list-digests", 0 },
        {"--list-plugins", 0 },
        {"--list-collections", 1 },
        {"--create-collection", 4 },
        {"--delete-collection", 2 },
        {"--list-secrets", 2 },
        {"--store-standalone-secret", 5 },
        {"--store-collection-secret", 4 },
        {"--get-standalone-secret", 2 },
        {"--get-collection-secret", 3 },
        {"--delete-standalone-secret", 2 },
        {"--delete-collection-secret", 3 },
        {"--list-keys", 2 },
        {"--generate-stored-key", 6 },
        {"--derive-stored-key", 7 },
        {"--import-stored-key", 5 },
        {"--delete-key", 3 },
        {"--sign", 6 },
        {"--verify", 7 },
        {"--encrypt", 5 },
        {"--decrypt", 5 },
    };

    const QMap<QString, QString> paramExamples {
        {"--list-algorithms", "" },
        {"--list-digests", "" },
        {"--list-plugins", "" },
        {"--list-collections", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher" },
        {"--create-collection", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection" },
        {"--delete-collection", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection" },
        {"--list-secrets", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection" },
        {"--store-standalone-secret", "org.sailfishos.secrets.plugin.storage.sqlite org.sailfishos.secrets.plugin.encryption.openssl MyStandaloneSecret" },
        {"--store-collection-secret", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection MyCollectionSecret" },
        {"--get-standalone-secret", "org.sailfishos.secrets.plugin.storage.sqlite MyStandaloneSecret" },
        {"--get-collection-secret", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection MyCollectionSecret" },
        {"--delete-standalone-secret", "org.sailfishos.secrets.plugin.storage.sqlite MyStandaloneSecret" },
        {"--delete-collection-secret", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection MyCollectionSecret" },
        {"--list-keys", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher" },
        {"--generate-stored-key", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection MyRsaKey RSA 2048" },
        {"--derive-stored-key", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection MyAesKey AES 256 salt.data" },
        {"--import-stored-key", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection MyImportedKey keyfile.pem" },
        {"--delete-key", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection MyRsaKey" },
        {"--sign", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection MyRsaKey SHA256 document.txt > document.txt.sig" },
        {"--verify", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection MyRsaKey SHA256 document.txt document.txt.sig" },
        {"--encrypt", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection MyAesKey document.txt > document.txt.enc" },
        {"--decrypt", "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher MyCollection MyAesKey document.txt.enc > document.txt.dec" },
    };

    bool autotestMode = false;
    if (args.size() && args.first() == QStringLiteral("--test")) {
        args.takeFirst();
        autotestMode = true;
    }

    if (args.size() == 0 || !paramDescriptions.contains(args[0])) {
        // build the usage help text.
        bool showOptionDescriptions = args.size() &&
                (args[0] == QStringLiteral("--help") ||
                 args[0] == QStringLiteral("--h") ||
                 args[0] == QStringLiteral("-h"));
        QStringList usage;
        QMap<QString, QString>::const_iterator it = paramDescriptions.constBegin();
        while (it != paramDescriptions.constEnd()) {
            const QString descriptionLine = QStringLiteral("  ") + it.value();
            const QString usageLine = QStringLiteral("  ") + it.key() + QStringLiteral(" ") + paramOptions.value(it.key());
            const QString exampleLine = QStringLiteral("  ") + it.key() + QStringLiteral(" ") + paramExamples.value(it.key());
            if (showOptionDescriptions) {
                usage.append(descriptionLine);
                usage.append(usageLine);
                usage.append(QStringLiteral("  E.g.:"));
                usage.append(exampleLine);
                usage.append(QString());
            } else {
                usage.append(usageLine);
            }
            it++;
        }

        // then prepend the --help and -h options
        if (showOptionDescriptions) {
            usage.prepend(QString());
            usage.prepend(QStringLiteral("  --help, -h"));
            usage.prepend(QStringLiteral("  Display this help text"));
        } else {
            usage.prepend(QStringLiteral("  --help, -h"));
        }

        // and print the usage help text.
        qInfo() << "Usage: secrets-tool [--test] [options]";
        qInfo() << "";
        qInfo() << "The --test flag should be provided if the daemon is running in --test mode.";
        qInfo() << "";
        qInfo() << "Options:";
        Q_FOREACH (const QString &line, usage) {
            qInfo() << line.toLocal8Bit().constData();
        }
        qInfo() << "";
        return 0;
    }

    const QString command = args.takeFirst();
    if (args.size() < paramOptionsMin.value(command)
            || args.size() > paramOptionsMax.value(command)) {
        qInfo() << "  Usage:" << appName << command << paramOptions.value(command);
        qInfo() << "Example:" << appName << command << paramExamples.value(command);
        return 1;
    }

    CommandHelper helper(autotestMode);
    QObject::connect(&helper, &CommandHelper::finished,
                     &app, &QCoreApplication::quit);
    helper.start(command, args);
    app.exec();
    return helper.exitCode();
}
