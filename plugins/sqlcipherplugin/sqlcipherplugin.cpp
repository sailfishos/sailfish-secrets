/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "sqlcipherplugin.h"

#include <QStandardPaths>
#include <QString>

Q_PLUGIN_METADATA(IID Sailfish_Secrets_EncryptedStoragePlugin_IID)

Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::SqlCipherPlugin(QObject *parent)
    : QObject(parent)
    , Sailfish::Secrets::Daemon::Plugins::EncryptedStoragePlugin()
    , Sailfish::Secrets::Daemon::Plugins::CryptoPlugin()
    , m_databaseSubdir(QLatin1String("sqlcipherplugin"))
    , m_databaseDirPath(databaseDirPath(name().endsWith(QStringLiteral(".test"), Qt::CaseInsensitive),
                                        m_databaseSubdir))
    , m_opensslCryptoPlugin(this)
{
    init_aes_encryption();
}

Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::~SqlCipherPlugin()
{
    qDeleteAll(m_collectionDatabases);
}

QString Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::databaseDirPath(
        bool isTestPlugin,
        const QString &databaseSubdir)
{
    // note: these paths are very dependent upon the implementation of database.cpp
    const QString systemDataDirPath(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + QLatin1String("/system/"));
    const QString privilegedDataDirPath(systemDataDirPath + QLatin1String("privileged/"));
    const QString subdir = isTestPlugin
                         ? QString(QLatin1String("Secrets/%1-test/")).arg(databaseSubdir)
                         : QString(QLatin1String("Secrets/%1/")).arg(databaseSubdir);
    return privilegedDataDirPath + subdir;
}
