/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "applicationpermissions_p.h"
#include "logging_p.h"

#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>

QString Sailfish::Secrets::Daemon::ApiImpl::ApplicationPermissions::applicationId(pid_t pid) const
{
    // TODO: readlink /proc/pid/exe -- but requires root permissions?

    // special case handling of the pid 999999 for demonstration testing purposes only!
    // TODO: remove this special case handling!
    if (pid == 999999) {
        return QLatin1String("test-third-party-application");
    }

    if (pid == 0) {
        qCDebug(lcSailfishSecretsDaemon) << "zero pid, assuming privileged!";
        return platformApplicationId();
    }

    const QString pidFile = QString::fromLatin1("/proc/%1/cmdline").arg(pid);
    if (!QFile::exists(pidFile)) {
        qCWarning(lcSailfishSecretsDaemon) << "no such pid:" << pid;
        return QString();
    }

    QFile file(pidFile);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qCWarning(lcSailfishSecretsDaemon) << "unable to open pid file:" << pidFile;
        return QString();
    }

    QByteArray contents;
    char data;
    while (file.read(&data, 1)) {
        if (data == '\0') {
            data = ' ';
        }
        contents.append(data);
    }

    const QString retn(QString::fromUtf8(contents).trimmed());
    qCDebug(lcSailfishSecretsDaemon) << "caller with pid" << pid << "has applicationId:" << retn;
    return retn;
}

bool Sailfish::Secrets::Daemon::ApiImpl::ApplicationPermissions::applicationIsPlatformApplication(pid_t pid) const
{
    // TODO: implement a real ACL?  This implementation just checks that the pid is privileged egid.

    if (pid == 0) {
        qCDebug(lcSailfishSecretsDaemon) << "zero pid, assuming privileged!";
        return true;
    }

    QFileInfo info(QString("/proc/%1").arg(pid));
    if (info.group() != "privileged" && info.group() != "disk" && info.owner() != "root") {
        return false;
    }

    return true;
}
