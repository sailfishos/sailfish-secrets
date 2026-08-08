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
#include <QtCore/QUrl>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

namespace {
    QString readBoosterCgroup(pid_t pid)
    {
        const QString pidFile(QStringLiteral("/proc/%1/cgroup").arg(pid));
        if (!QFile::exists(pidFile)) {
            qCDebug(lcSailfishSecretsDaemon) << "no cgroup in procfs for process:" << pid;
            return QString();
        }

        QFile file(pidFile);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            qCDebug(lcSailfishSecretsDaemon) << "unable to open cgroup file:" << pidFile;
            return QString();
        }

        const QList<QByteArray> lines(file.readAll().split('\n'));
        for (const QByteArray &line : lines) {
            int idx = line.indexOf(":name=booster:");
            if (idx >= 0) {
                const QByteArray cgroupName(line.mid(idx + strlen(":name=booster:")));
                if (!cgroupName.isEmpty() && cgroupName != QStringLiteral("/")) {
                    const QString retn(QString::fromUtf8(cgroupName).trimmed());
                    qCDebug(lcSailfishSecretsDaemon) << "caller with pid" << pid << "has cgroup applicationId:" << retn;
                    return retn;
                }
            }
        }

        qCDebug(lcSailfishSecretsDaemon) << "unable to find relevant cgroup for process:" << pid;
        return QString();
    }

    QString readExeSymlink(pid_t pid)
    {
        struct stat sb;
        const QString pidFile(QStringLiteral("/proc/%1/exe").arg(pid));
        if (lstat(pidFile.toUtf8().data(), &sb) == -1) {
            qCDebug(lcSailfishSecretsDaemon) << "unable to lstat procfs exe link file for process:" << pid;
            return QString();
        }

        QScopedPointer<char, QScopedPointerPodDeleter> linkName(reinterpret_cast<char*>(malloc(sb.st_size + 1)));
        if (linkName.data() == NULL) {
            qCDebug(lcSailfishSecretsDaemon) << "unable to allocate memory for link name for process:" << pid;
            return QString();
        }

        ssize_t r = readlink(pidFile.toStdString().c_str(),
                             linkName.data(),
                             sb.st_size + 1);
        if (r < 0) {
            qCDebug(lcSailfishSecretsDaemon) << "unable to readlink exe for process:" << pid;
            return QString();
        }

        linkName.data()[sb.st_size] = '\0';
        const QString retn(QString::fromUtf8(QByteArray(linkName.data())));
        qCDebug(lcSailfishSecretsDaemon) << "caller with pid" << pid << "has exe applicationId:" << retn;
        return retn;
    }

    QString readExactExeSymlink(pid_t pid)
    {
        const QByteArray path = QStringLiteral("/proc/%1/exe").arg(pid).toUtf8();
        QByteArray target(256, '\0');
        for (;;) {
            const ssize_t size = readlink(path.constData(), target.data(), target.size());
            if (size < 0) {
                return QString();
            }
            if (size < target.size()) {
                target.truncate(static_cast<int>(size));
                return QString::fromUtf8(target);
            }
            if (target.size() >= 65536) {
                return QString();
            }
            target.resize(target.size() * 2);
        }
    }

    QString readCmdline(pid_t pid)
    {
        const QString pidFile(QStringLiteral("/proc/%1/cmdline").arg(pid));
        if (!QFile::exists(pidFile)) {
            qCDebug(lcSailfishSecretsDaemon) << "no cmdline in procfs for process:" << pid;
            return QString();
        }

        QFile file(pidFile);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            qCDebug(lcSailfishSecretsDaemon) << "unable to open cmdline file:" << pidFile;
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
        qCDebug(lcSailfishSecretsDaemon) << "caller with pid" << pid << "has cmdline applicationId:" << retn;
        return retn;
    }
}

QString Sailfish::Secrets::Daemon::ApiImpl::ApplicationPermissions::exactApplicationId(pid_t pid) const
{
    if (pid <= 0) {
        qCWarning(lcSailfishSecretsDaemon) << "Cannot determine an exact application id for pid" << pid;
        return QString();
    }

    const QFileInfo processInfo(QStringLiteral("/proc/%1").arg(pid));
    const QString executable = readExactExeSymlink(pid);
    if (!processInfo.exists() || executable.isEmpty()) {
        qCWarning(lcSailfishSecretsDaemon) << "Incomplete exact application identity for pid" << pid;
        return QString();
    }
    return exactApplicationId(pid, processInfo.ownerId(), processInfo.groupId(),
                              executable);
}

QString Sailfish::Secrets::Daemon::ApiImpl::ApplicationPermissions::exactApplicationId(
        pid_t pid, uid_t trustedUid, gid_t trustedGid,
        const QString &trustedExecutable) const
{
    if (pid <= 0 || trustedExecutable.isEmpty()) {
        qCWarning(lcSailfishSecretsDaemon) << "Incomplete exact application identity for pid" << pid;
        return QString();
    }

    const QByteArray encodedExecutable = QUrl::toPercentEncoding(trustedExecutable);
    const QByteArray encodedCgroup = QUrl::toPercentEncoding(readBoosterCgroup(pid));
    return QString::fromLatin1("exact:v1;uid=%1;gid=%2;exe=%3;cgroup=%4")
            .arg(trustedUid)
            .arg(trustedGid)
            .arg(QString::fromLatin1(encodedExecutable))
            .arg(QString::fromLatin1(encodedCgroup));
}

QString Sailfish::Secrets::Daemon::ApiImpl::ApplicationPermissions::applicationId(pid_t pid) const
{
    if (pid == 0) {
        qCDebug(lcSailfishSecretsDaemon) << "zero pid, assuming privileged!";
        return platformApplicationId();
    }

    const QString cgroupName = readBoosterCgroup(pid);
    if (!cgroupName.isEmpty()) {
        return cgroupName;
    }

    const QString linkName = readExeSymlink(pid);
    if (!linkName.isEmpty()) {
        return linkName;
    }

    const QString cmdLine = readCmdline(pid);
    if (!cmdLine.isEmpty()) {
        return cmdLine;
    }

    qCWarning(lcSailfishSecretsDaemon) << "Unable to determine application id for process" << pid;
    return QString();
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
