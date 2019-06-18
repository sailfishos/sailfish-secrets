/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APIIMPL_APPLICATIONPERMISSIONS_P_H
#define SAILFISHSECRETS_APIIMPL_APPLICATIONPERMISSIONS_P_H

#include <QtCore/QObject>
#include <QtCore/QVariant>
#include <QtCore/QString>
#include <QtCore/QMap>
#include <QtCore/QList>
#include <QtCore/QSet>

#include <aboutsettings.h>
#include <sys/types.h>

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace ApiImpl {

class ApplicationPermissions : public QObject
{
    Q_OBJECT

public:
    ApplicationPermissions(QObject *parent = Q_NULLPTR)
        : QObject(parent) {
        AboutSettings settings;
        m_osName = settings.operatingSystemName();
    }

    QString applicationId(pid_t pid) const;
    QString platformApplicationId() const { return m_osName; }
    bool applicationIsPlatformApplication(pid_t pid) const;

private:
    QString m_osName;
};

} // namespace ApiImpl

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_APIIMPL_APPLICATIONPERMISSIONS_P_H
