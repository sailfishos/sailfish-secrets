/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_COMMON_DAEMON_UTIL_P_H
#define SAILFISHSECRETS_COMMON_DAEMON_UTIL_P_H

#include <QtCore/QString>

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Util {

QString generateHashedSecretName(const QString &collectionName, const QString &secretName);

} // namespace Util

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_COMMON_DAEMON_UTIL_P_H
