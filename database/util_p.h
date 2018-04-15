/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_COMMON_DAEMON_UTIL_P_H
#define SAILFISHSECRETS_COMMON_DAEMON_UTIL_P_H

#include <QtCore/QString>

#include "Secrets/result.h"
#include "Crypto/result.h"

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Util {

Sailfish::Crypto::Result transformSecretsResult(const Sailfish::Secrets::Result &result);

} // namespace Util

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_COMMON_DAEMON_UTIL_P_H
