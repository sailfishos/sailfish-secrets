/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_PLUGININFOREQUEST_P_H
#define LIBSAILFISHCRYPTO_PLUGININFOREQUEST_P_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/plugininforequest.h"
#include "Crypto/cryptomanager.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Crypto {

class PluginInfoRequestPrivate
{
    Q_DISABLE_COPY(PluginInfoRequestPrivate)

public:
    explicit PluginInfoRequestPrivate();

    QPointer<Sailfish::Crypto::CryptoManager> m_manager;
    QVector<Sailfish::Crypto::CryptoPluginInfo> m_cryptoPlugins;
    QStringList m_storagePlugins;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Crypto::Request::Status m_status;
    Sailfish::Crypto::Result m_result;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_PLUGININFOREQUEST_P_H
