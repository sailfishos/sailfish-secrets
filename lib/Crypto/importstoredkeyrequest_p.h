/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_IMPORTSTOREDKEYREQUEST_P_H
#define LIBSAILFISHCRYPTO_IMPORTSTOREDKEYREQUEST_P_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/importstoredkeyrequest.h"
#include "Crypto/cryptomanager.h"
#include "Crypto/interactionparameters.h"
#include "Crypto/key.h"

#include <QtCore/QPointer>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

#include <QtDBus/QDBusPendingCallWatcher>

namespace Sailfish {

namespace Crypto {

class ImportStoredKeyRequestPrivate
{
    Q_DISABLE_COPY(ImportStoredKeyRequestPrivate)

public:
    explicit ImportStoredKeyRequestPrivate();

    QPointer<Sailfish::Crypto::CryptoManager> m_manager;
    QString m_cryptoPluginName;
    QVariantMap m_customParameters;
    Sailfish::Crypto::InteractionParameters m_uiParams;
    Sailfish::Crypto::Key m_key;
    Sailfish::Crypto::Key m_importedKeyReference;

    QScopedPointer<QDBusPendingCallWatcher> m_watcher;
    Sailfish::Crypto::Request::Status m_status;
    Sailfish::Crypto::Result m_result;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_GENERATESTOREDKEYREQUEST_P_H
