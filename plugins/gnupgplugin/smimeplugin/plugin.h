/*
 * Copyright (C) 2018 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SMIME_H
#define SMIME_H

#include "gpgmebase.h"
#include "gpgmestorage.h"

namespace Sailfish {

namespace Crypto {

namespace Daemon {

namespace Plugins {

class Q_DECL_EXPORT SMimePlugin : public QObject
    , public Sailfish::Crypto::Daemon::Plugins::GnuPGPlugin
    , public Sailfish::Secrets::Daemon::Plugins::GnuPGStoragePlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)
    Q_INTERFACES(Sailfish::Crypto::CryptoPlugin Sailfish::Secrets::EncryptedStoragePlugin)

public:
    SMimePlugin(QObject *parent = Q_NULLPTR);
    ~SMimePlugin();

    QString name() const Q_DECL_OVERRIDE {
#ifdef SAILFISHSECRETS_TESTPLUGIN
        return QLatin1String("org.sailfishos.crypto.plugin.gnupg.smime.test");
#else
        return QLatin1String("org.sailfishos.crypto.plugin.gnupg.smime");
#endif
    }

    QString displayName() const Q_DECL_OVERRIDE {
        return QStringLiteral("GnuPG S/MIME");
    }

    int version() const Q_DECL_OVERRIDE {
        return 000001;
    }
};
 
} // namespace Plugins

} // namespace Daemon

} // namespace Crypto

} // namespace Sailfish

#endif // SMIME_H
