/*
 * Copyright (C) 2018 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef OPENPGP_H
#define OPENPGP_H

#include "gpgmebase.h"
#include "gpgmestorage.h"

namespace Sailfish {

namespace Crypto {

namespace Daemon {

namespace Plugins {

class Q_DECL_EXPORT OpenPGPPlugin : public QObject
    , public Sailfish::Crypto::Daemon::Plugins::GnuPGPlugin
    , public Sailfish::Secrets::Daemon::Plugins::GnuPGStoragePlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)
    Q_INTERFACES(Sailfish::Crypto::CryptoPlugin Sailfish::Secrets::EncryptedStoragePlugin)

public:
    OpenPGPPlugin(QObject *parent = Q_NULLPTR);
    ~OpenPGPPlugin();

    QString name() const Q_DECL_OVERRIDE {
#ifdef SAILFISHSECRETS_TESTPLUGIN
        return QLatin1String("org.sailfishos.crypto.plugin.gnupg.openpgp.test");
#else
        return QLatin1String("org.sailfishos.crypto.plugin.gnupg.openpgp");
#endif
    }

    QString displayName() const Q_DECL_OVERRIDE {
        return QStringLiteral("GnuPG");
    }

    int version() const Q_DECL_OVERRIDE {
        return 000001;
    }
};

} // namespace Plugins

} // namespace Daemon

} // namespace Crypto

} // namespace Sailfish

#endif // OPENPGP_H
