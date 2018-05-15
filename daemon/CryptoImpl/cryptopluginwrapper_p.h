/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSCRYPTO_APIIMPL_CRYPTOPLUGINWRAPPER_P_H
#define SAILFISHSCRYPTO_APIIMPL_CRYPTOPLUGINWRAPPER_P_H

#include "util_p.h"

#include "SecretsImpl/pluginwrapper_p.h"
#include "SecretsImpl/metadatadb_p.h"

#include "CryptoPluginApi/extensionplugins.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>

namespace Sailfish {

namespace Crypto {

namespace Daemon {

namespace ApiImpl {

class CryptoStoragePluginWrapper : public Sailfish::Secrets::Daemon::ApiImpl::EncryptedStoragePluginWrapper
{
public:
    CryptoStoragePluginWrapper(Sailfish::Crypto::CryptoPlugin *cryptoPlugin,
                               Sailfish::Secrets::EncryptedStoragePlugin *plugin,
                               bool autotestMode);
    ~CryptoStoragePluginWrapper();

    Sailfish::Secrets::Result keyNames(const QString &collectionName,
                                       const QVariantMap &customParameters,
                                       QStringList *keyNames) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result storedKeyIdentifiers(
            const QString &collectionName,
            const QVariantMap &customParameters,
            QVector<Sailfish::Crypto::Key::Identifier> *identifiers);

    Sailfish::Crypto::Result generateAndStoreKey(
            const Sailfish::Secrets::Daemon::ApiImpl::SecretMetadata &metadata,
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const QVariantMap &customParameters,
            const QByteArray &collectionUnlockKey,
            Sailfish::Crypto::Key *keyReference);

    Sailfish::Crypto::Result importAndStoreKey(
            const Sailfish::Secrets::Daemon::ApiImpl::SecretMetadata &metadata,
            const QByteArray &data,
            const Sailfish::Crypto::Key &keyTemplate,
            const QByteArray &importPassphrase,
            const QVariantMap &customParameters,
            const QByteArray &collectionUnlockKey,
            Sailfish::Crypto::Key *keyReference);

protected:
    Sailfish::Crypto::CryptoPlugin *m_cryptoPlugin;

private:
    Sailfish::Crypto::Result prepareToStoreKey(
            const Sailfish::Secrets::Daemon::ApiImpl::SecretMetadata &metadata,
            const QByteArray &collectionUnlockKey,
            bool *wasLocked);
};

} // ApiImpl

} // Daemon

} // Crypto

} // Sailfish

#endif // SAILFISHSCRYPTO_APIIMPL_CRYPTOPLUGINWRAPPER_P_H
